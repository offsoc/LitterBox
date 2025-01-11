import subprocess
import json
import threading
import logging
import traceback
from .base import DynamicAnalyzer

class RedEdrAnalyzer(DynamicAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.tool_process = None
        self.target_name = None
        self.results = {}
        self.collected_output = []
        self._output_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.output_thread = None
        self._stop_reading = threading.Event()
        
    def _reader_thread(self):
        """Thread to read RedEdr output without blocking"""
        try:
            while not self._stop_reading.is_set():
                line = self.tool_process.stdout.readline()
                if not line:
                    break
                    
                line = line.strip()
                if line:
                    with self._output_lock:
                        self.collected_output.append(line)
                        
        except Exception as e:
            print(f"Error in reader thread: {e}")
            
    def start_tool(self, target_name):
        """Start the RedEdr tool in monitoring mode"""
        try:
            self.target_name = target_name
            tool_config = self.config['analysis']['dynamic']['rededr']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                process_name=target_name
            )
            
            self.tool_process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Reset stop flag
            self._stop_reading.clear()
            
            # Start the output reader thread
            self.output_thread = threading.Thread(target=self._reader_thread)
            self.output_thread.daemon = True
            self.output_thread.start()
            
            return True
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': f'Failed to start RedEdr: {str(e)}'
            }
            return False
            
    def analyze(self, pid):
        """Not used for RedEdr"""
        pass
    
    def _parse_output(self, output):
        """Parse RedEdr JSON output into structured data"""
        findings = {
            'events': [],             
            'process_info': {         
                'commandline': None,
                'image_path': None,
                'working_dir': None,
                'parent_pid': None,
                'is_debugged': False,
                'is_protected_process': False,
                'pid': None,
                'start_time': None  # Add start time field
            },    
            'loaded_dlls': [],        
            'child_processes': [],    
            'threads': [],            
            'image_loads': [],        
            'image_unloads': [],      
            'cpu_priority_changes': []
        }

        try:
            # First pass to find process start time
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue

                if line.startswith('{'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                        
                    event_type = event.get('type', '').strip()
                    event_name = event.get('event', '').strip()
                    
                    # Capture process start time from the first ImageLoadInfo of the main process
                    if event_type == 'etw' and event_name == 'ImageLoadInfo' and not findings['process_info']['start_time']:
                        findings['process_info']['start_time'] = event.get('time')

            # Reset and process all events
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue

                if line.startswith('{'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    event_type = event.get('type', '').strip()
                    event_name = event.get('event', '').strip()
                    func_name  = event.get('func', '').strip()

                    # Process Query Events
                    if event_type in ['process_query', 'proces_query']:
                        # PEB Info
                        if func_name == 'peb' or event_name == 'peb':
                            findings['process_info'].update({
                                'commandline': event.get('commandline'),
                                'image_path': event.get('image_path'),
                                'working_dir': event.get('working_dir'),
                                'parent_pid': event.get('parent_pid'),
                                'is_debugged': event.get('is_debugged', False),
                                'is_protected_process': event.get('is_protected_process', False),
                                'pid': event.get('pid')
                            })
                        # Loaded DLLs
                        elif func_name == 'loaded_dll':
                            dlls = event.get('dlls', [])
                            event_time = event.get('time')
                            if isinstance(dlls, list):
                                # Add time to each DLL
                                for dll in dlls:
                                    if isinstance(dll, dict):
                                        dll['time'] = event_time
                                findings['loaded_dlls'].extend(dlls)
                            elif isinstance(dlls, dict):
                                dlls['time'] = event_time
                                findings['loaded_dlls'].append(dlls)

                    # ETW Events
                    elif event_type == 'etw':
                        if event.get('ProcessID') and not findings['process_info']['pid']:
                            findings['process_info']['pid'] = event.get('ProcessID')

                        if event_name == 'ProcessStartStart':
                            findings['child_processes'].append({
                                'pid': event.get('ProcessID'),
                                'parent_pid': event.get('ParentProcessID'),
                                'image_name': event.get('ImageName'),
                                'create_time': event.get('CreateTime')
                            })

                        elif event_name == 'ThreadStartStart':
                            findings['threads'].append({
                                'thread_id': event.get('ThreadID'),
                                'process_id': event.get('ProcessID'),
                                'start_addr': event.get('StartAddr'),
                                'stack_base': event.get('StackBase')
                            })

                        elif event_name == 'ImageLoadInfo':
                            findings['image_loads'].append({
                                'pid': event.get('ProcessID'),
                                'image_name': event.get('ImageName'),
                                'base': event.get('ImageBase'),
                                'size': event.get('ImageSize'),
                                'time_stamp': event.get('time'),  # Use ETW time
                                'stack_trace': event.get('stack_trace', []),
                            })

                        elif event_name == 'ImageUnloadInfo':
                            findings['image_unloads'].append({
                                'pid': event.get('ProcessID'),
                                'image_name': event.get('ImageName'),
                                'base': event.get('ImageBase'),
                                'size': event.get('ImageSize'),
                                'time_stamp': event.get('time'),
                                'stack_trace': event.get('stack_trace', []),
                            })
                            
                        elif event_name in ['CpuBasePriorityChangeInfo', 'CpuPriorityChangeInfo']:
                            findings['cpu_priority_changes'].append({
                                'pid': event.get('ProcessID'),
                                'thread_id': event.get('ThreadID'),
                                'old_priority': event.get('OldPriority'),
                                'new_priority': event.get('NewPriority'),
                                'time': event.get('time')
                            })

                    # Store all valid JSON events
                    findings['events'].append(event)

        except Exception as e:
            self.logger.error(f"Error parsing output: {e}", exc_info=True)
            return findings

        return findings

    def get_results(self):
        """
        Get all collected events and analysis results from RedEdr.
        Returns a structured dictionary containing process information, events, and statistics.
        """
        try:
            with self._output_lock:
                output_text = '\n'.join(self.collected_output)
                
            # Create a default structure for empty/error cases
            default_findings = {
                'process_info': {
                    'pid': None,
                    'commandline': None,
                    'image_path': None,
                    'working_dir': None,
                    'parent_pid': None,
                    'is_debugged': False,
                    'is_protected_process': False,
                    'integrity_level': 'unknown'
                },
                'loaded_dlls': [],
                'child_processes': [],
                'threads': [],
                'image_loads': [],
                'image_unloads': [],
                'cpu_priority_changes': [],
                'summary': {
                    'total_events': 0,
                    'total_dlls': 0,
                    'total_child_processes': 0,
                    'total_threads': 0,
                    'total_image_loads': 0,
                    'total_image_unloads': 0
                }
            }

            parsed_data = self._parse_output(output_text)
            
            # If parsing failed, return the default structure
            if parsed_data is None:
                self.logger.warning("Parsing output returned None, using default structure")
                return {
                    'status': 'completed',
                    'findings': default_findings,
                    'raw_output': output_text
                }

            # If we have parsed data, update the default structure with actual values
            findings = default_findings.copy()
            
            # Update process info if available
            if 'process_info' in parsed_data and parsed_data['process_info']:
                findings['process_info'].update({
                    'pid': parsed_data['process_info'].get('pid'),
                    'commandline': parsed_data['process_info'].get('commandline'),
                    'image_path': parsed_data['process_info'].get('image_path'),
                    'working_dir': parsed_data['process_info'].get('working_dir'),
                    'parent_pid': parsed_data['process_info'].get('parent_pid'),
                    'is_debugged': parsed_data['process_info'].get('is_debugged', False),
                    'is_protected_process': parsed_data['process_info'].get('is_protected_process', False)
                })

            # Update lists with actual data if available
            if 'loaded_dlls' in parsed_data:
                findings['loaded_dlls'] = parsed_data['loaded_dlls']
            if 'child_processes' in parsed_data:
                findings['child_processes'] = parsed_data['child_processes']
            if 'threads' in parsed_data:
                findings['threads'] = parsed_data['threads']
            if 'image_loads' in parsed_data:
                findings['image_loads'] = parsed_data['image_loads']
            if 'image_unloads' in parsed_data:
                findings['image_unloads'] = parsed_data['image_unloads']
            if 'cpu_priority_changes' in parsed_data:
                findings['cpu_priority_changes'] = parsed_data['cpu_priority_changes']

            # Update summary
            findings['summary'] = {
                'total_events': len(parsed_data.get('events', [])),
                'total_dlls': len(findings['loaded_dlls']),
                'total_child_processes': len(findings['child_processes']),
                'total_threads': len(findings['threads']),
                'total_image_loads': len(findings['image_loads']),
                'total_image_unloads': len(findings['image_unloads'])
            }

            findings['timeline'] = self._generate_timeline(findings)

            return {
                'status': 'completed',
                'findings': findings,
                'raw_output': output_text
            }
                
        except Exception as e:
            self.logger.error(f"Error in get_results: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'error_details': {
                    'type': type(e).__name__,
                    'traceback': traceback.format_exc()
                },
                'findings': default_findings
            }

    def _generate_timeline(self, parsed_data):
        """
        Generate a chronological timeline of significant events.
        Each event must have a timestamp in a consistent format.
        """
        timeline = []
        
        # Add process start if available
        if parsed_data.get('process_info', {}).get('pid'):
            timeline.append({
                'time': None,  # We don't have start time in current data
                'type': 'Process Start',
                'details': f"Process started: PID {parsed_data['process_info']['pid']}"
            })
        
        # Add child process creations
        for child in parsed_data.get('child_processes', []):
            timeline.append({
                'time': child.get('create_time', None),
                'type': 'Child Process',
                'details': f"Created child process: {child.get('image_name', 'Unknown')} (PID: {child.get('pid', 'Unknown')})"
            })

        # Add DLL loads
        for dll in parsed_data.get('loaded_dlls', []):
            timeline.append({
                'time': dll.get('time', None),
                'type': 'DLL Load',
                'details': f"Loaded DLL: {dll.get('name', 'Unknown')}"
            })

        # Add image loads
        for img in parsed_data.get('image_loads', []):
            timeline.append({
                'time': img.get('time_stamp', None),
                'type': 'Image Load',
                'details': f"Loaded image: {img.get('image_name', 'Unknown')}"
            })

        # Sort timeline by timestamp if available, otherwise keep original order
        # Filter out None timestamps and put them at the start
        timeline_with_time = [x for x in timeline if x['time'] is not None]
        timeline_without_time = [x for x in timeline if x['time'] is None]
        
        # Sort only events with timestamps
        timeline_with_time.sort(key=lambda x: str(x['time']))
        
        # Combine the lists, putting events without timestamps first
        sorted_timeline = timeline_without_time + timeline_with_time
        
        return sorted_timeline

    def cleanup(self):
        """Stop the RedEdr process if it's still running"""
        # Signal reader thread to stop
        self._stop_reading.set()
        
        if self.tool_process:
            try:
                self.tool_process.terminate()
                self.tool_process.wait(timeout=5)
                
                # Wait for reader thread to finish
                if self.output_thread and self.output_thread.is_alive():
                    self.output_thread.join(timeout=2)
                    
            except subprocess.TimeoutExpired:
                self.tool_process.kill()
            finally:
                if self.tool_process.stdout:
                    self.tool_process.stdout.close()
                if self.tool_process.stderr:
                    self.tool_process.stderr.close()