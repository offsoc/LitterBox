# app/analyzers/dynamic/moneta_analyzer.py

import subprocess
from .base import DynamicAnalyzer
import re
from datetime import datetime

class MonetaAnalyzer(DynamicAnalyzer):
    def analyze(self, pid):
        self.pid = pid
        try:
            tool_config = self.config['analysis']['dynamic']['moneta']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                pid=pid
            )
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            # Consider successful if we got output, regardless of return code
            findings = self._parse_output(stdout)
            has_results = bool(stdout and findings.get('raw_output'))
            
            self.results = {
                'status': 'completed' if has_results else 'failed',  # Changed condition
                'findings': findings,
                'errors': stderr if stderr else None
            }
            
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def cleanup(self):
        """No cleanup needed as process management is handled by manager"""
        pass


    def _parse_output(self, output):
        findings = {
            'process_info': None,
            'memory_regions': [],
            'total_regions': 0,
            'total_private_rx': 0,
            'total_private_rwx': 0,
            'total_abnormal_private_exec': 0,
            'total_heap_executable': 0,
            'total_modified_code': 0,
            'total_modified_pe_header': 0,
            'total_inconsistent_x': 0,
            'total_unsigned_modules': 0,
            'total_missing_peb': 0,
            'total_mismatching_peb': 0,
            'total_threads_non_image': 0,
            'threads': [],
            'scan_duration': None,
            'raw_output': output
        }
        
        try:
            lines = output.split('\n')
            current_region = None
            current_subregion = None
            
            for line in lines:
                original_line = line  # Keep original for debug
                line = line.rstrip()  # Remove trailing whitespace but keep leading
                
                if not line or 'Moneta v1.0' in line or '_____' in line:
                    continue

                # Scan duration
                if 'scan completed' in line:
                    duration_match = re.search(r'(\d+\.\d+) second', line)
                    if duration_match:
                        findings['scan_duration'] = float(duration_match.group(1))
                    continue
                        
                # Process info - exact match for '.exe :'
                if '.exe :' in line:
                    process_match = re.match(r'(.+\.exe)\s*:\s*(\d+)\s*:\s*(x64|Wow64)\s*:\s*(.+)', line)
                    if process_match:
                        findings['process_info'] = {
                            'name': process_match.group(1),
                            'pid': process_match.group(2),
                            'arch': process_match.group(3),
                            'path': process_match.group(4)
                        }
                    continue

                # Skip non-memory region lines that aren't thread info
                if '|' not in line and 'Thread' not in line and '[TID' not in line:
                    continue

                # Count leading spaces for hierarchy detection
                leading_spaces = len(line) - len(line.lstrip())
                
                # Thread detection - most indented (6 spaces)
                if leading_spaces >= 6 and '[TID' in line:
                    tid_match = re.search(r'\[TID\s*(0x[0-9A-Fa-f]+)\]', line)
                    if tid_match:
                        tid = tid_match.group(1)
                        if tid not in [t['tid'] for t in findings['threads']]:
                            findings['threads'].append({
                                'tid': tid,
                                'thread_obj': line.split('Thread')[1].split('[TID')[0].strip() if 'Thread' in line else None
                            })
                    continue

                # Memory regions
                parts = [p.strip() for p in line.split('|')]
                
                # Main region (2 spaces)
                if leading_spaces == 2:
                    findings['total_regions'] += 1
                    # Process main region flags
                    full_line = '|'.join(parts[2:])  # Combine all parts after type
                    
                    if 'Unsigned module' in full_line:
                        findings['total_unsigned_modules'] += 1
                        
                    if 'Missing PEB module' in full_line:
                        findings['total_missing_peb'] += 1
                        
                    if 'Mismatching PEB module' in full_line:
                        findings['total_mismatching_peb'] += 1
                        
                # Subregion (4 spaces)
                elif leading_spaces == 4 and len(parts) >= 2:
                    perms = parts[1].strip()
                    flags = ' '.join(parts[2:])  # Combine all remaining parts
                    
                    if 'Thread within non-image memory region' in flags:
                        findings['total_threads_non_image'] += 1

                    if 'Abnormal private executable memory' in flags:
                        findings['total_abnormal_private_exec'] += 1
                        
                        if 'RWX' in perms:
                            findings['total_private_rwx'] += 1
                            
                        elif 'RX' in perms:
                            findings['total_private_rx'] += 1
                            
                    if 'Heap' in flags and ('RWX' in perms or 'RX' in perms):
                        findings['total_heap_executable'] += 1
                        
                    if 'Modified code' in flags:
                        findings['total_modified_code'] += 1
                        
                    if 'Modified PE header' in flags:
                        findings['total_modified_pe_header'] += 1
                    
                    if 'Inconsistent +x between disk and memory' in flags:
                        findings['total_inconsistent_x'] += 1
                     
        except Exception as e:
            findings['parse_error'] = str(e)
            print("Error:", str(e))
                
        return findings
