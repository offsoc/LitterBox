# app/analyzers/manager.py

import logging
import subprocess
import time
import psutil
import json
from typing import Dict, Type, Optional
from abc import ABC, abstractmethod

# Import analyzers
from .static.yara_analyzer import YaraStaticAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .static.stringnalyzer_analyzer import StringsAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer
from .dynamic.rededr_analyzer import RedEdrAnalyzer

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, target):
        pass

    @abstractmethod
    def get_results(self):
        pass

class AnalysisManager:
    # Define analyzer mappings
    STATIC_ANALYZERS = {
        'yara': YaraStaticAnalyzer,
        'checkplz': CheckPlzAnalyzer,
        'stringnalyzer': StringsAnalyzer
    }

    DYNAMIC_ANALYZERS = {
        'yara': YaraDynamicAnalyzer,
        'pe_sieve': PESieveAnalyzer,
        'moneta': MonetaAnalyzer,
        'patriot': PatriotAnalyzer,
        'hsb': HSBAnalyzer,
        'rededr': RedEdrAnalyzer

    }

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        """
        Initialize the Analysis Manager with configuration and optional logger.
        
        Args:
            config (dict): Configuration dictionary
            logger (logging.Logger, optional): Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing AnalysisManager")
        self.config = config
        self.static_analyzers: Dict[str, BaseAnalyzer] = {}
        self.dynamic_analyzers: Dict[str, BaseAnalyzer] = {}
        
        self._initialize_analyzers()

    def _initialize_analyzer(self, 
                           name: str, 
                           analyzer_class: Type[BaseAnalyzer], 
                           config_section: dict) -> Optional[BaseAnalyzer]:
        """
        Initialize a single analyzer with error handling and logging.
        
        Args:
            name: Name of the analyzer
            analyzer_class: Class of the analyzer to initialize
            config_section: Configuration section for this analyzer
            
        Returns:
            Optional[BaseAnalyzer]: Initialized analyzer or None if initialization failed
        """
        if not config_section.get('enabled', False):
            self.logger.debug(f"Analyzer {name} is disabled in config")
            return None

        self.logger.debug(f"Initializing {name} with config: {config_section}")
        try:
            analyzer = analyzer_class(self.config)
            self.logger.debug(f"{name} initialized successfully")
            return analyzer
        except Exception as e:
            self.logger.error(f"Failed to initialize {name}: {e}", exc_info=True)
            return None

    def _initialize_analyzers(self):
        """Initialize all enabled analyzers based on configuration."""
        self.logger.debug("Beginning analyzer initialization")
        
        # Initialize static analyzers
        static_config = self.config['analysis']['static']
        for name, analyzer_class in self.STATIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, static_config[name]):
                self.static_analyzers[name] = analyzer

        # Initialize dynamic analyzers
        dynamic_config = self.config['analysis']['dynamic']
        for name, analyzer_class in self.DYNAMIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, dynamic_config[name]):
                self.dynamic_analyzers[name] = analyzer

        self.logger.debug(f"Initialized static analyzers: {list(self.static_analyzers.keys())}")
        self.logger.debug(f"Initialized dynamic analyzers: {list(self.dynamic_analyzers.keys())}")
        self.logger.debug("Analyzer initialization completed")

    def _run_analyzers(self, analyzers: Dict[str, BaseAnalyzer], target, analysis_type: str) -> dict:
        """
        Run a group of analyzers and collect their results.
        
        Args:
            analyzers: Dictionary of analyzer instances
            target: Analysis target (file path or PID)
            analysis_type: Type of analysis ('static' or 'dynamic')
                
        Returns:
            dict: Results from all analyzers
        """
        results = {}
        if not analyzers:
            self.logger.warning(f"No {analysis_type} analyzers are enabled")
            return results

        # For dynamic analysis, verify process exists first
        if analysis_type == 'dynamic':
            try:
                process = psutil.Process(int(target))
                if not process.is_running():
                    self.logger.error(f"Process {target} is not running")
                    return {'status': 'error', 'error': 'Process not running'}
            except (ValueError, psutil.NoSuchProcess):
                self.logger.error(f"Process {target} does not exist")
                return {'status': 'error', 'error': 'Process does not exist'}

        # Run analyzers only if we have a valid target
        self.logger.debug(f"Running {len(analyzers)} {analysis_type} analyzers")
        for name, analyzer in analyzers.items():
            try:
                self.logger.debug(f"Running {name}")
                analyzer.analyze(target)
                results[name] = analyzer.get_results()
            except Exception as e:
                self.logger.error(f"Error in {name}: {str(e)}")
                results[name] = {'status': 'error', 'error': str(e)}

        return results

    def run_static_analysis(self, file_path: str) -> dict:
        """Run static analysis with timing"""
        start_time = time.time()
        results = {}
        
        try:
            # Your existing static analysis code here
            results = self._run_analyzers(self.static_analyzers, file_path, 'static')
            
            # Add analysis timing metadata
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error during static analysis: {str(e)}", exc_info=True)
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time(),
                'error': str(e)
            }
        self.logger.debug(f"Static analysis completed in {time.time() - start_time:.2f} seconds")

        return results

    def run_dynamic_analysis(self, target, is_pid: bool = False, cmd_args: list = None) -> dict:
        """Run dynamic analysis with timing, process output capture, and RedEdr integration."""
        self.logger.debug(f"Starting dynamic analysis - Target: {target}, is_pid: {is_pid}, args: {cmd_args}")
        start_time = time.time()
        results = {}
        process = None
        rededr = None
        early_termination = False
        
        try:
            if not is_pid:
                # 1. Start RedEdr first if enabled
                rededr_config = self.config['analysis']['dynamic'].get('rededr', {})
                if rededr_config.get('enabled'):
                    self.logger.debug("Initializing RedEdr analyzer")
                    try:
                        target_name = target.split('\\')[-1]  # Extract filename from path
                        rededr = RedEdrAnalyzer(self.config)
                        if rededr.start_tool(target_name):
                            etw_wait_time = rededr_config.get('etw_wait_time', 5)
                            self.logger.debug(f"RedEdr initialized, waiting {etw_wait_time} seconds for ETW setup")
                            time.sleep(etw_wait_time)
                        else:
                            self.logger.error("Failed to start RedEdr")
                            results['rededr'] = {
                                'status': 'error',
                                'error': 'Failed to start tool'
                            }
                    except Exception as e:
                        self.logger.error(f"Error initializing RedEdr: {e}")
                        results['rededr'] = {
                            'status': 'error',
                            'error': str(e)
                        }
                
                # 2. Try to start and validate target process
                try:
                    process, pid = self._validate_process(target, is_pid, cmd_args)
                except Exception as e:
                    early_termination = True
                    error_msg = str(e)
                    self.logger.error(f"Process startup failed: {error_msg}")
                    
                    if "terminated after" in error_msg:
                        init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
                        results['status'] = 'early_termination'
                        results['error'] = {
                            'message': f'Process terminated before initialization period ({init_wait}s)',
                            'details': error_msg,
                            'termination_time': error_msg.split('terminated after ')[1].split(' seconds')[0],
                            'cmd_args': cmd_args if cmd_args else []
                        }
                    else:
                        results['status'] = 'error'
                        results['error'] = {
                            'message': 'Process startup failed',
                            'details': error_msg,
                            'cmd_args': cmd_args if cmd_args else []
                        }
                    
                    results['analysis_metadata'] = {
                        'total_duration': time.time() - start_time,
                        'timestamp': time.time(),
                        'early_termination': early_termination,
                        'analysis_started': False,
                        'cmd_args': cmd_args if cmd_args else []
                    }
                    
                    return results

                # 3. Run analyzers if process started successfully
                if not early_termination:
                    # Run all analyzers except RedEdr
                    regular_analyzers = {k: v for k, v in self.dynamic_analyzers.items() 
                                       if k != 'rededr'}
                    other_results = self._run_analyzers(regular_analyzers, pid, 'dynamic')
                    results.update(other_results)

                    # 4. Capture process output before cleanup
                    if process:
                        self.logger.debug("Capturing process output")
                        try:
                            # Read all output with a timeout, ensuring the process doesn't block indefinitely
                            stdout, stderr = process.communicate(timeout=1)
                            results['process_output'] = {
                                'stdout': stdout.strip() if stdout else '',
                                'stderr': stderr.strip() if stderr else '',
                                'had_output': bool(stdout.strip() or stderr.strip()),
                                'output_truncated': False  # No truncation since we capture everything till now
                            }
                            self.logger.debug("Process output captured successfully")
                        except subprocess.TimeoutExpired:
                            # If timeout, kill the process and capture everything up to this point
                            self.logger.debug("Output capture timed out; killing the process")
                            self._cleanup_process(process, is_pid)
                            stdout, stderr = process.communicate()  # Retrieve all output till now
                            results['process_output'] = {
                                'stdout': stdout.strip() if stdout else '',
                                'stderr': stderr.strip() if stderr else '',
                                'had_output': bool(stdout.strip() or stderr.strip()),
                                'output_truncated': False,  # Still no truncation, as we have all output till now
                                'note': 'Process killed after timeout'
                            }
                        except Exception as e:
                            # Handle other exceptions during output capture
                            
                            self.logger.error(f"Error capturing process output: {e}")
                            results['process_output'] = {
                                'error': str(e),
                                'had_output': False,
                                'output_truncated': False
                            }

                        # Cleanup after capturing output
                    
                    # 6. Get RedEdr results if it was started
                    if rededr:
                        self.logger.debug("Getting RedEdr events")
                        results['rededr'] = rededr.get_results()
                        
                        #self.logger.debug(results['rededr'].get('findings'))
                        
                        self.logger.debug("Cleaning up RedEdr")
                        try:
                            rededr.cleanup()
                        except Exception as e:
                            self.logger.error(f"Error cleaning up RedEdr: {e}")
                
            else:  # PID-based analysis
                process, pid = self._validate_process(target, is_pid)
                results = self._run_analyzers(self.dynamic_analyzers, pid, 'dynamic')
            
            # Add analysis metadata
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time(),
                'early_termination': early_termination,
                'analysis_started': not early_termination,
                'cmd_args': cmd_args if cmd_args else []
            }
                
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            results['status'] = 'error'
            results['error'] = {
                'message': 'Analysis failed',
                'details': str(e),
                'cmd_args': cmd_args if cmd_args else []
            }
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time(),
                'error': str(e),
                'early_termination': early_termination,
                'analysis_started': False,
                'cmd_args': cmd_args if cmd_args else []
            }
                
        self.logger.debug(f"Dynamic analysis completed in {time.time() - start_time:.2f} seconds")
        return results
    
    def _validate_process(self, target, is_pid: bool, cmd_args: list = None) -> tuple:
        """
        Validate and prepare process for dynamic analysis.
        
        Args:
            target: Process ID or file path
            is_pid: Whether target is a process ID
            cmd_args: Optional list of command line arguments
                
        Returns:
            tuple: (psutil.Process, process ID)
        """
        if is_pid:
            self.logger.debug(f"Validating PID: {target}")
            try:
                pid = int(target)
                process = psutil.Process(pid)
                if not process.is_running():
                    raise Exception(f"Process with PID {pid} is not running")
                self.logger.debug(f"Successfully validated PID {pid}, process is running")
                return process, pid
            except (ValueError, psutil.NoSuchProcess) as e:
                self.logger.error(f"Invalid or non-existent PID {target}: {e}")
                raise Exception(f"Invalid or non-existent PID: {e}")
        else:
            # Prepare command with arguments
            command = [target]
            if cmd_args:
                command.extend(cmd_args)
                
            self.logger.debug(f"Starting new process: {command}")
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            try:
                # Create process with non-blocking pipes
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                    bufsize=1,  # Line buffered
                    text=True,  # Use text mode instead of universal_newlines

                )
                pid = process.pid
                self.logger.debug(f"Process started with PID: {pid}")

                try:
                    ps_process = psutil.Process(pid)
                    if not ps_process.is_running():
                        raise Exception(f"Process {pid} terminated immediately")
                    
                    # Get init wait time from config
                    init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
                    self.logger.debug(f"Waiting {init_wait} seconds for process initialization")
                    
                    # Check process status during wait time
                    wait_interval = 0.1  # Check every 100ms
                    elapsed = 0
                    while elapsed < init_wait:
                        time.sleep(wait_interval)
                        elapsed += wait_interval
                        
                        if not ps_process.is_running():
                            cmd_str = ' '.join(command)
                            raise Exception(f"Process terminated after {elapsed:.1f} seconds (Command: {cmd_str})")
                    
                    # Final check
                    if not ps_process.is_running():
                        raise Exception(f"Process terminated during initialization")
                        
                    return process, pid
                    
                except psutil.NoSuchProcess:
                    cmd_str = ' '.join(command)
                    raise Exception(f"Process {pid} terminated immediately after start (Command: {cmd_str})")
                except Exception as e:
                    # Clean up the process handles if it somehow still exists
                    if process:
                        try:
                            process.kill()
                        except:
                            pass
                    raise e
            except Exception as e:
                raise Exception(f"Failed to start process: {str(e)}")

    def _cleanup_process(self, process, is_pid: bool):
        """
        Clean up process and its children after analysis.
        Handles cases where processes may have already terminated.
        
        Args:
            process: Process to clean up
            is_pid: Whether process was created by us
        """
        if process and not is_pid:
            self.logger.debug(f"Starting cleanup of process PID: {process.pid}")
            try:
                # First check if the process still exists
                try:
                    parent = psutil.Process(process.pid)
                    if not parent.is_running():
                        self.logger.error(f"Process {process.pid} has already terminated")
                        return
                except psutil.NoSuchProcess:
                    self.logger.error(f"Process {process.pid} no longer exists")
                    return
                
                # Get children before terminating parent
                try:
                    children = parent.children(recursive=True)
                    child_count = len(children)
                    self.logger.debug(f"Found {child_count} child processes to terminate")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.error(f"Failed to get child processes: {e}")
                    children = []
                
                # Terminate children
                for child in children:
                    try:
                        if child.is_running():
                            self.logger.info(f"Terminating child process: {child.pid}")
                            child.terminate()
                            # Give it a moment to terminate gracefully
                            child.wait(timeout=3)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                        self.logger.error(f"Failed to terminate child {child.pid}: {e}")
                        # Try to force kill if termination failed
                        try:
                            if child.is_running():
                                self.logger.debug(f"Force killing child process: {child.pid}")
                                child.kill()
                        except psutil.NoSuchProcess as kill_error:
                            self.logger.error(f"Child process disappeared during kill: {kill_error}")
                
                # Finally terminate parent
                try:
                    if parent.is_running():
                        self.logger.info(f"Terminating parent process: {parent.pid}")
                        parent.terminate()
                        parent.wait(timeout=3)
                        
                        # Force kill if still running
                        if parent.is_running():
                            self.logger.debug(f"Force killing parent process: {parent.pid}")
                            parent.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                    self.logger.error(f"Failed to terminate parent process: {e}")
                
                self.logger.debug("Process cleanup completed")
                
            except Exception as e:
                # Log unexpected errors as errors
                self.logger.error(f"Error during process cleanup: {str(e)}", exc_info=True)
                # Still don't raise the exception since cleanup errors shouldn't halt the analysis

