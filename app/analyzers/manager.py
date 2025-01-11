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
        'checkplz': CheckPlzAnalyzer
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

        self.logger.debug(f"Running {len(analyzers)} {analysis_type} analyzers")
        
        for name, analyzer in analyzers.items():
            try:
                self.logger.debug(f"Starting {analysis_type} analyzer: {name}")
                start_time = time.time()
                
                analyzer.analyze(target)
                results[name] = analyzer.get_results()
                
                duration = time.time() - start_time
                self.logger.debug(f"{analysis_type} analyzer {name} completed in {duration:.2f} seconds")
                self.logger.debug(f"Results from {name}: {results[name]}")
                
            except Exception as e:
                self.logger.error(f"Error in {analysis_type} analyzer {name}: {str(e)}", exc_info=True)
                results[name] = {
                    'status': 'error',
                    'error': str(e)
                }
        
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
        self.logger.debug(f"Statuc analysis completed in {time.time() - start_time:.2f} seconds")

        return results

    def _validate_process(self, target, is_pid: bool) -> tuple:
        """
        Validate and prepare process for dynamic analysis.
        
        Args:
            target: Process ID or file path
            is_pid: Whether target is a process ID
            
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
            self.logger.debug(f"Starting new process for target: {target}")
            process = subprocess.Popen(
                target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.logger.debug(f"Process started with PID: {process.pid}")
            self.logger.debug("Waiting 5 seconds for process initialization")
            time.sleep(5)
            return process, process.pid

    def _cleanup_process(self, process, is_pid: bool):
        """
        Clean up process and its children after analysis.
        
        Args:
            process: Process to clean up
            is_pid: Whether process was created by us
        """
        if process and not is_pid:
            self.logger.debug(f"Cleaning up created process with PID: {process.pid}")
            try:
                parent = psutil.Process(process.pid)
                
                child_count = len(parent.children(recursive=True))
                self.logger.debug(f"Found {child_count} child processes to terminate")
                
                for child in parent.children(recursive=True):
                    self.logger.debug(f"Terminating child process: {child.pid}")
                    child.terminate()
                    
                self.logger.debug(f"Terminating parent process: {parent.pid}")
                parent.terminate()
                self.logger.debug("Process cleanup completed successfully")
                
            except Exception as e:
                self.logger.error(f"Error during process cleanup: {str(e)}", exc_info=True)

    def run_dynamic_analysis(self, target, is_pid: bool = False) -> dict:
        """Run dynamic analysis with timing"""
        self.logger.debug(f"Starting dynamic analysis - Target: {target}, is_pid: {is_pid}")
        start_time = time.time()
        results = {}
        process = None
        rededr = None
        
        try:
            if not is_pid:
                # 1. Start RedEdr first if enabled
                if self.config['analysis']['dynamic'].get('rededr', {}).get('enabled'):
                    self.logger.debug("Initializing RedEdr analyzer")
                    try:
                        target_name = target.split('\\')[-1]  # Extract filename from path
                        rededr = RedEdrAnalyzer(self.config)
                        if rededr.start_tool(target_name):
                            self.logger.debug("RedEdr initialized, waiting 10 seconds for ETW setup")
                            time.sleep(10)  # Wait for RedEdr to initialize ETW
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
                
                # 2. Now start the target process
                self.logger.debug("Starting target process")
                process, pid = self._validate_process(target, is_pid)
                self.logger.debug(f"Target process started with PID: {pid}")
                
                # 3. Run other dynamic analyzers
                regular_analyzers = {k: v for k, v in self.dynamic_analyzers.items() 
                                   if k != 'rededr'}
                
                other_results = self._run_analyzers(regular_analyzers, pid, 'dynamic')
                results.update(other_results)
                
                # 4. Cleanup everything
                if process:
                    self.logger.debug("Cleaning up target process")
                    self._cleanup_process(process, is_pid)
                
                if rededr:
                    self.logger.debug("Getting RedEdr events")
                    results['rededr'] = rededr.get_results()
                    self.logger.debug("RedEdr findings:")
                    self.logger.debug(results['rededr'].get('findings'))
                    
                    self.logger.debug("Cleaning up RedEdr")
                    try:
                        rededr.cleanup()
                    except Exception as e:
                        self.logger.error(f"Error cleaning up RedEdr: {e}")
            else:  # PID-based analysis
                process, pid = self._validate_process(target, is_pid)
                results = self._run_analyzers(self.dynamic_analyzers, pid, 'dynamic')
                
            # Add analysis timing metadata
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time()
            }
                
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            results['process'] = {
                'status': 'error',
                'error': str(e)
            }
            results['analysis_metadata'] = {
                'total_duration': time.time() - start_time,
                'timestamp': time.time(),
                'error': str(e)
            }
                
        self.logger.debug(f"Dynamic analysis completed in {time.time() - start_time:.2f} seconds")
        return results