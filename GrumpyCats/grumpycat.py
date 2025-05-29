import argparse
import hashlib
import json
import logging
import os
import re
import requests
import sys
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Union, BinaryIO, Any, Tuple
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urljoin


class LitterBoxError(Exception):
    """Base exception for LitterBox client errors"""
    pass


class LitterBoxAPIError(LitterBoxError):
    """Exception for API-related errors"""
    def __init__(self, message: str, status_code: Optional[int] = None, response: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class LitterBoxClient:
    """A Python client for interacting with the LitterBox malware analysis sandbox API."""
    
    def __init__(self, 
                 base_url: str = "http://127.0.0.1:1337",
                 timeout: int = 120,
                 max_retries: int = 3,
                 verify_ssl: bool = True,
                 logger: Optional[logging.Logger] = None,
                 proxy_config: Optional[Dict] = None,
                 headers: Optional[Dict] = None):
        """Initialize the LitterBox client."""
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.logger = logger or logging.getLogger(__name__)
        self.proxy_config = proxy_config
        self.headers = headers or {}

        self.session = self._create_session(max_retries)

    def _create_session(self, max_retries: int) -> requests.Session:
        """Create and configure requests session with retries."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self.proxy_config:
            session.proxies.update(self.proxy_config)
        if not self.verify_ssl:
            session.verify = False
        session.headers.update(self.headers)
        
        return session

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling."""
        url = urljoin(self.base_url, endpoint)
        try:
            kwargs.setdefault('timeout', self.timeout)
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            try:
                error_data = response.json()
            except:
                error_data = {'error': response.text}
            raise LitterBoxAPIError(
                f"API error: {error_data.get('error', 'Unknown error')}",
                status_code=response.status_code,
                response=error_data
            )
        except requests.exceptions.RequestException as e:
            raise LitterBoxError(f"Request failed: {str(e)}")

    def _validate_command_args(self, cmd_args: Optional[List[str]]) -> Dict:
        """Validate and prepare command line arguments."""
        data = {}
        if cmd_args is not None:
            if not isinstance(cmd_args, list):
                raise ValueError("Arguments must be provided as a list")
            if not all(isinstance(arg, str) for arg in cmd_args):
                raise ValueError("All arguments must be strings")
            if any(any(char in arg for char in [';', '&', '|']) for arg in cmd_args):
                raise ValueError("Invalid argument characters detected")
            data['args'] = cmd_args
        return data

    def _validate_analysis_type(self, analysis_type: str, valid_types: List[str]):
        """Validate analysis type."""
        if analysis_type not in valid_types:
            raise ValueError(f"analysis_type must be one of: {', '.join(valid_types)}")

    def _prepare_file_upload(self, file_path: Union[str, Path, BinaryIO], file_name: Optional[str] = None):
        """Prepare file for upload."""
        if isinstance(file_path, (str, Path)):
            path = Path(file_path)
            if not path.exists():
                raise LitterBoxError(f"File not found: {path}")
            return {'file': (file_name or path.name, open(path, 'rb'), 'application/octet-stream')}
        else:
            if not file_name:
                raise ValueError("file_name is required when uploading file-like objects")
            return {'file': (file_name, file_path, 'application/octet-stream')}

    def upload_file(self, file_path: Union[str, Path, BinaryIO], file_name: Optional[str] = None) -> Dict:
        """Upload a file for analysis."""
        files = self._prepare_file_upload(file_path, file_name)
        response = self._make_request('POST', '/upload', files=files)
        return response.json()

    def analyze_file(self, target: str, analysis_type: str, cmd_args: Optional[List[str]] = None,
                    wait_for_completion: bool = True, verify_file: bool = False) -> Dict:
        """Run analysis on a file or process."""
        self._validate_analysis_type(analysis_type, ['static', 'dynamic'])
        
        # Validate PID for dynamic analysis
        if analysis_type == 'dynamic' and target.isdigit():
            self.validate_process(target)
        elif analysis_type == 'static' and target.isdigit():
            raise ValueError("Cannot perform static analysis on PID")
        
        # For non-PID targets, verify the file exists first if requested
        if not target.isdigit() and verify_file:
            try:
                self._make_request('GET', f'/api/results/{target}/info')
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    raise LitterBoxError(f"File {target} not found or not yet available")

        params = {'wait': '1' if wait_for_completion else '0'}
        data = self._validate_command_args(cmd_args)
        
        response = self._make_request('POST', f'/analyze/{analysis_type}/{target}', 
                                     params=params, json=data)
        
        # Handle early termination case (202 status)
        if response.status_code == 202:
            return response.json()
            
        result = response.json()
        
        # Handle error case
        if result.get('status') == 'error':
            error_info = result.get('error', {})
            if isinstance(error_info, str):
                error_info = {'message': error_info}
            return {
                'status': 'error',
                'error': error_info.get('message', 'Analysis failed'),
                'details': error_info.get('details')
            }
            
        return result

    def get_results(self, target: str, analysis_type: str) -> Dict:
        """Get results for a specific analysis."""
        self._validate_analysis_type(analysis_type, ['static', 'dynamic', 'info'])
        response = self._make_request('GET', f'/api/results/{target}/{analysis_type}')
        return response.json()

    def get_files_summary(self) -> Dict:
        """Get summary of all analyzed files and processes."""
        response = self._make_request('GET', '/files')
        return response.json()

    def run_blender_scan(self) -> Dict:
        """Run a system-wide Blender scan."""
        data = {"operation": "scan"}
        response = self._make_request('POST', '/blender', json=data)
        return response.json()

    def compare_with_blender(self, file_hash: str) -> Dict:
        """Compare a file's analysis results with current system state."""
        params = {'hash': file_hash}
        response = self._make_request('GET', '/blender', params=params)
        return response.json()

    def cleanup(self, include_uploads: bool = True, include_results: bool = True, 
               include_analysis: bool = True) -> Dict:
        """Clean up analysis artifacts and uploaded files."""
        data = {
            'cleanup_uploads': include_uploads,
            'cleanup_results': include_results,
            'cleanup_analysis': include_analysis
        }
        response = self._make_request('POST', '/cleanup', json=data)
        return response.json()

    def check_health(self) -> Dict:
        """Check the health status of the LitterBox service."""
        response = self._make_request('GET', '/health')
        return response.json()

    def delete_file(self, file_hash: str) -> Dict:
        """Delete a file and its analysis results."""
        response = self._make_request('DELETE', f'/file/{file_hash}')
        return response.json()

    def validate_process(self, pid: Union[str, int]) -> Dict:
        """Validate if a process ID exists and is accessible."""
        response = self._make_request('POST', f'/validate/{pid}')
        return response.json()

    def _validate_doppelganger_params(self, analysis_type: str, operation: str, 
                                     file_hash: Optional[str], folder_path: Optional[str]):
        """Validate doppelganger operation parameters."""
        if analysis_type not in ['blender', 'fuzzy']:
            raise ValueError("analysis_type must be either 'blender' or 'fuzzy'")

        if operation == 'scan' and analysis_type != 'blender':
            raise ValueError("scan operation is only available for blender analysis")
        
        if operation == 'create_db' and not folder_path:
            raise ValueError("folder_path is required for create_db operation")
        
        if operation == 'analyze' and not file_hash:
            raise ValueError("file_hash is required for analyze operation")

    def analyze_with_doppelganger(self, analysis_type: str, operation: str,
                                 file_hash: Optional[str] = None, folder_path: Optional[str] = None,
                                 extensions: Optional[List[str]] = None, threshold: int = 1) -> Dict:
        """Unified method for doppelganger analysis operations."""
        self._validate_doppelganger_params(analysis_type, operation, file_hash, folder_path)

        # For GET requests (comparisons)
        if file_hash and operation != 'analyze':
            params = {'type': analysis_type, 'hash': file_hash}
            response = self._make_request('GET', '/doppelganger', params=params)
            return response.json()

        # For POST requests
        data = {'type': analysis_type, 'operation': operation}

        if operation == 'create_db':
            data['folder_path'] = folder_path
            if extensions:
                data['extensions'] = extensions
        elif operation == 'analyze':
            data['hash'] = file_hash
            data['threshold'] = threshold

        response = self._make_request('POST', '/doppelganger', json=data)
        return response.json()

    def run_system_scan(self) -> Dict:
        """Run a system-wide scan using doppelganger blender analysis."""
        return self.analyze_with_doppelganger('blender', 'scan')

    def compare_against_system(self, file_hash: str, analysis_type: str = 'blender') -> Dict:
        """Compare a file against system state using doppelganger."""
        return self.analyze_with_doppelganger(analysis_type, 'compare', file_hash=file_hash)

    def create_fuzzy_db(self, folder_path: str, extensions: Optional[List[str]] = None) -> Dict:
        """Create fuzzy hash database using doppelganger."""
        return self.analyze_with_doppelganger('fuzzy', 'create_db', 
                                            folder_path=folder_path, extensions=extensions)

    def analyze_fuzzy(self, file_hash: str, threshold: int = 1) -> Dict:
        """Analyze a file using fuzzy hash comparison."""
        return self.analyze_with_doppelganger('fuzzy', 'analyze', 
                                            file_hash=file_hash, threshold=threshold)

    def get_report(self, target: str, download: bool = False) -> Union[str, bytes]:
        """Get analysis report for a file or process."""
        params = {'download': 'true' if download else 'false'}
        response = self._make_request('GET', f'/api/report/{target}', params=params)
        return response.content if download else response.text

    def _extract_filename_from_response(self, response: requests.Response, target: str) -> str:
        """Extract filename from Content-Disposition header or create default."""
        content_disposition = response.headers.get('Content-Disposition', '')
        
        if 'filename=' in content_disposition:
            match = re.search(r'filename="([^"]+)"', content_disposition)
            if match:
                return match.group(1)
        
        # Default filename
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"Report_{target}_{timestamp}.html"

    def download_report(self, target: str, output_path: Optional[str] = None) -> str:
        """Download analysis report and save it to disk."""
        response = self._make_request('GET', f'/api/report/{target}', 
                                     params={'download': 'true'}, stream=True)
        
        filename = self._extract_filename_from_response(response, target)
        
        # Determine final output path
        if output_path:
            save_path = os.path.join(output_path, filename) if os.path.isdir(output_path) else output_path
        else:
            save_path = filename
        
        try:
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            self.logger.info(f"Report saved to {save_path}")
            return save_path
        except Exception as e:
            raise LitterBoxError(f"Failed to save report: {str(e)}")

    def open_report_in_browser(self, target: str) -> bool:
        """Generate a report and open it in the default web browser."""
        try:
            report_content = self.get_report(target, download=False)
            
            fd, path = tempfile.mkstemp(suffix='.html')
            try:
                with os.fdopen(fd, 'w') as tmp:
                    tmp.write(report_content)
                
                webbrowser.open('file://' + path)
                self.logger.info(f"Report opened in browser from {path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to open report in browser: {str(e)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            return False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


def create_arg_parser():
    """Create and configure the argument parser for command line usage."""
    parser = argparse.ArgumentParser(
        description="LitterBox Malware Analysis Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload and analyze a file
  %(prog)s upload malware.exe --analysis static dynamic
  
  # Analyze a running process
  %(prog)s analyze-pid 1234 --wait
  
  # Run Doppelganger blender scan
  %(prog)s doppelganger-scan --type blender
  
  # Run Doppelganger FuzzyHash analysis
  %(prog)s doppelganger abc123def --type fuzzy
  
  # Create fuzzy hash database
  %(prog)s doppelganger-db --folder /path/to/files --extensions .exe .dll
  
  # Get analysis results
  %(prog)s results abc123def --type static
    
  # Download a HTML report
  %(prog)s report abc123def --download --output /path/to/reports/
  
  # Open a report in browser
  %(prog)s report abc123def --browser
  
  # Clean up analysis artifacts
  %(prog)s cleanup --all
"""
    )
    
    # General options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--url', default='http://127.0.0.1:1337', help='LitterBox server URL')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://proxy:8080)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload file for analysis')
    upload_parser.add_argument('file', help='File to upload')
    upload_parser.add_argument('--name', help='Custom name for the file')
    upload_parser.add_argument('--analysis', nargs='+', choices=['static', 'dynamic'],
                             help='Run analysis after upload')
    upload_parser.add_argument('--args', nargs='+', help='Command line arguments for dynamic analysis')
    
    # Analyze PID command
    analyze_pid_parser = subparsers.add_parser('analyze-pid', help='Analyze running process')
    analyze_pid_parser.add_argument('pid', type=int, help='Process ID to analyze')
    analyze_pid_parser.add_argument('--wait', action='store_true', help='Wait for analysis completion')
    analyze_pid_parser.add_argument('--args', nargs='+', help='Command line arguments')
    
    # Results command
    results_parser = subparsers.add_parser('results', help='Get analysis results')
    results_parser.add_argument('target', help='File hash or PID')
    results_parser.add_argument('--type', choices=['static', 'dynamic', 'info'],
                              required=True, help='Type of results to retrieve')
    
    # Files summary command
    subparsers.add_parser('files', help='Get summary of all analyzed files')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate analysis report')
    report_parser.add_argument('target', help='File hash or process ID')
    report_parser.add_argument('--download', action='store_true', help='Download the report')
    report_parser.add_argument('--output', help='Output path for downloaded report')
    report_parser.add_argument('--browser', action='store_true', help='Open report in browser')

    # Doppelganger scan command
    doppelganger_scan_parser = subparsers.add_parser('doppelganger-scan', help='Run doppelganger system scan')
    doppelganger_scan_parser.add_argument('--type', choices=['blender', 'fuzzy'], 
                                        default='blender', help='Type of scan to perform')
    
    # Doppelganger analyze command
    doppelganger_parser = subparsers.add_parser('doppelganger', help='Run doppelganger analysis')
    doppelganger_parser.add_argument('hash', help='File hash to analyze')
    doppelganger_parser.add_argument('--type', choices=['blender', 'fuzzy'], 
                                  required=True, help='Type of analysis to perform')
    doppelganger_parser.add_argument('--threshold', type=int, default=1,
                                  help='Similarity threshold for fuzzy analysis')
    
    # Doppelganger database command
    db_parser = subparsers.add_parser('doppelganger-db', help='Create doppelganger fuzzy database')
    db_parser.add_argument('--folder', required=True, help='Folder path to process')
    db_parser.add_argument('--extensions', nargs='+', help='File extensions to include')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up analysis artifacts')
    cleanup_parser.add_argument('--all', action='store_true', help='Clean all artifacts')
    cleanup_parser.add_argument('--uploads', action='store_true', help='Clean upload directory')
    cleanup_parser.add_argument('--results', action='store_true', help='Clean results directory')
    cleanup_parser.add_argument('--analysis', action='store_true', help='Clean analysis artifacts')
    
    # Health check command
    subparsers.add_parser('health', help='Check service health')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete file and its results')
    delete_parser.add_argument('hash', help='File hash to delete')
    
    return parser


def handle_analysis_result(result: Dict, analysis_type: str):
    """Handle and display analysis results consistently."""
    if result.get('status') == 'early_termination':
        print("Process terminated early:")
        print(f"Error: {result.get('error')}")
        details = result.get('details', {})
        print("Details:")
        print(f"  Termination time: {details.get('termination_time')}")
        print(f"  Init time: {details.get('init_time')}")
        print(f"  Message: {details.get('message')}")
    elif result.get('status') == 'error':
        print(f"Analysis failed: {result.get('error')}")
        if 'details' in result:
            print(f"Details: {result['details']}")
    else:
        print(json.dumps(result, indent=2))


def setup_client_from_args(args) -> LitterBoxClient:
    """Create client instance from command line arguments."""
    client_kwargs = {
        'base_url': args.url,
        'timeout': args.timeout,
        'verify_ssl': not args.no_verify_ssl,
        'logger': logging.getLogger('litterbox'),
    }
    
    if args.proxy:
        client_kwargs['proxy_config'] = {'http': args.proxy, 'https': args.proxy}
    
    return LitterBoxClient(**client_kwargs)


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        client = setup_client_from_args(args)
        
        if args.command == 'upload':
            result = client.upload_file(args.file, file_name=args.name)
            file_hash = result['file_info']['md5']
            print(f"File uploaded successfully. Hash: {file_hash}")
            
            if args.analysis:
                for analysis_type in args.analysis:
                    print(f"Running {analysis_type} analysis...")
                    analysis_args = args.args if analysis_type == 'dynamic' else None
                    result = client.analyze_file(file_hash, analysis_type, 
                                               cmd_args=analysis_args, wait_for_completion=True)
                    handle_analysis_result(result, analysis_type)
        
        elif args.command == 'analyze-pid':
            print(f"Analyzing process {args.pid}...")
            result = client.analyze_file(str(args.pid), 'dynamic', 
                                       cmd_args=args.args, wait_for_completion=args.wait)
            handle_analysis_result(result, 'dynamic')
        
        elif args.command == 'results':
            result = client.get_results(args.target, args.type)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'files':
            result = client.get_files_summary()
            print(json.dumps(result, indent=2))

        elif args.command == 'report':
            if args.browser:
                print(f"Opening report for {args.target} in browser...")
                if not client.open_report_in_browser(args.target):
                    print("Failed to open report in browser.")
                    sys.exit(1)
            elif args.download:
                print(f"Downloading report for {args.target}...")
                output_path = client.download_report(args.target, args.output)
                print(f"Report saved to: {output_path}")
            else:
                report = client.get_report(args.target)
                print(report)
        
        elif args.command == 'doppelganger-scan':
            print(f"Running doppelganger scan with type: {args.type}")
            result = client.analyze_with_doppelganger(args.type, 'scan')
            print(json.dumps(result, indent=2))
            
        elif args.command == 'doppelganger':
            print(f"Running doppelganger analysis with type: {args.type}")
            result = client.analyze_with_doppelganger(args.type, 'analyze', 
                                                    file_hash=args.hash, threshold=args.threshold)
            print(json.dumps(result, indent=2))
            
        elif args.command == 'doppelganger-db':
            print("Creating doppelganger fuzzy database...")
            result = client.analyze_with_doppelganger('fuzzy', 'create_db',
                                                    folder_path=args.folder, extensions=args.extensions)
            print(json.dumps(result, indent=2))

        elif args.command == 'cleanup':
            if args.all:
                args.uploads = args.results = args.analysis = True
            result = client.cleanup(include_uploads=args.uploads, include_results=args.results,
                                  include_analysis=args.analysis)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'health':
            result = client.check_health()
            print(json.dumps(result, indent=2))
        
        elif args.command == 'delete':
            result = client.delete_file(args.hash)
            print(json.dumps(result, indent=2))
        
        else:
            parser.print_help()
    
    except LitterBoxAPIError as e:
        logging.error(f"API Error (Status {e.status_code}): {str(e)}")
        if args.debug:
            logging.debug(f"Response data: {e.response}")
        sys.exit(1)
    except LitterBoxError as e:
        logging.error(f"Client Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected Error: {str(e)}")
        if args.debug:
            logging.exception("Detailed error information:")
        sys.exit(1)
    finally:
        client.session.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)