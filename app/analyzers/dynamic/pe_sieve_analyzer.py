# app/analyzers/dynamic/pe_sieve_analyzer.py
import subprocess
from .base import DynamicAnalyzer

class PESieveAnalyzer(DynamicAnalyzer):
    def analyze(self, pid):
        self.pid = pid
        try:
            tool_config = self.config['analysis']['dynamic']['pe_sieve']
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
            
            stdout, stderr = process.communicate(timeout=tool_config['timeout'])
            
            # Consider successful if we got output
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
        """Parse pe-sieve output according to the actual format"""
        findings = {
            'total_scanned': 0,
            'skipped': 0,
            'hooked': 0,
            'replaced': 0,
            'hdrs_modified': 0,
            'iat_hooks': 0,
            'implanted': 0,
            'implanted_pe' : 0,
            'implanted_shc' : 0,
            'unreachable': 0,
            'other': 0,
            'total_suspicious': 0,
            'raw_output': output  # Store raw output for reference

        }
        
        try:
            for line in output.split('\n'):
                line = line.strip()
                if line:
                    if "Total scanned:" in line:
                        findings['total_scanned'] = int(line.split(':')[1].strip())
                    elif "Skipped:" in line:
                        findings['skipped'] = int(line.split(':')[1].strip())
                    elif "Hooked:" in line:
                        findings['hooked'] = int(line.split(':')[1].strip())
                    elif "Replaced:" in line:
                        findings['replaced'] = int(line.split(':')[1].strip())
                    elif "Hdrs Modified:" in line:
                        findings['hdrs_modified'] = int(line.split(':')[1].strip())
                    elif "IAT Hooks:" in line:
                        findings['iat_hooks'] = int(line.split(':')[1].strip())
                    elif "Implanted:" in line:
                        findings['implanted'] = int(line.split(':')[1].strip())
                    elif "Implanted PE:" in line:
                        findings['implanted_pe'] = int(line.split(':')[1].strip())
                    elif "Implanted shc:" in line:
                        findings['implanted_shc'] = int(line.split(':')[1].strip())
                    elif "Unreachable files:" in line:
                        findings['unreachable'] = int(line.split(':')[1].strip())
                    elif "Other:" in line:
                        findings['other'] = int(line.split(':')[1].strip())
                    elif "Total suspicious:" in line:
                        findings['total_suspicious'] = int(line.split(':')[1].strip())
        except:
            pass
            
        return findings