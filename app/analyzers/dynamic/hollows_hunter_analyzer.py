import subprocess
import json
import logging
from .base import DynamicAnalyzer

class HollowsHunterAnalyzer(DynamicAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.logger = logging.getLogger("LitterBox")

    def analyze(self, directory):
        try:
            tool_config = self.config['analysis']['dynamic']['hollows_hunter']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                directory=directory
            )
                        
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            if stderr:
                self.logger.warning(f"HollowsHunter stderr: {stderr}")
            
            json_start = stdout.find('{')
            if json_start != -1:
                self.results = json.loads(stdout[json_start:])
                self.results['status'] = 'completed'
            else:
                self.results = {'status': 'failed', 'error': 'No JSON found in output'}
            
        except Exception as e:
            self.logger.error(f"Error in HollowsHunter analysis: {str(e)}")
            self.results = {'status': 'error', 'error': str(e)}

    def get_results(self):
        return self.results

    def cleanup(self):
        pass