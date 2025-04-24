import subprocess
import re
import os
from .base import StaticAnalyzer

class YaraStaticAnalyzer(StaticAnalyzer):
    def analyze(self, file_path):
        """
        Analyzes a file using YARA rules specified in the config.
        """
        try:
            tool_config = self.config['analysis']['static']['yara']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                rules_path=tool_config['rules_path'],
                file_path=file_path
            )

            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=tool_config['timeout'])
            matches = self._parse_output(stdout)

            # Map the matched strings to the rule definitions
            self._map_output_to_rule_strings(matches)

            self.results = {
                'status': 'completed' if process.returncode == 0 else 'failed',
                'scan_info': {
                    'target': file_path,
                    'rules_file': tool_config['rules_path']
                },
                'matches': matches,
                'errors': stderr if stderr else None
            }

        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def _parse_rule_strings(self, rule_filepath, rule_name):
        """
        Parse a YARA rule file to extract string definitions for a specific rule.
        """
        strings = {}
        try:
            if not os.path.exists(rule_filepath):
                return strings
                
            with open(rule_filepath, 'r') as f:
                lines = f.readlines()

            inside_rule = False
            strings_section = False
            for line in lines:
                stripped = line.strip()

                # Match rule line with various formats
                if re.match(r'^rule\s+' + re.escape(rule_name) + r'\s*($|\{)', stripped):
                    inside_rule = True
                elif inside_rule and stripped.startswith("strings:"):
                    strings_section = True
                elif inside_rule and strings_section and stripped.startswith("$"):
                    # Extract string identifier and value with more flexible pattern
                    match = re.match(r'^\$([a-zA-Z0-9_]+)\s*=\s*(.+)$', stripped)
                    if match:
                        identifier = match.group(1)
                        value = match.group(2).strip()
                        # Remove trailing comments if any
                        value = re.sub(r'\s+//.+$', '', value)
                        strings[identifier] = value
                elif inside_rule and stripped.startswith("condition:"):
                    strings_section = False
                elif inside_rule and stripped == "}" and not strings_section:
                    inside_rule = False

        except Exception as e:
            print(f"Error parsing rule file: {e}")

        return strings

    def _map_output_to_rule_strings(self, matches):
        """
        Map strings from the YARA output to their definitions in the rule file.
        """
        for match in matches:
            rule_name = match['rule']
            rule_filepath = match['metadata'].get('rule_filepath')
            
            # If rule filepath is not found, try to find it by other means
            if not rule_filepath:
                # First try threat_name
                threat_name = match['metadata'].get('threat_name')
                if threat_name:
                    rule_filepath = self._get_rule_filepath(threat_name)
                
                # Then try description (common in BinaryAlert rules)
                if not rule_filepath and 'description' in match['metadata']:
                    rule_filepath = self._get_rule_filepath_from_description(match['metadata']['description'])
                
                # Finally try rule name itself
                if not rule_filepath:
                    rule_filepath = self._get_rule_filepath_from_rule_name(rule_name)
                
                # Update metadata with found filepath
                if rule_filepath:
                    match['metadata']['rule_filepath'] = rule_filepath
                else:
                    continue  # Skip if no rule filepath found
            
            rule_strings = self._parse_rule_strings(rule_filepath, rule_name)

            for string in match['strings']:
                # Extract identifier without $ prefix
                identifier = string['identifier'].lstrip('$')
                if identifier in rule_strings:
                    # Replace raw data with mapped definition
                    string['data'] = rule_strings[identifier]

    def _parse_output(self, output):
        """
        Parse the YARA scan output and extract matches with their details.
        More flexible to handle different YARA output formats.
        """
        matches = []
        current_match = None
        current_strings = []
        lines = output.split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('YARA Scan Results') or line == 'Static pattern matching analysis results.':
                continue

            # More flexible rule match line detection
            if '[' in line and ']' in line and (re.search(r'\[\s*\w+\s*=', line) or ' matched ' in line):
                if current_match:
                    current_match['strings'] = current_strings
                    matches.append(current_match)
                    current_strings = []

                try:
                    # Handle different formats of rule match line
                    if ' matched ' in line:
                        # Format: "rule matched file"
                        parts = line.split(' matched ')
                        rule_name = parts[0].strip()
                        target = parts[1].strip()
                        metadata_str = ""
                    else:
                        # Format: "rule [metadata] file"
                        before_bracket = line.split(' [', 1)
                        rule_name = before_bracket[0].strip()
                        
                        # Extract everything between first [ and last ]
                        bracket_start = line.find('[')
                        bracket_end = line.rfind(']')
                        
                        if bracket_start != -1 and bracket_end != -1:
                            metadata_str = line[bracket_start+1:bracket_end]
                            target = line[bracket_end+1:].strip()
                        else:
                            metadata_str = ""
                            target = line.split(']')[-1].strip()

                    metadata = self._parse_metadata(metadata_str)
                    
                    # Try to get rule filepath using different methods
                    rule_filepath = None
                    if 'threat_name' in metadata:
                        rule_filepath = self._get_rule_filepath(metadata['threat_name'])
                    elif 'description' in metadata:
                        rule_filepath = self._get_rule_filepath_from_description(metadata['description'])
                    
                    if not rule_filepath:
                        rule_filepath = self._get_rule_filepath_from_rule_name(rule_name)
                    
                    metadata['rule_filepath'] = rule_filepath

                    current_match = {
                        'rule': rule_name,
                        'metadata': metadata,
                        'strings': [],
                        'target_file': target
                    }
                except Exception as e:
                    print(f"Error parsing rule line: {e}")
                    continue

            elif line.startswith('0x'):
                try:
                    # More flexible string match parsing
                    parts = re.split(r':\s+', line, 2)
                    if len(parts) >= 2:
                        offset = parts[0].strip()
                        
                        if len(parts) == 2:
                            # Format: "0xoffset: data"
                            identifier = "unnamed_string"
                            string_data = parts[1].strip()
                        else:
                            # Format: "0xoffset: $identifier: data"
                            identifier_parts = parts[1].strip().split(' ')
                            identifier = identifier_parts[0]
                            string_data = parts[2].strip() if len(parts) > 2 else ''

                        current_strings.append({
                            'offset': offset,
                            'identifier': identifier,
                            'data': string_data
                        })
                except Exception as e:
                    print(f"Error parsing string match: {e}")
                    continue

        if current_match:
            current_match['strings'] = current_strings
            matches.append(current_match)

        return matches

    def _parse_metadata(self, metadata_str):
        """
        Parse the metadata section from YARA rule match with support for different field naming conventions.
        """
        metadata = {}
        
        # Field mappings to normalize different naming conventions
        field_mappings = {
            'date': 'creation_date',
            'modified': 'last_modified',
            'description': 'description',
            'score': 'severity'
        }
        
        # Important fields to extract
        important_fields = {'id', 'creation_date', 'threat_name', 'severity', 'description', 'author', 'date', 'modified', 'score'}

        # Match key-value pairs with more flexible pattern
        pairs = re.findall(r'([^,\s]+?)\s*=\s*(?:"([^\"]+)"|(\d+)|([^,\s]+))', metadata_str)
        for pair in pairs:
            key = pair[0]
            # Get the first non-empty value from the capture groups
            value = next((v for v in pair[1:] if v), "")
            
            # Normalize field names
            normalized_key = field_mappings.get(key, key)
            
            # Convert severity/score to int if possible
            if normalized_key == 'severity' and value:
                try:
                    value = int(value)
                except ValueError:
                    value = 0
                    
            # Only store important fields or normalized versions
            if key in important_fields or normalized_key in important_fields:
                metadata[normalized_key] = value
                
                # Also store original key for completeness
                if key != normalized_key:
                    metadata[key] = value

        return metadata

    def _get_rule_filepath(self, threat_name):
        """
        Convert threat_name to corresponding rule filepath using the config's rules_path.
        """
        if not threat_name:
            return None

        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])
        rule_filename = threat_name.replace('.', '_')
        if not rule_filename.endswith('.yar'):
            rule_filename += '.yar'

        filepath = os.path.join(rules_dir, rule_filename)
        return filepath if os.path.exists(filepath) else None

    def _get_rule_filepath_from_description(self, description):
        """
        Try to find rule file based on description.
        """
        if not description:
            return None
            
        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])
        
        # Extract a potential filename from description
        # First word or phrase before colon or space
        words = re.split(r'[:\s]', description)
        if not words:
            return None
            
        # Try several potential filenames based on words in description
        for i in range(min(4, len(words))):
            potential_name = '_'.join(words[:i+1]).lower()
            for ext in ['.yar', '.yara']:
                filepath = os.path.join(rules_dir, potential_name + ext)
                if os.path.exists(filepath):
                    return filepath
                
        return None
        
    def _get_rule_filepath_from_rule_name(self, rule_name):
        """
        Try to find rule file based on rule name.
        """
        if not rule_name:
            return None
            
        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])
        
        # Try different variations of the rule name
        variations = [
            rule_name,
            rule_name.replace('_', '.'),
            rule_name.split('_')[0] if '_' in rule_name else None,
        ]
        
        for variation in variations:
            if not variation:
                continue
                
            for ext in ['.yar', '.yara']:
                filepath = os.path.join(rules_dir, variation + ext)
                if os.path.exists(filepath):
                    return filepath
                    
        # Last resort: Try scanning all files in the rules directory
        try:
            for filename in os.listdir(rules_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    filepath = os.path.join(rules_dir, filename)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if f"rule {rule_name}" in content or f"rule {rule_name} " in content:
                            return filepath
        except Exception as e:
            print(f"Error scanning rule files: {e}")
                    
        return None

    def cleanup(self):
        """
        No cleanup needed as process management is handled by manager.
        """
        pass