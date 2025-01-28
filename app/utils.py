# app/utils.py

import datetime
import glob
import hashlib
import math
import mimetypes
import os
import shutil
import psutil
import pefile
import json
from werkzeug.utils import secure_filename
from oletools.olevba import VBA_Parser

class Utils:
    def __init__(self, config):
        """
        Initialize the Helpers class with application configuration.
        
        Args:
            config (dict): Application configuration dictionary.
        """
        self.config = config

    def allowed_file(self, filename):
        """
        Check if the uploaded file has an allowed extension.
        
        Args:
            filename (str): Name of the file to check.
        
        Returns:
            bool: True if allowed, False otherwise.
        """
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.config['utils']['allowed_extensions']

    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy of data with detection insights.
        
        Args:
            data (bytes or str): Data to calculate entropy for.
        
        Returns:
            float: Calculated entropy rounded to two decimal places.
        """
        if len(data) == 0:
            return 0
        
        # Convert to bytes if not already
        if isinstance(data, str):
            data = data.encode()

        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            p_x = count / len(data)
            entropy += -p_x * math.log2(p_x)

        return round(entropy, 2)

    def get_pe_info(self, filepath):
        """
        Enhanced PE file analysis with deep import analysis and detection vectors.
        
        Args:
            filepath (str): Path to the PE file.
        
        Returns:
            dict: PE information and analysis results.
        """
        try:
            pe = pefile.PE(filepath)
            
            # Enhanced section analysis
            sections_info = []
            suspicious_imports = []
            high_risk_imports = {
                'kernel32.dll': {
                    'createremotethread': 'Process Injection capability detected',
                    'virtualallocex': 'Memory allocation in remote process detected',
                    'writeprocessmemory': 'Process memory manipulation detected',
                    'getprocaddress': 'Dynamic API resolution - possible evasion technique',
                    'loadlibrarya': 'Dynamic library loading - possible evasion technique',
                    'openprocess': 'Process manipulation capability',
                    'createtoolhelp32snapshot': 'Process enumeration capability',
                    'process32first': 'Process enumeration capability',
                    'process32next': 'Process enumeration capability'
                },
                'user32.dll': {
                    'getasynckeystate': 'Potential keylogging capability',
                    'getdc': 'Screen capture capability',
                    'getforegroundwindow': 'Window/Process monitoring capability'
                },
                'wininet.dll': {
                    'internetconnect': 'Network communication capability',
                    'internetopen': 'Network communication capability',
                    'ftpputfile': 'FTP upload capability',
                    'ftpopenfile': 'FTP communication capability'
                },
                'urlmon.dll': {
                    'urldownloadtofile': 'File download capability'
                }
            }
            """
            https://practicalsecurityanalytics.com/threat-hunting-with-function-imports/
            """
            # Check imports for suspicious behavior
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    
                    # Check each imported function
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode().lower()
                            
                            # Check if this is a high-risk import
                            if dll_name in high_risk_imports and func_name in high_risk_imports[dll_name]:
                                suspicious_imports.append({
                                    'dll': dll_name,
                                    'function': func_name,
                                    'note': high_risk_imports[dll_name][func_name],
                                    'hint': imp.hint if hasattr(imp, 'hint') else 0
                                })
            
            """
            https://practicalsecurityanalytics.com/file-entropy/
            """
            # Section Analysis with entropy
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                section_data = section.get_data()
                section_entropy = self.calculate_entropy(section_data)
                
                # Standard PE sections
                standard_sections = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug']
                is_standard = section_name in standard_sections
                
                sections_info.append({
                    'name': section_name,
                    'entropy': section_entropy,
                    'size': len(section_data),
                    'characteristics': section.Characteristics,
                    'is_standard': is_standard,
                    'detection_notes': []
                })
                
                # Add section-specific detection notes
                if section_entropy > 7.2:
                    sections_info[-1]['detection_notes'].append('High entropy may trigger detection')
                if section_name == '.text' and section_entropy > 7.0:
                    sections_info[-1]['detection_notes'].append('Unusual entropy for code section')
                if not is_standard:
                    sections_info[-1]['detection_notes'].append('Non-standard section name - may trigger detection')

            """
            https://practicalsecurityanalytics.com/pe-checksum/
            """
            # Check PE Checksum
            is_valid_checksum = pe.verify_checksum()
            calculated_checksum = pe.generate_checksum()
            stored_checksum = pe.OPTIONAL_HEADER.CheckSum
            
            info = {
                'file_type': 'PE32+ executable' if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 'PE32 executable',
                'machine_type': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, f"UNKNOWN ({pe.FILE_HEADER.Machine})").replace('IMAGE_FILE_MACHINE_', ''),
                'compile_time': datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
                'subsystem': pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, f"UNKNOWN ({pe.OPTIONAL_HEADER.Subsystem})").replace('IMAGE_SUBSYSTEM_', ''),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'sections': sections_info,
                'imports': list(set(entry.dll.decode() for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))),
                'suspicious_imports': suspicious_imports,
                'detection_notes': [],
                'checksum_info': {
                    'is_valid': is_valid_checksum,
                    'stored_checksum': hex(stored_checksum),
                    'calculated_checksum': hex(calculated_checksum),
                    'needs_update': calculated_checksum != stored_checksum
                }
            }
            
            # Add overall detection insights
            if not is_valid_checksum:
                info['detection_notes'].append('Invalid PE checksum - Common in modified/packed files (~83% correlation with malware)')

            if suspicious_imports:
                info['detection_notes'].append(f'Found {len(suspicious_imports)} suspicious API imports - Review import analysis')
                
            if any(section['entropy'] > 7.2 for section in sections_info):
                info['detection_notes'].append('High entropy sections detected - Consider entropy reduction techniques')
            
            if '.text' in [section['name'] for section in sections_info]:
                text_section = next(s for s in sections_info if s['name'] == '.text')
                if text_section['entropy'] > 7.0:
                    info['detection_notes'].append('Packed/encrypted code section may trigger heuristics')

            if any(not section['is_standard'] for section in sections_info):
                info['detection_notes'].append('Non-standard PE sections detected - May trigger static analysis')
                    
            pe.close()
            return {'pe_info': info}
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
            return {'pe_info': None}

    def get_office_info(self, filepath):
        """
        Enhanced Office document analysis with detection insights.
        
        Args:
            filepath (str): Path to the Office document.
        
        Returns:
            dict: Office information and analysis results.
        """
        try:
            vbaparser = VBA_Parser(filepath)
            detection_notes = []
            
            info = {
                'file_type': 'Microsoft Office Document',
                'has_macros': vbaparser.detect_vba_macros(),
                'macro_info': None,
                'detection_notes': detection_notes
            }
            
            if vbaparser.detect_vba_macros():
                macro_analysis = vbaparser.analyze_macros()
                info['macro_info'] = macro_analysis
                
                # Analyze macros for detection vectors
                macro_text = str(macro_analysis).lower()
                detection_patterns = {
                    'shell': 'Shell command execution detected',
                    'wscript': 'WScript execution detected',
                    'powershell': 'PowerShell execution detected',
                    'http': 'Network communication detected',
                    'auto': 'Auto-execution mechanism detected',
                    'document_open': 'Document open auto-execution',
                    'windowshide': 'Hidden window execution',
                    'createobject': 'COM object creation detected'
                }
                
                for pattern, note in detection_patterns.items():
                    if pattern in macro_text:
                        detection_notes.append(note)
            
            vbaparser.close()
            return {'office_info': info}
        except Exception as e:
            print(f"Error analyzing Office file: {e}")
            return {'office_info': None}

    def save_uploaded_file(self, file):
        """
        Save the uploaded file to the designated upload folder and store its information.
        
        Args:
            file (FileStorage): The uploaded file object.
        
        Returns:
            dict: Information about the saved file.
        """
        file_content = file.read()
        file.close()
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        original_filename = secure_filename(file.filename)
        extension = os.path.splitext(original_filename)[1].lower()
        filename = f"{md5_hash}_{original_filename}"
        
        upload_folder = self.config['utils']['upload_folder']
        result_folder = self.config['utils']['result_folder']
        
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        os.makedirs(result_folder, exist_ok=True)
        os.makedirs(os.path.join(result_folder, filename), exist_ok=True)
        
        with open(filepath, 'wb') as f:
            f.write(file_content)

        entropy_value = self.calculate_entropy(file_content)
        
        file_info = {
            'original_name': original_filename,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'size': len(file_content),
            'extension': extension,
            'mime_type': mimetypes.guess_type(original_filename)[0] or 'application/octet-stream',
            'upload_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'entropy': entropy_value,
            'entropy_analysis': {
                'value': entropy_value,
                'detection_risk': 'High' if entropy_value > 7.2 else 'Medium' if entropy_value > 6.8 else 'Low',
                'notes': []
            }
        }
        
        # Add entropy-based detection notes
        if entropy_value > 7.2:
            file_info['entropy_analysis']['notes'].append(
                'High entropy indicates encryption/packing - consider entropy reduction')
        elif entropy_value > 6.8:
            file_info['entropy_analysis']['notes'].append(
                'Moderate entropy - may trigger basic detection')
        
        # Add specific file type information for PE files
        if extension in ['.exe', '.dll', '.sys']:
            file_info.update(self.get_pe_info(filepath))

        # Add specific file type information for Office documents
        if extension in ['.docx', '.xlsx', '.doc', '.xls', '.xlsm', '.docm']:
            office_result = self.get_office_info(filepath)
            if 'error' in office_result:
                print(f"Warning: {office_result['error']}")
            file_info.update(office_result)

        # Save file info to result folder
        with open(os.path.join(result_folder, filename, 'file_info.json'), 'w') as f:
            json.dump(file_info, f)

        return file_info

    def find_file_by_hash(self, file_hash, search_folder):
        """
        Find a file in the specified folder by its hash.
        
        Args:
            file_hash (str): MD5 or SHA256 hash of the file.
            search_folder (str): Path to the folder to search in.
        
        Returns:
            str or None: Path to the found file or None if not found.
        """
        for filename in os.listdir(search_folder):
            if filename.startswith(file_hash):
                return os.path.join(search_folder, filename)
        return None

    def check_tool(self, tool_path):
        """
        Check if a tool is accessible and presumably executable.
        
        Args:
            tool_path (str): Path to the tool executable.
        
        Returns:
            bool: True if the tool is accessible and executable, False otherwise.
        """
        return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)

    def validate_pid(self, pid):
        """
        Validate if a PID exists and is accessible.
        
        Args:
            pid (int or str): Process ID to validate.
        
        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        try:
            pid = int(pid)
            if pid <= 0:
                return False, "Invalid PID: must be a positive integer"
                
            # Check if process exists
            if not psutil.pid_exists(pid):
                return False, f"Process with PID {pid} does not exist"
                
            # Try to get process info to check accessibility
            try:
                process = psutil.Process(pid)
                process.name()  # Try to access process name to verify permissions
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                return False, f"Cannot access process {pid}: {str(e)}"
                
            return True, None
                
        except ValueError:
            return False, "Invalid PID: must be a number"
        except Exception as e:
            return False, f"Error validating PID: {str(e)}"

    def get_entropy_risk_level(self, entropy):
        """
        Determine the risk level based on entropy value.
        
        Args:
            entropy (float): Entropy value.
        
        Returns:
            str: Risk level ('High', 'Medium', 'Low').
        """
        if entropy > 7.2:
            return 'High'
        elif entropy > 6.8:
            return 'Medium'
        return 'Low'

    def format_hex(self, value):
        """
        Format a value as a hexadecimal string.
        
        Args:
            value (int or str): Value to format.
        
        Returns:
            str: Hexadecimal representation or original string.
        """
        if isinstance(value, str) and value.startswith('0x'):
            return value.lower()
        try:
            return f"0x{int(value):x}"
        except (ValueError, TypeError):
            return str(value)

    def calculate_yara_risk(self, matches):
        """
        Calculate risk based on YARA matches considering severity levels.
        
        Args:
            matches (list): List of YARA match dictionaries.
        
        Returns:
            tuple: (risk_score, risk_factors)
        """
        if not matches:
            return 0, None

        # Severity weights
        SEVERITY_WEIGHTS = {
            'CRITICAL': 100,
            'HIGH': 80,
            'MEDIUM': 50,
            'LOW': 20,
            'INFO': 5
        }

        # Map numeric severities to levels
        NUMERIC_SEVERITY_MAP = {
            100: 'CRITICAL',
            80: 'HIGH',
            50: 'MEDIUM',
            20: 'LOW',
            5: 'INFO'
        }

        max_severity_score = 0
        severity_counts = {level: 0 for level in SEVERITY_WEIGHTS}

        # Count matches by severity and track highest severity
        for match in matches:
            meta = match.get('metadata', {})
            severity = meta.get('severity', 'MEDIUM')  # Default to MEDIUM if not specified

            # Convert numeric severity to descriptive level if necessary
            if isinstance(severity, int):
                severity = NUMERIC_SEVERITY_MAP.get(severity, 'MEDIUM')
            severity = severity.upper()

            if severity in SEVERITY_WEIGHTS:
                severity_counts[severity] += 1
                max_severity_score = max(max_severity_score, SEVERITY_WEIGHTS[severity])

        # Calculate weighted score
        total_score = 0
        risk_factors = []

        for severity, count in severity_counts.items():
            if count > 0:
                # Base score for this severity level
                severity_score = SEVERITY_WEIGHTS[severity]

                # Additional matches of same severity add diminishing returns
                if count > 1:
                    additional_score = sum(severity_score * (0.5 ** i) for i in range(1, count))
                    total_score += severity_score + additional_score
                else:
                    total_score += severity_score

                risk_factors.append(f"Found {count} {severity.lower()} severity YARA match{'es' if count > 1 else ''}")

        # Normalize score to 0-100 range
        normalized_score = min(100, total_score / 2)  # Divide by 2 to normalize, since total could exceed 100

        return normalized_score, risk_factors

    def calculate_risk(self, analysis_type='process', file_info=None, static_results=None, dynamic_results=None):
        """
        Unified risk calculation function that handles both file and process analysis.
        
        Args:
            analysis_type (str): Type of analysis - 'file' or 'process'
            file_info (dict, optional): Information about the file, required for 'file' analysis
            static_results (dict, optional): Static analysis results
            dynamic_results (dict, optional): Dynamic analysis results
        
        Returns:
            tuple: (risk_score, risk_factors)
        """
        risk_score = 0
        risk_factors = []
        
        # Define weights based on analysis type
        WEIGHTS = {
            'file': {
                'pe_info': 0.10,
                'static': 0.50,
                'dynamic': 0.40
            },
            'process': {
                'dynamic': 1.0
            }
        }[analysis_type]
        
        # 1. PE Information Risk Calculation (file analysis only)
        if analysis_type == 'file' and file_info and file_info.get('pe_info'):
            pe_risk = 0
            pe_info = file_info['pe_info']
            
            # Enhanced entropy detection
            high_entropy_sections = 0
            very_high_entropy_sections = 0
            for section in pe_info.get('sections', []):
                entropy = section.get('entropy', 0)
                if entropy > 7.5:
                    very_high_entropy_sections += 1
                    risk_factors.append(f"Critical entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}")
                elif entropy > 7.0:
                    high_entropy_sections += 1
                    risk_factors.append(f"High entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}")
            
            pe_risk += min(high_entropy_sections * 10 + very_high_entropy_sections * 20, 40)
            
            # Enhanced import analysis
            suspicious_imports = pe_info.get('suspicious_imports', [])
            if suspicious_imports:
                critical_functions = {
                    'createremotethread', 'virtualallocex', 'writeprocessmemory',
                    'ntmapviewofsection', 'zwmapviewofsection'
                }
                high_risk_functions = {
                    'loadlibrarya', 'loadlibraryw', 'getprocaddress',
                    'openprocess', 'virtualallocexnuma'
                }
                
                critical_imports = sum(1 for imp in suspicious_imports 
                                    if imp.get('function', '').lower() in critical_functions)
                high_risk_imports = sum(1 for imp in suspicious_imports 
                                      if imp.get('function', '').lower() in high_risk_functions)
                
                pe_risk += min(critical_imports * 15 + high_risk_imports * 8, 30)
                if critical_imports > 0 or high_risk_imports > 0:
                    risk_factors.append(f"Found {critical_imports} critical process manipulation and {high_risk_imports} high-risk dynamic loading imports")
            
            # Enhanced checksum analysis
            if pe_info.get('checksum_info'):
                checksum = pe_info['checksum_info']
                if checksum.get('stored_checksum') != checksum.get('calculated_checksum'):
                    pe_risk += 25
                    risk_factors.append("PE checksum mismatch detected")
            
            risk_score += (pe_risk / 100) * WEIGHTS['pe_info'] * 100

        # 2. Static Analysis Risk Calculation (file analysis only)
        if analysis_type == 'file' and static_results:
            static_risk = 0
            
            # Enhanced YARA detection scoring
            yara_matches = static_results.get('yara', {}).get('matches', [])
            yara_score, yara_factors = self.calculate_yara_risk(yara_matches)
            if yara_score > 0:
                match_multiplier = min(len(yara_matches) * 0.15 + 1, 1.5)
                static_risk += yara_score * match_multiplier
                risk_factors.extend([f"Static: {factor}" for factor in yara_factors])
            
            # Enhanced CheckPLZ analysis
            checkplz_findings = static_results.get('checkplz', {}).get('findings', {})
            if checkplz_findings:
                threat_score = 0
                if checkplz_findings.get('initial_threat'):
                    threat_score += 50
                    risk_factors.append("Critical: CheckPLZ detected initial threat indicators")
                
                indicators = checkplz_findings.get('threat_indicators', [])
                if indicators:
                    indicator_score = min(len(indicators) * 15, 40)
                    threat_score += indicator_score
                    risk_factors.append(f"Found {len(indicators)} additional threat indicators")
                
                static_risk += threat_score
            
            # Add file entropy analysis
            if static_results.get('file_entropy'):
                entropy = static_results['file_entropy']
                if entropy > 7.5:
                    static_risk += 30
                    risk_factors.append(f"Critical overall file entropy: {entropy:.2f}")
                elif entropy > 7.0:
                    static_risk += 20
                    risk_factors.append(f"High overall file entropy: {entropy:.2f}")
            
            risk_score += (static_risk / 100) * WEIGHTS['static'] * 100

        # 3. Dynamic Analysis Risk Calculation (both file and process)
        if dynamic_results:
            dynamic_risk = 0
            
            # YARA dynamic detections
            yara_matches = dynamic_results.get('yara', {}).get('matches', [])
            yara_score, yara_factors = self.calculate_yara_risk(yara_matches)
            if yara_score > 0:
                dynamic_risk += yara_score
                risk_factors.extend([f"Dynamic: {factor}" for factor in yara_factors])
            
            # Enhanced PE-Sieve scoring
            pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
            pesieve_suspicious = int(pesieve_findings.get('total_suspicious', 0))
            if pesieve_suspicious > 0:
                severity_multiplier = 1.5 if pesieve_findings.get('severity') == 'critical' else 1.0
                pe_sieve_score = min(pesieve_suspicious * (20 if analysis_type == 'file' else 15) * severity_multiplier,
                                   45 if analysis_type == 'file' else 30)
                dynamic_risk += pe_sieve_score
                risk_factors.append(f"PE-Sieve found {pesieve_suspicious} suspicious indicators")
            
            # Enhanced memory anomaly detection
            moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
            if moneta_findings:
                memory_scores = {
                    'total_private_rwx': 15 if analysis_type == 'file' else 10,
                    'total_modified_code': 12 if analysis_type == 'file' else 10,
                    'total_heap_executable': 10,
                    'total_modified_pe_header': 10,
                    'total_private_rx': 8,
                    'total_inconsistent_x': 8,
                    'total_missing_peb': 5,
                    'total_mismatching_peb': 5
                }
                
                total_score = 0
                anomaly_count = 0
                
                for key, weight in memory_scores.items():
                    count = int(moneta_findings.get(key, 0) or 0)
                    if count > 0:
                        total_score += min(count * weight, weight * 2)
                        anomaly_count += count
                
                if anomaly_count > 0:
                    dynamic_risk += min(total_score, 40 if analysis_type == 'file' else 30)
                    risk_factors.append(f"Found {anomaly_count} weighted memory anomalies")
            
            # Enhanced behavior analysis
            patriot_findings = dynamic_results.get('patriot', {}).get('findings', {})
            if patriot_findings:
                behaviors = patriot_findings.get('findings', [])
                behavior_count = len(behaviors)
                
                if behavior_count > 0:
                    severity_scores = {
                        'critical': 25 if analysis_type == 'file' else 20,
                        'high': 15,
                        'medium': 10,
                        'low': 5
                    }
                    
                    behavior_score = 0
                    for behavior in behaviors:
                        severity = behavior.get('severity', 'low')
                        behavior_score += severity_scores.get(severity, 5)
                    
                    dynamic_risk += min(behavior_score, 35)
                    risk_factors.append(f"Found {behavior_count} weighted suspicious behaviors")
            
            # Enhanced HSB detection
            hsb_findings = dynamic_results.get('hsb', {}).get('findings', {})
            if hsb_findings and hsb_findings.get('detections'):
                total_hsb_score = 0
                for detection in hsb_findings['detections']:
                    if detection.get('findings'):
                        count = len(detection['findings'])
                        severity = detection.get('max_severity', 0)
                        
                        if analysis_type == 'file':
                            severity_multiplier = 1 + (severity * 0.5)
                            detection_score = min(count * 15 * severity_multiplier, 40)
                        else:
                            if severity == 0:  # LOW
                                detection_score = min(count * 10, 20)
                            elif severity == 1:  # MID
                                detection_score = min(count * 15, 25)
                            else:  # HIGH
                                detection_score = min(count * 20, 35)
                        
                        total_hsb_score += detection_score
                        
                        severity_text = "LOW" if severity == 0 else "MID" if severity == 1 else "HIGH"
                        if severity >= 2:
                            risk_factors.append(f"Critical: Found {count} high-severity memory operations")
                        else:
                            risk_factors.append(f"Found {count} {severity_text} severity memory operations")
                
                dynamic_risk += min(total_hsb_score, 45 if analysis_type == 'file' else 35)
            
            risk_score += (dynamic_risk / 100) * WEIGHTS['dynamic'] * 100

        # Final normalization and scaling
        if analysis_type == 'file':
            # Apply exponential scaling to high scores
            base_score = min(max(risk_score, 0), 100)
            if base_score > 75:
                risk_score = min(base_score * 1.15, 100)
        else:  # process
            if max(yara_score, 0) == 0 and pesieve_suspicious <= 1:
                risk_score = min(risk_score, 65)
            
            if all(f.lower().find('high') == -1 for f in risk_factors):
                risk_score = min(risk_score, 75)
        
        return round(min(max(risk_score, 0), 100), 2), risk_factors

    def get_risk_level(self, risk_score):
        """
        Convert numerical risk score to categorical risk level.
        
        Args:
            risk_score (float): Risk score between 0 and 100.
        
        Returns:
            str: Risk level ('Critical', 'High', 'Medium', 'Low').
        """
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        else:
            return "Low"

    def load_json_file(self, filepath):
        """Helper function to safely load JSON files"""
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            app.logger.error(f"Error loading JSON file {filepath}: {str(e)}")
            return None

    def extract_detection_counts(self, results):
        """Extract all detection counts from analysis results"""
        counts = {
            'yara': 0,
            'pesieve': 0,
            'moneta': 0,
            'patriot': 0,
            'hsb': 0
        }
        try:
            # YARA - unchanged
            yara_matches = results.get('yara', {}).get('matches', [])
            counts['yara'] = len({match.get('rule') for match in yara_matches if match.get('rule')}) if isinstance(yara_matches, list) else 0

            # PE-sieve - unchanged
            pesieve_findings = results.get('pe_sieve', {}).get('findings', {})
            counts['pesieve'] = int(pesieve_findings.get('total_suspicious', 0) or 0)

            # Moneta - only count actual suspicious findings
            moneta_findings = results.get('moneta', {}).get('findings', {})
            non_detection_fields = ['total_regions', 'total_unsigned_modules', 'scan_duration']
            counts['moneta'] = sum(
                int(moneta_findings.get(key, 0) or 0)
                for key in moneta_findings 
                if key.startswith('total_') and key not in non_detection_fields
            )

            # Patriot - unchanged
            patriot_findings = results.get('patriot', {}).get('findings', {}).get('findings', [])
            counts['patriot'] = len(patriot_findings) if isinstance(patriot_findings, list) else 0

            # HSB - unchanged
            hsb_findings = results.get('hsb', {}).get('findings', {})
            if hsb_findings and hsb_findings.get('detections'):
                counts['hsb'] = len(hsb_findings['detections'][0].get('findings', []))

        except (TypeError, ValueError, IndexError):
            pass

        return counts