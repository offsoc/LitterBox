# app/routes.py

import datetime
import glob
import json
import os
import shutil
from datetime import datetime
from flask import render_template, request, jsonify
from .utils import Utils
from .analyzers.manager import AnalysisManager
from .analyzers.blender import BlenderAnalyzer


def register_routes(app):
    analysis_manager = AnalysisManager(app.config, logger=app.logger)

    utils = Utils(app.config)  # Initialize Utils with app configuration


    @app.route('/')
    def index():
        return render_template('upload.html')


    @app.route('/upload', methods=['POST'])
    def upload_file():
        app.logger.debug("Received a file upload request.")
        
        # Check if the 'file' part exists in the request
        if 'file' not in request.files:
            app.logger.debug("No file part in the request.")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        
        # Check if a file was selected
        if file.filename == '':
            app.logger.debug("No file selected for upload.")
            return jsonify({'error': 'No selected file'}), 400
        
        # Validate file type and save if valid
        if file and utils.allowed_file(file.filename):
            app.logger.debug(f"File '{file.filename}' is allowed. Attempting to save.")
            try:
                file_info = utils.save_uploaded_file(file)
                app.logger.debug(f"File '{file.filename}' uploaded and saved successfully.")
                return jsonify({
                    'message': 'File uploaded successfully',
                    'file_info': file_info
                }), 200
            except Exception as e:
                app.logger.error(f"Error occurred while saving file '{file.filename}': {e}")
                return jsonify({'error': str(e)}), 500
        
        # If the file type is not allowed
        app.logger.debug(f"File type of '{file.filename}' is not allowed.")
        return jsonify({'error': 'File type not allowed'}), 400


    @app.route('/validate/<pid>', methods=['POST'])
    def validate_process(pid):
        """Endpoint just for PID validation"""
        app.logger.debug(f"Received PID validation request for PID: {pid}")
        
        # Validate the PID using the utility function
        try:
            is_valid, error_msg = utils.validate_pid(pid)
            if not is_valid:
                app.logger.debug(f"PID {pid} is invalid. Reason: {error_msg}")
                return jsonify({'error': error_msg}), 404

            app.logger.debug(f"PID {pid} is valid.")
            return jsonify({'status': 'valid'}), 200

        except Exception as e:
            app.logger.error(f"Unexpected error during PID validation for PID {pid}: {e}")
            return jsonify({'error': 'Internal server error'}), 500


    @app.route('/analyze/<analysis_type>/<target>', methods=['GET', 'POST'])
    def analyze_file(analysis_type, target):
        try:
            app.logger.debug(f"Received request to analyze file. Analysis type: {analysis_type}, Target: {target}")
            
            is_pid = False
            file_path = None
            result_path = None

            # Check if this is a PID-based analysis
            if analysis_type == 'dynamic' and target.isdigit():
                is_pid = True
                pid = target
                app.logger.debug(f"Performing dynamic analysis for PID: {pid}")
                
                # Validate PID before proceeding
                is_valid, error_msg = utils.validate_pid(pid)
                if not is_valid:
                    app.logger.debug(f"PID validation failed for PID {pid}. Reason: {error_msg}")
                    return jsonify({'error': error_msg}), 404

                # Define result_path for PID-based dynamic analysis
                result_folder = os.path.join(utils.config['utils']['result_folder'], f'dynamic_{pid}')
                os.makedirs(result_folder, exist_ok=True)
                result_path = result_folder
                app.logger.debug(f"Result path for PID {pid}: {result_path}")
            else:
                # Look for file based on hash
                app.logger.debug(f"Looking for file with hash: {target}")
                file_path = utils.find_file_by_hash(target, app.config['utils']['upload_folder'])
                result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
                if not file_path:
                    app.logger.debug(f"File with hash {target} not found in upload folder.")
                    return jsonify({'error': 'File not found'}), 404
                app.logger.debug(f"File found at: {file_path}, Results will be saved to: {result_path}")

            # GET request - Render results template
            if request.method == 'GET':
                app.logger.debug(f"GET request received for analysis type: {analysis_type}, Target: {target}")
                return render_template('results.html', 
                                       analysis_type=analysis_type,
                                       file_hash=target)

            # POST request - Perform analysis
            app.logger.debug(f"POST request received. Performing {analysis_type} analysis.")

            if analysis_type == 'static':
                if is_pid:
                    app.logger.debug(f"Static analysis requested on PID {pid}. This is invalid.")
                    return jsonify({'error': 'Cannot perform static analysis on PID'}), 400
                app.logger.debug(f"Performing static analysis on file: {file_path}")
                results = analysis_manager.run_static_analysis(file_path)

                # Save results to result folder
                static_results_path = os.path.join(result_path, 'static_analysis_results.json')
                with open(static_results_path, 'w') as f:
                    json.dump(results, f)
                app.logger.debug(f"Static analysis results saved to: {static_results_path}")
                
            elif analysis_type == 'dynamic':

                # POST request - Get command line arguments if provided
                try:
                    request_data = request.get_json() or {}
                    cmd_args = request_data.get('args', [])
                    # Validate command line arguments
                    if not isinstance(cmd_args, list):
                        app.logger.error("Invalid arguments format provided")
                        return jsonify({'error': 'Arguments must be provided as a list'}), 400
                    
                    # Basic argument safety checks
                    for arg in cmd_args:
                        if not isinstance(arg, str):
                            app.logger.error("Non-string argument provided")
                            return jsonify({'error': 'All arguments must be strings'}), 400
                        if ';' in arg or '&' in arg or '|' in arg:
                            app.logger.error("Potentially dangerous argument detected")
                            return jsonify({'error': 'Invalid argument characters detected'}), 400
                    
                    app.logger.debug(f"Command line arguments received: {cmd_args}")
                except Exception as e:
                    app.logger.error(f"Error parsing request data: {e}")
                    cmd_args = []

                target_for_analysis = pid if is_pid else file_path
                app.logger.debug(f"Performing dynamic analysis on target: {target_for_analysis}, is_pid: {is_pid}")
                # Pass the command line arguments to the analysis manager
                results = analysis_manager.run_dynamic_analysis(target_for_analysis, is_pid, cmd_args)

                # Check for early termination cases
                if results.get('status') == 'early_termination':
                    app.logger.error("Process terminated early during initialization")
                    dynamic_results_path = os.path.join(result_path, 'dynamic_analysis_results.json')
                    with open(dynamic_results_path, 'w') as f:
                        json.dump(results, f)
                    app.logger.debug(f"Early termination results saved to: {dynamic_results_path}")
                    
                    return jsonify({
                        'status': 'early_termination',
                        'error': results.get('error', {}).get('message', 'Process terminated early'),
                        'details': {
                            'termination_time': results.get('error', {}).get('termination_time'),
                            'init_time': results.get('error', {}).get('init_time'),
                            'message': results.get('error', {}).get('details')
                        }
                    }), 202

                # Normal case - save complete results
                dynamic_results_path = os.path.join(result_path, 'dynamic_analysis_results.json')
                with open(dynamic_results_path, 'w') as f:
                    json.dump(results, f)
                app.logger.debug(f"Dynamic analysis results saved to: {dynamic_results_path}")
                
            else:
                app.logger.debug(f"Invalid analysis type received: {analysis_type}")
                return jsonify({'error': 'Invalid analysis type'}), 400

            # Return appropriate response based on the analysis completion
            if results.get('status') == 'error':
                app.logger.debug("Analysis completed with errors.")
                return jsonify({
                    'status': 'error',
                    'error': results.get('error', {}).get('message', 'Analysis failed'),
                    'details': results.get('error', {}).get('details')
                }), 500
                
            app.logger.debug("Analysis completed successfully.")
            return jsonify({
                'status': 'success',
                'results': results
            })

        except Exception as e:
            # Log the exception for debugging purposes
            app.logger.error(f"Error in analyze_file route: {e}")
            return jsonify({'error': str(e)}), 500


    @app.route('/results/<target>/<analysis_type>', methods=['GET'])
    def get_analysis_results(target, analysis_type):
        app.logger.debug(f"Received analysis results request for target: {target}, analysis_type: {analysis_type}")
        try:
            # Handle PID-based dynamic analysis
            if target.isdigit() and analysis_type == 'dynamic':
                pid = target
                app.logger.debug(f"Processing dynamic analysis request for PID: {pid}")
                result_folder = os.path.join(app.config['utils']['result_folder'], f'dynamic_{pid}')
                app.logger.debug(f"Looking for results in folder: {result_folder}")
                
                if not os.path.exists(result_folder):
                    error_message = f'Process with PID {pid} does not exist'
                    app.logger.debug(f"Result folder not found: {error_message}")
                    return render_template('error.html', error=error_message), 404

                dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
                app.logger.debug(f"Looking for dynamic analysis results at: {dynamic_path}")
                
                if not os.path.exists(dynamic_path):
                    error_message = f'Dynamic analysis results for PID {pid} not found.'
                    app.logger.debug(f"Dynamic analysis results not found: {error_message}")
                    return render_template('error.html', error=error_message), 404

                dynamic_results = utils.load_json_file(dynamic_path)
                if not dynamic_results:
                    app.logger.error(f"Failed to load dynamic analysis results from {dynamic_path}")
                    return render_template('error.html', error='Error loading dynamic analysis results'), 500

                app.logger.debug("Successfully loaded dynamic analysis results")

                # Calculate risk
                # Calculate risk using new unified function
                risk_score, risk_factors = utils.calculate_risk(
                    analysis_type='process',
                    dynamic_results=dynamic_results
                )
                risk_level = utils.get_risk_level(risk_score)
                app.logger.debug(f"Calculated risk assessment - Score: {risk_score}, Level: {risk_level}")

                # Add risk assessment to results
                dynamic_results['risk_assessment'] = {
                    'score': risk_score,
                    'level': risk_level,
                    'factors': risk_factors
                }

                # Get all detection counts
                detections = utils.extract_detection_counts(dynamic_results)
                app.logger.debug(f"Extracted detection counts: {detections}")

                return render_template(
                    'dynamic_info.html',
                    file_info=None,
                    analysis_results=dynamic_results,
                    yara_detections=detections['yara'],
                    pesieve_detections=detections['pesieve'],
                    moneta_detections=detections['moneta'],
                    patriot_detections=detections['patriot'],
                    hsb_detections=detections['hsb'],
                    risk_level=risk_level,
                    risk_score=risk_score,
                    risk_factors=risk_factors
                )

            # Handle file-based analysis
            app.logger.debug(f"Processing file-based analysis for hash: {target}")
            result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
            if not result_path:
                app.logger.debug(f"No results found for hash: {target}")
                return render_template('error.html', error='Results not found'), 404

            app.logger.debug(f"Found results at path: {result_path}")

            # Load file_info.json
            file_info_path = os.path.join(result_path, 'file_info.json')
            if not os.path.exists(file_info_path):
                app.logger.debug(f"File info not found at: {file_info_path}")
                return render_template('error.html', error='File info not found'), 404

            file_info = utils.load_json_file(file_info_path)
            if not file_info:
                app.logger.error(f"Failed to load file info from {file_info_path}")
                return render_template('error.html', error='Error loading file info'), 500

            app.logger.debug("Successfully loaded file info")

            # Load static and dynamic results if they exist
            static_path = os.path.join(result_path, 'static_analysis_results.json')
            dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')
            
            static_results = utils.load_json_file(static_path)
            dynamic_results = utils.load_json_file(dynamic_path)
            app.logger.debug(f"Static results loaded: {bool(static_results)}, Dynamic results loaded: {bool(dynamic_results)}")

            # Calculate risk
            risk_score, risk_factors = utils.calculate_risk(
                analysis_type='file',
                file_info=file_info,
                static_results=static_results,
                dynamic_results=dynamic_results
            )
            risk_level = utils.get_risk_level(risk_score)
            app.logger.debug(f"Calculated file risk assessment - Score: {risk_score}, Level: {risk_level}")

            # Add risk information to file_info
            file_info['risk_assessment'] = {
                'score': risk_score,
                'level': risk_level,
                'factors': risk_factors
            }

            if analysis_type == 'info':
                app.logger.debug("Processing file info analysis type")
                if 'pe_info' in file_info:
                    app.logger.debug("Processing PE info data")
                    # Calculate section entropy risk levels
                    for section in file_info['pe_info']['sections']:
                        section['entropy_risk'] = utils.get_entropy_risk_level(section['entropy'])
                        app.logger.debug(f"Calculated entropy risk for section {section.get('name', 'unknown')}: {section['entropy_risk']}")

                    # Group suspicious imports by DLL
                    grouped_imports = {}
                    for imp in file_info['pe_info'].get('suspicious_imports', []):
                        dll = imp['dll']
                        if dll not in grouped_imports:
                            grouped_imports[dll] = []
                        grouped_imports[dll].append(imp)
                    file_info['pe_info']['grouped_suspicious_imports'] = grouped_imports
                    app.logger.debug(f"Grouped suspicious imports for {len(grouped_imports)} DLLs")

                    # Format checksum values
                    if 'checksum_info' in file_info['pe_info']:
                        checksum = file_info['pe_info']['checksum_info']
                        checksum['stored_checksum'] = utils.format_hex(checksum['stored_checksum'])
                        checksum['calculated_checksum'] = utils.format_hex(checksum['calculated_checksum'])
                        app.logger.debug(f"Formatted checksum values - Stored: {checksum['stored_checksum']}, Calculated: {checksum['calculated_checksum']}")

                app.logger.debug("Rendering file_info.html template")
                return render_template(
                    'file_info.html',
                    file_info=file_info,
                    entropy_risk_levels={
                        'High': 7.2,
                        'Medium': 6.8,
                        'Low': 0
                    }
                )

            elif analysis_type in ['static', 'dynamic']:
                app.logger.debug(f"Processing {analysis_type} analysis type")
                results_file = f'{analysis_type}_analysis_results.json'
                results_path = os.path.join(result_path, results_file)
                
                if not os.path.exists(results_path):
                    app.logger.debug(f"No {analysis_type} analysis results found at: {results_path}")
                    return render_template('error.html', 
                        error=f'No {analysis_type} analysis results found'), 404

                analysis_results = utils.load_json_file(results_path)
                if not analysis_results:
                    app.logger.error(f"Failed to load {analysis_type} analysis results from {results_path}")
                    return render_template('error.html', 
                        error=f'Error loading {analysis_type} analysis results'), 500

                app.logger.debug(f"Successfully loaded {analysis_type} analysis results")

                if analysis_type == 'static':
                    # Get YARA detections
                    detections = utils.extract_detection_counts(analysis_results)
                    yara_detections = detections['yara']
                    app.logger.debug(f"YARA detections: {yara_detections}")

                    # Handle checkplz detections
                    checkplz_detections = 0
                    checkplz_findings = analysis_results.get('checkplz', {}).get('findings', {})
                    if isinstance(checkplz_findings, dict):
                        checkplz_detections = 1 if checkplz_findings.get('initial_threat') else 0
                    app.logger.debug(f"Checkplz detections: {checkplz_detections}")
                    stringnalyzer_results = analysis_results.get('stringnalyzer', {})

                    # Format scan duration
                    formatted_duration = "00:00.000"
                    try:
                        raw_duration = analysis_results.get('checkplz', {}).get('findings', {}).get('scan_results', {}).get('scan_duration')
                        app.logger.debug(f"Raw scan duration value: {raw_duration}")
                        scan_duration = float(raw_duration or 0)
                        
                        minutes = int(scan_duration // 60)
                        seconds = int(scan_duration % 60)
                        milliseconds = int((scan_duration % 1) * 1000)
                        formatted_duration = f"{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
                        app.logger.debug(f"Formatted scan duration: {formatted_duration}")
                    except (TypeError, ValueError, AttributeError) as e:
                        app.logger.error(f"Error formatting scan duration: {e}")
                        app.logger.debug(f"Checkplz results structure: {analysis_results.get('checkplz', {})}")

                    app.logger.debug("Rendering static_info.html template")
                    return render_template(
                        'static_info.html',
                        file_info=file_info,
                        analysis_results=analysis_results,
                        yara_detections=yara_detections,
                        checkplz_detections=checkplz_detections,
                        stringnalyzer_results=stringnalyzer_results,  # Add this line
                        scan_duration=formatted_duration
                    )

                elif analysis_type == 'dynamic':
                    detections = utils.extract_detection_counts(analysis_results)
                    app.logger.debug(f"Extracted dynamic analysis detections: {detections}")
                    
                    app.logger.debug("Rendering dynamic_info.html template")
                    return render_template(
                        'dynamic_info.html',
                        file_info=file_info,
                        analysis_results=analysis_results,
                        yara_detections=detections['yara'],
                        pesieve_detections=detections['pesieve'],
                        moneta_detections=detections['moneta'],
                        patriot_detections=detections['patriot'],
                        hsb_detections=detections['hsb']
                    )

            else:
                app.logger.debug(f"Invalid analysis type received: {analysis_type}")
                return render_template('error.html', error='Invalid analysis type.'), 400

        except Exception as e:
            app.logger.error(f"Error in get_analysis_results route: {e}")
            app.logger.error("Traceback:", exc_info=True)  # This will log the full traceback
            return render_template('error.html', error=str(e)), 500


    @app.route('/summary', methods=['GET'])
    def summary_page():
        """Route for the summary page"""
        return render_template('summary.html')


    @app.route('/files', methods=['GET'])
    def get_files_summary():
        try:
            app.logger.debug("Starting to generate files and PID-based analysis summaries.")
            
            results_dir = app.config['utils']['result_folder']
            file_based_summary = {}
            pid_based_summary = {}

            # List all items in the results folder
            try:
                all_items = os.listdir(results_dir)
                app.logger.debug(f"Found {len(all_items)} items in results directory: {results_dir}")
            except Exception as e:
                app.logger.error(f"Error accessing results directory '{results_dir}': {e}")
                raise

            for item in all_items:
                item_path = os.path.join(results_dir, item)

                if not os.path.isdir(item_path):
                    app.logger.debug(f"Skipping non-directory item: {item}")
                    continue

                # Handle PID-based analysis
                if item.startswith('dynamic_'):
                    pid = item.replace('dynamic_', '')
                    app.logger.debug(f"Processing dynamic analysis results for PID: {pid}")

                    dynamic_results_path = os.path.join(item_path, 'dynamic_analysis_results.json')
                    if os.path.exists(dynamic_results_path):
                        try:
                            with open(dynamic_results_path, 'r') as f:
                                dynamic_results = json.load(f)
                            app.logger.debug(f"Loaded dynamic analysis results for PID: {pid}")
                        except Exception as e:
                            app.logger.error(f"Error loading dynamic analysis results for PID {pid}: {e}")
                            continue

                        # Extract scanner-specific results and calculate risk score
                        try:
                            process_info = dynamic_results.get('moneta', {}).get('findings', {}).get('process_info', {})
                            risk_score, risk_factors = utils.calculate_risk(analysis_type='process',dynamic_results=dynamic_results)
                            risk_level = utils.get_risk_level(risk_score)

                            yara_matches = dynamic_results.get('yara', {}).get('matches', [])
                            pe_sieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
                            moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
                            hsb_detections = dynamic_results.get('hsb', {}).get('findings', {}).get('detections', [])

                            pid_based_summary[pid] = {
                                'pid': pid,
                                'process_name': process_info.get('name', 'unknown'),
                                'process_path': process_info.get('path', 'unknown'),
                                'architecture': process_info.get('arch', 'unknown'),
                                'analysis_time': dynamic_results.get('analysis_time', 'unknown'),
                                'result_dir_full_path': os.path.abspath(item_path),
                                'risk_assessment': {
                                    'score': risk_score,
                                    'level': risk_level,
                                    'factors': risk_factors
                                },
                                'analysis_summary': {
                                    'yara': {
                                        'total_findings': len(yara_matches),
                                        'findings': yara_matches  # Store complete YARA findings
                                    },
                                    'pe_sieve': {
                                        'total_findings': pe_sieve_findings.get('total_suspicious', 0),
                                        'findings': pe_sieve_findings  # Store complete PE-sieve findings
                                    },
                                    'moneta': {
                                        'total_findings': sum(1 for key, value in moneta_findings.items() 
                                                            if key.startswith('total_') and isinstance(value, (int, float)) and value > 0),
                                        'findings': moneta_findings  # Store complete Moneta findings
                                    },
                                    'hsb': {
                                        'total_findings': sum(len(det.get('findings', [])) for det in hsb_detections if det.get('pid') == int(pid)),
                                        'findings': [det for det in hsb_detections if det.get('pid') == int(pid)]  # Store complete HSB findings for this PID
                                    }
                                }
                            }
                            app.logger.debug(f"Processed dynamic analysis for PID: {pid}")
                        except Exception as e:
                            app.logger.error(f"Error processing PID {pid}: {e}")
                            continue

                    continue

                # Handle file-based analysis
                file_info_path = os.path.join(item_path, 'file_info.json')
                if not os.path.exists(file_info_path):
                    app.logger.debug(f"No file_info.json found in {item_path}. Skipping.")
                    continue

                try:
                    with open(file_info_path, 'r') as f:
                        file_info = json.load(f)
                    app.logger.debug(f"Loaded file info for item: {item}")
                except Exception as e:
                    app.logger.error(f"Error loading file_info.json for item {item}: {e}")
                    continue

                # Load static and dynamic results
                static_path = os.path.join(item_path, 'static_analysis_results.json')
                dynamic_path = os.path.join(item_path, 'dynamic_analysis_results.json')

                static_results = None
                if os.path.exists(static_path):
                    try:
                        with open(static_path, 'r') as f:
                            static_results = json.load(f)
                        app.logger.debug(f"Loaded static analysis results for item: {item}")
                    except Exception as e:
                        app.logger.error(f"Error loading static analysis results for item {item}: {e}")

                dynamic_results = None
                if os.path.exists(dynamic_path):
                    try:
                        with open(dynamic_path, 'r') as f:
                            dynamic_results = json.load(f)
                        app.logger.debug(f"Loaded dynamic analysis results for item: {item}")
                    except Exception as e:
                        app.logger.error(f"Error loading dynamic analysis results for item {item}: {e}")

                # Calculate risk score
                try:
                    risk_score, risk_factors = utils.calculate_risk(analysis_type='file',file_info=file_info,static_results=static_results,dynamic_results=dynamic_results)
                    risk_level = utils.get_risk_level(risk_score)
                    file_based_summary[item] = {
                        'md5': file_info.get('md5', 'unknown'),
                        'sha256': file_info.get('sha256', 'unknown'),
                        'filename': file_info.get('original_name', 'unknown'),
                        'file_size': file_info.get('size', 0),
                        'upload_time': file_info.get('upload_time', 'unknown'),
                        'result_dir_full_path': os.path.abspath(item_path),
                        'entropy_value': file_info.get('entropy_analysis', {}).get('value', 0),
                        'detection_risk': file_info.get('entropy_analysis', {}).get('detection_risk', 'Unknown'),
                        'has_static_analysis': os.path.exists(static_path),
                        'has_dynamic_analysis': os.path.exists(dynamic_path),
                        'risk_assessment': {
                            'score': risk_score,
                            'level': risk_level,
                            'factors': risk_factors
                        }
                    }
                    app.logger.debug(f"Processed file-based analysis for item: {item}")
                except Exception as e:
                    app.logger.error(f"Error processing risk assessment for item {item}: {e}")
                    continue

            app.logger.debug("File and PID-based summaries successfully generated.")
            return jsonify({
                'status': 'success',
                'file_based': {
                    'count': len(file_based_summary),
                    'files': file_based_summary
                },
                'pid_based': {
                    'count': len(pid_based_summary),
                    'processes': pid_based_summary
                }
            })

        except Exception as e:
            app.logger.error(f"Error in get_files_summary: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


    @app.route('/blender', methods=['GET', 'POST'])
    def blender():
        app.logger.debug("Accessed blender endpoint")

        try:
            blender_analyzer = BlenderAnalyzer(app.config, logger=app.logger)

            if request.method == 'GET':
                # Check if the request is for comparison
                payload_hash = request.args.get('hash')
                if payload_hash:
                    comparison_result = blender_analyzer.compare_payload(payload_hash)

                    # Check if status is "error" and force 400 response
                    if isinstance(comparison_result, dict) and comparison_result.get("status") == "error":
                        return jsonify({'error': comparison_result.get("message", "Unknown error")}), 400

                    return jsonify({
                        'status': 'success',
                        'message': 'Comparison completed',
                        'result': comparison_result
                    })

                # Otherwise, return the latest report
                result_folder = os.path.join(app.config['utils']['result_folder'], "Blender")
                latest_report = None
                last_modified = None

                if os.path.exists(result_folder):
                    files = [f for f in os.listdir(result_folder) if f.startswith("Blender_results_")]
                    if files:
                        latest_file = max(files, key=lambda x: os.path.getmtime(os.path.join(result_folder, x)))
                        file_path = os.path.join(result_folder, latest_file)
                        with open(file_path, 'r') as f:
                            latest_report = f.read()
                        last_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')

                return render_template('blender.html',
                                       initial_data=latest_report,
                                       last_modified=last_modified)

            operation = request.json.get('operation')
            app.logger.debug(f"POST request received. Operation: {operation}")

            if operation == 'scan':
                parsed_processes = blender_analyzer.take_system_sample()

                return jsonify({
                    'status': 'success',
                    'message': 'System scan completed',
                    'processes': parsed_processes
                })

            else:
                app.logger.debug(f"Invalid operation requested: {operation}")
                return jsonify({'error': 'Invalid operation'}), 400

        except Exception as e:
            app.logger.error(f"Error in blender operation: {e}")
            return jsonify({'error': str(e)}), 500


    @app.route('/cleanup', methods=['POST'])
    def cleanup():
        try:
            app.logger.debug("Starting cleanup process.")
            results = {
                'uploads_cleaned': 0,
                'analysis_cleaned': 0,
                'result_cleaned': 0,
                'errors': []
            }

            # Clean uploads folder
            upload_folder = app.config['utils']['upload_folder']
            if os.path.exists(upload_folder):
                app.logger.debug(f"Cleaning uploads folder: {upload_folder}")
                try:
                    files = os.listdir(upload_folder)
                    for f in files:
                        file_path = os.path.join(upload_folder, f)
                        try:
                            if os.path.isfile(file_path):
                                os.unlink(file_path)
                                results['uploads_cleaned'] += 1
                                app.logger.debug(f"Deleted file: {file_path}")
                        except Exception as e:
                            app.logger.error(f"Error deleting file {file_path}: {e}")
                            results['errors'].append(f"Error deleting {f}: {str(e)}")
                except Exception as e:
                    app.logger.error(f"Error accessing uploads folder: {e}")
                    results['errors'].append(f"Error accessing uploads folder: {str(e)}")

            # Clean result folders
            result_folder = app.config['utils']['result_folder']
            exclude_folder = "Blender"  # Exclude this folder

            if os.path.exists(result_folder):
                app.logger.debug(f"Cleaning result folders: {result_folder}")
                try:
                    folders = os.listdir(result_folder)
                    for folder in folders:
                        if folder == exclude_folder:  # Skip Blender folder
                            continue

                        folder_path = os.path.join(result_folder, folder)
                        try:
                            if os.path.isdir(folder_path):
                                shutil.rmtree(folder_path)
                                results['result_cleaned'] += 1
                                app.logger.debug(f"Deleted result folder: {folder_path}")
                        except Exception as e:
                            app.logger.error(f"Error deleting folder {folder_path}: {e}")
                            results['errors'].append(f"Error deleting {folder}: {str(e)}")
                except Exception as e:
                    app.logger.error(f"Error accessing result folder: {e}")
                    results['errors'].append(f"Error accessing result folder: {str(e)}")


            # Clean analysis folders
            analysis_paths = [
                os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis'),
                os.path.join('.', 'Scanners', 'HollowsHunter', 'Analysis')
            ]

            for analysis_path in analysis_paths:
                if os.path.exists(analysis_path):
                    app.logger.debug(f"Cleaning analysis folders: {analysis_path}")
                    try:
                        process_folders = glob.glob(os.path.join(analysis_path, 'process_*'))
                        for folder in process_folders:
                            try:
                                shutil.rmtree(folder)
                                results['analysis_cleaned'] += 1
                                app.logger.debug(f"Deleted analysis folder: {folder}")
                            except Exception as e:
                                app.logger.error(f"Error deleting analysis folder {folder}: {e}")
                                results['errors'].append(f"Error deleting {folder}: {str(e)}")
                    except Exception as e:
                        app.logger.error(f"Error accessing analysis folder: {e}")
                        results['errors'].append(f"Error accessing analysis folder: {str(e)}")

            # Determine status
            status = 'warning' if results['errors'] else 'success'
            message = 'Cleanup completed with some errors' if results['errors'] else 'Cleanup completed successfully'
            app.logger.debug(f"Cleanup completed. Status: {status}, Message: {message}")

            return jsonify({
                'status': status,
                'message': message,
                'details': results
            }), 200 if status == 'success' else 207

        except Exception as e:
            app.logger.error(f"Unexpected error during cleanup: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Cleanup failed',
                'error': str(e)
            }), 500


    @app.route('/health', methods=['GET'])
    def health_check():
        try:
            app.logger.debug("Starting health check.")
            config = app.config
            upload_config = config.get('utils', {})
            analysis_config = config.get('analysis', {})
            issues = []

            # Simple upload folder check
            upload_folder = upload_config.get('upload_folder')
            if not upload_folder:
                app.logger.warning("Upload folder path is not configured.")
                issues.append("Upload folder path is not configured.")
            elif not os.path.isdir(upload_folder):
                app.logger.warning(f"Upload folder does not exist: {upload_folder}")
                issues.append(f"Upload folder does not exist: {upload_folder}")

            # Check static and dynamic analysis tools
            def check_analysis_tool(section, tool_name):
                tool_config = section.get(tool_name, {})
                if tool_config.get('enabled', False):
                    app.logger.debug(f"Checking tool configuration: {tool_name}")
                    tool_path = tool_config.get('tool_path')
                    if not tool_path:
                        issues.append(f"{tool_name}: tool path not configured")
                    elif not os.path.isfile(tool_path):
                        issues.append(f"{tool_name}: tool not found at {tool_path}")
                    
                    rules_path = tool_config.get('rules_path')
                    if rules_path and not os.path.isfile(rules_path):
                        issues.append(f"{tool_name}: rules not found at {rules_path}")

            # Get tools from config instead of hardcoding
            static_section = analysis_config.get('static', {})
            dynamic_section = analysis_config.get('dynamic', {})

            # Check all configured static tools
            for tool_name in static_section.keys():
                check_analysis_tool(static_section, tool_name)

            # Check all configured dynamic tools
            for tool_name in dynamic_section.keys():
                check_analysis_tool(dynamic_section, tool_name)

            # Get all enabled tools for configuration response
            static_tools = {
                tool: static_section.get(tool, {}).get('enabled', False) 
                for tool in static_section.keys()
            }
            
            dynamic_tools = {
                tool: dynamic_section.get(tool, {}).get('enabled', False) 
                for tool in dynamic_section.keys()
            }

            status = 'ok' if not issues else 'degraded'
            app.logger.debug(f"Health check completed. Status: {status}")
            
            return jsonify({
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'upload_folder_accessible': os.path.isdir(upload_folder) if upload_folder else False,
                'issues': issues,
                'configuration': {
                    'static_analysis': static_tools,
                    'dynamic_analysis': dynamic_tools
                }
            }), 200 if status == 'ok' else 503

        except Exception as e:
            app.logger.error(f"Unexpected error during health check: {e}")
            return jsonify({
                'status': 'error',
                'timestamp': datetime.now().isoformat(),
                'issues': [str(e)]
            }), 500


    @app.route('/file/<target>', methods=['DELETE'])
    def delete_file(target):
        try:
            app.logger.debug(f"Deleting file: {target}")
            upload_path = utils.find_file_by_hash(target, app.config['utils']['upload_folder'])
            result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
            analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')

            deleted = {'upload': False, 'result': False, 'analysis': False}

            if upload_path:
                try:
                    os.unlink(upload_path)
                    deleted['upload'] = True
                    app.logger.debug(f"Deleted upload file: {upload_path}")
                except Exception as e:
                    app.logger.error(f"Error deleting upload file {upload_path}: {e}")

            if result_path:
                try:
                    shutil.rmtree(result_path)
                    deleted['result'] = True
                    app.logger.debug(f"Deleted result folder: {result_path}")
                except Exception as e:
                    app.logger.error(f"Error deleting result folder {result_path}: {e}")

            process_folders = glob.glob(os.path.join(analysis_path, f'*_{target}_*'))
            for folder in process_folders:
                try:
                    shutil.rmtree(folder)
                    deleted['analysis'] = True
                    app.logger.debug(f"Deleted analysis folder: {folder}")
                except Exception as e:
                    app.logger.error(f"Error deleting analysis folder {folder}: {e}")

            if not any(deleted.values()):
                app.logger.warning(f"File not found: {target}")
                return jsonify({'status': 'error', 'message': 'File not found'}), 404

            app.logger.debug(f"File {target} deleted successfully.")
            return jsonify({'status': 'success', 'message': 'File deleted successfully', 'details': deleted})

        except Exception as e:
            app.logger.error(f"Unexpected error deleting file {target}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/results/<target>/static', methods=['GET'])
    def api_static_results(target):
        try:
            app.logger.debug(f"Fetching static analysis results for target: {target}")
            result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
            if not result_path:
                app.logger.warning(f"Static results not found for target: {target}")
                return jsonify({'error': 'Results not found'}), 404

            static_path = os.path.join(result_path, 'static_analysis_results.json')
            if not os.path.exists(static_path):
                app.logger.warning(f"Static analysis results not found for target: {target}")
                return jsonify({'error': 'Static analysis results not found'}), 404

            with open(static_path, 'r') as f:
                app.logger.debug(f"Returning static analysis results for target: {target}")
                return jsonify(json.load(f))

        except Exception as e:
            app.logger.error(f"Error fetching static analysis results for target {target}: {e}")
            return jsonify({'error': str(e)}), 500


    @app.route('/api/results/<target>/dynamic', methods=['GET'])
    def api_dynamic_results(target):
        try:
            app.logger.debug(f"Fetching dynamic analysis results for target: {target}")

            if target.isdigit():
                result_folder = os.path.join(app.config['utils']['result_folder'], f'dynamic_{target}')
                dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
            else:
                result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
                if not result_path:
                    app.logger.warning(f"Dynamic results not found for target: {target}")
                    return jsonify({'error': 'Results not found'}), 404
                dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')

            if not os.path.exists(dynamic_path):
                app.logger.warning(f"Dynamic analysis results not found for target: {target}")
                return jsonify({'error': 'Dynamic analysis results not found'}), 404

            with open(dynamic_path, 'r') as f:
                app.logger.debug(f"Returning dynamic analysis results for target: {target}")
                return jsonify(json.load(f))

        except Exception as e:
            app.logger.error(f"Error fetching dynamic analysis results for target {target}: {e}")
            return jsonify({'error': str(e)}), 500


    @app.route('/api/results/<target>/info', methods=['GET'])
    def api_file_info(target):
        try:
            app.logger.debug(f"Fetching file info for target: {target}")
            result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
            if not result_path:
                app.logger.warning(f"File info not found for target: {target}")
                return jsonify({'error': 'File info not found'}), 404

            file_info_path = os.path.join(result_path, 'file_info.json')
            if not os.path.exists(file_info_path):
                app.logger.warning(f"File info not found for target: {target}")
                return jsonify({'error': 'File info not found'}), 404

            with open(file_info_path, 'r') as f:
                app.logger.debug(f"Returning file info for target: {target}")
                return jsonify(json.load(f))

        except Exception as e:
            app.logger.error(f"Error fetching file info for target {target}: {e}")
            return jsonify({'error': str(e)}), 500
    

    @app.errorhandler(404)
    def page_not_found(error):
        app.logger.debug(f"Page not found: {request.path}")
        return render_template('error.html', error=f"Page not found: {request.path}"), 404
    
    return app
