# LitterBox
![single grumpy cat](https://github.com/user-attachments/assets/20030454-55b8-4473-b7b7-f65bb7150d51)

Your malware's favorite sandbox - where red teamers come to bury their payloads.

A sandbox environment designed specifically for malware development and payload testing. 

This Web Application enables red teamers to validate evasion techniques, assess detection signatures, and test implant behavior before deployment in the field. 

Think of it as your personal LitterBox for perfecting your tradecraft without leaving traces on production detection systems.

The platform provides automated analysis through an intuitive web interface, monitoring process behavior and generating comprehensive runtime analysis reports. 

This ensures your payloads work as intended before execution in target environments.

## Features

### Initial Analysis
- File identification with multiple hashing algorithms (MD5, SHA256)
- Shannon entropy calculation for encryption detection
- Advanced file type detection and MIME analysis
- Original filename preservation
- Upload timestamp tracking

### PE File Analysis
For Windows executables (.exe, .dll, .sys):
- PE file type detection (PE32/PE32+)
- Machine architecture identification
- Compilation timestamp analysis
- Subsystem classification
- Entry point detection
- Section enumeration and analysis
- Import DLL dependency mapping

### Office Document Analysis
For Microsoft Office files (.docx, .xlsx, .doc, .xls, .xlsm, .docm):
- Macro detection and extraction
- VBA code analysis
- Hidden content identification

## Analysis Capabilities

### Static Analysis Engine
- Signature-based detection using industry-standard rulesets
- Binary entropy analysis
- String extraction and analysis
- Pattern matching for suspicious indicators

### Dynamic Analysis Engine
Available in two modes:
- File Analysis Mode
- Process ID (PID) Analysis Mode

Features include:
- Behavioral monitoring
- Memory region inspection
- Process hollowing detection
- Injection technique analysis
- Sleep pattern monitoring
- Collect Windows telemetry via ETW

## Integrated Tools

### Static Analysis Suite
- [YARA](https://github.com/elastic/protections-artifacts/tree/main/yara) - Pattern matching and signature detection
- [CheckPlz](https://github.com/BlackSnufkin/CheckPlz) - AV detection testing
- [Stringnalyzer](https://github.com/BlackSnufkin/Rusty-Playground/Stringnalyzer) - Payload Strings analyzer (Note: May produce false positives)

### Dynamic Analysis Suite
- [YARA](https://github.com/elastic/protections-artifacts/tree/main/yara) (memory scanning) - Runtime pattern detection
- [PE-Sieve](https://github.com/hasherezade/pe-sieve) - Detecting and dumping in-memory malware implants and advanced process injection techniques
- [Moneta](https://github.com/forrest-orr/moneta) - Usermode memory analysis tool to detect malware IOCs
- [Patriot](https://github.com/BlackSnufkin/patriot) - Detecting various kinds of in-memory stealth techniques
- [RedEdr](https://github.com/dobin/RedEdr) - Collect Windows telemetry via ETW providers (Note: See issue #6)
- [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons) - Beacon behavior analysis

## Web Endpoint Reference


#### File Management
```http
POST   /upload                    # Upload files for analysis
GET    /files                     # Get list of processed files
```
#### Analysis Operations 
```http
GET    /analyze/static/<hash>     # Static file analysis
POST   /analyze/dynamic/<hash>    # Dynamic file analysis  
POST   /analyze/dynamic/<pid>     # Process analysis
```
#### API Results (JSON)
```http
GET    /api/results/<hash>/info   # Get Json file info
GET    /api/results/<hash>/static # Get Json results for file static analysis
GET    /api/results/<hash>/dynamic # Get Json results for file dynamic analysis
GET    /api/results/<pid>/dynamic # Get Json results for pid analysis
```
#### Web Results
```http
GET    /results/<hash>/info      # Get file info
GET    /results/<hash>/static    # Get results for file static analysis
GET    /results/<hash>/dynamic   # Get results for file dynamic analysis
GET    /results/<pid>/dynamic    # Get results for pid analysis
```
#### System Management
```http
GET  /health                 # System health and tool status check
POST /cleanup                # Clean analysis artifacts and uploads
POST /validate/<pid>         # Validate process accessibility
DELETE /file/<hash>          # Delete single analysis
```
## Installation

### Prerequisites
- Python 3.11 or higher
- Administrator privileges (required for certain features)
- Windows operating system (required for specific analyzers)

### Setup Steps

1. Clone the repository:
```bash
git clone https://github.com/BlackSnufkin/LitterBox.git
cd LitterBox
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

### Running LitterBox

```bash
python litterbox.py
```
### Running LitterBox in debug mode

```bash
python litterbox.py --debug
```

The web interface will be available at: `http://127.0.0.1:1337`

## Configuration

The `config.yml` file controls:
- Upload directory and allowed extensions
- Analysis tool paths and Command options
- YARA rule locations
- Analysis timeouts and limits


## SECURITY WARNINGS

- **DO NOT USE IN PRODUCTION**: This tool is designed for development and testing environments only. Running it in production could expose your systems to serious security risks.
- **ISOLATED ENVIRONMENT**: Only run LitterBox in an isolated, disposable virtual machine or dedicated testing environment.
- **NO WARRANTY**: This software is provided "as is" without any guarantees. Use at your own risk.
- **LEGAL DISCLAIMER**: Only use this tool for authorized testing purposes. Users are responsible for complying with all applicable laws and regulations.

## Acknowledgments

This project incorporates the following open-source components and acknowledges their authors:


- [Elastic](https://github.com/elastic/protections-artifacts/tree/main/yara)
- [hasherezade](https://github.com/hasherezade/pe-sieve)
- [Forrest Orr](https://github.com/forrest-orr/moneta)
- [rasta-mouse](https://github.com/rasta-mouse/ThreatCheck)
- [thefLink](https://github.com/thefLink/Hunt-Sleeping-Beacons)
- [joe-desimone](https://github.com/joe-desimone/patriot)
- [dobin](https://github.com/dobin/RedEdr)

## Screenshots

![upload](https://github.com/user-attachments/assets/26ab6f33-4746-41c7-82cd-ee490d57ad95)

![dynamic](https://github.com/user-attachments/assets/02202021-f7e0-47a2-a993-2655da36dfde)

![static](https://github.com/user-attachments/assets/9f10cff2-e0f8-4a33-9a8e-5e98667e4d4f)

![summary](https://github.com/user-attachments/assets/58dc3840-4bd9-4dc3-9778-d9640b372af6)



