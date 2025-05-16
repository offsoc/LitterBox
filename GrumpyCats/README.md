# GrumpyCats - LitterBox Malware Analysis Clients

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL%20v3-green.svg)]()

A comprehensive toolkit for interacting with LitterBox malware analysis sandbox, featuring a standalone Python client and an MCP server for LLM-assisted analysis.

---

## grumpycat.py

**A Python client for interacting with a LitterBox malware analysis sandbox API.**

### Requirements

```bash
pip install requests
```
* NOTE: Install it globaly on the system 

### Usage

```bash
python grumpycat.py [GLOBAL_OPTIONS] <command> [COMMAND_OPTIONS]
```

```
LitterBox Malware Analysis Client

positional arguments:
  {upload,analyze-pid,results,files,doppelganger-scan,doppelganger,doppelganger-db,cleanup,health,delete}
                        Command to execute
    upload              Upload file for analysis
    analyze-pid         Analyze running process
    results             Get analysis results
    files               Get summary of all analyzed files
    doppelganger-scan   Run doppelganger system scan
    doppelganger        Run doppelganger analysis
    doppelganger-db     Create doppelganger fuzzy database
    cleanup             Clean up analysis artifacts
    health              Check service health
    delete              Delete file and its results

options:
  -h, --help            show this help message and exit
  --debug               Enable debug logging
  --url URL             LitterBox server URL
  --timeout TIMEOUT     Request timeout in seconds
  --no-verify-ssl       Disable SSL verification
  --proxy PROXY         Proxy URL (e.g., http://proxy:8080)


```

## Examples

```
  # Upload and analyze a file
  grumpycat.py upload malware.exe --analysis static dynamic

  # Analyze a running process
  grumpycat.py analyze-pid 1234 --wait

  # Run Doppelganger scan
  grumpycat.py doppelganger-scan --type blender

  # Run Doppelganger analysis
  grumpycat.py doppelganger abc123def --type fuzzy

  # Create fuzzy hash database
  grumpycat.py doppelganger-db --folder /path/to/files --extensions .exe .dll

  # Get analysis results
  grumpycat.py results abc123def --type static

  # Clean up analysis artifacts
  grumpycat.py cleanup --all
```
---

## LitterBoxMCP.py

**A MCP server that wrap grumpycat.py to intercat with LitterBox server.**

### Requirements

| Requirement | Installation |
|-------------|--------------|
| **Claude Desktop** | [Download](https://claude.ai/desktop) |
| **fastmcp** | `pip install fastmcp` |
| **mcp-server** | `pip install mcp-server` |
| **requests** | `pip install requests` |
| **uv** | `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| **grumpycat.py** | Place in same directory |

### Setup

1. **Install all requirements**
2. **Install LitterBoxMCP in Claude Desktop:**

```bash
mcp install .\LitterBoxMCP.py
```

**Expected output:**
```
[05/16/25 02:47:13] INFO     Added server 'LitterBoxMCP' to Claude config                                  claude.py:143
                    INFO     Successfully installed LitterBoxMCP in Claude app  
```

### Core Analysis Tools

| Tool | Description |
|------|-------------|
| `upload_payload(path, name=None)` | Upload payload and get hash for analysis |
| `analyze_static(file_hash)` | Run static analysis - check YARA signatures and file characteristics |
| `analyze_dynamic(target, cmd_args=None)` | Run dynamic analysis - test behavioral detection and runtime artifacts |
| `get_file_info(file_hash)` | Get file metadata, entropy, and PE information |
| `get_static_results(file_hash)` | Get detailed static analysis results |
| `get_dynamic_results(target)` | Get detailed dynamic analysis results |

### Utility Tools

| Tool | Description |
|------|-------------|
| `list_payloads()` | Get summary of all tested payloads |
| `validate_pid(pid)` | Validate process ID before dynamic analysis |
| `cleanup()` | Remove all testing artifacts from sandbox |
| `health_check()` | Verify sandbox tools are operational |
| `delete_payload(file_hash)` | Remove payload and all analysis results |

### OPSEC-Focused Prompts

| Prompt | Purpose |
|--------|---------|
| `analyze_detection_patterns(file_hash="")` | Analyze what's getting detected and why - YARA rules, entropy, behavioral patterns |
| `assess_evasion_effectiveness(file_hash="")` | Evaluate signature and behavioral evasion success rates |
| `analyze_opsec_violations(file_hash="")` | Identify attribution risks and operational security violations |
| `generate_improvement_plan(file_hash="")` | Create prioritized roadmap for payload enhancement |
| `evaluate_deployment_readiness(file_hash="")` | Assess if payload is ready for operational deployment |

### Key Features

- **Robust Error Handling** - Detailed status messages for API errors
- **OPSEC Focus** - Detection evasion, signature bypassing, and attribution avoidance
- **Actionable Intelligence** - Specific recommendations for improving payload stealth
- **Comprehensive Analysis** - Static signatures, dynamic behavior, and operational security

## Claude prompts example


https://github.com/user-attachments/assets/bd5e0653-c4c3-4d89-8651-215b8ee9cea2



