# GrumpyCats

![GrumpyCats Banner](https://github.com/user-attachments/assets/9d4018f7-79e8-4835-82af-49cf6c12b9e9)

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL%20v3-green.svg)]()
[![MCP Supported](https://img.shields.io/badge/MCP-Supported-blueviolet.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-brightgreen.svg)]()

## Overview

GrumpyCats provides a comprehensive toolkit for interacting with the LitterBox malware analysis sandbox. The package includes two main components:

1. **grumpycat.py** - A Python client that functions as both a standalone CLI utility and an importable library
2. **LitterBoxMCP.py** - An MCP server that enables LLM agents to interact with the LitterBox platform

---

## Table of Contents
- [GrumpyCats](#grumpycats)
  - [grumpycat.py](#grumpycatpy)
  - [Usage Examples](#usage-examples)
  - [LitterBoxMCP.py](#litterboxmcppy)
  - [Installation](#installation)
  - [API Reference](#litterboxmcp-api-reference)
---

## grumpycat.py

This Python client provides both CLI and API access to the LitterBox malware analysis sandbox.

### Requirements

```bash
pip install requests
```
**Note:** Install globally on your system if using with Claude Desktop or other LLM agents.

### Command Line Interface

```bash
python grumpycat.py [GLOBAL_OPTIONS] <command> [COMMAND_OPTIONS]
```

### Available Commands

| Command | Description |
|---------|-------------|
| `upload` | Upload file for analysis |
| `analyze-pid` | Analyze running process |
| `results` | Get analysis results |
| `report` | Generate and download analysis report |
| `files` | Get summary of all analyzed files |
| `doppelganger-scan` | Run doppelganger system scan |
| `doppelganger` | Run doppelganger analysis |
| `doppelganger-db` | Create doppelganger fuzzy database |
| `cleanup` | Clean up analysis artifacts |
| `health` | Check service health |
| `delete` | Delete file and its results |

### Global Options

| Option | Description |
|--------|-------------|
| `--debug` | Enable debug logging |
| `--url URL` | LitterBox server URL |
| `--timeout TIMEOUT` | Request timeout in seconds |
| `--no-verify-ssl` | Disable SSL verification |
| `--proxy PROXY` | Proxy URL (e.g., http://proxy:8080) |


## Usage Examples

### Basic Analysis Workflow

```bash
# Upload and analyze a file
grumpycat.py upload malware.exe --analysis static dynamic

# Analyze a running process
grumpycat.py analyze-pid 1234 --wait

# Get analysis results
grumpycat.py results abc123def --type static
```

### Doppelganger Analysis

```bash
# Run Doppelganger blender scan
grumpycat.py doppelganger-scan --type blender

# Run Doppelganger FuzzyHash analysis
grumpycat.py doppelganger abc123def --type fuzzy

# Create fuzzy hash database
grumpycat.py doppelganger-db --folder /path/to/files --extensions .exe .dll
```

### Report Generation

```bash
# Generate and view an HTML report in terminal
grumpycat.py report abc123def

# Download a report to the current directory
grumpycat.py report abc123def --download

# Download a report to a specific location
grumpycat.py report abc123def --download --output /path/to/reports/malware_report.html

# Open a report directly in your web browser
grumpycat.py report abc123def --browser
```

### Maintenance Operations

```bash
# Clean up analysis artifacts
grumpycat.py cleanup --all

# Check system health
grumpycat.py health

# Delete a payload and its results
grumpycat.py delete abc123def
```
---

## LitterBoxMCP.py

The LitterBoxMCP server wraps the grumpycat.py functionality to enable LLM agents (like Claude) to interact with the LitterBox analysis platform through natural language.

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

```bash
mcp install .\LitterBoxMCP.py
```

**Expected output:**
```
[05/16/25 02:47:13] INFO     Added server 'LitterBoxMCP' to Claude config                                  claude.py:143
                    INFO     Successfully installed LitterBoxMCP in Claude app  
```

## Installation

1. Clone or download the LitterBox repository
2. For CLI usage, install the requests library globally
3. For MCP server usage, install all requirements listed in the LitterBoxMCP section
4. Install the MCP server in Claude Desktop if using LLM integration


## LitterBoxMCP API Reference

The following functions are available when using LitterBoxMCP with Claude Desktop or other LLM agents:

### Core Analysis Tools

| Function | Description |
|----------|-------------|
| `upload_payload(path, name=None)` | Upload payload and get hash for analysis |
| `analyze_static(file_hash)` | Run static analysis - check YARA signatures and file characteristics |
| `analyze_dynamic(target, cmd_args=None)` | Run dynamic analysis - test behavioral detection and runtime artifacts |
| `get_file_info(file_hash)` | Get file metadata, entropy, and PE information |
| `get_static_results(file_hash)` | Get detailed static analysis results |
| `get_dynamic_results(target)` | Get detailed dynamic analysis results |

### Utility Tools

| Function | Description |
|----------|-------------|
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

### Claude Integration

https://github.com/user-attachments/assets/bd5e0653-c4c3-4d89-8651-215b8ee9cea2
