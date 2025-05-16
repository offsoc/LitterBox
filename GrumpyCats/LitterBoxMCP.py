from mcp.server.fastmcp import FastMCP
from grumpycat import LitterBoxClient, LitterBoxError, LitterBoxAPIError

# Initialize MCP server focused on efficient payload OPSEC analysis
mcp = FastMCP(
    name="LitterBoxMCP",
    instructions=(
        "You are an elite payload OPSEC specialist focused on detection evasion.\n"
        "Analyze YARA signatures, behavioral patterns, and detection triggers.\n"
        "Provide actionable tradecraft improvements for bypassing EDR and AV.\n"
        "Focus on signature evasion, behavioral stealth, and attribution avoidance.\n"
        "Emphasize practical improvements to enhance payload operational security."
    ),
)

# Initialize LitterBox client
client = LitterBoxClient(base_url="http://127.0.0.1:1337")

def handle_api(callable_fn, *args, **kwargs):
    """Clean error handling for API operations"""
    try:
        result = callable_fn(*args, **kwargs)
        return {"status": "success", "data": result}
    except LitterBoxAPIError as e:
        return {"status": "api_error", "message": str(e), "http_code": e.status_code}
    except LitterBoxError as e:
        return {"status": "client_error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Core Analysis Tools
@mcp.tool(name="upload_payload", description="Upload payload for OPSEC testing")
def upload_payload(path: str, name: str = None):
    """Upload payload and get hash for analysis"""
    return handle_api(client.upload_file, path, file_name=name)

@mcp.tool(name="analyze_static", description="Run static analysis - check YARA signatures and file characteristics")
def analyze_static(file_hash: str):
    """Run static analysis to identify signature detections"""
    return handle_api(client.analyze_file, file_hash, 'static')

@mcp.tool(name="analyze_dynamic", description="Run dynamic analysis - test behavioral detection and runtime artifacts")
def analyze_dynamic(target: str, cmd_args: list = None):
    """Run dynamic analysis to test behavioral evasion"""
    return handle_api(client.analyze_file, target, 'dynamic', cmd_args=cmd_args)

@mcp.tool(name="get_file_info", description="Get basic file information and characteristics")
def get_file_info(file_hash: str):
    """Get file metadata, entropy, and PE information"""
    return handle_api(client.get_results, file_hash, 'info')

@mcp.tool(name="get_static_results", description="Get static analysis results - YARA hits and signature detections")
def get_static_results(file_hash: str):
    """Get detailed static analysis results"""
    return handle_api(client.get_results, file_hash, 'static')

@mcp.tool(name="get_dynamic_results", description="Get dynamic analysis results - behavioral detections and runtime artifacts")
def get_dynamic_results(target: str):
    """Get detailed dynamic analysis results"""
    return handle_api(client.get_results, target, 'dynamic')


# Utility Tools
@mcp.tool(name="list_payloads", description="List all analyzed payloads with summaries")
def list_payloads():
    """Get summary of all tested payloads"""
    return handle_api(client.get_files_summary)

@mcp.tool(name="validate_pid", description="Validate process ID for dynamic analysis")
def validate_pid(pid: int):
    """Validate PID before dynamic analysis"""
    return handle_api(client.validate_process, pid)

@mcp.tool(name="cleanup", description="Clean up all testing artifacts")
def cleanup():
    """Remove all testing artifacts from sandbox"""
    return handle_api(client.cleanup)

@mcp.tool(name="health_check", description="Check sandbox health status")
def health_check():
    """Verify sandbox tools are operational"""
    return handle_api(client.check_health)

@mcp.tool(name="delete_payload", description="Delete specific payload and results")
def delete_payload(file_hash: str):
    """Remove payload and all analysis results"""
    return handle_api(client.delete_file, file_hash)

# OPSEC-Focused Prompts
@mcp.prompt()
def analyze_detection_patterns(file_hash: str = "") -> str:
    """Analyze what's getting detected and why"""
    return f"""Analyze detection patterns for {f'payload {file_hash}' if file_hash else 'the payload'}:

## Static Detection Analysis
- YARA rule matches and triggered signatures
- File entropy and packing indicators
- Import table and string analysis findings
- PE structure anomalies

## Dynamic Detection Analysis  
- Process manipulation behaviors detected
- Memory artifacts flagged by Moneta
- Behavioral patterns triggering alerts
- Runtime API usage patterns

## Detection Improvement Strategy
- Signature evasion techniques needed
- Behavioral modification recommendations
- Obfuscation and packing adjustments
- Alternative implementation approaches

Focus on specific, actionable improvements to bypass detected patterns."""

@mcp.prompt()
def assess_evasion_effectiveness(file_hash: str = "") -> str:
    """Assess payload evasion effectiveness and improvement areas"""
    return f"""Evaluate evasion effectiveness for {f'payload {file_hash}' if file_hash else 'the payload'}:

## Signature Evasion Assessment
- YARA rule bypass success/failure
- Anti-virus signature avoidance
- Static analysis resistance level
- String obfuscation effectiveness

## Behavioral Evasion Assessment
- EDR behavioral detection bypass
- Process manipulation stealth
- Memory artifact minimization
- Runtime pattern camouflage

## Improvement Recommendations
- Prioritized evasion enhancements
- Specific code modification suggestions
- Alternative technique recommendations
- Testing validation requirements

Provide concrete steps to improve detection evasion rates."""

@mcp.prompt()
def analyze_opsec_violations(file_hash: str = "") -> str:
    """Identify OPSEC violations and attribution risks"""
    return f"""Identify OPSEC violations for {f'payload {file_hash}' if file_hash else 'the payload'}:

## Attribution Risk Factors
- Similarity to known offensive tools
- Unique behavioral fingerprints
- Metadata and compilation artifacts
- Code pattern attributions

## OPSEC Violation Analysis
- Signature patterns revealing tool origin
- Behavioral traits linking to frameworks
- File characteristics indicating toolset
- Communication patterns exposing infrastructure

## Mitigation Strategies
- Attribution masking techniques
- Behavioral diversification methods
- Metadata sanitization requirements
- Fingerprint elimination approaches

Focus on maintaining operational anonymity and avoiding tool attribution."""

@mcp.prompt()
def generate_improvement_plan(file_hash: str = "") -> str:
    """Generate prioritized improvement plan for payload enhancement"""
    return f"""Create improvement plan for {f'payload {file_hash}' if file_hash else 'the payload'}:

## Detection Issues Identified
- Critical signature detections requiring immediate attention
- Behavioral patterns triggering EDR alerts
- File characteristics exposing payload nature
- Attribution risks from tool similarity

## Improvement Priority Matrix
1. **CRITICAL** - Signature bypasses for deployment readiness
2. **HIGH** - Behavioral evasion improvements
3. **MEDIUM** - Attribution risk mitigation
4. **LOW** - General stealth enhancements

## Implementation Roadmap
- Immediate fixes for critical detections
- Behavioral modification timeline
- Testing and validation checkpoints
- Deployment readiness criteria

## Success Metrics
- Signature detection rate reduction
- Behavioral alert elimination
- Attribution risk minimization
- Overall stealth improvement

Provide actionable, prioritized steps for payload enhancement."""

@mcp.prompt()
def evaluate_deployment_readiness(file_hash: str = "") -> str:
    """Evaluate if payload is ready for operational deployment"""
    return f"""Evaluate deployment readiness for {f'payload {file_hash}' if file_hash else 'the payload'}:

## Readiness Assessment Criteria
- **Signature Evasion**: No YARA rule matches
- **Behavioral Stealth**: Clean dynamic analysis results
- **Attribution Risk**: Low similarity to known tools
- **Technical Functionality**: Proper execution and behavior

## Risk Assessment
- Detection probability estimation
- Attribution risk evaluation
- Operational security threats
- Incident response impact

## Deployment Decision Matrix
```
Category        | Status | Severity | Blocker
----------------|--------|----------|--------
Signatures      | P/F    | H/M/L    | Y/N
Behavior        | P/F    | H/M/L    | Y/N
Attribution     | P/F    | H/M/L    | Y/N
Functionality   | P/F    | H/M/L    | Y/N
```

## Final Recommendation
- **GO/NO-GO/CONDITIONAL** deployment decision
- Required fixes before deployment
- Risk acceptance considerations
- Monitoring requirements post-deployment

Provide clear deployment recommendation with supporting rationale."""

if __name__ == "__main__":
    mcp.serve(host="0.0.0.0", port=50051)