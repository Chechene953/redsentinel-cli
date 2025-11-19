# redsentinel/tools/nuclei_wrapper.py
from redsentinel.tools.external_tool import find_binary, run_command
from redsentinel.core.error_handler import get_error_handler, ErrorContext
import os
import logging
import json
import tempfile
from typing import List, Dict, Any, Optional, Union

logger = logging.getLogger(__name__)
error_handler = get_error_handler()


def parse_nuclei_json(output_file: str) -> List[Dict[str, Any]]:
    """
    Parse Nuclei JSON output file
    
    Args:
        output_file: Path to Nuclei JSON output file
    
    Returns:
        List of parsed vulnerability findings
    """
    vulnerabilities = []
    
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    finding = json.loads(line)
                    vulnerabilities.append(finding)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Nuclei JSON line: {e}")
                    continue
    
    except FileNotFoundError:
        logger.error(f"Nuclei output file not found: {output_file}")
    except Exception as e:
        error_handler.handle_error(e, ErrorContext("parse_nuclei_json", output_file))
    
    return vulnerabilities


def parse_nuclei_output(output: str, format_type: str = "json") -> List[Dict[str, Any]]:
    """
    Parse Nuclei output text
    
    Args:
        output: Nuclei output text
        format_type: Output format (json, text)
    
    Returns:
        List of parsed findings
    """
    findings = []
    
    if format_type == "json":
        # Try to parse as JSON lines (JSONL)
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                continue
    
    elif format_type == "text":
        # Parse text output (basic parsing)
        lines = output.split('\n')
        current_finding = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_finding:
                    findings.append(current_finding)
                    current_finding = {}
                continue
            
            # Try to extract information from text format
            if '[' in line and ']' in line:
                # Extract severity/template name
                parts = line.split(']')
                if len(parts) >= 2:
                    severity_part = parts[0].replace('[', '').strip()
                    rest = ']'.join(parts[1:]).strip()
                    
                    current_finding['severity'] = severity_part
                    current_finding['template'] = rest.split()[0] if rest else ""
                    current_finding['matched_at'] = rest.split()[-1] if len(rest.split()) > 1 else ""
    
    return findings


def nuclei_scan(
    targets: Union[str, List[str]],
    path: str = "/usr/local/bin/nuclei",
    templates: Optional[str] = None,
    args: str = "-silent -json",
    timeout: int = 300,
    dry_run: bool = False,
    output_format: str = "json"
) -> Dict[str, Any]:
    """
    Run Nuclei scan with improved output parsing
    
    Args:
        targets: Target(s) to scan (string or list)
        path: Path to nuclei binary
        templates: Template directory or specific template
        args: Additional Nuclei arguments
        timeout: Timeout in seconds
        dry_run: If True, don't actually run
        output_format: Output format (json, text)
    
    Returns:
        Dict with scan results including parsed findings
    """
    context = ErrorContext("nuclei_scan", str(targets))
    
    binpath = find_binary("nuclei") or (path if os.path.exists(path) else None)
    if not binpath:
        return {"error": "nuclei binary not found", "findings": []}
    
    # Create temporary file for targets if list
    tfile = None
    if isinstance(targets, (list, tuple)):
        tfile = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for t in targets:
            tfile.write(t + "\n")
        tfile.close()
        targets_arg = f"-l {tfile.name}"
    else:
        targets_arg = targets
    
    # Create temporary output file
    output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
    output_file.close()
    
    # Build command
    tmpl = f"-t {templates}" if templates else ""
    
    # Ensure JSON output if format is json
    if output_format == "json" and "-json" not in args:
        args = f"{args} -json"
    
    cmd = f"{binpath} {targets_arg} {tmpl} {args} -o {output_file.name}"
    
    try:
        rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
        
        findings = []
        if not dry_run and os.path.exists(output_file.name):
            if output_format == "json":
                findings = parse_nuclei_json(output_file.name)
            else:
                # Read text output
                with open(output_file.name, 'r', encoding='utf-8') as f:
                    output_text = f.read()
                findings = parse_nuclei_output(output_text, format_type="text")
        
        # Cleanup
        if os.path.exists(output_file.name):
            os.unlink(output_file.name)
        if tfile and os.path.exists(tfile.name):
            os.unlink(tfile.name)
        
        return {
            "rc": rc,
            "out": out,
            "err": err,
            "findings": findings,
            "count": len(findings),
            "format": output_format
        }
    
    except Exception as e:
        error_info = error_handler.handle_error(e, context)
        
        # Cleanup on error
        if os.path.exists(output_file.name):
            try:
                os.unlink(output_file.name)
            except:
                pass
        if tfile and os.path.exists(tfile.name):
            try:
                os.unlink(tfile.name)
            except:
                pass
        
        return {
            "error": str(e),
            "error_details": error_info,
            "findings": [],
            "count": 0
        }


def extract_nuclei_vulnerabilities(nuclei_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract structured vulnerability information from Nuclei results
    
    Args:
        nuclei_results: Results from nuclei_scan
    
    Returns:
        List of structured vulnerability dicts
    """
    vulnerabilities = []
    
    findings = nuclei_results.get("findings", [])
    
    for finding in findings:
        vuln = {
            "id": finding.get("template-id", finding.get("template", "unknown")),
            "name": finding.get("info", {}).get("name", finding.get("template", "Unknown")),
            "severity": finding.get("info", {}).get("severity", finding.get("severity", "unknown")).upper(),
            "description": finding.get("info", {}).get("description", ""),
            "matched_at": finding.get("matched-at", finding.get("matched_at", "")),
            "request": finding.get("request", ""),
            "response": finding.get("response", ""),
            "curl_command": finding.get("curl-command", ""),
            "cve_ids": finding.get("info", {}).get("classification", {}).get("cve-id", []),
            "cwe_ids": finding.get("info", {}).get("classification", {}).get("cwe-id", []),
            "cvss_score": finding.get("info", {}).get("classification", {}).get("cvss-score", ""),
            "reference": finding.get("info", {}).get("reference", []),
            "tags": finding.get("info", {}).get("tags", [])
        }
        
        # Extract CVE/CWE from tags if not in classification
        if not vuln["cve_ids"]:
            tags = vuln.get("tags", [])
            vuln["cve_ids"] = [tag for tag in tags if tag.startswith("CVE-")]
        
        if not vuln["cwe_ids"]:
            tags = vuln.get("tags", [])
            vuln["cwe_ids"] = [tag for tag in tags if tag.startswith("CWE-")]
        
        vulnerabilities.append(vuln)
    
    return vulnerabilities
