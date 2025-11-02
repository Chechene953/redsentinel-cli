# redsentinel/workflows/engine.py
import asyncio
import logging
from typing import Dict, List, Any
from redsentinel.workflows.presets import get_workflow, list_workflows

logger = logging.getLogger(__name__)


# Tool mapping for dynamic imports
TOOL_MAPPING = {
    "crtsh_subdomains": "redsentinel.recon",
    "enhanced_subdomain_enum": "redsentinel.recon",
    "scan_ports": "redsentinel.scanner",
    "fetch_http_info": "redsentinel.webcheck",
    "nmap_scan_nm": "redsentinel.tools.nmap_wrapper",
    "nuclei_scan": "redsentinel.tools.nuclei_wrapper",
    "ffuf_scan": "redsentinel.tools.ffuf_wrapper",
    "comprehensive_dns_enum": "redsentinel.tools.dns_tools",
    "comprehensive_ssl_analysis": "redsentinel.tools.ssl_tools",
    "nikto_scan": "redsentinel.tools.nikto_wrapper"
}


def import_tool(tool_name):
    """Dynamically import tool function"""
    if tool_name not in TOOL_MAPPING:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    module_path = TOOL_MAPPING[tool_name]
    module = __import__(module_path, fromlist=[tool_name])
    return getattr(module, tool_name)


def substitute_params(params, target):
    """Substitute {target} placeholder in params"""
    if isinstance(params, dict):
        return {k: substitute_params(v, target) for k, v in params.items()}
    elif isinstance(params, list):
        return [substitute_params(v, target) for v in params]
    elif isinstance(params, str):
        return params.replace("{target}", target)
    return params


async def execute_step(step, target):
    """Execute a single workflow step"""
    step_name = step.get("name")
    tool_name = step.get("tool")
    enabled = step.get("enabled", True)
    params = step.get("params", {})
    
    if not enabled:
        logger.info(f"Skipping disabled step: {step_name}")
        return {"step": step_name, "status": "skipped"}
    
    try:
        # Import and call tool
        tool_func = import_tool(tool_name)
        
        # Substitute parameters
        real_params = substitute_params(params, target)
        
        # Execute (handle async/sync)
        if asyncio.iscoroutinefunction(tool_func):
            result = await tool_func(**real_params)
        else:
            result = tool_func(**real_params)
        
        return {
            "step": step_name,
            "status": "completed",
            "result": result
        }
    
    except Exception as e:
        logger.error(f"Error in step {step_name}: {e}")
        return {
            "step": step_name,
            "status": "error",
            "error": str(e)
        }


async def run_workflow(workflow_name, target, steps=None):
    """
    Run a workflow
    
    Args:
        workflow_name: Name of workflow preset
        target: Target domain or host
        steps: Optional custom steps (overrides preset)
    
    Returns:
        dict with workflow results
    """
    # Get workflow preset if no custom steps
    if steps is None:
        workflow = get_workflow(workflow_name)
        if not workflow:
            return {"error": f"Workflow '{workflow_name}' not found"}
        steps = workflow["steps"]
    
    results = {
        "workflow": workflow_name,
        "target": target,
        "steps": []
    }
    
    # Execute each step sequentially
    for step in steps:
        step_result = await execute_step(step, target)
        results["steps"].append(step_result)
        
        # Stop on error if configured
        if step_result["status"] == "error":
            break
    
    return results


def get_available_workflows():
    """Get list of available workflow presets"""
    return list_workflows()

