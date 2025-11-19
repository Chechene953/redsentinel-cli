# redsentinel/workflows/engine.py
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from redsentinel.workflows.presets import get_workflow, list_workflows
from redsentinel.core.error_handler import ErrorHandler, ErrorContext, get_error_handler

logger = logging.getLogger(__name__)
error_handler = get_error_handler()

# Tool mapping for dynamic imports
TOOL_MAPPING = {
    "crtsh_subdomains": ("redsentinel.recon", "crtsh_subdomains"),
    "enhanced_subdomain_enum": ("redsentinel.recon", "enhanced_subdomain_enum"),
    "scan_ports": ("redsentinel.scanner", "scan_ports"),
    "fetch_http_info": ("redsentinel.webcheck", "fetch_http_info"),
    "nmap_scan_nm": ("redsentinel.tools.nmap_wrapper", "nmap_scan_nm"),
    "nuclei_scan": ("redsentinel.tools.nuclei_wrapper", "nuclei_scan"),
    "ffuf_scan": ("redsentinel.tools.ffuf_wrapper", "ffuf_scan"),
    "comprehensive_dns_enum": ("redsentinel.tools.dns_tools", "comprehensive_dns_enum"),
    "comprehensive_ssl_analysis": ("redsentinel.tools.ssl_tools", "comprehensive_ssl_analysis"),
    "nikto_scan": ("redsentinel.tools.nikto_wrapper", "nikto_scan")
}

# Fallback mappings pour compatibilité avec anciens workflows
LEGACY_TOOL_MAPPING = {
    "scan_ports": ("redsentinel.cli_menu", "do_portscan"),  # Ancien mapping
}


def import_tool(tool_name: str, retry_count: int = 3) -> Optional[Callable]:
    """
    Dynamically import tool function with error handling and retry
    
    Args:
        tool_name: Name of the tool to import
        retry_count: Number of retry attempts
    
    Returns:
        Callable function or None if import failed
    """
    context = ErrorContext("import_tool", tool_name)
    
    if tool_name not in TOOL_MAPPING and tool_name not in LEGACY_TOOL_MAPPING:
        error_handler.handle_error(
            ValueError(f"Unknown tool: {tool_name}"),
            context
        )
        return None
    
    # Essayer le mapping principal d'abord
    module_path, func_name = TOOL_MAPPING.get(tool_name) or LEGACY_TOOL_MAPPING.get(tool_name)
    
    last_error = None
    
    for attempt in range(retry_count):
        try:
            context.add_context("attempt", attempt + 1)
            context.add_context("module_path", module_path)
            context.add_context("func_name", func_name)
            
            # Importer le module
            if '.' in module_path:
                parts = module_path.split('.')
                # Importer progressivement pour éviter les erreurs de chemin
                module = None
                for i in range(1, len(parts) + 1):
                    partial_path = '.'.join(parts[:i])
                    try:
                        if i == len(parts):
                            module = __import__(partial_path, fromlist=[parts[-1]])
                        else:
                            __import__(partial_path)
                    except ImportError as e:
                        if i == len(parts):
                            # Dernière partie - c'est peut-être une fonction
                            # Essayer d'importer le module parent
                            parent_path = '.'.join(parts[:-1])
                            module = __import__(parent_path, fromlist=[parts[-2]])
                            # La fonction pourrait être dans le module parent
                            func_name = parts[-1]
                            break
                        raise
            else:
                module = __import__(module_path, fromlist=[tool_name])
                func_name = tool_name
            
            # Récupérer la fonction
            if hasattr(module, func_name):
                func = getattr(module, func_name)
                context.add_context("success", True)
                return func
            else:
                # Essayer de trouver la fonction dans les sous-modules
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if callable(attr) and attr_name.lower() == func_name.lower():
                        context.add_context("found_alternative", attr_name)
                        return attr
                
                raise AttributeError(f"Function '{func_name}' not found in module '{module_path}'")
        
        except ImportError as e:
            last_error = e
            context.add_context("error_type", "ImportError")
            context.add_context("error_message", str(e))
            
            # Si c'est le dernier essai, logger l'erreur
            if attempt == retry_count - 1:
                error_handler.handle_error(e, context)
            else:
                # Attendre un peu avant de réessayer
                import time
                time.sleep(0.1 * (attempt + 1))
        
        except AttributeError as e:
            last_error = e
            context.add_context("error_type", "AttributeError")
            context.add_context("error_message", str(e))
            
            if attempt == retry_count - 1:
                error_handler.handle_error(e, context)
            else:
                import time
                time.sleep(0.1 * (attempt + 1))
        
        except Exception as e:
            last_error = e
            context.add_context("error_type", type(e).__name__)
            context.add_context("error_message", str(e))
            
            if attempt == retry_count - 1:
                error_handler.handle_error(e, context)
            else:
                import time
                time.sleep(0.1 * (attempt + 1))
    
    # Si tous les essais ont échoué
    logger.error(f"Failed to import tool '{tool_name}' after {retry_count} attempts")
    return None


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
    """Execute a single workflow step with improved error handling"""
    step_name = step.get("name", "unknown")
    tool_name = step.get("tool")
    enabled = step.get("enabled", True)
    params = step.get("params", {})
    continue_on_error = step.get("continue_on_error", False)
    
    if not enabled:
        logger.info(f"Skipping disabled step: {step_name}")
        return {"step": step_name, "status": "skipped"}
    
    if not tool_name:
        return {
            "step": step_name,
            "status": "error",
            "error": "No tool specified"
        }
    
    context = ErrorContext(f"execute_step_{step_name}", target)
    context.add_context("tool_name", tool_name)
    context.add_context("step_name", step_name)
    
    try:
        # Import and call tool with retry
        tool_func = import_tool(tool_name)
        
        if tool_func is None:
            error_msg = f"Failed to import tool '{tool_name}'"
            if continue_on_error:
                logger.warning(f"{error_msg}. Continuing workflow.")
                return {
                    "step": step_name,
                    "status": "skipped",
                    "error": error_msg
                }
            else:
                return {
                    "step": step_name,
                    "status": "error",
                    "error": error_msg
                }
        
        # Substitute parameters
        real_params = substitute_params(params, target)
        context.add_context("params", real_params)
        
        # Execute (handle async/sync)
        try:
            if asyncio.iscoroutinefunction(tool_func):
                result = await error_handler.safe_execute_async(
                    tool_func,
                    **real_params,
                    context=context
                )
            else:
                result = error_handler.safe_execute_sync(
                    tool_func,
                    **real_params,
                    context=context
                )
            
            # Vérifier si le résultat est une erreur (dict avec 'error_type')
            if isinstance(result, dict) and 'error_type' in result:
                if continue_on_error:
                    logger.warning(f"Error in step {step_name}: {result.get('error_message', 'Unknown error')}")
                    return {
                        "step": step_name,
                        "status": "skipped",
                        "error": result.get('error_message', 'Unknown error')
                    }
                else:
                    return {
                        "step": step_name,
                        "status": "error",
                        "error": result.get('error_message', 'Unknown error')
                    }
            
            return {
                "step": step_name,
                "status": "completed",
                "result": result
            }
        
        except Exception as e:
            error_info = error_handler.handle_error(e, context)
            if continue_on_error:
                logger.warning(f"Error in step {step_name}: {e}")
                return {
                    "step": step_name,
                    "status": "skipped",
                    "error": str(e)
                }
            else:
                return {
                    "step": step_name,
                    "status": "error",
                    "error": str(e),
                    "error_details": error_info
                }
    
    except Exception as e:
        error_info = error_handler.handle_error(e, context)
        return {
            "step": step_name,
            "status": "error",
            "error": str(e),
            "error_details": error_info
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

