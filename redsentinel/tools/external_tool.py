# redsentinel/tools/external_tool.py
import subprocess, shlex, shutil, logging
logger = logging.getLogger(__name__)

def find_binary(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if path:
        logger.debug("Found binary %s at %s", bin_name, path)
    return path

def run_command(cmd: str, timeout: int = 120, capture_output: bool = True, dry_run: bool = False):
    logger.info("Running command: %s", cmd)
    if dry_run:
        logger.warning("Dry-run enabled - not executing: %s", cmd)
        return 0, "", "DRY_RUN"
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=capture_output, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout running command: %s", cmd)
        return -1, e.stdout or "", str(e)
    except Exception as e:
        logger.exception("Error running command: %s", e)
        return -1, "", str(e)
