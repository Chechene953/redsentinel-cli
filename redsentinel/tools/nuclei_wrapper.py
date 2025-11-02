# redsentinel/tools/nuclei_wrapper.py
from redsentinel.tools.external_tool import find_binary, run_command
import os, logging

logger = logging.getLogger(__name__)

def nuclei_scan(targets, path="/usr/local/bin/nuclei", templates=None, args="-silent -o /tmp/nuclei_out.txt", timeout=300, dry_run=False):
    binpath = find_binary("nuclei") or (path if os.path.exists(path) else None)
    if not binpath:
        return {"error": "nuclei binary not found"}
    tfile = "/tmp/nuclei_targets.txt"
    if isinstance(targets, (list,tuple)):
        with open(tfile,"w") as f:
            for t in targets:
                f.write(t+"\n")
        targets_arg = f"-l {tfile}"
    else:
        targets_arg = targets
    tmpl = f"-t {templates}" if templates else ""
    cmd = f"{binpath} {targets_arg} {tmpl} {args}"
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    return {"rc": rc, "out": out, "err": err}
