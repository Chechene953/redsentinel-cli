# redsentinel/utils.py
import logging, yaml, os
from datetime import datetime

def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )

def load_config(path="config.yaml"):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"
