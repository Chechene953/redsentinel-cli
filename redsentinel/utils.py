# redsentinel/utils.py
import logging, yaml, os
from datetime import datetime

def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )

def load_config(path=None):
    if path is None:
        # Chercher config.yaml à plusieurs emplacements
        search_paths = [
            "config.yaml",  # Répertoire courant
            os.path.expanduser("~/.redsentinel/config.yaml"),  # Config utilisateur
            "/etc/redsentinel/config.yaml",  # Config système
        ]
        
        for search_path in search_paths:
            if os.path.exists(search_path):
                path = search_path
                break
        else:
            return {}  # Aucun fichier config trouvé
    
    if not os.path.exists(path):
        return {}
    
    with open(path, "r") as f:
        return yaml.safe_load(f)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"
