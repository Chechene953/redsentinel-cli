# redsentinel/manage/target_manager.py
"""
Target Management System for RedSentinel
Manages targets, scopes, exclusion lists, and batch operations
"""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class TargetManager:
    """Manage targets and scope"""
    
    def __init__(self, storage_path="~/.redsentinel/targets.json"):
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.targets = self._load_targets()
    
    def _load_targets(self):
        """Load targets from storage"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading targets: {e}")
                return {"targets": [], "groups": [], "exclusions": []}
        return {"targets": [], "groups": [], "exclusions": []}
    
    def _save_targets(self):
        """Save targets to storage"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.targets, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving targets: {e}")
            return False
    
    def add_target(self, target, group=None, notes=None):
        """Add a new target"""
        target_entry = {
            "name": target,
            "added": datetime.now().isoformat(),
            "group": group,
            "notes": notes,
            "last_scan": None,
            "status": "new"
        }
        
        self.targets["targets"].append(target_entry)
        self._save_targets()
        
        return target_entry
    
    def add_group(self, group_name, targets=None):
        """Add a target group"""
        group = {
            "name": group_name,
            "targets": targets or [],
            "created": datetime.now().isoformat()
        }
        
        self.targets["groups"].append(group)
        self._save_targets()
        
        return group
    
    def add_exclusion(self, pattern, reason=None):
        """Add exclusion pattern"""
        exclusion = {
            "pattern": pattern,
            "reason": reason,
            "added": datetime.now().isoformat()
        }
        
        self.targets["exclusions"].append(exclusion)
        self._save_targets()
        
        return exclusion
    
    def get_targets(self, group=None):
        """Get all targets or targets from a group"""
        if group:
            group_targets = [g["targets"] for g in self.targets["groups"] if g["name"] == group]
            if group_targets:
                return group_targets[0]
            return []
        return self.targets["targets"]
    
    def update_target_status(self, target_name, status, last_scan=None):
        """Update target status"""
        for target in self.targets["targets"]:
            if target["name"] == target_name:
                target["status"] = status
                if last_scan:
                    target["last_scan"] = last_scan
                self._save_targets()
                return True
        return False
    
    def is_excluded(self, target):
        """Check if target matches any exclusion pattern"""
        import fnmatch
        
        for exclusion in self.targets["exclusions"]:
            pattern = exclusion["pattern"]
            if fnmatch.fnmatch(target, pattern):
                return True
        return False
    
    def get_statistics(self):
        """Get target management statistics"""
        return {
            "total_targets": len(self.targets["targets"]),
            "total_groups": len(self.targets["groups"]),
            "total_exclusions": len(self.targets["exclusions"]),
            "targets_by_status": {
                "new": sum(1 for t in self.targets["targets"] if t["status"] == "new"),
                "scanned": sum(1 for t in self.targets["targets"] if t["status"] == "scanned"),
                "error": sum(1 for t in self.targets["targets"] if t["status"] == "error")
            }
        }


def create_target_manager():
    """Create a TargetManager instance"""
    return TargetManager()


def manage_targets(target_action, **kwargs):
    """
    High-level target management function
    
    Args:
        target_action: Action (add, list, group, exclude)
        **kwargs: Action-specific parameters
    
    Returns:
        result of the action
    """
    manager = TargetManager()
    
    if target_action == "add":
        return manager.add_target(
            kwargs.get("target"),
            kwargs.get("group"),
            kwargs.get("notes")
        )
    elif target_action == "list":
        return manager.get_targets(kwargs.get("group"))
    elif target_action == "groups":
        return manager.targets.get("groups", [])
    elif target_action == "exclusions":
        return manager.targets.get("exclusions", [])
    elif target_action == "stats":
        return manager.get_statistics()
    
    return None

