# redsentinel/monitor/continuous.py
"""
Continuous Monitoring System for RedSentinel
Monitors targets for changes and generates alerts
"""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ContinuousMonitor:
    """Monitor targets continuously for changes"""
    
    def __init__(self, storage_path="~/.redsentinel/monitoring.json"):
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.monitoring_data = self._load_monitoring()
        self.baselines = {}
    
    def _load_monitoring(self):
        """Load monitoring data"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading monitoring data: {e}")
                return {"targets": [], "baselines": {}}
        return {"targets": [], "baselines": {}}
    
    def _save_monitoring(self):
        """Save monitoring data"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.monitoring_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving monitoring data: {e}")
            return False
    
    def establish_baseline(self, target, baseline_data):
        """
        Establish baseline for a target
        
        Args:
            target: Target name
            baseline_data: Dict with baseline metrics
        
        Returns:
            bool: Success status
        """
        self.monitoring_data["baselines"][target] = {
            "data": baseline_data,
            "created": datetime.now().isoformat(),
            "changed_ips": set(),
            "changed_ports": set(),
            "changed_subdomains": set()
        }
        return self._save_monitoring()
    
    def compare_to_baseline(self, target, current_data):
        """
        Compare current data to baseline
        
        Args:
            target: Target name
            current_data: Current scan data
        
        Returns:
            dict with detected changes
        """
        changes = {
            "target": target,
            "new_ips": [],
            "new_ports": [],
            "new_subdomains": [],
            "removed_ips": [],
            "removed_ports": [],
            "removed_subdomains": []
        }
        
        if target not in self.monitoring_data["baselines"]:
            return {"error": "No baseline established for target"}
        
        baseline = self.monitoring_data["baselines"][target]["data"]
        
        # Compare subdomains
        baseline_subs = set(baseline.get("subdomains", []))
        current_subs = set(current_data.get("subdomains", []))
        
        changes["new_subdomains"] = list(current_subs - baseline_subs)
        changes["removed_subdomains"] = list(baseline_subs - current_subs)
        
        # Compare open ports
        baseline_ports = set(baseline.get("open_ports", []))
        current_ports = set(current_data.get("open_ports", []))
        
        changes["new_ports"] = list(current_ports - baseline_ports)
        changes["removed_ports"] = list(baseline_ports - current_ports)
        
        return changes
    
    def should_alert(self, changes):
        """
        Determine if changes warrant an alert
        
        Args:
            changes: Dict with detected changes
        
        Returns:
            bool: Whether to alert
        """
        # Alert on significant changes
        if changes.get("new_ports"):
            return True
        if changes.get("new_subdomains"):
            return True
        if changes.get("new_ips"):
            return True
        
        return False
    
    def generate_alert(self, changes):
        """
        Generate alert for detected changes
        
        Args:
            changes: Dict with detected changes
        
        Returns:
            dict with alert information
        """
        alert = {
            "target": changes["target"],
            "timestamp": datetime.now().isoformat(),
            "severity": "INFO",
            "changes": changes
        }
        
        # Determine severity
        if changes.get("new_ports") or changes.get("new_subdomains"):
            alert["severity"] = "WARNING"
        
        if len(changes.get("new_ports", [])) > 3 or len(changes.get("new_subdomains", [])) > 5:
            alert["severity"] = "HIGH"
        
        return alert
    
    def get_monitoring_status(self):
        """Get monitoring status for all targets"""
        status = {
            "monitored_targets": len(self.monitoring_data["baselines"]),
            "last_check": None,
            "alerts_available": False
        }
        
        if self.monitoring_data.get("targets"):
            latest = max(
                (t.get("last_check") for t in self.monitoring_data["targets"] if t.get("last_check")),
                default=None
            )
            status["last_check"] = latest
        
        return status


def run_continuous_check(target, previous_data, current_data):
    """
    Run a continuous monitoring check
    
    Args:
        target: Target name
        previous_data: Previous scan data
        current_data: Current scan data
    
    Returns:
        dict with monitoring results
    """
    monitor = ContinuousMonitor()
    
    # Establish baseline if not exists
    if target not in monitor.monitoring_data["baselines"]:
        monitor.establish_baseline(target, previous_data)
        return {"status": "baseline_established"}
    
    # Compare to baseline
    changes = monitor.compare_to_baseline(target, current_data)
    
    # Check if alert needed
    if monitor.should_alert(changes):
        alert = monitor.generate_alert(changes)
        return {
            "status": "changes_detected",
            "alert": alert,
            "changes": changes
        }
    
    return {
        "status": "no_changes",
        "changes": changes
    }

