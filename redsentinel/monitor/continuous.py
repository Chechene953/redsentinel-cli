# redsentinel/monitor/continuous.py
"""
Continuous Monitoring System for RedSentinel
Monitors targets for changes and generates alerts
Enhanced with configurable alerts, CI/CD integration, and webhooks
"""

import json
import logging
import asyncio
import aiohttp
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable
from redsentinel.monitor.change_detector import ChangeDetector
from redsentinel.core.error_handler import get_error_handler, ErrorContext

logger = logging.getLogger(__name__)
error_handler = get_error_handler()


class ContinuousMonitor:
    """Monitor targets continuously for changes"""
    
    def __init__(self, storage_path="~/.redsentinel/monitoring.json"):
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.monitoring_data = self._load_monitoring()
        self.baselines = {}
        self.change_detector = ChangeDetector()
        self.alert_callbacks = []
        self.webhook_urls = []
        self.ci_cd_config = {}
    
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
        Compare current data to baseline avec détection avancée
        
        Args:
            target: Target name
            current_data: Current scan data
        
        Returns:
            dict with detected changes
        """
        if target not in self.monitoring_data["baselines"]:
            return {"error": "No baseline established for target"}
        
        baseline = self.monitoring_data["baselines"][target]["data"]
        
        # Utiliser le détecteur de changements avancé
        changes = self.change_detector.compare_scans(baseline, current_data)
        changes["target"] = target
        
        # Filtrer le bruit
        changes = self.change_detector.filter_noise(changes)
        
        return changes
    
    def should_alert(self, changes, thresholds: Optional[Dict] = None):
        """
        Determine if changes warrant an alert avec seuils configurables
        
        Args:
            changes: Dict with detected changes
            thresholds: Seuils personnalisés (optionnel)
        
        Returns:
            bool: Whether to alert
        """
        return self.change_detector.should_alert(changes, thresholds)
    
    def generate_alert(self, changes):
        """
        Generate alert for detected changes avec message formaté
        
        Args:
            changes: Dict with detected changes
        
        Returns:
            dict with alert information
        """
        alert = {
            "target": changes.get("target", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "severity": "INFO",
            "changes": changes,
            "message": self.change_detector.generate_alert_message(changes)
        }
        
        # Déterminer la sévérité
        stats = changes.get("statistics", {})
        
        if stats.get("total_new_vulns", 0) > 0:
            # Vérifier la sévérité des nouvelles vulnérabilités
            critical_vulns = [
                v for v in changes.get("new_vulnerabilities", [])
                if v.get("severity", "").upper() == "CRITICAL"
            ]
            if critical_vulns:
                alert["severity"] = "CRITICAL"
            elif stats["total_new_vulns"] >= 3:
                alert["severity"] = "HIGH"
            else:
                alert["severity"] = "MEDIUM"
        
        elif stats.get("total_new_endpoints", 0) >= 10 or stats.get("total_new_subdomains", 0) >= 5:
            alert["severity"] = "HIGH"
        elif stats.get("total_new_endpoints", 0) > 0 or stats.get("total_new_subdomains", 0) > 0:
            alert["severity"] = "MEDIUM"
        
        return alert
    
    def add_alert_callback(self, callback: Callable):
        """Ajoute un callback appelé lors d'une alerte"""
        self.alert_callbacks.append(callback)
    
    def add_webhook(self, webhook_url: str):
        """Ajoute une URL de webhook pour les alertes"""
        self.webhook_urls.append(webhook_url)
    
    async def send_webhooks(self, alert: Dict):
        """Envoie des alertes via webhooks"""
        if not self.webhook_urls:
            return
        
        async with aiohttp.ClientSession() as session:
            for webhook_url in self.webhook_urls:
                try:
                    async with session.post(
                        webhook_url,
                        json=alert,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            logger.info(f"Webhook sent successfully to {webhook_url}")
                except Exception as e:
                    error_handler.handle_error(e, ErrorContext("send_webhook", webhook_url))
    
    async def trigger_alert(self, alert: Dict):
        """Déclenche une alerte avec tous les callbacks et webhooks"""
        # Appeler les callbacks
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                error_handler.handle_error(e, ErrorContext("alert_callback", ""))
        
        # Envoyer les webhooks
        await self.send_webhooks(alert)
    
    def configure_ci_cd(self, platform: str, config: Dict):
        """
        Configure l'intégration CI/CD
        
        Args:
            platform: Plateforme CI/CD (github_actions, gitlab_ci, jenkins, azure_devops)
            config: Configuration spécifique à la plateforme
        """
        self.ci_cd_config[platform] = config
    
    async def trigger_ci_cd(self, alert: Dict):
        """Déclenche une action CI/CD selon la configuration"""
        # Implémentation basique - peut être étendue selon les besoins
        if "github_actions" in self.ci_cd_config:
            # TODO: Implémenter déclenchement GitHub Actions
            logger.info("GitHub Actions trigger not yet implemented")
        
        if "gitlab_ci" in self.ci_cd_config:
            # TODO: Implémenter déclenchement GitLab CI
            logger.info("GitLab CI trigger not yet implemented")
    
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


async def run_continuous_check(target, previous_data, current_data, monitor: Optional[ContinuousMonitor] = None):
    """
    Run a continuous monitoring check avec alertes améliorées
    
    Args:
        target: Target name
        previous_data: Previous scan data
        current_data: Current scan data
        monitor: Instance de monitor (optionnel)
    
    Returns:
        dict with monitoring results
    """
    if monitor is None:
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
        await monitor.trigger_alert(alert)
        
        # Déclencher CI/CD si configuré
        if monitor.ci_cd_config:
            await monitor.trigger_ci_cd(alert)
        
        return {
            "status": "changes_detected",
            "alert": alert,
            "changes": changes
        }
    
    return {
        "status": "no_changes",
        "changes": changes
    }

