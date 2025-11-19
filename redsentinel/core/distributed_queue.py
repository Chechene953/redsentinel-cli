"""
Distributed Job Queue - Celery-based task queue
Enables distributed and scalable task execution
"""

import logging
from typing import Any, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import Celery
try:
    from celery import Celery, Task
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None
    Task = None
    AsyncResult = None


# Configuration
class CeleryConfig:
    """Celery configuration"""
    broker_url = 'redis://localhost:6379/0'
    result_backend = 'redis://localhost:6379/0'
    task_serializer = 'json'
    result_serializer = 'json'
    accept_content = ['json']
    timezone = 'UTC'
    enable_utc = True
    task_track_started = True
    task_time_limit = 3600  # 1 hour
    task_soft_time_limit = 3500  # 58 minutes
    worker_prefetch_multiplier = 4
    worker_max_tasks_per_child = 1000


if CELERY_AVAILABLE:
    # Create Celery app
    celery_app = Celery('redsentinel')
    celery_app.config_from_object(CeleryConfig)
    
    
    # Custom task base class for monitoring
    class MonitoredTask(Task):
        """Custom task class with monitoring"""
        
        def on_success(self, retval, task_id, args, kwargs):
            """Handle successful task"""
            logger.info(f"Task {self.name} ({task_id}) completed successfully")
        
        def on_failure(self, exc, task_id, args, kwargs, einfo):
            """Handle failed task"""
            logger.error(f"Task {self.name} ({task_id}) failed: {exc}")
        
        def on_retry(self, exc, task_id, args, kwargs, einfo):
            """Handle task retry"""
            logger.warning(f"Task {self.name} ({task_id}) retrying: {exc}")
    
    
    # Example tasks
    @celery_app.task(base=MonitoredTask, name='scan.port_scan')
    def task_port_scan(target: str, ports: str = '1-1000') -> Dict[str, Any]:
        """
        Distributed port scanning task
        
        Args:
            target: Target host
            ports: Port range
        
        Returns:
            Scan results
        """
        from redsentinel.scanners.port_scanner_pro import PortScannerPro
        
        scanner = PortScannerPro()
        results = scanner.scan(target, ports)
        
        return {
            'target': target,
            'ports': ports,
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    
    @celery_app.task(base=MonitoredTask, name='scan.vulnerability_scan')
    def task_vulnerability_scan(target: str, scan_type: str = 'full') -> Dict[str, Any]:
        """
        Distributed vulnerability scanning task
        
        Args:
            target: Target URL
            scan_type: Type of scan (quick, full, custom)
        
        Returns:
            Vulnerability scan results
        """
        from redsentinel.vulnerability_scanner.orchestrator import VulnScanOrchestrator
        
        orchestrator = VulnScanOrchestrator()
        results = orchestrator.scan(target, scan_type)
        
        return {
            'target': target,
            'scan_type': scan_type,
            'vulnerabilities': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    
    @celery_app.task(base=MonitoredTask, name='recon.subdomain_enum')
    def task_subdomain_enumeration(domain: str) -> Dict[str, Any]:
        """
        Distributed subdomain enumeration task
        
        Args:
            domain: Target domain
        
        Returns:
            Subdomain enumeration results
        """
        from redsentinel.osint.advanced.subdomain_advanced import SubdomainEnumerator
        
        enumerator = SubdomainEnumerator()
        subdomains = enumerator.enumerate(domain)
        
        return {
            'domain': domain,
            'subdomains': subdomains,
            'count': len(subdomains),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    
    @celery_app.task(base=MonitoredTask, name='osint.full_recon')
    def task_full_reconnaissance(target: str) -> Dict[str, Any]:
        """
        Distributed full reconnaissance task
        
        Args:
            target: Target (domain, IP, or URL)
        
        Returns:
            Complete reconnaissance results
        """
        from redsentinel.tools.recon_pro import ReconPro
        
        recon = ReconPro()
        results = recon.full_recon(target)
        
        return {
            'target': target,
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    
    @celery_app.task(base=MonitoredTask, name='report.generate')
    def task_generate_report(scan_id: str, format: str = 'pdf') -> Dict[str, Any]:
        """
        Distributed report generation task
        
        Args:
            scan_id: Scan identifier
            format: Report format (pdf, html, json)
        
        Returns:
            Report generation status
        """
        from redsentinel.reporting.report_generator import ReportGenerator
        
        generator = ReportGenerator()
        report_path = generator.generate(scan_id, format)
        
        return {
            'scan_id': scan_id,
            'format': format,
            'report_path': report_path,
            'timestamp': datetime.utcnow().isoformat()
        }


class DistributedQueue:
    """
    Wrapper for Celery distributed task queue
    Provides a simplified interface for distributed task execution
    """
    
    def __init__(self):
        if not CELERY_AVAILABLE:
            logger.warning("Celery not available. Distributed queue disabled.")
            self.enabled = False
        else:
            self.app = celery_app
            self.enabled = True
    
    def submit_task(self, task_name: str, *args, **kwargs) -> Optional[str]:
        """
        Submit a task to the distributed queue
        
        Args:
            task_name: Name of the task
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Task ID or None if failed
        """
        if not self.enabled:
            logger.error("Distributed queue not enabled")
            return None
        
        try:
            task = self.app.send_task(task_name, args=args, kwargs=kwargs)
            logger.info(f"Submitted task {task_name}: {task.id}")
            return task.id
        
        except Exception as e:
            logger.error(f"Error submitting task {task_name}: {e}")
            return None
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a task
        
        Args:
            task_id: Task identifier
        
        Returns:
            Task status dictionary
        """
        if not self.enabled:
            return None
        
        try:
            result = AsyncResult(task_id, app=self.app)
            
            status = {
                'id': task_id,
                'state': result.state,
                'ready': result.ready(),
                'successful': result.successful() if result.ready() else None,
                'failed': result.failed() if result.ready() else None
            }
            
            if result.ready():
                if result.successful():
                    status['result'] = result.result
                else:
                    status['error'] = str(result.result)
            
            return status
        
        except Exception as e:
            logger.error(f"Error getting task status: {e}")
            return None
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task
        
        Args:
            task_id: Task identifier
        
        Returns:
            True if cancelled, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            result = AsyncResult(task_id, app=self.app)
            result.revoke(terminate=True)
            logger.info(f"Cancelled task: {task_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error cancelling task: {e}")
            return False
    
    def get_task_result(self, task_id: str, timeout: int = None) -> Optional[Any]:
        """
        Get result of a completed task
        
        Args:
            task_id: Task identifier
            timeout: Timeout in seconds (blocks until completed or timeout)
        
        Returns:
            Task result or None
        """
        if not self.enabled:
            return None
        
        try:
            result = AsyncResult(task_id, app=self.app)
            return result.get(timeout=timeout)
        
        except Exception as e:
            logger.error(f"Error getting task result: {e}")
            return None
    
    def purge_queue(self) -> int:
        """
        Purge all pending tasks from queue
        
        Returns:
            Number of tasks purged
        """
        if not self.enabled:
            return 0
        
        try:
            purged = self.app.control.purge()
            logger.info(f"Purged {purged} tasks from queue")
            return purged
        
        except Exception as e:
            logger.error(f"Error purging queue: {e}")
            return 0
    
    def get_active_tasks(self) -> Dict[str, Any]:
        """
        Get currently active tasks
        
        Returns:
            Dictionary of active tasks by worker
        """
        if not self.enabled:
            return {}
        
        try:
            inspect = self.app.control.inspect()
            active = inspect.active()
            return active or {}
        
        except Exception as e:
            logger.error(f"Error getting active tasks: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics
        
        Returns:
            Dictionary with queue stats
        """
        if not self.enabled:
            return {'enabled': False}
        
        try:
            inspect = self.app.control.inspect()
            
            stats = {
                'enabled': True,
                'active_tasks': inspect.active(),
                'registered_tasks': list(inspect.registered().values())[0] if inspect.registered() else [],
                'stats': inspect.stats()
            }
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting queue stats: {e}")
            return {'enabled': True, 'error': str(e)}


# Global distributed queue instance
distributed_queue = DistributedQueue()


# Convenience functions
def submit_port_scan(target: str, ports: str = '1-1000') -> Optional[str]:
    """Submit port scan task"""
    return distributed_queue.submit_task('scan.port_scan', target, ports)


def submit_vuln_scan(target: str, scan_type: str = 'full') -> Optional[str]:
    """Submit vulnerability scan task"""
    return distributed_queue.submit_task('scan.vulnerability_scan', target, scan_type)


def submit_subdomain_enum(domain: str) -> Optional[str]:
    """Submit subdomain enumeration task"""
    return distributed_queue.submit_task('recon.subdomain_enum', domain)


def submit_full_recon(target: str) -> Optional[str]:
    """Submit full reconnaissance task"""
    return distributed_queue.submit_task('osint.full_recon', target)


def submit_report_generation(scan_id: str, format: str = 'pdf') -> Optional[str]:
    """Submit report generation task"""
    return distributed_queue.submit_task('report.generate', scan_id, format)


__all__ = [
    'DistributedQueue',
    'distributed_queue',
    'submit_port_scan',
    'submit_vuln_scan',
    'submit_subdomain_enum',
    'submit_full_recon',
    'submit_report_generation',
    'celery_app',  # Export for worker: celery -A redsentinel.core.distributed_queue worker
]

