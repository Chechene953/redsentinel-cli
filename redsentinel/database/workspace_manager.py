"""
Workspace Manager - Manages workspaces/projects
Provides workspace CRUD operations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

try:
    from sqlalchemy.exc import IntegrityError
    from redsentinel.database.engine import get_session
    from redsentinel.database.models import Workspace, Target, Scan
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

logger = logging.getLogger(__name__)


class WorkspaceManager:
    """
    Manages workspace operations
    
    Features:
    - Create/Read/Update/Delete workspaces
    - List all workspaces
    - Switch between workspaces
    - Workspace statistics
    """
    
    def __init__(self):
        if not SQLALCHEMY_AVAILABLE:
            logger.error("SQLAlchemy not available")
            self.session = None
        else:
            self.session = get_session()
        self.current_workspace = None
    
    def create_workspace(self, name: str, description: str = "") -> Optional[Workspace]:
        """Create a new workspace"""
        if not self.session:
            logger.error("Database not available")
            return None
        
        try:
            workspace = Workspace(
                name=name,
                description=description
            )
            
            self.session.add(workspace)
            self.session.commit()
            
            logger.info(f"Created workspace: {name}")
            return workspace
        
        except IntegrityError:
            self.session.rollback()
            logger.error(f"Workspace already exists: {name}")
            return None
        
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error creating workspace: {e}")
            return None
    
    def get_workspace(self, workspace_id: int = None, name: str = None) -> Optional[Workspace]:
        """Get workspace by ID or name"""
        if not self.session:
            return None
        
        try:
            if workspace_id:
                return self.session.query(Workspace).filter_by(id=workspace_id).first()
            elif name:
                return self.session.query(Workspace).filter_by(name=name).first()
            else:
                return None
        
        except Exception as e:
            logger.error(f"Error getting workspace: {e}")
            return None
    
    def list_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces with statistics"""
        if not self.session:
            return []
        
        try:
            workspaces = self.session.query(Workspace).all()
            
            result = []
            for ws in workspaces:
                result.append({
                    'id': ws.id,
                    'name': ws.name,
                    'description': ws.description,
                    'created_at': ws.created_at.isoformat() if ws.created_at else None,
                    'target_count': len(ws.targets),
                    'scan_count': len(ws.scans)
                })
            
            return result
        
        except Exception as e:
            logger.error(f"Error listing workspaces: {e}")
            return []
    
    def update_workspace(self, workspace_id: int, **kwargs) -> bool:
        """Update workspace"""
        if not self.session:
            return False
        
        try:
            workspace = self.get_workspace(workspace_id=workspace_id)
            
            if not workspace:
                logger.error(f"Workspace not found: {workspace_id}")
                return False
            
            for key, value in kwargs.items():
                if hasattr(workspace, key):
                    setattr(workspace, key, value)
            
            workspace.updated_at = datetime.now()
            self.session.commit()
            
            logger.info(f"Updated workspace: {workspace.name}")
            return True
        
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error updating workspace: {e}")
            return False
    
    def delete_workspace(self, workspace_id: int = None, name: str = None) -> bool:
        """Delete workspace and all associated data"""
        if not self.session:
            return False
        
        try:
            workspace = self.get_workspace(workspace_id=workspace_id, name=name)
            
            if not workspace:
                logger.error("Workspace not found")
                return False
            
            workspace_name = workspace.name
            self.session.delete(workspace)
            self.session.commit()
            
            logger.info(f"Deleted workspace: {workspace_name}")
            return True
        
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error deleting workspace: {e}")
            return False
    
    def set_current_workspace(self, workspace_id: int = None, name: str = None) -> bool:
        """Set current active workspace"""
        workspace = self.get_workspace(workspace_id=workspace_id, name=name)
        
        if workspace:
            self.current_workspace = workspace
            logger.info(f"Switched to workspace: {workspace.name}")
            return True
        else:
            logger.error("Workspace not found")
            return False
    
    def get_current_workspace(self) -> Optional[Workspace]:
        """Get current workspace"""
        return self.current_workspace
    
    def get_workspace_stats(self, workspace_id: int) -> Dict[str, Any]:
        """Get detailed statistics for a workspace"""
        if not self.session:
            return {}
        
        try:
            workspace = self.get_workspace(workspace_id=workspace_id)
            
            if not workspace:
                return {}
            
            # Count targets by type
            target_types = {}
            for target in workspace.targets:
                target_type = target.target_type or 'unknown'
                target_types[target_type] = target_types.get(target_type, 0) + 1
            
            # Count scans by status
            scan_statuses = {}
            for scan in workspace.scans:
                status = scan.status or 'unknown'
                scan_statuses[status] = scan_statuses.get(status, 0) + 1
            
            # Count vulnerabilities by severity
            vuln_severities = {}
            for target in workspace.targets:
                for vuln in target.vulnerabilities:
                    severity = vuln.severity or 'unknown'
                    vuln_severities[severity] = vuln_severities.get(severity, 0) + 1
            
            return {
                'workspace_id': workspace.id,
                'workspace_name': workspace.name,
                'total_targets': len(workspace.targets),
                'total_scans': len(workspace.scans),
                'total_vulnerabilities': sum(len(t.vulnerabilities) for t in workspace.targets),
                'target_types': target_types,
                'scan_statuses': scan_statuses,
                'vulnerability_severities': vuln_severities,
                'created_at': workspace.created_at.isoformat() if workspace.created_at else None,
                'updated_at': workspace.updated_at.isoformat() if workspace.updated_at else None
            }
        
        except Exception as e:
            logger.error(f"Error getting workspace stats: {e}")
            return {}
    
    def export_workspace(self, workspace_id: int, format: str = 'json') -> Optional[str]:
        """Export workspace data"""
        # Placeholder for export functionality
        logger.info(f"Exporting workspace {workspace_id} to {format}")
        return None
    
    def import_workspace(self, data: Dict[str, Any]) -> Optional[Workspace]:
        """Import workspace data"""
        # Placeholder for import functionality
        logger.info("Importing workspace data")
        return None


# Example usage
if __name__ == "__main__":
    manager = WorkspaceManager()
    
    # Create workspace
    ws = manager.create_workspace("Test Workspace", "A test workspace")
    
    if ws:
        print(f"Created workspace: {ws.id} - {ws.name}")
        
        # List workspaces
        workspaces = manager.list_workspaces()
        print(f"Total workspaces: {len(workspaces)}")
        
        # Get stats
        stats = manager.get_workspace_stats(ws.id)
        print(f"Stats: {stats}")
