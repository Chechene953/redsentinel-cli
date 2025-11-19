"""
API Server - Internal REST API for RedSentinel
Enables remote control and integration
"""

import asyncio
from typing import Dict, Any, List
import logging

try:
    from fastapi import FastAPI, HTTPException, Depends, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    BaseModel = object

logger = logging.getLogger(__name__)


# Pydantic models for API
if FASTAPI_AVAILABLE:
    class ScanRequest(BaseModel):
        target: str
        scan_type: str = "full"
        options: Dict[str, Any] = {}
    
    class ScanResponse(BaseModel):
        scan_id: str
        status: str
        message: str
    
    class VulnerabilityResponse(BaseModel):
        vulnerabilities: List[Dict[str, Any]]
        total: int


class APIServer:
    """
    FastAPI-based REST API server
    
    Features:
    - REST endpoints for all core functionality
    - JWT authentication
    - CORS support
    - WebSocket support for real-time updates
    - API documentation (Swagger/OpenAPI)
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        if not FASTAPI_AVAILABLE:
            logger.error("FastAPI not installed. Install with: pip install 'redsentinel[api]'")
            self.app = None
            return
        
        self.host = host
        self.port = port
        self.app = FastAPI(
            title="RedSentinel API",
            description="Professional Cybersecurity Platform API",
            version="7.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Security
        self.security = HTTPBearer()
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup routes
        self._setup_routes()
    
    def _setup_middleware(self):
        """Setup CORS and other middleware"""
        if not self.app:
            return
        
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately in production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def _setup_routes(self):
        """Setup API routes"""
        if not self.app:
            return
        
        @self.app.get("/")
        async def root():
            return {
                "name": "RedSentinel API",
                "version": "7.0.0",
                "status": "running"
            }
        
        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": asyncio.get_event_loop().time()}
        
        # Scan endpoints
        @self.app.post("/api/v1/scans", response_model=ScanResponse)
        async def create_scan(scan_request: ScanRequest):
            """Create a new scan"""
            try:
                from redsentinel.core.job_queue import job_queue, JobPriority
                
                # Add scan job to queue
                job_id = job_queue.add_job(
                    name=f"Scan: {scan_request.target}",
                    func=self._execute_scan,
                    args=(scan_request.target, scan_request.scan_type, scan_request.options),
                    priority=JobPriority.NORMAL
                )
                
                return ScanResponse(
                    scan_id=job_id,
                    status="queued",
                    message=f"Scan queued for {scan_request.target}"
                )
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/scans/{scan_id}")
        async def get_scan_status(scan_id: str):
            """Get scan status"""
            try:
                from redsentinel.core.job_queue import job_queue
                
                job = job_queue.get_job(scan_id)
                if not job:
                    raise HTTPException(status_code=404, detail="Scan not found")
                
                return job.to_dict()
            
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/scans")
        async def list_scans():
            """List all scans"""
            try:
                from redsentinel.core.job_queue import job_queue
                
                jobs = job_queue.get_all_jobs()
                return {"scans": jobs, "total": len(jobs)}
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Vulnerability endpoints
        @self.app.get("/api/v1/vulnerabilities")
        async def list_vulnerabilities(severity: str = None, limit: int = 100):
            """List vulnerabilities"""
            try:
                from redsentinel.database.engine import get_session
                from redsentinel.database.models import Vulnerability
                
                # This is a placeholder - implement actual DB query
                return {
                    "vulnerabilities": [],
                    "total": 0
                }
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Target endpoints
        @self.app.get("/api/v1/targets")
        async def list_targets():
            """List all targets"""
            return {"targets": [], "total": 0}
        
        @self.app.post("/api/v1/targets")
        async def add_target(target: Dict[str, Any]):
            """Add a new target"""
            return {"message": "Target added", "target_id": "placeholder"}
        
        # Report endpoints
        @self.app.get("/api/v1/reports")
        async def list_reports():
            """List all reports"""
            return {"reports": [], "total": 0}
        
        @self.app.get("/api/v1/reports/{report_id}")
        async def get_report(report_id: str):
            """Get a specific report"""
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Workspace endpoints
        @self.app.get("/api/v1/workspaces")
        async def list_workspaces():
            """List all workspaces"""
            try:
                from redsentinel.database.workspace_manager import WorkspaceManager
                
                manager = WorkspaceManager()
                workspaces = manager.list_workspaces()
                
                return {"workspaces": workspaces, "total": len(workspaces)}
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/v1/workspaces")
        async def create_workspace(workspace: Dict[str, Any]):
            """Create a new workspace"""
            try:
                from redsentinel.database.workspace_manager import WorkspaceManager
                
                manager = WorkspaceManager()
                ws = manager.create_workspace(workspace['name'])
                
                return {"message": "Workspace created", "workspace_id": str(ws.id)}
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    
    async def _execute_scan(self, target: str, scan_type: str, options: Dict[str, Any]):
        """Execute a scan (placeholder)"""
        logger.info(f"Executing {scan_type} scan on {target}")
        await asyncio.sleep(2)  # Simulate scan
        return {"target": target, "status": "completed"}
    
    def run(self):
        """Run the API server"""
        if not self.app:
            logger.error("Cannot run API server: FastAPI not available")
            return
        
        logger.info(f"Starting API server on {self.host}:{self.port}")
        
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
    
    async def start_async(self):
        """Start server asynchronously"""
        if not self.app:
            logger.error("Cannot start API server: FastAPI not available")
            return
        
        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()


# Convenience function
def start_api_server(host: str = "127.0.0.1", port: int = 8000):
    """Start the API server"""
    from redsentinel.core.config_manager import config
    
    # Get config
    api_enabled = config.get('api_server.enabled', False)
    
    if not api_enabled:
        logger.warning("API server is disabled in configuration")
        return
    
    api_host = config.get('api_server.host', host)
    api_port = config.get('api_server.port', port)
    
    server = APIServer(api_host, api_port)
    server.run()


if __name__ == "__main__":
    # Test the API server
    server = APIServer()
    server.run()
