"""
Database Engine - Professional SQLAlchemy setup and session management
Supports both SQLite and PostgreSQL with advanced features:
- Connection pooling
- Query optimization
- Health checks
- Migration support
- Backup/restore
- Encryption (optional)
"""

import os
from pathlib import Path
from contextlib import contextmanager
import logging
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from sqlalchemy import create_engine, event, inspect
    from sqlalchemy.orm import sessionmaker, scoped_session
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.pool import StaticPool, QueuePool, NullPool
    from sqlalchemy import exc
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    declarative_base = None
    create_engine = None

logger = logging.getLogger(__name__)

# Base class for models
if SQLALCHEMY_AVAILABLE:
    Base = declarative_base()
else:
    Base = object


class DatabaseEngine:
    """Database engine manager"""
    
    def __init__(self, db_type: str = "sqlite", **kwargs):
        if not SQLALCHEMY_AVAILABLE:
            logger.error("SQLAlchemy not installed. Install with: pip install sqlalchemy")
            self.engine = None
            self.Session = None
            return
        
        self.db_type = db_type
        self.kwargs = kwargs
        self.engine = self._create_engine(db_type, **kwargs)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        self._setup_event_listeners()
        
    def _setup_event_listeners(self):
        """Setup event listeners for monitoring and optimization"""
        if not self.engine:
            return
        
        # Log slow queries (> 1 second)
        @event.listens_for(self.engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            conn.info.setdefault('query_start_time', []).append(datetime.now())
        
        @event.listens_for(self.engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            total = (datetime.now() - conn.info['query_start_time'].pop()).total_seconds()
            if total > 1.0:
                logger.warning(f"Slow query ({total:.2f}s): {statement[:100]}")
    
    def _create_engine(self, db_type: str, **kwargs):
        """Create database engine based on type"""
        
        if db_type == "sqlite":
            # SQLite configuration
            db_path = kwargs.get('db_path', './data/redsentinel.db')
            db_file = Path(db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            
            enable_wal = kwargs.get('enable_wal', True)
            
            engine = create_engine(
                f'sqlite:///{db_path}',
                connect_args={'check_same_thread': False},
                poolclass=StaticPool,
                echo=kwargs.get('echo', False)
            )
            
            # Enable SQLite optimizations
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                
                # Enable Write-Ahead Logging for better concurrency
                if enable_wal:
                    cursor.execute("PRAGMA journal_mode=WAL")
                
                # Performance optimizations
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=10000")  # ~40MB cache
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.execute("PRAGMA mmap_size=30000000000")  # Memory-mapped I/O
                cursor.close()
            
            logger.info(f"Using SQLite database: {db_path} (WAL: {enable_wal})")
        
        elif db_type == "postgresql":
            # PostgreSQL configuration
            host = kwargs.get('host', 'localhost')
            port = kwargs.get('port', 5432)
            database = kwargs.get('database', 'redsentinel')
            user = kwargs.get('user', 'redsentinel')
            password = kwargs.get('password', '')
            
            connection_string = f"postgresql://{user}:{password}@{host}:{port}/{database}"
            
            engine = create_engine(
                connection_string,
                pool_size=kwargs.get('pool_size', 10),
                max_overflow=kwargs.get('max_overflow', 20),
                pool_pre_ping=True,
                echo=kwargs.get('echo', False)
            )
            
            logger.info(f"Using PostgreSQL database: {host}:{port}/{database}")
        
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        return engine
    
    def create_tables(self):
        """Create all tables"""
        if not self.engine:
            logger.error("Engine not initialized")
            return
        
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created")
    
    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        if not self.engine:
            logger.error("Engine not initialized")
            return
        
        Base.metadata.drop_all(self.engine)
        logger.warning("Database tables dropped")
    
    @contextmanager
    def session_scope(self):
        """Provide a transactional scope for database operations"""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check database health and return status
        
        Returns:
            Dictionary with health status
        """
        try:
            with self.session_scope() as session:
                # Simple query to test connection
                session.execute("SELECT 1")
            
            stats = self.get_stats()
            
            return {
                'status': 'healthy',
                'database_type': self.db_type,
                'connection': 'ok',
                'stats': stats
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'database_type': self.db_type,
                'connection': 'failed',
                'error': str(e)
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with database stats
        """
        try:
            inspector = inspect(self.engine)
            table_names = inspector.get_table_names()
            
            stats = {
                'tables_count': len(table_names),
                'tables': table_names
            }
            
            # Get row counts for each table
            with self.session_scope() as session:
                table_sizes = {}
                for table in table_names:
                    try:
                        result = session.execute(f"SELECT COUNT(*) FROM {table}")
                        count = result.scalar()
                        table_sizes[table] = count
                    except:
                        table_sizes[table] = 0
                
                stats['table_sizes'] = table_sizes
                stats['total_records'] = sum(table_sizes.values())
            
            # Database-specific stats
            if self.db_type == 'sqlite':
                db_path = self.kwargs.get('db_path', './data/redsentinel.db')
                if Path(db_path).exists():
                    stats['database_size_bytes'] = Path(db_path).stat().st_size
                    stats['database_size_mb'] = stats['database_size_bytes'] / (1024 * 1024)
            
            elif self.db_type == 'postgresql':
                with self.session_scope() as session:
                    # Get database size
                    result = session.execute("SELECT pg_database_size(current_database())")
                    size_bytes = result.scalar()
                    stats['database_size_bytes'] = size_bytes
                    stats['database_size_mb'] = size_bytes / (1024 * 1024)
                    
                    # Get connection count
                    result = session.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    )
                    stats['active_connections'] = result.scalar()
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {'error': str(e)}
    
    def vacuum(self):
        """
        Optimize database (VACUUM for SQLite, VACUUM ANALYZE for PostgreSQL)
        """
        try:
            if self.db_type == 'sqlite':
                with self.engine.connect() as conn:
                    # SQLite VACUUM must be outside transaction
                    conn.execute("VACUUM")
                    conn.execute("ANALYZE")
                logger.info("SQLite database vacuumed and analyzed")
            
            elif self.db_type == 'postgresql':
                with self.engine.connect() as conn:
                    conn.execute("VACUUM ANALYZE")
                logger.info("PostgreSQL database vacuumed and analyzed")
        
        except Exception as e:
            logger.error(f"Error vacuuming database: {e}")
    
    def backup(self, backup_path: Optional[str] = None) -> bool:
        """
        Backup database
        
        Args:
            backup_path: Path for backup file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.db_type == 'sqlite':
                import shutil
                
                db_path = self.kwargs.get('db_path', './data/redsentinel.db')
                
                if backup_path is None:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    backup_dir = Path('./backups')
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_path = backup_dir / f'redsentinel_backup_{timestamp}.db'
                
                # Use SQLite backup API for safe backup
                import sqlite3
                source = sqlite3.connect(db_path)
                dest = sqlite3.connect(backup_path)
                
                with dest:
                    source.backup(dest)
                
                source.close()
                dest.close()
                
                logger.info(f"Database backed up to {backup_path}")
                return True
            
            elif self.db_type == 'postgresql':
                # PostgreSQL backup requires pg_dump
                import subprocess
                
                if backup_path is None:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    backup_dir = Path('./backups')
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_path = backup_dir / f'redsentinel_backup_{timestamp}.sql'
                
                host = self.kwargs.get('host', 'localhost')
                port = self.kwargs.get('port', 5432)
                database = self.kwargs.get('database', 'redsentinel')
                user = self.kwargs.get('user', 'redsentinel')
                
                # Set PGPASSWORD environment variable
                env = os.environ.copy()
                password = self.kwargs.get('password', '')
                if password:
                    env['PGPASSWORD'] = password
                
                cmd = [
                    'pg_dump',
                    '-h', host,
                    '-p', str(port),
                    '-U', user,
                    '-F', 'c',  # Custom format
                    '-f', str(backup_path),
                    database
                ]
                
                subprocess.run(cmd, check=True, env=env)
                logger.info(f"Database backed up to {backup_path}")
                return True
        
        except Exception as e:
            logger.error(f"Error backing up database: {e}")
            return False
    
    def get_connection_pool_status(self) -> Dict[str, Any]:
        """Get connection pool status"""
        try:
            pool = self.engine.pool
            return {
                'size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'total_connections': pool.size() + pool.overflow()
            }
        except Exception as e:
            logger.error(f"Error getting pool status: {e}")
            return {'error': str(e)}


# Initialize database engine from config
def init_database():
    """Initialize database from configuration"""
    from redsentinel.core.config_manager import config
    
    db_type = config.get('database.type', 'sqlite')
    
    if db_type == 'sqlite':
        db_path = config.get('database.sqlite_path', './data/redsentinel.db')
        engine_instance = DatabaseEngine('sqlite', db_path=db_path)
    
    elif db_type == 'postgresql':
        engine_instance = DatabaseEngine(
            'postgresql',
            host=config.get('database.postgres_host', 'localhost'),
            port=config.get('database.postgres_port', 5432),
            database=config.get('database.postgres_db', 'redsentinel'),
            user=config.get('database.postgres_user', 'redsentinel'),
            password=config.get('database.postgres_password', '')
        )
    
    else:
        raise ValueError(f"Unsupported database type: {db_type}")
    
    # Create tables
    engine_instance.create_tables()
    
    return engine_instance


# Global engine instance (lazy initialization)
_engine_instance = None


def get_engine():
    """Get global engine instance"""
    global _engine_instance
    
    if _engine_instance is None:
        _engine_instance = init_database()
    
    return _engine_instance


def get_session():
    """Get database session"""
    engine = get_engine()
    return engine.Session()


# For convenience
engine = None  # Will be initialized on first use
