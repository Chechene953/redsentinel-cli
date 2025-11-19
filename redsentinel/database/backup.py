"""
Database Backup - Automated backup and restore
Handles database backups with compression and encryption
"""

import os
import shutil
import tarfile
import gzip
from pathlib import Path
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DatabaseBackup:
    """
    Database backup and restore manager
    
    Features:
    - Automated backups
    - Compression (gzip/tar)
    - Optional encryption
    - Backup rotation
    - Point-in-time recovery
    """
    
    def __init__(self, backup_dir: str = "./backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def backup_sqlite(self, db_path: str, compress: bool = True, encrypt: bool = False) -> Optional[str]:
        """
        Backup SQLite database
        
        Args:
            db_path: Path to SQLite database file
            compress: Whether to compress the backup
            encrypt: Whether to encrypt the backup
            
        Returns:
            Path to backup file
        """
        try:
            db_file = Path(db_path)
            
            if not db_file.exists():
                logger.error(f"Database file not found: {db_path}")
                return None
            
            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"redsentinel_backup_{timestamp}.db"
            
            if compress:
                backup_name += ".gz"
            
            backup_path = self.backup_dir / backup_name
            
            # Copy database
            if compress:
                with open(db_file, 'rb') as f_in:
                    with gzip.open(backup_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(db_file, backup_path)
            
            # Optional encryption
            if encrypt:
                encrypted_path = self._encrypt_file(backup_path)
                if encrypted_path:
                    backup_path.unlink()  # Remove unencrypted backup
                    backup_path = encrypted_path
            
            logger.info(f"Database backed up to: {backup_path}")
            return str(backup_path)
        
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return None
    
    def restore_sqlite(self, backup_path: str, target_path: str, decrypt: bool = False) -> bool:
        """
        Restore SQLite database from backup
        
        Args:
            backup_path: Path to backup file
            target_path: Path where to restore database
            decrypt: Whether backup is encrypted
            
        Returns:
            True if successful
        """
        try:
            backup_file = Path(backup_path)
            
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Optional decryption
            if decrypt:
                backup_file = self._decrypt_file(backup_file)
                if not backup_file:
                    return False
            
            # Restore database
            if backup_path.endswith('.gz'):
                with gzip.open(backup_file, 'rb') as f_in:
                    with open(target_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(backup_file, target_path)
            
            logger.info(f"Database restored to: {target_path}")
            return True
        
        except Exception as e:
            logger.error(f"Restore error: {e}")
            return False
    
    def backup_postgres(self, connection_string: str, compress: bool = True) -> Optional[str]:
        """Backup PostgreSQL database using pg_dump"""
        import subprocess
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"redsentinel_postgres_{timestamp}.sql"
            
            if compress:
                backup_name += ".gz"
            
            backup_path = self.backup_dir / backup_name
            
            # Use pg_dump
            cmd = ["pg_dump", connection_string]
            
            if compress:
                cmd.extend(["|", "gzip", ">", str(backup_path)])
                subprocess.run(" ".join(cmd), shell=True, check=True)
            else:
                with open(backup_path, 'w') as f:
                    subprocess.run(cmd, stdout=f, check=True)
            
            logger.info(f"PostgreSQL database backed up to: {backup_path}")
            return str(backup_path)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"pg_dump error: {e}")
            return None
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return None
    
    def list_backups(self) -> list:
        """List all available backups"""
        backups = []
        
        for file in self.backup_dir.glob("redsentinel_backup_*"):
            backups.append({
                'path': str(file),
                'name': file.name,
                'size': file.stat().st_size,
                'created': datetime.fromtimestamp(file.stat().st_ctime).isoformat()
            })
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    def rotate_backups(self, keep_count: int = 10):
        """
        Rotate backups, keeping only the most recent ones
        
        Args:
            keep_count: Number of backups to keep
        """
        backups = self.list_backups()
        
        if len(backups) > keep_count:
            to_delete = backups[keep_count:]
            
            for backup in to_delete:
                try:
                    Path(backup['path']).unlink()
                    logger.info(f"Deleted old backup: {backup['name']}")
                except Exception as e:
                    logger.error(f"Error deleting backup: {e}")
    
    def _encrypt_file(self, file_path: Path) -> Optional[Path]:
        """Encrypt a file (placeholder)"""
        from redsentinel.database.encryption import encrypt_data
        
        # In production, encrypt the entire file
        encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # For large files, use stream encryption
            # This is a simplified example
            encrypted_data = encrypt_data(data.decode('latin-1'))
            
            if encrypted_data:
                with open(encrypted_path, 'w') as f:
                    f.write(encrypted_data)
                
                return encrypted_path
        
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None
    
    def _decrypt_file(self, file_path: Path) -> Optional[Path]:
        """Decrypt a file (placeholder)"""
        from redsentinel.database.encryption import decrypt_data
        
        decrypted_path = file_path.with_suffix('')
        
        try:
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            
            decrypted_data = decrypt_data(encrypted_data)
            
            if decrypted_data:
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data.encode('latin-1'))
                
                return decrypted_path
        
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None


# Convenience functions
def backup_database(db_path: str = None, compress: bool = True, encrypt: bool = False) -> Optional[str]:
    """Backup the database"""
    from redsentinel.core.config_manager import config
    
    if not db_path:
        db_type = config.get('database.type', 'sqlite')
        
        if db_type == 'sqlite':
            db_path = config.get('database.sqlite_path', './data/redsentinel.db')
        else:
            logger.error("Only SQLite backups supported via this function")
            return None
    
    backup_manager = DatabaseBackup()
    return backup_manager.backup_sqlite(db_path, compress=compress, encrypt=encrypt)


def restore_database(backup_path: str, target_path: str = None, decrypt: bool = False) -> bool:
    """Restore the database from backup"""
    from redsentinel.core.config_manager import config
    
    if not target_path:
        target_path = config.get('database.sqlite_path', './data/redsentinel.db')
    
    backup_manager = DatabaseBackup()
    return backup_manager.restore_sqlite(backup_path, target_path, decrypt=decrypt)


def list_backups() -> list:
    """List all backups"""
    backup_manager = DatabaseBackup()
    return backup_manager.list_backups()


# Example usage
if __name__ == "__main__":
    backup_manager = DatabaseBackup()
    
    # Backup database
    backup_path = backup_manager.backup_sqlite("./data/redsentinel.db", compress=True)
    
    if backup_path:
        print(f"✅ Backup created: {backup_path}")
    
    # List backups
    backups = backup_manager.list_backups()
    print(f"\nAvailable backups: {len(backups)}")
    for backup in backups:
        print(f"  • {backup['name']} ({backup['size']} bytes)")
    
    # Rotate backups
    backup_manager.rotate_backups(keep_count=5)
