"""
Change Detector - Détecte les changements sur les cibles
Monitore les modifications et alerte en cas de changement
"""

import asyncio
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Change:
    """Représente un changement détecté"""
    target: str
    change_type: str
    old_value: Any
    new_value: Any
    detected_at: datetime
    severity: str = "info"
    
    def to_dict(self):
        return {
            'target': self.target,
            'change_type': self.change_type,
            'old_value': str(self.old_value),
            'new_value': str(self.new_value),
            'detected_at': self.detected_at.isoformat(),
            'severity': self.severity
        }


class ChangeDetector:
    """
    Détecteur de changements pour monitoring continu
    
    Features:
    - Détection de changements de contenu
    - Hash comparison
    - Notifications
    - Historique des changements
    """
    
    def __init__(self):
        self.baseline: Dict[str, Any] = {}
        self.changes: List[Change] = []
        self.max_history = 1000
    
    def set_baseline(self, target: str, data: Any):
        """Définir la baseline pour une cible"""
        if isinstance(data, str):
            hash_value = hashlib.sha256(data.encode()).hexdigest()
        elif isinstance(data, bytes):
            hash_value = hashlib.sha256(data).hexdigest()
        else:
            hash_value = hashlib.sha256(str(data).encode()).hexdigest()
        
        self.baseline[target] = {
            'hash': hash_value,
            'data': data,
            'timestamp': datetime.now()
        }
        
        logger.debug(f"Baseline set for {target}")
    
    def detect_changes(self, target: str, new_data: Any) -> Optional[Change]:
        """
        Détecter les changements par rapport à la baseline
        
        Args:
            target: Cible à vérifier
            new_data: Nouvelles données
            
        Returns:
            Change object si changement détecté, None sinon
        """
        if target not in self.baseline:
            logger.warning(f"No baseline for {target}, setting now")
            self.set_baseline(target, new_data)
            return None
        
        # Calculer hash des nouvelles données
        if isinstance(new_data, str):
            new_hash = hashlib.sha256(new_data.encode()).hexdigest()
        elif isinstance(new_data, bytes):
            new_hash = hashlib.sha256(new_data).hexdigest()
        else:
            new_hash = hashlib.sha256(str(new_data).encode()).hexdigest()
        
        old_hash = self.baseline[target]['hash']
        
        # Comparer
        if new_hash != old_hash:
            change = Change(
                target=target,
                change_type='content_modified',
                old_value=old_hash,
                new_value=new_hash,
                detected_at=datetime.now(),
                severity='warning'
            )
            
            # Ajouter à l'historique
            self.changes.append(change)
            if len(self.changes) > self.max_history:
                self.changes.pop(0)
            
            # Mettre à jour baseline
            self.set_baseline(target, new_data)
            
            logger.info(f"Change detected on {target}")
            return change
        
        return None
    
    def get_changes(self, target: Optional[str] = None) -> List[Change]:
        """Récupérer les changements"""
        if target:
            return [c for c in self.changes if c.target == target]
        return self.changes
    
    def clear_changes(self):
        """Effacer l'historique"""
        self.changes.clear()
    
    def has_baseline(self, target: str) -> bool:
        """Vérifier si une baseline existe"""
        return target in self.baseline
    
    def remove_baseline(self, target: str):
        """Supprimer une baseline"""
        if target in self.baseline:
            del self.baseline[target]
            logger.debug(f"Baseline removed for {target}")


# Exemple d'utilisation
if __name__ == "__main__":
    detector = ChangeDetector()
    
    # Définir baseline
    detector.set_baseline("example.com", "Initial content")
    
    # Pas de changement
    change = detector.detect_changes("example.com", "Initial content")
    print(f"Change 1: {change}")  # None
    
    # Changement détecté
    change = detector.detect_changes("example.com", "Modified content")
    print(f"Change 2: {change}")  # Change object
    
    # Historique
    print(f"Total changes: {len(detector.get_changes())}")

