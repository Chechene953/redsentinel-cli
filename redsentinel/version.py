#!/usr/bin/env python3
"""
Version management and update checker for RedSentinel
"""

import subprocess
import os
from pathlib import Path

# Version actuelle
__version__ = "1.1.1"


def get_current_version():
    """Retourne la version actuelle"""
    return __version__


def check_git_update_available():
    """
    Vérifie si une mise à jour Git est disponible
    Retourne:
        - None si ce n'est pas un repo Git ou erreur
        - (current_hash, remote_hash) si différent
        - False si à jour
    """
    try:
        # Vérifier si on est dans un repo Git
        repo_path = Path(__file__).parent.parent
        git_dir = repo_path / ".git"
        
        if not git_dir.exists():
            return None  # Pas un repo Git
        
        # Obtenir le commit hash actuel
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            return None
        
        current_hash = result.stdout.strip()
        
        # Fetch les dernières modifications (sans merge)
        subprocess.run(
            ["git", "fetch"],
            cwd=repo_path,
            capture_output=True,
            timeout=10
        )
        
        # Comparer avec origin/main
        result = subprocess.run(
            ["git", "rev-parse", "origin/main"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            # Essayer avec origin/master
            result = subprocess.run(
                ["git", "rev-parse", "origin/master"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return None
        
        remote_hash = result.stdout.strip()
        
        # Comparer les hash
        if current_hash == remote_hash:
            return False  # À jour
        else:
            return (current_hash, remote_hash)  # Mise à jour disponible
    
    except Exception:
        # Erreur silencieuse
        return None


def get_version_info():
    """Récupère les informations de version"""
    current_version = get_current_version()
    
    # Essayer de récupérer le dernier commit hash
    commit_hash = None
    try:
        repo_path = Path(__file__).parent.parent
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            commit_hash = result.stdout.strip()
    except Exception:
        pass
    
    return {
        "version": current_version,
        "commit": commit_hash
    }


def check_update_and_prompt(console):
    """Vérifie les mises à jour et propose de mettre à jour si disponible"""
    from redsentinel.design import warning, info, error, success
    from rich.panel import Panel
    from rich.prompt import Confirm
    
    update_status = check_git_update_available()
    
    if update_status is None:
        # Pas un repo Git ou erreur
        return False
    
    if update_status is False:
        # À jour
        return False
    
    # Mise à jour disponible
    current_hash, remote_hash = update_status
    
    console.print()
    warning("⚠️  Une nouvelle version de RedSentinel est disponible !")
    info(f"Version actuelle: {current_hash[:8]}...")
    info(f"Version distante: {remote_hash[:8]}...")
    console.print()
    
    try:
        if Confirm.ask("Souhaitez-vous mettre à jour maintenant ?", default=True):
            # Proposer de mettre à jour
            console.print()
            info("Lancement de la mise à jour...")
            
            try:
                import sys
                import os
                # Trouver le répertoire du projet
                repo_path = Path(__file__).parent.parent
                os.chdir(repo_path)
                
                # Exécuter git pull
                result = subprocess.run(
                    ["git", "pull"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    console.print()
                    success("Mise à jour réussie ! Redémarrez RedSentinel pour appliquer les changements.")
                    console.print()
                    console.print(Panel.fit(
                        "[bold cyan]Redémarrage recommandé[/bold cyan]\n\n"
                        "Pour appliquer la mise à jour, relancez: [yellow]redsentinel[/yellow]",
                        border_style="cyan"
                    ))
                    console.print()
                    return True
                else:
                    error(f"Échec de la mise à jour: {result.stderr}")
            except Exception as e:
                error(f"Erreur lors de la mise à jour: {str(e)}")
                console.print()
                info("Vous pouvez toujours mettre à jour manuellement avec:")
                console.print(Panel.fit(
                    "[yellow]cd ~/redsentinel-cli-main[/yellow]\n"
                    "[yellow]bash update.sh[/yellow]",
                    border_style="yellow"
                ))
                console.print()
            
    except KeyboardInterrupt:
        console.print()
        info("Mise à jour annulée")
        console.print()
    
    return False

