#!/usr/bin/env python3
"""
Module de cracking de hash avec Hashcat et John the Ripper
Support pour détection automatique ou manuelle du type de hash
"""

import subprocess
import os
import re
import tempfile
from typing import Dict, Optional, List


# Mapping des types de hash pour Hashcat et John
HASHCAT_TYPES = {
    "md5": 0,
    "md4": 900,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "sha3-256": 5000,
    "sha3-512": 5100,
    "bcrypt": 3200,
    "nthash": 1000,  # NT/NTLM
    "lm": 3000,
    "sha256-crypt": 7400,
    "sha512-crypt": 1800,
    "scrypt": 8900,
    "pbkdf2-sha256": 10900,
    "pbkdf2-sha512": 17100,
    "argon2": 16500,
    "argon2id": 16500,
    "mysql": 300,  # MySQL 3.x/4.x/5.x
    "mysql5": 300,
    "mysql-sha1": 300,
    "postgres": 999999,  # pas directement supporté
    "mssql": 131,
    "mssql2005": 131,
    "oracle": 3100,
    "apache": 1600,  # Apache MD5
    "apache-crypt": 1600,
    "plaintext": "plaintext"
}

JOHN_TYPES = {
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "bcrypt": "bcrypt",
    "nthash": "NT",
    "lm": "LM",
    "sha256-crypt": "sha256crypt",
    "sha512-crypt": "sha512crypt",
    "scrypt": "scrypt",
    "pbkdf2-sha256": "pbkdf2-hmac-sha256",
    "pbkdf2-sha512": "pbkdf2-hmac-sha512",
    "argon2": "argon2",
    "argon2id": "argon2id",
    "mysql": "mysql",
    "mysql-sha1": "mysql-sha1",
    "postgres": "postgres",
    "mssql": "mssql",
    "mssql2005": "mssql",
    "oracle": "oracle",
    "apache": "apache",
    "apache-crypt": "apache"
}


def detect_hash_type(hash_string: str) -> Optional[str]:
    """
    Détecte automatiquement le type de hash
    
    Args:
        hash_string: Le hash à analyser
    
    Returns:
        Type de hash détecté ou None
    """
    hash_string = hash_string.strip().lower()
    len_hash = len(hash_string)
    
    # MD5/NTLM: 32 caractères hex (ambiguïté)
    if len_hash == 32 and re.match(r'^[a-f0-9]{32}$', hash_string):
        # Par défaut, retourner MD5 (plus commun) - l'utilisateur peut spécifier manuellement NTLM
        return "md5"
    
    # SHA1: 40 caractères hex
    if len_hash == 40 and re.match(r'^[a-f0-9]{40}$', hash_string):
        return "sha1"
    
    # SHA256: 64 caractères hex
    if len_hash == 64 and re.match(r'^[a-f0-9]{64}$', hash_string):
        return "sha256"
    
    # SHA512: 128 caractères hex
    if len_hash == 128 and re.match(r'^[a-f0-9]{128}$', hash_string):
        return "sha512"
    
    # bcrypt: commence par $2a$, $2b$, $2x$, $2y$ et fait 60 caractères
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or \
       hash_string.startswith('$2x$') or hash_string.startswith('$2y$'):
        if len(hash_string) == 60:
            return "bcrypt"
    
    # sha256-crypt: commence par $5$
    if hash_string.startswith('$5$'):
        return "sha256-crypt"
    
    # sha512-crypt: commence par $6$
    if hash_string.startswith('$6$'):
        return "sha512-crypt"
    
    # scrypt: commence par $7$ ou $scrypt$
    if hash_string.startswith('$7$') or hash_string.startswith('$scrypt$'):
        return "scrypt"
    
    # pbkdf2: commence par $pbkdf2$
    if hash_string.startswith('$pbkdf2'):
        if 'sha256' in hash_string:
            return "pbkdf2-sha256"
        elif 'sha512' in hash_string:
            return "pbkdf2-sha512"
    
    # argon2: commence par $argon2
    if hash_string.startswith('$argon2'):
        if 'argon2id' in hash_string or '$argon2id$' in hash_string:
            return "argon2id"
        return "argon2"
    
    # MySQL (format spécial)
    if len_hash == 40 and not re.match(r'^[a-f0-9]{40}$', hash_string):
        # MySQL SHA1 avec * devant
        if hash_string.startswith('*'):
            return "mysql-sha1"
    
    # Apache MD5 crypt
    if hash_string.startswith('$apr1$') or hash_string.startswith('$apache$'):
        return "apache"
    
    # Plaintext (pas de hash, retourné tel quel)
    if len_hash < 16 and not any(c in hash_string for c in '$*'):
        return "plaintext"
    
    return None


def crack_hash_hashcat(
    hash_string: str,
    hash_type: Optional[str] = None,
    wordlist: Optional[str] = None,
    use_rockyou: bool = True
) -> Dict:
    """
    Crack un hash avec Hashcat
    
    Args:
        hash_string: Le hash à cracker
        hash_type: Type de hash (si None, détection auto)
        wordlist: Chemin vers la wordlist
        use_rockyou: Utiliser RockYou si wordlist=None
    
    Returns:
        Dict avec les résultats
    """
    # Vérifier si hashcat est installé
    try:
        subprocess.run(["hashcat", "--version"], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutError):
        return {
            "error": "Hashcat non trouvé. Installez-le: https://hashcat.net/hashcat/",
            "success": False
        }
    
    # Détecter le type de hash si non fourni
    if not hash_type:
        hash_type = detect_hash_type(hash_string)
        if not hash_type:
            return {
                "error": "Type de hash non détecté automatiquement. Spécifiez-le manuellement.",
                "detected": False,
                "success": False
            }
    
    # Vérifier que le type est supporté par Hashcat
    if hash_type not in HASHCAT_TYPES:
        return {
            "error": f"Type de hash '{hash_type}' non supporté par Hashcat",
            "success": False
        }
    
    hashcat_code = HASHCAT_TYPES[hash_type]
    
    # Créer un fichier temporaire avec le hash
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as hash_file:
        hash_file.write(hash_string.strip())
        hash_file_path = hash_file.name
    
    # Préparer la wordlist
    if wordlist and os.path.exists(wordlist):
        wordlist_path = wordlist
    elif use_rockyou:
        # Chercher RockYou
        rockyou_locations = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz"
        ]
        wordlist_path = None
        for loc in rockyou_locations:
            if os.path.exists(loc):
                wordlist_path = loc
                break
        
        if not wordlist_path:
            return {
                "error": "RockYou non trouvé. Installez: sudo apt install wordlists",
                "success": False
            }
    else:
        return {
            "error": "Aucune wordlist spécifiée",
            "success": False
        }
    
    try:
        # Commande Hashcat
        cmd = [
            "hashcat",
            "-m", str(hashcat_code),
            "-a", "0",  # Attack mode 0: Straight dictionary
            hash_file_path,
            wordlist_path,
            "--quiet",  # Mode silencieux
            "--potfile-disable",  # Ne pas sauvegarder dans potfile
            "--outfile-format", "2"  # Format simple
        ]
        
        # Lancer Hashcat
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 heure max
        )
        
        # Lire le résultat (hashcat écrit le résultat dans le même fichier)
        if result.returncode == 0:
            # Hashcat a trouvé le mot de passe
            # Le format de sortie simple affiche hash:password
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        return {
                            "success": True,
                            "hash_type": hash_type,
                            "hashcat_type": hashcat_code,
                            "password": parts[1].strip(),
                            "method": "hashcat",
                            "wordlist": wordlist_path
                        }
        
        # Si pas de résultat, retourner échec
        return {
            "success": False,
            "hash_type": hash_type,
            "hashcat_type": hashcat_code,
            "method": "hashcat",
            "wordlist": wordlist_path,
            "message": "Mot de passe non trouvé dans la wordlist"
        }
    
    except subprocess.TimeoutError:
        return {
            "success": False,
            "error": "Timeout: Le cracking a pris trop de temps (>1h)",
            "hash_type": hash_type,
            "method": "hashcat"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Erreur Hashcat: {str(e)}",
            "hash_type": hash_type,
            "method": "hashcat"
        }
    
    finally:
        # Nettoyer le fichier temporaire
        if os.path.exists(hash_file_path):
            os.unlink(hash_file_path)


def crack_hash_john(
    hash_string: str,
    hash_type: Optional[str] = None,
    wordlist: Optional[str] = None,
    use_rockyou: bool = True
) -> Dict:
    """
    Crack un hash avec John the Ripper
    
    Args:
        hash_string: Le hash à cracker
        hash_type: Type de hash (si None, détection auto)
        wordlist: Chemin vers la wordlist
        use_rockyou: Utiliser RockYou si wordlist=None
    
    Returns:
        Dict avec les résultats
    """
    # Vérifier si John est installé
    try:
        subprocess.run(["john", "--version"], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutError):
        return {
            "error": "John the Ripper non trouvé. Installez: sudo apt install john",
            "success": False
        }
    
    # Détecter le type de hash si non fourni
    if not hash_type:
        hash_type = detect_hash_type(hash_string)
        if not hash_type:
            return {
                "error": "Type de hash non détecté automatiquement. Spécifiez-le manuellement.",
                "detected": False,
                "success": False
            }
    
    # Créer un fichier temporaire avec le hash
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as hash_file:
        hash_file.write(hash_string.strip())
        hash_file_path = hash_file.name
    
    # Préparer la wordlist
    if wordlist and os.path.exists(wordlist):
        wordlist_path = wordlist
    elif use_rockyou:
        rockyou_locations = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz"
        ]
        wordlist_path = None
        for loc in rockyou_locations:
            if os.path.exists(loc):
                wordlist_path = loc
                break
        
        if not wordlist_path:
            return {
                "error": "RockYou non trouvé. Installez: sudo apt install wordlists",
                "success": False
            }
    else:
        return {
            "error": "Aucune wordlist spécifiée",
            "success": False
        }
    
    try:
        # Commande John the Ripper
        cmd = ["john", "--wordlist", wordlist_path, hash_file_path]
        
        # Si type spécifique, l'ajouter
        if hash_type in JOHN_TYPES:
            cmd.extend(["--format", JOHN_TYPES[hash_type]])
        
        # Lancer John
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600
        )
        
        # Afficher les résultats trouvés
        show_cmd = ["john", "--show", hash_file_path]
        show_result = subprocess.run(
            show_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Parser les résultats
        if show_result.returncode == 0 and show_result.stdout.strip():
            lines = show_result.stdout.strip().split('\n')
            if len(lines) > 0 and ':' in lines[0]:
                parts = lines[0].split(':', 1)
                if len(parts) >= 2:
                    return {
                        "success": True,
                        "hash_type": hash_type,
                        "password": parts[1].strip(),
                        "method": "john",
                        "wordlist": wordlist_path
                    }
        
        return {
            "success": False,
            "hash_type": hash_type,
            "method": "john",
            "wordlist": wordlist_path,
            "message": "Mot de passe non trouvé dans la wordlist"
        }
    
    except subprocess.TimeoutError:
        return {
            "success": False,
            "error": "Timeout: Le cracking a pris trop de temps (>1h)",
            "hash_type": hash_type,
            "method": "john"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Erreur John: {str(e)}",
            "hash_type": hash_type,
            "method": "john"
        }
    
    finally:
        # Nettoyer
        if os.path.exists(hash_file_path):
            os.unlink(hash_file_path)


def crack_hash(
    hash_string: str,
    hash_type: Optional[str] = None,
    tool: str = "hashcat",
    wordlist: Optional[str] = None,
    use_rockyou: bool = True
) -> Dict:
    """
    Crack un hash avec Hashcat ou John the Ripper
    
    Args:
        hash_string: Le hash à cracker
        hash_type: Type de hash (None = détection auto)
        tool: Outil à utiliser ("hashcat" ou "john")
        wordlist: Chemin vers la wordlist
        use_rockyou: Utiliser RockYou si wordlist=None
    
    Returns:
        Dict avec les résultats
    """
    if tool.lower() == "hashcat":
        return crack_hash_hashcat(hash_string, hash_type, wordlist, use_rockyou)
    elif tool.lower() == "john":
        return crack_hash_john(hash_string, hash_type, wordlist, use_rockyou)
    else:
        return {
            "error": f"Outil '{tool}' non supporté. Utilisez 'hashcat' ou 'john'",
            "success": False
        }

