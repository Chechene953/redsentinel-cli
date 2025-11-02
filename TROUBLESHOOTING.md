# 🔧 Dépannage RedSentinel

## Problème : "redsentinel" ne se lance pas en dehors du dossier

### Symptômes
- `redsentinel: command not found` quand vous n'êtes pas dans le dossier du projet
- Vous devez être dans le dossier du projet pour lancer `redsentinel`

### Cause
La commande `pipx ensurepath` n'a pas été exécutée, ou le PATH n'a pas été rechargé.

### Solution

```bash
# 1. Vérifier si redsentinel est installé
which redsentinel

# 2. Si rien trouvé, réinstaller proprement
cd ~/redsentinel-cli  # ou votre chemin
bash reinstall.sh

# 3. Quand pipx vous demande, choisissez l'option 1
pipx ensurepath

# 4. Redémarrer le terminal ou :
source ~/.bashrc

# 5. Vérifier que ça marche
redsentinel --version
```

## Problème : Les mises à jour automatiques ne se détectent pas

### Symptômes
- Vous avez pushé les changements
- Quand vous lancez `redsentinel`, il ne vous propose pas de mise à jour

### Cause
Plusieurs raisons possibles :
1. Le repo Git n'a pas été cloné correctement avec `pipx install -e .`
2. Les remotes Git ne sont pas configurés
3. La branche locale n'est pas liée à origin
4. Aucun changement détectable (même version, même commit)

### Diagnostic

```bash
# 1. Lancer le diagnostic
bash troubleshoot.sh

# 2. Vérifier où est installé redsentinel
pipx list | grep redsentinel

# 3. Aller dans le dossier installé (si pipx)
cd ~/.local/share/pipx/venvs/redsentinel/

# 4. Vérifier si c'est un repo Git
ls -la .git

# 5. Si .git n'existe pas, c'est le problème !
```

### Solution

Le problème vient du fait que `pipx install -e .` ne copie pas forcément le dossier `.git`. Il y a plusieurs solutions :

#### Solution 1 : Réinstaller avec le repo Git complet

```bash
cd ~/redsentinel-cli  # votre repo source

# Désinstaller l'ancien
pipx uninstall redsentinel

# Réinstaller
pipx install -e .
```

#### Solution 2 : Utiliser un script de mise à jour manuelle

Créez un script `update-redsentinel.sh` dans votre home :

```bash
#!/bin/bash
cd ~/redsentinel-cli
git pull
pipx reinstall redsentinel
```

Utilisez ce script au lieu de compter sur la mise à jour automatique.

#### Solution 3 : Vérifier que pipx a bien installé en mode développement

```bash
# Vérifier que pipx a bien utilisé -e
pipx list --include-injected

# Si vous voyez "redsentinel  editable", c'est bon
```

## Problème : Erreur "git pull" dans le système de mise à jour

### Symptômes
- Le système détecte une mise à jour mais `git pull` échoue
- Erreur de permissions ou credentials

### Cause
Le système essaie de faire `git pull` mais n'a pas les bonnes permissions ou credentials.

### Solution

```bash
# Option 1 : Ignorer la mise à jour auto, utiliser le script
cd ~/redsentinel-cli
bash update.sh

# Option 2 : Configurer les credentials Git
git config --global credential.helper store
# Puis faire un git pull manuel une fois pour sauvegarder les credentials
```

## Problème : "Version 1.0.0" s'affiche toujours

### Symptômes
- Vous avez changé la version dans `redsentinel/version.py`
- Mais `redsentinel --version` affiche toujours l'ancienne version

### Cause
L'ancien package est encore installé dans le cache Python.

### Solution

```bash
# Forcer la réinstallation
pipx reinstall redsentinel

# Ou complètement propre
pipx uninstall redsentinel
pipx install -e .
```

## Problème : Conflit avec une installation manuelle

### Symptômes
- `redsentinel` se lance mais avec un comportement étrange
- Plusieurs installations détectées

### Solution

```bash
# 1. Nettoyer toutes les installations
sudo rm /usr/local/bin/redsentinel 2>/dev/null
rm -rf ~/redsentinel-auto 2>/dev/null
sudo pip3 uninstall redsentinel -y --break-system-packages 2>/dev/null || true
pipx uninstall redsentinel 2>/dev/null || true

# 2. Réinstaller proprement
cd ~/redsentinel-cli
bash reinstall.sh
```

## Vérifier l'état de l'installation

```bash
# Diagnostic complet
bash troubleshoot.sh

# Ou manuellement :
echo "PATH:"
echo $PATH | tr ':' '\n' | grep -E '(pipx|redsentinel)'

echo -e "\nCommande redsentinel:"
which redsentinel

echo -e "\nInstallation pipx:"
pipx list 2>/dev/null | grep redsentinel

echo -e "\nVersion Python:"
python3 --version

echo -e "\nTest de lancement:"
redsentinel --version 2>/dev/null || echo "ERREUR"
```

## Obtenir de l'aide

Si aucun de ces correctifs ne fonctionne :

1. Lancez `bash troubleshoot.sh` et notez les résultats
2. Vérifiez les logs d'erreur quand vous lancez `redsentinel`
3. Vérifiez votre version de Python : `python3 --version` (besoin de >=3.7)
4. Vérifiez que pipx est installé : `pipx --version`

## Recommandation

Pour éviter tous ces problèmes, utilisez **toujours** l'une de ces méthodes dans l'ordre :

1. **pipx** (recommandé) : `pipx install -e .`
2. **pip global** : `sudo pip3 install -e . --break-system-packages`
3. **install.sh** : `bash install.sh`

Ne mélangez **jamais** plusieurs méthodes d'installation !

