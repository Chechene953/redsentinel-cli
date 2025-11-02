# 📦 Guide de versionnement RedSentinel

Ce guide explique comment créer et publier une nouvelle version de RedSentinel.

## 📋 Étapes pour créer une nouvelle version

### 1. Mettre à jour le numéro de version

La version est centralisée dans un seul fichier :

**`redsentinel/version.py`**

```python
# Version actuelle
__version__ = "1.1.0"  # ⬅️ Modifiez ici
```

**Format de version** : Utilisez le [Semantic Versioning](https://semver.org/)
- **MAJOR** (1.0.0) : Changements incompatibles d'API
- **MINOR** (1.1.0) : Nouvelles fonctionnalités compatibles
- **PATCH** (1.0.1) : Corrections de bugs

### 2. Commiter les changements

```bash
git add redsentinel/version.py
git commit -m "chore: bump version to 1.1.0"
```

### 3. Créer un tag Git (optionnel mais recommandé)

```bash
git tag -a v1.1.0 -m "Version 1.1.0 - Features: logo ASCII, auto-update"
```

**Tags recommandés** :
- `v1.1.0` : Format standard
- Message descriptif des changements principaux

### 4. Pousser vers Git

```bash
# Pousser le code
git push origin main

# Pousser les tags
git push origin v1.1.0
```

### 5. Mise à jour sur Kali Linux

#### Méthode automatique (recommendé)

Une fois poussé vers Git, tous les utilisateurs verront la mise à jour :

```bash
redsentinel
```

Le système détectera automatiquement la nouvelle version et proposera de mettre à jour !

#### Méthode manuelle

Si l'utilisateur préfère mettre à jour manuellement :

```bash
cd ~/redsentinel-cli  # ou votre répertoire du projet
git pull
bash update.sh
```

## 🔄 Workflow complet d'exemple

```bash
# 1. Développer les nouvelles fonctionnalités
git add .
git commit -m "feat: add ASCII logo support"

# 2. Mettre à jour la version
# Éditer redsentinel/version.py : __version__ = "1.1.0"
git add redsentinel/version.py
git commit -m "chore: bump version to 1.1.0"

# 3. Créer un tag
git tag -a v1.1.0 -m "Version 1.1.0 - Logo ASCII and auto-update"

# 4. Pousser tout
git push origin main
git push origin v1.1.0

# ✅ Terminé ! Les utilisateurs verront la mise à jour au prochain lancement
```

## 📝 Checklist avant de publier

- [ ] Tests passent localement
- [ ] Version incrémentée dans `redsentinel/version.py`
- [ ] Commit avec message clair
- [ ] Tag Git créé (optionnel mais recommandé)
- [ ] Code poussé vers `origin/main`
- [ ] Tags poussés vers Git

## 🎯 Bonnes pratiques

### Messages de commit

Utilisez des prefixes conventionnels :
- `feat:` : Nouvelle fonctionnalité
- `fix:` : Correction de bug
- `chore:` : Maintenance (mise à jour de version, config)
- `docs:` : Documentation
- `refactor:` : Refactorisation de code
- `style:` : Changements de formatage
- `test:` : Ajout/modification de tests

### Tags de version

Créez toujours un tag pour les versions publiques :
```bash
git tag -a v1.1.0 -m "Version 1.1.0"
```

### Notes de version (Release Notes)

Pour les versions majeures, créez un fichier `CHANGELOG.md` ou des notes de release sur GitHub.

## 🔍 Vérifier la version actuelle

```bash
# Depuis le code source
python3 -c "from redsentinel.version import __version__; print(__version__)"

# Depuis le CLI
redsentinel --version

# Depuis pip/pipx
pipx list | grep redsentinel
```

## 🐛 Résolution de problèmes

### Le système de mise à jour ne détecte pas la nouvelle version

1. Vérifiez que le commit a été poussé
2. Vérifiez que la version a été incrémentée
3. Vérifiez les permissions Git (pour repo privé)
4. Relancez `git fetch` sur le repo distant

### Les utilisateurs ne voient pas la mise à jour

1. Assurez-vous que `git pull` fonctionne sur leurs machines
2. Vérifiez qu'ils ont bien les credentials pour un repo privé
3. Ils peuvent toujours utiliser `bash update.sh` manuellement

### Conflits de version

Si deux versions ont le même numéro :
- Utilisez toujours des numéros uniques
- Incrémentez le PATCH si besoin (1.1.1)

---

**💡 Astuce** : Le système de mise à jour automatique utilise Git pour détecter les changements. Pas besoin de PyPI ou autre registre de packages !

