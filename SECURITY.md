# Security Policy

## ⚠️ Usage Responsable

**RedSentinel est un outil de sécurité à des fins éducatives et de test de pénétration légitime uniquement.**

### Utilisation Légale Seulement

- ✅ **AUTORISÉ**: Tests de pénétration avec autorisation écrite explicite de la propriétaire de la cible
- ✅ **AUTORISÉ**: Tests sur vos propres systèmes et réseaux
- ✅ **AUTORISÉ**: Environnements de laboratoire contrôlés
- ❌ **INTERDIT**: Scans non autorisés de systèmes tiers
- ❌ **INTERDIT**: Accès non autorisé à des données
- ❌ **INTERDIT**: Activités malveillantes ou illégales

### Responsabilité

L'utilisation de RedSentinel est **entièrement à vos risques et périls**. Les auteurs et contributeurs ne sont pas responsables des dommages résultant d'une utilisation inappropriée ou illégale de cet outil.

## 🔐 Sécurité du Code

### Signaler une vulnérabilité

Si vous découvrez une vulnérabilité de sécurité dans le code de RedSentinel :

1. **Ne créez pas d'issue publique** sur GitHub
2. Contactez les mainteneurs de manière privée
3. Donnez suffisamment de détails pour reproduire le problème
4. Laissez un délai raisonnable pour la correction avant de divulguer publiquement

### Bonnes pratiques

- Le code ne contient **aucune information sensible hardcodée**
- Les configurations utilisateur ne sont **jamais commitées** dans le repo
- Utilisez toujours `.gitignore` pour exclure vos fichiers de configuration locaux
- Ne partagez jamais vos résultats de scan contenant des informations sensibles

## 🛡️ Recommandations

1. **Authentification**: RedSentinel n'inclut aucune authentification intégrée. Utilisez-le uniquement sur des machines sécurisées.
2. **Configuration**: Stockez votre `config.yaml` dans `~/.redsentinel/` avec les permissions appropriées (`chmod 600`).
3. **Résultats**: Les rapports HTML peuvent contenir des informations sensibles. Protégez-les en conséquence.
4. **Législation**: Respectez toutes les lois locales et internationales applicables.

## 📋 Checklist de Sécurité

Avant de rendre votre repo public, vérifiez :

- [ ] Aucune clé API ou secret hardcodé
- [ ] Aucun fichier de configuration avec des données sensibles
- [ ] `.gitignore` à jour
- [ ] Avertissements clairs sur l'utilisation légale
- [ ] Pas de données d'exemple compromettantes
- [ ] Base de données de résultats non commitée

## 🔍 Audit

RedSentinel utilise uniquement des outils existants (nmap, nuclei, etc.) et n'inclut pas de code malveillant. Cependant :

- Auditez le code avant de l'utiliser en production
- Vérifiez que les dépendances externes sont à jour
- Testez dans un environnement isolé d'abord

---

**Soyez responsable. Hackez légalement. Restez éthique.**

