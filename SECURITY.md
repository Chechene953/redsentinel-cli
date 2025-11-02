# Politique de Sécurité

## Usage Professionnel Uniquement

**RedSentinel est un outil de sécurité destiné exclusivement à des fins professionnelles légales dans le cadre de tests de pénétration autorisés.**

### Utilisation Autorisée

- Tests de pénétration avec autorisation écrite explicite du propriétaire de la cible
- Tests sur vos propres systèmes et réseaux
- Environnements de laboratoire contrôlés et autorisés
- Missions de sécurité professionnelles légales

### Utilisation Interdite

- Scans non autorisés de systèmes tiers
- Accès non autorisé à des données
- Activités malveillantes ou illégales
- Toute utilisation violant des lois locales ou internationales

### Clause de Non-Responsabilité

**Propriétaire** : Alexandre Tavares  
**Entreprise** : Redsentinel  
**Logiciel** : RedSentinel

RedSentinel est fourni "tel quel" et l'utilisation de cet outil est entièrement à vos risques et périls. Alexandre Tavares et Redsentinel :

- Ne peuvent être tenus responsables de toute utilisation non autorisée
- Ne peuvent être tenus responsables des dommages résultant d'une utilisation inappropriée
- Ne cautionnent aucune activité illégale ou malveillante
- Ne sont pas responsables des violations de lois résultant de l'utilisation de cet outil

L'utilisateur reconnaît être le seul responsable et s'engage à utiliser RedSentinel uniquement dans le cadre légal et éthique de missions professionnelles autorisées.

## Signaler une Vulnérabilité

Si vous découvrez une vulnérabilité de sécurité dans le code de RedSentinel :

1. Ne créez pas d'issue publique
2. Contactez directement Alexandre Tavares / Redsentinel
3. Fournissez des détails suffisants pour reproduire le problème
4. Laissez un délai raisonnable pour la correction

## Bonnes Pratiques

- Le code ne contient aucune information sensible hardcodée
- Les configurations utilisateur ne sont jamais commitées dans le repo
- Utilisez `.gitignore` pour exclure vos fichiers de configuration locaux
- Ne partagez jamais vos résultats de scan contenant des informations sensibles
- Stockez `config.yaml` dans `~/.redsentinel/` avec les permissions appropriées

## Recommandations de Sécurité

1. **Authentification** : RedSentinel n'inclut aucune authentification intégrée. Utilisez-le uniquement sur des machines sécurisées.

2. **Configuration** : Protégez votre fichier de configuration avec les permissions appropriées (`chmod 600`).

3. **Résultats** : Les rapports HTML peuvent contenir des informations sensibles. Protégez-les en conséquence.

4. **Législation** : Respectez toutes les lois locales et internationales applicables.

5. **Audit** : Auditez le code avant utilisation en production. Vérifiez que les dépendances externes sont à jour.

## Audit de Code

RedSentinel utilise uniquement des outils existants (nmap, nuclei, etc.) et n'inclut pas de code malveillant. Cependant, testez toujours dans un environnement isolé avant utilisation en production.

---

**Utilisation Responsable. Usage Professionnel Uniquement.**
