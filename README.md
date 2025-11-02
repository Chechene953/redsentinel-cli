# RedSentinel Automation Prototype

Cette archive contient un prototype d'outil d'automatisation pour tâches de reconnaissance et scan,
avec wrappers pour nmap, nuclei, etc. UTILISATION LÉGALE SEULEMENT: n'exécutez ces outils que sur des cibles
pour lesquelles vous avez une autorisation écrite.

Structure:
- redsentinel/: code source (cli, recon, scanner, webcheck, reporter, utils)
- redsentinel/tools/: wrappers pour outils externes (nmap, nuclei)
- redsentinel/storage/: sqlite wrapper
- plugins/: interface de plugin
- config.yaml: config d'exemple
- requirements.txt

Voir les commentaires dans les fichiers pour l'utilisation.
