# Ransomware Simulator 🔐

Ce projet est un **simulateur de ransomware éducatif** qui montre comment fonctionnent les véritables ransomwares et comment sécuriser ses données contre ce type d'attaque.

⚠️ **AVERTISSEMENT: Ce code est potentiellement dangereux!** ⚠️
- Ce programme peut réellement chiffrer vos fichiers
- À utiliser UNIQUEMENT dans un environnement isolé ou virtuel
- L'auteur n'assume aucune responsabilité pour une utilisation malveillante ou des dommages causés

## Fonctionnalités

- Chiffrement de fichiers avec AES-256
- Génération d'une clé de déchiffrement unique
- Création d'une note de rançon
- Changement du fond d'écran
- Outil de déchiffrement pour récupérer les fichiers

## Installation

Assurez-vous d'avoir Python 3.6+ installé, puis installez les dépendances:

```bash
pip install -r requirements.txt
```

## Utilisation

### Mode chiffrement (dangereux!)

```bash
python ransomware.py
```

Le programme demande une confirmation pour éviter une exécution accidentelle.

### Mode déchiffrement

```bash
python ransomware.py decrypt decrypt_key.key [chemin_à_déchiffrer]
```

Si aucun chemin n'est spécifié, le dossier courant sera déchiffré.

## À des fins éducatives uniquement

Ce projet a été créé pour:

1. Comprendre comment fonctionnent les ransomwares
2. Apprendre à protéger ses données contre ce type d'attaque
3. Démontrer l'importance des sauvegardes

## Comment se protéger des ransomwares

- Effectuez des sauvegardes régulières hors ligne
- N'ouvrez pas les pièces jointes ou liens suspects
- Maintenez votre système d'exploitation et logiciels à jour
- Utilisez une solution antivirus/antimalware de qualité
- Activez l'authentification à deux facteurs
- Limitez les privilèges d'administrateur

## Notes techniques

Le ransomware utilise:
- Chiffrement AES-256 en mode CBC
- Gestion sécurisée des clés
- Identification des cibles par extension de fichier
- Protection des dossiers système critiques

## Licence

Ce projet est fourni à des fins éducatives uniquement. 