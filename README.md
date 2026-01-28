# XML Sitemap Analyzer

Une application Streamlit pour analyser les sitemaps XML et obtenir des statistiques sur les URLs et leurs dates de modification.

## Fonctionnalités

- Analyse de sitemaps XML via URL
- Comptage des URLs uniques
- Analyse des dates de dernière modification
  - Dernières 24 heures
  - Dernière semaine
  - Dernier mois
  - Dernière année

## Installation

1. Cloner le repository
2. Installer les dépendances:
```bash
pip install -r requirements.txt
```

## Utilisation

### Méthode 1 : Script de lancement (Recommandé)
```bash
./run.sh
```

### Méthode 2 : Commande manuelle
```bash
streamlit run main.py
```

### ⚠️ Note importante pour les utilisateurs Mac avec Anaconda

Si vous avez plusieurs installations Python (Anaconda + Python système), assurez-vous d'utiliser le bon environnement :

```bash
# Utilisez le chemin complet vers Streamlit d'Anaconda
/Users/VOTRE_NOM/anaconda3/bin/streamlit run main.py

# Ou initialisez Conda dans votre terminal
conda init zsh
source ~/.zshrc
conda activate base
streamlit run main.py
``` 