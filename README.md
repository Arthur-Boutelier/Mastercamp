# Projet ANSSI -  Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Membres du Groupe :
- Arthur BOUTELIER
- Raphael BILLY
- Thomas BOTTALICO
- Baptiste BERTRAND
## Objectif du projet

Le but de ce projet est d’automatiser l’analyse des avis et alertes publiés par l’ANSSI / CERT-FR.

Le programme récupère des bulletins de sécurité, extrait les CVE associées et enrichit ces CVE avec des informations comme le CVSS, le CWE, l’EPSS, l’éditeur, le produit et les versions affectées.

Le projet contient aussi une partie de Data Visualisation afin de mieux visualiser les donnees et une partie de Machine Learning pour compléter certaines valeurs manquantes et créer un score de risque. Enfin, un système d’alerte surveille le flux RSS de l’ANSSI et génère des fichiers `.txt` représentant des emails d’alerte personnalisés.

## Fonctionnalités principales

* Extraction des avis et alertes ANSSI.
* Récupération des CVE associées à chaque bulletin.
* Enrichissement des CVE avec les données MITRE et FIRST EPSS.
* Création d’un dataset consolidé au format CSV.
* Analyse et visualisation des vulnérabilités.
* Complétion des scores CVSS et EPSS manquants avec des modèles de régression.
* Création d’un score de risque.
* Surveillance du flux RSS ANSSI.
* Génération de fichiers `.txt` simulant des emails d’alerte.

## Structure du projet

```text
TD_noté/
│
├── functions.py
├── utils.py
├── alerting.py
├── application.py
├── notebook.ipynb
│
├── data/
│   ├── alertes/
│   ├── avis/
│   ├── mitre/
│   ├── first/
│   └── test.csv
│
├── models/
│   ├── OneHot_encoder.pkl
│   ├── TfIdf_vectorizer.pkl
│   ├── model_cvss_realistic.pkl
│   ├── model_epss.pkl
│   ├── cvss_model_columns.pkl
│   └── epss_model_columns.pkl
│
└── mails/
```

## Rôle des fichiers

### `functions.py`

Ce fichier contient les fonctions d’extraction et d’enrichissement des données.

Il permet de lire les fichiers ANSSI, d’extraire les CVE, puis de récupérer les informations complémentaires via MITRE et FIRST EPSS.

### `utils.py`

Ce fichier contient les fonctions utilisées pour la partie Machine Learning.

Il permet de préparer les données, encoder les variables, entraîner les modèles, compléter les valeurs manquantes et calculer le score de risque.

### `alerting.py`

Ce fichier contient les fonctions liées aux alertes.

Il permet de lire le flux RSS ANSSI, détecter les nouveaux bulletins, choisir les bons destinataires et générer les mails sous forme de fichiers `.txt`.

### `application.py`

Ce fichier permet de lancer la veille en continu.

Il utilise les fonctions de `alerting.py` pour vérifier régulièrement le flux RSS ANSSI. Lorsqu’un nouveau bulletin est détecté, le programme génère automatiquement les fichiers `.txt` correspondant aux mails d’alerte.

### `notebook.ipynb`

Le notebook présente l’analyse du dataset, les visualisations, la partie Machine Learning, l’évaluation des modèles et la création du score de risque.

## Installation

Installer les bibliothèques nécessaires :

```bash
pip install pandas requests feedparser scikit-learn matplotlib joblib
```

## Utilisation

### Créer le dataset consolidé

```python
from functions import Initialisation_df

df = Initialisation_df()
df.to_csv("./data/test.csv", sep=";", index=False)
```

Le fichier `test.csv` contient les données consolidées issues des avis et alertes ANSSI enrichies avec les informations CVE.

### Lancer la partie Machine Learning

La partie Machine Learning se lance depuis le notebook.

Elle permet de :

* charger le dataset ;
* préparer les données ;
* entraîner les modèles ;
* compléter les valeurs CVSS et EPSS manquantes ;
* calculer un score de risque ;
* sauvegarder les résultats.

### Lancer une vérification simple du flux RSS

```python
import alerting

created_files = alerting.check_rss_and_generate_mails(
    alerting.destinataires_par_produit,
    max_bulletins=2
)

created_files
```

Les mails générés sont enregistrés dans le dossier :

```text
./mails/
```

### Lancer la veille continue

Le fichier `application.py` permet de lancer le programme en continu :

```bash
python application.py
```

Le programme vérifie régulièrement le flux RSS ANSSI. Si un nouveau bulletin est détecté, il génère les fichiers `.txt` des mails d’alerte.

## Machine Learning

Deux modèles de régression sont utilisés.

Le premier modèle sert à compléter les valeurs CVSS manquantes. Le CVSS est une note entre 0 et 10 qui représente la gravité technique d’une vulnérabilité.

Le second modèle sert à compléter les valeurs EPSS manquantes. L’EPSS est une valeur entre 0 et 1 qui représente la probabilité qu’une vulnérabilité soit exploitée.

Ces modèles ne remplacent pas les scores officiels. Ils servent surtout à compléter le dataset lorsque certaines valeurs sont manquantes.

## Score de risque

Le score de risque combine le CVSS complété et l’EPSS complété :

```python
risk_score = 0.6 * (CVSS_completed / 10) + 0.4 * EPSS_completed
```

Le CVSS indique la gravité technique.
L’EPSS indique la probabilité d’exploitation.

## Alertes personnalisées

Les destinataires sont choisis selon les produits concernés.

Exemple :

```python
destinataires_par_produit = {
    "microsoft": ["soc.microsoft@example.com", "admin.microsoft@example.com"],
    "azure": ["cloud.security@example.com"],
    "apache": ["web.security@example.com"],
    "linux": ["linux.admin@example.com"],
    "cisco": ["network.security@example.com"],
    "ivanti": ["soc.ivanti@example.com"],
    "default": ["soc.general@example.com"]
}
```

Si un bulletin concerne Microsoft, les destinataires liés à Microsoft sont alertés.
Si aucun produit ne correspond, le mail est envoyé au destinataire par défaut.

Dans cette version, les emails ne sont pas réellement envoyés. Le programme crée seulement des fichiers `.txt` avec une structure de mail classique :

```text
To: destinataire
Subject: Alerte ANSSI - nouvelles vulnérabilités détectées

Bonjour,

...
```

## Fichiers générés

Le projet peut générer :

* `test.csv` : dataset consolidé ;
* `dataset_completed_final.csv` : dataset enrichi avec les valeurs complétées ;
* `final_risk_prioritization.csv` : fichier utilisé pour prioriser les vulnérabilités ;
* des fichiers `.pkl` dans `models/` : modèles et encodeurs sauvegardés ;
* des fichiers `.txt` dans `mails/` : mails d’alerte générés ;
* `seen_anssi_ids.json` : fichier mémoire des bulletins déjà traités.

## Limites et améliorations possibles

* Ajouter l’envoi réel des emails.
* Ajouter plus de produits surveillés.
* Améliorer la gestion des erreurs API.
* Ajouter les résultats du clustering dans les mails.
* Ajouter directement les scores calculés par les modèles dans les alertes.
* Déployer la veille comme un service automatique.
