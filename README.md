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

## Fonctionnalités

Le projet permet de :

* récupérer les avis et alertes ANSSI ;
* extraire les CVE de chaque bulletin ;
* enrichir les CVE avec les données MITRE et FIRST EPSS ;
* construire un dataset consolidé au format CSV ;
* analyser et visualiser les vulnérabilités ;
* compléter les valeurs CVSS et EPSS manquantes avec des modèles de régression ;
* détecter de nouveaux bulletins via le flux RSS ANSSI ;
* générer des alertes personnalisées selon les produits ou éditeurs concernés ;
* créer des fichiers `.txt` simulant des emails d’alerte.

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

## Rôle des fichiers principaux

### `functions.py`

Contient les fonctions d’extraction et d’enrichissement des données.

Il permet de lire les bulletins ANSSI, récupérer les CVE, puis enrichir chaque CVE avec les données MITRE et FIRST EPSS.

### `utils.py`

Contient les fonctions liées à la partie Machine Learning.

Il permet de préparer les données, encoder les variables, entraîner les modèles, évaluer les résultats et compléter les valeurs CVSS et EPSS manquantes.

### `alerting.py`

Contient les fonctions liées aux alertes.

Il permet de lire le flux RSS ANSSI, détecter les nouveaux bulletins, choisir les destinataires concernés et générer les mails sous forme de fichiers `.txt`.

### `application.py`

Fichier principal permettant de lancer la veille en continu.

Il utilise les fonctions de `alerting.py` pour vérifier régulièrement le flux RSS ANSSI et générer automatiquement les fichiers d’alerte lorsqu’un nouveau bulletin est détecté.

### `notebook.ipynb`

Présente les étapes d’analyse du projet : chargement du dataset, visualisations, Machine Learning, évaluation des modèles et interprétation des résultats.


## Bibliothèques utilisées

Le projet utilise plusieurs bibliothèques Python.

Pour l’extraction et l’enrichissement des données, nous utilisons :

* `pandas` pour créer et manipuler les datasets ;
* `requests` pour récupérer les données depuis les API ANSSI, MITRE et FIRST EPSS ;
* `json` pour lire et écrire les fichiers JSON ;
* `os` et `pathlib` pour gérer les fichiers et les chemins.

Pour la lecture du flux RSS et le système d’alerte, nous utilisons :

* `feedparser` pour lire le flux RSS de l’ANSSI ;
* `re` pour récupérer les identifiants ANSSI dans les liens ;
* `time` pour faire tourner la veille en boucle avec un délai entre chaque vérification.

Pour la partie Machine Learning, nous utilisons :

* `numpy` pour certains calculs numériques ;
* `scikit-learn` pour préparer les données, entraîner les modèles et les évaluer ;
* `joblib` et `pickle` pour sauvegarder ou charger les modèles entraînés.

Pour les visualisations, nous utilisons :

* `matplotlib` pour créer les graphiques dans le notebook.

Les bibliothèques à installer sont :

```bash
pip install pandas numpy requests feedparser scikit-learn matplotlib joblib
```

Les bibliothèques `json`, `os`, `pathlib`, `re`, `time` et `pickle` sont déjà incluses avec Python. Elles n’ont donc pas besoin d’être installées séparément.


### Lancer la partie Machine Learning

La partie Machine Learning se lance depuis le notebook.

Elle permet de :

* charger le dataset ;
* préparer les variables ;
* entraîner les modèles ;
* compléter les valeurs manquantes ;
* sauvegarder les résultats et les modèles.

### Lancer une vérification ponctuelle du flux RSS

```python
import alerting

created_files = alerting.check_rss_and_generate_mails(
    alerting.destinataires_par_produit,
    max_bulletins=2
)

created_files
```

Les fichiers générés sont enregistrés dans :

```text
./mails/
```

### Lancer la veille continue

```bash
python application.py
```

Le programme vérifie régulièrement le flux RSS ANSSI. Lorsqu’un nouveau bulletin est détecté, il génère automatiquement un ou plusieurs fichiers `.txt` correspondant aux mails d’alerte.

## Machine Learning

Deux modèles de régression sont utilisés.

Le premier modèle sert à compléter les valeurs CVSS manquantes. Le CVSS est une note entre 0 et 10 qui représente la gravité technique d’une vulnérabilité.

Le second modèle sert à compléter les valeurs EPSS manquantes. L’EPSS est une valeur entre 0 et 1 qui représente la probabilité qu’une vulnérabilité soit exploitée.

Ces modèles ne remplacent pas les scores officiels. Ils permettent surtout de compléter le dataset lorsque certaines informations sont absentes.

## Système d’alerte

Le système d’alerte repose sur un dictionnaire associant certains produits ou éditeurs à des destinataires.

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

Si un nouveau bulletin concerne Microsoft, les destinataires associés à Microsoft sont alertés.
Si aucun produit ne correspond, le destinataire par défaut est utilisé.

Dans cette version, les emails ne sont pas réellement envoyés. Le programme génère uniquement des fichiers `.txt` avec une structure de mail classique :

```text
To: destinataire
Subject: Alerte ANSSI - nouvelles vulnérabilités détectées

Bonjour,

...
```

## Fichiers générés

Le projet peut générer :

* `test.csv` : dataset consolidé ;
* des fichiers `.pkl` dans `models/` : modèles et encodeurs sauvegardés ;
* des fichiers `.txt` dans `mails/` : mails d’alerte générés ;
* `seen_anssi_ids.json` : fichier mémoire des bulletins déjà traités.

## Limites et améliorations possibles

* Ajouter l’envoi réel des emails.
* Ajouter davantage de produits surveillés.
* Améliorer la gestion des erreurs API.
* Intégrer les résultats du clustering dans les mails d’alerte.
* Ajouter les scores complétés par les modèles directement dans les notifications.
* Déployer la veille comme un service automatique.



