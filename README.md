# Projet ANSSI -  Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Objectif du projet

Le but de ce projet est d’automatiser l’analyse des avis et alertes publiés par l’ANSSI / CERT-FR.

Le programme récupère des bulletins de sécurité, extrait les CVE associées et enrichit ces CVE avec des informations comme le CVSS, le CWE, l’EPSS, l’éditeur, le produit et les versions affectées.

Le projet contient aussi une partie de Data Visualisation afin de mieux visualiser les donnees et une partie de Machine Learning pour compléter certaines valeurs manquantes et créer un score de risque. Enfin, un système d’alerte surveille le flux RSS de l’ANSSI et génère des fichiers `.txt` représentant des emails d’alerte personnalisés.

## Fonctionnalités

Le projet permet de :

* récupérer les avis et alertes ANSSI 
* extraire les CVE de chaque bulletin 
* enrichir les CVE avec les données MITRE et FIRST EPSS 
* construire un dataset consolidé au format CSV 
* analyser et visualiser les vulnérabilités 
* compléter les valeurs CVSS et EPSS manquantes avec des modèles de régression 
* détecter de nouveaux bulletins via le flux RSS ANSSI 
* générer des alertes personnalisées selon les produits ou éditeurs concernés 
* créer des fichiers `.txt` simulant des emails d’alerte

## Structure du projet

```text
.
├── model/
│   ├── OneHot_encoder.pkl
│   ├── TfIdf_vectorizer_GBR.pkl
│   ├── TfIdf_vectorizer_KM.pkl
│   ├── model_cvss.pkl
│   ├── model_epss.pkl
│   └── model_kmean.pkl
│
├── KMeans.ipynb
├── ML.py
├── README.md
├── alert.py
├── application.py
├── clusters_kmeans.png
├── gestionDataframe.py
└── main.ipynb

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

* `pandas` pour créer et manipuler les datasets 
* `requests` pour récupérer les données depuis les API ANSSI, MITRE et FIRST EPSS 
* `json` pour lire et écrire les fichiers JSON 
* `os` et `pathlib` pour gérer les fichiers et les chemins

Pour la lecture du flux RSS et le système d’alerte, nous utilisons :

* `feedparser` pour lire le flux RSS de l’ANSSI 
* `re` pour récupérer les identifiants ANSSI dans les liens 
* `time` pour faire tourner la veille en boucle avec un délai entre chaque vérification

Pour la partie Machine Learning, nous utilisons :

* `numpy` pour certains calculs numériques 
* `scikit-learn` pour préparer les données, entraîner les modèles et les évaluer 
* `joblib` et `pickle` pour sauvegarder ou charger les modèles entraînés

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

* charger le dataset 
* préparer et encoder les variables 
* entraîner les modèles 
* compléter les valeurs manquantes 
* sauvegarder les résultats et les modèles

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

Nous avons ajouté une partie Machine Learning pour compléter certaines informations manquantes dans le dataset et pour mieux analyser les vulnérabilités.

### Modèles supervisés

Pour les modèles supervisés, nous avons utilisé `GradientBoostingRegressor`.

Ce modèle nous sert à prédire des valeurs numériques. Dans notre cas, nous l’avons utilisé pour compléter :

* les valeurs CVSS manquantes 
* les valeurs EPSS manquantes

Pour vérifier si les modèles donnent des résultats corrects, nous avons utilisé trois métriques :

* `MAE` : l’erreur moyenne entre la vraie valeur et la valeur prédite 
* `MSE` : une erreur moyenne qui pénalise davantage les grosses erreurs 
* `R²` : un score qui permet de voir si le modèle explique bien les données

L’objectif n’est pas de remplacer les scores officiels mais de compléter certaines valeurs absentes du dataset.

### Modèle non supervisé

Nous avons aussi utilisé `KMeans` pour faire du clustering.

Le but est de regrouper les vulnérabilités qui se ressemblent. Cela permet d’avoir une meilleure vision des différents types de vulnérabilités présentes dans le dataset.

Ces clusters peuvent ensuite être utilisés pour enrichir l’analyse ou pour ajouter des informations supplémentaires dans les alertes.


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

* `test.csv` : dataset consolidé 
* des fichiers `.pkl` dans `models/` : modèles et encodeurs sauvegardés 
* des fichiers `.txt` dans `mails/` : mails d’alerte générés 
* `seen_anssi_ids.json` : fichier mémoire des bulletins déjà traités

## Limites et améliorations possibles

* Ajouter l’envoi réel des emails.
* Ajouter davantage de produits surveillés.
* Améliorer la gestion des erreurs API.
* Intégrer les résultats du clustering dans les mails d’alerte.
* Ajouter les scores complétés par les modèles directement dans les notifications.
* Déployer la veille comme un service automatique.



