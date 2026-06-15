import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
import pickle
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics.pairwise import cosine_similarity




import pandas as pd

def encode_dataset(df):
    """
    Charge le dataset, renomme les colonnes, crée les variables temporelles,
    prépare les colonnes numériques et crée le dataset encodé.
    """
    OneHot_encoder = get_OneHot_encoder()
    df_encoded = df.copy()
    
    df_encoded["Date"] = pd.to_datetime(df_encoded["Date"], errors="coerce")
    df_encoded["year"] = df_encoded["Date"].dt.year
    df_encoded["month"] = df_encoded["Date"].dt.month
    df_encoded["Editeur"] = df_encoded["Editeur"].apply(remove_duplicates_in_cell)
    df_encoded["Produit"] = df_encoded["Produit"].apply(remove_duplicates_in_cell)
    categorical_cols = ["Type", "Editeur", "Produit", "CWE", "Base severity", "Vecteur de l'attaque", "Complexité de l'attaque",
                        "Privileges requis", "Action utilisateur", "Impact sur la confidentialité", "Impact sur l'intégrité",
                        "Impact sur la disponibilité"]
    texts_cols = ["Titre ANSSI", "Description CVE", "Description CWE"]
    numerics_cols = ["year", "month", "EPSS", "EPSS prédite", "CVSS", "CVSS prédite"]
    df_encoded[numerics_cols] = df_encoded[numerics_cols].apply(pd.to_numeric, errors="coerce")
    df_encoded[categorical_cols] = df_encoded[categorical_cols].fillna("Unknown")
    OneHot_encoded_matrix = OneHot_encoder.transform(df_encoded[categorical_cols])
    OneHot_features = OneHot_encoder.get_feature_names_out(categorical_cols)
    OneHot_df = pd.DataFrame(OneHot_encoded_matrix, columns=OneHot_features, index=df.index)
    df_encoded[texts_cols] = df_encoded[texts_cols].fillna("")
    df_encoded["text_for_tfidf"] = df_encoded[texts_cols].astype(str).agg(" ".join, axis=1)
    TfIdf_vectorizer = get_TfIdf_GBR_vectorizer()    
    TfIdf_encoded_SparseMatrix = TfIdf_vectorizer.transform(df_encoded["text_for_tfidf"])
    TfIdf_features = TfIdf_vectorizer.get_feature_names_out()
    TfIdf_df = pd.DataFrame(TfIdf_encoded_SparseMatrix.toarray(), columns=["tfidf_" + word for word in TfIdf_features],
                            index=df.index)
                            
    dataset_encoded = pd.concat([OneHot_df, TfIdf_df, df_encoded[numerics_cols]], axis=1)
    return dataset_encoded


def get_cvss_columns(dataset_encoded):
    """
    Récupère les colonnes trop directement liées au calcul du CVSS.
    Elles seront retirées pour créer le modèle réaliste.
    """
    cvss_related_prefixes = [
        "Base severity_",
        "Vecteur de l'attaque_",
        "Complexité de l'attaque_",
        "Privileges requis_",
        "Action utilisateur_",
        "Impact sur la confidentialité_",
        "Impact sur l'intégrité_",
        "Impact sur la disponibilité_"
    ]
    cols_to_remove = [
        col for col in dataset_encoded.columns
        if any(col.startswith(prefix) for prefix in cvss_related_prefixes)
    ]
    return cols_to_remove




def calc_cvss_missing_values(encoded_line):
    model = get_model_cvss()
    colonne_supp = get_cvss_columns(encoded_line)
    x = encoded_line.drop( columns = ["EPSS", "EPSS prédite", "CVSS", "CVSS prédite"] + colonne_supp)
    return model.predict(x)


def calc_epss_missing_values(encoded_line):
    model = get_model_epss()
    colonne_supp = get_cvss_columns(encoded_line)
    x = encoded_line.drop(columns = ["EPSS", "EPSS prédite", "CVSS", "CVSS prédite"] + colonne_supp)
    return model.predict(x)
    
    


def calc_risk_score(ligne):
    return (0.6 * ligne["CVSS prédite"] / 10) + 0.4 * ligne["EPSS prédite"]


def get_OneHot_encoder():
    path = Path("./model/OneHot_encoder.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier './model/OneHot_encoder.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )
    
def get_TfIdf_GBR_vectorizer():
    path = Path("./model/TfIdf_vectorizer_GBR.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier './model/TfIdf_vectorizer_GBR.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )
    
def get_TfIdf_KM_vectorizer():
    path = Path("./model/TfIdf_vectorizer_KM.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier './model/TfIdf_vectorizer_KM.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )

def get_model_cvss():
    path = Path("model/model_cvss.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier 'model/model_cvss.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )

def get_model_epss():
    path = Path("model/model_epss.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier 'model/model_epss.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )

def get_model_kmean():
    path = Path("model/model_kmean.pkl")
    if path.is_file():
        with open(path, "rb") as fichier:
            return pickle.load(fichier)
    else:
        raise FileNotFoundError(
            f"Fichier 'model/model_kmean.pkl' introuvable. \n"
            "Attention : Le modèle de prédiction n'est pas présent. "
            "Vous devez d'abord lancer et exécuter entièrement le Jupyter Notebook "
            "pour entraîner et sauvegarder le modèle avant d'utiliser cette fonction."
        )
    

def remove_duplicates_in_cell(cell_value, separator=','):
    if pd.isna(cell_value):
        return cell_value
    elements = [item.strip() for item in str(cell_value).split(separator)]
    unique_elements = list(dict.fromkeys(elements))
    return ', '.join(unique_elements)

