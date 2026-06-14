import pandas as pd
import numpy as np

from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score



def load_prepare_and_encode_dataset(path="./data/test.csv"):
    """
    Charge le dataset, renomme les colonnes, crée les variables temporelles,
    prépare les colonnes numériques et crée le dataset encodé.
    Retourne aussi les encodeurs OneHot et TF-IDF pour pouvoir les réutiliser.
    """
    # chargement du dataset et simplification du nom des colonnes
    df = pd.read_csv(path, sep=";", low_memory=False)
    df = df.rename(columns={
        "Description CVE": "Description",
        "Base severity": "Base Severity",
        "Vecteur de l'attaque": "Attack Vector",
        "Complexité de l'attaque": "Attack Complexity",
        "Privileges requis": "Privileges Required",
        "Action utilisateur": "User Interaction",
        "Impact sur la confidentialité": "Confidentiality Impact",
        "Impact sur l'intégrité": "Integrity Impact",
        "Impact sur la disponibilité": "Availability Impact"
    })

    # Création des variables temporelles
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    df["year"] = df["Date"].dt.year
    df["month"] = df["Date"].dt.month

    # Gestion des valeurs numeriques
    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")

    df["EPSS_missing"] = df["EPSS"].isna().astype(int)
    df["EPSS_filled"] = df["EPSS"].fillna(df["EPSS"].median())

    # Creation des differentes categories d'encodage
    categorical_cols = ["Type", "Editeur", "Produit", "CWE", "Base Severity", "Attack Vector", "Attack Complexity",
                        "Privileges Required", "User Interaction", "Confidentiality Impact", "Integrity Impact",
                        "Availability Impact"]

    texts_cols = ["Titre ANSSI", "Description", "Description CWE"]

    numerics_cols = ["EPSS_filled", "EPSS_missing", "year", "month"]

    # Encodage des colonnes OneHot (categorical_cols)
    OneHot_encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
    df[categorical_cols] = df[categorical_cols].fillna("Unknown")
    OneHot_encoded_matrix = OneHot_encoder.fit_transform(df[categorical_cols])
    OneHot_features = OneHot_encoder.get_feature_names_out(categorical_cols)
    OneHot_df = pd.DataFrame(OneHot_encoded_matrix, columns=OneHot_features, index=df.index)

    # Encodage des colonnes en TF-IDF (on regroupe toutes les colonnes textuelles)
    df[texts_cols] = df[texts_cols].fillna(
        "")  # fillna() remplace les Nan crée par pandas en str vide pour avoir un TF-IDF nul
    df["text_for_tfidf"] = df[texts_cols].astype(str).agg(" ".join, axis=1)
    TfIdf_vectorizer = TfidfVectorizer(stop_words='english', max_features=500, ngram_range=(1,
                                                                                            2))  # stop_words='english' pour ignorer les mots vides en anglais
    TfIdf_encoded_SparseMatrix = TfIdf_vectorizer.fit_transform(df["text_for_tfidf"])
    TfIdf_features = TfIdf_vectorizer.get_feature_names_out()
    TfIdf_df = pd.DataFrame(TfIdf_encoded_SparseMatrix.toarray(), columns=["tfidf_" + word for word in TfIdf_features],
                            index=df.index)
    # toarray() transforme cahque ligne en liste. On obtient une matrice avec toutes les descriptions
    # vectorizer.get_feature_names_out() retourne le mot pour chaque colonne de la matrice

    # Creation du dataset encode pour les modeles de ML
    dataset_encoded = pd.concat([OneHot_df, TfIdf_df, df[numerics_cols], df[["CVSS", "EPSS"]]], axis=1)

    return df, dataset_encoded, OneHot_encoder, TfIdf_vectorizer





def get_cvss_columns(dataset_encoded):
    """
    Récupère les colonnes trop directement liées au calcul du CVSS.
    Elles seront retirées pour créer le modèle réaliste.
    """

    cvss_related_prefixes = [
        "Base Severity_",
        "Attack Vector_",
        "Attack Complexity_",
        "Privileges Required_",
        "User Interaction_",
        "Confidentiality Impact_",
        "Integrity Impact_",
        "Availability Impact_"
    ]

    cols_to_remove = [
        col for col in dataset_encoded.columns
        if any(col.startswith(prefix) for prefix in cvss_related_prefixes)
    ]

    return cols_to_remove


def create_cvss_train_test_data(dataset_encoded, cols_to_remove):
    """
    Crée X et y pour le modèle CVSS réaliste.
    On garde uniquement les lignes où CVSS est connu.
    On retire CVSS, EPSS et les colonnes trop proches du calcul du CVSS.
    """
    from sklearn.model_selection import train_test_split

    df_cvss = dataset_encoded.dropna(subset=["CVSS"])

    X_cvss_realistic = df_cvss.drop(columns=["CVSS", "EPSS"] + cols_to_remove)
    y_cvss = df_cvss["CVSS"]

    X_train_realistic, X_test_realistic, y_train_realistic, y_test_realistic = train_test_split(
        X_cvss_realistic,
        y_cvss,
        test_size=0.2,
        random_state=42
    )
    return X_train_realistic, X_test_realistic, y_train_realistic, y_test_realistic


def evaluate_model(y_test, y_pred):
    """
    Affiche les métriques principales d'un modèle de régression.
    """
    mae = mean_absolute_error(y_test, y_pred)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    r2 = r2_score(y_test, y_pred)

    print("MAE :", mae)
    print("RMSE :", rmse)
    print("R² :", r2)

    return mae, rmse, r2


def complete_cvss_missing_values(df, dataset_encoded, model_cvss_realistic, cols_to_remove):
    """
    Crée CVSS_completed :
    - garde le vrai CVSS quand il existe
    - prédit le CVSS quand il est manquant
    """
    df = df.copy()
    df["CVSS_completed"] = df["CVSS"]

    mask_cvss_missing = df["CVSS"].isna()

    if mask_cvss_missing.sum() > 0:
        X_cvss_missing = dataset_encoded.loc[mask_cvss_missing].drop(
            columns=["CVSS", "EPSS"] + cols_to_remove
        )

        df.loc[mask_cvss_missing, "CVSS_completed"] = model_cvss_realistic.predict(X_cvss_missing)

    df["CVSS_completed"] = df["CVSS_completed"].clip(0, 10)

    return df


# Partie specifique a EPSS

def create_epss_train_test_data(dataset_encoded, df):
    """
    Crée X et y pour le modèle EPSS.
    On garde uniquement les lignes où EPSS est connu.
    On ajoute CVSS_completed comme variable explicative.
    On retire EPSS, CVSS, EPSS_filled et EPSS_missing pour éviter la fuite d'information.
    """

    from sklearn.model_selection import train_test_split
    dataset_encoded = dataset_encoded.copy()
    dataset_encoded["CVSS_completed"] = df["CVSS_completed"]
    df_epss = dataset_encoded.dropna(subset=["EPSS"])
    X_epss = df_epss.drop(
        columns=["EPSS", "CVSS", "EPSS_filled", "EPSS_missing"]
    )
    y_epss = df_epss["EPSS"]
    X_train_epss, X_test_epss, y_train_epss, y_test_epss = train_test_split(
        X_epss,
        y_epss,
        test_size=0.2,
        random_state=42
    )
    return X_train_epss, X_test_epss, y_train_epss, y_test_epss



def complete_epss_missing_values(df, dataset_encoded, model_epss):
    """
    Crée EPSS_completed :
    - garde le vrai EPSS quand il existe
    - prédit le EPSS quand il est manquant
    """
    df = df.copy()
    dataset_encoded = dataset_encoded.copy()

    dataset_encoded["CVSS_completed"] = df["CVSS_completed"]

    df["EPSS_completed"] = df["EPSS"]

    mask_epss_missing = df["EPSS"].isna()

    if mask_epss_missing.sum() > 0:
        X_epss_missing = dataset_encoded.loc[mask_epss_missing].drop(
            columns=["EPSS", "CVSS", "EPSS_filled", "EPSS_missing"]
        )

        df.loc[mask_epss_missing, "EPSS_completed"] = model_epss.predict(X_epss_missing)

    df["EPSS_completed"] = df["EPSS_completed"].clip(0, 1)

    return df

# risk score
def create_risk_score(df):
    """
    Crée un score de risque à partir de CVSS_completed et EPSS_completed.
    Le CVSS est normalisé entre 0 et 1, puis combiné avec l'EPSS.
    """
    df = df.copy()
    df["risk_score"] = (
        0.6 * (df["CVSS_completed"] / 10) +
        0.4 * df["EPSS_completed"]
    )
    df["risk_priority"] = pd.cut(
        df["risk_score"],
        bins=[0, 0.3, 0.6, 0.8, 1.0],
        labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        include_lowest=True
    )
    return df


def create_completed_dataset(df):
    """
    Crée le dataset final enrichi.
    On garde toutes les colonnes du dataset d'origine,
    puis on ajoute le score de risque et la priorité.
    """

    df_completed = df.copy()

    df_completed = create_risk_score(df_completed)

    return df_completed


# Traiter de nouvelles data

def process_new_data(
    path,
    OneHot_encoder,
    TfIdf_vectorizer,
    model_cvss_realistic,
    model_epss,
    cvss_model_columns,
    epss_model_columns
):
    """
    Traite de nouvelles data.
    """

    df_new = pd.read_csv(path, sep=";", low_memory=False)

    df_new = df_new.rename(columns={
        "Description CVE": "Description",
        "Base severity": "Base Severity",
        "Vecteur de l'attaque": "Attack Vector",
        "Complexité de l'attaque": "Attack Complexity",
        "Privileges requis": "Privileges Required",
        "Action utilisateur": "User Interaction",
        "Impact sur la confidentialité": "Confidentiality Impact",
        "Impact sur l'intégrité": "Integrity Impact",
        "Impact sur la disponibilité": "Availability Impact"
    })

    df_new["Date"] = pd.to_datetime(df_new["Date"], errors="coerce")
    df_new["year"] = df_new["Date"].dt.year
    df_new["month"] = df_new["Date"].dt.month

    if "CVSS" not in df_new.columns:
        df_new["CVSS"] = np.nan

    if "EPSS" not in df_new.columns:
        df_new["EPSS"] = np.nan

    df_new["CVSS"] = pd.to_numeric(df_new["CVSS"], errors="coerce")
    df_new["EPSS"] = pd.to_numeric(df_new["EPSS"], errors="coerce")

    df_new["EPSS_missing"] = df_new["EPSS"].isna().astype(int)
    df_new["EPSS_filled"] = df_new["EPSS"].fillna(0)

    categorical_cols = [
        "Type", "Editeur", "Produit", "CWE", "Base Severity",
        "Attack Vector", "Attack Complexity", "Privileges Required",
        "User Interaction", "Confidentiality Impact",
        "Integrity Impact", "Availability Impact"
    ]

    texts_cols = ["Titre ANSSI", "Description", "Description CWE"]

    numerics_cols = ["EPSS_filled", "EPSS_missing", "year", "month"]

    for col in categorical_cols:
        if col not in df_new.columns:
            df_new[col] = "Unknown"

    for col in texts_cols:
        if col not in df_new.columns:
            df_new[col] = ""

    df_new[categorical_cols] = df_new[categorical_cols].fillna("Unknown")

    OneHot_encoded_matrix = OneHot_encoder.transform(df_new[categorical_cols])
    OneHot_features = OneHot_encoder.get_feature_names_out(categorical_cols)

    OneHot_df = pd.DataFrame(
        OneHot_encoded_matrix,
        columns=OneHot_features,
        index=df_new.index
    )

    df_new[texts_cols] = df_new[texts_cols].fillna("")
    df_new["text_for_tfidf"] = df_new[texts_cols].astype(str).agg(" ".join, axis=1)

    TfIdf_encoded_SparseMatrix = TfIdf_vectorizer.transform(df_new["text_for_tfidf"])
    TfIdf_features = TfIdf_vectorizer.get_feature_names_out()

    TfIdf_df = pd.DataFrame(
        TfIdf_encoded_SparseMatrix.toarray(),
        columns=["tfidf_" + word for word in TfIdf_features],
        index=df_new.index
    )

    dataset_new_encoded = pd.concat(
        [
            OneHot_df,
            TfIdf_df,
            df_new[numerics_cols],
            df_new[["CVSS", "EPSS"]]
        ],
        axis=1
    )

    X_new_cvss = dataset_new_encoded.reindex(
        columns=cvss_model_columns,
        fill_value=0
    )

    df_new["CVSS_completed"] = df_new["CVSS"]

    mask_cvss_missing = df_new["CVSS"].isna()

    if mask_cvss_missing.sum() > 0:
        df_new.loc[mask_cvss_missing, "CVSS_completed"] = model_cvss_realistic.predict(
            X_new_cvss.loc[mask_cvss_missing]
        )

    df_new["CVSS_completed"] = df_new["CVSS_completed"].clip(0, 10)

    dataset_new_encoded["CVSS_completed"] = df_new["CVSS_completed"]

    X_new_epss = dataset_new_encoded.reindex(
        columns=epss_model_columns,
        fill_value=0
    )

    df_new["EPSS_completed"] = df_new["EPSS"]

    mask_epss_missing = df_new["EPSS"].isna()

    if mask_epss_missing.sum() > 0:
        df_new.loc[mask_epss_missing, "EPSS_completed"] = model_epss.predict(
            X_new_epss.loc[mask_epss_missing]
        )

    df_new["EPSS_completed"] = df_new["EPSS_completed"].clip(0, 1)

    df_new = create_completed_dataset(df_new)

    return df_new, dataset_new_encoded