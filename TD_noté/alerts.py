import os
import pandas as pd


destinataires_par_produit = {
    "microsoft": ["soc.microsoft@example.com", "admin.microsoft@example.com"],
    "azure": ["cloud.security@example.com"],
    "apache": ["web.security@example.com"],
    "linux": ["linux.admin@example.com"],
    "cisco": ["network.security@example.com"],
    "ivanti": ["soc.ivanti@example.com"],
    "default": ["soc.general@example.com"]
}


def nettoyer_liste(valeur):
    """
    Cette fonction nettoie les champs comme Produit ou Editeur.
    Par exemple, si on a "Linux, Linux", on garde seulement "Linux".
    """
    elements = str(valeur).split(",")
    elements = [e.strip() for e in elements if e.strip() != ""]
    elements_uniques = list(dict.fromkeys(elements))

    return ", ".join(elements_uniques)


def raccourcir_versions(versions, max_versions=5):
    """
    Cette fonction rend la liste des versions plus lisible dans le mail.
    On enlève les doublons et on affiche seulement quelques versions.
    """
    versions = str(versions).split(",")
    versions = [v.strip() for v in versions if v.strip() != ""]

    versions_uniques = list(dict.fromkeys(versions))

    if len(versions_uniques) > max_versions:
        versions_affichees = ", ".join(versions_uniques[:max_versions])
        nb_restantes = len(versions_uniques) - max_versions
        return f"{versions_affichees}... (+ {nb_restantes} autres, voir lien solution)"

    return ", ".join(versions_uniques)


def trouver_destinataires(row):
    """
    Cette fonction sert à trouver à qui envoyer l'alerte.
    On regarde le produit, l'éditeur et le titre ANSSI, puis on compare avec notre dictionnaire.
    Si aucun produit ne correspond, on envoie à l'adresse par défaut.
    """
    texte = (
        str(row["Produit"]) + " " +
        str(row["Editeur"]) + " " +
        str(row["Titre ANSSI"])
    ).lower()

    destinataires = []
    produits_detectes = []

    for produit, emails in destinataires_par_produit.items():
        if produit != "default" and produit in texte:
            destinataires.extend(emails)
            produits_detectes.append(produit)

    if len(destinataires) == 0:
        destinataires = destinataires_par_produit["default"]
        produits_detectes = ["default"]

    return list(set(destinataires)), produits_detectes


def filtrer_alertes_recentes(df, nb_jours=90):
    """
    Cette fonction garde seulement les vulnérabilités récentes et importantes.
    On prend les lignes HIGH ou CRITICAL dans les derniers jours du dataset.
    """
    df = df.copy()
    df["Date"] = pd.to_datetime(df["Date"])

    date_reference = df["Date"].max()
    date_limite = date_reference - pd.Timedelta(days=nb_jours)

    alertes = df[
        (df["Date"] >= date_limite) &
        (df["risk_priority"].isin(["HIGH", "CRITICAL"]))
    ].copy()

    alertes = alertes.sort_values(
        by=["Date", "risk_score"],
        ascending=False
    )

    return alertes


def trouver_cve_similaires(row, df, n=2):
    """
    Cette fonction cherche les CVE les plus récentes dans le même cluster KMeans.
    On ne prend pas la CVE actuelle et on évite de prendre des CVE plus récentes que l'alerte.
    """
    df = df.copy()
    df["Date"] = pd.to_datetime(df["Date"])

    similaires = df[
        (df["cluster"] == row["cluster"]) &
        (df["CVE"] != row["CVE"]) &
        (df["Date"] <= row["Date"])
    ].copy()

    similaires = similaires.drop_duplicates(subset=["CVE"])

    similaires = similaires.sort_values(
        by=["Date", "risk_score"],
        ascending=[False, False]
    )

    return similaires[["CVE", "Date", "Lien CVE"]].head(n)


def creer_mail_alerte(row, df):
    """
    Cette fonction crée le contenu du mail d'alerte.
    Le mail n'est pas vraiment envoyé, on prépare seulement le sujet et le texte.
    On ajoute aussi deux CVE récentes du même cluster à la fin.
    """
    destinataires, produits_detectes = trouver_destinataires(row)
    cve_similaires = trouver_cve_similaires(row, df)

    subject = f"[ALERTE ANSSI - {row['risk_priority']}] {row['CVE']}"

    body = f"""To: {", ".join(destinataires)}
Subject: {subject}

Bonjour,

Une vulnérabilité prioritaire et récente a été détectée sur un produit surveillé.

Produit(s) ou éditeur(s) détecté(s) : {", ".join(produits_detectes)}

Informations sur la vulnérabilité :
- ID ANSSI : {row["ID ANSSI"]}
- Titre ANSSI : {row["Titre ANSSI"]}
- Type : {row["Type"]}
- Date : {row["Date"].date()}
- CVE : {row["CVE"]}
- Éditeur : {nettoyer_liste(row["Editeur"])}
- Produit : {nettoyer_liste(row["Produit"])}
- Versions affectées : {raccourcir_versions(row["Versions affectées"])}

Scores :
- CVSS complété : {row["CVSS_completed"]}
- EPSS complété : {row["EPSS_completed"]}
- Score de risque : {row["risk_score"]}
- Priorité : {row["risk_priority"]}

Liens utiles :
- Lien CVE : {row["Lien CVE"]}
- Lien solution : {row["Lien solution"]}

Recommandation :
Il est conseillé de vérifier rapidement si le produit concerné est utilisé dans le système d'information.
Si c'est le cas, il faut consulter la solution proposée et appliquer les correctifs disponibles.

Deux CVE récentes du même cluster KMeans :
"""

    if len(cve_similaires) == 0:
        body += "- Aucune CVE récente trouvée dans le même cluster.\n"
    else:
        for _, cve in cve_similaires.iterrows():
            body += f"- {cve['CVE']} | Date : {cve['Date'].date()} | Lien : {cve['Lien CVE']}\n"

    body += """
Cordialement,
Système de veille ANSSI
"""

    return subject, body


def generer_fichiers_alertes(df, dossier_sortie="mails_generes", nb_jours=90, nombre_max=20):
    """
    Cette fonction génère les fichiers texte des alertes.
    Elle filtre d'abord les alertes récentes, puis crée un fichier .txt pour chaque alerte.
    Elle retourne aussi un DataFrame résumé des mails générés.
    """
    os.makedirs(dossier_sortie, exist_ok=True)

    df = df.copy()
    df["Date"] = pd.to_datetime(df["Date"])

    alertes = filtrer_alertes_recentes(df, nb_jours=nb_jours)

    resume = []

    for index, row in alertes.head(nombre_max).iterrows():
        subject, body = creer_mail_alerte(row, df)

        nom_fichier = f"{dossier_sortie}/alerte_{index}_{row['CVE']}.txt"

        with open(nom_fichier, "w", encoding="utf-8") as f:
            f.write(body)

        destinataires, produits_detectes = trouver_destinataires(row)

        resume.append({
            "CVE": row["CVE"],
            "Date": row["Date"],
            "Produit": nettoyer_liste(row["Produit"]),
            "Editeur": nettoyer_liste(row["Editeur"]),
            "Priorité": row["risk_priority"],
            "Score de risque": row["risk_score"],
            "Destinataires": ", ".join(destinataires),
            "Fichier généré": nom_fichier
        })

    return pd.DataFrame(resume)