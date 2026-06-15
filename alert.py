import os
import json
import re
import feedparser
import pandas as pd
from ML import *

from gestionDataframe import obtenir_json, create_dico_ANSSI, create_dico_CVE


def get_anssi_ids_from_rss(url="https://www.cert.ssi.gouv.fr/feed/"):
    rss_feed = feedparser.parse(url)
    ids = []
    for entry in rss_feed.entries:
        link = entry.link
        result = re.search(r"CERTFR-\d{4}-(ALE|AVI)-\d+", link)
        if result:
            anssi_id = result.group(0)
            ids.append(anssi_id)
    return ids

def get_new_anssi_ids(url="https://www.cert.ssi.gouv.fr/feed/", chemin_csv="./data/dataset_complet.csv"):
    """
    Récupère les IDs du flux RSS et filtre ceux qui sont déjà présents dans le dataset CSV.
    """
    rss_ids = get_anssi_ids_from_rss(url)
    new_ids = []

    if not os.path.exists(chemin_csv):
        print(f"Fichier {chemin_csv} introuvable. Tous les bulletins sont considérés comme nouveaux.")
        return rss_ids

    try:
        df = pd.read_csv(chemin_csv, usecols=['ID ANSSI'], sep=";")
        known_ids = df['ID ANSSI'].dropna().unique()
    except ValueError:
        print("Erreur : La colonne 'ID ANSSI' n'a pas été trouvée dans le CSV.")
        return rss_ids

    for anssi_id in rss_ids:
        if anssi_id not in known_ids:
            new_ids.append(anssi_id)

    return new_ids

def get_anssi_type(anssi_id):
    if "ALE" in anssi_id:
        return "alerte"
    elif "AVI" in anssi_id:
        return "avis"
    else:
        return None

def get_bulletin_cves(anssi_id):
    type_recherche = get_anssi_type(anssi_id)

    if type_recherche is None:
        print("ID ignoré :", anssi_id)
        return []

    try:
        json_anssi = obtenir_json(anssi_id, type_recherche)
    except Exception as e:
        print("Impossible de récupérer le JSON ANSSI pour :", anssi_id)
        print("Type :", type_recherche)
        print("Erreur :", e)
        return []

    dico_anssi, tab_cve = create_dico_ANSSI(json_anssi)

    alerts = []

    for cve in tab_cve:
        try:
            dico_cve = create_dico_CVE(cve)

            if dico_cve is not None:
                ligne = dico_anssi | dico_cve
                alerts.append(ligne)

        except Exception as e:
            print("Erreur avec une CVE du bulletin :", anssi_id)
            print(e)

    return alerts

def find_recipients_for_alert(alert, destinataires_par_produit):
    recipients = []
    editeur = str(alert.get("Editeur", "")).lower()
    produit = str(alert.get("Produit", "")).lower()
    titre = str(alert.get("Titre ANSSI", "")).lower()
    for keyword, emails in destinataires_par_produit.items():
        if keyword == "default":
            continue
        if keyword in editeur or keyword in produit or keyword in titre:
            recipients.extend(emails)
    if len(recipients) == 0:
        recipients = destinataires_par_produit["default"]
    return list(set(recipients))

def group_alerts_by_recipient(alerts, destinataires_par_produit):
    alerts_by_recipient = {}
    for alert in alerts:
        recipients = find_recipients_for_alert(alert, destinataires_par_produit)
        for email in recipients:
            if email not in alerts_by_recipient:
                alerts_by_recipient[email] = []
            alerts_by_recipient[email].append(alert)
    return alerts_by_recipient

def create_mail_text(email, alerts):
    subject = "Alerte ANSSI - nouvelles vulnérabilités détectées"
    body = ""
    body += f"To: {email}\n"
    body += f"Subject: {subject}\n\n"
    body += "Bonjour,\n\n"
    body += "De nouvelles vulnérabilités ANSSI concernent des produits surveillés.\n\n"
    for alert in alerts:
        body += "----------------------------------------\n"
        body += f"ID ANSSI : {alert.get('ID ANSSI')}\n"
        body += f"Titre : {alert.get('Titre ANSSI')}\n"
        body += f"Type : {alert.get('Type')}\n"
        body += f"Date : {alert.get('Date')}\n"
        body += f"CVE : {alert.get('CVE')}\n"
        body += f"Description de la CVE : {alert.get('Description CVE')}\n"
        body += f"CWE : {alert.get('CWE')}\n"
        body += f"Description CWE : {alert.get('Description CWE')}\n"
        body += f"Éditeur : {alert.get('Editeur')}\n"
        body += f"Produit : {alert.get('Produit')}\n"
        body += f"CVSS : {alert.get('CVSS prédite')}\n"
        body += f"EPSS : {alert.get('EPSS prédite')}\n"
        body += f"Lien CVE : {alert.get('Lien CVE')}\n"
        body += f"Lien solution : {alert.get('Lien solution')}\n\n"
    body += "Merci de vérifier ces vulnérabilités et de prioriser les actions nécessaires.\n"
    return body

def save_mail_to_txt(email, mail_text, output_dir="./mails"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    clean_email = email.replace("@", "_").replace(".", "_")
    file_path = f"{output_dir}/mail_{clean_email}.txt"
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(mail_text)
    return file_path


def check_rss_and_generate_mails(destinataires_par_produit, chemin_csv="./data/dataset_complet.csv"):
    new_ids = get_new_anssi_ids(chemin_csv=chemin_csv)
    print("Nouveaux IDs détectés :", new_ids)
    if len(new_ids) == 0:
        print("Aucun nouveau bulletin ANSSI détecté.")
        return []
    all_alerts = []
    for anssi_id in new_ids[:2]:
        print("Traitement du bulletin :", anssi_id)
        alerts = get_bulletin_cves(anssi_id)
        print("Nombre d'alertes récupérées :", len(alerts))
        all_alerts.extend(alerts)
    if len(all_alerts) > 0:
            df_new_alerts = pd.DataFrame(all_alerts)
            df_new_alerts_encoded = encode_dataset(df_new_alerts)
            df_new_alerts["CVSS prédite"] = calc_cvss_missing_values(df_new_alerts_encoded)
            df_new_alerts["EPSS prédite"] = calc_epss_missing_values(df_new_alerts_encoded)
            df_new_alerts["score de risque"] = calc_risk_score(df_new_alerts)
            if os.path.exists(chemin_csv):
                colonnes_existantes = pd.read_csv(chemin_csv, sep=";", nrows=0).columns
                df_new_alerts = df_new_alerts.reindex(columns=colonnes_existantes)
                df_new_alerts.to_csv(chemin_csv, mode='a', index=False, header=False, sep=";")
            else:
                df_new_alerts.to_csv(chemin_csv, mode='w', index=False, header=True, sep = ";")
    print("Nombre total d'alertes :", len(all_alerts))
    alerts_by_recipient = group_alerts_by_recipient(
        all_alerts,
        destinataires_par_produit
    )
    print("Destinataires trouvés :", list(alerts_by_recipient.keys()))
    created_files = []
    for email, alerts in alerts_by_recipient.items():
        mail_text = create_mail_text(email, alerts)
        file_path = save_mail_to_txt(email, mail_text)
        created_files.append(file_path)
    return created_files