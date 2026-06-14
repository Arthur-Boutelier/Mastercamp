import os
from pathlib import Path
import requests
import json
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split

def create_dico_ANSSI(json_anssi):
    anssi_line = {}
    name = json_anssi["reference"]
    line_type = "Alerte" if "ALE" in name else "Avis"
    anssi_line["ID ANSSI"] = name
    anssi_line["Titre ANSSI"] = json_anssi["title"]
    anssi_line["Type"] =  line_type
    anssi_line["Date"] = json_anssi["revisions"][0]["revision_date"]
    tab_cve = json_anssi["cves"]
    return anssi_line, tab_cve
        
def create_dico_CVE(CVE_dict):
    nom_cve = CVE_dict["name"]
    json_cve_mitre = obtenir_json(nom_cve, "mitre")    
    while json_cve_mitre.get("cveMetadata", {}).get("state") == "REJECTED":
        remplacants = json_cve_mitre.get("containers", {}).get("cna", {}).get("replacedBy", [])
        if remplacants:
            nom_cve = remplacants[0]
            json_cve_mitre = obtenir_json(nom_cve, "mitre")
        else:
            break
    if "error" in json_cve_mitre:
        return None
    json_cve_first = obtenir_json(CVE_dict["name"], "first")
    cwe, description = get_cwe(json_cve_mitre)
    attack_vector, attack_complexity, privileges_required, user_interaction, confidentiality_impact, integrity_impact, availibity_impact, base_score, base_severity = get_cvss(json_cve_mitre)
    dico_cve = {
        "CVE" : nom_cve,
        "Description CVE" : get_description_cve(json_cve_mitre),
        "CVSS" : base_score,
        "Base severity" : base_severity,
        "Vecteur de l'attaque" : attack_vector,
        "Complexité de l'attaque" : attack_complexity,
        "Privileges requis" : privileges_required,
        "Action utilisateur" : user_interaction,
        "Impact sur la confidentialité" : confidentiality_impact,
        "Impact sur l'intégrité" : integrity_impact,
        "Impact sur la disponibilité" : availibity_impact,
        "CWE" : cwe,
        "Description CWE" : description,
        "EPSS" : get_epss(json_cve_first),
        "Lien CVE" : CVE_dict["url"],
        "Lien solution" : get_remediations(json_cve_mitre),
        "Editeur" : ", ".join([element.get("vendor", "Unknow") for element in json_cve_mitre["containers"]["cna"].get("affected", {})]),
        "Produit" : ",  ".join([element.get("product", "Unknow") for element in json_cve_mitre["containers"]["cna"].get("affected", {})]),
        "Versions affectées" : ", ".join([v['version'] for produit in json_cve_mitre['containers']['cna'].get("affected", {}) for v in produit.get('versions', []) if v.get('status') == 'affected']),    
    }
    return dico_cve

def Initialisation_df():
    lignes = []
    colonne_name = ["ID ANSSI", "Titre ANSSI", "Type", "Date", "CVE", "Description CVE", "CVSS", "Base severity", "Vecteur de l'attaque", "Complexité de l'attaque", "Privileges requis", "Action utilisateur", "Impact sur la confidentialité", "Impact sur l'intégrité", "Impact sur la disponibilité", "CWE", "EPSS", "Lien CVE", "Lien solution", "Description CWE", "Editeur", "Produit", "Versions affectées"]
    tab_alertes = os.listdir("./data/alertes")
    for fichier_anssi in tab_alertes:
        print(fichier_anssi)
        json_anssi = obtenir_json(fichier_anssi, "alerte")
        dico_anssi, tab_cve = create_dico_ANSSI(json_anssi)
        for cve in tab_cve:
            dico_cve = create_dico_CVE(cve)
            if dico_cve is not None:
                new_ligne = dico_anssi | dico_cve
                lignes.append(new_ligne)
    tab_avis = os.listdir("./data/Avis")
    for fichier_anssi in tab_avis:
        print(fichier_anssi)
        json_anssi = obtenir_json(fichier_anssi, "avis")
        dico_anssi, tab_cve = create_dico_ANSSI(json_anssi)
        for cve in tab_cve:
            dico_cve = create_dico_CVE(cve)
            if dico_cve is not None:
                new_ligne = dico_anssi | dico_cve
                lignes.append(new_ligne)
    df = pd.DataFrame(lignes)
    df = df.reindex(columns=colonne_name)
    return df

def get_description_cve(json_cve_mitre):
    descriptions_list = json_cve_mitre.get("containers", {}).get("cna", {}).get("descriptions", [])    
    for desc in descriptions_list:
        if desc.get("lang") == "en":
            return desc.get("value", "Aucune description")
    if descriptions_list:
        return descriptions_list[0].get("value", "Aucune description")        
    return "Aucune description"


    

def obtenir_json(fichier_name, type_recherche):
    dico_url = {
        "first" : f"https://api.first.org/data/v1/epss?cve={fichier_name}",
        "mitre" : f"https://cveawg.mitre.org/api/cve/{fichier_name}",
        "alerte" : f"https://www.cert.ssi.gouv.fr/alerte/{fichier_name}/json/",
        "avis" : f"https://www.cert.ssi.gouv.fr/avis/{fichier_name}/json/"
    }
    dico_path = {
        "first" : Path("./data/first"),
        "mitre" : Path("./data/mitre"),
        "alerte" : Path("./data/alertes"),
        "avis" : Path("./data/avis")
    }
    if  not dico_path[type_recherche].is_dir() or fichier_name not in os.listdir(dico_path[type_recherche]):
        response = requests.get(dico_url[type_recherche])
        json_fichier = response.json()
    else:
        f = open(f'{dico_path[type_recherche]}/{fichier_name}', 'r')
        json_fichier = json.load(f)
        f.close()
    return json_fichier
        
def get_epss(json_cve_first):
    epss_data = json_cve_first.get("data", [])
    if epss_data:
        return epss_data[0]["epss"]
    else:
        return None

def get_cwe(json_cve_mitre):
    problemtype_list = json_cve_mitre.get("containers", {}).get("cna", {}).get("problemTypes", [])  
    cwes = []
    descriptions = []    
    for pt in problemtype_list:
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            cwe_desc = desc.get("description")            
            if cwe_id and cwe_id not in cwes:
                cwes.append(cwe_id)
            if cwe_desc and cwe_desc not in descriptions:
                descriptions.append(cwe_desc)                
    final_cwe = ", ".join(cwes) if cwes else None    
    final_desc = " | ".join(descriptions) if descriptions else None
    
    return final_cwe, final_desc

def get_cvss(json_cve_mitre):
    metrics = json_cve_mitre.get("containers", {}).get("cna", {}).get("metrics", [])  
    attack_complexity, attack_vector, privileges_required, user_interaction, confidentiality_impact, integrity_impact, availibity_impact, base_score, base_severity = (None for _ in range(9))    
    trad_av = {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'}
    trad_ac = {'L': 'LOW', 'H': 'HIGH'}
    trad_pr = {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
    trad_ui = {'N': 'NONE', 'R': 'REQUIRED'}
    trad_cia = {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}

    if metrics:
        for dico in metrics:
            cvss_key = next((cle for cle in dico if "cvss" in cle.lower()), None)
            if cvss_key:
                cvss_data = dico[cvss_key]
                base_score = cvss_data.get("baseScore")
                base_severity = cvss_data.get("baseSeverity")
                vector_string = cvss_data.get("vectorString", "")                
                if vector_string:
                    elements = vector_string.split('/')                    
                    for element in elements:
                        if ":" not in element:
                            continue
                        cle, valeur = element.split(':')
                        if cle == 'AV': attack_vector = trad_av.get(valeur, valeur)
                        elif cle == 'AC': attack_complexity = trad_ac.get(valeur, valeur)
                        elif cle == 'PR': privileges_required = trad_pr.get(valeur, valeur)
                        elif cle == 'UI': user_interaction = trad_ui.get(valeur, valeur)
                        elif cle == 'C': confidentiality_impact = trad_cia.get(valeur, valeur)
                        elif cle == 'I': integrity_impact = trad_cia.get(valeur, valeur)
                        elif cle == 'A': availibity_impact = trad_cia.get(valeur, valeur)
                break 
                
    return attack_vector, attack_complexity, privileges_required, user_interaction, confidentiality_impact, integrity_impact, availibity_impact, base_score, base_severity
                
def get_remediations(json_cve_mitre):
    cna = json_cve_mitre.get("containers", {}).get("cna", {})
    liens_correctifs = []    
    for ref in cna.get("references", []):
        tags = ref.get("tags", [])
        url = ref.get("url")
        if url and ("patch" in tags or "vendor-advisory" in tags or "mitigation" in tags):
            liens_correctifs.append(url)            
    if not liens_correctifs and cna.get("references"):
        premier_lien = cna.get("references")[0].get("url")
        if premier_lien:
            liens_correctifs.append(premier_lien)
    str_liens = " ".join(liens_correctifs) if liens_correctifs else "Aucun lien de patch spécifique"
    
    return str_liens
        


    
    
    
        