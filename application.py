import time
from alert import check_rss_and_generate_mails
destinataires_par_produit = {
    "microsoft": ["soc.microsoft@example.com", "admin.microsoft@example.com"],
    "azure": ["cloud.security@example.com"],
    "apache": ["web.security@example.com"],
    "linux": ["linux.admin@example.com"],
    "cisco": ["network.security@example.com"],
    "ivanti": ["soc.ivanti@example.com"],
    "default": ["soc.general@example.com"]
}

if __name__ == "__main__":
    print("Démarrage du moniteur d'alertes ANSSI...")
    while True:
        #try:
        print("\n--- Nouvelle vérification du flux RSS ---")
        check_rss_and_generate_mails(destinataires_par_produit)
        """except Exception as e:
            print(f"Erreur lors de la vérification : {e}")"""
            
        print("Mise en veille... Prochaine vérification dans 10 minutes.")
        
        time.sleep(600)