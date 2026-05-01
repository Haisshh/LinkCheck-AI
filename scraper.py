import pandas as pd
import zipfile
import requests
import os
import urllib3
from features import extract_features, FEATURE_NAMES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chemins vers tes fichiers
PHISHING_CSV = "data/verified_online.csv"  # Ton nouveau fichier
SAFE_ZIP = "data/tranco_GV97K-1m.csv.zip"
OUTPUT_PATH = "data/scraped_data.csv"

def run_scraper(n_sites=50):
    print(f"🚀 Préparation du dataset avec verified_online.csv...")
    results = []

    # 1. Chargement des URLs de Phishing depuis ton CSV
    try:
        df_p = pd.read_csv(PHISHING_CSV)
        # On cherche la colonne qui contient l'URL (souvent nommée 'url' dans PhishTank)
        col_url = 'url' if 'url' in df_p.columns else df_p.columns[1] 
        urls_p = df_p[col_url].dropna().sample(min(n_sites, len(df_p))).tolist()
        print(f"✅ {len(urls_p)} URLs de phishing chargées depuis ton fichier.")
    except Exception as e:
        print(f"❌ Erreur lecture phishing : {e}")
        urls_p = []

    # 2. Chargement des URLs Safe depuis le ZIP
    try:
        with zipfile.ZipFile(SAFE_ZIP, 'r') as z:
            csv_file = [n for n in z.namelist() if n.endswith('.csv')][0]
            df_s = pd.read_csv(z.open(csv_file), header=None, nrows=1000)
            urls_s = df_s[1].dropna().sample(min(n_sites, len(df_s))).tolist()
            print(f"✅ {len(urls_s)} URLs safe chargées.")
    except Exception as e:
        print(f"❌ Erreur Safe : {e}")
        urls_s = []

    # 3. Fonction de Scraping (Visite des sites)
    def process(urls, label):
        for url in urls:
            full_url = url if '://' in url else 'http://' + url
            print(f"📡 [{'Phish' if label==1 else 'Safe'}] {url[:40]}...", end=" ", flush=True)
            html = None
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                r = requests.get(full_url, timeout=5, verify=False, headers=headers)
                if r.status_code == 200:
                    html = r.text
                    print("✅ HTML")
                else:
                    print(f"⚠️ {r.status_code}")
            except:
                print("❌ Mort")
            
            # Extraction des caractéristiques URL + HTML
            f = extract_features(full_url, html)
            f['label'] = label
            results.append(f)

    # Lancement de l'analyse
    process(urls_p, 1)
    process(urls_s, 0)

    # 4. Sauvegarde finale pour l'entraînement
    if results:
        os.makedirs("data", exist_ok=True)
        new_df = pd.DataFrame(results)
        
        if os.path.exists(OUTPUT_PATH):
            # On charge l'ancien, on ajoute le nouveau
            old_df = pd.read_csv(OUTPUT_PATH)
            combined_df = pd.concat([old_df, new_df], ignore_index=True)
            # On supprime les doublons au cas où on aurait scanné deux fois le même site
            combined_df = combined_df.drop_duplicates(subset=FEATURE_NAMES)
            combined_df.to_csv(OUTPUT_PATH, index=False)
            print(f"\n✅ Mémoire mise à jour ! Total : {len(combined_df)} sites dans {OUTPUT_PATH}")
        else:
            new_df.to_csv(OUTPUT_PATH, index=False)
            print(f"\n🎉 Premier fichier créé avec {len(new_df)} sites.")

if __name__ == "__main__":
    run_scraper(3000) 