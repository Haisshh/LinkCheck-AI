import os
import time
import zipfile
import requests
import pandas as pd
import urllib3
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from features import extract_features, FEATURE_NAMES

# Désactiver les alertes SSL pour les sites suspects
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chemins
PHISHING_CSV = "data/verified_online.csv"
SAFE_ZIP = "data/tranco_GV97K-1m.csv.zip"
OUTPUT_PATH = "data/scraped_data.csv"

RETRY_STRATEGY = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET"]),
)

_SESSION: requests.Session | None = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=8, pool_maxsize=32, max_retries=RETRY_STRATEGY)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LinkCheck-AI/1.2",
            "Accept-Language": "en-US,en;q=0.5",
        })
        _SESSION = session
    return _SESSION


def save_to_disk(results_list):
    """Fonction utilitaire pour sauvegarder les données et vider la mémoire"""
    if not results_list:
        return
    
    new_df = pd.DataFrame(results_list)
    if os.path.exists(OUTPUT_PATH):
        old_df = pd.read_csv(OUTPUT_PATH)
        combined_df = pd.concat([old_df, new_df], ignore_index=True)
        # Supprimer les doublons basés sur les caractéristiques communes pour éviter de polluer l'IA
        common_features = [f for f in FEATURE_NAMES if f in combined_df.columns]
        if common_features:
            combined_df = combined_df.drop_duplicates(subset=common_features)
        combined_df.to_csv(OUTPUT_PATH, index=False)
    else:
        os.makedirs("data", exist_ok=True)
        new_df.to_csv(OUTPUT_PATH, index=False)
    
    print(f"Sauvegarde effectuée sur {OUTPUT_PATH}. Mémoire libérée.")


def _fetch_html(full_url: str) -> str:
    try:
        response = _get_session().get(full_url, timeout=6, verify=False)
        return response.text if response.status_code == 200 else ""
    except requests.RequestException:
        return ""


def run_scraper(n_sites=50000):
    print(f"Lancement du méga-scraper (Objectif : {n_sites} sites)")
    
    # 1. Chargement des sources
    try:
        df_p = pd.read_csv(PHISHING_CSV)
        col_url = 'url' if 'url' in df_p.columns else df_p.columns[1] 
        urls_p = df_p[col_url].dropna().sample(min(n_sites, len(df_p))).tolist()
    except Exception as e:
        print(f"❌ Erreur phishing : {e}")
        urls_p = []

    try:
        with zipfile.ZipFile(SAFE_ZIP) as z:
            with z.open(z.namelist()[0]) as f:
                df_s = pd.read_csv(f, header=None)
                urls_s = df_s[1].sample(min(n_sites, len(df_s))).tolist()
    except Exception as e:
        print(f"Erreur safe : {e}")
        urls_s = []

    # 2. Fonction de traitement interne
    current_results = []
    
    def process_links(url_list, label, category_name):
        nonlocal current_results

        print(f"\n--- Début analyse : {category_name} ---")

        def crawl(url: str) -> tuple[str, str]:
            full_url = url if url.startswith("http") else "http://" + url
            return full_url, _fetch_html(full_url)

        max_workers = min(8, (os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, (full_url, html) in enumerate(executor.map(crawl, url_list), start=1):
                print(f"[{idx}/{len(url_list)}] {full_url[:50]}...", end=" ")
                if html:
                    print("✅")
                else:
                    print("❌")

                features = extract_features(full_url, html)
                features["label"] = label
                current_results.append(features)

                if len(current_results) >= 500:
                    save_to_disk(current_results)
                    current_results = []

                time.sleep(0.02)

    # 3. Lancement
    process_links(urls_p, 1, "PHISHING")
    process_links(urls_s, 0, "SAFE")

    # 4. Sauvegarde finale des derniers éléments restants
    if current_results:
        save_to_disk(current_results)
    
    print("\n✨ Mission terminée ! Ton dataset est prêt pour la version 1.2.")

if __name__ == "__main__":
    run_scraper(50000)