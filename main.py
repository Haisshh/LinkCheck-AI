import os
import zipfile
import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify
from features import extract_features

app = Flask(__name__)

# --- CONFIGURATION V1.2 ---
MODEL_PATH = "model.pkl"
TRANCO_ZIP = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB = {}

# 1. Chargement du Modèle IA
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Modèle IA chargé avec succès.")
except Exception as e:
    print(f"❌ Erreur chargement modèle : {e}")
    model = None

# 2. Chargement de la base Tranco en mémoire (RAM)
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    # On charge les 800 000 premiers pour un équilibre RAM/Performance
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco v1.2 chargée : {len(REPUTATION_DB)} domaines indexés.")
        except Exception as e:
            print(f"⚠️ Erreur lecture Tranco : {e}")
    else:
        print("⚠️ Fichier Tranco introuvable dans data/. La whitelist sera inactive.")

# Lancement du chargement au démarrage du serveur
load_tranco()

def get_domain_rank(url):
    """Extrait le domaine et vérifie son rang Tranco"""
    from urllib.parse import urlparse
    try:
        domain = urlparse(url).netloc.replace('www.', '').lower()
        # Test du domaine exact
        if domain in REPUTATION_DB:
            return REPUTATION_DB[domain]
        # Test du domaine parent (ex: m.hoyolab.com -> hoyolab.com)
        parts = domain.split('.')
        if len(parts) > 2:
            parent_domain = ".".join(parts[-2:])
            return REPUTATION_DB.get(parent_domain)
    except:
        return None
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return render_template('index.html', error="Veuillez entrer une URL.")

    # --- ÉTAPE 1 : IA ---
    # Extraction des caractéristiques (on passe html="" car on ne scrape pas en temps réel ici)
    features = extract_features(url, "")
    features_df = pd.DataFrame([features])
    
    # Calcul de la probabilité de phishing (0 à 100)
    proba_phishing = model.predict_proba(features_df)[0][1] * 100

    # --- ÉTAPE 2 : RÉPUTATION (TRANCO) ---
    rank = get_domain_rank(url)

    # --- ÉTAPE 3 : LOGIQUE DE DÉCISION v1.2 ---
    status = "SAFE"
    final_score = proba_phishing
    reason = ""

    if rank is not None and rank <= 800000:
        # Le site est connu (Top 800k)
        if proba_phishing < 95:
            status = "SAFE"
            final_score = proba_phishing * 0.1 # On réduit l'importance de l'IA
            reason = f"Domaine de confiance vérifié (Tranco #{rank})."
        else:
            # Cas rare : un site connu mais l'URL est vraiment bizarre (ex: redirection suspecte)
            status = "SUSPICIOUS"
            reason = f"Domaine connu (#{rank}), mais l'URL présente des anomalies critiques."
    else:
        # Le site est inconnu (IA seule juge)
        if proba_phishing > 80:
            status = "DANGEREUX"
            reason = "L'IA a détecté des caractéristiques typiques de phishing."
        elif proba_phishing > 40:
            status = "SUSPICIOUS"
            reason = "Site non répertorié présentant des éléments suspects."
        else:
            status = "SAFE"
            reason = "Site inconnu mais l'analyse structurelle est propre."

    return render_template('result.html', 
                           url=url, 
                           status=status, 
                           score=round(final_score, 1), 
                           reason=reason,
                           rank=rank)