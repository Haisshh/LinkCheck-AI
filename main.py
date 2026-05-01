import os
import zipfile
import pandas as pd
import joblib
import time
from flask import Flask, request, render_template, jsonify
from features import extract_features, FEATURE_NAMES

app = Flask(__name__)

# --- CONFIGURATION V1.2 ---
MODEL_PATH = "model.pkl"
TRANCO_ZIP = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB = {}

# 1. Chargement du Modèle IA
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ Modèle IA v1.2 chargé.")
    except Exception as e:
        print(f"❌ Erreur modèle : {e}")

# 2. Chargement Tranco (Top 800 000)
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco : {len(REPUTATION_DB)} domaines indexés.")
        except Exception as e:
            print(f"❌ Erreur Tranco : {e}")
    else:
        print("⚠️ data/tranco_GV97K-1m.csv.zip introuvable.")

load_tranco()

# --- FONCTIONS DE VÉRIFICATION ---

def get_domain_rank(url):
    from urllib.parse import urlparse
    try:
        clean_url = url.split('#')[0].split('?')[0]
        netloc = urlparse(clean_url).netloc or urlparse("http://"+clean_url).netloc
        domain = netloc.replace('www.', '').lower()
        if domain in REPUTATION_DB: return REPUTATION_DB[domain]
        parts = domain.split('.')
        if len(parts) > 2:
            root = ".".join(parts[-2:])
            if root in REPUTATION_DB: return REPUTATION_DB[root]
    except: return None
    return None

def is_trusted_institution(url):
    """Protection pour les sites éducatifs (.fr) et officiels"""
    url = url.lower()
    trusted_extensions = ['.gouv.fr', '.ac-', 'edulib.fr', 'education.fr']
    if any(ext in url for ext in trusted_extensions): return True
    if "lycee-" in url and url.endswith(".fr"): return True
    # Hard-whitelist pour les géants souvent faux-positifs
    hard_white = ['hoyolab.com', 'mihoyo.com', 'discord.com', 'google.com']
    if any(site in url for site in hard_white): return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url: return jsonify({"error": "Lien vide"}), 400

        # 1. Priorité absolue : Whitelist Institutionnelle
        if is_trusted_institution(url):
            return jsonify({
                "verdict": "safe", "score": 0, "ml_score": 0, 
                "analyzed_host": url, "rank": "Certifié",
                "reason_text": "Site institutionnel ou de confiance certifié.",
                "reasons": [{"text": "Domaine officiel reconnu", "severity": "info", "points": 0}]
            })

        # 2. Analyse IA (avec correction de l'ordre des colonnes)
        features = extract_features(url, "")
        features_df = pd.DataFrame([features])[FEATURE_NAMES]
        proba = model.predict_proba(features_df)[0][1] * 100
        ml_score = round(proba)

        # 3. Vérification Tranco
        rank = get_domain_rank(url)

        # 4. Décision Hybride
        verdict = "safe"
        final_score = ml_score
        
        if rank:
            # Site connu : On divise le risque par 20
            final_score = round(ml_score * 0.05)
            verdict = "safe" if final_score < 30 else "suspect"
            reason = f"Vérifié par Tranco (Rang #{rank})"
        else:
            if ml_score > 75: verdict = "dangerous"
            elif ml_score > 40: verdict = "suspect"
            reason = "Analyse IA sur domaine non répertorié."

        return jsonify({
            "verdict": verdict, "score": final_score, "ml_score": ml_score,
            "analyzed_host": url, "rank": rank, "reason_text": reason,
            "reasons": [{"text": reason, "severity": "info" if verdict=="safe" else "warning", "points": 0}]
        })

    except Exception as e:
        print(f"💥 Erreur : {e}")
        return jsonify({"error": str(e), "verdict": "suspect"}), 500