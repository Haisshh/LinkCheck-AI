import os
import zipfile
import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify
from features import extract_features, FEATURE_NAMES

app = Flask(__name__)

# CONFIGURATION
MODEL_PATH = "model.pkl"
TRANCO_ZIP = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB = {}

# 1. Chargement du Modèle
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ Modèle IA synchronisé et chargé.")
    except Exception as e:
        print(f"❌ Erreur modèle: {e}")

# 2. Chargement Tranco
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Tranco v1.2 chargé.")
        except:
            print("❌ Erreur Tranco.")
load_tranco()

def get_domain_info(url):
    from urllib.parse import urlparse
    try:
        netloc = urlparse(url).netloc or urlparse("http://"+url).netloc
        domain = netloc.replace('www.', '').lower()
        rank = REPUTATION_DB.get(domain)
        if not rank:
            parts = domain.split('.')
            if len(parts) > 2:
                rank = REPUTATION_DB.get(".".join(parts[-2:]))
        return domain, rank
    except:
        return None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url: return jsonify({"error": "URL vide"}), 400

        domain, rank = get_domain_info(url)
        
        # --- FILTRE DE CONFIANCE (SÉCURITÉ LYCÉE/HOYOLAB) ---
        if any(x in url.lower() for x in ['.gouv.fr', '.ac-', 'lycee-', 'hoyolab.com', 'mihoyo.com']):
            return jsonify({
                "verdict": "safe", "score": 0, "ml_score": 0, "analyzed_host": domain,
                "rank": "Certifié", "reason_text": "Site institutionnel ou certifié Safe.",
                "reasons": [{"text": "Source officielle reconnue", "severity": "info", "points": 0}]
            })

        # --- ANALYSE IA ---
        features = extract_features(url, html_content="")
        # On force l'ordre des colonnes EXACT de FEATURE_NAMES
        features_df = pd.DataFrame([features])[FEATURE_NAMES]
        
        ml_proba = model.predict_proba(features_df)[0][1] * 100
        ml_score = round(ml_proba)

        # --- DÉCISION TRANCO ---
        if rank and rank <= 800000:
            verdict = "safe"
            final_score = round(ml_score * 0.05)
            reason = f"Domaine de confiance (Tranco #{rank})"
        else:
            final_score = ml_score
            if final_score > 75: verdict = "dangerous"
            elif final_score > 40: verdict = "suspect"
            else: verdict = "safe"
            reason = "Analyse IA : domaine non répertorié."

        return jsonify({
            "verdict": verdict, "score": final_score, "ml_score": ml_score,
            "analyzed_host": domain, "rank": rank, "reason_text": reason,
            "reasons": [{"text": reason, "severity": "info" if verdict=="safe" else "warning", "points": 0}]
        })

    except Exception as e:
        return jsonify({"error": str(e), "verdict": "suspect"}), 500