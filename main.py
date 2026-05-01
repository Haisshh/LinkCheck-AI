import os
import zipfile
import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify
from features import extract_features, FEATURE_NAMES

app = Flask(__name__)

MODEL_PATH = "model.pkl"
TRANCO_ZIP = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB = {}

# Chargement du Modèle
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ Modèle chargé avec succès.")
    except Exception as e:
        print(f"❌ Erreur modèle : {e}")

# Chargement Tranco
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print("✅ Tranco chargé.")
        except: print("❌ Erreur Tranco.")
load_tranco()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url: return jsonify({"error": "URL vide"}), 400

        # --- WHITELIST PRIORITAIRE (Lycée, HoYoLAB) ---
        trusted = ['.gouv.fr', '.ac-', 'lycee-', 'hoyolab.com', 'mihoyo.com']
        if any(p in url.lower() for p in trusted):
            return jsonify({
                "verdict": "safe", "score": 0, "ml_score": 0, "analyzed_host": url,
                "rank": "Certifié", "reason_text": "Source officielle ou de confiance.",
                "reasons": [{"text": "Domaine certifié", "severity": "info", "points": 0}]
            })

        # --- ANALYSE IA ---
        raw_features = extract_features(url, "")
        
        # TRANSFORMATION EN DATAFRAME + FILTRE STRICT DES COLONNES
        # On ne garde QUE les colonnes présentes dans FEATURE_NAMES et on les trie
        features_df = pd.DataFrame([raw_features])
        features_df = features_df[FEATURE_NAMES] # C'est ici que l'ordre est fixé
        
        ml_score = round(model.predict_proba(features_df)[0][1] * 100)

        # --- VERIFICATION TRANCO ---
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace('www.', '').lower()
        rank = REPUTATION_DB.get(domain) or REPUTATION_DB.get(".".join(domain.split('.')[-2:]))

        if rank and rank <= 800000:
            verdict, final_score = "safe", round(ml_score * 0.05)
            reason = f"Vérifié par Tranco (Rang #{rank})"
        else:
            final_score = ml_score
            verdict = "dangerous" if ml_score > 75 else "suspect" if ml_score > 40 else "safe"
            reason = "Analyse IA sur domaine inconnu."

        return jsonify({
            "verdict": verdict, "score": final_score, "ml_score": ml_score,
            "analyzed_host": domain, "rank": rank, "reason_text": reason,
            "reasons": [{"text": reason, "severity": "info" if verdict=="safe" else "warning", "points": 0}]
        })

    except Exception as e:
        print(f"DEBUG: {str(e)}") # Pour voir l'erreur exacte dans ta console
        return jsonify({"error": str(e), "verdict": "suspect"}), 500