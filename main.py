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
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("✅ Modèle IA v1.2 chargé avec succès.")
    else:
        print("❌ Erreur : model.pkl introuvable à la racine.")
        model = None
except Exception as e:
    print(f"❌ Erreur lors du chargement du modèle : {e}")
    model = None

# 2. Chargement de la base de réputation Tranco
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    # On charge les 800 000 premiers domaines
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco v1.2 chargée ({len(REPUTATION_DB)} domaines).")
        except Exception as e:
            print(f"⚠️ Erreur lecture Tranco : {e}")
    else:
        print(f"⚠️ Fichier {TRANCO_ZIP} introuvable. Whitelist inactive.")

# Lancement au démarrage
load_tranco()

def get_domain_rank(url):
    """Extrait le domaine et vérifie son rang Tranco"""
    from urllib.parse import urlparse
    try:
        netloc = urlparse(url).netloc or urlparse("http://"+url).netloc
        domain = netloc.replace('www.', '').lower()
        
        # Test direct
        if domain in REPUTATION_DB:
            return REPUTATION_DB[domain]
        
        # Test domaine parent (ex: m.hoyolab.com -> hoyolab.com)
        parts = domain.split('.')
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            return REPUTATION_DB.get(parent)
    except:
        return None
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # On récupère les données JSON envoyées par index.html
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL manquante"}), 400
        
        url = data['url']
        
        # 1. ANALYSE IA
        if model is None:
            return jsonify({"error": "Modèle IA non chargé sur le serveur"}), 500

        features = extract_features(url, "")
        features_df = pd.DataFrame([features])
        
        # Probabilités [Sûr, Phishing]
        probabilities = model.predict_proba(features_df)[0]
        ml_score = round(probabilities[1] * 100)

        # 2. VÉRIFICATION RÉPUTATION
        rank = get_domain_rank(url)

        # 3. LOGIQUE DE DÉCISION HYBRIDE
        verdict = "safe"
        final_score = ml_score
        reason_text = ""

        if rank and rank <= 800000:
            if ml_score < 95:
                verdict = "safe"
                final_score = round(ml_score * 0.1) # Réduction drastique du risque
                reason_text = f"Site certifié (Tranco #{rank})."
            else:
                verdict = "suspect"
                reason_text = f"Domaine connu (#{rank}), mais l'URL est inhabituelle."
        else:
            if ml_score > 75: 
                verdict = "dangerous"
                reason_text = "L'IA détecte des motifs de phishing confirmés."
            elif ml_score > 35: 
                verdict = "suspect"
                reason_text = "Site inconnu présentant des éléments suspects."
            else:
                verdict = "safe"
                reason_text = "Analyse structurelle propre (domaine non classé)."

        # 4. RÉPONSE JSON (Obligatoire pour éviter l'erreur Unexpected Token)
        return jsonify({
            "verdict": verdict,
            "score": final_score,
            "ml_score": ml_score,
            "analyzed_host": url,
            "rank": rank,
            "reason_text": reason_text,
            "reasons": [
                {"text": reason_text, "severity": "info" if verdict == "safe" else "warning", "points": 0}
            ]
        })

    except Exception as e:
        # En cas de crash, on renvoie l'erreur en JSON plutôt que du HTML
        print(f"💥 ERREUR SERVEUR : {e}")
        return jsonify({
            "error": str(e),
            "verdict": "suspect",
            "score": 50,
            "reason_text": "Erreur interne lors de l'analyse."
        }), 500
