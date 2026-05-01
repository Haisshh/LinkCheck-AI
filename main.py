import os
import zipfile
import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify
# On importe FEATURE_NAMES pour garantir l'ordre des colonnes
from features import extract_features, FEATURE_NAMES

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
        print("❌ Erreur : model.pkl introuvable.")
        model = None
except Exception as e:
    print(f"❌ Erreur lors du chargement du modèle : {e}")
    model = None

# 2. Chargement de la base de réputation Tranco (Top 800k)
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    # On charge 800 000 lignes pour une protection maximale
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco v1.2 chargée : {len(REPUTATION_DB)} domaines indexés.")
        except Exception as e:
            print(f"⚠️ Erreur lecture Tranco : {e}")
    else:
        print("⚠️ Fichier Tranco introuvable. Whitelist inactive.")

load_tranco()

def get_domain_rank(url):
    """Extrait le domaine et vérifie son rang Tranco"""
    from urllib.parse import urlparse
    try:
        netloc = urlparse(url).netloc or urlparse("http://"+url).netloc
        domain = netloc.replace('www.', '').lower()
        if domain in REPUTATION_DB:
            return REPUTATION_DB[domain]
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
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL manquante"}), 400
        
        url = data['url']
        
        # --- ÉTAPE 1 : EXTRACTION ET ALIGNEMENT DES FEATURES ---
        if model is None:
            return jsonify({"error": "Modèle non chargé"}), 500

        # Extraction via ton script features.py
        features = extract_features(url, "")
        
        # CRUCIAL : On transforme en DataFrame ET on force l'ordre exact des colonnes 
        # tel qu'il était lors de l'entraînement grâce à FEATURE_NAMES
        features_df = pd.DataFrame([features])[FEATURE_NAMES]
        
        # Prédiction
        probabilities = model.predict_proba(features_df)[0]
        ml_score = round(probabilities[1] * 100)

        # --- ÉTAPE 2 : RÉPUTATION (TRANCO) ---
        rank = get_domain_rank(url)

        # --- ÉTAPE 3 : LOGIQUE DE DÉCISION v1.2 ---
        verdict = "safe"
        final_score = ml_score
        reason_text = ""

        if rank and rank <= 800000:
            # Si le site est dans le Top 800k, on bypass l'IA (sauf si score > 98%)
            if ml_score < 98:
                verdict = "safe"
                final_score = round(ml_score * 0.05) # Score quasi nul
                reason_text = f"Site de confiance (Tranco #{rank})."
            else:
                verdict = "suspect"
                reason_text = f"Domaine connu (#{rank}), mais structure d'URL suspecte."
        else:
            # Site inconnu : L'IA décide
            if ml_score > 75:
                verdict = "dangerous"
                reason_text = "L'IA détecte des motifs de phishing confirmés."
            elif ml_score > 35:
                verdict = "suspect"
                reason_text = "Site non répertorié présentant des signes suspects."
            else:
                verdict = "safe"
                reason_text = "Analyse structurelle propre (domaine inconnu)."

        # --- ÉTAPE 4 : RÉPONSE JSON ---
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
        print(f"💥 ERREUR : {e}")
        return jsonify({"error": str(e), "verdict": "suspect"}), 500