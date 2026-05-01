import os
import zipfile
import pandas as pd
import joblib
import time
from flask import Flask, request, render_template, jsonify
from features import extract_features, FEATURE_NAMES

app = Flask(__name__)

# --- CONFIGURATION ---
MODEL_PATH = "model.pkl"
TRANCO_ZIP = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB = {}

# Système de limitation (Anti-Spam simple)
last_requests = {}

# 1. Chargement du Modèle
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ Modèle IA chargé.")
    except:
        print("❌ Erreur chargement modèle.")

# 2. Chargement Tranco
def load_tranco():
    global REPUTATION_DB
    if os.path.exists(TRANCO_ZIP):
        try:
            with zipfile.ZipFile(TRANCO_ZIP) as z:
                with z.open(z.namelist()[0]) as f:
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco : {len(REPUTATION_DB)} sites.")
        except Exception as e:
            print(f"❌ Erreur Tranco : {e}")
    else:
        print("⚠️ Fichier Tranco manquant !")

load_tranco()

def get_domain_rank(url):
    """Extraction ultra-robuste du domaine"""
    from urllib.parse import urlparse
    try:
        # Nettoyer l'URL
        clean_url = url.split('#')[0].split('?')[0] # Enlever les fragments (#) et paramètres (?)
        netloc = urlparse(clean_url).netloc or urlparse("http://"+clean_url).netloc
        domain = netloc.replace('www.', '').lower()
        
        # Test 1: m.hoyolab.com
        if domain in REPUTATION_DB: return REPUTATION_DB[domain]
        
        # Test 2: hoyolab.com (si c'est un sous-domaine)
        parts = domain.split('.')
        if len(parts) > 2:
            root = ".".join(parts[-2:])
            if root in REPUTATION_DB: return REPUTATION_DB[root]
    except:
        return None
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # --- SÉCURITÉ ANTI-SPAM ---
    user_ip = request.remote_addr
    now = time.time()
    if user_ip in last_requests and now - last_requests[user_ip] < 2: # Max 1 requête toutes les 2 sec
        return jsonify({"verdict": "suspect", "score": 0, "reason_text": "Trop de requêtes ! Attendez un peu."}), 429
    last_requests[user_ip] = now

    try:
        data = request.get_json()
        url = data.get('url', '').lower()
        
        # --- FILTRE DE SECOURS (HARD-WHITELIST) ---
        # Si l'IA bug, on force les sites connus ici
        trusted_keywords = ['hoyolab.com', 'mihoyo.com', 'google.com', 'discord.com', 'github.com']
        if any(k in url for k in trusted_keywords):
            return jsonify({
                "verdict": "safe", "score": 0, "ml_score": 0, "analyzed_host": url,
                "rank": 1, "reason_text": "Site de confiance certifié (Protection V1.2)"
            })

        # --- ANALYSE IA ---
        features = extract_features(url, "")
        features_df = pd.DataFrame([features])[FEATURE_NAMES]
        probabilities = model.predict_proba(features_df)[0]
        ml_score = round(probabilities[1] * 100)

        # --- LOGIQUE TRANCO ---
        rank = get_domain_rank(url)
        verdict = "safe"
        final_score = ml_score
        
        if rank:
            verdict = "safe"
            final_score = 0
            reason = f"Vérifié par Tranco (Rang #{rank})"
        else:
            if ml_score > 70: verdict = "dangerous"
            elif ml_score > 30: verdict = "suspect"
            reason = "Analyse IA : Domaine non répertorié."

        return jsonify({
            "verdict": verdict, "score": final_score, "ml_score": ml_score,
            "analyzed_host": url, "rank": rank, "reason_text": reason
        })

    except Exception as e:
        return jsonify({"error": str(e), "verdict": "suspect"}), 500