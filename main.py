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

# 1. Chargement du Modèle IA (model.pkl)
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
                    # On charge 800k lignes pour protéger les sites légitimes
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=800000)
                    REPUTATION_DB = dict(zip(df['domain'], df['rank']))
            print(f"✅ Base Tranco chargée : {len(REPUTATION_DB)} domaines indexés.")
        except Exception as e:
            print(f"⚠️ Erreur lecture Tranco : {e}")
    else:
        print("⚠️ Fichier data/tranco_GV97K-1m.csv.zip introuvable. Whitelist inactive.")

# On pré-charge les données au lancement du serveur
load_tranco()

def get_domain_rank(url):
    """Extrait le domaine racine et cherche son rang Tranco"""
    from urllib.parse import urlparse
    try:
        # Nettoyage (m.hoyolab.com -> hoyolab.com)
        netloc = urlparse(url).netloc or urlparse("http://"+url).netloc
        domain = netloc.replace('www.', '').lower()
        
        # Test direct
        if domain in REPUTATION_DB:
            return REPUTATION_DB[domain]
        
        # Test domaine parent
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
    # Ton index.html envoie du JSON, on le récupère ici
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL manquante"}), 400
    
    url = data['url']
    
    # --- ANALYSE IA ---
    # On passe html="" car l'analyse en direct ne scrape pas (pour la rapidité)
    features = extract_features(url, "")
    features_df = pd.DataFrame([features])
    
    # Calcul de la probabilité via le modèle Scikit-Learn
    # proba[0] = safe, proba[1] = phishing
    if model:
        probabilities = model.predict_proba(features_df)[0]
        ml_score = round(probabilities[1] * 100)
    else:
        ml_score = 50 # Valeur par défaut si modèle HS

    # --- VÉRIFICATION RÉPUTATION (TRANCO) ---
    rank = get_domain_rank(url)

    # --- LOGIQUE DE DÉCISION HYBRIDE V1.2 ---
    verdict = "safe"
    final_score = ml_score
    reason_text = ""

    if rank and rank <= 800000:
        # Site connu : On devient très indulgent
        if ml_score < 95:
            verdict = "safe"
            final_score = round(ml_score * 0.1) # On divise le risque par 10
            reason_text = f"Site de confiance identifié (Rang mondial Tranco #{rank})."
        else:
            # Cas extrême : site connu mais URL vraiment malveillante
            verdict = "suspect"
            reason_text = f"Domaine connu (#{rank}), mais l'URL présente des signes d'anomalie."
    else:
        # Site inconnu : L'IA est seule juge
        if ml_score > 75:
            verdict = "dangerous"
            reason_text = "L'IA détecte une forte ressemblance avec des sites de phishing."
        elif ml_score > 35:
            verdict = "suspect"
            reason_text = "Site non répertorié présentant des caractéristiques suspectes."
        else:
            verdict = "safe"
            reason_text = "Analyse structurelle propre sur un domaine non répertorié."

    # On renvoie les données attendues par ton JavaScript dans index.html
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
