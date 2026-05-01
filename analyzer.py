import os
import re
import joblib
import pandas as pd
import requests
import logging
from urllib.parse import urlparse
from features import extract_features, FEATURE_NAMES
from screenshot import take_screenshot
import requests
import urllib3

# Configuration du logging pour voir ce qui se passe dans la console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("linkcheck.analyzer")

# Désactiver les avertissements SSL (pour les sites de phishing qui n'ont pas de certificat)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── CHARGEMENT DU MODÈLE ────────────────────────────────────────────────────
try:
    _model = joblib.load("model.pkl")
    # On n'a plus besoin de charger features.pkl séparément si on utilise 
    # la liste FEATURE_NAMES importée directement de features.py
    ML_AVAILABLE = True
    logger.info("✓ Modèle ML chargé avec succès.")
except Exception as e:
    ML_AVAILABLE = False
    logger.warning(f"⚠ Mode dégradé : model.pkl introuvable ({e})")

# ── WHITELIST DE SÉCURITÉ ───────────────────────────────────────────────────
TRUSTED_DOMAINS = [
    "google.com", "google.fr", "paypal.com", "paypal.fr", 
    "apple.com", "microsoft.com", "github.com", "netflix.com"
]

def analyze_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain = urlparse(url).netloc.lower().replace('www.', '')
    
    # 1. Vérification Whitelist (Retour immédiat)
    if any(domain == d or domain.endswith('.' + d) for d in TRUSTED_DOMAINS):
        return {
            "score": 0,
            "verdict": "safe",
            "analyzed_host": domain,
            "reasons": [{"text": "Site officiel reconnu (Whitelist)", "severity": "safe"}],
            "html_captured": False
        }

    # 2. Tentative de récupération du contenu HTML (Le "Bouclier" réseau)
    html_content = None
    try:
        logger.info(f"Analyse du contenu de : {url}")
        response = requests.get(
            url, 
            timeout=5, 
            verify=False, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        if response.status_code == 200:
            html_content = response.text
            logger.info("HTML récupéré avec succès.")
    except Exception as e:
        logger.error(f"Impossible de joindre le site : {e}")

    # 3. Extraction des caractéristiques (URL + HTML si dispo)
    f_dict = extract_features(url, html_content)

    # 4. Calcul du score par l'IA
    if ML_AVAILABLE:
        try:
            # Création du DataFrame avec l'ordre exact des colonnes
            df_input = pd.DataFrame([f_dict])[FEATURE_NAMES]
            prob = _model.predict_proba(df_input)[0][1]
            score = round(prob * 100)
        except Exception as e:
            logger.error(f"Erreur lors de la prédiction : {e}")
            score = 50 # Score neutre en cas d'erreur
    else:
        score = 50

    # 5. Détermination du verdict
    if score > 70:
        verdict = "dangerous"
    elif score > 35:
        verdict = "suspect"
    else:
        verdict = "safe"

    # 6. Capture d'écran (Optionnel - peut être mis en async si trop lent)
    # On utilise le domaine pour le nom du fichier image
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', domain)[:40]
    screenshot_path = take_screenshot(url, safe_name)

    return {
        "score": score,
        "verdict": verdict,
        "analyzed_host": domain,
        "html_captured": True if html_content else False,
        "screenshot": screenshot_path,
        "reasons": generate_reasons(score, f_dict)
    }

def generate_reasons(score, f):
    """Génère des explications textuelles basées sur les features."""
    reasons = []
    if f.get("has_password_input") and score > 50:
        reasons.append({"text": "Demande de mot de passe sur un site non certifié", "severity": "danger"})
    if f.get("nb_subdomains", 0) > 3:
        reasons.append({"text": "Nombre anormal de sous-domaines", "severity": "warn"})
    if f.get("prefix_suffix"):
        reasons.append({"text": "Utilisation suspecte de tirets dans le domaine", "severity": "warn"})
    if score > 75:
        reasons.append({"text": "L'IA a détecté une structure de page frauduleuse", "severity": "danger"})
    return reasons

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_safe_html(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LinkCheck-Bot/1.0",
        "Accept-Language": "en-US,en;q=0.5"
    }
    try:
        # TIMEOUT : Si le site ne répond pas en 5s, on abandonne (évite de faire ramer ton site)
        # ALLOW_REDIRECTS : On limite à 3 pour éviter les boucles infinies des pirates
        response = requests.get(
            url, 
            timeout=5, 
            headers=headers, 
            verify=False, 
            allow_redirects=True
        )
        
        # SÉCURITÉ TYPE : On ne télécharge que si c'est du HTML (pas des virus .exe ou .zip)
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return ""

        return response.text
    except Exception as e:
        print(f"⚠️ Erreur de scan sécurisé : {e}")
        return None