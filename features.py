import re
import math
import string
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# ── LISTE OFFICIELLE DES COLONNES (L'ordre est CRITIQUE pour l'IA) ──────────
# Cette liste doit être exactement la même dans train.py et analyzer.py
FEATURE_NAMES = [
    "url_length", "nb_dots", "nb_hyphens", "nb_at", "nb_slash", 
    "nb_subdomains", "prefix_suffix", "has_password_input", 
    "nb_hyperlinks", "nb_forms", "has_brand_in_url"
]

# Mots-clés de marques pour la détection
BRANDS = ["paypal", "google", "amazon", "apple", "microsoft", "netflix", "ebay"]

def extract_features(url: str, html_content: str = None) -> dict:
    """
    Extrait les caractéristiques d'une URL et optionnellement de son contenu HTML.
    
    RÈGLE : Si html_content est None, les features HTML sont mises à 0.
    Cela permet à l'IA de fonctionner même si le site est inaccessible.
    """
    
    # Nettoyage de l'URL
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.lower()
    
    features = {}

    # ── 1. FEATURES D'URL (Toujours calculées) ──────────────────────────────
    features["url_length"] = len(url)
    features["nb_dots"] = url.count('.')
    features["nb_hyphens"] = url.count('-')
    features["nb_at"] = url.count('@')
    features["nb_slash"] = url.count('/')
    
    # Nombre de sous-domaines (ex: dev.login.paypal.com -> 4 parties -> 2 sous-domaines)
    parts = hostname.split('.')
    features["nb_subdomains"] = max(0, len(parts) - 2)
    
    # Présence d'un tiret dans le nom de domaine (très courant en phishing)
    features["prefix_suffix"] = 1 if '-' in hostname else 0
    
    # Détection de marques dans l'URL (ex: paypal-security.com)
    features["has_brand_in_url"] = 1 if any(brand in url.lower() for brand in BRANDS) else 0

    # ── 2. FEATURES HTML (Calculées seulement si html_content est présent) ──
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Présence d'un champ mot de passe
            features["has_password_input"] = 1 if soup.find("input", {"type": "password"}) else 0
            
            # Nombre de liens (a href)
            features["nb_hyperlinks"] = len(soup.find_all('a'))
            
            # Nombre de formulaires
            features["nb_forms"] = len(soup.find_all('form'))
            
        except Exception:
            # En cas d'erreur de parsing HTML, on met à 0
            features["has_password_input"] = 0
            features["nb_hyperlinks"] = 0
            features["nb_forms"] = 0
    else:
        # Valeurs par défaut si pas de HTML
        features["has_password_input"] = 0
        features["nb_hyperlinks"] = 0
        features["nb_forms"] = 0

    return features