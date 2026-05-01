import re
from urllib.parse import urlparse

# L'ordre doit être EXACTEMENT celui-ci d'après ton dernier message d'erreur
FEATURE_NAMES = [
    'url_length', 
    'nb_dots', 
    'nb_hyphens', 
    'nb_at', 
    'nb_slash', 
    'has_brand_in_url', 
    'has_password_input', 
    'nb_forms',
    'nb_hyperlinks',
    'nb_subdomains',
    'prefix_suffix'
]

def extract_features(url, html_content=""):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    
    # Calcul des champs demandés
    subdomains = hostname.split('.')
    nb_subdomains = len(subdomains)
    prefix_suffix = 1 if '-' in hostname else 0

    features = {
        'url_length': len(url),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_slash': url.count('/'),
        'has_brand_in_url': 1 if any(b in hostname for b in ['google', 'microsoft', 'apple', 'facebook', 'hoyolab']) else 0,
        'has_password_input': 1 if 'type="password"' in html_content.lower() else 0,
        'nb_forms': html_content.count('<form'),
        'nb_hyperlinks': html_content.count('<a href='),
        'nb_subdomains': nb_subdomains,
        'prefix_suffix': prefix_suffix
    }
    
    # On ne retourne que les colonnes que l'IA connaît
    return {k: features[k] for k in FEATURE_NAMES}