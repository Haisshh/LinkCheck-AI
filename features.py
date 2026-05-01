import re
from urllib.parse import urlparse

# Liste SYNCHRONISÉE avec ton modèle (fit time)
FEATURE_NAMES = [
    'url_length', 
    'nb_dots', 
    'nb_hyphens', 
    'nb_at', 
    'nb_slash', 
    'nb_and',
    'has_brand_in_url', 
    'has_password_input', 
    'nb_forms'
]

def extract_features(url, html_content=""):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    url_lower = url.lower()
    
    # Dictionnaire de base
    features = {
        'url_length': len(url),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_slash': url.count('/'),
        'nb_and': url.count('&'),
        # Détection de marques connues (pour has_brand_in_url)
        'has_brand_in_url': 1 if any(brand in hostname for brand in ['google', 'microsoft', 'apple', 'facebook', 'hoyolab', 'mihoyo']) else 0,
        # Analyse du contenu HTML (si fourni)
        'has_password_input': 1 if 'type="password"' in html_content.lower() or 'type=\'password\'' in html_content.lower() else 0,
        'nb_forms': html_content.count('<form')
    }
    
    return features