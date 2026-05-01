import re
from urllib.parse import urlparse

# Cette liste est l'ordre EXACT réclamé par ton erreur "seen at fit time"
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
    
    # Calcul des nouvelles features demandées par ton modèle
    # prefix_suffix : souvent 1 si le domaine contient un tiret '-'
    prefix_suffix = 1 if '-' in hostname else 0
    
    # nb_subdomains : nombre de parties dans le domaine (ex: m.hoyolab.com = 3)
    subdomains = hostname.split('.')
    nb_subdomains = len(subdomains)

    features = {
        'url_length': len(url),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_slash': url.count('/'),
        'has_brand_in_url': 1 if any(b in hostname for b in ['google', 'fb', 'microsoft', 'apple', 'hoyolab']) else 0,
        'has_password_input': 1 if 'type="password"' in html_content.lower() else 0,
        'nb_forms': html_content.count('<form'),
        'nb_hyperlinks': html_content.count('<a href='), # Nombre de liens 
        'nb_subdomains': nb_subdomains,
        'prefix_suffix': prefix_suffix
    }
    
    return features