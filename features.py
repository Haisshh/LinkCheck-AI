import re
from urllib.parse import urlparse

# L'ordre doit être identique à celui de ton entraînement !
FEATURE_NAMES = [
    'url_length', 'n_dots', 'n_hyphens', 'n_underline', 'n_slash', 
    'n_question', 'n_equal', 'n_at', 'n_and', 'n_exclamation', 
    'n_digits', 'n_letters', 'n_specials', 'has_https'
]

def extract_features(url, html_content=""):
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    features = {
        'url_length': len(url),
        'n_dots': url.count('.'),
        'n_hyphens': url.count('-'),
        'n_underline': url.count('_'),
        'n_slash': url.count('/'),
        'n_question': url.count('?'),
        'n_equal': url.count('='),
        'n_at': url.count('@'),
        'n_and': url.count('&'),
        'n_exclamation': url.count('!'),
        'n_digits': sum(c.isdigit() for c in url),
        'n_letters': sum(c.isalpha() for c in url),
        'n_specials': sum(not c.isalnum() for c in url),
        'has_https': 1 if parsed.scheme == 'https' else 0
    }
    return features