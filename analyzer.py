# analyzer.py
# Analyse complète d'une URL : whitelist → HTML → features → heuristique → ML → screenshot.

import re
import time
import logging
from typing import Optional
from urllib.parse import urlparse
from functools import lru_cache

import joblib
import pandas as pd
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from features import extract_features, FEATURE_NAMES, SUSPICIOUS_WORDS, SHORTENERS
from screenshot import take_screenshot_async

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("linkcheck.analyzer")

# ── Modèle ML ─────────────────────────────────────────────────────────────────

_model: Optional[object]    = None
_feat_names: Optional[list] = None

try:
    _model      = joblib.load("model.pkl")
    _feat_names = joblib.load("features.pkl")
    logger.info("[analyzer] Modèle ML chargé — %d features", len(_feat_names))
except FileNotFoundError:
    logger.info("[analyzer] model.pkl absent — mode heuristique uniquement")
except Exception as e:
    logger.error("[analyzer] Erreur chargement modèle : %s", e)

ML_AVAILABLE = _model is not None and _feat_names is not None

# ── Constantes ────────────────────────────────────────────────────────────────

TRUSTED_DOMAINS: frozenset[str] = frozenset({
    "google.com", "google.fr", "paypal.com", "paypal.fr",
    "apple.com", "microsoft.com", "github.com", "netflix.com",
    "wikipedia.org", "youtube.com", "stackoverflow.com",
})

# Homoglyphes connus pour chaque marque
BRAND_FAKES: dict[str, tuple[str, ...]] = {
    "amazon":    ("amaz0n", "amazoon"),
    "google":    ("g00gle", "googIe"),
    "paypal":    ("paypa1", "paypai", "pay-pal"),
    "apple":     ("app1e", "appl3"),
    "microsoft": ("micr0soft", "micros0ft"),
    "facebook":  ("faceb00k",),
    "netflix":   ("netfl1x",),
    "ebay":      ("ebay1",),
}

_FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LinkCheck-Bot/1.0",
    "Accept-Language": "en-US,en;q=0.5",
}
_MAX_HTML_BYTES = 2_000_000  # 2 Mo

_RETRY_STRATEGY = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET"]),
)
_SESSION: Optional[requests.Session] = None


def _create_session() -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=_RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(_FETCH_HEADERS)
    return session


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = _create_session()
    return _SESSION


# ── Récupération HTML ─────────────────────────────────────────────────────────

def _fetch_html(url: str) -> Optional[str]:
    """Retourne le HTML de l'URL ou None. Logs détaillés par type d'erreur."""
    try:
        t0 = time.monotonic()
        session = _get_session()
        r = session.get(url, timeout=5, verify=False, allow_redirects=True, stream=True)
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            logger.warning("[analyzer] HTTP %s pour %s", r.status_code, url)
            return None

        if "text/html" not in r.headers.get("Content-Type", "").lower():
            logger.warning("[analyzer] Contenu non-HTML ignoré pour %s", url)
            return None

        r.raw.decode_content = True
        html_bytes = r.raw.read(_MAX_HTML_BYTES)
        html = html_bytes.decode("utf-8", errors="replace")
        logger.info("[analyzer] HTML OK en %dms (%d o)", elapsed, len(html))
        return html

    except requests.exceptions.Timeout:
        logger.warning("[analyzer] Timeout >5s : %s", url)
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "getaddrinfo" in msg or "Name or service" in msg:
            logger.warning("[analyzer] Domaine inexistant : %s", url)
        elif "Connection refused" in msg:
            logger.warning("[analyzer] Connexion refusée : %s", url)
        else:
            logger.warning("[analyzer] Erreur réseau : %s — %s", url, msg[:80])
    except requests.exceptions.TooManyRedirects:
        logger.warning("[analyzer] Boucle de redirections : %s", url)
    except Exception as e:
        logger.error("[analyzer] Erreur inattendue (%s) : %s", type(e).__name__, e)
    return None


# ── Analyse heuristique ───────────────────────────────────────────────────────

def _heuristic(hostname: str, full_url: str, f: dict) -> tuple[int, list[dict]]:
    """Règles manuelles. Score plafonné à 85 (le ML ajuste le reste)."""
    score   = 0
    reasons = []
    scheme  = full_url.split("://")[0].lower() if "://" in full_url else "https"

    # HTTPS
    if scheme != "https":
        score += 20
        reasons.append({"text": "Protocole non sécurisé (HTTP)", "points": 20, "severity": "danger"})

    # Raccourcisseur
    if hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS):
        score += 15
        reasons.append({"text": f"Raccourcisseur d'URL ({hostname})", "points": 15, "severity": "danger"})

    # Sous-domaines
    n = f.get("nb_subdomains", 0)
    if n >= 3:
        pts = min(25, n * 7)
        score += pts
        reasons.append({"text": f"{n} niveaux de sous-domaines", "points": pts, "severity": "danger"})
    elif n == 2:
        score += 8
        reasons.append({"text": "Double sous-domaine", "points": 8, "severity": "warn"})

    # Longueur domaine
    dl = len(hostname)
    if dl > 40:
        score += 15
        reasons.append({"text": f"Domaine très long ({dl} car.)", "points": 15, "severity": "danger"})
    elif dl > 30:
        score += 8
        reasons.append({"text": f"Domaine long ({dl} car.)", "points": 8, "severity": "warn"})

    # Homoglyphes / usurpation de marque
    url_lower = full_url.lower()
    for brand, fakes in BRAND_FAKES.items():
        if any(fk in hostname for fk in fakes):
            score += 25
            reasons.append({"text": f"Imitation de \"{brand}\" par homoglyphe", "points": 25, "severity": "danger"})
            break
        if brand in hostname and not (
            hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")
        ):
            score += 15
            reasons.append({"text": f'Marque "{brand}" dans un domaine non officiel', "points": 15, "severity": "danger"})
            break

    # Mots suspects
    found = [w for w in SUSPICIOUS_WORDS if w in url_lower]
    if len(found) >= 3:
        score += 20
        reasons.append({"text": f"Termes à risque : {', '.join(found[:4])}", "points": 20, "severity": "danger"})
    elif len(found) == 2:
        score += 12
        reasons.append({"text": f"Termes suspects : {', '.join(found)}", "points": 12, "severity": "warn"})
    elif len(found) == 1:
        score += 6
        reasons.append({"text": f'Terme suspect : "{found[0]}"', "points": 6, "severity": "info"})

    # Formulaire de mot de passe dans le HTML
    if f.get("has_password_input"):
        score += 10
        reasons.append({"text": "Formulaire de mot de passe dans le HTML", "points": 10, "severity": "warn"})

    # @ dans l'URL (redirection trompeuse)
    if "@" in full_url:
        score += 20
        reasons.append({"text": "Caractère '@' dans l'URL — redirection trompeuse", "points": 20, "severity": "danger"})

    # Bonus combinaison
    if sum(1 for r in reasons if r["severity"] == "danger") >= 3:
        score += 15
        reasons.append({"text": "Plusieurs indicateurs critiques combinés", "points": 15, "severity": "danger"})

    if not reasons:
        reasons.append({"text": "Aucun indicateur suspect identifié", "points": 0, "severity": "safe"})

    return min(85, score), reasons


# ── Score ML ──────────────────────────────────────────────────────────────────

def _ml_score(f: dict) -> Optional[int]:
    if not ML_AVAILABLE:
        return None
    try:
        X    = pd.DataFrame([f])[_feat_names]
        prob = float(_model.predict_proba(X)[0][1])
        ml   = round(prob * 100)
        logger.debug("[analyzer] ML score : %d/100", ml)
        return ml
    except Exception as e:
        logger.error("[analyzer] Erreur ML : %s", e)
        return None


# ── Cache pour features ───────────────────────────────────────────────────────

@lru_cache(maxsize=1024)
def _cached_extract_features(url: str, html_hash: int) -> dict:
    """Cache les features pour éviter les recalculs."""
    return extract_features(url, None if html_hash == 0 else "dummy")  # Ajuster selon besoin


# ── Point d'entrée ────────────────────────────────────────────────────────────

_RE_SAFE_NAME = re.compile(r'[^a-zA-Z0-9]')

def analyze_url(url: str) -> dict:
    t0       = time.monotonic()
    url      = url.strip()
    full_url = url if "://" in url else "https://" + url

    # Parse hostname
    try:
        hostname = (urlparse(full_url).hostname or "").lower().replace("www.", "")
    except Exception:
        logger.warning("[analyzer] URL malformée : %s", url)
        return {"score": 0, "verdict": "error", "analyzed_host": url,
                "reasons": [{"text": "URL invalide", "points": 0, "severity": "info"}],
                "html_captured": False, "screenshot": None}

    logger.info("[analyzer] → %s", hostname)

    # 1. Whitelist : retour immédiat, zéro réseau
    if hostname in TRUSTED_DOMAINS or any(hostname.endswith("." + d) for d in TRUSTED_DOMAINS):
        logger.info("[analyzer] Whitelist hit (%.1fms)", (time.monotonic() - t0) * 1000)
        return {"score": 0, "verdict": "safe", "analyzed_host": hostname,
                "reasons": [{"text": "Site de confiance (liste blanche)", "points": 0, "severity": "safe"}],
                "html_captured": False, "screenshot": None}

    # 2. HTML
    html = _fetch_html(full_url)

    # 3. Features
    html_hash = hash(html) if html else 0
    f = _cached_extract_features(full_url, html_hash)

    # 4. Heuristique + ML
    h_score, reasons = _heuristic(hostname, full_url, f)
    ml               = _ml_score(f)
    score            = min(100, round(0.55 * ml + 0.45 * h_score) if ml is not None else h_score)
    verdict          = "safe" if score <= 30 else "suspect" if score <= 60 else "dangerous"

    logger.info("[analyzer] %s → %s %d/100 (%.0fms)",
                hostname, verdict, score, (time.monotonic() - t0) * 1000)

    # 5. Screenshot async (uniquement si suspect/dangereux)
    if verdict in ("suspect", "dangerous"):
        try:
            safe_name = _RE_SAFE_NAME.sub("_", hostname)[:40]
            take_screenshot_async(full_url, safe_name)
        except Exception as e:
            logger.error("[analyzer] Screenshot non planifié : %s", e)

    return {
        "score":         score,
        "verdict":       verdict,
        "analyzed_host": hostname,
        "reasons":       reasons,
        "ml_score":      ml,
        "html_captured": html is not None,
        "screenshot":    None,  # disponible via GET /screenshot/<host>
    }