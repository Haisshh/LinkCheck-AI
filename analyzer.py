"""
analyzer.py — Analyse complète d'une URL.

CORRECTIONS :
  - imports dédupliqués (requests, urllib3 étaient importés 2-3 fois)
  - urllib3.disable_warnings() appelé une seule fois
  - get_safe_html() morte supprimée — remplacée par _fetch_html() propre
  - html_content=None géré dans extract_features (plus de crash)
  - take_screenshot() remplacée par take_screenshot_async() — Flask ne bloque plus
  - whitelist vérifiée AVANT toute requête réseau
"""

import re
import time
import logging

import requests
import urllib3
import joblib
import pandas as pd
from urllib.parse import urlparse

from features import extract_features, FEATURE_NAMES, SUSPICIOUS_WORDS, SHORTENERS
from screenshot import take_screenshot_async

# Un seul appel, en haut du fichier
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("linkcheck.analyzer")

# ── Chargement du modèle ───────────────────────────────────────────────────────
try:
    _model       = joblib.load("model.pkl")
    _feat_names  = joblib.load("features.pkl")
    ML_AVAILABLE = True
    logger.info("[analyzer] Modèle ML chargé — %d features", len(_feat_names))
except FileNotFoundError:
    ML_AVAILABLE = False
    logger.info("[analyzer] model.pkl absent — mode heuristique uniquement")
except Exception as e:
    ML_AVAILABLE = False
    logger.error("[analyzer] Erreur chargement modèle : %s", e)

# ── Whitelist ──────────────────────────────────────────────────────────────────
TRUSTED_DOMAINS = [
    "google.com", "google.fr", "paypal.com", "paypal.fr",
    "apple.com", "microsoft.com", "github.com", "netflix.com",
    "wikipedia.org", "youtube.com", "stackoverflow.com"
]

# ── Marques usurpées ───────────────────────────────────────────────────────────
KNOWN_BRANDS = {
    "amazon":    ["amaz0n", "amazoon"],
    "google":    ["g00gle", "googIe"],
    "paypal":    ["paypa1", "paypai", "pay-pal"],
    "apple":     ["app1e", "appl3"],
    "microsoft": ["micr0soft", "micros0ft"],
    "facebook":  ["faceb00k"],
    "netflix":   ["netfl1x"],
    "ebay":      ["ebay1"],
}


# ── Récupération HTML ──────────────────────────────────────────────────────────

def _fetch_html(url: str) -> str | None:
    """
    Tente de récupérer le HTML de l'URL.
    Retourne None si le site est inaccessible — jamais une chaîne vide qui masque l'erreur.
    Logs détaillés selon le type d'échec.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LinkCheck-Bot/1.0",
        "Accept-Language": "en-US,en;q=0.5",
    }
    try:
        t0 = time.time()
        response = requests.get(
            url,
            timeout=5,
            verify=False,
            headers=headers,
            allow_redirects=True,
            stream=True,   # évite de télécharger des fichiers binaires lourds
        )
        elapsed = round((time.time() - t0) * 1000)

        # On n'accepte que du HTML — pas de .exe, .zip etc.
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            logger.warning("[analyzer] Contenu non-HTML ignoré (%s) pour %s", content_type, url)
            return None

        # Limite de taille : 2 Mo max pour éviter les abus
        content = response.content[:2_000_000].decode("utf-8", errors="replace")
        logger.info("[analyzer] HTML récupéré en %dms (%d octets)", elapsed, len(content))
        return content

    except requests.exceptions.Timeout:
        logger.warning("[analyzer] Timeout (>5s) — site trop lent : %s", url)
        return None
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "Name or service not known" in msg or "getaddrinfo" in msg:
            logger.warning("[analyzer] Domaine inexistant : %s", url)
        else:
            logger.warning("[analyzer] Connexion refusée : %s", url)
        return None
    except requests.exceptions.TooManyRedirects:
        logger.warning("[analyzer] Boucle de redirections : %s", url)
        return None
    except Exception as e:
        logger.error("[analyzer] Erreur réseau inattendue (%s) : %s", type(e).__name__, e)
        return None


# ── Analyse heuristique ────────────────────────────────────────────────────────

def _heuristic(hostname: str, full_url: str, f: dict) -> tuple[int, list]:
    """Règles manuelles. Retourne (score, reasons). Score max 85."""
    score   = 0
    reasons = []
    parsed  = urlparse(full_url)

    if parsed.scheme != "https":
        score += 20
        reasons.append({"text": "Protocole non sécurisé (HTTP)", "points": 20, "severity": "danger"})

    is_short = any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)
    if is_short:
        score += 15
        reasons.append({"text": f"Raccourcisseur d'URL ({hostname})", "points": 15, "severity": "danger"})

    nb_sub = f.get("nb_subdomains", 0)
    if nb_sub >= 3:
        pts = min(25, nb_sub * 7)
        score += pts
        reasons.append({"text": f"{nb_sub} niveaux de sous-domaines", "points": pts, "severity": "danger"})
    elif nb_sub == 2:
        score += 8
        reasons.append({"text": "Double sous-domaine", "points": 8, "severity": "warn"})

    dl = len(hostname)
    if dl > 40:
        score += 15
        reasons.append({"text": f"Domaine très long ({dl} car.)", "points": 15, "severity": "danger"})
    elif dl > 30:
        score += 8
        reasons.append({"text": f"Domaine long ({dl} car.)", "points": 8, "severity": "warn"})

    for brand, fakes in KNOWN_BRANDS.items():
        if any(fk in hostname for fk in fakes):
            score += 25
            reasons.append({"text": f"Imitation de \"{brand}\" par homoglyphe", "points": 25, "severity": "danger"})
            break
        if brand in hostname and not (
            hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")
        ):
            score += 15
            reasons.append({"text": f"Marque \"{brand}\" dans un domaine non officiel", "points": 15, "severity": "danger"})
            break

    fw = [w for w in SUSPICIOUS_WORDS if w in full_url.lower()]
    if len(fw) >= 3:
        score += 20
        reasons.append({"text": f"Termes à risque : {', '.join(fw[:4])}", "points": 20, "severity": "danger"})
    elif len(fw) == 2:
        score += 12
        reasons.append({"text": f"Termes suspects : {', '.join(fw)}", "points": 12, "severity": "warn"})
    elif len(fw) == 1:
        score += 6
        reasons.append({"text": f"Terme suspect : \"{fw[0]}\"", "points": 6, "severity": "info"})

    if f.get("has_password_input"):
        score += 10
        reasons.append({"text": "Formulaire de mot de passe détecté dans le HTML", "points": 10, "severity": "warn"})

    if "@" in full_url:
        score += 20
        reasons.append({"text": "Caractère '@' dans l'URL — redirection trompeuse", "points": 20, "severity": "danger"})

    nb_danger = sum(1 for r in reasons if r["severity"] == "danger")
    if nb_danger >= 3:
        bonus = 15
        score += bonus
        reasons.append({"text": f"{nb_danger} indicateurs critiques combinés", "points": bonus, "severity": "danger"})

    if not reasons:
        reasons.append({"text": "Aucun indicateur suspect identifié", "points": 0, "severity": "safe"})

    return min(85, score), reasons


# ── Score ML ───────────────────────────────────────────────────────────────────

def _ml_score(f: dict) -> int | None:
    if not ML_AVAILABLE:
        return None
    try:
        X    = pd.DataFrame([f])[_feat_names]
        prob = float(_model.predict_proba(X)[0][1])
        ml   = round(prob * 100)
        logger.debug("[analyzer] Score ML : %d/100", ml)
        return ml
    except Exception as e:
        logger.error("[analyzer] Erreur inférence ML : %s", e)
        return None


# ── Point d'entrée ─────────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    t0  = time.time()
    url = url.strip()
    full_url = url if "://" in url else "https://" + url

    try:
        parsed   = urlparse(full_url)
        hostname = (parsed.hostname or "").lower().replace("www.", "")
    except Exception:
        logger.warning("[analyzer] URL malformée : %s", url)
        return {
            "score": 0, "verdict": "error", "analyzed_host": url,
            "reasons": [{"text": "URL invalide", "points": 0, "severity": "info"}],
            "html_captured": False, "screenshot": None,
        }

    logger.info("[analyzer] Analyse : %s", hostname)

    # 1. Whitelist — retour immédiat, zéro réseau
    if any(hostname == d or hostname.endswith("." + d) for d in TRUSTED_DOMAINS):
        logger.info("[analyzer] Whitelisté en %.1fms", (time.time() - t0) * 1000)
        return {
            "score": 0, "verdict": "safe", "analyzed_host": hostname,
            "reasons": [{"text": "Site de confiance (liste blanche)", "points": 0, "severity": "safe"}],
            "html_captured": False, "screenshot": None,
        }

    # 2. Récupération HTML (optionnel — None si échec)
    html_content = _fetch_html(full_url)

    # 3. Extraction features (html_content peut être None — géré dans features.py)
    f = extract_features(full_url, html_content)

    # 4. Heuristique
    h_score, reasons = _heuristic(hostname, full_url, f)

    # 5. ML
    ml = _ml_score(f)
    final_score = round(0.55 * ml + 0.45 * h_score) if ml is not None else h_score
    final_score = min(100, final_score)

    verdict = "safe" if final_score <= 30 else "suspect" if final_score <= 60 else "dangerous"
    logger.info("[analyzer] %s → %s (%d/100) en %.0fms",
                hostname, verdict, final_score, (time.time() - t0) * 1000)

    # 6. Screenshot async — Flask répond immédiatement, Chrome tourne en arrière-plan
    if verdict in ("suspect", "dangerous"):
        try:
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', hostname)[:40]
            take_screenshot_async(full_url, safe_name)
            logger.info("[analyzer] Screenshot planifié en arrière-plan")
        except Exception as e:
            logger.error("[analyzer] Impossible de planifier le screenshot : %s", e)

    return {
        "score":         final_score,
        "verdict":       verdict,
        "analyzed_host": hostname,
        "reasons":       reasons,
        "ml_score":      ml,
        "html_captured": html_content is not None,
        "screenshot":    None,   # disponible via /screenshot/<host> après traitement
    }
