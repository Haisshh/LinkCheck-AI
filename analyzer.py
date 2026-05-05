# analyzer.py
# Full URL analysis pipeline: whitelist -> HTML fetch -> features -> heuristic scoring -> ML scoring -> screenshot.

import re
import os
import ssl
import socket
import time
import logging
from datetime import datetime
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

try:
    from threat_intel import query_all_async
except Exception as e:
    query_all_async = None  # type: ignore[assignment]
    logging.getLogger("linkcheck.analyzer").warning("[analyzer] Threat intel disabled: %s", e)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("linkcheck.analyzer")

# ML Model 

_model: Optional[object]    = None
_feat_names: Optional[list] = None

try:
    _model      = joblib.load("model.pkl")
    _feat_names = joblib.load("features.pkl")
    logger.info("[analyzer] ML model loaded — %d features", len(_feat_names))
except FileNotFoundError:
    logger.info("[analyzer] model.pkl missing — heuristic-only mode")
except Exception as e:
    logger.error("[analyzer] Model load error: %s", e)

ML_AVAILABLE = _model is not None and _feat_names is not None
THREAT_INTEL_ENABLED = os.environ.get("LINKCHECK_THREAT_INTEL", "true").lower() not in {
    "0", "false", "no", "off"
}
THREAT_INTEL_WAIT_SECONDS = float(os.environ.get("LINKCHECK_THREAT_INTEL_WAIT", "2.5"))

# Constantes 

# Whitelist: root domains only (hierarchical matching enabled)
# Subdomains automatically covered: e.g., xbox.com → support.xbox.com, mail.xbox.com, etc.
TRUSTED_DOMAINS: frozenset[str] = frozenset({

    # Big Tech 
    "google.com", "youtube.com", "gmail.com", "googleapis.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "meta.com", "facebook.com", "instagram.com", "whatsapp.com",
    "x.com", "twitter.com",
    "linkedin.com",

    # Dev / Tech 
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com",
    "docker.com", "kubernetes.io",
    "digitalocean.com", "heroku.com",
    "vercel.com", "netlify.com",
    "cloudflare.com",

    # Streaming 
    "netflix.com", "spotify.com", "twitch.tv",
    "disneyplus.com", "primevideo.com",

    # E-commerce 
    "amazon.com", "ebay.com", "aliexpress.com",
    "cdiscount.com", "fnac.com", "darty.com",
    "vinted.com", "leboncoin.fr",

    # Paiement / Banque 
    "paypal.com", "stripe.com",
    "wise.com", "revolut.com",
    "visa.com", "mastercard.com",

    # Banques FR
    "credit-agricole.fr", "societegenerale.fr",
    "bnpparibas.fr", "labanquepostale.fr",
    "caissedepargne.fr", "banquepopulaire.fr",

    # Livraison 
    "dhl.com", "fedex.com", "ups.com",
    "chronopost.fr", "colissimo.fr", "laposte.fr",

    # Sécurité / Open source 
    "mozilla.org", "apache.org", "linux.org",
    "ubuntu.com", "debian.org", "redhat.com",
    "kali.org", "archlinux.org",

    # Éducation 
    "wikipedia.org", "coursera.org", "edx.org",
    "openclassrooms.com", "khanacademy.org",

    # Communication 
    "discord.com", "slack.com", "zoom.us",
    "skype.com", "teams.microsoft.com",

    # Cloud / SaaS 
    "dropbox.com", "box.com",
    "notion.so", "airtable.com",

    # Jeux 
    "steampowered.com", "epicgames.com",
    "riotgames.com", "blizzard.com",
    "playstation.com", "xbox.com",

    # Médias
    "bbc.com", "cnn.com", "lemonde.fr",
    "nytimes.com", "theguardian.com",

    # Gouvernement
    "service-public.fr", "gouv.fr",
    "impots.gouv.fr", "ameli.fr",

})

# Homoglyphes connus pour chaque marque - use frozenset for O(1) lookup
BRAND_FAKES: dict[str, frozenset[str]] = {
    "amazon":    frozenset(("amaz0n", "amazoon")),
    "google":    frozenset(("g00gle", "googIe")),
    "paypal":    frozenset(("paypa1", "paypai", "pay-pal")),
    "apple":     frozenset(("app1e", "appl3")),
    "microsoft": frozenset(("micr0soft", "micros0ft")),
    "facebook":  frozenset(("faceb00k",)),
    "netflix":   frozenset(("netfl1x",)),
    "ebay":      frozenset(("ebay1",)),
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
    """Create HTTP session with retry strategy."""
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=_RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(_FETCH_HEADERS)
    return session


def _get_session() -> requests.Session:
    """Get or create singleton HTTP session."""
    global _SESSION
    if _SESSION is None:
        _SESSION = _create_session()
    return _SESSION


# Whitelist helpers (hierarchical matching with caching) 

def is_trusted(domain: str) -> bool:
    domain = domain.lower().strip()

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True

    return False

@lru_cache(maxsize=2048)
def _extract_root_domain(hostname: str) -> str:
    """
    Extract root domain from hostname for hierarchical whitelist matching.
    
    Examples:
    - "support.xbox.com" → "xbox.com"
    - "mail.google.fr" → "google.fr"
    - "192.168.1.1" → "192.168.1.1" (IP unchanged)
    
    Args:
        hostname: Full hostname or IP address
        
    Returns:
        Root domain (last 2 parts) or original if fewer than 2 parts
    """
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


@lru_cache(maxsize=2048)
def _is_whitelisted(hostname: str) -> bool:
    """
    Check if hostname or its root domain is whitelisted.
    
    Hierarchical whitelist: if xbox.com is whitelisted, then:
    - xbox.com ✓
    - support.xbox.com ✓
    - mail.xbox.com ✓
    - any.subdomain.xbox.com ✓
    
    Cached for O(1) lookup after first call.
    
    Args:
        hostname: Hostname to check
        
    Returns:
        True if whitelisted, False otherwise
    """
    if hostname in TRUSTED_DOMAINS:
        return True
    root = _extract_root_domain(hostname)
    return root in TRUSTED_DOMAINS


# HTML Fetch 

def _fetch_html(url: str) -> Optional[str]:
    """Return the HTML of the URL or None. Detailed logs for each error type."""
    try:
        t0 = time.monotonic()
        session = _get_session()
        r = session.get(url, timeout=5, verify=False, allow_redirects=True, stream=True)
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            logger.warning("[analyzer] HTTP %s for %s", r.status_code, url)
            return None

        if "text/html" not in r.headers.get("Content-Type", "").lower():
            logger.warning("[analyzer] Non-HTML content ignored for %s", url)
            return None

        r.raw.decode_content = True
        html_bytes = r.raw.read(_MAX_HTML_BYTES)
        html = html_bytes.decode("utf-8", errors="replace")
        logger.info("[analyzer] HTML OK en %dms (%d o)", elapsed, len(html))
        return html

    except requests.exceptions.Timeout:
        logger.warning("[analyzer] Timeout >5s: %s", url)
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "getaddrinfo" in msg or "Name or service" in msg:
            logger.warning("[analyzer] Domain not found: %s", url)
        elif "Connection refused" in msg:
            logger.warning("[analyzer] Connection refused: %s", url)
        else:
            logger.warning("[analyzer] Network error: %s — %s", url, msg[:80])
    except requests.exceptions.TooManyRedirects:
        logger.warning("[analyzer] Redirect loop: %s", url)
    except Exception as e:
        logger.error("[analyzer] Unexpected error (%s): %s", type(e).__name__, e)
    return None


# Heuristic analysis 

@lru_cache(maxsize=512)
def _ssl_analysis(hostname: str) -> dict:
    """Analyze SSL certificate for hostname."""
    analysis = {
        "valid_certificate": False,
        "issuer": None,
        "expired": True,
        "days_to_expire": None,
        "self_signed": False,
        "trust_score": 0,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = cert.get("issuer", ())
        analysis["issuer"] = " ".join(x[0][1] for x in issuer if x[0][0] == "O") if issuer else None
        analysis["valid_certificate"] = True

        not_before = datetime.strptime(cert.get("notBefore"), "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()

        analysis["expired"] = not (not_before <= now <= not_after)
        analysis["days_to_expire"] = max((not_after - now).days, 0)
        analysis["self_signed"] = cert.get("issuer") == cert.get("subject")

        if analysis["valid_certificate"] and not analysis["expired"]:
            trust_score = 70
            if analysis["days_to_expire"] > 90:
                trust_score += 20
            elif analysis["days_to_expire"] > 30:
                trust_score += 10
            elif analysis["days_to_expire"] >= 0:
                trust_score += 5
            if not analysis["self_signed"]:
                trust_score += 10
            analysis["trust_score"] = min(100, trust_score)
        else:
            analysis["trust_score"] = 0

    except Exception as e:
        analysis["error"] = str(e)
        analysis["trust_score"] = 0
    return analysis


@lru_cache(maxsize=512)
def _dns_reputation(hostname: str) -> dict:
    """Check DNS resolution and IP reputation."""
    result = {
        "resolved": False,
        "ip_addresses": [],
        "trust_score": 0,
        "error": None,
    }
    try:
        infos = socket.getaddrinfo(hostname, None)
        addresses = sorted({item[4][0] for item in infos if item and item[4]})
        result["resolved"] = bool(addresses)
        result["ip_addresses"] = addresses
        if not addresses:
            result["trust_score"] = 0
        else:
            trust = 60
            if len(addresses) > 1:
                trust += 20
            if any(not ip.startswith(("10.", "172.", "192.168.")) for ip in addresses):
                trust += 10
            result["trust_score"] = min(100, trust)
    except Exception as e:
        result["error"] = str(e)
        result["trust_score"] = 0
    return result


def _heuristic(hostname: str, full_url: str, f: dict) -> tuple[int, list[dict], list[dict]]:
    """Manual rules. Score capped at 85 (ML adjusts the rest)."""
    score   = 0
    reasons = []
    brand_spoofing = []
    scheme  = full_url.split("://")[0].lower() if "://" in full_url else "https"

    # HTTPS
    if scheme != "https":
        score += 10
        reasons.append({"text": "Protocole non sécurisé (HTTP)", "points": 10, "severity": "danger"})

    # URL shortener
    if hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS):
        score += 10
        reasons.append({"text": f"URL shortener ({hostname})", "points": 10, "severity": "danger"})

    # Subdomain depth (reduced to avoid false positives)
    n = f.get("nb_subdomains", 0)
    if n >= 3:
        pts = min(12, n * 3)
        score += pts
        reasons.append({"text": f"{n} niveaux de sous-domaines", "points": pts, "severity": "warn"})
    elif n == 2:
        score += 3
        reasons.append({"text": "Double sous-domaine", "points": 3, "severity": "info"})

    # Domain length (adjusted thresholds)
    dl = len(hostname)
    if dl > 50:
        score += 7
        reasons.append({"text": f"Very long domain ({dl} chars)", "points": 7, "severity": "warn"})
    elif dl > 35:
        score += 3
        reasons.append({"text": f"Long domain ({dl} chars)", "points": 3, "severity": "info"})

    # Homoglyphs / brand impersonation
    url_lower = full_url.lower()
    for brand, fakes in BRAND_FAKES.items():
        if any(fk in hostname for fk in fakes):
            score += 15
            reasons.append({"text": f"Homoglyph mimicry of \"{brand}\"", "points": 15, "severity": "danger"})
            brand_spoofing.append({"brand": brand, "type": "homoglyph", "matched": [fk for fk in fakes if fk in hostname]})
            break
        if brand in hostname and not (
            hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")
        ):
            score += 10
            reasons.append({"text": f'Brand "{brand}" in a non-official domain', "points": 10, "severity": "danger"})
            brand_spoofing.append({"brand": brand, "type": "brand_imitation", "matched": brand})
            break

    # Suspicious keywords (reduced points)
    found = [w for w in SUSPICIOUS_WORDS if w in url_lower]
    if len(found) >= 3:
        score += 10
        reasons.append({"text": f"Risk terms: {', '.join(found[:4])}", "points": 10, "severity": "warn"})
    elif len(found) == 2:
        score += 6
        reasons.append({"text": f"Suspicious terms: {', '.join(found)}", "points": 6, "severity": "info"})
    elif len(found) == 1:
        score += 2
        reasons.append({"text": f'Suspicious term: "{found[0]}"', "points": 2, "severity": "info"})

    # Password form in HTML (reduced)
    if f.get("has_password_input"):
        score += 2
        reasons.append({"text": "Formulaire de mot de passe dans le HTML", "points": 2, "severity": "info"})

    # '@' in URL (deceptive redirect)
    if "@" in full_url:
        score += 15
        reasons.append({"text": "Character '@' in URL — deceptive redirect", "points": 15, "severity": "danger"})

    # Combined bonus for multiple critical indicators
    if sum(1 for r in reasons if r["severity"] == "danger") >= 3:
        score += 10
        reasons.append({"text": "Multiple critical indicators combined", "points": 10, "severity": "danger"})

    if not reasons:
        reasons.append({"text": "No suspicious indicator identified", "points": 0, "severity": "safe"})

    return min(85, score), reasons, brand_spoofing


# Score ML 

def _ml_score(f: dict) -> Optional[int]:
    """Calculate ML phishing score."""
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


# Feature cache

@lru_cache(maxsize=1024)
def _cached_extract_features(url: str, html_hash: int, html_content: Optional[str]) -> dict:
    """Cache feature extraction to avoid recomputation."""
    return extract_features(url, html_content)


# Entry point

_RE_SAFE_NAME = re.compile(r'[^a-zA-Z0-9]')


def _collect_threat_intel(future) -> dict:
    """Return threat intelligence if it finishes quickly; never break analysis."""
    if future is None:
        return {
            "enabled": THREAT_INTEL_ENABLED,
            "available": False,
            "error": "not scheduled",
        }
    try:
        ti = future.result(timeout=THREAT_INTEL_WAIT_SECONDS)
        ti["enabled"] = True
        ti["available"] = ti.get("apis_checked", 0) > 0
        return ti
    except Exception as e:
        logger.warning("[analyzer] Threat intel unavailable: %s", e)
        return {
            "enabled": True,
            "available": False,
            "error": f"{type(e).__name__}: {e}",
            "is_malicious": False,
            "threat_score": 0,
            "flagged_by": [],
            "sources": {},
            "apis_checked": 0,
            "apis_skipped": 0,
        }


def _apply_threat_intel(
    score: int,
    verdict: str,
    reasons: list[dict],
    threat_intel: dict,
    heuristic_score: int,
    html_available: bool,
) -> tuple[int, str]:
    """Blend external reputation into the existing local/ML score."""
    if not threat_intel.get("available"):
        return score, verdict

    flagged_by = threat_intel.get("flagged_by", [])
    threat_score = int(threat_intel.get("threat_score") or 0)
    apis_checked = int(threat_intel.get("apis_checked") or 0)

    if flagged_by:
        label = ", ".join(flagged_by[:3])
        reasons.append({
            "text": f"Threat intelligence flagged this URL ({label})",
            "points": max(20, min(45, threat_score)),
            "severity": "danger",
        })
        return max(score, threat_score, 75), "dangerous"

    if threat_score >= 55:
        reasons.append({
            "text": f"Elevated external reputation risk ({threat_score}/100)",
            "points": 12,
            "severity": "warn",
        })
        blended = max(score, round(score * 0.75 + threat_score * 0.25))
        return blended, "suspect" if blended > 40 and verdict == "safe" else verdict

    if apis_checked >= 3 and score >= 66 and heuristic_score <= 10 and threat_score <= 35:
        reasons.append({
            "text": f"External reputation sources found no malicious listing ({apis_checked} checked)",
            "points": -35,
            "severity": "safe",
        })
        adjusted = 25 if html_available else 35
        return min(score, adjusted), "safe"

    if apis_checked >= 3 and score > 40 and heuristic_score <= 20 and threat_score <= 35:
        reasons.append({
            "text": f"External reputation sources reduce the risk ({apis_checked} checked)",
            "points": -20,
            "severity": "safe",
        })
        adjusted = max(20, round(score * 0.55))
        return adjusted, "safe" if adjusted <= 40 else "suspect"

    if apis_checked > 0:
        reasons.append({
            "text": f"External reputation sources checked ({apis_checked})",
            "points": 0,
            "severity": "safe",
        })

    return score, verdict


def analyze_url(url: str) -> dict:
    """Main URL analysis entry point."""
    t0       = time.monotonic()
    url      = url.strip()
    full_url = url if "://" in url else "https://" + url

    # Parse hostname
    try:
        hostname = (urlparse(full_url).hostname or "").lower().replace("www.", "")
    except Exception:
        logger.warning("[analyzer] Malformed URL: %s", url)
        return {"score": 0, "verdict": "error", "analyzed_host": url,
                "reasons": [{"text": "Invalid URL", "points": 0, "severity": "info"}],
                "html_captured": False, "screenshot": None,
                "threat_intel": {"enabled": THREAT_INTEL_ENABLED, "available": False, "error": "invalid URL"}}

    logger.info("[analyzer] → %s", hostname)

    # 1. Whitelist: hierarchical check with caching — immediate return, no network
    if _is_whitelisted(hostname):
        logger.info("[analyzer] Whitelist hit (%.1fms)", (time.monotonic() - t0) * 1000)
        return {"score": 0, "verdict": "safe", "analyzed_host": hostname,
                "reasons": [{"text": "Trusted site (whitelist)", "points": 0, "severity": "safe"}],
                "html_captured": False, "screenshot": None,
                "threat_intel": {"enabled": THREAT_INTEL_ENABLED, "available": False, "skipped": "trusted domain"}}

    threat_future = None
    if THREAT_INTEL_ENABLED and query_all_async is not None:
        try:
            threat_future = query_all_async(full_url)
        except Exception as e:
            logger.warning("[analyzer] Threat intel not scheduled: %s", e)

    # 2. HTML
    html = _fetch_html(full_url)

    # 3. Features
    html_hash = hash(html) if html else 0
    f = _cached_extract_features(full_url, html_hash, html)

    # 4. Heuristique + ML (IA au cœur : 80% ML, 20% heuristique)
    h_score, reasons, brand_spoofing = _heuristic(hostname, full_url, f)
    ml               = _ml_score(f)
    ssl_info         = {"skipped": True, "trust_score": 50, "error": "analysis skipped"}
    dns_info         = {"skipped": True, "trust_score": 50, "error": "analysis skipped"}
    extra_checks = ml is None or ml >= 40 or h_score >= 20
    if extra_checks:
        ssl_info = _ssl_analysis(hostname)
        dns_info = _dns_reputation(hostname)
    if ml is not None:
        # IA prioritaire : moins strict sur les zones grises
        if html is None and h_score <= 10 and ml >= 75:
            score = 45
            verdict = "suspect"
            reasons.append({
                "text": "ML risk reduced because page content could not be fetched and local indicators are weak",
                "points": -30,
                "severity": "info",
            })
        elif ml < 25:
            score = max(5, round(0.88 * ml + 0.12 * h_score))
            verdict = "safe"
        elif ml > 75:
            score = min(95, round(0.88 * ml + 0.12 * h_score))
            verdict = "dangerous"
        else:
            score = round(0.8 * ml + 0.2 * h_score)
            verdict = "safe" if score <= 40 else "suspect" if score <= 65 else "dangerous"
    else:
        score = h_score
        verdict = "safe" if score <= 35 else "suspect" if score <= 65 else "dangerous"

    logger.info("[analyzer] %s → %s %d/100 (%.0fms)",
                hostname, verdict, score, (time.monotonic() - t0) * 1000)

    threat_intel = _collect_threat_intel(threat_future)
    score, verdict = _apply_threat_intel(score, verdict, reasons, threat_intel, h_score, html is not None)

    logger.info("[analyzer] final %s -> %s %d/100 (%.0fms)",
                hostname, verdict, score, (time.monotonic() - t0) * 1000)

    screenshot_path = None

    # 5. Screenshot async (uniquement si suspect/dangereux)
    if verdict == "dangerous" or (verdict == "suspect" and score >= 55):
        try:
            safe_name = _RE_SAFE_NAME.sub("_", hostname)[:40]
            take_screenshot_async(full_url, safe_name)
            screenshot_path = f"screenshot/{safe_name}"
        except Exception as e:
            logger.error("[analyzer] Screenshot non planifié : %s", e)

    return {
        "score":           score,
        "verdict":         verdict,
        "is_phishing":     verdict != "safe",
        "confidence":      ml / 100 if ml is not None else None,
        "analyzed_host":   hostname,
        "reasons":         reasons,
        "ml_score":        ml,
        "heuristic_score": h_score,
        "brand_spoofing":  brand_spoofing,
        "ssl_info":        ssl_info,
        "dns_info":        dns_info,
        "threat_intel":    threat_intel,
        "html_captured":   html is not None,
        "screenshot":      screenshot_path,
    }
