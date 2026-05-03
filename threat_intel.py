# threat_intel.py
# Threat intelligence via 5 free APIs, all running in parallel.
# Each call is isolated: if one API fails, the others continue.
#
# APIs intégrées :
#   1. VirusTotal       — 4 req/min gratuit (clé requise)
#   2. URLhaus          — 100% gratuit, sans clé, base de 3M+ URLs malveillantes
#   3. PhishTank        — gratuit, spécialisé phishing (clé optionnelle)
#   4. Google Safe Browsing — gratuit, 10 000 req/jour (clé requise)
#   5. IPQualityScore   — gratuit, 200 req/jour (clé requise)
#
# Configuration dans .env :
#   VIRUSTOTAL_API_KEY=...
#   GOOGLE_SAFE_BROWSING_API_KEY=...
#   IPQS_API_KEY=...
#   PHISHTANK_API_KEY=...          (optionnel — fonctionne sans)
#
# Toutes les clés sont optionnelles : si absente, l'API est ignorée silencieusement.

import os
import time
import logging
import hashlib
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError
from threading import Lock, local
from typing import Optional
from urllib.parse import urlparse, quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("linkcheck.threat_intel")

# ── Clés API (chargées depuis .env via main.py) ───────────────────────────────

_VT_KEY    = os.environ.get("VIRUSTOTAL_API_KEY", "")
_GSB_KEY   = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
_IPQS_KEY  = os.environ.get("IPQS_API_KEY", "")
_PT_KEY    = os.environ.get("PHISHTANK_API_KEY", "")  # optionnel
_URLHAUS_KEY = os.environ.get("URLHAUS_AUTH_KEY", "")

# ── Pool de threads dédié (séparé du pool screenshot) ────────────────────────
# max_workers=5 = une requête par API en parallèle
_ASYNC_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="threat_intel_orchestrator")
_API_POOL = ThreadPoolExecutor(max_workers=5, thread_name_prefix="threat_intel_api")

# Timeout réseau strict par API
_TIMEOUT = 6  # secondes

# ── Session HTTP partagée ─────────────────────────────────────────────────────
_thread_local = local()


def _get_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": "LinkCheck-ThreatIntel/1.0"})
        _thread_local.session = session
    return session


# ─────────────────────────────────────────────────────────────────────────────
# 1. VIRUSTOTAL
# Doc : https://developers.virustotal.com/reference/url-info
# Gratuit : 4 req/min, 500 req/jour
# ─────────────────────────────────────────────────────────────────────────────

def _virustotal(url: str) -> dict:
    """
    Query VirusTotal for URL reputation.
    Uses URL ID (base64url of URL) to avoid re-scanning.
    Returns detection ratio and vendor results.
    """
    result = {"source": "virustotal", "available": False, "error": None}

    if not _VT_KEY:
        result["error"] = "API key not configured (VIRUSTOTAL_API_KEY)"
        return result

    try:
        import base64
        # VirusTotal URL ID = base64url(url) without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        t0 = time.monotonic()
        r = _get_session().get(
            endpoint,
            headers={"x-apikey": _VT_KEY},
            timeout=_TIMEOUT,
        )
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code == 404:
            # URL not in VT database yet — submit for scanning
            scan_r = _get_session().post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": _VT_KEY},
                data={"url": url},
                timeout=_TIMEOUT,
            )
            if scan_r.status_code == 200:
                result["available"]   = True
                result["status"]      = "submitted"
                result["malicious"]   = 0
                result["suspicious"]  = 0
                result["total"]       = 0
                result["is_malicious"]= False
                result["detail"]      = "URL submitted to VirusTotal for first scan"
                logger.info("[VT] Submitted new URL (%dms)", elapsed)
            else:
                result["error"] = f"Submit failed: HTTP {scan_r.status_code}"
            return result

        if r.status_code == 429:
            result["error"] = "Rate limit reached (4 req/min)"
            return result

        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        data  = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Collect which vendors flagged it
        analysis   = data["data"]["attributes"].get("last_analysis_results", {})
        flagged_by = [
            vendor for vendor, res in analysis.items()
            if res.get("category") in ("malicious", "phishing", "suspicious")
        ][:10]  # top 10 max

        result.update({
            "available":    True,
            "malicious":    malicious,
            "suspicious":   suspicious,
            "harmless":     harmless,
            "total":        total,
            "flagged_by":   flagged_by,
            "is_malicious": malicious >= 2 or (malicious + suspicious) >= 4,
            "risk_score":   round((malicious + suspicious * 0.5) / max(total, 1) * 100),
            "elapsed_ms":   elapsed,
        })
        logger.info("[VT] %s — malicious=%d/%d (%dms)", url[:50], malicious, total, elapsed)

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout >{_TIMEOUT}s"
        logger.warning("[VT] Timeout for %s", url[:50])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error("[VT] Error: %s", e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. URLHAUS (Abuse.ch)
# Doc : https://urlhaus-api.abuse.ch/
# Gratuit : sans clé, sans limite officielle
# Base : 3M+ URLs malveillantes connues
# ─────────────────────────────────────────────────────────────────────────────

def _urlhaus(url: str) -> dict:
    """
    Query URLhaus for known malware/phishing URLs.
    Requires a free URLhaus Auth-Key.
    """
    result = {"source": "urlhaus", "available": False, "error": None}

    if not _URLHAUS_KEY:
        result["error"] = "Auth-Key not configured (URLHAUS_AUTH_KEY)"
        return result

    try:
        t0 = time.monotonic()
        r = _get_session().post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": _URLHAUS_KEY},
            timeout=_TIMEOUT,
        )
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        data = r.json()

        if data.get("query_status") == "no_results":
            result.update({
                "available":    True,
                "found":        False,
                "is_malicious": False,
                "status":       "not_listed",
                "elapsed_ms":   elapsed,
            })
        else:
            threat     = data.get("threat", "unknown")
            url_status = data.get("url_status", "unknown")
            tags       = data.get("tags") or []

            result.update({
                "available":    True,
                "found":        True,
                "is_malicious": True,
                "status":       url_status,   # "online" | "offline" | "unknown"
                "threat":       threat,        # "malware_download" | "botnet_cc" etc.
                "tags":         tags,
                "date_added":   data.get("date_added"),
                "reporter":     data.get("reporter"),
                "elapsed_ms":   elapsed,
            })
            logger.warning("[URLhaus] MALICIOUS %s — threat=%s status=%s", url[:50], threat, url_status)

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout >{_TIMEOUT}s"
        logger.warning("[URLhaus] Timeout for %s", url[:50])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error("[URLhaus] Error: %s", e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. PHISHTANK
# Doc : https://phishtank.org/api_info.php
# Gratuit : clé optionnelle (limite plus haute avec clé)
# Base : spécialisée phishing, vérifiée par la communauté
# ─────────────────────────────────────────────────────────────────────────────

def _phishtank(url: str) -> dict:
    """
    Query PhishTank for known phishing URLs.
    Works without API key but rate-limited. Key increases limits.
    """
    result = {"source": "phishtank", "available": False, "error": None}
    try:
        payload = {
            "url": url,
            "format": "json",
        }
        if _PT_KEY:
            payload["app_key"] = _PT_KEY

        t0 = time.monotonic()
        r = _get_session().post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={"User-Agent": "phishtank/LinkCheck-1.0"},
            timeout=_TIMEOUT,
        )
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        data    = r.json()
        results = data.get("results", {})

        in_db     = results.get("in_database", False)
        is_phish  = results.get("valid", False)  # community-verified phish
        verified  = results.get("verified", False)

        result.update({
            "available":    True,
            "in_database":  in_db,
            "is_malicious": is_phish and verified,
            "verified":     verified,
            "phish_id":     results.get("phish_id"),
            "phish_detail": results.get("phish_detail_url"),
            "elapsed_ms":   elapsed,
        })

        if is_phish:
            logger.warning("[PhishTank] PHISHING %s (verified=%s)", url[:50], verified)

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout >{_TIMEOUT}s"
        logger.warning("[PhishTank] Timeout for %s", url[:50])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error("[PhishTank] Error: %s", e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. GOOGLE SAFE BROWSING
# Doc : https://developers.google.com/safe-browsing/v4/lookup-api
# Gratuit : 10 000 req/jour (clé Google Cloud requise)
# Couvre : malware, phishing, unwanted software, social engineering
# ─────────────────────────────────────────────────────────────────────────────

def _google_safe_browsing(url: str) -> dict:
    """
    Query Google Safe Browsing Lookup API v4.
    Returns threat types if URL is flagged.
    Requires GOOGLE_SAFE_BROWSING_API_KEY in .env
    """
    result = {"source": "google_safe_browsing", "available": False, "error": None}

    if not _GSB_KEY:
        result["error"] = "API key not configured (GOOGLE_SAFE_BROWSING_API_KEY)"
        return result

    payload = {
        "client": {"clientId": "linkcheck", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",     # phishing, deceptive pages
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":     ["ANY_PLATFORM"],
            "threatEntryTypes":  ["URL"],
            "threatEntries":     [{"url": url}],
        },
    }

    try:
        t0 = time.monotonic()
        r = _get_session().post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={_GSB_KEY}",
            json=payload,
            timeout=_TIMEOUT,
        )
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}: {r.text[:100]}"
            return result

        data    = r.json()
        matches = data.get("matches", [])

        threat_types = list({m["threatType"] for m in matches})

        result.update({
            "available":    True,
            "is_malicious": bool(matches),
            "threat_types": threat_types,
            "match_count":  len(matches),
            "elapsed_ms":   elapsed,
        })

        if matches:
            logger.warning("[GSB] FLAGGED %s — threats=%s", url[:50], threat_types)

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout >{_TIMEOUT}s"
        logger.warning("[GSB] Timeout for %s", url[:50])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error("[GSB] Error: %s", e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. IPQUALITYSCORE
# Doc : https://www.ipqualityscore.com/documentation/malicious-url-scanner-api
# Gratuit : 200 req/jour (clé requise, inscription gratuite)
# Détecte : phishing, malware, parking, spamming, short URLs
# ─────────────────────────────────────────────────────────────────────────────

def _ipqualityscore(url: str) -> dict:
    """
    Query IPQualityScore Malicious URL Scanner.
    Rich output: phishing score, malware, parking, spamming, DNS info.
    Requires IPQS_API_KEY in .env
    """
    result = {"source": "ipqualityscore", "available": False, "error": None}

    if not _IPQS_KEY:
        result["error"] = "API key not configured (IPQS_API_KEY)"
        return result

    try:
        encoded_url = quote(url, safe="")
        endpoint    = f"https://www.ipqualityscore.com/api/json/url/{_IPQS_KEY}/{encoded_url}"

        t0 = time.monotonic()
        r = _get_session().get(
            endpoint,
            params={
                "strictness":       1,      # 0=lenient, 1=balanced, 2=strict
                "fast":             False,  # full scan (slower but more accurate)
                "timeout":          5,
            },
            timeout=_TIMEOUT,
        )
        elapsed = round((time.monotonic() - t0) * 1000)

        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        data = r.json()

        if not data.get("success"):
            result["error"] = data.get("message", "Unknown IPQS error")
            return result

        risk_score = data.get("risk_score", 0)   # 0–100

        phishing = bool(data.get("phishing", False))
        malware = bool(data.get("malware", False))
        suspicious = bool(data.get("suspicious", False))

        result.update({
            "available":      True,
            "risk_score":     risk_score,
            "is_malicious":   phishing or malware or risk_score >= 90 or (risk_score >= 80 and suspicious),
            "phishing":       phishing,
            "malware":        malware,
            "suspicious":     suspicious,
            "parking":        data.get("parking", False),   # domaine parké = suspect
            "spamming":       data.get("spamming", False),
            "adult":          data.get("adult", False),
            "category":       data.get("category", ""),
            "domain_rank":    data.get("domain_rank"),      # Alexa-like rank
            "dns_valid":      data.get("dns_valid", True),
            "server":         data.get("server", ""),
            "content_type":   data.get("content_type", ""),
            "elapsed_ms":     elapsed,
        })

        if result["is_malicious"]:
            logger.warning("[IPQS] RISK %d — phishing=%s malware=%s url=%s",
                           risk_score, data.get("phishing"), data.get("malware"), url[:50])

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout >{_TIMEOUT}s"
        logger.warning("[IPQS] Timeout for %s", url[:50])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error("[IPQS] Error: %s", e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATEUR PRINCIPAL
# Lance toutes les APIs disponibles en parallèle
# ─────────────────────────────────────────────────────────────────────────────

# Mapping nom → fonction
_APIS = {
    "virustotal":          _virustotal,
    "urlhaus":             _urlhaus,
    "phishtank":           _phishtank,
    "google_safe_browsing": _google_safe_browsing,
    "ipqualityscore":      _ipqualityscore,
}


def _unused_cached_threat_intel(url: str) -> dict:
    """
    Internal cached version. Cache key = URL.
    TTL géré par le wrapper public (pas de TTL natif sur lru_cache).
    """
    return _run_all_apis(url)


_cache_timestamps: dict[str, float] = {}
_CACHE_TTL = 600  # 10 minutes
_CACHE_MAXSIZE = 512
_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = Lock()


def query_all(url: str) -> dict:
    """
    Public entry point. Runs all configured APIs in parallel and returns
    an aggregated result with individual source details.

    Result structure:
    {
        "is_malicious": bool,          # True if ANY API flagged it
        "threat_score": int,           # 0-100, weighted aggregate
        "sources": {
            "virustotal":   {...},
            "urlhaus":      {...},
            "phishtank":    {...},
            "google_safe_browsing": {...},
            "ipqualityscore": {...},
        },
        "flagged_by": ["virustotal", "urlhaus"],  # sources that flagged
        "elapsed_ms": int,
    }
    """
    # Cache avec TTL manuel (lru_cache ne supporte pas le TTL natif)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(url)
        if cached and (now - cached[0]) < _CACHE_TTL:
            logger.debug("[TI] Cache hit for %s", url[:50])
            return copy.deepcopy(cached[1])

    result = _run_all_apis(url)
    with _cache_lock:
        if len(_cache) >= _CACHE_MAXSIZE:
            oldest_url = min(_cache, key=lambda key: _cache[key][0])
            _cache.pop(oldest_url, None)
        _cache[url] = (now, copy.deepcopy(result))
    return result

    # Mettre à jour le cache
    _cached_threat_intel.cache_clear()  # vide le cache précédent pour cette URL
    _cache_timestamps[url] = now
    # On ne peut pas injecter dans lru_cache directement, donc on rappelle
    # pour populer le cache avec le nouveau résultat
    _cached_threat_intel.__wrapped__ = lambda u: result  # type: ignore
    return result


def _run_all_apis(url: str) -> dict:
    """Execute all APIs concurrently and aggregate results."""
    t0 = time.monotonic()

    # Soumettre toutes les APIs en parallèle
    futures: dict[Future, str] = {
        _API_POOL.submit(fn, url): name
        for name, fn in _APIS.items()
    }

    sources: dict[str, dict] = {}

    # Collecter les résultats avec timeout global de 8s
    try:
        for future in as_completed(futures, timeout=8):
            name = futures[future]
            try:
                sources[name] = future.result()
            except Exception as e:
                sources[name] = {
                    "source":    name,
                    "available": False,
                    "error":     f"Future error: {type(e).__name__}: {e}",
                }
                logger.error("[TI] Future failed for %s: %s", name, e)
    except TimeoutError:
        logger.warning("[TI] Global timeout for %s", url[:50])

    for future, name in futures.items():
        if name not in sources:
            future.cancel()
            sources[name] = {
                "source":    name,
                "available": False,
                "error":     "Global timeout >8s",
            }

    # ── Agrégation ────────────────────────────────────────────────
    flagged_by = [
        name for name, src in sources.items()
        if src.get("available") and src.get("is_malicious")
    ]

    # Score de menace agrégé (pondéré par fiabilité de chaque source)
    weights = {
        "virustotal":           0.35,   # le plus fiable
        "google_safe_browsing": 0.25,   # très fiable, faux positifs rares
        "ipqualityscore":       0.20,   # bon signal complémentaire
        "urlhaus":              0.12,   # spécialisé malware
        "phishtank":            0.08,   # spécialisé phishing mais parfois lent
    }

    weighted_sum   = 0.0
    weight_used    = 0.0

    for name, src in sources.items():
        if not src.get("available"):
            continue
        w = weights.get(name, 0.1)

        # Normaliser le score de chaque source vers 0-100
        if name == "virustotal":
            raw = src.get("risk_score", 100 if src.get("is_malicious") else 0)
        elif name == "ipqualityscore":
            raw = src.get("risk_score", 0)
        elif name == "google_safe_browsing":
            raw = 95 if src.get("is_malicious") else 0
        elif name == "urlhaus":
            raw = 90 if src.get("is_malicious") else 0
        elif name == "phishtank":
            raw = 95 if src.get("is_malicious") else 0
        else:
            raw = 0

        weighted_sum += raw * w
        weight_used  += w

    threat_score = round(weighted_sum / weight_used) if weight_used > 0 else 0
    is_malicious = len(flagged_by) >= 1  # une seule source suffit

    elapsed = round((time.monotonic() - t0) * 1000)

    logger.info(
        "[TI] %s — score=%d flagged_by=%s (%dms)",
        url[:50], threat_score, flagged_by, elapsed,
    )

    return {
        "is_malicious": is_malicious,
        "threat_score": threat_score,
        "flagged_by":   flagged_by,
        "sources":      sources,
        "elapsed_ms":   elapsed,
        "apis_checked": len([s for s in sources.values() if s.get("available")]),
        "apis_skipped": len([s for s in sources.values() if not s.get("available")]),
    }


def query_all_async(url: str) -> Future:
    """
    Lance query_all() dans le thread pool et retourne immédiatement un Future.
    Utilisé dans analyzer.py pour ne pas bloquer Flask.

    Exemple:
        future = query_all_async(url)
        # ... autres traitements ...
        ti_result = future.result(timeout=10)
    """
    return _ASYNC_POOL.submit(query_all, url)
