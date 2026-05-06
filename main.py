# main.py
# LinkCheck Flask server — HTTP entry point.
# All analysis logic is in analyzer.py.

import os
import re
import zipfile
import json
import logging
import requests
from datetime import datetime
from functools import lru_cache

import pandas as pd
from flask import Flask, abort, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_cors import CORS


def _load_dotenv(path: str = ".env") -> None:
    """Load environment variables from .env file if it exists."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


_load_dotenv()

from analyzer import analyze_url

# ── Logging ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("linkcheck.main")

# ── App Flask ────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

CORS(app, resources={r"/analyze": {"origins": "*"}})  # Secure the /analyze route with CORS

def _rate_key() -> str:
    """
    Extract client IP from request headers or connection.
    Centralized function to avoid duplication.
    
    Returns:
        IP address string for rate limiting key
    """
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

limiter = Limiter(
    app=app,
    key_func=_rate_key,
    default_limits=["30 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# ── Tranco ───────────────────────────────────────────────────────────────

_TRANCO_PATH = "data/tranco_GV97K-1m.csv.zip"
_REPUTATION: dict[str, int] = {}
DISCORD_FEEDBACK_WEBHOOK = os.environ.get("DISCORD_FEEDBACK_WEBHOOK")
FEEDBACK_STORAGE_PATH = os.environ.get("FEEDBACK_STORAGE_PATH", "data/feedback.jsonl")
FEEDBACK_ADMIN_TOKEN = os.environ.get("FEEDBACK_ADMIN_TOKEN")


def _load_tranco() -> None:
    """Load Tranco reputation database for domain reputation scoring."""
    global _REPUTATION
    if not os.path.exists(_TRANCO_PATH):
        logger.info("[main] Tranco missing — reputation scoring disabled")
        return
    try:
        with zipfile.ZipFile(_TRANCO_PATH) as z, z.open(z.namelist()[0]) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=800_000)
            _REPUTATION = dict(zip(df["domain"], df["rank"]))
        logger.info("[main] Tranco loaded: %d domains", len(_REPUTATION))
    except Exception as e:
        logger.error("[main] Tranco load failed: %s", e)


@lru_cache(maxsize=2048)
def _tranco_score(rank: int | None) -> int:
    """
    Calculate trust score based on Tranco ranking with caching.
    
    Args:
        rank: Tranco rank (1-800000) or None if not ranked
    
    Returns:
        Trust score (0-100)
    """
    if rank is None:
        return 40
    if rank <= 1000:
        return 100
    if rank <= 10_000:
        return 90
    if rank <= 100_000:
        return 80
    if rank <= 800_000:
        return 70
    return 50


def _combine_trust(result: dict) -> int:
    """
    Combine multiple trust signals into a single score.
    
    Weights:
    - ML trust: 35%
    - Heuristic: 20%
    - Tranco: 20%
    - Threat intelligence: 15%
    - SSL: 5%
    - DNS: 5%
    """
    if result.get("verdict") == "safe" and any(
        "Trusted site" in str(reason.get("text", ""))
        for reason in result.get("reasons", [])
    ):
        return 100

    ml = result.get("ml_score")
    heuristic = result.get("heuristic_score")
    ssl = result.get("ssl_info", {}).get("trust_score")
    dns = result.get("dns_info", {}).get("trust_score")
    tranco = result.get("tranco_score")
    threat = result.get("threat_intel", {})

    ml_trust = 100 - ml if ml is not None else 50
    heuristic_trust = 100 - heuristic if heuristic is not None else 50
    ssl_trust = ssl if ssl is not None else 50
    dns_trust = dns if dns is not None else 50
    tranco_trust = tranco if tranco is not None else 50
    if threat.get("available"):
        threat_trust = 0 if threat.get("is_malicious") else max(0, 100 - int(threat.get("threat_score") or 0))
    else:
        threat_trust = 50

    clean_reputation = (
        result.get("verdict") == "safe"
        and threat.get("available")
        and int(threat.get("apis_checked") or 0) >= 3
        and not threat.get("flagged_by")
    )
    if clean_reputation:
        ml_trust = max(ml_trust, 70)
        threat_trust = max(threat_trust, 90)

    score = (
        ml_trust * 0.35 +
        heuristic_trust * 0.2 +
        tranco_trust * 0.2 +
        threat_trust * 0.15 +
        ssl_trust * 0.05 +
        dns_trust * 0.05
    )
    score = round(score)
    if clean_reputation:
        score = max(score, 80)
    return score


_load_tranco()


# ── Routes ───────────────────────────────────────────────────────────────

@app.get("/")
def index():
    """Serve the main UI."""
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    """Analyze a URL from the UI and return structured JSON."""
    return api_analyze()


@app.post("/api/analyze")
def api_analyze():
    """
    Developer API: analyze a URL and return structured JSON.
    
    Request body:
    {
        "url": "https://example.com"
    }
    
    Returns:
    JSON with detailed analysis (score, verdict, reasons, etc.)
    """
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Missing URL", "code": "MISSING_URL"}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL too long (max 2000 characters)", "code": "URL_TOO_LONG"}), 400

    logger.info("[api] %s → %s", _rate_key(), url[:80])
    result = analyze_url(url)

    # Tranco enrichment
    domain = result.get("analyzed_host", "")
    rank = _REPUTATION.get(domain) or _REPUTATION.get(".".join(domain.split(".")[-2:]))

    if rank:
        result["tranco_rank"] = rank
        if rank <= 1000:
            result["score"] = max(0, round(result["score"] * 0.6))
            result["verdict"] = "safe" if result["score"] <= 40 else result["verdict"]
            result["is_phishing"] = result["verdict"] != "safe"
            result["reasons"].insert(0, {
                "text": f"Site très populaire (Tranco #{rank}) - confiance boostée",
                "points": -25, "severity": "safe",
            })
        elif rank <= 10_000:
            result["score"] = max(0, round(result["score"] * 0.8))
            result["reasons"].insert(0, {
                "text": f"Site populaire (Tranco #{rank}) - confiance ajustée",
                "points": -20, "severity": "safe",
            })
        elif rank <= 100_000:
            result["score"] = max(0, round(result["score"] * 0.9))
            result["reasons"].insert(0, {
                "text": f"Site connu (Tranco #{rank})",
                "points": -10, "severity": "info",
            })
        elif rank <= 800_000:
            result["score"] = max(0, round(result["score"] * 0.95))
            result["reasons"].insert(0, {
                "text": f"Popular domain (Tranco #{rank}) - moderate trust",
                "points": -5, "severity": "info",
            })
        else:
            result["reasons"].append({
                "text": f"Rang Tranco élevé (#{rank}) - réputation faible",
                "points": 0, "severity": "info",
            })
        result["tranco_score"] = _tranco_score(rank)
    else:
        result["tranco_rank"] = None
        result["tranco_score"] = _tranco_score(None)

    result["trust_score"] = _combine_trust(result)
    return jsonify(result)


def _send_feedback_to_discord(payload: dict) -> tuple[bool, str]:
    """Send feedback payload to Discord webhook."""
    if not DISCORD_FEEDBACK_WEBHOOK:
        return False, "Discord webhook not configured"
    try:
        resp = requests.post(DISCORD_FEEDBACK_WEBHOOK, json=payload, timeout=5)
        if not resp.ok:
            return False, f"Discord HTTP {resp.status_code}"
        return True, "OK"
    except Exception as e:
        return False, str(e)


def _store_feedback_record(record: dict) -> None:
    """Store feedback record as JSONL."""
    storage_folder = os.path.dirname(FEEDBACK_STORAGE_PATH)
    if storage_folder:
        os.makedirs(storage_folder, exist_ok=True)
    with open(FEEDBACK_STORAGE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _authorize_admin() -> None:
    """Verify admin token from Authorization header or query param."""
    if not FEEDBACK_ADMIN_TOKEN:
        abort(403, description="Feedback admin token not configured")
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.args.get("token", "").strip()
    if token != FEEDBACK_ADMIN_TOKEN:
        abort(401, description="Invalid admin token")


def _load_feedback_records(limit: int | None = None) -> list[dict]:
    """Load feedback records from JSONL file."""
    if not os.path.exists(FEEDBACK_STORAGE_PATH):
        return []
    records = []
    with open(FEEDBACK_STORAGE_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None and len(records) > limit:
        return records[-limit:]
    return records


@app.get("/admin/feedback")
@limiter.limit("30 per minute")
def admin_feedback():
    """Serve admin feedback UI."""
    _authorize_admin()
    return render_template("admin_feedback.html")


@app.get("/admin/feedback/json")
@limiter.limit("30 per minute")
def admin_feedback_json():
    """Get feedback records as JSON."""
    _authorize_admin()
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit else None
    except ValueError:
        limit_value = None
    return jsonify(_load_feedback_records(limit=limit_value))


@app.get("/admin/feedback/download")
@limiter.limit("10 per minute")
def admin_feedback_download():
    """Download feedback file."""
    _authorize_admin()
    if not os.path.exists(FEEDBACK_STORAGE_PATH):
        return jsonify({"error": "No feedback file found"}), 404
    return send_file(
        FEEDBACK_STORAGE_PATH,
        mimetype="application/json",
        as_attachment=True,
        download_name=os.path.basename(FEEDBACK_STORAGE_PATH)
    )


@app.post("/feedback")
@limiter.limit("10 per minute")
def feedback():
    """Accept and store user feedback on analysis results."""
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()
    if not url:
        return jsonify({"error": "Missing URL", "code": "MISSING_URL"}), 400

    analyzed_host = str(body.get("analyzed_host", "")).strip()
    verdict = str(body.get("verdict", "")).strip()
    score = body.get("score")
    comment = str(body.get("comment", "")).strip() or "No comment provided"

    embed = {
        "username": "LinkCheck Feedback",
        "embeds": [
            {
                "title": "New false positive report",
                "description": f"**URL**: {url}\n**Analyzed host**: {analyzed_host or 'N/A'}\n**Score**: {score}/100\n**Verdict**: {verdict}",
                "color": 15329363,
                "fields": [
                    {"name": "Comment", "value": comment[:1024]},
                ],
                "footer": {"text": "LinkCheck UI feedback"},
            }
        ]
    }

    record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "analyzed_host": analyzed_host,
        "score": score,
        "verdict": verdict,
        "comment": comment,
        "discord_webhook_configured": bool(DISCORD_FEEDBACK_WEBHOOK),
    }

    try:
        _store_feedback_record(record)
    except Exception as e:
        logger.error("[main] Feedback storage failed: %s", e)
        return jsonify({"error": "Unable to save feedback locally", "detail": str(e)}), 500

    sent, error = _send_feedback_to_discord(embed)
    if sent:
        return jsonify({"status": "ok", "message": "Feedback sent"}), 200

    logger.warning("[main] Discord feedback fallback: %s", error)
    return jsonify({
        "status": "ok",
        "message": "Feedback received and saved on server",
        "detail": error,
    }), 200


_RE_SAFE = re.compile(r'[^a-zA-Z0-9_]')

@app.get("/screenshot/<path:hostname>")
@limiter.limit("60 per minute")
def screenshot(hostname: str):
    """
    Poll for screenshot. Returns 202 if not ready, or PNG if available.
    
    Endpoint for checking if a screenshot was generated for a URL analysis.
    """
    safe = _RE_SAFE.sub("", hostname)[:40]
    path = os.path.join("static", "screenshots", f"{safe}.png")
    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    return jsonify({"status": "pending"}), 202


@app.errorhandler(404)
def _404(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def _500(e):
    logger.error("[main] 500 : %s", e)
    return jsonify({"error": "Erreur serveur"}), 500


# ── Launch ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("[main] Starting — limit 30 req/min (analyze endpoint)")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        threaded=True
    )
