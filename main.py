# main.py
# Serveur Flask LinkCheck — point d'entrée HTTP.
# Toute la logique d'analyse est dans analyzer.py.

import os
import re
import zipfile
import logging
import requests

import pandas as pd
from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter


def _load_dotenv(path: str = ".env") -> None:
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

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("linkcheck.main")

# ── App Flask ─────────────────────────────────────────────────────────────────

app = Flask(__name__)

def _rate_key() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

limiter = Limiter(_rate_key, app=app, default_limits=["30 per minute"])

# ── Tranco ────────────────────────────────────────────────────────────────────

_TRANCO_PATH = "data/tranco_GV97K-1m.csv.zip"
_REPUTATION: dict[str, int] = {}
DISCORD_FEEDBACK_WEBHOOK = os.environ.get("DISCORD_FEEDBACK_WEBHOOK")


def _load_tranco() -> None:
    global _REPUTATION
    if not os.path.exists(_TRANCO_PATH):
        logger.info("[main] Tranco absent — réputation désactivée")
        return
    try:
        with zipfile.ZipFile(_TRANCO_PATH) as z, z.open(z.namelist()[0]) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=800_000)
            _REPUTATION = dict(zip(df["domain"], df["rank"]))
        logger.info("[main] Tranco chargé : %d domaines", len(_REPUTATION))
    except Exception as e:
        logger.error("[main] Tranco KO : %s", e)


def _tranco_score(rank: int | None) -> int:
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
    ml = result.get("ml_score")
    heuristic = result.get("heuristic_score")
    ssl = result.get("ssl_info", {}).get("trust_score")
    dns = result.get("dns_info", {}).get("trust_score")
    tranco = result.get("tranco_score")

    ml_trust = ml if ml is not None else 50
    heuristic_trust = 100 - heuristic if heuristic is not None else 50
    ssl_trust = ssl if ssl is not None else 50
    dns_trust = dns if dns is not None else 50
    tranco_trust = tranco if tranco is not None else 50

    score = (
        ml_trust * 0.4 +
        heuristic_trust * 0.2 +
        tranco_trust * 0.2 +
        ssl_trust * 0.1 +
        dns_trust * 0.1
    )
    return round(score)


_load_tranco()



# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() if request.headers.get("X-Forwarded-For") else (request.remote_addr or "unknown")

    body = request.get_json(silent=True) or {}
    url  = str(body.get("url", "")).strip()

    if not url:
        return jsonify({"error": "URL vide"}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL trop longue (max 2000 car.)"}), 400

    logger.info("[main] %s → %s", ip, url[:80])
    result = analyze_url(url)

    # Enrichissement Tranco (IA + Réputation)
    domain = result.get("analyzed_host", "")
    rank   = _REPUTATION.get(domain) or _REPUTATION.get(".".join(domain.split(".")[-2:]))

    if rank:
        result["tranco_rank"] = rank
        if rank <= 1000:
            result["score"] = max(0, round(result["score"] * 0.6))
            result["verdict"] = "safe" if result["score"] <= 40 else result["verdict"]
            result["is_phishing"] = result["verdict"] != "safe"
            result["reasons"].insert(0, {
                "text": f"Site très populaire (Tranco #{rank}) - confiance renforcée",
                "points": -25, "severity": "safe",
            })
        elif rank <= 10_000:
            result["score"] = max(0, round(result["score"] * 0.8))
            result["reasons"].insert(0, {
                "text": f"Site populaire (Tranco #{rank}) - ajustement de confiance",
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
                "text": f"Domaine populaire (Tranco #{rank}) - confiance modérée",
                "points": -5, "severity": "info",
            })
        else:
            result["reasons"].append({
                "text": f"Rang Tranco élevé (#{rank}) - pas de réputation forte",
                "points": 0, "severity": "info",
            })
        result["tranco_score"] = _tranco_score(rank)
    else:
        result["tranco_rank"] = None
        result["tranco_score"] = _tranco_score(None)

    result["trust_score"] = _combine_trust(result)
    return jsonify(result)


def _send_feedback_to_discord(payload: dict) -> tuple[bool, str]:
    if not DISCORD_FEEDBACK_WEBHOOK:
        return False, "Webhook Discord non configuré"
    try:
        resp = requests.post(DISCORD_FEEDBACK_WEBHOOK, json=payload, timeout=5)
        if not resp.ok:
            return False, f"Discord HTTP {resp.status_code}"
        return True, "OK"
    except Exception as e:
        return False, str(e)


@app.post("/feedback")
def feedback():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()
    if not url:
        return jsonify({"error": "URL manquante"}), 400

    analyzed_host = str(body.get("analyzed_host", "")).strip()
    verdict = str(body.get("verdict", "")).strip()
    score = body.get("score")
    comment = str(body.get("comment", "")).strip() or "Aucun commentaire fourni"

    embed = {
        "username": "LinkCheck Feedback",
        "embeds": [
            {
                "title": "Nouveau signalement de faux positif",
                "description": f"**URL**: {url}\n**Hôte analysé**: {analyzed_host or 'N/A'}\n**Score**: {score}/100\n**Verdict**: {verdict}",
                "color": 15329363,
                "fields": [
                    {"name": "Commentaire", "value": comment[:1024]},
                ],
                "footer": {"text": "LinkCheck UI feedback"},
            }
        ]
    }

    sent, error = _send_feedback_to_discord(embed)
    if not sent:
        logger.warning("[main] Feedback Discord KO : %s", error)
        return jsonify({"error": "Impossible d'envoyer le feedback", "detail": error}), 502

    return jsonify({"status": "ok", "message": "Feedback envoyé"}), 200


_RE_SAFE = re.compile(r'[^a-zA-Z0-9_]')

@app.get("/screenshot/<path:hostname>")
def screenshot(hostname: str):
    """Polling : retourne l'image si prête, 202 sinon."""
    safe = _RE_SAFE.sub("", hostname)[:40]
    path = os.path.join("static", "screenshots", f"{safe}.png")
    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    return jsonify({"status": "pending"}), 202


@app.errorhandler(404)
def _404(e):
    return jsonify({"error": "Introuvable"}), 404


@app.errorhandler(500)
def _500(e):
    logger.error("[main] 500 : %s", e)
    return jsonify({"error": "Erreur serveur"}), 500


# ── Lancement ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("[main] Démarrage — limite 30 req/min")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true", threaded=True)