# main.py
# Serveur Flask LinkCheck — point d'entrée HTTP.
# Toute la logique d'analyse est dans analyzer.py.

import os
import re
import zipfile
import logging

import pandas as pd
from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter

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

    # Enrichissement Tranco
    domain = result.get("analyzed_host", "")
    rank   = _REPUTATION.get(domain) or _REPUTATION.get(".".join(domain.split(".")[-2:]))
    result["tranco_rank"] = rank

    if rank and rank <= 10_000 and result["verdict"] != "safe":
        result["score"]   = round(result["score"] * 0.3)
        result["verdict"] = "safe" if result["score"] <= 30 else "suspect"
        result["reasons"].insert(0, {
            "text": f"Domaine bien classé Tranco (rang #{rank})",
            "points": 0, "severity": "safe",
        })

    return jsonify(result)


_RE_SAFE = re.compile(r'[^a-zA-Z0-9_\-]')

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