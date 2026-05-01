"""
main.py — Serveur Flask LinkCheck.

CORRECTIONS :
  - analyze_url() importée depuis analyzer.py — main.py ne réimplémente plus rien
  - model None vérifié avant predict_proba (évite le crash si model.pkl absent)
  - Whitelist vérifiée sur le domaine parsé, pas sur l'URL brute
    (évite le faux positif "http://evil.com/lycee-passwords")
  - urlparse importé en haut — pas à l'intérieur d'une fonction
  - Rate limiting + threaded=True conservés
"""

import os
import re
import time
import logging
import zipfile
from collections import defaultdict
from urllib.parse import urlparse

import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify, send_file

from analyzer import analyze_url   # source unique d'analyse — pas de doublon

# ── Logs ───────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("linkcheck.main")

app = Flask(__name__)

# ── Tranco (réputation de domaine) ────────────────────────────────────────────
TRANCO_ZIP    = "data/tranco_GV97K-1m.csv.zip"
REPUTATION_DB: dict[str, int] = {}


def load_tranco():
    global REPUTATION_DB
    if not os.path.exists(TRANCO_ZIP):
        logger.info("[main] Tranco introuvable — vérification de réputation désactivée")
        return
    try:
        with zipfile.ZipFile(TRANCO_ZIP) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=800_000)
                REPUTATION_DB = dict(zip(df["domain"], df["rank"]))
        logger.info("[main] Tranco chargé : %d domaines", len(REPUTATION_DB))
    except Exception as e:
        logger.error("[main] Erreur chargement Tranco : %s", e)


load_tranco()

# ── Rate limiting ──────────────────────────────────────────────────────────────
_rate_data: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT  = 30   # requêtes max
RATE_WINDOW = 60   # par fenêtre en secondes


def _check_rate_limit(ip: str) -> bool:
    now    = time.time()
    cutoff = now - RATE_WINDOW
    _rate_data[ip] = [t for t in _rate_data[ip] if t > cutoff]
    if len(_rate_data[ip]) >= RATE_LIMIT:
        logger.warning("[rate-limit] %s bloquée (%d req/%ds)", ip, len(_rate_data[ip]), RATE_WINDOW)
        return False
    _rate_data[ip].append(now)
    return True


def _get_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    ip = _get_ip()
    if not _check_rate_limit(ip):
        return jsonify({"error": "Trop de requêtes. Limite : 30/minute."}), 429

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Champ 'url' manquant"}), 400

    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "URL vide"}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL trop longue (max 2000 car.)"}), 400

    logger.info("[main] Analyse demandée par %s : %s", ip, url[:80])

    # Délègue TOUT à analyzer.py — main.py ne fait aucune analyse
    result = analyze_url(url)

    # Enrichissement Tranco si domaine connu
    domain = result.get("analyzed_host", "")
    rank   = (
        REPUTATION_DB.get(domain)
        or REPUTATION_DB.get(".".join(domain.split(".")[-2:]))
    )
    if rank:
        result["tranco_rank"] = rank
        # Un domaine très bien classé (top 10 000) abaisse le score final
        if rank <= 10_000 and result["verdict"] != "safe":
            result["score"]   = round(result["score"] * 0.3)
            result["verdict"] = "safe" if result["score"] <= 30 else "suspect"
            result["reasons"].insert(0, {
                "text":     f"Domaine bien classé Tranco (rang #{rank})",
                "points":   0,
                "severity": "safe"
            })
    else:
        result["tranco_rank"] = None

    return jsonify(result)


@app.route("/screenshot/<path:hostname>")
def get_screenshot(hostname: str):
    """Polling endpoint — retourne la capture quand elle est prête."""
    safe = re.sub(r'[^a-zA-Z0-9_\-]', '', hostname)[:40]
    path = os.path.join("static", "screenshots", f"{safe}.png")
    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    return jsonify({"status": "pending"}), 202


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint introuvable"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("[main] Erreur 500 : %s", e)
    return jsonify({"error": "Erreur interne du serveur"}), 500


# ── Lancement ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("[main] Démarrage — rate limit : %d req/%ds", RATE_LIMIT, RATE_WINDOW)
    # threaded=True obligatoire : sans ça, le screenshot async bloque quand même Flask
    app.run(debug=True, threaded=True)
