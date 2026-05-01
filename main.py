"""
LinkCheck — Serveur principal Flask
"""

from flask import Flask, render_template, request, jsonify
from analyzer import analyze_url
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# 1. Configuration du Limiteur (Version Pro)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
limiter.init_app(app)

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("5 per minute")  # La sécurité est ici !
def analyze():
    # On récupère les données JSON envoyées par le frontend
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Champ 'url' manquant"}), 400

    url = data.get("url", "").strip()

    # Validation de sécurité basique
    if not url:
        return jsonify({"error": "L'URL est vide"}), 400
        
    if len(url) > 2000:
        return jsonify({"error": "URL trop longue"}), 400

    # Lancement de l'analyse via analyzer.py
    # On retourne directement le dictionnaire de résultats
    resultat = analyze_url(url)
    return jsonify(resultat)

# --- GESTION DES ERREURS ---

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Du calme ! Vous envoyez trop de requêtes. Attendez une minute."
    }), 429

if __name__ == "__main__":
    app.run(debug=True)