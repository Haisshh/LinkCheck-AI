#!/bin/bash

# Script de déploiement pour LinkCheck AI

echo "🚀 Déploiement de LinkCheck AI..."

# Vérifier si Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé. Installez Docker d'abord."
    exit 1
fi

# Construire l'image
echo "🔨 Construction de l'image Docker..."
docker build -t linkcheck-ai .

# Lancer le conteneur
echo "▶️  Lancement du conteneur..."
docker run -d \
    --name linkcheck-ai \
    -p 5000:5000 \
    -e FLASK_DEBUG=false \
    -v $(pwd)/data:/app/data \
    -v $(pwd)/static:/app/static \
    linkcheck-ai

echo "✅ Application déployée sur http://localhost:5000"
echo "📊 Logs : docker logs -f linkcheck-ai"
echo "🛑 Arrêt : docker stop linkcheck-ai && docker rm linkcheck-ai"