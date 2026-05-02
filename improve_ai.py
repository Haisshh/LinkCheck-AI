#!/usr/bin/env python3
"""
Pipeline complet pour améliorer l'IA LinkCheck :
1. Préparer les données
2. Entraîner le modèle de base
3. Optimiser les hyperparamètres
4. Évaluer les performances
"""

import subprocess
import sys

def run_command(cmd, description):
    print(f"\n=== {description} ===")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de {description}: {e}")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        sys.exit(1)

def main():
    print("🚀 Démarrage du pipeline d'amélioration de l'IA LinkCheck")

    # Étape 1: Préparer les données
    run_command("python prepare_data.py", "Préparation des données")

    # Étape 2: Entraînement de base
    run_command("python train.py", "Entraînement du modèle de base")

    # Étape 3: Optimisation des hyperparamètres
    run_command("python tune.py", "Optimisation des hyperparamètres")

    # Étape 4: Évaluation
    run_command("python evaluate.py", "Évaluation des modèles")

    print("\n✅ Pipeline terminé !")
    print("Modèles sauvegardés : model.pkl (base), model_tuned.pkl (optimisé)")
    print("Lancez 'python run.py' pour utiliser l'IA.")

if __name__ == "__main__":
    main()