#!/usr/bin/env python3
"""
Complete pipeline for improving the LinkCheck AI:
1. Prepare data
2. Train base model
3. Tune hyperparameters
4. Evaluate performance
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

    # Step 1: Prepare data
    run_command("python prepare_data.py", "Prepare data")

    # Step 2: Train base model
    run_command("python train.py", "Train base model")

    # Step 3: Tune hyperparameters
    run_command("python tune.py", "Tune hyperparameters")

    # Step 4: Evaluate
    run_command("python evaluate.py", "Evaluate models")

    print("\n✅ Pipeline terminé !")
    print("Modèles sauvegardés : model.pkl (base), model_tuned.pkl (optimisé)")
    print("Lancez 'python run.py' pour utiliser l'IA.")

if __name__ == "__main__":
    main()