"""
train.py — Entraînement du modèle LinkCheck depuis les fichiers Parquet.

Pourquoi Parquet et pas le scraping ZIP ?
  - Les fichiers Training.parquet / Testing.parquet contiennent déjà
    des milliers de sites pré-analysés avec leurs vraies features HTML.
  - Scraper des URLs en live est lent, nécessite internet, et plante
    si un site ne répond pas.
  - Le Parquet est fiable, rapide, reproductible.

Ce script ne fait AUCUNE requête réseau.
"""

import os
import sys
import time
import logging
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from features import FEATURE_NAMES

# ── Logs ───────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("linkcheck.train")

# ── Chemins ────────────────────────────────────────────────────────────────────
TRAIN_PATH = "data/extracted/Training.parquet"
TEST_PATH  = "data/extracted/Testing.parquet"
MODEL_OUT  = "model.pkl"
FEAT_OUT   = "features.pkl"


# ── Chargement ─────────────────────────────────────────────────────────────────

def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    for path in (TRAIN_PATH, TEST_PATH):
        if not os.path.exists(path):
            logger.error("Fichier introuvable : %s", path)
            logger.error("Placez Training.parquet et Testing.parquet dans data/extracted/")
            sys.exit(1)

    logger.info("Chargement de %s ...", TRAIN_PATH)
    df_train = pd.read_parquet(TRAIN_PATH)
    logger.info("  → %d lignes, %d colonnes", len(df_train), len(df_train.columns))

    logger.info("Chargement de %s ...", TEST_PATH)
    df_test = pd.read_parquet(TEST_PATH)
    logger.info("  → %d lignes, %d colonnes", len(df_test), len(df_test.columns))

    return df_train, df_test


# ── Préparation ────────────────────────────────────────────────────────────────

def prepare(df_train: pd.DataFrame, df_test: pd.DataFrame):
    """
    Sépare X/y, aligne les colonnes, gère les valeurs manquantes.
    Retourne X_train, y_train, X_test, y_test, feature_names.
    """
    # Colonnes à exclure (non numériques / label)
    drop = [c for c in ["url", "status"] if c in df_train.columns]

    X_train = df_train.drop(columns=drop)
    X_test  = df_test.drop(columns=[c for c in drop if c in df_test.columns])

    # Label
    if "status" not in df_train.columns:
        logger.error("Colonne 'status' introuvable. Colonnes disponibles : %s",
                     list(df_train.columns))
        sys.exit(1)

    y_train = df_train["status"]
    y_test  = df_test["status"]

    # Vérification alignement
    if list(X_train.columns) != list(X_test.columns):
        logger.error("Les colonnes de Train et Test ne correspondent pas !")
        only_train = set(X_train.columns) - set(X_test.columns)
        only_test  = set(X_test.columns)  - set(X_train.columns)
        if only_train: logger.error("  Seulement dans Train : %s", only_train)
        if only_test:  logger.error("  Seulement dans Test  : %s", only_test)
        sys.exit(1)

    # Valeurs manquantes → 0
    missing_train = X_train.isnull().sum().sum()
    missing_test  = X_test.isnull().sum().sum()
    if missing_train or missing_test:
        logger.warning("Valeurs manquantes : %d (train), %d (test) → remplacées par 0",
                       missing_train, missing_test)
    X_train = X_train.fillna(0)
    X_test  = X_test.fillna(0)

    feature_names = X_train.columns.tolist()
    logger.info("Features utilisées : %d", len(feature_names))

    # Distribution des labels
    for name, y in [("Train", y_train), ("Test", y_test)]:
        counts = y.value_counts().to_dict()
        logger.info("  %s → %s", name, counts)

    return X_train, y_train, X_test, y_test, feature_names


# ── Entraînement ───────────────────────────────────────────────────────────────

def train(X_train, y_train, X_test, y_test, feature_names):
    logger.info("Entraînement RandomForest (100 arbres, max_depth=20)...")
    t0 = time.time()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,          # tous les cœurs CPU
        class_weight="balanced",  # compense si classes déséquilibrées
    )
    model.fit(X_train, y_train)
    elapsed = round(time.time() - t0, 1)
    logger.info("Entraînement terminé en %ss", elapsed)

    # Évaluation
    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    logger.info("Accuracy : %.2f%%", acc * 100)
    print("\n" + classification_report(y_test, y_pred))

    # Top 10 features les plus importantes
    importances = sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:10]
    logger.info("Top 10 features :")
    for name, imp in importances:
        logger.info("  %-35s %.4f", name, imp)

    # Sauvegarde
    joblib.dump(model, MODEL_OUT)
    joblib.dump(feature_names, FEAT_OUT)   # CORRECTION : était X.columns dans l'original
    logger.info("Sauvegardé : %s, %s", MODEL_OUT, FEAT_OUT)
    logger.info("Prêt — lancez `python run.py` pour démarrer le serveur.")


# ── Point d'entrée ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    df_train, df_test       = load_data()
    X_train, y_train, X_test, y_test, feature_names = prepare(df_train, df_test)
    train(X_train, y_train, X_test, y_test, feature_names)
