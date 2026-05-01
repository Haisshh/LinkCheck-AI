# train.py
# Entraînement du modèle LinkCheck depuis Training.parquet / Testing.parquet.
# Aucune requête réseau. Rapide, reproductible.

import os
import sys
import time
import logging

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("linkcheck.train")

TRAIN_PATH = "data/extracted/Training.parquet"
TEST_PATH  = "data/extracted/Testing.parquet"
MODEL_OUT  = "model.pkl"
FEAT_OUT   = "features.pkl"
DROP_COLS  = {"url", "status"}


def _load() -> tuple[pd.DataFrame, pd.DataFrame]:
    for p in (TRAIN_PATH, TEST_PATH):
        if not os.path.exists(p):
            logger.error("Fichier manquant : %s", p)
            sys.exit(1)
    train = pd.read_parquet(TRAIN_PATH)
    test  = pd.read_parquet(TEST_PATH)
    logger.info("Train : %d lignes | Test : %d lignes", len(train), len(test))
    return train, test


def _prepare(train: pd.DataFrame, test: pd.DataFrame):
    if "status" not in train.columns:
        logger.error("Colonne 'status' absente. Disponibles : %s", list(train.columns))
        sys.exit(1)

    drop_t = [c for c in DROP_COLS if c in train.columns]
    drop_e = [c for c in DROP_COLS if c in test.columns]

    X_train, y_train = train.drop(columns=drop_t).fillna(0), train["status"]
    X_test,  y_test  = test.drop(columns=drop_e).fillna(0),  test["status"]

    if list(X_train.columns) != list(X_test.columns):
        only_tr = set(X_train.columns) - set(X_test.columns)
        only_te = set(X_test.columns)  - set(X_train.columns)
        logger.error("Colonnes désalignées — train only : %s | test only : %s", only_tr, only_te)
        sys.exit(1)

    feat_names = X_train.columns.tolist()
    logger.info("%d features, train=%d test=%d", len(feat_names), len(X_train), len(X_test))

    for label, y in (("train", y_train), ("test", y_test)):
        logger.info("  %s labels → %s", label, y.value_counts().to_dict())

    return X_train, y_train, X_test, y_test, feat_names


def _train_and_save(X_train, y_train, X_test, y_test, feat_names: list) -> None:
    logger.info("Entraînement RandomForest…")
    t0    = time.monotonic()
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)
    logger.info("Terminé en %.1fs", time.monotonic() - t0)

    y_pred = model.predict(X_test)
    logger.info("Accuracy : %.2f%%", accuracy_score(y_test, y_pred) * 100)
    print(classification_report(y_test, y_pred))

    top10 = sorted(zip(feat_names, model.feature_importances_),
                   key=lambda x: x[1], reverse=True)[:10]
    logger.info("Top 10 features :")
    for name, imp in top10:
        logger.info("  %-38s %.4f", name, imp)

    joblib.dump(model,      MODEL_OUT)
    joblib.dump(feat_names, FEAT_OUT)
    logger.info("Sauvegardé : %s, %s — lancez `python run.py`", MODEL_OUT, FEAT_OUT)


if __name__ == "__main__":
    train_df, test_df = _load()
    _train_and_save(*_prepare(train_df, test_df))