import os
import sys
import time
import logging
import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import GridSearchCV, cross_validate
from sklearn.utils.class_weight import compute_sample_weight

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("linkcheck.tune")

TRAIN_PATH = "data/extracted/Training.parquet"
TEST_PATH  = "data/extracted/Testing.parquet"
MODEL_OUT  = "model_tuned.pkl"
FEAT_OUT   = "features.pkl"

def load_data():
    for p in (TRAIN_PATH, TEST_PATH):
        if not os.path.exists(p):
            logger.error("Fichier manquant : %s", p)
            sys.exit(1)
    train = pd.read_parquet(TRAIN_PATH)
    test  = pd.read_parquet(TEST_PATH)
    logger.info("Train : %d lignes | Test : %d lignes", len(train), len(test))
    return train, test

def prepare_data(train, test):
    if "status" not in train.columns:
        logger.error("Colonne 'status' absente.")
        sys.exit(1)

    drop_cols = {"url", "status"}
    drop_t = [c for c in drop_cols if c in train.columns]
    drop_e = [c for c in drop_cols if c in test.columns]

    X_train, y_train = train.drop(columns=drop_t).fillna(0), train["status"]
    X_test,  y_test  = test.drop(columns=drop_e).fillna(0),  test["status"]

    if list(X_train.columns) != list(X_test.columns):
        only_tr = set(X_train.columns) - set(X_test.columns)
        only_te = set(X_test.columns)  - set(X_train.columns)
        logger.error("Colonnes désalignées — train only : %s | test only : %s", only_tr, only_te)
        sys.exit(1)

    feat_names = X_train.columns.tolist()
    logger.info("%d features", len(feat_names))

    return X_train, y_train, X_test, y_test, feat_names

def tune_and_train(X_train, y_train, X_test, y_test, feat_names):
    logger.info("Optimisation des hyperparamètres avec GridSearchCV…")

    param_grid = {
        'max_iter': [100, 200, 300],
        'learning_rate': [0.01, 0.1, 0.2],
        'max_leaf_nodes': [31, 63, 127],
        'max_depth': [None, 10, 20],
    }

    model = HistGradientBoostingClassifier(random_state=42, early_stopping=True, validation_fraction=0.1)

    grid_search = GridSearchCV(
        estimator=model,
        param_grid=param_grid,
        cv=3,
        scoring='accuracy',
        n_jobs=-1,
        verbose=1
    )

    sample_weight = compute_sample_weight("balanced", y_train)
    grid_search.fit(X_train, y_train, sample_weight=sample_weight)

    logger.info("Meilleurs paramètres : %s", grid_search.best_params_)
    logger.info("Meilleure CV accuracy : %.2f%%", grid_search.best_score_ * 100)

    best_model = grid_search.best_estimator_

    # Evaluate on the test set
    y_pred = best_model.predict(X_test)
    logger.info("Accuracy sur test : %.2f%%", accuracy_score(y_test, y_pred) * 100)
    print(classification_report(y_test, y_pred))

    # Top features
    if hasattr(best_model, 'feature_importances_'):
        top10 = sorted(zip(feat_names, best_model.feature_importances_), key=lambda x: x[1], reverse=True)[:10]
        logger.info("Top 10 features :")
        for name, imp in top10:
            logger.info("  %-38s %.4f", name, imp)
    else:
        logger.info("Feature importances not available for this model.")

    # Sauvegarde
    joblib.dump(best_model, MODEL_OUT)
    joblib.dump(feat_names, FEAT_OUT)
    logger.info("Modèle tuné sauvegardé : %s", MODEL_OUT)

if __name__ == "__main__":
    train_df, test_df = load_data()
    X_train, y_train, X_test, y_test, feat_names = prepare_data(train_df, test_df)
    tune_and_train(X_train, y_train, X_test, y_test, feat_names)