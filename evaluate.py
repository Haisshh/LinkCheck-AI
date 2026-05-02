import os
import sys
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix

MODEL_PATH = "model.pkl"
TUNED_MODEL_PATH = "model_tuned.pkl"
FEAT_PATH = "features.pkl"
TEST_PATH = "data/extracted/Testing.parquet"

def load_model_and_data(model_path):
    if not os.path.exists(model_path):
        print(f"Modèle {model_path} introuvable.")
        return None, None

    if not os.path.exists(FEAT_PATH):
        print(f"Features {FEAT_PATH} introuvables.")
        return None, None

    if not os.path.exists(TEST_PATH):
        print(f"Données de test {TEST_PATH} introuvables.")
        return None, None

    model = joblib.load(model_path)
    feat_names = joblib.load(FEAT_PATH)
    test_df = pd.read_parquet(TEST_PATH)

    # Préparer X_test, y_test
    drop_cols = {"url", "status"}
    drop_e = [c for c in drop_cols if c in test_df.columns]
    X_test = test_df.drop(columns=drop_e).fillna(0)
    y_test = test_df["status"] if "status" in test_df.columns else test_df["label"]

    # Assurer que les colonnes correspondent
    X_test = X_test[feat_names]

    return model, X_test, y_test

def evaluate_model(model, X_test, y_test, name):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

    print(f"\n=== Évaluation du modèle : {name} ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score: {f1_score(y_test, y_pred):.4f}")
    if y_proba is not None:
        print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    print("\nMatrice de confusion:")
    print(confusion_matrix(y_test, y_pred))

    print("\nRapport de classification:")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    # Évaluer le modèle original
    model_orig, X_test, y_test = load_model_and_data(MODEL_PATH)
    if model_orig:
        evaluate_model(model_orig, X_test, y_test, "Original")

    # Évaluer le modèle tuné
    model_tuned, _, _ = load_model_and_data(TUNED_MODEL_PATH)
    if model_tuned:
        evaluate_model(model_tuned, X_test, y_test, "Tuné")