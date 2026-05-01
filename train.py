import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from features import FEATURE_NAMES

def train_beast_mode():
    if not os.path.exists("data/scraped_data.csv"):
        print("❌ Erreur : Lance d'abord scraper.py !")
        return

    print("🧠 Entraînement de l'IA en cours...")
    df = pd.read_csv("data/scraped_data.csv")
    
    # On sépare les données (X) de la réponse (y)
    X = df[FEATURE_NAMES]
    y = df['label']

    # On garde 20% des sites pour tester si l'IA ne ment pas
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Création de l'IA (Random Forest est le plus robuste pour le phishing)
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    model.fit(X_train, y_train)

    # Vérification des performances
    predictions = model.predict(X_test)
    print("\n📊 RAPPORT DE PERFORMANCE :")
    print(classification_report(y_test, predictions))

    # Sauvegarde des deux fichiers vitaux pour analyzer.py
    joblib.dump(model, "model.pkl")
    joblib.dump(FEATURE_NAMES, "features.pkl")
    print("\n✅ Modèle 'de fou' sauvegardé ! (model.pkl + features.pkl)")

if __name__ == "__main__":
    import os
    train_beast_mode()