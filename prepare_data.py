import os
import pandas as pd
from sklearn.model_selection import train_test_split

# Charger les données
data_path = "data/scraped_data.csv"  # ou "data/memoire_ia.csv" si vous utilisez les données existantes
if not os.path.exists(data_path):
    print(f"Fichier {data_path} introuvable. Utilisez scraped_data.csv ou memoire_ia.csv.")
    exit(1)

df = pd.read_csv(data_path)

# Corriger les noms de colonnes si nécessaire (typo historique)
if 'suspecious_tld' in df.columns:
    df['suspicious_tld'] = df['suspecious_tld']
    df.drop(columns=['suspecious_tld'], inplace=True)

# Supprimer les colonnes inutiles si nécessaire (par exemple, 'url' si présente)
columns_to_drop = []
if 'url' in df.columns:
    columns_to_drop.append('url')
if 'status' in df.columns and 'status' != 'label':  # Assumer que 'label' est la cible
    columns_to_drop.append('status')

df = df.drop(columns=columns_to_drop, errors='ignore')

# Vérifier que 'label' existe
if 'label' not in df.columns:
    print("Colonne 'label' manquante dans les données.")
    exit(1)

# Remplir les NaN
df = df.fillna(0)

# Diviser en train/test (80/20)
train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label'])

# Créer le dossier si nécessaire
os.makedirs("data/extracted", exist_ok=True)

# Sauvegarder en Parquet
train_df.to_parquet("data/extracted/Training.parquet", index=False)
test_df.to_parquet("data/extracted/Testing.parquet", index=False)

print("Données préparées :")
print(f"  Entraînement : {len(train_df)} lignes")
print(f"  Test : {len(test_df)} lignes")
print(f"  Colonnes : {len(df.columns) - 1} features + label")