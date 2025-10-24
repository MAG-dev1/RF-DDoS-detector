import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# --- Config ---
NORMAL_CSV = "normal.csv"
ATTACK_CSV = "ddos.csv"
MODEL_OUT = "rf_ddos_model.joblib"

# --- Cargar datasets ---
df_normal = pd.read_csv(NORMAL_CSV)
df_attack = pd.read_csv(ATTACK_CSV)

# --- Etiquetar ---
df_normal["label"] = 0
df_attack["label"] = 1

# --- Unir datasets ---
df = pd.concat([df_normal, df_attack], ignore_index=True)

# --- Features y target ---
X = df.drop(columns=["label"])
y = df["label"]

# --- Split ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# --- Entrenar Random Forest ---
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

# --- Evaluación ---
y_pred = rf.predict(X_test)
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

# --- Guardar modelo ---
joblib.dump(rf, MODEL_OUT)
print(f"Modelo guardado en {MODEL_OUT}")
