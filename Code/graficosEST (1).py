import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set(style="whitegrid")

# ---------------- CONFIG ----------------
estimators = 100  # Cambiá este valor al que quieras analizar
file = f"100EST.csv"

# ---------------- CARGA DATOS ----------------
df = pd.read_csv(file)

# Convertir timestamp a tiempo relativo (opcional)
df['time_sec'] = df['timestamp'] - df['timestamp'].min()

# ---------------- GRAFICOS ----------------
fig, axes = plt.subplots(2, 2, figsize=(12, 8))

# 1. Detecciones vs tiempo
sns.lineplot(ax=axes[0,0], data=df, x='time_sec', y='pred', marker="o")
axes[0,0].set_title(f"Detecciones vs Tiempo (estimators={estimators})")
axes[0,0].set_xlabel("Tiempo (s) relativo")
axes[0,0].set_ylabel("Predicción (0=normal, 1=ataque)")

# 2. Packet count vs tiempo
sns.lineplot(ax=axes[0,1], data=df, x='time_sec', y='packet_count', marker="o")
axes[0,1].set_title("Packet count vs Tiempo")
axes[0,1].set_xlabel("Tiempo (s) relativo")
axes[0,1].set_ylabel("Packet count")

# 3. SYN count vs tiempo
sns.lineplot(ax=axes[1,0], data=df, x='time_sec', y='syn_count', marker="o", color='red')
axes[1,0].set_title("SYN count vs Tiempo")
axes[1,0].set_xlabel("Tiempo (s) relativo")
axes[1,0].set_ylabel("SYN count")

# 4. Probabilidad de predicción positiva vs tiempo
sns.lineplot(ax=axes[1,1], data=df, x='time_sec', y='prob', marker="o", color='green')
axes[1,1].set_title("Probabilidad de predicción positiva")
axes[1,1].set_xlabel("Tiempo (s) relativo")
axes[1,1].set_ylabel("Probabilidad")
axes[1,1].set_ylim(0, 1)

plt.tight_layout()
plt.show()
