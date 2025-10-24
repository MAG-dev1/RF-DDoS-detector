import pandas as pd
import ast
import matplotlib.pyplot as plt

# Leer el CSV
df = pd.read_csv("detection_log.csv")

# Convertir 'features' de texto a dict
df["features"] = df["features"].apply(ast.literal_eval)

# Extraer campos básicos
df["packet_count"] = df["features"].apply(lambda x: x["packet_count"])
df["psh_count"] = df["features"].apply(lambda x: x["psh_count"])
df["ack_count"] = df["features"].apply(lambda x: x["ack_count"])
df["syn_count"] = df["features"].apply(lambda x: x["syn_count"])
df["tcp_count"] = df["features"].apply(lambda x: x["tcp_count"])
df["unique_src"] = df["features"].apply(lambda x: x["unique_src"])

# Calcular métricas adicionales
df["psh_rate"] = df["psh_count"] / df["packet_count"]
df["ack_rate"] = df["ack_count"] / df["packet_count"]
df["syn_ratio"] = df["syn_count"] / df["tcp_count"]
df["packets_per_src"] = df["packet_count"] / df["unique_src"]

# Lista de gráficos a mostrar
graphs = [
    ("PSH Count vs Packet Count", df["packet_count"], df["psh_count"], "Packet Count", "PSH Count"),
    ("PSH Rate", df.index, df["psh_rate"], "Window", "PSH Rate"),
    ("ACK Rate", df.index, df["ack_rate"], "Window", "ACK Rate"),
    ("SYN Ratio", df.index, df["syn_ratio"], "Window", "SYN Ratio"),
    ("Packets per Source", df.index, df["packets_per_src"], "Window", "Packets per Source")
]

# Función para navegar entre gráficos
class GraphNavigator:
    def __init__(self, graphs):
        self.graphs = graphs
        self.idx = 0
        self.fig, self.ax = plt.subplots()
        self.plot_graph()
        self.fig.canvas.mpl_connect('key_press_event', self.on_key)
        plt.show()

    def plot_graph(self):
        self.ax.clear()
        title, x, y, xlabel, ylabel = self.graphs[self.idx]
        self.ax.scatter(x, y, color="blue", alpha=0.7)
        self.ax.set_xlabel(xlabel)
        self.ax.set_ylabel(ylabel)
        self.ax.set_title(title)
        self.ax.grid(True)
        self.fig.canvas.draw()

    def on_key(self, event):
        if event.key == 'right':
            self.idx = (self.idx + 1) % len(self.graphs)
            self.plot_graph()
        elif event.key == 'left':
            self.idx = (self.idx - 1) % len(self.graphs)
            self.plot_graph()

# Iniciar el navegador de gráficos
GraphNavigator(graphs)
