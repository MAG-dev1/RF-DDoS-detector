# Servidor TCP con Detección Segura por RandomForest

## Qué es
Proyecto de investigación que detecta y **mitiga ataques DDoS/análogos** en un servidor TCP local usando un modelo RandomForest combinado con reglas simples. El sistema **solo bloquea** cuando el modelo ML y una regla heurística coinciden, y tras detecciones repetidas para reducir falsos positivos.

## Objetivo
Evaluar una estrategia híbrida (ML + reglas) para:
- detectar patrones anómalos en ventanas cortas de tráfico,
- tomar decisiones de bloqueo temporales,
- minimizar falsos positivos exigiendo consenso y repeticiones.

## Arquitectura (alto nivel)
- **Sniffer (scapy)** en hilo separado: captura flags TCP y actualiza un mapa de flags por flujo.
- **Servidor TCP** (selectors): acepta conexiones, recibe datos y los apila por IP en ventanas temporales.
- **Extractor de features**: agrupa paquetes por ventana (WINDOW_SEC) y calcula features (p. ej. `packet_count`, `syn_count`, `total_bytes`, entropías, tiempos).
- **Clasificador RandomForest**: modelo cargado desde `datos/rf_ddos_model.joblib` que predice si la ventana es maliciosa.
- **Reglas simples**: pre-filtro (p. ej. umbral de SYN y de número de paquetes). Solo si RF=1 **y** alguna regla se cumple, se cuenta una detección.
- **Mecanismo de detección acumulada**: requiere `DETECT_THRESHOLD` detecciones dentro de `DETECT_WINDOW` segundos para bloquear temporalmente la IP.
- **Blacklist temporal**: bloqueos por `BLACKLIST_SEC` segundos; expiración automática.

## Comportamiento clave
- Ventanas deslizantes por IP (por defecto 2s).
- Se requiere un mínimo de paquetes (`MIN_PKTS_TO_EVAL`) para invocar al modelo.
- Se registra cada detección en `detection_log.csv`.
- Bloqueo solo tras detecciones repetidas.
- Si se detecta y bloquea, el servidor puede lanzar excepción para señalizar ataque (`SystemError`).

## Archivos importantes
- `server_rf_safe.py` — código principal.
- `datos/rf_ddos_model.joblib` — modelo RandomForest entrenado.
- `datos/rf_ddos_model.joblib.meta` — (opcional) metadata con orden de features.
- `detection_log.csv` — log de detecciones.

## Requisitos mínimos
- Python 3.8+
- `scapy`
- `pandas`
- `joblib` (sklearn)
- Permisos para sniffing en la interfaz (si se usa sniffer)
- Ejecutar en entorno donde la escucha en puerto 8080 sea posible

## Configuración rápida
- `MODEL_PATH`, `META_PATH` — rutas del modelo.
- `HOST`, `PORT` — host/puerto del servidor.
- `WINDOW_SEC` — duración de la ventana de análisis.
- `MIN_PKTS_TO_EVAL`, `SYN_RULE`, `PKT_RULE` — umbrales para evaluación y reglas.
- `DETECT_THRESHOLD`, `DETECT_WINDOW`, `BLACKLIST_SEC` — parámetros de conteo y bloqueo.

## Cómo usar
1. Coloca el modelo (`.joblib`) en `datos/`.
2. `pip install scapy pandas joblib`
3. Ejecutar: `python3 server_rf_safe.py`
4. Generar tráfico hacia `HOST:PORT` para probar detección y bloqueo.
5. Revisar `detection_log.csv` para eventos registrados.
