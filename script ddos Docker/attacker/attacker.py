# attacker/attacker.py
import os
import socket
import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

TARGET_HOST = os.environ.get("TARGET_HOST", "host.docker.internal")  # por defecto al host
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8080"))
CONC = int(os.environ.get("CONC", "50"))   # hilos por contenedor
ITER = int(os.environ.get("ITER", "1000")) # intentos por hilo
DELAY = float(os.environ.get("DELAY", "0.01"))

def worker(thread_id):
    for i in range(ITER):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((TARGET_HOST, TARGET_PORT))
                s.sendall(b'ping\n')
        except Exception:
            pass
        time.sleep(DELAY)
    logging.info(f"Hilo {thread_id} terminado")

def main():
    logging.info(f"Attacker -> target={TARGET_HOST}:{TARGET_PORT} CONC={CONC} ITER={ITER} DELAY={DELAY}")
    threads = []
    for i in range(CONC):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    logging.info("Ataque terminado")

if __name__ == "__main__":
    main()
