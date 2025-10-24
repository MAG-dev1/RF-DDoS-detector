#!/usr/bin/env python3
# server_rf_safe.py
"""
Servidor TCP con RandomForest (modo seguro).
Only blocks when RF + simple rule agree, and only after repeated detections.
"""

import joblib, math, socket, selectors, types, time, csv
from collections import defaultdict, deque, Counter
import pandas as pd

# -------- Config (ajusta si querés) --------
MODEL_PATH = "datos/rf_ddos_model.joblib"
META_PATH = MODEL_PATH + ".meta"
HOST = "127.0.0.1"
PORT = 8080

WINDOW_SEC = 2             # ventana por IP en segundos (mayor reduce falsos)
MIN_PKTS_TO_EVAL = 1      # mínimo paquetes en la ventana para considerar predicción
DETECT_THRESHOLD = 3       # cantidad de detecciones (coincidentes) antes de bloquear
DETECT_WINDOW = 15         # segundos para contar detecciones
BLACKLIST_SEC = 300        # bloqueo temporal (s)
DETECT_LOG = "detection_log.csv"

# Reglas simples (pre-filtro). Si cualquiera se cumple + RF=1 -> cuenta detección.
SYN_RULE = 5               # si syn_count >= SYN_RULE consideramos sospechoso
PKT_RULE = 50              # si packet_count >= PKT_RULE consideramos sospechoso

# -------- Cargar modelo y features (robusto) --------
rf = joblib.load(MODEL_PATH)
try:
    meta = joblib.load(META_PATH)
    model_feature_list = list(meta.get("feature_cols", []))
except Exception:
    feat_tmp = getattr(rf, "feature_names_in_", None)
    model_feature_list = list(feat_tmp) if feat_tmp is not None else []

# fallback: columnas típicas de ventanas si no hay metadata
if not model_feature_list:
    model_feature_list = [
        "win_idx","win_start","packet_count","tcp_count","udp_count","icmp_count",
        "syn_count","ack_count","fin_count","psh_count","rst_count","total_bytes",
        "avg_packet_size","mean_time_diff","std_time_diff","unique_src","unique_dst",
        "unique_src_ports","unique_dst_ports","src_entropy","dst_entropy",
        "syn_ratio","tcp_ratio","avg_bytes_per_packet"
    ]

print("[MODEL] loaded. feature count =", len(model_feature_list))

# -------- Estado in-memory --------
# buckets[ip] holds tuples: (ts, length, proto, flags, dst_port)
buckets = defaultdict(lambda: deque())
# window start per ip (float seconds)
window_start = defaultdict(lambda: 0.0)
BLACKLIST = {}                        # ip -> unblock_ts
detections = defaultdict(lambda: deque())  # ip -> deque of detection timestamps

# setup detection log header if not exists
try:
    open(DETECT_LOG, 'x').close()
    with open(DETECT_LOG, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["ts","ip","port","reason","features"])
except FileExistsError:
    pass

# -------- Helpers --------
def is_blacklisted(ip):
    return ip in BLACKLIST and BLACKLIST[ip] > time.time()

def block_ip(ip, seconds=BLACKLIST_SEC):
    BLACKLIST[ip] = time.time() + seconds
    print(f"[BLOCK] {ip} blocked for {seconds}s")

def log_detection(ts, ip, port, reason, features):
    with open(DETECT_LOG, "a", newline='') as f:
        w = csv.writer(f)
        w.writerow([ts, ip, port, reason, features])

def compute_window_features_from_list(window_pkts, win_start):
    """window_pkts: list of tuples (ts,length,proto,flags,port) all inside window."""
    if not window_pkts:
        return None
    pkts_count = len(window_pkts)
    tcp_count = sum(1 for _, _, proto, _, _ in window_pkts if proto == 'TCP')
    udp_count = sum(1 for _, _, proto, _, _ in window_pkts if proto == 'UDP')
    icmp_count = sum(1 for _, _, proto, _, _ in window_pkts if proto == 'ICMP')

    syn_count = sum(1 for _, _, _, flags, _ in window_pkts if 'SYN' in (flags or "").upper())
    ack_count = sum(1 for _, _, _, flags, _ in window_pkts if 'ACK' in (flags or "").upper())
    fin_count = sum(1 for _, _, _, flags, _ in window_pkts if 'FIN' in (flags or "").upper())
    psh_count = sum(1 for _, _, _, flags, _ in window_pkts if 'PSH' in (flags or "").upper())
    rst_count = sum(1 for _, _, _, flags, _ in window_pkts if 'RST' in (flags or "").upper())

    total_bytes = sum(length for _, length, _, _, _ in window_pkts)
    avg_packet_size = total_bytes / pkts_count if pkts_count else 0.0

    times = [t for t, _, _, _, _ in window_pkts]
    inter_times = [t2 - t1 for t1, t2 in zip(times, times[1:])] or [0.0]
    mean_time_diff = sum(inter_times) / len(inter_times)
    std_time_diff = (sum((x - mean_time_diff) ** 2 for x in inter_times) / len(inter_times)) ** 0.5

    unique_src = len(set([ip for ip, _, _, _, _ in window_pkts]))
    unique_dst = len(set([dst for _, _, _, dst, _ in window_pkts]))
    unique_src_ports = len(set([sport for _, _, _, _, sport in window_pkts]))
    unique_dst_ports = len(set([dport for _, _, _, _, dport in window_pkts]))

    # entropy approximations (if you need better, compute exact distribution)
    def shannon_entropy(items):
        if not items: return 0.0
        c = Counter(items)
        total = sum(c.values())
        ent = 0.0
        for v in c.values():
            p = v / total
            ent -= p * math.log(p + 1e-12)
        return ent

    src_entropy = shannon_entropy([ip for ip, _, _, _, _ in window_pkts])
    dst_entropy = shannon_entropy([dst for _, _, _, dst, _ in window_pkts])

    syn_ratio = syn_count / pkts_count if pkts_count else 0.0
    tcp_ratio = tcp_count / pkts_count if pkts_count else 0.0
    avg_bytes_per_packet = total_bytes / pkts_count if pkts_count else 0.0

    feats = {
        "win_idx": int(win_start),
        "win_start": float(win_start),
        "packet_count": int(pkts_count),
        "tcp_count": int(tcp_count),
        "udp_count": int(udp_count),
        "icmp_count": int(icmp_count),
        "syn_count": int(syn_count),
        "ack_count": int(ack_count),
        "fin_count": int(fin_count),
        "psh_count": int(psh_count),
        "rst_count": int(rst_count),
        "total_bytes": int(total_bytes),
        "avg_packet_size": float(avg_packet_size),
        "mean_time_diff": float(mean_time_diff),
        "std_time_diff": float(std_time_diff),
        "unique_src": int(unique_src),
        "unique_dst": int(unique_dst),
        "unique_src_ports": int(unique_src_ports),
        "unique_dst_ports": int(unique_dst_ports),
        "src_entropy": float(src_entropy),
        "dst_entropy": float(dst_entropy),
        "syn_ratio": float(syn_ratio),
        "tcp_ratio": float(tcp_ratio),
        "avg_bytes_per_packet": float(avg_bytes_per_packet)
    }
    return feats

def should_count_detection_by_rule(feats):
    """Pre-filter rules: require at least one of these to be True to accept RF detection."""
    if feats is None:
        return False
    if feats.get("packet_count", 0) >= PKT_RULE:
        return True
    if feats.get("syn_count", 0) >= SYN_RULE:
        return True
    return False

def handle_rf_and_blocking(ip, port, feats):
    """Run RF, apply rule, update detections and possibly block."""
    if feats is None:
        return False
    # safety: require minimum packets
    if feats.get("packet_count", 0) < MIN_PKTS_TO_EVAL:
        # too few packets, skip
        print(f"[SKIP] {ip} not enough pkts ({feats.get('packet_count')})")
        return False

    # Build dataframe row in the order model expects
    df_row = pd.DataFrame([{k: feats.get(k, 0) for k in model_feature_list}], columns=model_feature_list)
    try:
        pred = int(rf.predict(df_row)[0])
        if hasattr(rf, "predict_proba"):
            prob = rf.predict_proba(df_row)[0].max()
        else:
            prob = None
    except Exception as e:
        print("[ERROR] predict:", e)
        pred = 0
        prob = None

    print(f"[PRED] {ip}:{port} -> pred={pred} prob={prob} pkts={feats.get('packet_count')} syn={feats.get('syn_count')}")
    # only count detection if RF==1 AND simple rule agrees
    if pred == 1 and should_count_detection_by_rule(feats):
        now = time.time()
        detections[ip].append(now)
        # clean old detections
        while detections[ip] and detections[ip][0] < now - DETECT_WINDOW:
            detections[ip].popleft()
        log_detection(int(now), ip, port, "rf+rule", feats)
        print(f"[DETECT COUNT] {ip} detections={len(detections[ip])}")
        if len(detections[ip]) >= DETECT_THRESHOLD:
            block_ip(ip)
            print(f"[ACTION] Blocked {ip} after {len(detections[ip])} detections")
            raise SystemError("DDOS atack detected!")
            
    else:
        # log negative or rule-mismatch for debugging (optional)
        if pred == 1:
            print(f"[NO COUNT] RF=1 but rule failed for {ip} (syn={feats.get('syn_count')}, pkts={feats.get('packet_count')})")
        # if pred==0 we don't log to avoid noise
    return False

# -------- Server (live) --------
def start_live_server(host=HOST, port=PORT):
    sel = selectors.DefaultSelector()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen()
    print(f"[START] Listening on {host}:{port}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    def accept_wrapper(sock):
        conn, addr = sock.accept()
        ip = addr[0]
        print(f"[NEW] Connection from {ip}:{addr[1]}")
        if is_blacklisted(ip):
            print(f"[DROP] {ip} is blacklisted, closing connection")
            conn.close()
            return
        conn.setblocking(False)
        data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
        sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)

    def safe_close(sock, reason=""):
        try:
            addr = sock.getpeername()
        except:
            addr = ("?", "?")
        print(f"[CLOSE] {addr[0]}:{addr[1]} {reason}")
        try: sel.unregister(sock)
        except: pass
        try: sock.close()
        except: pass

    try:
        while True:
            events = sel.select(timeout=1)
            now = time.time()
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    sock = key.fileobj
                    data = key.data
                    ip = data.addr[0]
                    port = data.addr[1]

                    if mask & selectors.EVENT_READ:
                        try:
                            recv = sock.recv(4096)
                        except Exception:
                            safe_close(sock, "recv error")
                            continue
                        if not recv:
                            safe_close(sock, "client closed")
                            continue

                        # Append packet: use proto 'TCP' by default, flags empty (if you can parse flags from payload put them)
                        buckets[ip].append((time.time(), len(recv), 'TCP', '', port))
                        print(f"[RECV] {ip}:{port} {len(recv)} bytes (queue={len(buckets[ip])})")

                        # Initialize window start for ip if not set
                        if window_start[ip] == 0.0:
                            window_start[ip] = now

                        # If window time passed, evaluate window and slide
                        if now >= window_start[ip] + WINDOW_SEC:
                            # compute features for packets >= window_start[ip]
                            win_start = window_start[ip]
                            # take packets within [win_start, win_start+WINDOW_SEC)
                            window_pkts = [p for p in buckets[ip] if win_start <= p[0] < win_start + WINDOW_SEC]
                            feats = compute_window_features_from_list(window_pkts, win_start)
                            if feats:
                                # only attempt RF if minimum pkts reached
                                if feats.get("packet_count", 0) >= MIN_PKTS_TO_EVAL:
                                    blocked = handle_rf_and_blocking(ip, port, feats)
                                    if blocked:
                                        # clear bucket and close socket
                                        buckets[ip].clear()
                                        safe_close(sock, "blocked")
                                        continue
                                else:
                                    print(f"[SKIP] window too small for RF: {ip} pkts={feats.get('packet_count')}")
                            # advance window_start by WINDOW_SEC (slide)
                            # remove those packets from deque (only those < win_start + WINDOW_SEC)
                            new_deque = deque([p for p in buckets[ip] if p[0] >= win_start + WINDOW_SEC])
                            buckets[ip] = new_deque
                            window_start[ip] = win_start + WINDOW_SEC

                        # echo reply behavior
                        data.outb += recv

                    if mask & selectors.EVENT_WRITE and getattr(data, "outb", None):
                        try:
                            sent = sock.send(data.outb)
                            data.outb = data.outb[sent:]
                        except Exception:
                            safe_close(sock, "send error")

            # cleanup blacklist expirations
            expired = [ip for ip,t in list(BLACKLIST.items()) if t <= time.time()]
            for ip in expired:
                print(f"[UNBLOCK] {ip} removed from blacklist")
                del BLACKLIST[ip]

    except KeyboardInterrupt:
        print("Stopping server")
    finally:
        sel.close()

if __name__ == "__main__":
    start_live_server()
