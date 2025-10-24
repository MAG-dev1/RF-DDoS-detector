# Script to convert raw Wireshark CSV (export) into ML-ready features for DDoS detection.
# - Reads a Wireshark-exported CSV with columns similar to the sample you sent:
#   "No.","Time","Source","Destination","Protocol","Length","Info"
# - Produces two outputs:
#   1) per-packet features CSV (features_packets.csv)
#   2) aggregated per-window features CSV (features_windows.csv) — ideal for Random Forest
# - Window size is configurable (default 1.0 second).
# - No external libraries besides pandas and numpy are required.
# Usage example:
#   python transform_wireshark.py --input wireshark_raw.csv --window 1.0 --out-prefix output
# If input doesn't exist, script will just print instructions.
import os
import re
import argparse
from collections import Counter, defaultdict
import math

import pandas as pd
import numpy as np

FLAG_RE = re.compile(r'\[([A-Z, ,]+)\]')
PORT_PAIR_RE = re.compile(r'(\d+)\s*>\s*(\d+)')

def parse_flags(info):
    """Return set of flags found in Info field (e.g., 'SYN', 'ACK', 'FIN', 'PSH', 'RST')."""
    m = FLAG_RE.search(info)
    if not m:
        return set()
    flags = m.group(1)
    # Split by comma or space and remove empty
    parts = re.split(r'[,\s]+', flags)
    return set([p for p in parts if p])

def parse_ports(info):
    """Try to extract src and dst ports from Info field. Returns (src_port, dst_port) or (None,None)."""
    m = PORT_PAIR_RE.search(info)
    if not m:
        return (None, None)
    try:
        return int(m.group(1)), int(m.group(2))
    except:
        return (None, None)

def entropy_of_list(items):
    """Shannon entropy base e of list of hashable items"""
    if len(items) == 0:
        return 0.0
    c = Counter(items)
    total = sum(c.values())
    ent = 0.0
    for v in c.values():
        p = v / total
        ent -= p * math.log(p + 1e-12)
    return ent

def packet_features_from_df(df):
    """Return per-packet dataframe with extracted numeric features."""
    times = df['Time'].astype(float).values
    lengths = df['Length'].astype(int).values
    protocols = df['Protocol'].astype(str).values
    infos = df['Info'].astype(str).values
    srcs = df['Source'].astype(str).values
    dsts = df['Destination'].astype(str).values

    records = []
    prev_time = None
    for i, t in enumerate(times):
        time_diff = t - prev_time if prev_time is not None else 0.0
        prev_time = t
        info = infos[i]
        flags = parse_flags(info)
        src_port, dst_port = parse_ports(info)
        prot = protocols[i].upper()
        rec = {
            'time': t,
            'time_diff': time_diff,
            'packet_size': lengths[i],
            'protocol': prot,
            'is_tcp': 1 if 'TCP' in prot else 0,
            'is_udp': 1 if 'UDP' in prot else 0,
            'is_icmp': 1 if 'ICMP' in prot else 0,
            'flags_SYN': 1 if 'SYN' in flags else 0,
            'flags_ACK': 1 if 'ACK' in flags else 0,
            'flags_FIN': 1 if 'FIN' in flags else 0,
            'flags_PSH': 1 if 'PSH' in flags else 0,
            'flags_RST': 1 if 'RST' in flags else 0,
            'src_ip': srcs[i],
            'dst_ip': dsts[i],
            'src_port': src_port,
            'dst_port': dst_port,
            'raw_info': info
        }
        records.append(rec)
    return pd.DataFrame.from_records(records)

def aggregate_windows(df_packets, window_size=1.0):
    """Aggregate per-packet features into fixed windows (seconds). Returns dataframe per-window."""
    if df_packets.empty:
        return pd.DataFrame()
    start = df_packets['time'].min()
    end = df_packets['time'].max()
    # compute window index for each packet
    df = df_packets.copy()
    df['win_idx'] = ((df['time'] - start) // window_size).astype(int)
    groups = df.groupby('win_idx')

    agg_records = []
    for win_idx, g in groups:
        win_start = start + win_idx * window_size
        packet_count = len(g)
        tcp_count = g['is_tcp'].sum()
        udp_count = g['is_udp'].sum()
        icmp_count = g['is_icmp'].sum()
        syn_count = g['flags_SYN'].sum()
        ack_count = g['flags_ACK'].sum()
        fin_count = g['flags_FIN'].sum()
        psh_count = g['flags_PSH'].sum()
        rst_count = g['flags_RST'].sum()
        total_bytes = g['packet_size'].sum()
        avg_packet_size = g['packet_size'].mean() if packet_count>0 else 0
        mean_time_diff = g['time_diff'].mean() if packet_count>0 else 0
        std_time_diff = g['time_diff'].std(ddof=0) if packet_count>1 else 0.0
        unique_src = g['src_ip'].nunique()
        unique_dst = g['dst_ip'].nunique()
        unique_src_ports = g['src_port'].nunique(dropna=True)
        unique_dst_ports = g['dst_port'].nunique(dropna=True)
        src_entropy = entropy_of_list(g['src_ip'].tolist())
        dst_entropy = entropy_of_list(g['dst_ip'].tolist())

        rec = {
            'win_idx': win_idx,
            'win_start': win_start,
            'packet_count': packet_count,
            'tcp_count': int(tcp_count),
            'udp_count': int(udp_count),
            'icmp_count': int(icmp_count),
            'syn_count': int(syn_count),
            'ack_count': int(ack_count),
            'fin_count': int(fin_count),
            'psh_count': int(psh_count),
            'rst_count': int(rst_count),
            'total_bytes': int(total_bytes),
            'avg_packet_size': float(avg_packet_size),
            'mean_time_diff': float(mean_time_diff),
            'std_time_diff': float(std_time_diff),
            'unique_src': int(unique_src),
            'unique_dst': int(unique_dst),
            'unique_src_ports': int(unique_src_ports if not np.isnan(unique_src_ports) else 0),
            'unique_dst_ports': int(unique_dst_ports if not np.isnan(unique_dst_ports) else 0),
            'src_entropy': float(src_entropy),
            'dst_entropy': float(dst_entropy),
            # Derived ratios (helpful for RF)
            'syn_ratio': float(syn_count / packet_count) if packet_count>0 else 0.0,
            'tcp_ratio': float(tcp_count / packet_count) if packet_count>0 else 0.0,
            'avg_bytes_per_packet': float(total_bytes / packet_count) if packet_count>0 else 0.0
        }
        agg_records.append(rec)
    return pd.DataFrame.from_records(agg_records).sort_values('win_idx').reset_index(drop=True)

def load_wireshark_csv(path):
    """Load Wireshark CSV export robustly. Expects column names including Time, Source, Destination, Protocol, Length, Info."""
    # Use pandas read_csv with quotechar='"' to handle Wireshark format
    df = pd.read_csv(path, quotechar='"', skipinitialspace=True, engine='python')
    # Normalize column names
    df_cols = [c.strip().strip('"') for c in df.columns]
    df.columns = df_cols
    # Accept columns possibly named slightly different (e.g., 'No.' or 'No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
    required = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
    for r in required:
        if r not in df.columns:
            raise ValueError(f"Column '{r}' not found in CSV. Columns found: {df.columns.tolist()}")
    return df[required].copy()

def main():
    parser = argparse.ArgumentParser(description='Transform raw Wireshark CSV to ML-ready features for DDoS detection.')
    parser.add_argument('--input', '-i', required=True, help='Input Wireshark CSV file path')
    parser.add_argument('--window', '-w', type=float, default=1.0, help='Window size in seconds for aggregation (default 1.0)')
    parser.add_argument('--out-prefix', '-o', default='features', help='Output prefix for CSVs')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Input file '{args.input}' not found. Please export your capture from Wireshark as CSV with columns: Time, Source, Destination, Protocol, Length, Info.")
        return

    print("Loading CSV...")
    df_raw = load_wireshark_csv(args.input)
    print(f"Rows loaded: {len(df_raw)}")

    print("Extracting per-packet features...")
    df_packets = packet_features_from_df(df_raw)
    packets_out = f"{args.out_prefix}_packets.csv"
    df_packets.to_csv(packets_out, index=False)
    print(f"Per-packet features saved to {packets_out}")

    print(f"Aggregating into windows of {args.window} second(s)...")
    df_windows = aggregate_windows(df_packets, window_size=args.window)
    windows_out = f"{args.out_prefix}_windows.csv"
    df_windows.to_csv(windows_out, index=False)
    print(f"Per-window features saved to {windows_out}")

    print("Done. Recommended next steps:\n - Label the windows (0 normal, 1 DoS) according to when attacks happened.\n - Use the windows CSV for training a RandomForest (better) than per-packet.\n - Try different window sizes (0.5s, 1s, 2s) and feature selection.")

if __name__ == '__main__':
    main()
