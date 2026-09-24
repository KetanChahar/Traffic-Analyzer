"""
Helper functions used by the dashboard:
- saving/loading a capture session to disk
- resolving raw IPs/ports into readable hostnames/service names (cached)
- detecting likely port-scanning behaviour in a capture
"""

import socket
import joblib
import pandas as pd
from functools import lru_cache


def save_packets(packets, filename):
    joblib.dump(packets, filename)


def load_packets(filename):
    return joblib.load(filename)


# lru_cache means each unique port/IP is only resolved once per run,
# no matter how many times it shows up across the dashboard's sections.
@lru_cache(maxsize=None)
def get_port_service(port):
    try:
        if port is None or pd.isna(port):
            return ""
        return socket.getservbyport(int(port))
    except Exception:
        return str(port)


@lru_cache(maxsize=None)
def resolve_ip(ip):
    try:
        if ip is None or pd.isna(ip):
            return ""
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def detect_port_scanners(df, port_threshold=15):
    """
    Flags any source IP that talked to an unusually high number of DISTINCT
    destination ports. A normal client hits a handful of ports; a port
    scanner touches dozens/hundreds in the same capture window.
    """
    scan_df = (
        df.dropna(subset=['src_ip', 'dst_port'])
          .groupby('src_ip')['dst_port']
          .nunique()
          .reset_index(name='unique_ports_contacted')
    )
    flagged = scan_df[scan_df['unique_ports_contacted'] >= port_threshold]
    return flagged.sort_values('unique_ports_contacted', ascending=False)
