"""
simulator.py
Generates realistic network log entries, injecting 3 types of anomalies:
  - Port scan      (one external IP hitting many sequential ports rapidly)
  - Latency spike  (sudden jump to 500-2000 ms for a burst of packets)
  - UDP flood      (DDoS-style: many packets from same IP in a short window)
"""

import random
from datetime import datetime, timedelta

INTERNAL_IPS  = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.0.5", "10.0.0.8"]
GATEWAY_IP    = "192.168.1.1"
ATTACKER_IP   = "45.33.32.156"   # known-bad external IP
COMMON_PORTS  = [80, 443, 22, 3306, 5432, 8080, 53, 8443]
PROTOCOLS     = ["TCP", "UDP", "ICMP"]


def _make_entry(t: datetime, src: str, dst: str, proto: str,
                sport: int, dport: int, size: int,
                latency: float, flags: str = "", anomaly: bool = False) -> dict:
    return {
        "timestamp":  t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "src":        src,
        "dst":        dst,
        "protocol":   proto,
        "sport":      sport,
        "dport":      dport,
        "size":       size,
        "latency_ms": round(latency, 2),
        "flags":      flags,
        "anomaly":    anomaly,
    }


def generate_logs(n: int = 200, inject_anomalies: bool = True) -> list[dict]:
    """Return a list of log-entry dicts sorted by timestamp."""
    base_time = datetime.now()
    logs = []

    # ── Normal traffic ────────────────────────────────────────
    for i in range(n):
        t       = base_time + timedelta(seconds=i * 0.5)
        src     = random.choice(INTERNAL_IPS)
        proto   = random.choice(PROTOCOLS)
        dport   = random.choice(COMMON_PORTS)
        logs.append(_make_entry(
            t, src, GATEWAY_IP, proto,
            sport   = random.randint(49152, 65535),
            dport   = dport,
            size    = random.randint(64, 1500),
            latency = random.uniform(1.0, 20.0),
            flags   = "SYN" if proto == "TCP" else "",
        ))

    if not inject_anomalies:
        return sorted(logs, key=lambda x: x["timestamp"])

    # ── Anomaly 1: Port scan ──────────────────────────────────
    # External IP probes 20 sequential ports very quickly
    scan_t = base_time + timedelta(seconds=random.randint(40, 80))
    for j in range(20):
        t = scan_t + timedelta(milliseconds=j * 150)
        logs.append(_make_entry(
            t, ATTACKER_IP, GATEWAY_IP, "TCP",
            sport   = random.randint(1024, 65535),
            dport   = j + 1,        # ports 1-20 sequentially
            size    = 40,
            latency = 0.5,
            flags   = "SYN",
            anomaly = True,
        ))

    # ── Anomaly 2: Latency spike ──────────────────────────────
    # 6 consecutive packets from a normal host suddenly jump to 500-2000 ms
    spike_idx = random.randint(60, n - 10)
    for j in range(6):
        logs[spike_idx + j]["latency_ms"] = round(random.uniform(500, 2000), 2)
        logs[spike_idx + j]["anomaly"]    = True

    # ── Anomaly 3: UDP flood (DDoS) ───────────────────────────
    # Attacker hammers port 80 with 35 rapid UDP packets
    flood_t = base_time + timedelta(seconds=random.randint(90, 130))
    for j in range(35):
        t = flood_t + timedelta(milliseconds=j * 40)   # 40 ms apart → ~25 pps
        logs.append(_make_entry(
            t, ATTACKER_IP, GATEWAY_IP, "UDP",
            sport   = random.randint(1024, 65535),
            dport   = 80,
            size    = random.randint(900, 1500),
            latency = random.uniform(80, 400),
            anomaly = True,
        ))

    return sorted(logs, key=lambda x: x["timestamp"])
