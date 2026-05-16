"""
parser.py
Parses raw log entries and produces a structured statistics dict.
The stats are what gets sent to the AI — not raw packets (too noisy).

Detects heuristically:
  - Port scan candidates  (>= 10 unique destination ports from one IP)
  - Flood candidates      (>= 30 packets from one IP in the capture window)
  - High latency events   (latency > 200 ms)
"""

import statistics
from collections import Counter, defaultdict


def _per_ip_stats(logs: list[dict]) -> dict:
    """Aggregate per-source-IP counters."""
    buckets: dict[str, dict] = defaultdict(lambda: {
        "count":        0,
        "unique_dports": set(),
        "total_bytes":  0,
        "latencies":    [],
        "protocols":    Counter(),
    })
    for log in logs:
        b = buckets[log["src"]]
        b["count"]          += 1
        b["unique_dports"].add(log["dport"])
        b["total_bytes"]    += log["size"]
        b["latencies"].append(log["latency_ms"])
        b["protocols"][log["protocol"]] += 1
    return dict(buckets)


def parse_logs(logs: list[dict]) -> dict:
    """
    Return a rich statistics summary suitable for an LLM prompt.
    Keys kept short to save tokens while remaining descriptive.
    """
    if not logs:
        return {}

    ip_buckets   = _per_ip_stats(logs)
    all_latencies = [l["latency_ms"] for l in logs]
    protocols    = Counter(l["protocol"] for l in logs)
    dport_counts = Counter(l["dport"]    for l in logs)

    # ── Per-IP summary ────────────────────────────────────────
    per_ip = {}
    suspicious_ips = []

    for ip, b in ip_buckets.items():
        unique_ports = len(b["unique_dports"])
        pkt_count    = b["count"]
        avg_lat      = round(statistics.mean(b["latencies"]), 2) if b["latencies"] else 0

        per_ip[ip] = {
            "packets":       pkt_count,
            "unique_dports": unique_ports,
            "bytes":         b["total_bytes"],
            "avg_lat_ms":    avg_lat,
            "protocols":     dict(b["protocols"]),
        }

        reasons = []
        if unique_ports >= 10:
            reasons.append(f"port scan ({unique_ports} unique destination ports)")
        if pkt_count >= 30:
            reasons.append(f"high packet rate ({pkt_count} packets)")
        if reasons:
            suspicious_ips.append({"ip": ip, "reasons": reasons})

    # ── High-latency events ───────────────────────────────────
    high_latency_events = [
        {"timestamp": l["timestamp"], "src": l["src"], "latency_ms": l["latency_ms"]}
        for l in logs if l["latency_ms"] > 200
    ]

    # ── Overall stats ─────────────────────────────────────────
    return {
        "total_packets":      len(logs),
        "unique_src_ips":     len(ip_buckets),
        "capture_window_sec": _window_seconds(logs),
        "latency": {
            "avg_ms":   round(statistics.mean(all_latencies), 2),
            "max_ms":   round(max(all_latencies), 2),
            "min_ms":   round(min(all_latencies), 2),
            "stddev_ms": round(statistics.stdev(all_latencies) if len(all_latencies) > 1 else 0, 2),
        },
        "protocol_breakdown": dict(protocols),
        "top_5_target_ports": dict(dport_counts.most_common(5)),
        "suspicious_ips":     suspicious_ips,
        "high_latency_events_count": len(high_latency_events),
        "high_latency_sample":       high_latency_events[:5],
        "per_ip_summary":            per_ip,
    }


def _window_seconds(logs: list[dict]) -> float:
    """Rough duration of the capture window in seconds."""
    try:
        from datetime import datetime
        fmt = "%Y-%m-%d %H:%M:%S.%f"
        t0  = datetime.strptime(logs[0]["timestamp"],  fmt)
        t1  = datetime.strptime(logs[-1]["timestamp"], fmt)
        return round((t1 - t0).total_seconds(), 1)
    except Exception:
        return 0.0
