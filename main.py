"""
main.py
Entry point for the AI-Powered Network Log Analyzer.

Run:
    python main.py               # with anomalies injected (default)
    python main.py --clean       # clean traffic only (no anomalies)
    python main.py --logs 500    # generate 500 log entries
"""

import sys
import time
import json
from simulator import generate_logs
from parser    import parse_logs
from analyzer  import analyze

# ── ANSI color helpers ────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
B  = "\033[94m"   # blue
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEV_COLOR = {"LOW": G, "MEDIUM": Y, "HIGH": R, "CRITICAL": R + BOLD}
SEV_ICON  = {"LOW": "●", "MEDIUM": "◆", "HIGH": "▲", "CRITICAL": "✖"}


def color(text, code): return f"{code}{text}{RESET}"
def bold(text):        return f"{BOLD}{text}{RESET}"
def dim(text):         return f"{DIM}{text}{RESET}"
def div(char="─", n=68): return color(char * n, B)


def banner():
    print(color("""
 ╔══════════════════════════════════════════════════════════════════╗
 ║          AI-Powered Network Log Analyzer                        ║
 ║          Anomaly detection via Claude AI                        ║
 ╚══════════════════════════════════════════════════════════════════╝
""", C))


def show_sample(logs: list[dict], n: int = 6):
    print(bold(f"\n  Step 1 — Log capture  ({len(logs)} entries generated)"))
    print(div())
    header = f"  {'Timestamp':<27} {'Src':>15} {'Proto':>5}  {'Port':>5}  {'Lat (ms)':>9}  {'Flag'}"
    print(dim(header))
    for log in logs[:n]:
        flag  = color(" ⚠ ANOMALY", R) if log["anomaly"] else ""
        lat_c = Y if log["latency_ms"] > 200 else W
        print(
            f"  {dim(log['timestamp'])}  "
            f"{log['src']:>15}  "
            f"{color(log['protocol'], C):>5}  "
            f"{log['dport']:>5}  "
            f"{color(f"{log['latency_ms']:>8.1f}", lat_c)} ms"
            f"{flag}"
        )
    print(dim(f"  ... and {len(logs) - n} more entries"))


def show_stats(stats: dict):
    print(bold(f"\n  Step 2 — Parsed statistics"))
    print(div())
    lat = stats["latency"]
    print(f"  Total packets      : {color(str(stats['total_packets']), W)}")
    print(f"  Capture window     : {color(str(stats['capture_window_sec']) + ' sec', W)}")
    print(f"  Unique source IPs  : {color(str(stats['unique_src_ips']), W)}")
    print(f"  Avg / max latency  : "
          f"{color(f\"{lat['avg_ms']:.1f} ms\", W)} / "
          f"{color(f\"{lat['max_ms']:.1f} ms\", Y if lat['max_ms'] > 200 else W)}")
    print(f"  Protocol breakdown : {color(str(stats['protocol_breakdown']), W)}")
    print(f"  Top target ports   : {color(str(stats['top_5_target_ports']), W)}")
    print(f"  High-lat events    : {color(str(stats['high_latency_events_count']), Y if stats['high_latency_events_count'] else G)}")

    if stats["suspicious_ips"]:
        print(f"\n  {color('Suspicious IPs flagged by heuristics:', R)}")
        for entry in stats["suspicious_ips"]:
            print(f"    {color(entry['ip'], R)}  →  {', '.join(entry['reasons'])}")
    else:
        print(f"\n  {color('No suspicious IPs flagged by heuristics.', G)}")


def spinner(label: str, duration: float = 1.2):
    frames = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
    end_t  = time.time() + duration
    i = 0
    while time.time() < end_t:
        print(f"\r  {color(frames[i % len(frames)], C)}  {label}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print("\r" + " " * 60 + "\r", end="")


def show_alerts(result: dict):
    overall = result.get("overall_severity", "UNKNOWN")
    alerts  = result.get("alerts", [])
    summary = result.get("summary", "")

    print(bold(f"\n  Step 4 — AI Analysis   (overall: {color(overall, SEV_COLOR.get(overall, W))})"))
    print(div("═"))

    if not alerts:
        print(color("  No anomalies detected.", G))
    else:
        for alert in alerts:
            sev   = alert.get("severity", "LOW")
            sc    = SEV_COLOR.get(sev, W)
            icon  = SEV_ICON.get(sev, "●")
            print()
            print(f"  {color(icon, sc)} {color(f'[{sev}]', sc)}  {bold(alert.get('title', ''))}")
            print(f"     {color('What:',    C)} {alert.get('description', '')}")
            print(f"     {color('Where:',   C)} {alert.get('affected', '-')}")
            print(f"     {color('Action:',  C)} {alert.get('recommendation', '-')}")

    print()
    print(div())
    print(bold("  Summary"))
    # Word-wrap the summary to 65 chars
    words, line = summary.split(), ""
    for word in words:
        if len(line) + len(word) + 1 > 65:
            print(f"  {line}")
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        print(f"  {line}")
    print(div("═"))


def parse_args():
    inject   = "--clean" not in sys.argv
    n_logs   = 200
    if "--logs" in sys.argv:
        idx = sys.argv.index("--logs")
        try:
            n_logs = int(sys.argv[idx + 1])
        except (IndexError, ValueError):
            pass
    return n_logs, inject


# ── Main ──────────────────────────────────────────────────────
def main():
    banner()
    n_logs, inject = parse_args()

    # Step 1: Generate logs
    print(color(f"  Generating {n_logs} log entries (anomalies={'ON' if inject else 'OFF'})...", DIM))
    logs = generate_logs(n=n_logs, inject_anomalies=inject)
    show_sample(logs)

    # Step 2: Parse
    print(bold("\n  Step 2 — Parsing logs..."))
    stats = parse_logs(logs)
    show_stats(stats)

    # Step 3: Send to AI
    print(bold("\n  Step 3 — Sending to Claude AI..."))
    spinner("Waiting for AI analysis...", duration=1.0)

    try:
        result = analyze(stats, logs[:15])
    except EnvironmentError as e:
        print(color(f"\n  [ERROR] {e}", R))
        sys.exit(1)
    except Exception as e:
        print(color(f"\n  [ERROR] Unexpected error: {e}", R))
        raise

    # Step 4: Display results
    show_alerts(result)

    # Optionally dump raw result for debugging
    if "--json" in sys.argv:
        print("\n" + json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
