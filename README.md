# AI-Powered Network Log Analyzer

Captures (or simulates) network traffic logs, extracts statistics, and feeds
them to **Claude AI** for anomaly detection with plain-English alerts.

Relevant to Airspan's Testing/Validation and Automation roles — this mirrors
real RAN monitoring pipelines.

---

## Setup

```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."   # get from console.anthropic.com
```

## Run

```bash
python main.py              # 200 logs, anomalies injected
python main.py --logs 500   # 500 logs
python main.py --clean      # no anomalies (baseline traffic only)
python main.py --json       # also dump raw AI response as JSON
```

## Project structure

```
├── simulator.py   Generate realistic logs + 3 injected anomaly types
├── parser.py      Extract per-IP stats, flag suspicious IPs heuristically
├── analyzer.py    Call Claude API with structured prompt, parse JSON response
├── main.py        Orchestrate pipeline, colored terminal output
└── requirements.txt
```

## Anomalies injected

| Type | What it looks like |
|---|---|
| Port scan | One external IP hits 20 sequential ports in <3 sec |
| Latency spike | 6 packets jump from ~10 ms to 500–2000 ms |
| UDP flood | 35 large UDP packets to port 80 in <1.5 sec |

## Key concepts for your demo / viva

| Topic | Where it appears |
|---|---|
| Socket-level networking | `simulator.py` — src/dst IPs, protocol, port, flags |
| Traffic feature extraction | `parser.py` — per-IP packet counts, unique ports, latency stats |
| Port scan detection | Heuristic: ≥10 unique dports from one IP |
| Flood detection | Heuristic: ≥30 packets from one IP in window |
| LLM-based analysis | `analyzer.py` — structured prompt + JSON output |
| Prompt engineering | System prompt separates role/context from task; JSON schema enforced |
# Netsentinel
# Netsentinel
