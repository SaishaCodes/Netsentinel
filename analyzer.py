"""
analyzer.py  (Gemini version — free tier)
Sends parsed log stats to Google Gemini Flash and returns structured alerts.

Setup:
    pip install google-generativeai
    export GEMINI_API_KEY="AIza..."    # from aistudio.google.com — FREE, no card needed
"""

import json
import os
import google.generativeai as genai


SYSTEM_PROMPT = """You are a senior network security analyst specializing in RAN
(Radio Access Network) infrastructure. Analyze network log statistics and identify
anomalies. Be specific — reference exact IPs, port numbers, and packet counts.
Do NOT hallucinate details not present in the data."""

USER_PROMPT_TEMPLATE = """Analyze the following network log statistics and identify anomalies.

=== LOG STATISTICS ===
{stats_json}

=== SAMPLE LOG ENTRIES (first 15) ===
{sample_json}

Respond ONLY with valid JSON — no markdown fences, no extra text:
{{
  "alerts": [
    {{
      "title": "Short title (max 8 words)",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "description": "Plain-English explanation of what was detected and why it is suspicious.",
      "affected": "IP / port / protocol involved",
      "recommendation": "Concrete action to take."
    }}
  ],
  "overall_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "2-3 sentence paragraph: overall network health assessment and key concerns."
}}
"""


def analyze(stats: dict, sample_logs: list[dict]) -> dict:
    """
    Call Gemini Flash with log stats and return a parsed alert dict.

    Args:
        stats       – output of parser.parse_logs()
        sample_logs – first N raw log entries (for context)

    Returns:
        dict with keys: alerts (list), overall_severity (str), summary (str)
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY not set.\n"
            "  1. Go to https://aistudio.google.com\n"
            "  2. Click 'Get API Key' — it's free, no credit card needed\n"
            "  3. Run:  export GEMINI_API_KEY='AIza...'"
        )

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name        = "gemini-1.5-flash",   # free tier model
        system_instruction = SYSTEM_PROMPT,
    )

    prompt = USER_PROMPT_TEMPLATE.format(
        stats_json  = json.dumps(stats,            indent=2),
        sample_json = json.dumps(sample_logs[:15], indent=2),
    )

    response = model.generate_content(prompt)
    raw = response.text.strip()

    # Strip markdown fences if the model wraps them
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0].strip()

    return json.loads(raw)