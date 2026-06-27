"""
Shared utilities for SC Checker: atomic JSON writes, Discord helpers.
"""
import json
import os
import tempfile
from pathlib import Path

from config import DISCORD_TEXT_LIMIT


# ──────────── Atomic JSON writes ────────────

def atomic_write_json(path, data):
    """Write JSON atomically: write to temp file then os.replace()."""
    dir_path = Path(path).parent
    dir_path.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ──────────── Discord helpers ────────────

DISCORD_COLOR_MAP = {
    "CRITICAL": 0xFF0000, "HIGH": 0xFF8C00, "MEDIUM": 0xFFD700,
    "LOW": 0x00FF00, "INFO": 0x808080,
}

DISCORD_COLOR_MAP_STR = {
    "CRITICAL": "#FF0000", "HIGH": "#FF8C00", "MEDIUM": "#FFD700",
    "LOW": "#00FF00", "INFO": "#808080",
}


def build_discord_embed(title, text, risk_level, risk_score, status_code,
                        scan_duration_ms, open_ports, cve_findings, waf_detected,
                        version):
    """Build a Discord embed dict for notifications."""
    upper = risk_level.upper() if risk_level else "INFO"
    return {
        "title": title,
        "description": text[:DISCORD_TEXT_LIMIT],
        "color": DISCORD_COLOR_MAP.get(upper, 0x808080),
        "fields": [
            {"name": "Risk Score", "value": f"{risk_score}/100", "inline": True},
            {"name": "Status", "value": str(status_code or "N/A"), "inline": True},
            {"name": "Duration", "value": f"{scan_duration_ms}ms", "inline": True},
            {"name": "Open Ports",
             "value": str(open_ports[:10]) if open_ports else "none",
             "inline": True},
            {"name": "CVEs", "value": str(len(cve_findings)), "inline": True},
            {"name": "WAF",
             "value": ", ".join(waf_detected) if waf_detected else "none",
             "inline": True},
        ],
        "footer": {"text": f"SC Checker v{version}"},
    }
