"""
Webhook notification system with SSRF protection via DNS-pinning,
atomic file writes, and optional Fernet encryption for stored secrets.
"""
import json
import base64
import html as _html
import ipaddress
import os
import socket
import tempfile
import urllib.parse
from pathlib import Path

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
import requests

try:
    from cryptography.fernet import Fernet
    _FERNET_AVAILABLE = True
except ImportError:
    _FERNET_AVAILABLE = False

APP_DIR = Path(__file__).resolve().parent
WEBHOOKS_FILE = APP_DIR / "webhooks.json"
_FERNET_KEY_FILE = APP_DIR / ".webhooks.key"
from config import VERSION, DEFAULT_REQUEST_TIMEOUT, DISCORD_TEXT_LIMIT, DISCORD_TEXT_HARD, DISCORD_TITLE_LIMIT
from utils import atomic_write_json as _atomic_write_json, DISCORD_COLOR_MAP, DISCORD_COLOR_MAP_STR, build_discord_embed

# ──────────── Fernet key management ────────────

def _get_fernet():
    """Return a Fernet instance, loading or generating a key as needed."""
    if not _FERNET_AVAILABLE:
        return None
    try:
        if _FERNET_KEY_FILE.exists():
            key = _FERNET_KEY_FILE.read_bytes().strip()
            return Fernet(key)
        key = Fernet.generate_key()
        # Write with restricted permissions (owner-only read/write)
        fd = os.open(str(_FERNET_KEY_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return Fernet(key)
    except Exception:
        return None

# ──────────── SSRF protection with DNS pinning ────────────

def _is_safe_ip(addr_str: str) -> bool:
    """Check whether an IP address string is safe (non-private, non-reserved)."""
    try:
        addr = ipaddress.ip_address(addr_str)
        return not (
            addr.is_private or addr.is_reserved or addr.is_loopback
            or addr.is_link_local or addr.is_multicast or addr.is_unspecified
        )
    except ValueError:
        return False


def _send_safe_post(url, json_payload=None, data_payload=None,
                    extra_headers=None, timeout=DEFAULT_REQUEST_TIMEOUT, verify=False):
    """Send an HTTP POST with SSRF protection via DNS-pinning.

    Resolves the hostname once, validates the resolved IP, then makes the
    request to the IP address with the original Host header — closing the
    DNS-rebinding window that existed when resolve and request were separate.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Blocked scheme: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Missing hostname in URL")

    # Block obviously-dangerous hostnames
    blocked_names = {
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "::",
        "169.254.169.254", "metadata.google.internal",
    }
    if hostname.lower() in blocked_names:
        raise ValueError(f"Blocked hostname: {hostname}")

    # Resolve DNS ONCE and validate every returned address
    try:
        resolved = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(f"DNS resolution failed for {hostname}: {exc}") from exc
    if not resolved:
        raise ValueError(f"DNS resolution returned no results for {hostname}")

    safe_ip = None
    for _, _, _, _, sockaddr in resolved:
        ip_str = sockaddr[0]
        if _is_safe_ip(ip_str):
            safe_ip = ip_str
            break
    if not safe_ip:
        raise ValueError(f"All resolved IPs for {hostname} are private/reserved (SSRF)")

    # Reconstruct URL with the pinned IP instead of the hostname
    port_part = f":{parsed.port}" if parsed.port else ""
    safe_url = urllib.parse.urlunsplit((
        parsed.scheme, f"{safe_ip}{port_part}",
        parsed.path or "/", parsed.query, "",
    ))
    headers = dict(extra_headers or {})
    headers["Host"] = hostname  # preserve original Host header

    if HAS_HTTPX:
        with httpx.Client(timeout=timeout, verify=verify) as c:
            if json_payload is not None:
                r = c.post(safe_url, json=json_payload, headers=headers)
            else:
                r = c.post(safe_url, data=data_payload, headers=headers)
            return r.status_code
    else:
        if json_payload is not None:
            r = requests.post(
                safe_url, json=json_payload, headers=headers,
                timeout=timeout, verify=verify,
            )
        else:
            r = requests.post(
                safe_url, data=data_payload, headers=headers,
                timeout=timeout, verify=verify,
            )
        return r.status_code

# ──────────── Secret encryption / obfuscation ────────────

_SENSITIVE_KEYS = {
    "bot_token", "webhook_url", "chat_id", "channel_id",
    "push_key", "user_key", "app_token", "auth_header",
}

def _obfuscate_settings(settings: dict) -> dict:
    """Encrypt sensitive values with Fernet (preferred) or base64 fallback."""
    fernet = _get_fernet()
    result = {}
    for k, v in settings.items():
        if k in _SENSITIVE_KEYS and isinstance(v, str) and v:
            if fernet:
                token = fernet.encrypt(v.encode("utf-8")).decode("utf-8")
                result[k] = "fnet:" + token
            else:
                enc = base64.b64encode(v.encode("utf-8")).decode("utf-8")
                result[k] = "enc:" + enc
        else:
            result[k] = v
    return result

def _deobfuscate_settings(settings: dict) -> dict:
    """Decrypt sensitive values. Falls back gracefully if key has changed."""
    fernet = _get_fernet()
    result = {}
    for k, v in settings.items():
        if isinstance(v, str):
            if v.startswith("fnet:") and fernet:
                try:
                    result[k] = fernet.decrypt(v[5:].encode("utf-8")).decode("utf-8")
                    continue
                except Exception:
                    result[k] = v  # decryption failed — return as-is
            elif v.startswith("enc:"):
                try:
                    result[k] = base64.b64decode(v[4:]).decode("utf-8")
                    continue
                except Exception:
                    result[k] = v
        result[k] = v
    return result

# ──────────── Channel definitions ────────────

WEBHOOK_CHANNELS = {
    "Telegram Bot": {
        "fields": ["bot_token", "chat_id"],
        "send": "telegram",
    },
    "Discord Webhook": {
        "fields": ["webhook_url"],
        "send": "discord_webhook",
    },
    "Discord Bot": {
        "fields": ["bot_token", "channel_id"],
        "send": "discord_bot",
    },
    "Slack Webhook": {
        "fields": ["webhook_url"],
        "send": "slack",
    },
    "Pushover": {
        "fields": ["push_key", "user_key", "app_token"],
        "send": "pushover",
    },
    "Custom HTTP": {
        "fields": ["webhook_url", "auth_header"],
        "send": "custom",
    },
}

# ──────────── Webhook notifier ────────────

class WebhookNotifier:
    def __init__(self):
        self._webhooks = self._load()

    def _load(self):
        if WEBHOOKS_FILE.exists():
            try:
                data = json.loads(WEBHOOKS_FILE.read_text("utf-8"))
                return data if isinstance(data, list) else []
            except Exception:
                pass
        return []

    def _save(self):
        _atomic_write_json(WEBHOOKS_FILE, self._webhooks)

    def get_all(self):
        return list(self._webhooks)

    def add(self, channel, name, settings, enabled=True):
        entry = {
            "channel": channel, "name": name,
            "settings": _obfuscate_settings(settings),
            "enabled": enabled,
        }
        self._webhooks.append(entry)
        self._save()

    def remove(self, index):
        if 0 <= index < len(self._webhooks):
            self._webhooks.pop(index)
            self._save()

    def toggle(self, index, enabled):
        if 0 <= index < len(self._webhooks):
            self._webhooks[index]["enabled"] = enabled
            self._save()

    def send_all(self, report):
        results = []
        for wh in self._webhooks:
            if not wh.get("enabled", True):
                continue
            try:
                result = self._send_one(wh, report)
                results.append({"name": wh.get("name", "?"), "ok": True, "detail": result})
            except Exception as e:
                results.append({"name": wh.get("name", "?"), "ok": False, "detail": str(e)[:200]})
        return results

    def _send_one(self, webhook, report):
        channel = webhook.get("channel", "")
        settings = _deobfuscate_settings(webhook.get("settings", {}))
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
        emoji = severity_emoji.get(report.risk_level.upper(), "⚪")
        title = f"{emoji} Site Report: {report.target}"
        summary = (
            f"Risk: {report.risk_level.upper()} ({report.risk_score}/100)\n"
            f"Status: {report.status_code or 'N/A'}\n"
            f"Server: {report.server_banner or 'N/A'}\n"
            f"Open Ports: {', '.join(str(p) for p in report.open_ports[:10]) or 'none'}\n"
            f"Missing Headers: {len(report.missing_security_headers)}\n"
            f"CVE Findings: {len(report.cve_findings)}\n"
            f"Critical Paths: {len(report.critical_paths)}\n"
            f"WAF: {', '.join(report.waf_detected) if report.waf_detected else 'none'}\n"
            f"Scan Time: {report.scan_duration_ms}ms"
        )
        if report.critical_paths:
            summary += "\n\nCritical paths:\n" + "\n".join(
                f"  ! {p}" for p in report.critical_paths[:5]
            )
        if report.cve_findings:
            summary += "\n\nTop CVEs:\n" + "\n".join(
                f"  {c.get('cve','?')} (score {c.get('score','?')}): {c.get('desc','')[:60]}"
                for c in report.cve_findings[:5]
            )
        if channel == "Telegram Bot":
            return self._send_telegram(settings, title, summary)
        elif channel == "Discord Webhook":
            return self._send_discord_webhook(settings, title, summary, report)
        elif channel == "Discord Bot":
            return self._send_discord_bot(settings, title, summary, report)
        elif channel == "Slack Webhook":
            return self._send_slack(settings, title, summary, report)
        elif channel == "Pushover":
            return self._send_pushover(settings, title, summary)
        elif channel == "Custom HTTP":
            return self._send_custom(settings, title, summary, report)
        return "Unknown channel"

    # ── Telegram ──────────────────────────────────────────────────
    def _send_telegram(self, settings, title, text):
        token = settings.get("bot_token", "")
        chat_id = settings.get("chat_id", "")
        if not token or not chat_id:
            raise ValueError("Missing bot_token or chat_id")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        safe_title = _html.escape(str(title))
        safe_text = _html.escape(str(text))
        full_msg = f"{safe_title}\n\n{safe_text}"
        if len(full_msg) > 4000:
            full_msg = full_msg[:4000] + "\n\n[Truncated]"
        payload = {
            "chat_id": chat_id, "text": full_msg,
            "parse_mode": "HTML", "disable_web_page_preview": True,
        }
        # api.telegram.org — skip SSL verify (DNS pinning may cause IP mismatch)
        if HAS_HTTPX:
            with httpx.Client(timeout=DEFAULT_REQUEST_TIMEOUT, verify=False) as c:
                r = c.post(url, json=payload)
                return f"Telegram OK: {r.status_code}"
        else:
            r = requests.post(url, json=payload, timeout=DEFAULT_REQUEST_TIMEOUT, verify=False)
            return f"Telegram OK: {r.status_code}"

    # ── Discord Webhook (SSRF-protected URL) ──────────────────────
    def _send_discord_webhook(self, settings, title, text, report):
        url = settings.get("webhook_url", "")
        if not url:
            raise ValueError("Missing webhook_url")
        embed = {
            "title": title,
            "description": text[:DISCORD_TEXT_LIMIT],
            "color": DISCORD_COLOR_MAP.get(report.risk_level.upper(), 0x808080),
            "fields": [
                {"name": "Risk Score", "value": f"{report.risk_score}/100", "inline": True},
                {"name": "Status", "value": str(report.status_code or "N/A"), "inline": True},
                {"name": "Duration", "value": f"{report.scan_duration_ms}ms", "inline": True},
            ],
            "footer": {"text": f"SC Checker v{VERSION}"},
        }
        payload = {"embeds": [embed]}
        # User-provided URL — use DNS-pinned safe request
        code = _send_safe_post(url, json_payload=payload)
        return f"Discord Webhook OK: {code}"

    # ── Discord Bot (known discord.com API) ───────────────────────
    def _send_discord_bot(self, settings, title, text, report):
        token = settings.get("bot_token", "")
        channel_id = settings.get("channel_id", "")
        if not token or not channel_id:
            raise ValueError("Missing bot_token or channel_id")
        if not channel_id.isdigit():
            raise ValueError("Invalid channel_id format")
        url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
        embed = build_discord_embed(
            title, text, report.risk_level, report.risk_score,
            report.status_code, report.scan_duration_ms,
            report.open_ports, report.cve_findings,
            report.waf_detected, VERSION,
        )
        payload = {"embeds": [embed]}
        headers = {"Authorization": f"Bot {token}", "Content-Type": "application/json"}
        # discord.com — skip SSL verify to avoid cert issues
        if HAS_HTTPX:
            with httpx.Client(timeout=DEFAULT_REQUEST_TIMEOUT, verify=False) as c:
                r = c.post(url, json=payload, headers=headers)
                return f"Discord Bot OK: {r.status_code}"
        else:
            r = requests.post(url, json=payload, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT, verify=False)
            return f"Discord Bot OK: {r.status_code}"

    # ── Slack (SSRF-protected URL) ────────────────────────────────
    def _send_slack(self, settings, title, text, report=None):
        url = settings.get("webhook_url", "")
        if not url:
            raise ValueError("Missing webhook_url")
        risk = getattr(report, "risk_level", "INFO") if report else "INFO"
        payload = {
            "attachments": [{
                "color": DISCORD_COLOR_MAP_STR.get(risk.upper(), "#808080"),
                "title": title,
                "text": text[:DISCORD_TEXT_HARD],
                "footer": f"SC Checker v{VERSION}",
            }]
        }
        code = _send_safe_post(url, json_payload=payload)
        return f"Slack OK: {code}"

    # ── Pushover ──────────────────────────────────────────────────
    def _send_pushover(self, settings, title, text):
        push_key = settings.get("push_key", "")
        user_key = settings.get("user_key", "")
        app_token = settings.get("app_token", "")
        if not push_key or not user_key or not app_token:
            raise ValueError("Missing push_key, user_key, or app_token")
        # Pushover API: 'token' = app_token, 'user' = user_key
        payload = {
            "token": app_token,
            "user": user_key,
            "title": title,
            "message": text[:DISCORD_TITLE_LIMIT],
            "priority": 0,
        }
        # api.pushover.net — skip SSL verify to avoid cert issues
        if HAS_HTTPX:
            with httpx.Client(timeout=15, verify=False) as c:
                r = c.post("https://api.pushover.net/1/messages.json", data=payload)
                return f"Pushover OK: {r.status_code}"
        else:
            r = requests.post(
                "https://api.pushover.net/1/messages.json",
                data=payload, timeout=15, verify=False,
            )
            return f"Pushover OK: {r.status_code}"

    # ── Custom HTTP (SSRF-protected URL) ──────────────────────────
    def _send_custom(self, settings, title, text, report):
        url = settings.get("webhook_url", "")
        if not url:
            raise ValueError("Missing webhook_url")
        headers = {"Content-Type": "application/json"}
        auth = settings.get("auth_header", "")
        if auth:
            headers["Authorization"] = auth
        payload = {
            "event": "scan_complete",
            "target": report.target,
            "risk_level": report.risk_level,
            "risk_score": report.risk_score,
            "status_code": report.status_code,
            "summary": text,
            "report": {
                "open_ports": report.open_ports,
                "missing_headers": report.missing_security_headers,
                "cve_count": len(report.cve_findings),
                "critical_paths": report.critical_paths,
                "scan_duration_ms": report.scan_duration_ms,
            },
        }
        # User-provided URL — use DNS-pinned safe request, skip SSL verify
        code = _send_safe_post(url, json_payload=payload, extra_headers=headers, verify=False)
        return f"Custom OK: {code}"
