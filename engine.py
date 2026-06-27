import json
import re
import ssl
import sys
import socket
import subprocess
import tempfile
import threading
import urllib.parse
import time
import asyncio
import logging
import os
import base64
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from http.cookies import SimpleCookie
import random as _random

# ──────────────── PRE-COMPILED REGEX PATTERNS ────────────────

# XSS context stripping
_XSS_STRIP_SCRIPT = re.compile(r'<script[^>]*>.*?</script>', re.I | re.S)
_XSS_STRIP_STYLE = re.compile(r'<style[^>]*>.*?</style>', re.I | re.S)
_XSS_STRIP_NOSCRIPT = re.compile(r'<noscript[^>]*>.*?</noscript>', re.I | re.S)
_XSS_ATTR_DQ = re.compile(r'\b\w[\w-]*\s*=\s*"[^"]*"')
_XSS_ATTR_SQ = re.compile(r"\b\w[\w-]*\s*=\s*'[^']*'")
_XSS_ATTR_UNQ = re.compile(r'\b\w[\w-]*\s*=\s*[^\s>"\'>]+')
_XSS_STRIP_URLS = re.compile(r'https?://[^\s"\'<>]*')
_XSS_STRIP_META_TAGS = re.compile(r'<(?:meta|link|img|iframe|embed|object|source|video|audio)\b[^>]*\s*/?>', re.I)
_XSS_STRIP_COMMENTS = re.compile(r'<!--.*?-->', re.S)

# Mixed content detection
_MIXED_STRIP_SCRIPT = re.compile(r'<script[^>]*>.*?</script>', re.I | re.S)
_MIXED_STRIP_STYLE = re.compile(r'<style[^>]*>.*?</style>', re.I | re.S)
_MIXED_STRIP_NOSCRIPT = re.compile(r'<noscript[^>]*>.*?</noscript>', re.I | re.S)
_MIXED_STRIP_COMMENTS = re.compile(r'<!--.*?-->', re.S)
_MIXED_RESOURCE_TAGS = re.compile(r'(?:img|script|iframe|link|video|audio|source|embed|object)\b')
_MIXED_HTTP_SRC = re.compile(r'(?:img|script|iframe|link|video|audio|source|embed|object)\b[^>]*\bsrc\s*=\s*["\']http://([^"\'\s>]+)', re.I)
_MIXED_HTTP_HREF = re.compile(r'(?:img|script|iframe|link|video|audio|source|embed|object)\b[^>]*\bhref\s*=\s*["\']http://([^"\'\s>]+)', re.I)
_MIXED_HTTP_POSTER = re.compile(r'<video\b[^>]*\bposter\s*=\s*["\']http://([^"\'\s>]+)', re.I)
_MIXED_CSS_URL = re.compile(r'\bstyle\s*=\s*["\'][^"\']*\burl\s*\(\s*["\']?http://([^"\'\s)>]+)', re.I)

# DSL interpreter
_DSL_VAR_ASSIGN = re.compile(r'^\$(\w+)\s*=\s*(.+)')
_DSL_IF = re.compile(r'^IF\s+(.+?)\s+THEN\s*$', re.I)
_DSL_END = re.compile(r'^END\s*$', re.I)
_DSL_ELSE = re.compile(r'^ELSE\s*$', re.I)
_DSL_FOR = re.compile(r'^FOR\s+\$(\w+)\s+IN\s+(.+?)\s+THEN\s*$', re.I)
_DSL_RETURN = re.compile(r'^RETURN\s+(.+)', re.I)
_DSL_AND = re.compile(r'\s+AND\s+')
_DSL_OR = re.compile(r'\s+OR\s+')
_DSL_NOT = re.compile(r'^NOT\s+(.+)')
_DSL_CMP = re.compile(r'(.+?)\s*(==|!=|>=|<=|>|<|contains|not_contains|starts_with|ends_with)\s*(.+)')

from cache import ScanCache, SessionCache
from models import Report
from config import (APP_DIR, DEFAULT_TIMEOUT, FAST_TIMEOUT, DIR_WORKERS, PORT_WORKERS,
                     CVE_CACHE_FILE, AI_PROVIDERS, AI_SETTINGS_FILE,
                     DEFAULT_REQUEST_TIMEOUT, HTTP_USER_AGENT, MAX_CONCURRENT_REQUESTS,
                     BATCH_SIZE_LARGE, BATCH_SIZE_SMALL, DRAIN_TIMEOUT, COUNTER_LOG_INTERVAL,
                     BODY_PREVIEW_SHORT, BODY_PREVIEW_MEDIUM, BODY_PREVIEW_LONG)
from utils import atomic_write_json as _atomic_write_json

logger = logging.getLogger("SCChecker")

PLUGIN_TIMEOUT = 10  # seconds — max time for a single plugin hook call

requests.packages.urllib3.disable_warnings()
_cve_cache_lock = threading.Lock()


# ──────────────── WORDLISTS ────────────────

GENERIC_PATHS = [
    "admin", "administrator", "admin.php", "login", "signin", "auth",
    "dashboard", "panel", "controlpanel", "cpanel", "webmail",
    "config.php", "configuration.php", "settings.php",
    ".htaccess", ".htpasswd", "web.config",
    "phpinfo.php", "info.php", "test.php", "server-status",
    ".env", ".env.bak", ".env.production", ".env.local",
    ".git/config", ".git/HEAD", ".svn/entries",
    "backup.sql", "database.sql", "dump.sql", "db.sql",
    "robots.txt", "sitemap.xml",
    "readme.html", "README.md", "LICENSE",
    "composer.json", "package.json",
    ".bash_history", ".ssh/", "id_rsa",
    "debug.log", "error.log", "access.log",
    "phpmyadmin/", "pma/", "adminer.php",
]

WP_PATHS = [
    "wp-admin", "wp-login.php", "wp-config.php.bak",
    "wp-content/debug.log", "wp-includes/",
    "wp-cron.php", "xmlrpc.php", "wp-json/wp/v2/users/",
    "feed/", "wp-content/plugins/",
]

LARAVEL_PATHS = ["artisan", "_profiler/", "storage/logs/laravel.log", "bootstrap/cache/"]
DRUPAL_PATHS = ["core/CHANGELOG.txt", "sites/default/settings.php"]
JOOMLA_PATHS = ["administrator/", "configuration.php"]
SPRING_PATHS = ["actuator", "actuator/health", "actuator/env", "actuator/heapdump", "swagger-ui.html"]
DJANGO_PATHS = ["admin/", "api/", "__debug__/"]
NEXTJS_PATHS = ["_next/", "api/auth/"]

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 8888, 9000, 9090,
    9200, 11211, 27017, 50000, 50070,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Proxy2", 9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 50000: "SAP", 50070: "HDFS",
}

CRITICAL_PATHS = {
    ".env", ".env.bak", ".git/config", ".git/HEAD",
    "backup.sql", "database.sql", "phpmyadmin", "adminer.php",
    "config.php", ".htpasswd", "id_rsa", ".bash_history",
    "storage/logs/laravel.log", "sites/default/settings.php", "actuator/env",
}

# ──── Content validation for critical paths (anti-false-positive) ────

_SOFT_404_SIGNATURES = [
    "page not found", "404 not found", "sorry, we couldn't find",
    "the page you requested was not found", "error 404",
    "file not found", "requested url was not found",
    "this page doesn't exist", "no results found",
    "the resource you are looking for",
]

_CRITICAL_CONTENT_RULES = {
    "id_rsa":         ["BEGIN", "PRIVATE KEY", "ssh-rsa", "-----BEGIN"],
    ".env":           ["=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"],
    ".env.bak":       ["=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"],
    ".git/config":    ["[core]", "repositoryformatversion", "[remote"],
    ".git/HEAD":      ["ref:", "refs/heads"],
    "backup.sql":     ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL", "-- phpMyAdmin"],
    "database.sql":   ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL"],
    ".htpasswd":      [":"],  # user:hash format
    ".bash_history":  ["cd ", "ls ", "sudo ", "ssh ", "export "],
    "config.php":     ["<?php", "$db", "$database", "DB_HOST", "define("],
    "sites/default/settings.php": ["<?php", "$databases", "$settings", "drupal"],
    "storage/logs/laravel.log":   ["stack trace", "Stack trace", "Laravel", "ERROR"],
    "actuator/env":   ["{", "spring", "server.port", "environment"],
    "phpmyadmin":     ["phpMyAdmin", "pma_username", "login_form"],
    "adminer.php":    ["Adminer", "login", "username"],
}


def _is_soft_404(body: str) -> bool:
    """Return True if the body looks like a soft-404 / generic error page."""
    lower = body[:3000].lower()
    return any(sig in lower for sig in _SOFT_404_SIGNATURES)


def _is_real_critical(path: str, body: str, size: int) -> bool:
    """Validate that a 200 response on a critical path is genuinely sensitive.

    Returns True only when the body contains content characteristic of the
    actual file (not a CDN soft-404, login page, or generic error).
    """
    if _is_soft_404(body):
        return False

    # Very small or very large responses are suspicious for CDNs
    if size < 10:
        return False

    rules = _CRITICAL_CONTENT_RULES.get(path)
    if rules is None:
        # No specific rules — fall back to: not HTML login/generic page
        lower = body[:2000].lower()
        if any(kw in lower for kw in ("sign in", "log in", "please login",
                                       "access denied", "forbidden",
                                       "just a moment", "checking your browser")):
            return False
        # If it looks like HTML with a login form, not a real file leak
        if "<form" in lower and ("password" in lower or "login" in lower):
            return False
        return True

    # Check if ANY rule signature is present in the body
    return any(sig in body[:5000] for sig in rules)

SECURITY_HEADERS = [
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "strict-transport-security",
]

# Curated subset of domains from https://hstspreload.org that enforce HTTPS
# purely via browser preload (no Strict-Transport-Security header sent).
_HSTS_PRELOAD_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "google.co.uk", "google.de", "google.fr", "google.es", "google.it",
    "google.ru", "google.com.br", "google.co.jp", "google.ca",
    "google.com.au", "google.nl", "google.pl", "google.com.mx",
    "google.com.ar", "google.com.tr", "google.co.in", "google.co.kr",
    "google.com.hk", "google.com.tw", "google.sg", "google.com.sg",
    "google.com.pk", "google.com.ng", "google.com.eg", "google.co.za",
    "google.co.ve", "google.com.pe", "google.com.co", "google.cl",
    "google.com.ua", "google.com.vn", "google.be", "google.ch",
    "google.at", "google.se", "google.no", "google.dk", "google.fi",
    "google.pl", "google.cz", "google.pt", "google.gr", "google.ro",
    "google.hu", "google.ie", "google.co.il", "google.ae",
    "google.com.sa", "google.com.do", "google.com.my", "google.com.ph",
    "google.co.th", "google.lk", "google.com.bd", "google.com.gh",
    "google.co.ke", "google.co.tz", "google.co.ug", "google.co.mz",
    "google.com.np", "google.com.mm", "google.com.kh", "google.co.id",
    "gmail.com", "googlemail.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "gvt1.com", "gvt2.com", "gcpnt.com",
    "googleadservices.com", "googlesyndication.com", "doubleclick.net",
    "googletagmanager.com", "google-analytics.com",
    "cloudflare.com", "github.com", "github.io", "githubassets.com",
    "githubusercontent.com", "github.dev",
    "twitter.com", "x.com", "twimg.com",
    "facebook.com", "fbcdn.net", "facebook.net",
    "instagram.com", "cdninstagram.com",
    "linkedin.com", "licdn.com",
    "microsoft.com", "office.com", "office365.com", "live.com",
    "outlook.com", "azure.com", "msn.com", "bing.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "wikipedia.org", "wikimedia.org", "wmflabs.org",
    "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
    "yahoo.com", "yimg.com",
    "ebay.com", "ebaystatic.com",
    "netflix.com", "nflxvideo.net", "nflximg.net",
    "twitch.tv", "jtvnw.net", "ttvnw.net", "twitchcdn.net",
    "discord.com", "discord.gg", "discordapp.com", "discord.media",
    "discordapp.net", "discordstatus.com",
    "slack.com", "slack-edge.com", "slack-imgs.com",
    "zoom.us", "zoomgov.com",
    "spotify.com", "scdn.co",
    "dropbox.com", "dropboxstatic.com",
    "paypal.com", "paypalobjects.com",
    "wikimedia.org", "mediawiki.org",
    "stackoverflow.com", "stackexchange.com", "serverfault.com",
    "medium.com", "s3-us-west-2.amazonaws.com",
    "notion.so", "notionusercontent.com",
    "figma.com", "figma.net",
    "vercel.app", "vercel.com", "vercel-dns.com",
    "netlify.app", "netlify.com",
    "heroku.com", "herokuapp.com",
    "digitalocean.com", "digitaloceanspaces.com",
    "fastly.com", "fastly.net",
    "akamai.com", "akamaized.net", "akamaihd.net",
    "cloudfront.net", "cloudfront.com",
    "sentry.io", "sentry-cdn.com",
    "bitbucket.org", "atlassian.com", "atlassian.net",
    "docker.com", "docker.io", "dockerhub.com",
    "gitlab.com", "gitlab.io",
    "npmjs.com", "npmjs.org",
    "pypi.org", "python.org",
    "rubygems.org", "ruby-lang.org",
    "crates.io", "rust-lang.org",
    "nuget.org", "dot.net",
    "mozilla.org", "mozilla.com", "firefox.com",
    "w3.org", "schema.org",
    "archive.org", "archive-it.org",
    "bbc.com", "bbc.co.uk", "bbci.co.uk",
    "cnn.com", "nytimes.com", "washingtonpost.com",
    "theguardian.com", "guardian.co.uk",
    "reuters.com", "apnews.com",
    "bloomberg.com", "ft.com",
    "wsj.com", "economist.com",
    "bbc.co.uk", "gov.uk", "parliament.uk",
    "gov", "gov.br", "gov.in", "gov.au", "gc.ca",
    "gov.de", "gouv.fr", "gob.es", "gov.it",
    "gov.sg", "gov.jp", "go.kr", "gov.cn",
    "gov.ru", "gov.ua", "gov.pl", "gov.nl",
    "gov.be", "gov.ch", "gov.at", "gov.se", "gov.no",
    "gov.dk", "gov.fi", "gov.pt", "gov.gr", "gov.ro",
    "gov.hu", "gov.ie", "gov.il", "gov.ae", "gov.sa",
    "edu", "ac.uk", "edu.au", "edu.cn", "ac.jp",
    "edu.br", "edu.in", "edu.sg",
    "1password.com", "lastpass.com",
    "mozilla.org", "letsencrypt.org",
}

TECH_FINGERPRINT = {
    "server": "Server", "x-powered-by": "X-Powered-By", "x-generator": "Generator",
    "cf-ray": "Cloudflare", "x-amz-cf-id": "CloudFront", "via": "Via",
}

CMS_SIGNATURES = {
    "WordPress": [r"wp-content/", r'content="WordPress'],
    "Joomla": [r"joomla", r'content="Joomla'],
    "Drupal": [r"drupal", r'content="Drupal'],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken"],
    "Spring": [r"Whitelabel Error Page", r"actuator"],
    "Express": [r"X-Powered-By: Express"],
    "Next.js": [r"__next"],
    "Nuxt.js": [r"__nuxt"],
    "Angular": [r"ng-version"],
    "ASP.NET": [r"__VIEWSTATE"],
    "Ghost": [r'content="Ghost'],
    "Shopify": [r"cdn\.shopify\.com"],
}

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": ["cloudflare", "cf-browser-verification"]},
    "AWS WAF": {"headers": ["x-amzn-requestid", "x-amzn-waf"], "body": ["awswaf", "aws-waf"]},
    "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"]},
    "Imperva": {"headers": ["x-iinfo"], "body": ["imperva", "incapsula"]},
    "Akamai": {"headers": ["x-akamai-transformed", "x-akamai"], "body": ["akamai", "reference number"]},
    "Sucuri": {"headers": ["x-sucuri-id"], "body": ["sucuri"]},
    "Wordfence": {"headers": [], "body": ["wordfence", "wf-csrf-token"]},
    "Barracuda": {"headers": [], "body": ["barracuda", "barra_counter_session"]},
    "F5 BIG-IP": {"headers": ["x-cnection"], "body": ["bigip", "tscookieid", "f5 BIG-IP", "ASM"]},
    "FortiWeb": {"headers": [], "body": ["fortiweb"]},
    "DenyAll": {"headers": [], "body": ["denyall", "incap_ses"]},
    "Radware": {"headers": ["x-radware"], "body": ["radware"]},
}

VERSION_PATTERNS = [
    (r"nginx/([\d.]+)", "Nginx"), (r"Apache/([\d.]+)", "Apache"),
    (r"PHP/([\d.]+)", "PHP"), (r"IIS/([\d.]+)", "IIS"),
    (r"LiteSpeed/([\d.]+)", "LiteSpeed"), (r"OpenResty/([\d.]+)", "OpenResty"),
    (r"Caddy", "Caddy"), (r"Varnish/([\d.]+)", "Varnish"),
    (r"WordPress\s+([\d.]+)", "WordPress"), (r"Drupal\s+([\d.]+)", "Drupal"),
    (r"Joomla!\s+([\d.]+)", "Joomla"), (r"jQuery\s+([\d.]+)", "jQuery"),
    (r"React/([\d.]+)", "React"), (r"Vue\.js\s+([\d.]+)", "Vue.js"),
    (r"Angular[\s/]?([\d.]+)", "Angular"), (r"Bootstrap\s+([\d.]+)", "Bootstrap"),
    (r"Node\.js/([\d.]+)", "Node.js"), (r"Express[\s/]?([\d.]+)", "Express"),
    (r"Python/([\d.]+)", "Python"), (r"Ruby/([\d.]+)", "Ruby"),
    (r"curl/([\d.]+)", "cURL"), (r"Wget/([\d.]+)", "Wget"),
]

# Pre-compiled regex patterns for CMS and version detection
_COMPILED_CMS_PATTERNS = {name: [re.compile(p, re.I) for p in pats] for name, pats in CMS_SIGNATURES.items()}
_COMPILED_VERSION_PATTERNS = [(re.compile(pat, re.I), name) for pat, name in VERSION_PATTERNS]


# ──────────────── DATA ────────────────

# Report dataclass moved to models.py

# ──────────────── ENGINE ────────────────

class ScanEngine:
    def __init__(self, timeout=DEFAULT_TIMEOUT, custom_paths=None, proxy=None, custom_lists=None, plugins=None, verify_ssl=True):
        self.timeout = timeout
        self.custom_paths = custom_paths or []
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.cache = ScanCache()
        self.session_cache = SessionCache(ttl=300, max_size=4096)
        self.cl = custom_lists or {}
        self.plugins = plugins or []
        self._progress_cb = None
        self._log_cb = None
        self.scan_settings = {}
        self.stop_event = threading.Event()
        self._async_lock = threading.Lock()

        default_headers = {"User-Agent": HTTP_USER_AGENT}
        for h in self.cl.get("headers", []):
            if ":" in h:
                k, v = h.split(":", 1)
                default_headers[k.strip()] = v.strip()

        # Custom user-agent rotation
        self._ua_list = self.cl.get("useragents", [])
        self._ua_index = 0
        self._req_counter = 0
        if self._ua_list:
            default_headers["User-Agent"] = self._ua_list[0]

        if HAS_HTTPX:
            import httpx as _httpx_mod
            self.client = httpx.Client(
                timeout=timeout, follow_redirects=True, verify=self.verify_ssl,
                headers=default_headers,
                proxy=proxy if proxy else None,
                limits=_httpx_mod.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=30,
                ),
            )
        else:
            self.session = requests.Session()
            self.session.headers.update(default_headers)
            self.session.verify = self.verify_ssl
            if proxy:
                self.session.proxies = {"http": proxy, "https": proxy}

        # Lazy-load CVE cache once per engine lifetime
        self._cve_cache = None
        self._cve_cache_loaded = False

    def set_callbacks(self, progress_cb=None, log_cb=None):
        self._progress_cb = progress_cb
        self._log_cb = log_cb

    def close(self):
        try:
            if hasattr(self, 'client') and self.client:
                self.client.close()
        except Exception:
            pass
        try:
            if hasattr(self, 'session') and self.session:
                self.session.close()
        except Exception:
            pass

    def _rotate_ua(self):
        """Rotate to next User-Agent from custom list."""
        if self._ua_list:
            self._ua_index = (self._ua_index + 1) % len(self._ua_list)
            ua = self._ua_list[self._ua_index]
            if HAS_HTTPX:
                self.client.headers["User-Agent"] = ua
            else:
                self.session.headers["User-Agent"] = ua

    def _collect_error(self, report, phase, err):
        if report is not None and hasattr(report, 'scan_errors'):
            report.scan_errors.append(f"[{phase}] {str(err)[:200]}")
        logger.warning("[%s] %s", phase, err)

    def _collect_hook_findings(self, plugin, result):
        if not result or not hasattr(plugin, 'add_finding'):
            return
        items = result if isinstance(result, list) else [result]
        for item in items:
            if isinstance(item, dict):
                plugin.add_finding(
                    item.get("severity", "info"),
                    item.get("title", ""),
                    item.get("detail", ""),
                    item.get("url", ""),
                )
            elif isinstance(item, str) and item:
                plugin.add_finding("info", item, "")

    def _fire_hook(self, hook_name, *args, **kwargs):
        """Fire a hook on all enabled plugins with timeout + error isolation.

        Each plugin's hook runs in a separate thread with PLUGIN_TIMEOUT.
        This prevents a hung or slow plugin from blocking the entire scan.
        For hooks that return data, returns list of non-None results.
        """
        results = []
        active = [p for p in self.plugins if callable(getattr(p, hook_name, None))]
        if active:
            self._log(f"[plugin] Firing {hook_name} ({len(active)} handler{'s' if len(active) != 1 else ''})")
        for p in active:
            pname = getattr(p, 'name', '?')
            result_container = [None]
            exc_container = [None]

            def _run(_p=p, _rc=result_container, _ec=exc_container):
                try:
                    _rc[0] = _p.__getattribute__(hook_name)(self, *args, **kwargs)
                except Exception as e:
                    _ec[0] = e

            t = threading.Thread(target=_run, daemon=False)
            t.start()
            t.join(timeout=PLUGIN_TIMEOUT)
            if t.is_alive():
                self._log(f"[plugin:{pname}] {hook_name} timed out after {PLUGIN_TIMEOUT}s")
                logger.warning("Plugin %s hook %s timed out", pname, hook_name)
                continue
            if exc_container[0] is not None:
                self._log(f"[plugin:{pname}] {hook_name} error: {exc_container[0]}")
                logger.warning("Plugin %s hook %s error: %s", pname, hook_name, exc_container[0])
            elif result_container[0] is not None:
                self._collect_hook_findings(p, result_container[0])
                results.append(result_container[0])
        return results

    def _http_get(self, url, timeout=10, **kw):
        try:
            if HAS_HTTPX:
                return self.client.get(url, timeout=timeout, **kw)
            else:
                return self.session.get(url, timeout=timeout, **kw)
        except Exception:
            return None

    def _http_post(self, url, timeout=15, **kw):
        try:
            if HAS_HTTPX:
                return self.client.post(url, timeout=timeout, **kw)
            else:
                return self.session.post(url, timeout=timeout, **kw)
        except Exception:
            return None

    def _progress(self, phase, cur, total):
        if self._progress_cb:
            self._progress_cb(phase, cur, total)

    def _log(self, msg):
        if self._log_cb:
            self._log_cb(msg)

    def _req(self, method, url, timeout=None, **kw):
        t = timeout or self.timeout
        t0 = time.perf_counter()
        resp = None
        # Rotate UA every 8 requests to avoid fingerprinting
        if self._ua_list:
            self._req_counter += 1
            if self._req_counter % COUNTER_LOG_INTERVAL == 0:
                self._rotate_ua()
        try:
            if HAS_HTTPX:
                resp = self.client.request(method, url, timeout=t, **kw)
            else:
                resp = self.session.request(method, url, timeout=t, **kw)
        except Exception:
            try:
                if HAS_HTTPX:
                    resp = self.client.request(method, url, timeout=t, **kw)
                else:
                    resp = self.session.request(method, url, timeout=t, **kw)
            except Exception:
                resp = None
        return resp, int((time.perf_counter() - t0) * 1000)

    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_host(host):
        return bool(re.match(r'^[a-zA-Z0-9._-]+$', host)) and len(host) <= 253

    @staticmethod
    def _is_private_ip(ip):
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local or addr.is_multicast
        except ValueError:
            return False

    def normalize(self, target):
        raw = target.strip()
        if not raw:
            raise ValueError("Empty target")
        if re.match(r'^(file|ftp|javascript|data|gopher|vbscript|dict):', raw, re.I):
            raise ValueError(f"Blocked scheme: {raw.split(':')[0]}")
        if re.match(r'^[A-Za-z]:\\', raw) or raw.startswith("/"):
            raise ValueError("Path traversal not allowed")
        is_ip = self.is_ip(raw)
        if is_ip:
            if self._is_private_ip(raw):
                raise ValueError(f"Private IP blocked: {raw}")
            scheme = "http"
            host = raw
            port = 80
            url = f"http://{raw}"
            return url, scheme, host, port
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"
        p = urllib.parse.urlsplit(raw)
        if not p.hostname:
            raise ValueError("Invalid host")
        scheme = p.scheme or "https"
        host = p.hostname
        port = p.port or (443 if scheme == "https" else 80)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
        if host and (host.lower() in blocked_hosts or (host.endswith(".local") or host.endswith(".internal"))):
            raise ValueError(f"Blocked host: {host}")
        if host and self.is_ip(host) and self._is_private_ip(host):
            raise ValueError(f"Private IP blocked: {host}")
        url = urllib.parse.urlunsplit((scheme, f"{host}:{port}" if p.port else host, p.path or "/", p.query, ""))
        return url, scheme, host, port

    def resolve_ip(self, host):
        cached = self.session_cache.get(f"dns:{host}")
        if cached:
            return cached
        cached = self.cache.get_dns(host)
        if cached:
            self.session_cache.set(f"dns:{host}", cached)
            return cached
        try:
            ip = socket.gethostbyname(host)
            if self._is_private_ip(ip):
                raise ValueError(f"DNS rebinding blocked: {host} resolves to private IP {ip}")
            self.cache.set_dns(host, ip)
            self.session_cache.set(f"dns:{host}", ip)
            return ip
        except OSError:
            return host

    def base_url(self, scheme, host, port):
        return f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

    def probe_root(self, url):
        t0 = time.perf_counter()
        r, _ = self._req("GET", url)
        return r, int((time.perf_counter() - t0) * 1000)

    # ──── Server node detection ────

    ALT_HTTP_PORTS = [80, 8080, 8443, 8000, 5000, 3000, 9090, 443]

    def _probe_alt_ports(self, host, ports=None):
        """Try common alternative HTTP ports in parallel. Returns list of (port, url) with working HTTP."""
        if ports is None:
            ports = [p for p in self.ALT_HTTP_PORTS if p not in (80, 443)]
        found = []

        def _try_port(p):
            try:
                s = socket.create_connection((host, p), timeout=2)
                s.close()
                scheme = "https" if p in (443, 8443) else "http"
                url = f"{scheme}://{host}:{p}" if p not in (80, 443) else f"{scheme}://{host}"
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp is not None:
                    return (p, url, scheme)
            except Exception:
                pass
            return None

        # NOTE: httpx.Client is NOT thread-safe — _try_port uses self._req.
        # When HAS_HTTPX, run sequentially. Only parallelize with requests.Session.
        if HAS_HTTPX:
            for p in ports:
                result = _try_port(p)
                if result:
                    found.append(result)
        else:
            with ThreadPoolExecutor(max_workers=min(8, len(ports))) as ex:
                futures = {ex.submit(_try_port, p): p for p in ports}
                for fut in as_completed(futures):
                    try:
                        result = fut.result()
                        if result:
                            found.append(result)
                    except Exception:
                        pass

        return found

    def collect_headers(self, resp):
        if resp is None:
            return {}
        if HAS_HTTPX:
            return dict(resp.headers)
        return {str(k): str(v) for k, v in resp.headers.items()}

    def missing_headers(self, headers):
        lower = {k.lower(): v for k, v in headers.items()}
        return [h for h in SECURITY_HEADERS if h not in lower]

    def fingerprint(self, headers):
        hints = []
        lower = {k.lower(): v for k, v in headers.items()}
        for h, lbl in TECH_FINGERPRINT.items():
            v = lower.get(h)
            if v:
                hints.append(f"{lbl}: {v[:100]}")
        return hints

    def probe_methods(self, url):
        allowed, trace = [], False
        try:
            r, _ = self._req("OPTIONS", url, timeout=FAST_TIMEOUT)
            a = r.headers.get("Allow", "") if hasattr(r, 'headers') else ""
            if a:
                allowed = sorted({m.strip().upper() for m in a.split(",") if m.strip()})
        except Exception:
            pass
        try:
            r, _ = self._req("TRACE", url, timeout=FAST_TIMEOUT)
            trace = r.status_code < 400 if r else False
        except Exception:
            pass
        return allowed, trace

    def fetch_robots(self, base):
        try:
            r, _ = self._req("GET", urllib.parse.urljoin(base + "/", "robots.txt"), timeout=FAST_TIMEOUT)
            if not r or r.status_code != 200:
                return []
            return [l.strip() for l in r.text.splitlines() if l.strip() and not l.strip().startswith("#") and l.strip().lower().startswith(("allow:", "disallow:", "sitemap:"))][:30]
        except Exception:
            return []

    def fetch_sitemap(self, base):
        try:
            r, _ = self._req("GET", urllib.parse.urljoin(base + "/", "sitemap.xml"), timeout=FAST_TIMEOUT)
            if not r or r.status_code != 200:
                return []
            return [l.strip() for l in r.text.replace(">", ">\n").splitlines() if "<loc>" in l.lower()][:20]
        except Exception:
            return []

    def tls_summary(self, host, port, scheme):
        if scheme != "https":
            return {}
        combined = self._ssl_combined(host, port)
        return combined.get("tls", {})

    def _ssl_combined(self, host, port):
        cache_key = f"ssl:{host}:{port}"
        cached = self.session_cache.get(cache_key)
        if cached:
            return cached
        info = {"expiry_days": None, "expiry_date": "", "weak_cipher": False, "tls": {}, "deep": {}}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port or 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    ciph = ss.cipher()
                    cn = ciph[0] if ciph else ""
                    prot = ss.version() or ""
                    weak_c = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
                    weak = any(w in cn.upper() for w in weak_c) or "TLSv1.0" in prot or "TLSv1.1" in prot
                    na = cert.get("notAfter", "")
                    if na:
                        days = (parsedate_to_datetime(na) - datetime.now(timezone.utc)).days
                        info["expiry_days"] = days
                        info["expiry_date"] = na
                    info["weak_cipher"] = weak
                    info["tls"] = {
                        "version": prot, "cipher": cn,
                        "bits": str(ciph[2]) if ciph and len(ciph) > 2 else "",
                        "subject": ", ".join("=".join(i) for g in cert.get("subject", []) for i in g)[:200],
                        "issuer": ", ".join("=".join(i) for g in cert.get("issuer", []) for i in g)[:200],
                        "not_after": na,
                    }
                    san = []
                    for ext in cert.get("subjectAltName", []):
                        san.append(ext[1] if len(ext) > 1 else str(ext))
                    info["deep"] = {
                        "protocol": prot, "cipher_name": cn,
                        "cipher_bits": ciph[2] if ciph and len(ciph) > 2 else "",
                        "subject": info["tls"]["subject"],
                        "issuer": info["tls"]["issuer"],
                        "not_before": cert.get("notBefore", ""),
                        "not_after": na,
                        "san": san[:20],
                        "serial": cert.get("serialNumber", ""),
                        "weak_protocol": any(wp in prot for wp in ["TLSv1.0", "TLSv1.1", "SSLv3"]),
                    }
        except Exception as e:
            info["deep"]["error"] = str(e)[:100]
        self.session_cache.set(cache_key, info)
        return info

    def ssl_expiry(self, host, port):
        r = self._ssl_combined(host, port)
        return r["expiry_days"], r["expiry_date"], r["weak_cipher"]

    def _iter_set_cookie_headers(self, resp):
        """Yield every Set-Cookie header across the redirect chain + final.

        Why: requests/httpx move cookies set during intermediate redirects
        into the session jar and drop them from the *final* response. For a
        consent-redirect-heavy site (e.g. YouTube) the final resp often has
        no Set-Cookie at all, so naively inspecting only resp.cookies missed
        them. Walking resp.history + the final response's raw headers
        recovers the full picture regardless of backend.
        """
        if not resp:
            return
        # Intermediate redirects (both requests.Response and httpx.Response
        # expose .history as a list of prior responses).
        for prev in getattr(resp, "history", []) or []:
            yield from self._raw_set_cookie_headers(prev)
        yield from self._raw_set_cookie_headers(resp)

    @staticmethod
    def _raw_set_cookie_headers(resp):
        """Return all Set-Cookie header values for a single response.

        getlist is used when available (httpx.Headers / requests'CaseInsensitive
        dict won't, but both also accept indexing); fall back to a single value.
        """
        if not resp:
            return
        headers = getattr(resp, "headers", None)
        if headers is None:
            return
        try:
            vals = headers.get_list("set-cookie")
            for v in vals:
                yield v
            return
        except (AttributeError, TypeError):
            pass
        try:
            vals = headers.getlist("Set-Cookie")
            for v in vals:
                yield v
            return
        except (AttributeError, TypeError):
            pass
        # Last resort: a single combined value.
        try:
            v = headers.get("Set-Cookie") or headers.get("set-cookie")
        except Exception:
            v = None
        if v:
            yield v

    # Cookie names that typically carry sensitive data and SHOULD have
    # proper security flags. Tracking/analytics/advertising cookies are
    # intentionally excluded — flagging them as "issues" is noise.
    _SENSITIVE_COOKIE_PATTERNS = (
        "session", "sid", "sess", "auth", "login", "user", "token",
        "csrf", "xsrf", "jwt", "bearer", "api_key", "secret",
        "password", "credential", "access", "refresh", "id_token",
        "phpsessid", "jsessionid", "asp.net_sessionid", "laravel_session",
        "csrftoken", "xsrf-token",
    )

    def _is_sensitive_cookie(self, name: str) -> bool:
        lower = name.lower()
        return any(pat in lower for pat in self._SENSITIVE_COOKIE_PATTERNS)

    def check_cookies(self, resp):
        """Inspect cookie flags across the whole redirect chain.

        Returns (issues, names) where:
          - issues: list of "'<name>' missing HttpOnly/Secure/SameSite"
          - names:  sorted list of distinct cookie names actually seen

        Only sensitive cookies (session, auth, CSRF tokens) are checked for
        missing flags. Tracking/analytics cookies intentionally skip these
        flags and reporting them creates noise on major sites.
        """
        issues = []
        names = []
        if not resp:
            return issues, names

        seen = set()
        for raw in self._iter_set_cookie_headers(resp):
            if not raw or SimpleCookie is None:
                continue
            try:
                c = SimpleCookie()
                c.load(raw)
            except Exception:
                continue
            for morsel_name, morsel in c.items():
                name = morsel_name or "(unset)"
                if name in seen:
                    continue
                seen.add(name)
                names.append(name)

                # Only flag missing flags on sensitive cookies
                if not self._is_sensitive_cookie(name):
                    continue

                rest = getattr(morsel, "_rest", {}) or {}
                attrs = {k.lower() for k in rest.keys()}
                if morsel.get("httponly"):
                    attrs.add("httponly")
                if morsel.get("secure"):
                    attrs.add("secure")
                if "httponly" not in attrs:
                    issues.append(f"'{name}' missing HttpOnly")
                if "secure" not in attrs:
                    issues.append(f"'{name}' missing Secure")
                samesite = (rest.get("SameSite") or rest.get("samesite") or "").lower()
                if not samesite:
                    issues.append(f"'{name}' missing SameSite")
        return issues, names

    def check_cors(self, url):
        issues = []
        for origin in ("https://evil.com", "null"):
            try:
                r, _ = self._req("GET", url, headers={"Origin": origin}, timeout=FAST_TIMEOUT)
                if not r:
                    continue
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*":
                    issues.append("CORS wildcard (*)")
                    break
                if acao.lower() == origin.lower():
                    issues.append(f"CORS reflects: {acao}")
                    if acac.lower() == "true":
                        issues.append("CORS credentials=true")
                    break
            except Exception:
                continue
        return issues

    def check_hsts(self, headers, resp=None, host=""):
        """Check for HSTS via header, redirect chain, AND preload list.

        Many major sites (Google, GitHub, etc.) rely on the HSTS preload
        list embedded in browsers and do NOT send a Strict-Transport-Security
        header at all.  We check three things in order:
          1. Final response headers
          2. Any redirect in the chain (some sites set it on 301 only)
          3. Whether the domain is in the browser preload list
        """
        lower = {k.lower(): v for k, v in headers.items()}
        if lower.get("strict-transport-security"):
            return True
        # Check redirect chain history for HSTS header
        if resp is not None:
            for prev in getattr(resp, "history", []) or []:
                prev_lower = {k.lower(): v for k, v in (prev.headers if hasattr(prev, 'headers') else {}).items()}
                if prev_lower.get("strict-transport-security"):
                    return True
        # Check HSTS preload list (top domains that enforce HTTPS via browser
        # preload, not via HTTP header).  This avoids false negatives on sites
        # like google.com that rely purely on the preload list.
        return self._hsts_preloaded(host)

    @staticmethod
    def _hsts_preloaded(host):
        """Return True if host is known to be in the browser HSTS preload list.

        This is a curated subset of the most popular domains from
        https://hstspreload.org — enough to eliminate false negatives on
        common scan targets without requiring a network fetch.
        """
        h = host.lower().lstrip(".")
        # Exact match or parent domain match (e.g. "www.google.com" → "google.com")
        return any(h == d or h.endswith("." + d) for d in _HSTS_PRELOAD_DOMAINS)

    def check_http_https(self, host, port):
        if port == 443:
            return True
        try:
            r, _ = self._req("GET", f"http://{host}" + (":%d" % port if port != 80 else ""), timeout=FAST_TIMEOUT)
            if not r:
                return False
            loc = r.headers.get("Location", "")
            return r.status_code in (301, 302, 307, 308) and "https" in loc.lower()
        except Exception:
            return False

    def check_clickjacking(self, headers):
        lower = {k.lower(): v for k, v in headers.items()}
        xfo = lower.get("x-frame-options", "").upper()
        if xfo in ("DENY", "SAMEORIGIN"):
            return True
        csp = lower.get("content-security-policy", "")
        if "frame-ancestors" in csp:
            fa = csp.split("frame-ancestors")[1].split(";")[0].strip()
            if fa and fa not in ("'none'", "none"):
                return True
        return False

    def detect_waf(self, resp):
        """Detect WAF using unified WAF_SIGNATURES dict."""
        wafs = []
        if not resp:
            return wafs
        lower_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower = resp.text[:10000].lower() if hasattr(resp, 'text') else ""
        for waf_name, sigs in WAF_SIGNATURES.items():
            # Check header signatures
            for h in sigs.get("headers", []):
                if h.lower() in lower_headers or h.lower() in " ".join(lower_headers.values()):
                    wafs.append(waf_name)
                    break
            else:
                # Check body signatures
                for b in sigs.get("body", []):
                    if b.lower() in body_lower:
                        wafs.append(waf_name)
                        break
        # Status-code based detection
        if resp.status_code in (403, 406, 429, 503):
            server = lower_headers.get("server", "")
            for waf_name, sigs in WAF_SIGNATURES.items():
                if waf_name in wafs:
                    continue
                all_sigs = sigs.get("headers", []) + sigs.get("body", [])
                if any(s.lower() in server for s in all_sigs):
                    wafs.append(waf_name)
        return wafs

    def detect_cms(self, resp, body=""):
        hints, cms, fw = [], [], []
        if not resp:
            return hints, cms, fw
        lh = {k.lower(): v for k, v in resp.headers.items()}
        for h in ("server", "x-powered-by", "x-generator"):
            v = lh.get(h, "")
            if v:
                hints.append(f"{h}: {v[:100]}")
        all_t = (lh.get("server", "") + " " + lh.get("x-powered-by", "") + " " + body[:50000]).lower()
        for name, pats in _COMPILED_CMS_PATTERNS.items():
            for p in pats:
                if p.search(all_t):
                    if name in ("WordPress", "Joomla", "Drupal", "Ghost", "Shopify"):
                        cms.append(name)
                    else:
                        fw.append(name)
                    break
        return hints, list(set(cms)), list(set(fw))

    def detect_versions(self, resp, body=""):
        versions = []
        if not resp:
            return versions
        lh = {k.lower(): v for k, v in resp.headers.items()}
        server = lh.get("server", "")
        x_power = lh.get("x-powered-by", "")
        all_t = (server + " " + x_power + " " + body[:50000]).lower()
        for compiled_pat, name in _COMPILED_VERSION_PATTERNS:
            m = compiled_pat.search(all_t)
            if m:
                try:
                    versions.append({"name": name, "version": m.group(1) if m.lastindex else "detected"})
                except IndexError:
                    versions.append({"name": name, "version": "detected"})
        return versions

    # CVE cache TTL: 30 days
    _CVE_CACHE_TTL = 86400 * 30

    def _load_cve_cache(self):
        """Load CVE cache once per engine lifetime (lazy)."""
        if self._cve_cache_loaded:
            return self._cve_cache
        try:
            raw = json.loads(CVE_CACHE_FILE.read_text("utf-8")) if CVE_CACHE_FILE.exists() else {}
            now = time.time()
            # Filter out expired entries on load
            self._cve_cache = {}
            for k, v in raw.items():
                if isinstance(v, dict) and "data" in v:
                    ts = v.get("ts", 0)
                    if now - ts < self._CVE_CACHE_TTL:
                        self._cve_cache[k] = v
                elif isinstance(v, list):
                    # Legacy format (list of CVEs without wrapper) — keep as-is
                    self._cve_cache[k] = v
        except Exception:
            self._cve_cache = {}
        self._cve_cache_loaded = True
        return self._cve_cache

    def check_cve(self, versions):
        findings = []
        cache_data = self._load_cve_cache()

        uncached = []
        for v in versions:
            name = v["name"].lower()
            ver = v["version"]
            if ver == "detected":
                continue
            cache_key = f"{name}:{ver}"
            if cache_key in cache_data:
                entry = cache_data[cache_key]
                # Support both new {"data": [...], "ts": ...} and legacy list format
                cves = entry["data"] if isinstance(entry, dict) and "data" in entry else entry
                for c in cves:
                    findings.append({"product": v["name"], "version": v["version"], "cve": c["id"], "score": c["score"], "desc": c["desc"]})
                continue
            uncached.append(v)

        def _fetch_cve(v):
            try:
                query = f"{v['name']} {v['version']}"
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=3"
                r = self._http_get(url, timeout=8)
                if r and r.status_code == 200:
                    data = r.json()
                    cves = []
                    for item in data.get("vulnerabilities", [])[:3]:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:150]
                                break
                        metrics = cve.get("metrics", {})
                        score = 0
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            if key in metrics and metrics[key]:
                                score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                                break
                        if cve_id:
                            cves.append({"id": cve_id, "score": score, "desc": desc})
                    return v, cves
            except Exception:
                pass
            return v, []

        new_entries = 0
        if uncached:
            # NOTE: httpx.Client is NOT thread-safe — _fetch_cve uses self._http_get.
            if HAS_HTTPX:
                cve_results = [_fetch_cve(v) for v in uncached]
            else:
                with ThreadPoolExecutor(max_workers=3) as ex:
                    cve_results = list(ex.map(lambda v: _fetch_cve(v), uncached))
            for v, cves in cve_results:
                cache_key = f"{v['name'].lower()}:{v['version']}"
                cache_data[cache_key] = {"data": cves, "ts": time.time()}
                if cache_key not in self._cve_cache:
                    new_entries += 1
                self._cve_cache[cache_key] = cache_data[cache_key]
                for c in cves:
                    findings.append({"product": v["name"], "version": v["version"], "cve": c["id"], "score": c["score"], "desc": c["desc"]})

        # Incremental write — only if new entries were added
        if new_entries > 0:
            try:
                with _cve_cache_lock:
                    _atomic_write_json(str(CVE_CACHE_FILE), cache_data)
            except Exception:
                pass
        return findings

    def check_dns(self, host):
        if not self._is_valid_host(host):
            return {}
        records = {}
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        for rt in ("MX", "TXT", "NS"):
            try:
                r = subprocess.run(["nslookup", "-type=" + rt, host], capture_output=True, text=True, timeout=5, creationflags=flags)
                entries = []
                for line in r.stdout.splitlines():
                    l = line.strip().lower()
                    if rt == "MX" and "mail exchanger" in l:
                        entries.append(line.strip()[:200])
                    elif rt == "TXT" and line.strip().startswith('"') and len(line.strip()) > 3:
                        entries.append(line.strip()[:200])
                    elif rt == "NS" and ("nameserver" in l or "canonical" in l):
                        entries.append(line.strip()[:200])
                if entries:
                    records[rt] = entries[:10]
            except Exception:
                continue
        return records

    def check_subdomains(self, host):
        subs = [
            "www", "mail", "ftp", "webmail", "smtp", "ns1", "ns2",
            "vpn", "remote", "api", "dev", "staging", "test",
            "demo", "beta", "admin", "panel", "dashboard", "app",
            "cdn", "static", "media", "db", "redis", "git",
            "jenkins", "ci", "monitor", "grafana", "backup", "blog",
            "docs", "shop", "status", "sso", "auth", "login",
        ]
        subs.extend(self.cl.get("subdomains", []))
        subs = sorted(set(subs))
        parts = host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
        found = []

        def check(sub):
            fqdn = f"{sub}.{domain}"
            if fqdn == host:
                return None
            try:
                resolved = socket.gethostbyname(fqdn)
                if resolved:
                    return fqdn
            except OSError:
                pass
            return None

        total = len(subs)
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, s): s for s in subs}
            for i, f in enumerate(as_completed(futures), 1):
                if self.stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                self._progress("subdomains", i, total)
                try:
                    r = f.result()
                except Exception:
                    continue
                if r:
                    found.append(r)
        return sorted(set(found))

    def grab_banner(self, ip, port):
        cache_key = f"{ip}:{port}"
        cached = self.session_cache.get(f"banner:{cache_key}")
        if cached is not None:
            return cached
        cached = self.cache.get_tcp(cache_key)
        if cached is not None:
            self.session_cache.set(f"banner:{cache_key}", cached)
            return cached
        banner = ""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((ip, port))
            if port in (80, 8080, 8000):
                s.send(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                banner = s.recv(1024).decode("utf-8", errors="ignore").split("\r\n")[0][:120]
            elif port == 22 or port == 21:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()[:120]
            elif port == 25:
                s.send(b"EHLO test\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").split("\r\n")[0][:120]
            else:
                s.send(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()[:120]
        except Exception:
            pass
        finally:
            if s:
                try: s.close()
                except Exception: pass
        self.cache.set_tcp(cache_key, banner)
        self.session_cache.set(f"banner:{cache_key}", banner)
        return banner

    def scan_ports(self, ip):
        def check(p):
            cache_key = f"{ip}:{p}:open"
            cached = self.cache.get_tcp(cache_key)
            if cached is not None:
                return p if cached else None
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                result = s.connect_ex((ip, p)) == 0
                try:
                    self.cache.set_tcp(cache_key, result)
                except Exception:
                    pass
                return p if result else None
            except Exception:
                try:
                    self.cache.set_tcp(cache_key, False)
                except Exception:
                    pass
                return None
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        found = []
        custom_ports = []
        for p in self.cl.get("ports", []):
            try:
                port_val = int(p)
                if 1 <= port_val <= 65535:
                    custom_ports.append(port_val)
            except ValueError:
                pass
        all_ports = sorted(set(COMMON_PORTS + custom_ports))
        total = len(all_ports)
        with ThreadPoolExecutor(max_workers=PORT_WORKERS) as ex:
            futures = {ex.submit(check, p): p for p in all_ports}
            for i, f in enumerate(as_completed(futures), 1):
                if self.stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                self._progress("ports", i, total)
                try:
                    r = f.result()
                except Exception:
                    continue
                if r is not None:
                    found.append(r)
        return sorted(found)

    def scan_paths(self, base, paths):
        found = []
        blacklist = set(bl.lstrip("/") for bl in self.cl.get("blacklist", []))
        paths = [p for p in paths if p not in blacklist]

        def worker(path):
            url = urllib.parse.urljoin(base + "/", path)
            try:
                r, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
            except Exception:
                return None
            if r and r.status_code == 200:
                body_snippet = (r.text[:5000] if hasattr(r, 'text') else "")
                return {"path": f"/{path}", "status": r.status_code,
                        "size": len(r.content) if hasattr(r, 'content') else len(r.text),
                        "_body": body_snippet}
            return None

        total = len(paths)
        # NOTE: httpx.Client is NOT thread-safe — worker uses self._req.
        # When HAS_HTTPX, run sequentially. Only parallelize with requests.Session.
        if HAS_HTTPX:
            for i, p in enumerate(paths, 1):
                if self.stop_event.is_set():
                    break
                self._progress("paths", i, total)
                item = worker(p)
                if item:
                    found.append(item)
        else:
            with ThreadPoolExecutor(max_workers=DIR_WORKERS) as ex:
                futures = {ex.submit(worker, p): p for p in paths}
                for i, f in enumerate(as_completed(futures), 1):
                    if self.stop_event.is_set():
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
                    self._progress("paths", i, total)
                    try:
                        item = f.result()
                    except Exception:
                        continue
                    if item:
                        found.append(item)

        found.sort(key=lambda x: (x["status"], str(x["path"])))
        critical = []
        for item in found:
            p = str(item["path"]).lstrip("/")
            if p in CRITICAL_PATHS and item["status"] == 200:
                body = item.pop("_body", "")
                if _is_real_critical(p, body, item["size"]):
                    critical.append(p)
        # Clean _body from non-critical items
        for item in found:
            item.pop("_body", None)
        critical = sorted(set(critical))
        return found, critical

    def check_sql_errors(self, url):
        errors = []
        sep = "&" if "?" in url else "?"
        payloads = [("'", "SQL syntax"), ("%27", "SQL syntax")]
        for p in self.cl.get("payloads", []):
            payloads.append((p, f"custom: {p[:20]}"))
        for payload, label in payloads:
            try:
                r, _ = self._req("GET", f"{url}{sep}id={urllib.parse.quote(payload)}", timeout=FAST_TIMEOUT)
                body = r.text.lower() if hasattr(r, 'text') else ""
                for ind in ("you have an error in your sql", "mysql_fetch", "pg_query", "sqlstate", "incorrect syntax near", "ORA-", "SQLite/JDBCDriver", "mysql_num_rows"):
                    if ind in body:
                        errors.append(f"SQL error ({label})")
                        break
            except Exception:
                continue
            if errors:
                break
        return errors

    def check_xss(self, url, baseline_body=None):
        token = "chk_xss_7f3a"
        sep = "&" if "?" in url else "?"

        # Baseline: reuse already-fetched body if available to avoid redundant HTTP request.
        if baseline_body:
            baseline = baseline_body
        else:
            try:
                baseline_resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                baseline = baseline_resp.text if baseline_resp and hasattr(baseline_resp, 'text') else ""
            except Exception:
                baseline = ""

        payloads = [token]
        for p in self.cl.get("payloads", []):
            if "<" in p or "script" in p.lower():
                payloads.append(p[:50])
        for payload in payloads:
            try:
                r, _ = self._req("GET", f"{url}{sep}xss={urllib.parse.quote(payload)}", timeout=FAST_TIMEOUT)
                body = r.text if hasattr(r, 'text') else ""
                if payload not in body:
                    continue
                # Token is in the response — but was it already in the baseline?
                # If so, the site just includes the URL in its HTML (canonical,
                # meta, JS vars), not a real reflection.
                if payload in baseline:
                    continue
                # --- Context stripping to eliminate false positives ---
                cleaned = _XSS_STRIP_SCRIPT.sub('', body)
                cleaned = _XSS_STRIP_STYLE.sub('', cleaned)
                cleaned = _XSS_STRIP_NOSCRIPT.sub('', cleaned)
                cleaned = _XSS_ATTR_DQ.sub('', cleaned)
                cleaned = _XSS_ATTR_SQ.sub('', cleaned)
                cleaned = _XSS_ATTR_UNQ.sub('', cleaned)
                cleaned = _XSS_STRIP_URLS.sub('', cleaned)
                cleaned = _XSS_STRIP_META_TAGS.sub('', cleaned)
                cleaned = _XSS_STRIP_COMMENTS.sub('', cleaned)
                if payload in cleaned:
                    return True
            except Exception:
                continue
        return False

    # Known tracking/analytics domains that commonly use http:// even on HTTPS pages.
    # These are not meaningful mixed-content risks.
    _TRACKING_DOMAINS = {
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "googleadservices.com", "facebook.net", "facebook.com/tr",
        "scorecardresearch.com", "quantserve.com", "pixel.quantserve.com",
        "analytics.google.com", "bat.bing.com", "hotjar.com",
        "connect.facebook.net", "static.ads-twitter.com",
        "youtube.com", "google.com", "googlevideo.com", "ggpht.com",
        "ytimg.com", "googleusercontent.com",
    }

    def check_mixed(self, resp):
        if not resp:
            return False
        url = str(resp.url) if hasattr(resp, 'url') else ""
        if not url.startswith("https"):
            return False
        body = (resp.text if hasattr(resp, 'text') else "")[:100000]

        # --- Strategy: find http:// URLs ONLY inside tags that actually
        # load subresources (img, script, iframe, link, video, audio,
        # source, embed, object).  Navigation tags like <a> and <form>
        # do NOT trigger mixed-content browser warnings and must be
        # ignored.  Inline <script>/<style> blocks contain JS/CSS
        # strings that also do NOT load resources. ---
        #
        # Step 1 — Strip non-resource blocks so they cannot leak into
        # the tag-level search via overlapping matches.
        stripped = _MIXED_STRIP_SCRIPT.sub('', body)
        stripped = _MIXED_STRIP_STYLE.sub('', stripped)
        stripped = _MIXED_STRIP_NOSCRIPT.sub('', stripped)
        stripped = _MIXED_STRIP_COMMENTS.sub('', stripped)

        # Step 2 — Find <tag ... src="http://..." or <tag ... href="http://...">
        # for resource-loading tags ONLY.
        http_src = _MIXED_HTTP_SRC.findall(stripped)
        http_href = _MIXED_HTTP_HREF.findall(stripped)
        http_poster = _MIXED_HTTP_POSTER.findall(stripped)
        http_css_url = _MIXED_CSS_URL.findall(stripped)

        matches = http_src + http_href + http_poster + http_css_url
        if not matches:
            return False

        # Filter out tracking/analytics resources and same-domain http references
        page_host = urllib.parse.urlparse(url).hostname or ""
        for ref in matches:
            try:
                ref_host = urllib.parse.urlparse("http://" + ref).hostname or ""
            except Exception:
                continue
            # Skip if it's a known tracking domain
            if any(td in ref_host for td in self._TRACKING_DOMAINS):
                continue
            # Skip same-domain http (often just internal links, not mixed content)
            if ref_host == page_host:
                continue
            # Skip common tracking pixel patterns (1x1 images)
            if any(kw in ref.lower() for kw in ("pixel", "beacon", "track", "analytics", "collect")):
                continue
            # This is a genuine mixed-content resource from a third-party
            return True
        return False

    def check_dir_listing(self, resp, url):
        if resp and resp.status_code == 200:
            body = (resp.text if hasattr(resp, 'text') else "")[:5000].lower()
            if "index of" in body or "directory listing" in body:
                return [url]
        return []

    def score_risk(self, r):
        s = 0
        s += min(len(r.critical_paths) * 15, 30)
        s += min(len(r.missing_security_headers) * 2, 10)
        s += min(len(r.open_ports) * 2, 12)
        if r.trace_enabled: s += 8
        if any(m in ("PUT", "DELETE") for m in r.allowed_methods): s += 8
        s += min(len(r.cookie_issues) * 3, 9)
        s += min(len(r.cors_issues) * 6, 12)
        s += min(len(r.sql_errors) * 10, 20)
        if r.xss_reflection: s += 10
        if not getattr(r, 'server_node', False):
            if not r.hsts_enabled: s += 3
            if not r.http_to_https_redirect: s += 4
        if r.ssl_expiry_days is not None and r.ssl_expiry_days < 30: s += 8
        if r.ssl_weak_cipher: s += 8
        if r.directory_listing: s += 6
        s += min(len(r.cve_findings) * 5, 15)
        s = min(s, 100)
        if s >= 70: return s, "critical"
        if s >= 50: return s, "high"
        if s >= 30: return s, "medium"
        if s >= 10: return s, "low"
        return s, "info"

    def run(self, target):
        t0 = time.perf_counter()
        r = Report()
        r.generated_at = datetime.now().isoformat()
        r.target = target
        r.proxy_used = self.proxy or ""
        is_ip = self.is_ip(target.strip())

        self._log(f"Resolving {target}...")
        r.normalized_url, r.scheme, r.host, r.port = self.normalize(target)
        r.ip = self.resolve_ip(r.host) if not is_ip else r.host

        self._log(f"Checking connectivity to {r.host}...")
        connected = False
        try:
            sock = socket.create_connection((r.host, r.port), timeout=8)
            sock.close()
            connected = True
        except (socket.timeout, OSError):
            self._log(f"Port {r.port} unreachable, trying alternatives...")
            _alt_probe = [80, 443, 8080, 8443, 8000, 5000, 3000, 9090]
            for _p in _alt_probe:
                if _p == r.port:
                    continue
                try:
                    _sock = socket.create_connection((r.host, _p), timeout=3)
                    _sock.close()
                    _scheme = "https" if _p in (443, 8443) else "http"
                    r.port = _p
                    r.scheme = _scheme
                    r.normalized_url = self.base_url(_scheme, r.host, _p)
                    self._log(f"Connected on port {_p} ({_scheme})")
                    connected = True
                    break
                except (socket.timeout, OSError):
                    continue
        if not connected:
            # No TCP port reachable — may be a DNS-only node; allow scan to continue
            self._log(f"No TCP ports reachable on {r.host} — will scan as server node")
            r.no_http = True
            r.server_node = True

        self._fire_hook("on_scan_start", target, r)

        if is_ip:
            self._log(f"IP mode: {r.host}")
            r.reverse_dns = self._rev_dns(r.ip)
            r.ip_geo = self._ip_geo(r.ip)
            r.asn_info = self._asn_lookup(r.ip)
            r.dns_records = self.check_dns(r.host)

            self._log("Port scan...")
            r.open_ports = self.scan_ports(r.ip)
            self._log("Banner grabbing...")
            r.port_banners = {}
            def _grab(p):
                try:
                    return str(p), self.grab_banner(r.ip, p)
                except Exception:
                    return str(p), ""
            with ThreadPoolExecutor(max_workers=min(20, len(r.open_ports) or 1)) as ex:
                futs = [ex.submit(_grab, p) for p in r.open_ports]
                for fut in as_completed(futs):
                    try:
                        p, banner = fut.result()
                        r.port_banners[p] = banner
                    except Exception:
                        pass

            # ── Plugin hook: on_after_ports (IP mode) ──
            self._fire_hook("on_after_ports", r.open_ports, r)

            if 443 in r.open_ports:
                self._log("SSL check on 443...")
                r.scheme = "https"
                r.port = 443
                ssl_data = self._ssl_combined(r.host, 443)
                r.ssl_expiry_days = ssl_data["expiry_days"]
                r.ssl_expiry_date = ssl_data["expiry_date"]
                r.ssl_weak_cipher = ssl_data["weak_cipher"]
                r.tls_summary = ssl_data["tls"]
                r.ssl_deep = ssl_data["deep"]
                # ── Plugin hook: on_after_ssl (IP mode) ──
                self._fire_hook("on_after_ssl", ssl_data, r)

            r.risk_score, r.risk_level = self.score_risk(r)
            # ── Plugin hook: on_scan_complete (IP mode) ──
            self._fire_hook("on_scan_complete", r)
            # ── Collect plugin graph nodes (IP mode) ──
            for p in self.plugins:
                fn = getattr(p, "get_graph_nodes", None)
                if callable(fn):
                    try:
                        nodes = fn(r)
                        if isinstance(nodes, list):
                            r.plugin_graph_nodes.extend(nodes)
                    except Exception:
                        pass
            r.scan_duration_ms = int((time.perf_counter() - t0) * 1000)
            self._log(f"IP scan complete in {r.scan_duration_ms}ms")
            return r

        base = self.base_url(r.scheme, r.host, r.port)
        resp = None

        # Skip HTTP probe if already detected as server node from connectivity check
        if not r.server_node:
            # ── Plugin hook: on_before_request ──
            self._fire_hook("on_before_request", "GET", r.normalized_url)

            self._log("Probing root...")
            resp, ms = self.probe_root(r.normalized_url)
            r.response_time_ms = ms
            r.status_code = resp.status_code if resp else None
            r.final_url = str(resp.url) if resp and hasattr(resp, 'url') else ""

        # ── Server node detection ──
        if resp is None and not r.server_node:
            self._log("No HTTP on default port — probing alternative ports...")
            r.no_http = True
            alt_found = self._probe_alt_ports(r.host)
            if alt_found:
                best_port, best_url, best_scheme = alt_found[0]
                r.alternative_http_ports = [p for p, _, _ in alt_found]
                self._log(f"HTTP found on alternative port {best_port} — switching")
                r.port = best_port
                r.scheme = best_scheme
                r.normalized_url = best_url
                base = self.base_url(r.scheme, r.host, r.port)
                resp, ms = self.probe_root(r.normalized_url)
                r.response_time_ms = ms
                r.status_code = resp.status_code if resp else None
                r.final_url = str(resp.url) if resp and hasattr(resp, 'url') else ""
                # If HTTP was found, it's no longer a server node
                if resp is not None:
                    r.server_node = False
            else:
                self._log("No HTTP server detected — server node mode")
                r.server_node = True

        r.headers = self.collect_headers(resp)
        body = resp.text if resp and hasattr(resp, 'text') else ""

        # ── Plugin hook: on_request ──
        self._fire_hook("on_request", r.normalized_url, resp, r)

        # ── Plugin hook: on_after_headers ──
        self._fire_hook("on_after_headers", dict(r.headers), r)

        if not r.server_node:
            self._log("Security checks...")
            if self.stop_event.is_set():
                return r
            # ── CPU checks (instant, pure computation — run inline) ──
            r.missing_security_headers = self.missing_headers(r.headers)
            r.fingerprint_hints = self.fingerprint(r.headers)
            r.cookie_issues, r.cookies_found = self.check_cookies(resp)
            r.hsts_enabled = self.check_hsts(r.headers, resp, r.host)
            r.clickjacking_protected = self.check_clickjacking(r.headers)
            r.mixed_content = self.check_mixed(resp)
            r.directory_listing = self.check_dir_listing(resp, r.normalized_url)
            r.version_hints, r.detected_cms, r.detected_frameworks = self.detect_cms(resp, body)

            # ── I/O checks (HTTP/socket — run in parallel, ~6× faster) ──
            # NOTE: httpx.Client is NOT thread-safe, so we use requests.Session
            # per-thread or fallback to sequential for HTTP checks.
            # SSL check is socket-based (thread-safe), so it runs in the pool.
            ssl_data = self._ssl_combined(r.host, r.port)

            # For HTTP checks, run sequentially if using httpx (not thread-safe),
            # or in parallel if using requests (which IS thread-safe).
            if HAS_HTTPX:
                r.allowed_methods, r.trace_enabled = self.probe_methods(r.normalized_url)
                r.cors_issues = self.check_cors(r.normalized_url)
                r.http_to_https_redirect = self.check_http_https(r.host, r.port)
                r.xss_reflection = self.check_xss(r.normalized_url, baseline_body=body)
                r.sql_errors = self.check_sql_errors(r.normalized_url)
            else:
                with ThreadPoolExecutor(max_workers=5) as io_pool:
                    fut_methods  = io_pool.submit(self.probe_methods, r.normalized_url)
                    fut_cors     = io_pool.submit(self.check_cors, r.normalized_url)
                    fut_https    = io_pool.submit(self.check_http_https, r.host, r.port)
                    fut_xss      = io_pool.submit(self.check_xss, r.normalized_url, baseline_body=body)
                    fut_sql      = io_pool.submit(self.check_sql_errors, r.normalized_url)

                    try:
                        r.allowed_methods, r.trace_enabled = fut_methods.result()
                    except Exception:
                        r.allowed_methods, r.trace_enabled = [], False
                    try:
                        r.cors_issues = fut_cors.result()
                    except Exception:
                        r.cors_issues = []
                    try:
                        r.http_to_https_redirect = fut_https.result()
                    except Exception:
                        r.http_to_https_redirect = False
                    try:
                        r.xss_reflection = fut_xss.result()
                    except Exception:
                        r.xss_reflection = False
                    try:
                        r.sql_errors = fut_sql.result()
                    except Exception:
                        r.sql_errors = []

            r.ssl_expiry_days = ssl_data["expiry_days"]
            r.ssl_expiry_date = ssl_data["expiry_date"]
            r.ssl_weak_cipher = ssl_data["weak_cipher"]
            r.tls_summary = ssl_data["tls"]
            r.ssl_deep = ssl_data["deep"]

            # ── Plugin hook: on_after_ssl ──
            self._fire_hook("on_after_ssl", ssl_data, r)

            if self.stop_event.is_set():
                return r
            self._log("WAF detection...")
            r.waf_detected = self.detect_waf(resp)

            self._log("Version detection...")
            versions = self.detect_versions(resp, body)
            version_strs = [f"{v['name']}: {v['version']}" for v in versions]
            # Merge CMS hints with version hints (avoid duplicates)
            seen = set(r.version_hints)
            for vs in version_strs:
                if vs not in seen:
                    r.version_hints.append(vs)
                    seen.add(vs)
        else:
            self._log("Server node mode — skipping HTTP-dependent checks")
            versions = []
            # Try SSL check even without HTTP (e.g. server with SSL on 443)
            try:
                ssl_data = self._ssl_combined(r.host, 443)
                r.ssl_expiry_days = ssl_data["expiry_days"]
                r.ssl_expiry_date = ssl_data["expiry_date"]
                r.ssl_weak_cipher = ssl_data["weak_cipher"]
                r.tls_summary = ssl_data["tls"]
                r.ssl_deep = ssl_data["deep"]
                # ── Plugin hook: on_after_ssl (server node mode) ──
                self._fire_hook("on_after_ssl", ssl_data, r)
            except Exception:
                pass

        if self.stop_event.is_set():
            return r
        self._log("Parallel checks (DNS, CVE, subdomains)...")
        # NOTE: httpx.Client is NOT thread-safe — _ip_geo and _asn_lookup use
        # self._http_get → self.client.get(). When HAS_HTTPX, run those sequentially.
        # check_dns, check_cve, check_subdomains, _rev_dns use subprocess — thread-safe.
        if HAS_HTTPX:
            r.dns_records = self.check_dns(r.host)
            r.cve_findings = self.check_cve(versions)
            r.subdomains = self.check_subdomains(r.host)
            r.ip_geo = self._ip_geo(r.ip)
            r.asn_info = self._asn_lookup(r.ip)
            r.reverse_dns = self._rev_dns(r.ip)
        else:
            with ThreadPoolExecutor(max_workers=6) as ex:
                dns_fut = ex.submit(self.check_dns, r.host)
                cve_fut = ex.submit(self.check_cve, versions)
                sub_fut = ex.submit(self.check_subdomains, r.host)
                ip_fut = ex.submit(self._ip_geo, r.ip)
                asn_fut = ex.submit(self._asn_lookup, r.ip)
                rev_fut = ex.submit(self._rev_dns, r.ip)
                try:
                    r.dns_records = dns_fut.result()
                except Exception:
                    pass
                try:
                    r.cve_findings = cve_fut.result()
                except Exception:
                    pass
                try:
                    r.subdomains = sub_fut.result()
                except Exception:
                    pass
                try:
                    r.ip_geo = ip_fut.result()
                except Exception:
                    pass
                try:
                    r.asn_info = asn_fut.result()
                except Exception:
                    pass
                try:
                    r.reverse_dns = rev_fut.result()
                except Exception:
                    pass

        if self.stop_event.is_set():
            return r
        self._log("Port scan...")
        r.open_ports = self.scan_ports(r.ip)

        self._log("Banner grabbing...")
        r.port_banners = {}
        def _grab(p):
            try:
                return str(p), self.grab_banner(r.ip, p)
            except Exception:
                return str(p), ""
        with ThreadPoolExecutor(max_workers=min(20, len(r.open_ports) or 1)) as ex:
            futs = [ex.submit(_grab, p) for p in r.open_ports]
            for fut in as_completed(futs):
                if self.stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    p, banner = fut.result()
                    r.port_banners[p] = banner
                except Exception:
                    pass

        # ── Plugin hook: on_after_ports ──
        self._fire_hook("on_after_ports", r.open_ports, r)

        if self.stop_event.is_set():
            return r

        if not r.server_node:
            all_paths = list(dict.fromkeys(
                self.custom_paths + GENERIC_PATHS + WP_PATHS + LARAVEL_PATHS +
                DRUPAL_PATHS + JOOMLA_PATHS + SPRING_PATHS + DJANGO_PATHS + NEXTJS_PATHS
            ))
            self._log(f"Scanning {len(all_paths)} paths...")
            r.discovered_paths, r.critical_paths = self.scan_paths(base, all_paths)
            r.total_paths_scanned = len(all_paths)
            # ── Plugin hook: on_after_paths ──
            self._fire_hook("on_after_paths", r.discovered_paths, r)
        else:
            self._log("Server node mode — skipping path scanning")

        if r.trace_enabled: r.anomaly_hints.append("TRACE enabled")
        if any(m in ("PUT", "DELETE") for m in r.allowed_methods): r.anomaly_hints.append(f"Risky methods: {', '.join(r.allowed_methods)}")
        if not r.server_node:
            if not r.hsts_enabled: r.anomaly_hints.append("HSTS missing")
            if not r.http_to_https_redirect: r.anomaly_hints.append("No HTTPS redirect")
            if r.directory_listing: r.anomaly_hints.append("Directory listing")
            if r.xss_reflection: r.anomaly_hints.append("XSS reflection")
        if r.ssl_expiry_days is not None and r.ssl_expiry_days < 30: r.anomaly_hints.append(f"SSL expires in {r.ssl_expiry_days}d!")
        if r.ssl_weak_cipher: r.anomaly_hints.append("Weak SSL cipher")

        r.risk_score, r.risk_level = self.score_risk(r)

        # ── Plugin hook: on_scan_complete ──
        self._fire_hook("on_scan_complete", r)

        # ── Collect plugin graph nodes ──
        for p in self.plugins:
            fn = getattr(p, "get_graph_nodes", None)
            if callable(fn):
                try:
                    nodes = fn(r)
                    if isinstance(nodes, list):
                        r.plugin_graph_nodes.extend(nodes)
                except Exception:
                    pass

        r.scan_duration_ms = int((time.perf_counter() - t0) * 1000)
        self._log(f"Complete in {r.scan_duration_ms}ms — Risk: {r.risk_level.upper()}")
        return r

    def scan_extended(self, r):
        if self.stop_event.is_set():
            return r
        is_server = getattr(r, 'server_node', False)
        base = self.base_url(r.scheme, r.host, r.port)
        resp_root = None

        # For server nodes: skip HTTP-only deep checks, only do SSL/DNS/network
        if is_server:
            self._log("[deep] Server node mode — SSL/DNS/network checks only")
            # Still try to get a response for non-HTTP checks
            try:
                resp_root, _ = self._req("GET", r.normalized_url, timeout=FAST_TIMEOUT)
            except Exception:
                pass
        else:
            try:
                resp_root, _ = self._req("GET", r.normalized_url, timeout=FAST_TIMEOUT)
            except Exception:
                pass

        if self.stop_event.is_set():
            return r
        self._log("[deep] SSL deep check...")
        r.ssl_deep = self._ssl_deep(r.host, r.port, r.scheme)

        if not is_server:
            self._log("[deep] HTTP methods...")
            r.http_methods_full = self._http_methods_full(r.normalized_url)

            if self.stop_event.is_set():
                return r
            self._log("[deep] Security headers...")
            r.security_txt = self._check_security_txt(base)
            r.permissions_policy = r.headers.get("Permissions-Policy", r.headers.get("permissions-policy", "NOT SET"))
            csp = r.headers.get("Content-Security-Policy", r.headers.get("content-security-policy", ""))
            r.csp_analysis = self._analyze_csp(csp)
            r.expect_ct = r.headers.get("Expect-CT", r.headers.get("expect-ct", "NOT SET"))
            r.referrer_policy = r.headers.get("Referrer-Policy", r.headers.get("referrer-policy", "NOT SET"))
            r.x_permitted_cross = r.headers.get("X-Permitted-Cross-Domain-Policies", r.headers.get("x-permitted-cross-domain-policies", "NOT SET"))

            if self.stop_event.is_set():
                return r
            self._log("[deep] Performance...")
            r.ttfb_ms, r.content_size, r.content_encoding = self._measure_perf(r.normalized_url)
            r.redirect_chain = self._trace_redirects(r.normalized_url)

            if self.stop_event.is_set():
                return r
            self._log("[deep] Recon...")
            body = resp_root.text if resp_root and hasattr(resp_root, 'text') else ""
            r.emails_found = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body)))[:20]
            r.phones_found = list(set(re.findall(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', body)))[:15]
            r.social_links = list(set(re.findall(r'https?://(?:www\.)?(?:facebook|twitter|x|instagram|linkedin|youtube|tiktok|github|telegram|vk)\.[^\s"\'<>]+', body)))[:15]
            r.meta_tags = self._extract_meta(body)
            r.hidden_forms = self._extract_forms(body)
            r.external_links = self._extract_external(body, r.host)[:30]
            r.js_libraries = self._detect_js(body)
            r.server_banner = r.headers.get("Server", r.headers.get("server", ""))
        else:
            body = resp_root.text if resp_root and hasattr(resp_root, 'text') else ""
            r.server_banner = r.headers.get("Server", r.headers.get("server", ""))

        if self.stop_event.is_set():
            return r
        self._log("[deep] IP info...")
        r.reverse_dns = self._rev_dns(r.ip)

        if not is_server:
            if self.stop_event.is_set():
                return r
            self._log("[deep] Injections & leaks...")
            ss_inj = self.scan_settings
            if ss_inj.get("injections_leaks", True):
                def _run_check(name, func, *args):
                    try:
                        return (name, func(*args))
                    except Exception:
                        return (name, [] if name != "host_header_inject" else "SAFE")

                checks = [
                    ("host_header_inject", self._host_header_inject, base),
                    ("crlf_injection", self._crlf_check, base),
                    ("open_redirect", self._open_redirect, base),
                    ("dir_traversal", self._dir_traversal, base),
                    ("backup_files", self._check_backup, base),
                    ("source_leak", self._check_source_leak, base),
                    ("admin_panels", self._check_admin_panels, base),
                    ("login_pages", self._check_login_pages, base),
                    ("api_endpoints", self._check_api_endpoints, base, body),
                ]
                # NOTE: httpx.Client is NOT thread-safe — run sequentially when HAS_HTTPX.
                # requests.Session IS thread-safe — safe for ThreadPoolExecutor.
                if HAS_HTTPX:
                    for name, func, *args in checks:
                        if self.stop_event.is_set():
                            break
                        try:
                            setattr(r, name, func(*args))
                        except Exception:
                            pass
                else:
                    with ThreadPoolExecutor(max_workers=6) as ex:
                        futures = {ex.submit(_run_check, n, f, *a): n for n, f, *a in checks}
                        for fut in as_completed(futures):
                            if self.stop_event.is_set():
                                ex.shutdown(wait=False, cancel_futures=True)
                                break
                            try:
                                name, result = fut.result()
                                setattr(r, name, result)
                            except Exception:
                                pass

            if self.stop_event.is_set():
                return r
            self._log("[advanced] Payload mutation...")
            r.mutated_payloads = self._payload_mutation(body, base)
        else:
            self._log("[deep] Server node — skipping injections, mutations, HTTP checks")

        ss = self.scan_settings

        if self.stop_event.is_set():
            return r
        self._log("[advanced] Parallel advanced checks...")
        adv_checks = []

        if is_server:
            # Server node: only DNS/network checks, skip all HTTP-dependent
            self._log("[advanced] Server node — DNS/network checks only")
            if ss.get("zone_transfer", True):
                adv_checks.append(("zone_transfer", lambda: self._zone_transfer(r.host)))
            if ss.get("subdomain_takeover", True):
                adv_checks.append(("subdomain_takeover", lambda: self._subdomain_takeover(r.host)))
            if ss.get("email_security", True):
                adv_checks.append(("email_security", lambda: self._email_security(r.host)))
            if ss.get("ct_logs", True):
                adv_checks.append(("ct_logs", lambda: self._ct_search(r.host)))
            if ss.get("whois", True):
                adv_checks.append(("whois", lambda: self._whois_lookup(r.ip)))
            if ss.get("cvss_scoring", True):
                adv_checks.append(("cvss_scores", lambda: self._calculate_cvss(r)))
            if ss.get("shodan", True):
                adv_checks.append(("shodan", lambda: self._shodan_lookup(r.ip)))
        else:
            # Normal web scan: all checks
            if ss.get("supply_chain", True):
                adv_checks.append(("supply_chain", lambda: self._supply_chain(body, r.host)))
            if ss.get("graphql", True):
                adv_checks.append(("graphql", lambda: self._graphql_scan(base)))
            if ss.get("websocket", True):
                adv_checks.append(("websocket_results", lambda: self._websocket_scan(base, body)))
            if ss.get("session_manip", True):
                adv_checks.append(("session_issues", lambda: self._session_manipulation(base)))
            if ss.get("chaos_scan", True):
                adv_checks.append(("chaos_findings", lambda: self._chaos_scan(base)))
            if ss.get("jwt_analysis", True):
                adv_checks.append(("jwt_tokens", lambda: self._jwt_analysis(r)))
            if ss.get("ssti", True):
                adv_checks.append(("ssti_results", lambda: self._ssti_check(base)))
            if ss.get("zone_transfer", True):
                adv_checks.append(("zone_transfer", lambda: self._zone_transfer(r.host)))
            if ss.get("subdomain_takeover", True):
                adv_checks.append(("subdomain_takeover", lambda: self._subdomain_takeover(r.host)))
            if ss.get("email_security", True):
                adv_checks.append(("email_security", lambda: self._email_security(r.host)))
            if ss.get("http_smuggling", True):
                adv_checks.append(("http_smuggling", lambda: self._http_smuggling(base)))
            if ss.get("deep_tech_stack", True):
                adv_checks.append(("tech_stack_deep", lambda: self._tech_stack_deep(r)))
            if ss.get("hidden_endpoints", True):
                adv_checks.append(("hidden_endpoints", lambda: self._find_hidden_endpoints(base, body)))
            if ss.get("waf_fingerprint", True):
                adv_checks.append(("waf_fingerprint", lambda: self._waf_fingerprint(r, body)))
            if ss.get("rate_limit", True):
                adv_checks.append(("rate_limit", lambda: self._rate_limit_detect(base)))
            if ss.get("cors_deep", True):
                adv_checks.append(("cors_deep", lambda: self._cors_deep_test(base)))
            if ss.get("js_analysis", True):
                adv_checks.append(("js_analysis", lambda: self._js_analysis(base, body)))
            if ss.get("ct_logs", True):
                adv_checks.append(("ct_logs", lambda: self._ct_search(r.host)))
            if ss.get("whois", True):
                adv_checks.append(("whois", lambda: self._whois_lookup(r.ip)))
            if ss.get("exploit_verify", True):
                adv_checks.append(("exploit_verified", lambda: self._verify_exploits(r)))
            if ss.get("cvss_scoring", True):
                adv_checks.append(("cvss_scores", lambda: self._calculate_cvss(r)))
            if ss.get("shodan", True):
                adv_checks.append(("shodan", lambda: self._shodan_lookup(r.ip)))

        results = {}
        # NOTE: httpx.Client is NOT thread-safe — run sequentially when HAS_HTTPX.
        # requests.Session IS thread-safe — safe for ThreadPoolExecutor.
        if HAS_HTTPX:
            for name, fn in adv_checks:
                if self.stop_event.is_set():
                    break
                try:
                    results[name] = fn()
                except Exception as e:
                    self._collect_error(r, name, e)
        else:
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = {ex.submit(fn): name for name, fn in adv_checks}
                for fut in as_completed(futures):
                    if self.stop_event.is_set():
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
                    name = futures[fut]
                    try:
                        results[name] = fut.result()
                    except Exception as e:
                        self._collect_error(r, name, e)

        for name, result in results.items():
            if self.stop_event.is_set():
                break
            if name == "graphql":
                r.graphql_schema, r.graphql_vulns = result
            else:
                setattr(r, name, result)

        if self.stop_event.is_set():
            return r

        if not is_server:
            self._log("[advanced] DSL rules...")
            r.dsl_results = self._dsl_scan(r)

            if self.stop_event.is_set():
                return r
            if ss.get("screenshots", False):
                self._log("[recon] Screenshots...")
                r.screenshots = self._take_screenshot(base, r.host)
        else:
            self._log("[deep] Server node — skipping DSL rules and screenshots")

        if self.stop_event.is_set():
            return r
        self._log("[advanced] AI analysis...")
        r.ai_findings = self._ai_analyze(r)

        self._log("[extended] Done")
        return r

    # =================== JWT ANALYSIS ===================

    def _payload_mutation(self, body, base=""):
        ss = self.scan_settings
        mutations = []
        base_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "{{7*7}}",
            "${7*7}",
            "1; DROP TABLE users",
            "../../etc/passwd",
            "1' UNION SELECT NULL--",
            "%00",
        ]
        target = base.rstrip("/") + "/" if base else ""
        for payload in base_payloads[:ss.get("limit_payload_mutation", 2)]:
            variants = self._mutate(payload)
            for v in variants[:ss.get("limit_variant_per_payload", 3)]:
                try:
                    resp, _ = self._req("GET", f"{target}?q={v}", timeout=FAST_TIMEOUT)
                    if resp and resp.status_code == 200 and len(resp.text) > 100:
                        mutations.append({
                            "original": payload, "mutated": v,
                            "status": resp.status_code, "len": len(resp.text),
                            "verdict": "POSSIBLE_BYPASS"
                        })
                except Exception:
                    pass
        return mutations[:30]

    def _mutate(self, payload):
        variants = [payload]
        # URL encode
        variants.append(urllib.parse.quote(payload, safe=''))
        # Double encode
        variants.append(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
        # HTML entities
        variants.append(payload.replace("'", "&#39;").replace('"', "&quot;").replace("<", "&lt;"))
        # Unicode
        variants.append(payload.replace("'", "\u2019").replace('"', "\u201c"))
        # Case swap
        variants.append(payload.swapcase())
        # Whitespace injection
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "\t"))
        # Null byte
        variants.append(payload + "%00")
        # Backtick
        variants.append(payload.replace("'", "`"))
        # Mixed encoding
        variants.append(payload.replace("o", "%6f").replace("r", "%72"))
        return list(dict.fromkeys(variants))

    # =================== JWT ANALYSIS ===================

    def _jwt_analysis(self, report):
        findings = []
        # Check headers for JWT
        for header_name, header_val in report.headers.items():
            if isinstance(header_val, str) and header_val.startswith("eyJ"):
                findings.append(self._decode_jwt(header_val, f"Header: {header_name}"))
        # cookie_issues is a list of strings like "'name' missing HttpOnly"
        # No JWT data to extract from cookie_issues (they're issue descriptions, not values)
        # Check response for JWT patterns
        try:
            resp, _ = self._req("GET", report.normalized_url, timeout=FAST_TIMEOUT)
            if resp:
                for match in re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', resp.text):
                    found = self._decode_jwt(match, "Response body")
                    if found and not any(f.get("token") == match[:50] for f in findings if isinstance(f, dict)):
                        findings.append(found)
        except Exception:
            pass
        return [f for f in findings if f]

    def _decode_jwt(self, token, source):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            alg = header.get("alg", "none")
            issues = []
            if alg == "none":
                issues.append("Algorithm 'none' — signature bypass possible")
            elif alg in ("HS256", "HS384", "HS512"):
                issues.append(f"HMAC algorithm {alg} — brute-forceable if secret is weak")
            elif alg in ("RS256", "RS384", "RS512"):
                pass  # RSA is ok
            if payload.get("exp"):
                exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    issues.append(f"Token EXPIRED at {exp_dt.isoformat()}")
            if not payload.get("exp"):
                issues.append("No expiration (exp) claim")
            if not payload.get("iss"):
                issues.append("No issuer (iss) claim")
            if not payload.get("aud"):
                issues.append("No audience (aud) claim")
            # Check for sensitive data
            sensitive_keys = ["password", "secret", "token", "key", "ssn", "credit"]
            for sk in sensitive_keys:
                if any(sk in str(k).lower() for k in payload.keys()):
                    issues.append(f"Sensitive data in payload: '{sk}'")
            return {
                "token": token[:50] + "...",
                "source": source,
                "algorithm": alg,
                "header": header,
                "payload_preview": {k: str(v)[:50] for k, v in list(payload.items())[:10]},
                "issues": issues,
                "severity": "HIGH" if issues else "INFO",
            }
        except Exception:
            return None

    # =================== SSTI CHECK ===================

    def _ssti_check(self, base):
        ss = self.scan_settings
        findings = []
        templates = [
            ("{{7*7}}", "49", "Jinja2/Twig/Mustache"),
            ("${7*7}", "49", "FreeMarker/Velocity"),
            ("<%= 7*7 %>", "49", "ERB"),
            ("#{7*7}", "49", "Ruby/Slim"),
            ("{{self.__class__.__mro__[1].__subclasses__()}}", "[", "Python Jinja2 RCE"),
            ("${T(java.lang.Runtime).getRuntime().exec('id')}", "", "Java Spring SSTI"),
        ][:ss.get("limit_ssti", 4)]
        for payload, expected, engine in templates:
            try:
                url = base.rstrip("/") + "/?name=" + urllib.parse.quote(payload)
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp and expected in resp.text:
                    findings.append({
                        "payload": payload,
                        "engine": engine,
                        "response_preview": resp.text[:200],
                        "severity": "CRITICAL",
                        "detail": f"SSTI confirmed with {engine} engine"
                    })
            except Exception:
                pass
        # POST body injection
        for payload, expected, engine in templates[:min(3, ss.get("limit_ssti", 4))]:
            try:
                resp, _ = self._req("POST", base, timeout=FAST_TIMEOUT,
                                     content=f"name={urllib.parse.quote(payload)}",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
                if resp and expected in resp.text:
                    findings.append({
                        "payload": payload,
                        "engine": engine,
                        "method": "POST",
                        "severity": "CRITICAL",
                        "detail": f"SSTI via POST body with {engine}"
                    })
            except Exception:
                pass
        return findings

    # =================== ZONE TRANSFER ===================

    def _zone_transfer(self, host):
        if not self._is_valid_host(host):
            return []
        findings = []
        # Get nameservers
        try:
            result = subprocess.run(
                ["nslookup", "-type=NS", host],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            ns_servers = re.findall(r'nameserver\s*=\s*([\d.]+)', result.stdout)
        except Exception:
            ns_servers = []
        for ns in ns_servers:
            try:
                result = subprocess.run(
                    ["nslookup", "-type=AXFR", host, ns],
                    capture_output=True, text=True, timeout=15,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                output = result.stdout
                if "xfr" in output.lower() or "transfer" in output.lower():
                    records = re.findall(r'(\w+)\s+(?:IN\s+)?(\w+)\s+(.+)', output)
                    findings.append({
                        "server": ns,
                        "severity": "CRITICAL",
                        "detail": f"Zone transfer successful! {len(records)} records leaked",
                        "records": [f"{r[0]} {r[1]} {r[2]}" for r in records[:20]]
                    })
                elif "refused" in output.lower() or "not authorized" in output.lower():
                    pass  # Normal
                elif output.strip():
                    findings.append({
                        "server": ns,
                        "severity": "INFO",
                        "detail": f"NS lookup returned: {output[:200]}"
                    })
            except Exception:
                pass
        return findings

    # =================== SUBDOMAIN TAKEOVER ===================

    def _subdomain_takeover(self, host):
        ss = self.scan_settings
        findings = []
        # CNAME-based check
        vulnerable_services = {
            "amazonaws.com": ["s3.amazonaws.com", "elasticbeanstalk", "cloudfront.net"],
            "herokuapp.com": ["herokuspace.com"],
            "azurewebsites.net": ["azurewebsites.net"],
            "cloudapp.net": ["cloudapp.net"],
            "appspot.com": ["appspot.com"],
            "github.io": ["github.io"],
            "bitbucket.io": ["bitbucket.io"],
            "shopify.com": ["myshopify.com"],
            "surge.sh": ["surge.sh"],
            "zendesk.com": ["zendesk.com"],
            "readme.io": ["readme.io"],
            "ghost.io": ["ghost.io"],
            "pantheon.io": ["pantheon.io"],
            "fastly.net": ["fastly.net"],
            "netlify.app": ["netlify.app"],
            "vercel.app": ["vercel.app"],
            "pages.dev": ["pages.dev"],
        }
        # Check common subdomains
        common_subs = ["www", "api", "dev", "staging", "test", "admin", "mail", "ftp", "vpn", "shop", "blog", "cdn", "static", "assets", "img"][:ss.get("limit_subdomains", 6)]
        for sub in common_subs:
            fqdn = f"{sub}.{host}"
            try:
                cname = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                ip = cname[0][4][0] if cname else None
                if ip:
                    # Check if CNAME points to vulnerable service
                    try:
                        r, _ = self._req("GET", f"https://{fqdn}", timeout=3)
                        body = r.text[:500] if r and hasattr(r, 'text') else ""
                        status = r.status_code if r else 0
                    except Exception:
                        body = ""
                        status = 0
                    for svc, patterns in vulnerable_services.items():
                        if any(p in body.lower() for p in patterns):
                            findings.append({
                                "subdomain": fqdn,
                                "ip": ip,
                                "service": svc,
                                "severity": "HIGH",
                                "detail": f"Possible takeover: {fqdn} points to {svc} but content suggests unclaimed"
                            })
                            break  # one finding per subdomain
                    if status in (404, 403) and body:
                        for svc, patterns in vulnerable_services.items():
                            if any(p in body.lower() for p in patterns):
                                # Only add if not already found above
                                if not any(f["subdomain"] == fqdn for f in findings):
                                    findings.append({
                                        "subdomain": fqdn,
                                        "service": svc,
                                        "severity": "HIGH",
                                        "detail": f"HTTP {status} with {svc} markers — likely takeover candidate"
                                    })
                                break
            except Exception:
                pass
        return findings

    # =================== EMAIL SECURITY ===================

    def _email_security(self, host):
        if not self._is_valid_host(host):
            return {"spf": "", "dmarc": "", "dkim": "", "issues": []}
        result = {"spf": "", "dmarc": "", "dkim": "", "issues": []}
        # SPF
        try:
            r = subprocess.run(
                ["nslookup", "-type=TXT", host],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            spf_match = re.search(r'"(v=spf1[^"]+)"', r.stdout)
            if spf_match:
                result["spf"] = spf_match.group(1)
            else:
                result["issues"].append("SPF record not found")
        except Exception:
            pass
        # DMARC
        try:
            r = subprocess.run(
                ["nslookup", "-type=TXT", f"_dmarc.{host}"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            dmarc_match = re.search(r'"(v=DMARC1[^"]+)"', r.stdout)
            if dmarc_match:
                result["dmarc"] = dmarc_match.group(1)
                if "p=none" in result["dmarc"]:
                    result["issues"].append("DMARC policy is 'none' (monitoring only)")
            else:
                result["issues"].append("DMARC record not found")
        except Exception:
            pass
        # DKIM (common selectors) - parallel
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mandrill", "everlytickey1", "dkim", "mail"]
        def _check_dkim(sel):
            try:
                r = subprocess.run(
                    ["nslookup", "-type=TXT", f"{sel}._domainkey.{host}"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                if "v=DKIM1" in r.stdout or "p=MIGf" in r.stdout:
                    return f"{sel}._domainkey.{host}"
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=9) as ex:
            for res in ex.map(_check_dkim, dkim_selectors):
                if res:
                    result["dkim"] = res
                    break
        if not result["dkim"]:
            result["issues"].append("DKIM record not found")
        return result

    # =================== HTTP SMUGGLING ===================

    def _http_smuggling(self, base):
        findings = []
        # CL.TE detection
        smuggle_payloads = [
            {
                "name": "CL.TE",
                "headers": {"Transfer-Encoding": "chunked", "Content-Length": "6"},
                "body": "0\r\n\r\nSMUGGLED",
                "detect": "SMUGGLED",
            },
            {
                "name": "TE.CL",
                "headers": {"Transfer-Encoding": "chunked", "Content-Length": "3"},
                "body": "8\r\nSMUGGLED\r\n0\r\n\r\n",
                "detect": "SMUGGLED",
            },
            {
                "name": "TE.TE",
                "headers": {"Transfer-Encoding": " chunked"},
                "body": "0\r\n\r\nSMUGGLED",
                "detect": "SMUGGLED",
            },
        ]
        for payload in smuggle_payloads:
            try:
                headers = {
                    "Host": base.split("//")[1].split("/")[0],
                    "User-Agent": "SCChecker/1.0",
                }
                headers.update(payload["headers"])
                resp, _ = self._req("POST", base, timeout=FAST_TIMEOUT,
                                     content=payload["body"], headers=headers)
                if resp and payload["detect"] in resp.text:
                    findings.append({
                        "type": payload["name"],
                        "severity": "CRITICAL",
                        "detail": f"HTTP Request Smuggling ({payload['name']}) confirmed"
                    })
            except Exception:
                pass
        return findings

    # =================== TECH STACK DEEP ===================

    def _tech_stack_deep(self, report):
        techs = []
        # Server header analysis
        if report.server_banner:
            sv = report.server_banner.lower()
            if "apache" in sv: techs.append({"name": "Apache", "detail": report.server_banner})
            elif "nginx" in sv: techs.append({"name": "Nginx", "detail": report.server_banner})
            elif "iis" in sv: techs.append({"name": "IIS", "detail": report.server_banner})
            elif "cloudflare" in sv: techs.append({"name": "Cloudflare", "detail": report.server_banner})
        # Framework detection from headers
        powered = report.headers.get("x-powered-by", "").lower()
        if powered:
            techs.append({"name": "X-Powered-By", "detail": powered})
        # Check for common frameworks
        try:
            resp, _ = self._req("GET", report.normalized_url, timeout=FAST_TIMEOUT)
            if resp:
                body = resp.text[:5000] if hasattr(resp, 'text') else ""
                hdrs = dict(resp.headers)
                # WordPress
                if "wp-content" in body or "wp-includes" in body:
                    techs.append({"name": "WordPress", "detail": "wp-content/includes detected"})
                # Laravel
                if "laravel" in body.lower() or "XSRF-TOKEN" in str(dict(resp.cookies)):
                    techs.append({"name": "Laravel", "detail": "Laravel signatures detected"})
                # Django
                if "csrfmiddlewaretoken" in body or "django" in str(hdrs).lower():
                    techs.append({"name": "Django", "detail": "Django signatures detected"})
                # React/Next.js
                if "__NEXT_DATA__" in body or "_next/static" in body:
                    techs.append({"name": "Next.js", "detail": "Next.js SSR detected"})
                if "react" in body.lower() or "_react" in body:
                    techs.append({"name": "React", "detail": "React client-side detected"})
                # Vue/Nuxt
                if "__nuxt" in body or "nuxt" in body.lower():
                    techs.append({"name": "Nuxt.js", "detail": "Nuxt SSR detected"})
                if "vue" in body.lower():
                    techs.append({"name": "Vue.js", "detail": "Vue.js detected"})
                # Angular
                if "ng-version" in body or "angular" in body.lower():
                    techs.append({"name": "Angular", "detail": "Angular detected"})
                # jQuery version
                jq_ver = re.search(r'jquery[/-](\d+\.\d+\.\d+)', body)
                if jq_ver:
                    techs.append({"name": "jQuery", "detail": f"Version {jq_ver.group(1)}"})
                # Bootstrap
                bs_ver = re.search(r'bootstrap[/-](\d+\.\d+\.\d+)', body)
                if bs_ver:
                    techs.append({"name": "Bootstrap", "detail": f"Version {bs_ver.group(1)}"})
                # PHP
                if ".php" in body.lower() or "phpsessid" in str(dict(resp.cookies)).lower():
                    techs.append({"name": "PHP", "detail": "PHP signatures detected"})
                # Node.js
                if "x-powered-by: express" in str(hdrs).lower():
                    techs.append({"name": "Node.js/Express", "detail": "Express framework"})
        except Exception:
            pass
        return techs

    # =================== HIDDEN ENDPOINTS ===================

    def _find_hidden_endpoints(self, base, body):
        endpoints = []
        # Extract from JS
        js_urls = re.findall(r'["\'](/[a-zA-Z0-9/_-]+(?:\?[^"\']*)?)["\']', body)
        api_patterns = re.findall(r'["\'](?:https?://[^"\']+/(?:api|v1|v2|graphql|rest)/[^"\']+)["\']', body)
        all_urls = list(set(js_urls + api_patterns))[:50]
        def _check_ep(url):
            if not url.startswith("http"):
                url = base.rstrip("/") + url
            try:
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp and resp.status_code in (200, 401, 403):
                    return {
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.text) if hasattr(resp, 'text') else 0,
                        "severity": "MEDIUM" if resp.status_code == 200 else "LOW",
                        "detail": f"HTTP {resp.status_code}"
                    }
            except Exception:
                pass
            return None
        # NOTE: httpx.Client is NOT thread-safe — _check_ep uses self._req.
        if HAS_HTTPX:
            for url in all_urls:
                result = _check_ep(url)
                if result:
                    endpoints.append(result)
        else:
            with ThreadPoolExecutor(max_workers=10) as ex:
                for result in ex.map(_check_ep, all_urls):
                    if result:
                        endpoints.append(result)
        # Check robots.txt for hidden paths
        try:
            resp, _ = self._req("GET", base.rstrip("/") + "/robots.txt", timeout=FAST_TIMEOUT)
            if resp and resp.status_code == 200:
                hidden = re.findall(r'Disallow:\s*(.+)', resp.text)
                for h in hidden[:10]:
                    h = h.strip()
                    if h and h != "/":
                        url = base.rstrip("/") + h
                        try:
                            resp2, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                            if resp2 and resp2.status_code == 200:
                                endpoints.append({
                                    "url": url,
                                    "status": resp2.status_code,
                                    "size": len(resp2.text) if hasattr(resp2, 'text') else 0,
                                    "severity": "MEDIUM",
                                    "detail": f"Found via robots.txt, HTTP {resp2.status_code}"
                                })
                        except Exception:
                            pass
        except Exception:
            pass
        return endpoints[:30]

    # =================== WAF FINGERPRINT ===================

    def _waf_fingerprint(self, r, body=""):
        """Deep WAF fingerprint — uses unified WAF_SIGNATURES."""
        result = {"detected": False, "name": "", "version": "", "rules": []}
        lower_headers = {k.lower(): v for k, v in r.headers.items()}
        body_lower = (body[:3000].lower() if body else "")
        for name, sigs in WAF_SIGNATURES.items():
            found = []
            for h in sigs.get("headers", []):
                if h.lower() in lower_headers:
                    found.append(f"header:{h}")
            for b in sigs.get("body", []):
                if b.lower() in body_lower:
                    found.append(f"body:{b}")
            if found:
                result["detected"] = True
                result["name"] = name
                result["rules"] = found
                break
        # Try to detect version from headers
        if result["detected"]:
            for h, v in r.headers.items():
                if "x-" in h.lower() and isinstance(v, str) and "version" in v.lower():
                    result["version"] = v[:50]
                    break
        return result

    # =================== RATE LIMIT DETECTION ===================

    def _rate_limit_detect(self, base):
        result = {"detected": False, "limit": 0, "remaining": 0, "reset": "", "headers": {}}
        rl_headers = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                       "retry-after", "x-rate-limit-limit", "x-rate-limit-remaining",
                       "x-rate-limit-reset", "ratelimit-limit", "ratelimit-remaining"]
        try:
            resp, _ = self._req("GET", base, timeout=FAST_TIMEOUT)
            if resp:
                for h in resp.headers:
                    hl = h.lower()
                    for rh in rl_headers:
                        if rh in hl:
                            result["headers"][h] = resp.headers[h]
                            result["detected"] = True
                            if "limit" in hl:
                                try: result["limit"] = int(resp.headers[h])
                                except (ValueError, TypeError): pass
                            elif "remaining" in hl:
                                try: result["remaining"] = int(resp.headers[h])
                                except (ValueError, TypeError): pass
                            elif "reset" in hl:
                                result["reset"] = resp.headers[h]
        except Exception:
            pass
        # Also test rapid-fire to detect 429
        # NOTE: httpx.Client is NOT thread-safe, so we run sequentially when HAS_HTTPX.
        # Only parallelize when using requests.Session (which IS thread-safe).
        if not result["detected"]:
            def _rapid_fire():
                try:
                    resp, _ = self._req("GET", base, timeout=FAST_TIMEOUT)
                    return resp
                except Exception:
                    return None
            if HAS_HTTPX:
                # Sequential — httpx.Client not thread-safe
                rapid_results = [_rapid_fire() for _ in range(5)]
            else:
                # Parallel — requests.Session IS thread-safe
                with ThreadPoolExecutor(max_workers=5) as ex:
                    rapid_results = list(ex.map(lambda _: _rapid_fire(), range(5)))
            for resp in rapid_results:
                if resp and resp.status_code == 429:
                    result["detected"] = True
                    result["headers"]["status"] = "429 Too Many Requests"
                    ra = resp.headers.get("Retry-After", "")
                    if ra:
                        result["reset"] = ra
                    break
            if not result["detected"]:
                result["note"] = "No rate limiting detected after 5 rapid requests"
        return result

    # =================== DEEP CORS TEST ===================

    def _cors_deep_test(self, base):
        findings = []
        tests = [
            ("null origin", {"Origin": "null"}),
            ("localhost", {"Origin": "http://localhost"}),
            ("evil.com", {"Origin": "https://evil.com"}),
            ("subdomain", {"Origin": "https://test." + base.split("//")[-1].split("/")[0]}),
            ("double hostname", {"Origin": base.rstrip("/") + ".evil.com"}),
            ("http downgrade", {"Origin": base.replace("https://", "http://")}),
        ]
        for name, extra_headers in tests:
            try:
                headers = {"User-Agent": "Mozilla/5.0"}
                headers.update(extra_headers)
                resp, _ = self._req("GET", base, headers=headers, timeout=FAST_TIMEOUT)
                if resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao:
                        vuln = False
                        detail = f"ACAO: {acao}"
                        if acao == "*" and acac.lower() == "true":
                            vuln = True
                            detail += " | wildcard + credentials"
                        elif acao == "null" and acac.lower() == "true":
                            vuln = True
                            detail += " | null origin accepted"
                        elif name == "evil.com" and acao == "https://evil.com":
                            vuln = True
                            detail += " | reflects arbitrary origin"
                        elif name == "double hostname" and acao:
                            vuln = True
                            detail += " | accepts subdomain trick"
                        elif name == "http downgrade" and acao:
                            vuln = True
                            detail += " | accepts downgraded origin"
                        findings.append({
                            "test": name,
                            "vulnerable": vuln,
                            "acao": acao,
                            "acac": acac,
                            "detail": detail,
                            "severity": "HIGH" if vuln else "INFO",
                        })
            except Exception:
                pass
        return findings

    # =================== JS ANALYSIS ===================

    def _js_analysis(self, base, body):
        result = {"scripts": [], "endpoints": [], "secrets": [], "libs": [], "sri_missing": 0}
        # Parse script tags
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body)
        result["scripts"] = scripts[:20]

        # Resolve script URLs
        def _resolve_url(s):
            if s.startswith("//"):
                return "https:" + s
            elif s.startswith("/"):
                return base.rstrip("/") + s
            return s

        resolved = [(s, _resolve_url(s)) for s in scripts[:20]]

        # Secret patterns (pre-compiled)
        secret_patterns = [
            (re.compile(r'["\'](?:api[_-]?key|apikey|api_secret|secret[_-]?key)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "API Key"),
            (re.compile(r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "Password"),
            (re.compile(r'["\'](?:token|auth_token|access_token|bearer)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "Token"),
            (re.compile(r'["\'](?:aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key))["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', re.I), "AWS Key"),
            (re.compile(r'(?:sk|pk|rk)_[a-zA-Z0-9]{20,}', re.I), "Stripe Key"),
        ]

        def _analyze_one(item):
            orig, url = item
            endpoints = []
            secrets = []
            try:
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp and resp.status_code == 200:
                    js = resp.text[:50000]
                    api_urls = re.findall(r'["\'](?:https?://[^"\']+/api/[^"\']+)["\']', js)
                    api_paths = re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', js)
                    endpoints.extend(list(set(api_urls + api_paths))[:10])
                    for pat, label in secret_patterns:
                        matches = pat.findall(js)
                        for m in matches[:3]:
                            secrets.append({"type": label, "value": m[:40] + "...", "source": orig})
            except Exception:
                pass
            return endpoints, secrets

        # NOTE: httpx.Client is NOT thread-safe — _analyze_one uses self._req.
        if resolved:
            if HAS_HTTPX:
                for item in resolved:
                    eps, secs = _analyze_one(item)
                    result["endpoints"].extend(eps)
                    result["secrets"].extend(secs)
            else:
                with ThreadPoolExecutor(max_workers=min(len(resolved), 10)) as ex:
                    for eps, secs in ex.map(_analyze_one, resolved):
                        result["endpoints"].extend(eps)
                        result["secrets"].extend(secs)

        # Check SRI
        if '<script' in body:
            script_tags = re.findall(r'<script[^>]*>', body)
            for tag in script_tags:
                if 'src=' in tag and 'integrity=' not in tag:
                    result["sri_missing"] += 1

        result["endpoints"] = list(set(result["endpoints"]))[:20]
        result["secrets"] = result["secrets"][:10]
        return result

    # =================== CERTIFICATE TRANSPARENCY ===================

    def _ct_search(self, host):
        results = []
        try:
            resp = self._http_get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                seen = set()
                for entry in data[:50]:
                    name = entry.get("name_value", "")
                    issuer = entry.get("issuer_name", "")
                    not_before = entry.get("not_before", "")
                    key = f"{name}|{not_before}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "name": name,
                            "issuer": issuer[:60],
                            "not_before": not_before,
                        })
        except Exception:
            pass
        return results[:30]

    # =================== WHOIS LOOKUP ===================

    def _whois_lookup(self, ip):
        result = {"Registrar": "", "Created": "", "Expires": "", "Name Servers": "", "raw": ""}
        if not ip:
            return result
        try:
            # Use RDAP (free, no API key)
            resp = self._http_get(f"https://rdap.org/ip/{ip}", timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                events = {e.get("eventAction"): e.get("eventDate", "") for e in data.get("events", [])}
                result["Created"] = events.get("registration", "")
                result["Expires"] = events.get("expiration", "")
                result["Registrar"] = data.get("ldhName", "")
                ns = [n.get("ldhName", "") for n in data.get("nameservers", [])]
                result["Name Servers"] = ", ".join(ns[:5])
        except Exception:
            pass
        # Also try whois via socket (basic)
        try:
            whois_server = "whois.iana.org"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((whois_server, 43))
                s.send((ip + "\r\n").encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 1024 * 1024:
                        break
                text = data.decode("utf-8", errors="ignore")
                result["raw"] = text[:500]
                if not result["Registrar"]:
                    m = re.search(r'organisation:\s*(.+)', text, re.IGNORECASE)
                    if m:
                        result["Registrar"] = m.group(1).strip()
        except Exception:
            pass
        return result

    # =================== VERIFY EXPLOITS ===================

    def _verify_exploits(self, r):
        verified = []
        computed_base = self.base_url(r.scheme, r.host, r.port)
        # Verify XSS
        if r.xss_reflection:
            payload = "<scrIpt>alert(document.domain)</scrIpt>"
            for path in ["/", "/search", "/q", "/s", "/index"]:
                try:
                    url = computed_base.rstrip("/") + path + "?xss=" + requests.utils.quote(payload)
                    resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                    if resp and payload.lower() in resp.text.lower():
                        verified.append({"type": "XSS", "severity": "CRITICAL", "url": url, "detail": "Reflected XSS confirmed"})
                        break
                except Exception:
                    pass
        # Verify SQL errors
        if r.sql_errors:
            sqli_payloads = ["' OR '1'='1", "1' AND SLEEP(2)--", "1 UNION SELECT NULL--"]
            for p in sqli_payloads[:1]:
                for path in ["/", "/index", "/page", "/id"]:
                    try:
                        url = computed_base.rstrip("/") + path + "?id=" + requests.utils.quote(p)
                        resp, _ = self._req("GET", url, timeout=10)
                        if resp:
                            sql_indicators = ["sql syntax", "mysql_fetch", "ORA-", "SQLite", "pg_query", "Unclosed quotation"]
                            for ind in sql_indicators:
                                if ind.lower() in resp.text.lower():
                                    verified.append({"type": "SQLi", "severity": "CRITICAL", "url": url, "detail": f"SQL error confirmed: {ind}"})
                                    break
                    except Exception:
                        pass
        # Verify open redirect
        if r.open_redirect:
            redir_payloads = ["//evil.com", "/\\evil.com", "//evil%00.com"]
            for p in redir_payloads[:1]:
                try:
                    url = computed_base.rstrip("/") + "/redirect?url=" + requests.utils.quote(p)
                    resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT, allow_redirects=False)
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location", "")
                        if "evil.com" in loc:
                            verified.append({"type": "Open Redirect", "severity": "HIGH", "url": url, "detail": f"Redirects to: {loc}"})
                            break
                except Exception:
                    pass
        # Verify Host header injection
        if r.host_header_inject:
            try:
                resp, _ = self._req("GET", computed_base, headers={"Host": "evil.com"}, timeout=FAST_TIMEOUT)
                if resp and "evil.com" in resp.text:
                    verified.append({"type": "Host Header Injection", "severity": "HIGH", "url": computed_base, "detail": "Host header reflected in response"})
            except Exception:
                pass
        # Verify CRLF
        if r.crlf_injection:
            try:
                url = computed_base.rstrip("/") + "/test%0d%0aX-Injected:true"
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp and "X-Injected" in str(resp.headers):
                    verified.append({"type": "CRLF Injection", "severity": "HIGH", "url": url, "detail": "CRLF injection confirmed"})
            except Exception:
                pass
        return verified[:10]

    # =================== CVSS SCORING ===================

    def _calculate_cvss(self, r):
        scores = []
        def cvss_base(severity):
            m = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}
            return m.get(severity, 0.0)
        findings_map = [
            ("SQL Injection", "CRITICAL" if r.sql_errors else None),
            ("XSS Reflected", "HIGH" if r.xss_reflection else None),
            ("Open Redirect", "MEDIUM" if r.open_redirect else None),
            ("CRLF Injection", "HIGH" if r.crlf_injection else None),
            ("Host Header Injection", "HIGH" if r.host_header_inject else None),
            ("Directory Listing", "MEDIUM" if r.directory_listing else None),
            ("Mixed Content", "LOW" if r.mixed_content else None),
            ("Missing HSTS", "MEDIUM" if not r.hsts_enabled else None),
            ("Missing Clickjacking Protection", "MEDIUM" if not r.clickjacking_protected else None),
            ("SSL Weak Cipher", "HIGH" if r.ssl_weak_cipher else None),
            ("SSL Expired", "CRITICAL" if r.ssl_expiry_days is not None and r.ssl_expiry_days <= 0 else None),
            ("TRACE Enabled", "LOW" if r.trace_enabled else None),
        ]
        for name, sev in findings_map:
            if sev:
                scores.append({"finding": name, "severity": sev, "cvss": cvss_base(sev)})
        # JWT issues
        for j in r.jwt_tokens:
            if j.get("algorithm") == "none":
                scores.append({"finding": "JWT None Algorithm", "severity": "CRITICAL", "cvss": 9.8})
        # WAF
        if not r.waf_fingerprint.get("detected"):
            scores.append({"finding": "No WAF Detected", "severity": "INFO", "cvss": 0.0})
        # Rate limit
        if not r.rate_limit.get("detected"):
            scores.append({"finding": "No Rate Limiting", "severity": "LOW", "cvss": 2.0})
        # CORS
        for c in r.cors_deep:
            if c.get("vulnerable"):
                scores.append({"finding": f"CORS: {c['test']}", "severity": "HIGH", "cvss": 7.0})
        # Subdomain takeover
        for t in r.subdomain_takeover:
            if t.get("vulnerable"):
                scores.append({"finding": f"Subdomain Takeover: {t.get('subdomain','')}", "severity": "CRITICAL", "cvss": 9.0})
        return sorted(scores, key=lambda x: x["cvss"], reverse=True)

    # =================== SHODAN LOOKUP ===================

    def _shodan_lookup(self, ip):
        result = {"ip": ip, "ports": [], "os": "", "org": "", "vulns": []}
        if not ip:
            return result
        # Free Shodan API (no key, limited)
        try:
            resp = self._http_get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                result["ports"] = data.get("ports", [])
                result["os"] = data.get("os", "")
                result["hostnames"] = data.get("hostnames", [])
                result["vulns"] = data.get("vulns", [])[:10]
                result["cpes"] = data.get("cpes", [])[:5]
        except Exception:
            pass
        return result

    # =================== SCREENSHOTS ===================

    def _install_chromium(self):
        self._log("[screenshots] Chromium not found, installing...")
        browser_path = str(Path.home() / "AppData" / "Local" / "ms-playwright")
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browser_path

        exe_path, cli_path = None, None
        try:
            from playwright._impl._driver import compute_driver_executable
            result = compute_driver_executable()
            if isinstance(result, (tuple, list)) and len(result) == 2:
                exe_path, cli_path = str(result[0]), str(result[1])
            else:
                exe_path = str(result)
        except Exception:
            pass

        if exe_path and os.path.isfile(exe_path) and cli_path and os.path.isfile(cli_path):
            try:
                env = os.environ.copy()
                env["PLAYWRIGHT_BROWSERS_PATH"] = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
                try:
                    from playwright._impl._driver import get_driver_env
                    env.update(get_driver_env())
                except Exception:
                    pass
                self._log("[screenshots] Installing chromium via playwright driver...")
                r = subprocess.run(
                    [exe_path, cli_path, "install", "chromium", "chromium-headless-shell"],
                    env=env, capture_output=True, timeout=600
                )
                if r.returncode == 0:
                    self._log("[screenshots] Chromium installed successfully")
                    return True
                else:
                    self._log(f"[screenshots] Driver install failed: {r.stderr[:200] if r.stderr else 'unknown'}")
            except Exception as e:
                self._log(f"[screenshots] Driver error: {e}")

        node_path = None
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            candidate = Path(sys._MEIPASS) / "playwright" / "driver" / "node.exe"
            if candidate.is_file():
                node_path = str(candidate)
                cli_candidate = Path(sys._MEIPASS) / "playwright" / "driver" / "package" / "cli.js"
                if cli_candidate.is_file():
                    cli_path = str(cli_candidate)

        if node_path and cli_path and os.path.isfile(cli_path):
            try:
                self._log("[screenshots] Installing via bundled node driver...")
                r = subprocess.run(
                    [node_path, cli_path, "install", "chromium", "chromium-headless-shell"],
                    capture_output=True, timeout=600
                )
                if r.returncode == 0:
                    self._log("[screenshots] Chromium installed successfully")
                    return True
                self._log(f"[screenshots] Node install failed: {r.stderr[:200] if r.stderr else ''}")
            except Exception as e:
                self._log(f"[screenshots] Node error: {e}")

        self._log("[screenshots] Could not install Chromium automatically")
        return False

    def _take_screenshot(self, base, host):
        screenshots = []
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            screenshots.append({"error": "Playwright not installed"})
            return screenshots
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path.home() / "AppData" / "Local" / "ms-playwright")
        installed = False
        for attempt in range(3):
            try:
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path.home() / "AppData" / "Local" / "ms-playwright")
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
                    page = browser.new_page(viewport={"width": 1280, "height": 720})
                    screenshot_dir = APP_DIR / "reports" / "screenshots"
                    screenshot_dir.mkdir(parents=True, exist_ok=True)
                    paths_to_try = ["/", "/index.html", "/index.php"]
                    for path in paths_to_try:
                        try:
                            url = base.rstrip("/") + path
                            page.goto(url, timeout=15000, wait_until="domcontentloaded")
                            page.wait_for_timeout(2000)
                            filename = f"{host.replace('.', '_')}_{path.replace('/', '_') or 'root'}.png"
                            filepath = screenshot_dir / filename
                            page.screenshot(path=str(filepath), full_page=False)
                            screenshots.append({"url": url, "path": str(filepath), "filename": filename})
                            break
                        except Exception:
                            pass
                    browser.close()
                break
            except Exception as e:
                err_msg = str(e)[:200]
                needs_install = (
                    "Executable doesn't exist" in err_msg
                    or "playwright" in err_msg.lower()
                    or "not found" in err_msg.lower()
                    or "chromium" in err_msg.lower()
                )
                if needs_install and not installed:
                    self._log(f"[screenshots] {err_msg}")
                    if self._install_chromium():
                        installed = True
                        self._log("[screenshots] Retrying screenshot after install...")
                        continue
                    else:
                        screenshots.append({"error": "Could not install Chromium. Check your internet connection."})
                        break
                else:
                    screenshots.append({"error": err_msg})
                    break
        return screenshots

    # =================== SUPPLY CHAIN ANALYZER ===================

    def _supply_chain(self, body, host):
        findings = []
        script_pattern = re.compile(
            r'<script[^>]+(?:src|href)=["\']([^"\']+)["\']', re.I | re.S
        )
        link_pattern = re.compile(
            r'<link[^>]+href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\']', re.I | re.S
        )
        img_pattern = re.compile(
            r'(?:src|data-src)=["\']([^"\']+\.(?:js|css|png|jpg|gif|svg|webp)(?:\?[^"\']*)?)["\']', re.I
        )
        urls = []
        for m in script_pattern.finditer(body):
            urls.append(m.group(1))
        for m in link_pattern.finditer(body):
            urls.append(m.group(1))
        for m in img_pattern.finditer(body):
            urls.append(m.group(1))
        external = []
        for u in urls:
            if u.startswith("//"):
                u = "https:" + u
            elif u.startswith("/"):
                continue
            if host not in u and u.startswith("http"):
                external.append(u)
        external = list(dict.fromkeys(external))[:30]
        def _fetch_resource(url):
            entry = {"url": url, "issues": []}
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or ""
            if parsed.scheme == "http":
                entry["issues"].append("HTTP (not HTTPS)")
            known_cdns = {
                "cdnjs.cloudflare.com": "Cloudflare CDN",
                "cdn.jsdelivr.net": "jsDelivr",
                "unpkg.com": "unpkg",
                "ajax.googleapis.com": "Google CDN",
                "code.jquery.com": "jQuery CDN",
                "stackpath.bootstrapcdn.com": "Bootstrap CDN",
                "fonts.googleapis.com": "Google Fonts",
                "maxcdn.bootstrapcdn.com": "MaxCDN (deprecated)",
            }
            for cdn, name in known_cdns.items():
                if cdn in domain:
                    entry["cdn"] = name
                    break
            try:
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp:
                    entry["status"] = resp.status_code
                    entry["content_type"] = resp.headers.get("content-type", "")
                    ct = resp.headers.get("content-type", "")
                    if "js" in ct or url.endswith(".js"):
                        ver_match = re.search(r'[?&]v=(\d+)', url)
                        if ver_match:
                            entry["version_hint"] = ver_match.group(1)
                        txt = resp.text[:5000] if hasattr(resp, 'text') else ""
                        vuln_patterns = {
                            r'jquery[\-/.]1\.[0-6]': "jQuery < 1.7 (XSS)",
                            r'jquery[\-/.]2\.[0-1]': "jQuery < 2.2 (XSS)",
                            r'angular[\-/.]1\.[0-5]\.': "AngularJS 1.x (EOL)",
                            r'moment[\-/.]2\.[0-1][0-9]\.': "Moment.js (deprecated)",
                            r'bootstrap[\-/.]3\.': "Bootstrap 3 (EOL)",
                            r'lodash[\-/.]4\.0': "Lodash 4.0 (prototype poll)",
                        }
                        for pat, msg in vuln_patterns.items():
                            if re.search(pat, txt, re.I):
                                entry["issues"].append(msg)
                    script_tag = re.search(
                        r'<script[^>]+src=["\']' + re.escape(url) + r'["\'][^>]*>',
                        body, re.I
                    )
                    if script_tag and 'integrity=' not in script_tag.group(0).lower():
                        entry["issues"].append("Missing SRI")
                    if resp.headers.get("access-control-allow-origin") == "*":
                        entry["issues"].append("CORS wildcard")
            except Exception:
                entry["status"] = "FETCH_FAILED"
            if entry["issues"] or entry.get("cdn"):
                return entry
            return None
        # NOTE: httpx.Client is NOT thread-safe — _fetch_resource uses self._http_get.
        # When HAS_HTTPX, run sequentially. Only parallelize with requests.Session.
        if HAS_HTTPX:
            for item in external:
                result = _fetch_resource(item)
                if result:
                    findings.append(result)
        else:
            with ThreadPoolExecutor(max_workers=10) as ex:
                for result in ex.map(_fetch_resource, external):
                    if result:
                        findings.append(result)
        return findings

    # =================== GRAPHQL DEEP SCAN ===================

    def _graphql_scan(self, base):
        schema = {}
        vulns = []
        graphql_endpoints = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query", "/gql"]
        found_endpoint = None
        for ep in graphql_endpoints:
            url = base.rstrip("/") + ep
            try:
                probe = '{"query":"{__typename}"}'
                resp, _ = self._req("POST", url, timeout=FAST_TIMEOUT,
                                     content=probe,
                                     headers={"Content-Type": "application/json"})
                if resp and resp.status_code == 200:
                    text = resp.text[:500]
                    if "__typename" in text or "data" in text:
                        found_endpoint = url
                        break
            except Exception:
                pass
        if not found_endpoint:
            return schema, vulns
        introspection_query = {
            "query": """{ __schema { queryType { name } mutationType { name }
            types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"""
        }
        try:
            resp, _ = self._req("POST", found_endpoint, timeout=FAST_TIMEOUT,
                                 content=json.dumps(introspection_query),
                                 headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                for t in types:
                    if t.get("name", "").startswith("__"):
                        continue
                    type_name = t.get("name", "")
                    fields = t.get("fields", []) or []
                    schema[type_name] = {
                        "kind": t.get("kind", ""),
                        "fields": [f.get("name", "") for f in fields],
                        "field_details": []
                    }
                    for f in fields:
                        fname = f.get("name", "")
                        ftype = f.get("type", {}).get("name") or f.get("type", {}).get("ofType", {}).get("name", "")
                        args = [a.get("name", "") for a in (f.get("args", []) or [])]
                        schema[type_name]["field_details"].append({
                            "name": fname, "type": ftype, "args": args
                        })
                        # Test injection in string args
                        if args:
                            for arg in args:
                                test_query = '{"query":"query{' + type_name + '(' + arg + ': \\"1 OR 1=1\\"){id}}"}'
                                try:
                                    r2, _ = self._req("POST", found_endpoint, timeout=FAST_TIMEOUT,
                                                       content=test_query,
                                                       headers={"Content-Type": "application/json"})
                                    if r2 and (r2.status_code == 200 or r2.status_code == 500):
                                        rtxt = r2.text[:300]
                                        if "error" not in rtxt.lower() or "sql" in rtxt.lower():
                                            vulns.append({
                                                "type": "SQL Injection",
                                                "endpoint": found_endpoint,
                                                "type_name": type_name,
                                                "field": fname,
                                                "arg": arg,
                                                "response_preview": rtxt[:200]
                                            })
                                except Exception:
                                    pass
        except Exception:
            pass
        # Check introspection enabled
        if schema:
            vulns.append({
                "type": "Info Disclosure",
                "endpoint": found_endpoint,
                "detail": "Introspection enabled — full schema exposed"
            })
        # Check mutations
        try:
            query = '{"query":"{ __schema { mutationType { fields { name } } } }"}'
            resp, _ = self._req("POST", found_endpoint, timeout=FAST_TIMEOUT,
                                 content=query,
                                 headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                mutations = data.get("data", {}).get("__schema", {}).get("mutationType", {}).get("fields", [])
                if mutations:
                    vulns.append({
                        "type": "Mutation Exposure",
                        "endpoint": found_endpoint,
                        "mutations": [m["name"] for m in mutations]
                    })
                    # Try mutating with dangerous args
                    for m in mutations:
                        mname = m["name"]
                        for arg_val in ['"', "'", "null", "true", "0", "{}", "[]"]:
                            test = '{"query":"mutation{' + mname + '(' + m["name"] + ': \\"' + arg_val + '\\"){id}}"}'
                            try:
                                r2, _ = self._req("POST", found_endpoint, timeout=FAST_TIMEOUT,
                                                   content=test,
                                                   headers={"Content-Type": "application/json"})
                                if r2 and r2.status_code == 500:
                                    vulns.append({
                                        "type": "Injection via Mutation",
                                        "endpoint": found_endpoint,
                                        "mutation": mname,
                                        "payload": arg_val
                                    })
                            except Exception:
                                pass
        except Exception:
            pass
        return schema, vulns

    # =================== WEBSOCKET ANALYZER ===================

    def _websocket_scan(self, base, body):
        results = []
        ws_patterns = re.findall(r'wss?://[^\s"\'<>]+', body, re.I)
        ws_urls = list(dict.fromkeys(ws_patterns))[:5]
        # Also check common WS paths
        parsed = urllib.parse.urlparse(base)
        scheme_ws = "wss" if parsed.scheme == "https" else "ws"
        common_ws = [
            f"{scheme_ws}://{parsed.hostname}:{parsed.port or (443 if scheme_ws == 'wss' else 80)}/ws",
            f"{scheme_ws}://{parsed.hostname}:{parsed.port or (443 if scheme_ws == 'wss' else 80)}/socket",
            f"{scheme_ws}://{parsed.hostname}:{parsed.port or (443 if scheme_ws == 'wss' else 80)}/websocket",
            f"{scheme_ws}://{parsed.hostname}/ws",
        ]
        ws_urls = list(dict.fromkeys(ws_urls + common_ws))[:5]
        for ws_url in ws_urls:
            entry = {"url": ws_url, "tests": []}
            try:
                import websocket
                ws = websocket.create_connection(ws_url, timeout=3, sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith("wss") else {})
                entry["connected"] = True
                # Test XSS via message
                xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
                for payload in xss_payloads:
                    try:
                        ws.send(payload)
                        try:
                            resp = ws.recv()
                            if payload in resp:
                                entry["tests"].append({
                                    "type": "XSS Reflection", "payload": payload,
                                    "severity": "HIGH", "reflected": True
                                })
                        except Exception:
                            pass
                    except Exception:
                        pass
                # Test injection
                inject_payloads = ["' OR 1=1", "{{7*7}}", "${7*7}", "{{constructor.constructor('return this')()}}"]
                for payload in inject_payloads:
                    try:
                        ws.send(payload)
                        try:
                            resp = ws.recv()
                            if "49" in resp or "true" in resp:
                                entry["tests"].append({
                                    "type": "Template Injection", "payload": payload,
                                    "severity": "CRITICAL", "response": resp[:200]
                                })
                        except Exception:
                            pass
                    except Exception:
                        pass
                # Test DoS (large message)
                try:
                    large = "A" * 100000
                    ws.send(large)
                    entry["tests"].append({"type": "Large Payload", "severity": "INFO", "detail": "Server accepted 100KB"})
                except Exception:
                    entry["tests"].append({"type": "Large Payload", "severity": "LOW", "detail": "Server rejected large payload"})
                ws.close()
            except ImportError:
                entry["connected"] = False
                entry["tests"].append({"type": "ERROR", "detail": "websocket-client not installed"})
            except Exception as e:
                entry["connected"] = False
                entry["error"] = str(e)[:200]
            results.append(entry)
        return results

    # =================== SESSION MANIPULATION ===================

    def _session_manipulation(self, base):
        issues = []
        try:
            resp1, _ = self._req("GET", base, timeout=FAST_TIMEOUT)
            resp2, _ = self._req("GET", base, timeout=FAST_TIMEOUT)
            if resp1 and resp2:
                cookies1 = dict(resp1.cookies)
                cookies2 = dict(resp2.cookies)
                session_keys = [k for k in cookies1 if any(s in k.lower() for s in ["session", "sid", "token", "auth", "jwt"])]
                if session_keys:
                    for k in session_keys:
                        if cookies1.get(k) == cookies2.get(k):
                            issues.append({
                                "type": "Session Fixation",
                                "cookie": k,
                                "severity": "HIGH",
                                "detail": "Same session token for different requests"
                            })
                # Check token entropy
                for k, v in cookies1.items():
                    if any(s in k.lower() for s in ["session", "sid", "token", "auth"]):
                        if len(v) < 16:
                            issues.append({
                                "type": "Weak Token",
                                "cookie": k,
                                "severity": "MEDIUM",
                                "detail": f"Token length {len(v)} < 16 chars"
                            })
                        if v.isdigit():
                            issues.append({
                                "type": "Predictable Token",
                                "cookie": k,
                                "severity": "HIGH",
                                "detail": "Token is numeric only"
                            })
                        # Check entropy
                        if len(set(v)) < len(v) * 0.4:
                            issues.append({
                                "type": "Low Entropy Token",
                                "cookie": k,
                                "severity": "MEDIUM",
                                "detail": f"Only {len(set(v))} unique chars in {len(v)} char token"
                            })
                # Check Secure/HttpOnly/SameSite flags
                for cookie in resp1.cookies.jar:
                    try:
                        flags = []
                        if not cookie.secure:
                            flags.append("Missing Secure flag")
                        if not cookie.get_nonstandard_attr("HttpOnly"):
                            flags.append("Missing HttpOnly flag")
                        if flags:
                            issues.append({
                                "type": "Cookie Flags",
                                "cookie": cookie.name,
                                "severity": "MEDIUM",
                                "detail": ", ".join(flags)
                            })
                    except Exception:
                        pass
                # Check for token in URL
                final_url = str(resp1.url) if hasattr(resp1, 'url') else base
                parsed = urllib.parse.urlparse(final_url)
                if parsed.query:
                    params = urllib.parse.parse_qs(parsed.query)
                    for p in params:
                        if any(s in p.lower() for s in ["token", "session", "sid", "auth", "key"]):
                            issues.append({
                                "type": "Token in URL",
                                "severity": "HIGH",
                                "detail": f"Parameter '{p}' found in URL — may be logged/referer leaked"
                            })
                # Check for CORS with credentials
                cors = resp1.headers.get("access-control-allow-credentials", "").lower()
                acao = resp1.headers.get("access-control-allow-origin", "")
                if cors == "true" and acao == "*":
                    issues.append({
                        "type": "CORS Misconfiguration",
                        "severity": "HIGH",
                        "detail": "Allow-Credentials with wildcard origin"
                    })
        except Exception:
            pass
        return issues

    # =================== CHAOS SCANNING ===================

    def _chaos_scan(self, base):
        ss = self.scan_settings
        findings = []
        # Random headers
        chaos_headers = {
            "X-Forwarded-For": f"{_random.randint(1,255)}.{_random.randint(0,255)}.{_random.randint(0,255)}.{_random.randint(1,254)}",
            "X-Real-IP": f"127.0.0.{_random.randint(1,254)}",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-Host": "evil.com",
            "X-Host": "evil.com",
            "X-Forwarded-Server": "evil.com",
            "X-HTTP-Method-Override": "DELETE",
            "X-HTTP-Method": "DELETE",
            "X-Method-Override": "DELETE",
            "If-Modified-Since": "01 Jan 1970 00:00:00 GMT",
            "If-None-Match": "*",
            "Accept": "application/json",
            "X-Request-ID": "test-chaos-1337",
        }
        headers_list = list(chaos_headers.items())[:ss.get("limit_chaos_headers", 6)]
        def _chaos_header(hv):
            header, value = hv
            results = []
            try:
                resp, _ = self._req("GET", base, timeout=FAST_TIMEOUT, headers={header: value})
                if resp:
                    if resp.status_code == 200 and any(w in resp.text.lower() for w in ["admin", "dashboard", "console"]):
                        results.append({
                            "type": "Header Bypass → Admin Access",
                            "header": header, "value": value,
                            "severity": "CRITICAL",
                            "detail": f"Header {header} bypassed access control"
                        })
                    if resp.status_code in (301, 302, 307, 308):
                        loc = resp.headers.get("location", "")
                        if "admin" in loc.lower() or "login" in loc.lower():
                            results.append({
                                "type": "Header → Redirect",
                                "header": header, "value": value,
                                "severity": "HIGH",
                                "detail": f"Redirected to {loc}"
                            })
                    if resp.status_code == 500:
                        results.append({
                            "type": "Header → Server Error",
                            "header": header, "value": value,
                            "severity": "MEDIUM",
                            "detail": "Server error with custom header — possible internal handling issue"
                        })
            except Exception:
                pass
            return results
        # NOTE: httpx.Client is NOT thread-safe — _chaos_header uses self._req.
        if HAS_HTTPX:
            for hv in headers_list:
                findings.extend(_chaos_header(hv))
        else:
            with ThreadPoolExecutor(max_workers=6) as ex:
                for res in ex.map(_chaos_header, headers_list):
                    findings.extend(res)
        # Random POST bodies
        chaos_bodies = [
            ("{}", {"Content-Type": "application/json"}),
            ("null", {"Content-Type": "application/json"}),
            ('{"id":1}', {"Content-Type": "application/json"}),
            ('{"query":"SELECT 1"}', {"Content-Type": "application/json"}),
            ("admin=true", {"Content-Type": "application/x-www-form-urlencoded"}),
            ("id=1 OR 1=1", {"Content-Type": "application/x-www-form-urlencoded"}),
            (b"\x00" * 100, {"Content-Type": "application/octet-stream"}),
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", {"Content-Type": "application/xml"}),
        ][:ss.get("limit_chaos_bodies", 4)]
        def _chaos_body(bh):
            body, headers = bh
            results = []
            try:
                resp, _ = self._req("POST", base, timeout=FAST_TIMEOUT, content=body, headers=headers)
                if resp:
                    if resp.status_code == 200 and len(resp.text) > 200:
                        results.append({
                            "type": "POST Body Accepted",
                            "detail": f"Server returned 200 with {len(resp.text)} bytes",
                            "severity": "MEDIUM",
                            "preview": resp.text[:200]
                        })
                    if resp.status_code == 500:
                        results.append({
                            "type": "POST → Server Error",
                            "detail": "Server crashed on POST body",
                            "severity": "MEDIUM"
                        })
            except Exception:
                pass
            return results
        # NOTE: httpx.Client is NOT thread-safe — _chaos_body uses self._req.
        if HAS_HTTPX:
            for bh in chaos_bodies:
                findings.extend(_chaos_body(bh))
        else:
            with ThreadPoolExecutor(max_workers=4) as ex:
                for res in ex.map(_chaos_body, chaos_bodies):
                    findings.extend(res)
        # Random URL params
        param_names = ["debug", "test", "admin", "mode", "action", "cmd", "exec", "eval", "callback", "jsonp"]
        for param in param_names:
            try:
                url = f"{base}?{param}=test"
                resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if resp:
                    if resp.status_code == 200 and any(w in resp.text.lower() for w in ["debug", "info", "phpinfo", "config", "env"]):
                        findings.append({
                            "type": "Debug Endpoint",
                            "detail": f"Parameter '{param}' exposed debug info",
                            "severity": "HIGH"
                        })
                    if resp.status_code == 500:
                        findings.append({
                            "type": "Parameter → Error",
                            "detail": f"Parameter '{param}' caused server error",
                            "severity": "LOW"
                        })
            except Exception:
                pass
        return findings[:30]

    # =================== CUSTOM DSL ===================

    def _dsl_scan(self, report):
        dsl_rules_path = os.path.join(APP_DIR, "dsl_rules.json")
        results = []
        rules = []
        if os.path.exists(dsl_rules_path):
            try:
                with open(dsl_rules_path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
            except Exception:
                pass
        if not rules:
            rules = self._default_dsl_rules_v2()
        for rule in rules:
            try:
                if isinstance(rule, dict):
                    matched = self._eval_dsl_rule(rule, report)
                    if matched:
                        results.append({
                            "rule": rule.get("name", "unnamed"),
                            "severity": rule.get("severity", "INFO"),
                            "detail": rule.get("message", "Matched"),
                            "condition": rule.get("condition", "")
                        })
                elif isinstance(rule, str):
                    # DSL v2 program
                    program_results = self._eval_dsl_program(rule, report)
                    results.extend(program_results)
            except Exception as e:
                results.append({
                    "rule": rule.get("name", "unnamed") if isinstance(rule, dict) else "dsl_program",
                    "severity": "ERROR",
                    "detail": f"Rule error: {str(e)[:100]}"
                })
        return results

    def _default_dsl_rules_v2(self):
        return [
            {"name": "No HSTS", "condition": "hsts_enabled == false", "severity": "HIGH", "message": "HSTS not enabled"},
            {"name": "HTTP Redirect Missing", "condition": "http_to_https_redirect == false", "severity": "MEDIUM", "message": "No HTTP->HTTPS redirect"},
            {"name": "SSL Expiring Soon", "condition": "ssl_expiry_days < 30", "severity": "HIGH", "message": "SSL certificate expires within 30 days"},
            {"name": "Clickjacking", "condition": "clickjacking_protected == false", "severity": "MEDIUM", "message": "Clickjacking not prevented"},
            {"name": "Directory Listing", "condition": "directory_listing == true", "severity": "HIGH", "message": "Directory listing enabled"},
            {"name": "XSS Reflection", "condition": "xss_reflection == true", "severity": "CRITICAL", "message": "XSS reflection detected"},
            {"name": "TRACE Enabled", "condition": "trace_enabled == true", "severity": "MEDIUM", "message": "TRACE method enabled"},
            {"name": "Open Redirect", "condition": "open_redirect != ''", "severity": "HIGH", "message": "Open redirect found"},
            {"name": "WAF Bypass", "condition": "waf_detected != '' AND mutated_payloads_count > 0", "severity": "CRITICAL", "message": "WAF detected but payloads bypassed it"},
            {"name": "GraphQL Exposed", "condition": "graphql_vulns_count > 0", "severity": "HIGH", "message": "GraphQL vulnerabilities found"},
            {"name": "Admin Panel", "condition": "admin_panels_count > 0", "severity": "HIGH", "message": "Admin panels discovered"},
            {"name": "Source Leak", "condition": "source_leak_count > 0", "severity": "HIGH", "message": "Source code/backup files leaked"},
        ]

    def _eval_dsl_rule(self, rule, report):
        condition = rule.get("condition", "")
        if not condition:
            return False
        parts = re.split(r'\s+AND\s+', condition, flags=re.I)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            m = re.match(r'(\w+)\s*(==|!=|>|<|>=|<=|contains|notcontains)\s*(.+)', part, re.I)
            if not m:
                continue
            field, op, expected = m.group(1), m.group(2), m.group(3).strip().strip('"').strip("'")
            actual = getattr(report, field, None)
            if actual is None:
                if field.endswith("_count"):
                    base_field = field[:-6]
                    val = getattr(report, base_field, [])
                    actual = len(val) if isinstance(val, list) else 0
                elif field == "mutated_payloads_count":
                    actual = len(report.mutated_payloads)
                elif field == "graphql_vulns_count":
                    actual = len(report.graphql_vulns)
                elif field == "admin_panels_count":
                    actual = len(report.admin_panels)
                elif field == "source_leak_count":
                    actual = len(report.source_leak)
                else:
                    return False
            if isinstance(actual, bool):
                expected_val = expected.lower() in ("true", "1", "yes")
            elif isinstance(actual, (int, float)):
                try:
                    expected_val = int(expected) if '.' not in expected else float(expected)
                except ValueError:
                    expected_val = expected
            else:
                expected_val = expected
            matched = False
            if isinstance(actual, list):
                if op == "!=": matched = (len(actual) > 0)
                elif op == "==": matched = (len(actual) == 0)
                elif op == ">": matched = (len(actual) > expected_val)
                elif op == "<": matched = (len(actual) < expected_val)
                elif op == ">=": matched = (len(actual) >= expected_val)
                elif op == "<=": matched = (len(actual) <= expected_val)
                elif op.lower() == "contains": matched = any(expected_val in str(x) for x in actual)
                elif op.lower() == "notcontains": matched = all(expected_val not in str(x) for x in actual)
            elif op == "==": matched = (actual == expected_val)
            elif op == "!=": matched = (actual != expected_val)
            elif op == ">": matched = (actual > expected_val)
            elif op == "<": matched = (actual < expected_val)
            elif op == ">=": matched = (actual >= expected_val)
            elif op == "<=": matched = (actual <= expected_val)
            elif op.lower() == "contains": matched = (expected_val in str(actual))
            elif op.lower() == "notcontains": matched = (expected_val not in str(actual))
            if not matched:
                return False
        return True

    # =================== DSL v2 INTERPRETER ===================

    def _eval_dsl_program(self, program, report):
        """DSL v2: variables, loops, IF/ELSE, CAPTURE, ASSERT, REQUEST."""
        results = []
        vars_ = {}
        lines = [l.strip() for l in program.splitlines() if l.strip() and not l.strip().startswith("#")]
        i = 0
        while i < len(lines):
            line = lines[i]
            try:
                # Variable assignment: $var = expr
                vm = re.match(r'^\$(\w+)\s*=\s*(.+)', line)
                if vm:
                    var_name, expr = vm.group(1), vm.group(2).strip()
                    vars_[var_name] = self._eval_dsl_expr(expr, vars_, report)
                    i += 1
                    continue

                # IF/THEN/ELSE/END
                ifm = re.match(r'^IF\s+(.+?)\s+THEN\s*$', line, re.I)
                if ifm:
                    condition = ifm.group(1)
                    then_lines = []
                    else_lines = []
                    i += 1
                    in_else = False
                    depth = 1
                    while i < len(lines) and depth > 0:
                        l = lines[i]
                        if re.match(r'^ELSE\s*$', l, re.I):
                            in_else = True
                            i += 1
                            continue
                        if re.match(r'^END\s*$', l, re.I):
                            depth -= 1
                            if depth == 0:
                                i += 1
                                break
                        if re.match(r'^IF\s+', l, re.I):
                            depth += 1
                        if in_else:
                            else_lines.append(l)
                        else:
                            then_lines.append(l)
                        i += 1
                    cond_result = self._eval_dsl_condition(condition, vars_, report)
                    block = then_lines if cond_result else else_lines
                    sub_results = self._eval_dsl_block(block, vars_, report)
                    results.extend(sub_results)
                    continue

                # FOR item IN list ... END
                form = re.match(r'^FOR\s+(\w+)\s+IN\s+(.+?)\s*$', line, re.I)
                if form:
                    item_name = form.group(1)
                    list_expr = form.group(2).strip()
                    loop_items = self._eval_dsl_expr(list_expr, vars_, report)
                    if not isinstance(loop_items, list):
                        loop_items = [loop_items]
                    if len(loop_items) > 1000:
                        loop_items = loop_items[:1000]
                    i += 1
                    loop_lines = []
                    depth = 1
                    while i < len(lines) and depth > 0:
                        l = lines[i]
                        if re.match(r'^END\s*$', l, re.I):
                            depth -= 1
                            if depth == 0:
                                i += 1
                                break
                        if re.match(r'^FOR\s+', l, re.I):
                            depth += 1
                        loop_lines.append(l)
                        i += 1
                    for item in loop_items:
                        vars_[item_name] = item
                        sub_results = self._eval_dsl_block(loop_lines, vars_, report)
                        results.extend(sub_results)
                    continue

                # ASSERT condition
                asrt = re.match(r'^ASSERT\s+(.+?)\s*$', line, re.I)
                if asrt:
                    condition = asrt.group(1)
                    ok = self._eval_dsl_condition(condition, vars_, report)
                    if not ok:
                        results.append({
                            "rule": "ASSERT",
                            "severity": "HIGH",
                            "detail": f"Assertion failed: {condition}",
                            "condition": condition
                        })
                    i += 1
                    continue

                # CAPTURE regex FROM field
                capm = re.match(r'^CAPTURE\s+"(.+?)"\s+FROM\s+(\w+)', line, re.I)
                if capm:
                    pattern, field = capm.group(1), capm.group(2)
                    value = getattr(report, field, "")
                    if isinstance(value, list):
                        value = str(value)
                    elif isinstance(value, dict):
                        value = json.dumps(value)
                    matches = re.findall(pattern, str(value))
                    var_name = f"_capture_{len(results)}"
                    vars_[var_name] = matches
                    if matches:
                        results.append({
                            "rule": f"CAPTURE {pattern}",
                            "severity": "INFO",
                            "detail": f"Found {len(matches)} matches: {str(matches)[:200]}",
                        })
                    i += 1
                    continue

                # REQUEST url CHECK response CONTAINS text
                reqm = re.match(r'^REQUEST\s+"(.+?)"\s+CHECK\s+RESPONSE\s+CONTAINS\s+"(.+?)"', line, re.I)
                if reqm:
                    url, text = reqm.group(1), reqm.group(2)
                    try:
                        resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                        if resp and text in resp.text:
                            results.append({
                                "rule": f"REQUEST {url}",
                                "severity": "INFO",
                                "detail": f"Response contains '{text}'"
                            })
                    except Exception:
                        pass
                    i += 1
                    continue

                # HTTP_TIME url < ms
                htm = re.match(r'^HTTP_TIME\s+"(.+?)"\s*(<|>)\s*(\d+)', line, re.I)
                if htm:
                    url, op, ms = htm.group(1), htm.group(2), int(htm.group(3))
                    try:
                        t0 = time.perf_counter()
                        resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                        elapsed = int((time.perf_counter() - t0) * 1000)
                        if op == "<" and elapsed > ms:
                            results.append({
                                "rule": f"HTTP_TIME {url}",
                                "severity": "MEDIUM",
                                "detail": f"Response time {elapsed}ms > {ms}ms threshold"
                            })
                        elif op == ">" and elapsed < ms:
                            results.append({
                                "rule": f"HTTP_TIME {url}",
                                "severity": "INFO",
                                "detail": f"Response time {elapsed}ms < {ms}ms"
                            })
                    except Exception:
                        pass
                    i += 1
                    continue

                # Simple condition line (backward compat)
                matched = self._eval_dsl_condition(line, vars_, report)
                if matched:
                    results.append({
                        "rule": "condition",
                        "severity": "INFO",
                        "detail": f"Condition met: {line}",
                        "condition": line
                    })
                i += 1
            except Exception as e:
                results.append({
                    "rule": "DSL Error",
                    "severity": "ERROR",
                    "detail": f"Line {i+1}: {str(e)[:80]}"
                })
                i += 1
        return results

    def _eval_dsl_block(self, lines, vars_, report):
        results = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                vm = re.match(r'^\$(\w+)\s*=\s*(.+)', line)
                if vm:
                    vars_[vm.group(1)] = self._eval_dsl_expr(vm.group(2).strip(), vars_, report)
                    continue
                asrt = re.match(r'^ASSERT\s+(.+)', line, re.I)
                if asrt:
                    ok = self._eval_dsl_condition(asrt.group(1), vars_, report)
                    if not ok:
                        results.append({"rule": "ASSERT", "severity": "HIGH", "detail": f"Failed: {asrt.group(1)}"})
                    continue
                capm = re.match(r'^CAPTURE\s+"(.+?)"\s+FROM\s+(\w+)', line, re.I)
                if capm:
                    pattern, field = capm.group(1), capm.group(2)
                    value = getattr(report, field, "")
                    matches = re.findall(pattern, str(value))
                    if matches:
                        results.append({"rule": "CAPTURE", "severity": "INFO", "detail": f"{len(matches)} matches"})
                    continue
                # Check as condition
                if self._eval_dsl_condition(line, vars_, report):
                    results.append({"rule": "condition", "severity": "INFO", "detail": f"Met: {line}"})
            except Exception as e:
                results.append({"rule": "DSL Error", "severity": "ERROR", "detail": str(e)[:80]})
        return results

    def _eval_dsl_expr(self, expr, vars_, report):
        expr = expr.strip()
        # Variable reference
        if expr.startswith("$"):
            var_name = expr[1:]
            return vars_.get(var_name, expr)
        # List literal
        if expr.startswith("[") and expr.endswith("]"):
            items = expr[1:-1].split(",")
            return [self._eval_dsl_expr(x.strip().strip('"'), vars_, report) for x in items]
        # String literal
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        # Number
        try:
            return int(expr)
        except ValueError:
            try:
                return float(expr)
            except ValueError:
                pass
        # Boolean
        if expr.lower() == "true": return True
        if expr.lower() == "false": return False
        # Report field
        if hasattr(report, expr):
            return getattr(report, expr)
        # Computed field
        if expr.endswith("_count"):
            base = expr[:-6]
            val = getattr(report, base, [])
            return len(val) if isinstance(val, list) else 0
        return expr

    def _eval_dsl_condition(self, cond, vars_, report):
        cond = cond.strip()
        # OR
        or_parts = re.split(r'\s+OR\s+', cond, flags=re.I)
        if len(or_parts) > 1:
            return any(self._eval_dsl_condition(p, vars_, report) for p in or_parts)
        # AND
        and_parts = re.split(r'\s+AND\s+', cond, flags=re.I)
        if len(and_parts) > 1:
            return all(self._eval_dsl_condition(p, vars_, report) for p in and_parts)
        # NOT
        notm = re.match(r'^NOT\s+(.+)', cond, re.I)
        if notm:
            return not self._eval_dsl_condition(notm.group(1), vars_, report)
        # Comparison
        m = re.match(r'(.+?)\s*(==|!=|>=|<=|>|<|contains|notcontains)\s*(.+)', cond, re.I)
        if m:
            left_expr, op, right_expr = m.group(1).strip(), m.group(2), m.group(3).strip()
            left = self._eval_dsl_expr(left_expr, vars_, report)
            right = self._eval_dsl_expr(right_expr, vars_, report)
            # Type coercion
            if isinstance(left, bool) or isinstance(right, bool):
                left = bool(left)
                right = right.lower() in ("true", "1", "yes") if isinstance(right, str) else bool(right)
            elif isinstance(left, (int, float)) and isinstance(right, str):
                try: right = int(right) if '.' not in right else float(right)
                except ValueError: pass
            elif isinstance(left, str) and isinstance(right, (int, float)):
                try: left = int(left) if '.' not in left else float(left)
                except ValueError: pass
            if op == "==": return left == right
            if op == "!=": return left != right
            if op == ">": return left > right
            if op == "<": return left < right
            if op == ">=": return left >= right
            if op == "<=": return left <= right
            if op.lower() == "contains": return str(right) in str(left)
            if op.lower() == "notcontains": return str(right) not in str(left)
        # Parenthesized
        if cond.startswith("(") and cond.endswith(")"):
            return self._eval_dsl_condition(cond[1:-1], vars_, report)
        # Fallback: truthy check
        val = self._eval_dsl_expr(cond, vars_, report)
        return bool(val) and val not in ("", 0, False, None, [])

    # =================== AI VULNERABILITY ANALYZER ===================

    def _load_ai_settings(self):
        if AI_SETTINGS_FILE.exists():
            try:
                data = json.loads(AI_SETTINGS_FILE.read_text("utf-8"))
                # Decode obfuscated API key if present
                if data.get("api_key") and data["api_key"].startswith("enc:"):
                    try:
                        data["api_key"] = base64.b64decode(data["api_key"][4:]).decode("utf-8")
                    except Exception:
                        pass
                return data
            except Exception:
                pass
        return {"provider": "", "api_key": "", "model": "", "account_id": "", "enabled": True}

    def _ai_analyze(self, report):
        findings = []
        settings = self._load_ai_settings()
        if not settings.get("enabled", True):
            return []
        provider_name = settings.get("provider", "")
        api_key = settings.get("api_key", "")
        model = settings.get("model", "")
        if not provider_name or not api_key:
            return [{"type": "AI Analysis", "severity": "INFO",
                      "detail": "Configure AI in Settings (sidebar) to enable analysis"}]
        provider = AI_PROVIDERS.get(provider_name)
        if not provider:
            return [{"type": "AI Error", "severity": "INFO", "detail": f"Unknown provider: {provider_name}"}]
        context_parts = [
            f"Target: {report.target}",
            f"Status: {report.status_code}",
            f"Server: {report.server_banner}",
            f"Headers: {json.dumps(report.headers)[:400]}",
            f"Missing headers: {', '.join(report.missing_security_headers[:10])}",
            f"CORS: {json.dumps(report.cors_issues)[:200]}",
            f"Cookies: {json.dumps(report.cookie_issues)[:200]}",
            f"WAF: {report.waf_detected}",
            f"Paths: {', '.join([p.get('path','') for p in report.discovered_paths[:5]])}",
            f"Critical: {', '.join(report.critical_paths[:5])}",
            f"CVEs: {json.dumps(report.cve_findings)[:300]}",
            f"XSS: {report.xss_reflection}",
            f"SQL errors: {report.sql_errors[:200]}",
            f"Open redirect: {report.open_redirect}",
            f"Host header inject: {report.host_header_inject}",
            f"CRLF: {report.crlf_injection}",
            f"JWT: {json.dumps(report.jwt_tokens)[:200]}",
            f"SSTI: {json.dumps(report.ssti_results)[:200]}",
            f"Zone transfer: {json.dumps(report.zone_transfer)[:200]}",
            f"Subdomain takeover: {json.dumps(report.subdomain_takeover)[:200]}",
            f"Email security: {json.dumps(report.email_security)[:200]}",
            f"HTTP smuggling: {json.dumps(report.http_smuggling)[:200]}",
            f"Supply chain: {json.dumps(report.supply_chain)[:300]}",
            f"GraphQL: {json.dumps(report.graphql_vulns)[:300]}",
            f"Session: {json.dumps(report.session_issues)[:300]}",
            f"Chaos: {json.dumps(report.chaos_findings)[:300]}",
        ]
        context = "\n".join(context_parts)
        prompt = f"""You are an expert penetration tester and security auditor. Analyze this scan report and identify ALL exploitable security vulnerabilities.

For EACH finding provide a JSON object:
- "type": vulnerability type (e.g. "SQL Injection", "XSS", "Misconfiguration")
- "severity": CRITICAL / HIGH / MEDIUM / LOW / INFO
- "detail": clear explanation of the issue
- "exploitation": step-by-step how an attacker could exploit it
- "fix": specific remediation steps

IMPORTANT: Focus on REAL exploitable issues that have actual impact. Consider:
- Attack chains (combining multiple findings for greater impact)
- Business logic flaws
- Authentication/authorization weaknesses
- Data exposure risks
- Infrastructure weaknesses

Report data:
{context}

Return ONLY a JSON array. No markdown, no explanation outside JSON."""
        try:
            resp_data = self._call_ai_provider(provider, provider_name, api_key, model, prompt, settings)
            content = resp_data.get("content", "")
            # Try code block first, then greedy array match
            json_match = re.search(r'```(?:json)?\s*(\[[\s\S]*?\])\s*```', content)
            if not json_match:
                json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                findings = json.loads(json_match.group(1) if json_match.lastindex else json_match.group())
        except json.JSONDecodeError:
            findings = [{"type": "AI Parse Error", "severity": "INFO", "detail": "Could not parse AI response", "raw": content[:500]}]
        except Exception as e:
            safe_err = str(e)[:300]
            for pattern in (api_key,):
                if pattern and len(pattern) > 3:
                    safe_err = safe_err.replace(pattern, "***")
            findings = [{"type": "AI Error", "severity": "INFO", "detail": safe_err}]
        return findings

    def _call_ai_provider(self, provider, provider_name, api_key, model, prompt, settings, history=None):
        headers = {"Content-Type": "application/json"}
        body = {}
        fmt = provider.get("format", "openai")
        temp = settings.get("temperature", 0.3)
        max_tok = settings.get("max_tokens", 2000)
        top_p = settings.get("top_p", 1.0)
        freq_pen = settings.get("frequency_penalty", 0.0)
        pres_pen = settings.get("presence_penalty", 0.0)
        sys_prompt = settings.get("system_prompt", "").strip()
        # history is a list of {"role": "user"/"assistant", "content": "..."}
        if history is None:
            history = []
        if fmt == "openai" or fmt == "openrouter":
            if provider.get("header_key"):
                headers[provider["header_key"]] = provider.get("header_prefix", "") + api_key
            else:
                headers["Authorization"] = f"Bearer {api_key}"
            if fmt == "openrouter":
                headers["HTTP-Referer"] = "https://sc-checker.local"
                headers["X-Title"] = "SC Checker"
            url = provider["url"]
            messages = []
            if sys_prompt:
                messages.append({"role": "system", "content": sys_prompt})
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": prompt})
            body = {
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tok,
                "top_p": top_p,
                "frequency_penalty": freq_pen,
                "presence_penalty": pres_pen,
            }
        elif fmt == "gemini":
            url = provider["url"].format(model=model, key=api_key)
            contents = []
            if sys_prompt:
                contents.append({"role": "user", "parts": [{"text": sys_prompt}]})
                contents.append({"role": "model", "parts": [{"text": "Understood. I will follow these instructions."}]})
            for h in history:
                role = "user" if h["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": h["content"]}]})
            contents.append({"role": "user", "parts": [{"text": prompt}]})
            body = {
                "contents": contents,
                "generationConfig": {
                    "temperature": temp,
                    "maxOutputTokens": max_tok,
                    "topP": top_p,
                },
            }
        elif fmt == "anthropic":
            url = provider["url"]
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
            messages = []
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": prompt})
            body = {
                "model": model,
                "max_tokens": max_tok,
                "messages": messages,
                "top_p": top_p,
            }
            if sys_prompt:
                body["system"] = sys_prompt
        else:
            url = provider["url"]
            if provider.get("header_key"):
                headers[provider["header_key"]] = provider.get("header_prefix", "") + api_key
            messages = []
            if sys_prompt:
                messages.append({"role": "system", "content": sys_prompt})
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": prompt})
            body = {
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tok,
                "top_p": top_p,
                "frequency_penalty": freq_pen,
                "presence_penalty": pres_pen,
            }
        # Handle Cloudflare account_id
        if settings.get("account_id") and "{account_id}" in url:
            url = url.replace("{account_id}", settings["account_id"])
        # Reduce prompt size if too large — keep system prompt and truncate user content
        if len(prompt) > 8000:
            prompt = prompt[:6000] + "\n\n[Truncated for API limit]"
            if "messages" in body:
                if body["messages"] and body["messages"][0].get("role") == "system":
                    body["messages"] = [body["messages"][0], {"role": "user", "content": prompt}]
                else:
                    body["messages"] = [{"role": "user", "content": prompt}]
            elif "contents" in body:
                body["contents"] = [{"parts": [{"text": prompt}]}]
        client = None
        try:
            if HAS_HTTPX:
                client = httpx.Client(timeout=120, verify=True)
        except Exception:
            pass
        for attempt in range(3):
            try:
                if client:
                    resp = client.post(url, headers=headers, json=body)
                    data = resp.json()
                else:
                    resp = requests.post(url, headers=headers, json=body, timeout=120, verify=True)
                    data = resp.json()
                break
            except Exception as e:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                safe_err = str(e)[:300]
                for pattern in (api_key, url):
                    if pattern and len(pattern) > 3:
                        safe_err = safe_err.replace(pattern, "***")
                safe_err = re.sub(r'(key|token|api)[=:]\S+', '***', safe_err, flags=re.I)
                return {"content": "", "error": safe_err}
        # Parse response based on format
        try:
            if fmt == "anthropic":
                content_list = data.get("content", [])
                content = content_list[0].get("text", "") if content_list else ""
            elif fmt == "gemini":
                candidates = data.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    content = parts[0].get("text", "") if parts else ""
                else:
                    content = ""
            else:
                choices = data.get("choices", [])
                content = choices[0].get("message", {}).get("content", "") if choices else ""
        except (KeyError, IndexError, TypeError):
            content = ""
        finally:
            if client:
                try: client.close()
                except Exception: pass
        return {"content": content}

    def _ssl_deep(self, host, port, scheme):
        if scheme != "https":
            return {}
        combined = self._ssl_combined(host, port)
        return combined.get("deep", {})

    def _http_methods_full(self, url):
        methods = []
        for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
            try:
                r, _ = self._req(m, url, timeout=FAST_TIMEOUT)
                if r:
                    methods.append({"method": m, "status": r.status_code, "allowed": r.status_code < 405})
                else:
                    methods.append({"method": m, "status": 0, "allowed": False})
            except Exception:
                methods.append({"method": m, "status": 0, "allowed": False})
        return methods

    def _check_security_txt(self, base):
        try:
            r, _ = self._req("GET", f"{base}/.well-known/security.txt", timeout=FAST_TIMEOUT)
            if r and r.status_code == 200 and len(r.text) > 10:
                return r.text[:2000]
            r2, _ = self._req("GET", f"{base}/security.txt", timeout=FAST_TIMEOUT)
            if r2 and r2.status_code == 200 and len(r2.text) > 10:
                return r2.text[:2000]
        except Exception:
            pass
        return "NOT FOUND"

    def _analyze_csp(self, csp):
        if not csp:
            return "NOT SET"
        issues = []
        if "'unsafe-inline'" in csp: issues.append("unsafe-inline")
        if "'unsafe-eval'" in csp: issues.append("unsafe-eval")
        if "*" in csp.split(): issues.append("wildcard source")
        if "data:" in csp: issues.append("data: source")
        if "frame-ancestors" not in csp: issues.append("no frame-ancestors")
        if "report-uri" not in csp and "report-to" not in csp: issues.append("no reporting")
        if not issues:
            return f"OK — {csp[:120]}"
        return f"Issues: {', '.join(issues)} | {csp[:100]}"

    def _measure_perf(self, url):
        ttfb = None
        size = 0
        encoding = ""
        try:
            t0 = time.perf_counter()
            resp, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
            ttfb = int((time.perf_counter() - t0) * 1000)
            if resp is not None:
                cl = resp.headers.get("content-length", "") if hasattr(resp, "headers") else ""
                size = int(cl) if cl.isdigit() else (len(resp.content) if hasattr(resp, "content") else 0)
                encoding = resp.headers.get("content-encoding", "") if hasattr(resp, "headers") else ""
        except Exception as e:
            self._collect_error(None, "perf", e)
        return ttfb, size, encoding

    def _trace_redirects(self, url):
        chain = []
        try:
            r, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
            if r is not None:
                hist = r.history if hasattr(r, "history") else []
                for h in hist:
                    chain.append({"url": str(h.url) if hasattr(h, "url") else "", "status": h.status_code})
                final_url = str(r.url) if hasattr(r, "url") else url
                chain.append({"url": final_url, "status": r.status_code, "final": True})
        except Exception:
            pass
        return chain[:15]

    def _extract_meta(self, body):
        tags = []
        for m in re.finditer(r'<meta\s+([^>]+)>', body, re.I):
            attrs = m.group(1)
            name = ""
            content = ""
            nm = re.search(r'(?:name|property|http-equiv)\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            ct = re.search(r'content\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            if nm: name = nm.group(1)
            if ct: content = ct.group(1)
            if name:
                tags.append({"name": name, "content": content[:100]})
        return tags[:25]

    def _extract_forms(self, body):
        forms = []
        for m in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.I | re.S):
            attrs = m.group(1)
            action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            hidden = re.findall(r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>', m.group(2), re.I)
            forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
                "hidden_inputs": len(hidden),
            })
        return forms[:15]

    def _extract_external(self, body, host):
        links = []
        for m in re.finditer(r'href\s*=\s*["\']?(https?://[^"\'>\s]+)', body, re.I):
            url = m.group(1)
            if host not in url:
                links.append(url)
        return list(set(links))

    def _detect_js(self, body):
        libs = []
        patterns = [
            (r'jquery[/.-]([0-9.]+)', "jQuery"), (r'react[/.-]([0-9.]+)', "React"),
            (r'vue[/.-]([0-9.]+)', "Vue.js"), (r'angular[/.-]([0-9.]+)', "Angular"),
            (r'bootstrap[/.-]([0-9.]+)', "Bootstrap"), (r'lodash[/.-]([0-9.]+)', "Lodash"),
            (r'moment[/.-]([0-9.]+)', "Moment.js"), (r'axios[/.-]([0-9.]+)', "Axios"),
            (r'next[/.-]([0-9.]+)', "Next.js"), (r'nuxt[/.-]([0-9.]+)', "Nuxt.js"),
            (r'webpack[/.-]([0-9.]+)', "Webpack"), (r'typescript[/.-]([0-9.]+)', "TypeScript"),
            (r'chart\.js[/.-]([0-9.]+)', "Chart.js"), (r'd3[/.-]v([0-9.]+)', "D3.js"),
            (r'tailwindcss', "Tailwind CSS"), (r'materialize[/.-]([0-9.]+)', "Materialize"),
            (r'sweetalert[/.-]([0-9.]+)', "SweetAlert"), (r'fontawesome[/.-]([0-9.]+)', "Font Awesome"),
        ]
        for pat, name in patterns:
            m = re.search(pat, body, re.I)
            if m:
                libs.append(f"{name} {m.group(1) if m.lastindex else ''}".strip())
        return libs[:15]

    def _ip_geo(self, ip):
        try:
            r = self._http_get(f"https://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,isp,org,as", timeout=5)
            if r and r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    def _asn_lookup(self, ip):
        try:
            r = self._http_get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r and r.status_code == 200:
                d = r.json()
                return {"asn": d.get("org", ""), "city": d.get("city", ""), "region": d.get("region", "")}
        except Exception:
            pass
        return {}

    def _rev_dns(self, ip):
        if not ip:
            return ""
        cached = self.session_cache.get(f"revdns:{ip}")
        if cached is not None:
            return cached
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                self.session_cache.set(f"revdns:{ip}", hostname)
                return hostname
        except (socket.herror, socket.gaierror, OSError):
            pass
        try:
            r = self._http_get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r and r.status_code == 200:
                d = r.json()
                org = d.get("org", "")
                if org:
                    self.session_cache.set(f"revdns:{ip}", org)
                    return org
        except Exception:
            pass
        self.session_cache.set(f"revdns:{ip}", "")
        return ""

    def _host_header_inject(self, base):
        try:
            r, _ = self._req("GET", base, headers={"Host": "evil.com"}, timeout=FAST_TIMEOUT)
            if not r:
                return "SAFE"
            if "evil.com" in (r.text if hasattr(r, 'text') else "")[:5000]:
                return "VULNERABLE — Host header reflected"
            if r.status_code == 200:
                return "Host header accepted (200 OK)"
        except Exception:
            pass
        return "SAFE"

    def _crlf_check(self, base):
        ss = self.scan_settings
        results = []
        payloads = ["%0d%0aInjected-Header:1", "%0D%0AX-Injected:1"][:ss.get("limit_crlf", 2)]
        for p in payloads:
            try:
                r, _ = self._req("GET", f"{base}/?test={p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                for k, v in r.headers.items():
                    if "injected" in k.lower():
                        results.append(f"CRLF via {p[:10]}... → header reflected")
                        break
            except Exception:
                continue
        return results

    def _open_redirect(self, base):
        ss = self.scan_settings
        results = []
        params = ["redirect", "url", "next", "return", "goto", "dest", "continue"][:ss.get("limit_redirect", 4)]
        for p in params:
            try:
                r, _ = self._req("GET", f"{base}/?{p}=https://evil.com", timeout=FAST_TIMEOUT, follow_redirects=False)
                if not r:
                    continue
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    results.append(f"Open redirect via ?{p}=...")
            except Exception:
                continue
        return results

    def _dir_traversal(self, base):
        ss = self.scan_settings
        results = []
        payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"][:ss.get("limit_dir_traversal", 2)]
        for p in payloads:
            try:
                r, _ = self._req("GET", f"{base}/{p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                body = r.text[:500] if hasattr(r, 'text') else ""
                if "root:" in body or "[extensions]" in body:
                    results.append(f"Directory traversal: {p}")
            except Exception:
                continue
        return results

    def _check_backup(self, base):
        ss = self.scan_settings
        found = []
        baks = [".bak", ".old", ".swp", ".save"][:ss.get("limit_backup", 4)]
        files = ["config", ".env", "web.config", "index", "settings"][:ss.get("limit_backup", 4)]
        targets = [f"{base}/{f}{b}" for f in files for b in baks]
        def _check(url):
            try:
                r, _ = self._req("GET", url, timeout=FAST_TIMEOUT)
                if r and r.status_code == 200 and len(r.text) > 50:
                    return url[len(base):]
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=min(10, len(targets) or 1)) as ex:
            for result in ex.map(_check, targets):
                if result:
                    found.append(result)
        return found[:10]

    def _check_source_leak(self, base):
        ss = self.scan_settings
        found = []
        leaks = [".git/HEAD", ".env", ".DS_Store", "composer.json", "package.json",
                 "phpinfo.php", "debug.log"][:ss.get("limit_source_leak", 6)]
        for p in leaks:
            try:
                r, _ = self._req("GET", f"{base}/{p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                if r.status_code == 200 and len(r.text) > 5:
                    if any(sig in r.text[:500] for sig in ["[core]", "APP_KEY=", "DB_PASSWORD", "<?xml", "composer", "node_modules"]):
                        found.append(f"/{p}")
            except Exception:
                continue
        return found[:10]

    def _check_admin_panels(self, base):
        ss = self.scan_settings
        found = []
        paths = ["admin", "wp-admin", "cpanel", "phpmyadmin", "manager", "panel"][:ss.get("limit_admin", 5)]
        for p in paths:
            try:
                r, _ = self._req("GET", f"{base}/{p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                if r.status_code in (200, 301, 302, 401, 403):
                    found.append(f"/{p} [{r.status_code}]")
            except Exception:
                continue
        return found[:10]

    def _check_login_pages(self, base):
        ss = self.scan_settings
        found = []
        paths = ["login", "signin", "auth", "wp-login.php", "user/login"][:ss.get("limit_login", 4)]
        for p in paths:
            try:
                r, _ = self._req("GET", f"{base}/{p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                if r.status_code in (200, 301, 302):
                    body = r.text[:5000] if hasattr(r, 'text') else ""
                    if any(kw in body.lower() for kw in ["password", "login", "sign in", "authenticate"]):
                        found.append(f"/{p}")
            except Exception:
                continue
        return found[:10]

    def _check_api_endpoints(self, base, body):
        ss = self.scan_settings
        found = []
        api_paths = ["api", "api/v1", "graphql", "swagger", "openapi.json"][:ss.get("limit_api", 4)]
        for p in api_paths:
            try:
                r, _ = self._req("GET", f"{base}/{p}", timeout=FAST_TIMEOUT)
                if not r:
                    continue
                if r.status_code in (200, 301, 302, 401, 403):
                    found.append(f"/{p} [{r.status_code}]")
            except Exception:
                continue
        body_urls = re.findall(r'["\'](?:https?://[^"\']*|/api/[^"\']*)["\']', body[:50000])
        for u in body_urls[:5]:
            u = u.strip("\"'")
            if "/api/" in u or "graphql" in u:
                found.append(u[:100])
        return list(set(found))[:15]


# ──────────────── ASYNC SCANNER ────────────────

class AsyncScanner:
    """True async parallel runner — replaces ThreadPoolExecutor for HTTP-bound checks."""

    def __init__(self, engine, max_concurrent=MAX_CONCURRENT_REQUESTS):
        self.engine = engine
        self._sem = asyncio.Semaphore(max_concurrent)
        self._client = None

    async def __aenter__(self):
        if HAS_HTTPX:
            self._client = httpx.AsyncClient(
                timeout=self.engine.timeout, follow_redirects=True, verify=self.engine.verify_ssl,
                headers={"User-Agent": HTTP_USER_AGENT},
                limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
            )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def _run_one(self, name, func):
        """Run a single check with semaphore throttle."""
        async with self._sem:
            try:
                result = await asyncio.to_thread(func)
                return name, result
            except Exception:
                default = [] if name != "host_header_inject" else "SAFE"
                return name, default

    async def run_checks(self, checks):
        """Run list of (name, func) pairs concurrently via asyncio.gather.

        checks: list of (name, callable)
        Returns: dict {name: result}
        """
        if not checks:
            return {}
        tasks = [self._run_one(name, func) for name, func in checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = {}
        for r in results:
            if isinstance(r, tuple) and len(r) == 2:
                name, result = r
                out[name] = result
        return out

    async def run_checks_with_attrs(self, report, checks):
        """Run checks and set results as attributes on the report.

        checks: list of (name, callable, *extra_args)
        Special handling for 'graphql' which sets two attributes.
        """
        if not checks:
            return
        wrapped = []
        for item in checks:
            name = item[0]
            func = item[1]
            wrapped.append((name, func))
        results = await self.run_checks(wrapped)
        for name, result in results.items():
            if name == "graphql":
                report.graphql_schema, report.graphql_vulns = result
            else:
                setattr(report, name, result)


# ──────────────── ASYNC ENGINE ────────────────

class AsyncScanEngine:
    """Async version of scan engine — x10 faster on path/port scanning."""

    def __init__(self, timeout=DEFAULT_TIMEOUT, custom_paths=None, proxy=None, custom_lists=None, plugins=None, verify_ssl=True):
        self.sync_engine = ScanEngine(timeout, custom_paths, proxy, custom_lists, plugins, verify_ssl=verify_ssl)
        self._log = self.sync_engine._log
        self._progress = self.sync_engine._progress
        self._client = None  # shared httpx.AsyncClient for async security checks

    def __getattr__(self, name):
        return getattr(self.sync_engine, name)

    async def async_scan_paths(self, base, paths, blacklist=None):
        blacklist = set(blacklist or [])
        results = []
        sem = asyncio.Semaphore(DIR_WORKERS)

        async def check(client, path):
            if path in blacklist:
                return None
            if self.sync_engine.stop_event.is_set():
                return None
            url = base.rstrip("/") + "/" + path.lstrip("/")
            try:
                async with sem:
                    resp = await client.get(url, timeout=FAST_TIMEOUT, follow_redirects=True)
                    size = len(resp.content)
                    if resp.status_code == 200:
                        body_snippet = resp.text[:5000] if hasattr(resp, 'text') else ""
                        return {"path": "/" + path.lstrip("/"), "status": resp.status_code, "size": size, "_body": body_snippet}
            except Exception:
                pass
            return None

        proxy_kw = {"proxy": self.sync_engine.proxy} if self.sync_engine.proxy else {}
        async with httpx.AsyncClient(verify=self.sync_engine.verify_ssl, follow_redirects=False, timeout=self.sync_engine.timeout, limits=httpx.Limits(max_connections=64, max_keepalive_connections=32), **proxy_kw) as client:
            total = len(paths)
            batch_size = BATCH_SIZE_LARGE
            for i in range(0, total, batch_size):
                if self.sync_engine.stop_event.is_set():
                    break
                batch = paths[i:i + batch_size]
                batch_results = await asyncio.gather(*(check(client, p) for p in batch), return_exceptions=True)
                for r in batch_results:
                    if isinstance(r, dict):
                        results.append(r)
                done = min(i + batch_size, total)
                if done % 200 < batch_size:
                    self._progress("paths", done, total)
        return results

    async def async_scan_ports(self, ip, ports=None):
        ports = ports or COMMON_PORTS
        results = []
        sem = asyncio.Semaphore(PORT_WORKERS)

        async def check(port):
            if self.sync_engine.stop_event.is_set():
                return None
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=DRAIN_TIMEOUT
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception:
                    return None

        total = len(ports)
        batch_size = BATCH_SIZE_SMALL
        for i in range(0, total, batch_size):
            if self.sync_engine.stop_event.is_set():
                break
            batch = ports[i:i + batch_size]
            batch_results = await asyncio.gather(*(check(p) for p in batch), return_exceptions=True)
            for r in batch_results:
                if isinstance(r, int):
                    results.append(r)
            done = min(i + batch_size, total)
            if done % 100 < batch_size:
                self._progress("ports", done, total)
        return sorted(results)

    # ──── Async HTTP helpers ────

    async def _areq(self, client, method, url, timeout=None, **kw):
        """Async HTTP request with exponential backoff retry."""
        t = timeout or self.sync_engine.timeout
        for attempt in range(2):
            try:
                resp = await client.request(method, url, timeout=t, **kw)
                status = resp.status_code
                return resp, status
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.3)
                    t = min(t * 1.5, 15)  # slight increase on retry
                else:
                    raise

    # ──── Async security check methods ────

    async def async_probe_methods(self, url, client):
        """Check HTTP methods (OPTIONS + TRACE) in parallel."""
        async def _check(method):
            try:
                r, s = await self._areq(client, method, url, timeout=FAST_TIMEOUT)
                return method, s, r.headers.get("Allow", "")
            except Exception:
                return method, 0, ""
        results = await asyncio.gather(*[_check("OPTIONS"), _check("TRACE")])
        methods = ["OPTIONS"]
        trace_ok = False
        for m, s, allow in results:
            if m == "OPTIONS" and allow:
                methods = [x.strip() for x in allow.split(",") if x.strip()]
            if m == "TRACE" and s == 200:
                trace_ok = True
        return methods, trace_ok

    async def async_check_cors(self, url, client):
        """Test CORS with two origins in parallel."""
        issues = []
        async def _test(origin):
            try:
                r, _ = await self._areq(client, "GET", url, headers={"Origin": origin}, timeout=FAST_TIMEOUT)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                results = []
                if acao == "*":
                    results.append("CORS wildcard (*)")
                elif acao.lower() == origin.lower():
                    results.append(f"CORS reflects: {acao}")
                    if acac.lower() == "true":
                        results.append("CORS credentials=true")
                return results
            except Exception:
                return []
        cors_results = await asyncio.gather(*[_test("https://evil.com"), _test("null")])
        for r in cors_results:
            issues.extend(r)
        return issues

    async def async_check_http_https(self, host, port, client):
        """Check HTTP→HTTPS redirect."""
        if port == 443:
            return True  # already HTTPS
        http_url = f"http://{host}:{port}"
        try:
            r, _ = await self._areq(client, "GET", http_url, timeout=FAST_TIMEOUT)
            loc = r.headers.get("Location", "")
            return "https://" in loc.lower()
        except Exception:
            return False

    async def async_ssl_combined(self, host, port):
        """SSL/TLS check via asyncio socket."""
        result = {"expiry_days": 0, "expiry_date": "", "weak_cipher": False, "tls": "", "deep": {}}
        try:
            ssl_info = await asyncio.get_event_loop().run_in_executor(
                None, self.sync_engine._ssl_combined, host, port
            )
            result.update(ssl_info)
        except Exception:
            pass
        return result

    async def async_check_xss(self, url, client, baseline_body=""):
        """XSS reflection check using shared baseline."""
        return self.sync_engine.check_xss(url, baseline_body=baseline_body)

    async def async_check_sql_errors(self, url, client):
        """SQL error check."""
        return self.sync_engine.check_sql_errors(url)

    # ──── Parallel security checks ────

    async def _parallel_security_checks(self, r, resp, body, client):
        """Run all I/O-bound security checks in parallel via asyncio.gather."""
        url = r.normalized_url
        host = r.host
        port = r.port

        # Group A: CPU checks (instant, run inline)
        r.missing_security_headers = self.sync_engine.missing_headers(r.headers)
        r.fingerprint_hints = self.sync_engine.fingerprint(r.headers)
        r.cookie_issues, r.cookies_found = self.sync_engine.check_cookies(resp)
        r.hsts_enabled = self.sync_engine.check_hsts(r.headers, resp, host)
        r.clickjacking_protected = self.sync_engine.check_clickjacking(r.headers)
        r.mixed_content = self.sync_engine.check_mixed(resp)
        r.directory_listing = self.sync_engine.check_dir_listing(resp, url)
        r.version_hints, r.detected_cms, r.detected_frameworks = self.sync_engine.detect_cms(resp, body)

        # Group B: I/O checks (HTTP/socket — run ALL concurrently)
        io_results = await asyncio.gather(
            self.async_probe_methods(url, client),
            self.async_check_cors(url, client),
            self.async_check_http_https(host, port, client),
            self.async_ssl_combined(host, port),
            self.async_check_xss(url, client, baseline_body=body),
            self.async_check_sql_errors(url, client),
            return_exceptions=True,
        )

        # Unpack I/O results safely
        # [0] probe_methods
        if isinstance(io_results[0], tuple):
            r.allowed_methods, r.trace_enabled = io_results[0]
        else:
            r.allowed_methods, r.trace_enabled = [], False

        # [1] cors
        r.cors_issues = io_results[1] if isinstance(io_results[1], list) else []

        # [2] http→https
        r.http_to_https_redirect = io_results[2] if isinstance(io_results[2], bool) else False

        # [3] ssl
        if isinstance(io_results[3], dict):
            ssl_data = io_results[3]
        else:
            ssl_data = {"expiry_days": 0, "expiry_date": "", "weak_cipher": False, "tls": "", "deep": {}}
        r.ssl_expiry_days = ssl_data.get("expiry_days", 0)
        r.ssl_expiry_date = ssl_data.get("expiry_date", "")
        r.ssl_weak_cipher = ssl_data.get("weak_cipher", False)
        r.tls_summary = ssl_data.get("tls", "")
        r.ssl_deep = ssl_data.get("deep", {})

        # ── Plugin hook: on_after_ssl (async) ──
        self.sync_engine._fire_hook("on_after_ssl", ssl_data, r)

        # [4] xss
        r.xss_reflection = io_results[4] if isinstance(io_results[4], bool) else False

        # [5] sql
        r.sql_errors = io_results[5] if isinstance(io_results[5], list) else []

        # WAF + versions (CPU, after I/O)
        r.waf_detected = self.sync_engine.detect_waf(resp)
        versions = self.sync_engine.detect_versions(resp, body)
        version_strs = [f"{v['name']}: {v['version']}" for v in versions]
        seen = set(r.version_hints)
        for vs in version_strs:
            if vs not in seen:
                r.version_hints.append(vs)
                seen.add(vs)
        return versions

    def run_async(self, target):
        """Run full scan using async engine for path/port scanning."""
        with self._async_lock:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._main_task = None
        try:
            coro = self._async_run(target)
            self._main_task = self._loop.create_task(coro)
            return self._loop.run_until_complete(self._main_task)
        except (asyncio.CancelledError, RuntimeError):
            return None
        finally:
            self._cleanup_loop(self._loop)
            with self._async_lock:
                self._main_task = None
                self._loop = None

    def stop_async(self):
        """Instantly stop the async scan by cancelling the main task."""
        self.sync_engine.stop_event.set()
        with self._async_lock:
            loop = self._loop
            task = self._main_task
        if loop and loop.is_running() and not loop.is_closed():
            def _force_stop():
                if task and not task.done():
                    task.cancel()
                loop.stop()
            try:
                loop.call_soon_threadsafe(_force_stop)
            except RuntimeError:
                pass

    def _cleanup_loop(self, loop):
        try:
            for task in asyncio.all_tasks(loop):
                task.cancel()
            if not loop.is_closed():
                loop.run_until_complete(asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True))
        except Exception:
            pass
        try:
            if not loop.is_closed():
                loop.close()
        except Exception:
            pass

    async def _async_run(self, target):
        t0 = time.perf_counter()
        r = Report()
        r.generated_at = datetime.now().isoformat()
        r.target = target
        r.proxy_used = self.sync_engine.proxy or ""
        is_ip = self.sync_engine.is_ip(target.strip())

        self._log(f"Resolving {target}...")
        r.normalized_url, r.scheme, r.host, r.port = self.sync_engine.normalize(target)
        r.ip = self.sync_engine.resolve_ip(r.host) if not is_ip else r.host

        self._log(f"Checking connectivity to {r.host}...")
        connected = False
        try:
            sock = socket.create_connection((r.host, r.port), timeout=8)
            sock.close()
            connected = True
        except (socket.timeout, OSError):
            self._log(f"Port {r.port} unreachable, trying alternatives...")
            _alt_probe = [80, 443, 8080, 8443, 8000, 5000, 3000, 9090]
            for _p in _alt_probe:
                if _p == r.port:
                    continue
                try:
                    _sock = socket.create_connection((r.host, _p), timeout=3)
                    _sock.close()
                    _scheme = "https" if _p in (443, 8443) else "http"
                    r.port = _p
                    r.scheme = _scheme
                    r.normalized_url = self.base_url(_scheme, r.host, _p)
                    self._log(f"Connected on port {_p} ({_scheme})")
                    connected = True
                    break
                except (socket.timeout, OSError):
                    continue
        if not connected:
            # No TCP port reachable — may be a DNS-only node; allow scan to continue
            self._log(f"No TCP ports reachable on {r.host} — will scan as server node")
            r.no_http = True
            r.server_node = True

        self.sync_engine._fire_hook("on_scan_start", target, r)

        if is_ip:
            self._log(f"IP mode (async): {r.host}")
            r.reverse_dns = self.sync_engine._rev_dns(r.ip)
            r.ip_geo = self.sync_engine._ip_geo(r.ip)
            r.asn_info = self.sync_engine._asn_lookup(r.ip)
            r.dns_records = self.sync_engine.check_dns(r.host)
            if self.sync_engine.stop_event.is_set():
                return r
            r.open_ports = await self.async_scan_ports(r.ip)
            r.port_banners = {}
            def _grab(p):
                return str(p), self.sync_engine.grab_banner(r.ip, p)
            with ThreadPoolExecutor(max_workers=min(20, len(r.open_ports) or 1)) as ex:
                for p, banner in ex.map(lambda p: _grab(p), r.open_ports):
                    r.port_banners[p] = banner

            # ── Plugin hook: on_after_ports (async IP mode) ──
            self.sync_engine._fire_hook("on_after_ports", r.open_ports, r)

            if self.sync_engine.stop_event.is_set():
                return r
            if 443 in r.open_ports:
                r.scheme = "https"
                r.port = 443
                ssl_data = self.sync_engine._ssl_combined(r.host, 443)
                r.ssl_expiry_days = ssl_data["expiry_days"]
                r.ssl_expiry_date = ssl_data["expiry_date"]
                r.ssl_weak_cipher = ssl_data["weak_cipher"]
                r.tls_summary = ssl_data["tls"]
                r.ssl_deep = ssl_data["deep"]
                # ── Plugin hook: on_after_ssl (async IP mode) ──
                self.sync_engine._fire_hook("on_after_ssl", ssl_data, r)
            r.risk_score, r.risk_level = self.sync_engine.score_risk(r)

            # ── Plugin hook: on_scan_complete (async IP mode) ──
            self.sync_engine._fire_hook("on_scan_complete", r)
            # ── Collect plugin graph nodes (async IP mode) ──
            for p in self.sync_engine.plugins:
                fn = getattr(p, "get_graph_nodes", None)
                if callable(fn):
                    try:
                        nodes = fn(r)
                        if isinstance(nodes, list):
                            r.plugin_graph_nodes.extend(nodes)
                    except Exception:
                        pass
            r.scan_duration_ms = int((time.perf_counter() - t0) * 1000)
            return r

        base = self.sync_engine.base_url(r.scheme, r.host, r.port)

        self._log("Probing root (async)...")
        resp = None
        body = ""
        if not r.server_node:
            # ── Plugin hook: on_before_request (async) ──
            self.sync_engine._fire_hook("on_before_request", "GET", r.normalized_url)

            resp, ms = self.sync_engine.probe_root(r.normalized_url)
            r.response_time_ms = ms
            r.headers = self.sync_engine.collect_headers(resp)
            body = resp.text if resp and hasattr(resp, 'text') else ""
            r.status_code = resp.status_code if resp else None
            r.final_url = str(resp.url) if resp and hasattr(resp, 'url') else ""

        # ── Server node detection (async — mirror sync logic) ──
        if resp is None and not r.server_node:
            self._log("No HTTP response — trying alt ports (async)...")
            r.no_http = True
            alt_found = self.sync_engine._probe_alt_ports(r.host)
            if alt_found:
                best_port, best_url, best_scheme = alt_found[0]
                r.port = best_port
                r.scheme = best_scheme
                r.normalized_url = best_url
                r.server_node = False
                resp, ms = self.sync_engine.probe_root(r.normalized_url)
                r.response_time_ms = ms
                r.headers = self.sync_engine.collect_headers(resp)
                body = resp.text if resp and hasattr(resp, 'text') else ""
                r.status_code = resp.status_code if resp else None
                r.final_url = str(resp.url) if resp and hasattr(resp, 'url') else ""
            else:
                self._log("No HTTP server detected — server node mode (async)")
                r.server_node = True

        # Ensure headers/body are defined for server nodes
        if not hasattr(r, 'headers') or r.headers is None:
            r.headers = {}

        # ── Plugin hook: on_request (async) ──
        self.sync_engine._fire_hook("on_request", r.normalized_url, resp, r)

        # ── Plugin hook: on_after_headers (async) ──
        self.sync_engine._fire_hook("on_after_headers", dict(r.headers), r)

        self._log("Security checks (parallel async)...")
        if self.sync_engine.stop_event.is_set():
            return r

        # Server node mode: only SSL + DNS, skip HTTP-dependent checks
        if r.server_node:
            self._log("Server node mode — SSL/DNS checks only (async)")
            try:
                ssl_data = self.sync_engine._ssl_combined(r.host, 443)
                r.ssl_expiry_days = ssl_data["expiry_days"]
                r.ssl_expiry_date = ssl_data["expiry_date"]
                r.ssl_weak_cipher = ssl_data["weak_cipher"]
                r.tls_summary = ssl_data["tls"]
                r.ssl_deep = ssl_data["deep"]
                # ── Plugin hook: on_after_ssl (async server node) ──
                self.sync_engine._fire_hook("on_after_ssl", ssl_data, r)
            except Exception:
                pass
            versions = []
        else:
            # Create shared AsyncClient for all security checks if not yet created
            own_client = False
            if not self._client:
                proxy_kw = {"proxy": self.sync_engine.proxy} if self.sync_engine.proxy else {}
                import httpx as _httpx_mod
                self._client = httpx.AsyncClient(
                    verify=self.sync_engine.verify_ssl, follow_redirects=True,
                    timeout=self.sync_engine.timeout,
                    limits=_httpx_mod.Limits(max_connections=64, max_keepalive_connections=32),
                    **proxy_kw,
                )
                own_client = True
            try:
                versions = await self._parallel_security_checks(r, resp, body, self._client)
            finally:
                if own_client and self._client:
                    try:
                        await self._client.aclose()
                    except Exception:
                        pass
                    self._client = None

        # Run DNS, CVE, subdomains in parallel (like sync engine)
        # NOTE: httpx.Client is NOT thread-safe — _ip_geo/_asn_lookup use sync_engine._http_get.
        if HAS_HTTPX:
            r.dns_records = self.sync_engine.check_dns(r.host)
            r.cve_findings = self.sync_engine.check_cve(versions)
            r.subdomains = self.sync_engine.check_subdomains(r.host)
            r.ip_geo = self.sync_engine._ip_geo(r.ip)
            r.asn_info = self.sync_engine._asn_lookup(r.ip)
            r.reverse_dns = self.sync_engine._rev_dns(r.ip)
        else:
            with ThreadPoolExecutor(max_workers=5) as ex:
                dns_fut = ex.submit(self.sync_engine.check_dns, r.host)
                cve_fut = ex.submit(self.sync_engine.check_cve, versions)
                sub_fut = ex.submit(self.sync_engine.check_subdomains, r.host)
                ip_fut = ex.submit(self.sync_engine._ip_geo, r.ip)
                asn_fut = ex.submit(self.sync_engine._asn_lookup, r.ip)
                rev_fut = ex.submit(self.sync_engine._rev_dns, r.ip)
                r.dns_records = dns_fut.result()
                r.cve_findings = cve_fut.result()
                r.subdomains = sub_fut.result()
                r.ip_geo = ip_fut.result()
                r.asn_info = asn_fut.result()
                r.reverse_dns = rev_fut.result()

        if self.sync_engine.stop_event.is_set():
            return r
        self._log("Async port scan...")
        r.open_ports = await self.async_scan_ports(r.ip)
        r.port_banners = {}
        def _grab2(p):
            return str(p), self.sync_engine.grab_banner(r.ip, p)
        with ThreadPoolExecutor(max_workers=min(20, len(r.open_ports) or 1)) as ex:
            for p, banner in ex.map(lambda p: _grab2(p), r.open_ports):
                if self.sync_engine.stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                r.port_banners[p] = banner

        # ── Plugin hook: on_after_ports (async) ──
        self.sync_engine._fire_hook("on_after_ports", r.open_ports, r)

        # Get blacklist from custom lists
        blacklist = set()
        if self.sync_engine.cl:
            blacklist = set(bl.lstrip("/") for bl in self.sync_engine.cl.get("blacklist", []))

        if self.sync_engine.stop_event.is_set():
            return r
        if not r.server_node:
            all_paths = list(dict.fromkeys(
                self.sync_engine.custom_paths + GENERIC_PATHS + WP_PATHS + LARAVEL_PATHS +
                DRUPAL_PATHS + JOOMLA_PATHS + SPRING_PATHS + DJANGO_PATHS + NEXTJS_PATHS
            ))
            self._log(f"Async scanning {len(all_paths)} paths...")
            r.discovered_paths = await self.async_scan_paths(base, all_paths, blacklist)
            # Validate critical paths with content checks to avoid soft-404 false positives
            critical = []
            for item in r.discovered_paths:
                p = item["path"].lstrip("/")
                if p in CRITICAL_PATHS and item.get("status") == 200:
                    body = item.pop("_body", "")
                    if _is_real_critical(p, body, item["size"]):
                        critical.append(p)
            # Clean _body from remaining items
            for item in r.discovered_paths:
                item.pop("_body", None)
            r.critical_paths = sorted(set(critical))
            r.total_paths_scanned = len(all_paths)
        else:
            self._log("Server node mode — skipping path scanning (async)")

        # ── Plugin hook: on_after_paths (async) ──
        self.sync_engine._fire_hook("on_after_paths", r.discovered_paths, r)

        if r.trace_enabled: r.anomaly_hints.append("TRACE enabled")
        if any(m in ("PUT", "DELETE") for m in r.allowed_methods): r.anomaly_hints.append(f"Risky methods: {', '.join(r.allowed_methods)}")
        if not r.hsts_enabled: r.anomaly_hints.append("HSTS missing")
        if not r.http_to_https_redirect: r.anomaly_hints.append("No HTTPS redirect")
        if r.ssl_expiry_days is not None and r.ssl_expiry_days < 30: r.anomaly_hints.append(f"SSL expires in {r.ssl_expiry_days}d!")
        if r.ssl_weak_cipher: r.anomaly_hints.append("Weak SSL cipher")
        if r.directory_listing: r.anomaly_hints.append("Directory listing")
        if r.xss_reflection: r.anomaly_hints.append("XSS reflection")

        r.risk_score, r.risk_level = self.sync_engine.score_risk(r)

        # ── Plugin hook: on_scan_complete (async) ──
        self.sync_engine._fire_hook("on_scan_complete", r)

        # ── Collect plugin graph nodes (async) ──
        for p in self.sync_engine.plugins:
            fn = getattr(p, "get_graph_nodes", None)
            if callable(fn):
                try:
                    nodes = fn(r)
                    if isinstance(nodes, list):
                        r.plugin_graph_nodes.extend(nodes)
                except Exception:
                    pass

        r.scan_duration_ms = int((time.perf_counter() - t0) * 1000)
        self._log(f"Async scan complete in {r.scan_duration_ms}ms — Risk: {r.risk_level.upper()}")
        return r
