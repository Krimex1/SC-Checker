import sys
import json
from pathlib import Path


VERSION = "1.3.0"
DEFAULT_TIMEOUT = 5.0
FAST_TIMEOUT = 2.0
DIR_WORKERS = 24
PORT_WORKERS = 64

# ──────────────── NETWORK ────────────────
DEFAULT_REQUEST_TIMEOUT = 15
HTTP_USER_AGENT = "Mozilla/5.0 (compatible; SC-Checker/1.3)"

# ──────────────── ENGINE CONCURRENCY ────────────────
MAX_CONCURRENT_REQUESTS = 12
BATCH_SIZE_LARGE = 200
BATCH_SIZE_SMALL = 100
DRAIN_TIMEOUT = 1.5
COUNTER_LOG_INTERVAL = 8

# ──────────────── CONTENT PREVIEW LIMITS ────────────────
BODY_PREVIEW_SHORT = 2000
BODY_PREVIEW_MEDIUM = 3000
BODY_PREVIEW_LONG = 5000

# ──────────────── NOTIFICATION TEXT LIMITS ────────────────
DISCORD_TEXT_LIMIT = 4000
DISCORD_TEXT_HARD = 3000
DISCORD_TITLE_LIMIT = 1024

if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = APP_DIR / "reports"
CUSTOM_DIR = REPORTS_DIR / "custom"
PLUGINS_DIR = APP_DIR / "plugins"
CACHE_DIR = REPORTS_DIR / "cache"
CVE_CACHE_FILE = REPORTS_DIR / "cve_cache.json"
AI_SETTINGS_FILE = APP_DIR / "ai_settings.json"
ICON_PATH = APP_DIR / "icon.ico"


# ──────────────── THEME ────────────────

THEMES = {
    "neon_dark": {
        "name": "Neon Dark",
        "bg": "#0a0a0f", "bg2": "#0f1019", "bg3": "#141520",
        "surface": "#12131e", "surface2": "#181a28", "surface3": "#1e2030",
        "glass": "#13141f", "glass2": "#181924", "glass3": "#1d1f2e",
        "glass_border": "#252740", "glass_border2": "#2e3050",
        "fg": "#e8eaf0", "fg2": "#c8cce0", "fg3": "#555873", "fg4": "#3a3d52",
        "blue": "#3b82f6", "blue_bright": "#60a5fa", "blue_dim": "#1e3a5f",
        "purple": "#a855f7", "purple_bright": "#c084fc", "purple_dim": "#3b1d6e",
        "pink": "#ec4899", "pink_bright": "#f472b6", "pink_dim": "#5c1a3a",
        "green": "#22c55e", "green_bright": "#4ade80", "green_dim": "#0f3d1f",
        "red": "#ef4444", "red_bright": "#f87171", "red_dim": "#3d0f0f",
        "yellow": "#eab308", "yellow_bright": "#facc15", "yellow_dim": "#3d3008",
        "orange": "#f97316", "orange_bright": "#fb923c", "orange_dim": "#3d2008",
        "cyan": "#06b6d4", "cyan_bright": "#22d3ee", "cyan_dim": "#083040",
        "teal": "#14b8a6",
    },
    "cyber_blue": {
        "name": "Cyber Blue",
        "bg": "#060d1a", "bg2": "#0a1628", "bg3": "#0e1e36",
        "surface": "#0c1a2e", "surface2": "#112240", "surface3": "#162d50",
        "glass": "#0d1b30", "glass2": "#122342", "glass3": "#172c52",
        "glass_border": "#1e3a6a", "glass_border2": "#2a4d8a",
        "fg": "#d0e0f0", "fg2": "#a0b8d0", "fg3": "#4a6a8a", "fg4": "#2d4a6a",
        "blue": "#00aaff", "blue_bright": "#33bbff", "blue_dim": "#0a3050",
        "purple": "#7b61ff", "purple_bright": "#9b81ff", "purple_dim": "#2a1d60",
        "pink": "#ff6b9d", "pink_bright": "#ff8bb5", "pink_dim": "#3d1530",
        "green": "#00d68f", "green_bright": "#33e0a5", "green_dim": "#0a3d25",
        "red": "#ff4757", "red_bright": "#ff6b7a", "red_dim": "#3d1015",
        "yellow": "#ffc048", "yellow_bright": "#ffd06a", "yellow_dim": "#3d2d0a",
        "orange": "#ff8c42", "orange_bright": "#ffa060", "orange_dim": "#3d2010",
        "cyan": "#00d4ff", "cyan_bright": "#33ddff", "cyan_dim": "#0a3545",
        "teal": "#00c9a7",
    },
    "midnight_purple": {
        "name": "Midnight Purple",
        "bg": "#0d0a14", "bg2": "#120e1e", "bg3": "#181428",
        "surface": "#14101f", "surface2": "#1c1630", "surface3": "#241e3a",
        "glass": "#151120", "glass2": "#1d1732", "glass3": "#251f3c",
        "glass_border": "#352a5a", "glass_border2": "#453a70",
        "fg": "#e0d8f0", "fg2": "#b8a8d0", "fg3": "#5a4a78", "fg4": "#3a2d55",
        "blue": "#6c5ce7", "blue_bright": "#8b7ef0", "blue_dim": "#1a1540",
        "purple": "#a855f7", "purple_bright": "#c084fc", "purple_dim": "#2d1560",
        "pink": "#fd79a8", "pink_bright": "#fda0c0", "pink_dim": "#3d1535",
        "green": "#00b894", "green_bright": "#33ccaa", "green_dim": "#0a3028",
        "red": "#ff6b6b", "red_bright": "#ff8888", "red_dim": "#3d1515",
        "yellow": "#feca57", "yellow_bright": "#ffe070", "yellow_dim": "#3d3010",
        "orange": "#ff9f43", "orange_bright": "#ffb060", "orange_dim": "#3d2510",
        "cyan": "#48dbfb", "cyan_bright": "#6ee0ff", "cyan_dim": "#0a3540",
        "teal": "#0abde3",
    },
    "forest_green": {
        "name": "Forest Green",
        "bg": "#0a120a", "bg2": "#0e180e", "bg3": "#121e12",
        "surface": "#0f150f", "surface2": "#162016", "surface3": "#1c281c",
        "glass": "#101610", "glass2": "#172217", "glass3": "#1d2a1d",
        "glass_border": "#2a402a", "glass_border2": "#3a553a",
        "fg": "#d0e8d0", "fg2": "#a0c0a0", "fg3": "#4a704a", "fg4": "#2d4a2d",
        "blue": "#2ecc71", "blue_bright": "#4ade80", "blue_dim": "#0a3018",
        "purple": "#9b59b6", "purple_bright": "#b07cc6", "purple_dim": "#2a1540",
        "pink": "#e056a0", "pink_bright": "#f070b0", "pink_dim": "#3d1530",
        "green": "#27ae60", "green_bright": "#3dce70", "green_dim": "#0a3d1a",
        "red": "#e74c3c", "red_bright": "#f06060", "red_dim": "#3d1010",
        "yellow": "#f1c40f", "yellow_bright": "#f5d430", "yellow_dim": "#3d3008",
        "orange": "#e67e22", "orange_bright": "#f09040", "orange_dim": "#3d2008",
        "cyan": "#1abc9c", "cyan_bright": "#3ddcb0", "cyan_dim": "#0a3530",
        "teal": "#16a085",
    },
    "crimson_red": {
        "name": "Crimson Red",
        "bg": "#120a0a", "bg2": "#1a0e0e", "bg3": "#221414",
        "surface": "#180f0f", "surface2": "#221616", "surface3": "#2c1c1c",
        "glass": "#1a1010", "glass2": "#231818", "glass3": "#2d2020",
        "glass_border": "#4a2525", "glass_border2": "#603535",
        "fg": "#f0d0d0", "fg2": "#d0a0a0", "fg3": "#704a4a", "fg4": "#4a2d2d",
        "blue": "#e74c3c", "blue_bright": "#f06060", "blue_dim": "#3d1010",
        "purple": "#c0392b", "purple_bright": "#d04a3a", "purple_dim": "#3d1515",
        "pink": "#e91e63", "pink_bright": "#f04080", "pink_dim": "#3d1025",
        "green": "#2ecc71", "green_bright": "#4ade80", "green_dim": "#0a3018",
        "red": "#ff4444", "red_bright": "#ff6666", "red_dim": "#3d0f0f",
        "yellow": "#f39c12", "yellow_bright": "#f5b040", "yellow_dim": "#3d2a08",
        "orange": "#d35400", "orange_bright": "#e06820", "orange_dim": "#3d1a05",
        "cyan": "#00bcd4", "cyan_bright": "#26c6da", "cyan_dim": "#0a3040",
        "teal": "#009688",
    },
    "light": {
        "name": "Light",
        "bg": "#f0f2f5", "bg2": "#e8eaed", "bg3": "#dfe1e5",
        "surface": "#ffffff", "surface2": "#f8f9fa", "surface3": "#eef0f2",
        "glass": "#ffffff", "glass2": "#f5f6f8", "glass3": "#ecedf0",
        "glass_border": "#d0d3d8", "glass_border2": "#b8bcc2",
        "fg": "#1a1a2e", "fg2": "#3a3a5c", "fg3": "#8888a0", "fg4": "#aab0c0",
        "blue": "#2563eb", "blue_bright": "#3b82f6", "blue_dim": "#dbeafe",
        "purple": "#7c3aed", "purple_bright": "#8b5cf6", "purple_dim": "#ede9fe",
        "pink": "#db2777", "pink_bright": "#ec4899", "pink_dim": "#fce7f3",
        "green": "#16a34a", "green_bright": "#22c55e", "green_dim": "#dcfce7",
        "red": "#dc2626", "red_bright": "#ef4444", "red_dim": "#fee2e2",
        "yellow": "#ca8a04", "yellow_bright": "#eab308", "yellow_dim": "#fef9c3",
        "orange": "#ea580c", "orange_bright": "#f97316", "orange_dim": "#ffedd5",
        "cyan": "#0891b2", "cyan_bright": "#06b6d4", "cyan_dim": "#cffafe",
        "teal": "#0d9488",
    },
}

THEME_FILE = APP_DIR / "theme.json"

# ──────────────── ACCENT DEFAULTS (shared by switch_theme + initial T) ────────────────
_ACCENT_DEFAULTS = {
    "accent": "#3b82f6", "accent2": "#a855f7", "accent3": "#60a5fa",
    "card": "#12131e", "border": "#252740", "border_light": "#2e3050",
    "entry_fg": "#181a28", "entry_bg": "#e8eaf0",
}

def load_theme():
    """Load saved theme or return default."""
    if THEME_FILE.exists():
        try:
            data = json.loads(THEME_FILE.read_text("utf-8"))
            name = data.get("theme", "neon_dark")
            if name in THEMES:
                return name
        except Exception:
            pass
    return "neon_dark"

def save_theme(name):
    """Save theme selection."""
    THEME_FILE.write_text(json.dumps({"theme": name}, indent=2), "utf-8")


def switch_theme(name):
    """Switch active theme at runtime - updates T dict in-place."""
    if name not in THEMES:
        return
    T.clear()
    T.update(THEMES[name])
    T.update({
        **_ACCENT_DEFAULTS,
        "card": THEMES[name].get("surface", _ACCENT_DEFAULTS["card"]),
        "border": THEMES[name].get("glass_border", _ACCENT_DEFAULTS["border"]),
        "border_light": THEMES[name].get("glass_border2", _ACCENT_DEFAULTS["border_light"]),
        "entry_fg": THEMES[name].get("bg2", _ACCENT_DEFAULTS["entry_fg"]),
        "entry_bg": THEMES[name].get("fg", _ACCENT_DEFAULTS["entry_bg"]),
    })
    save_theme(name)

T = {**THEMES[load_theme()], **_ACCENT_DEFAULTS}

FONT_MAIN = ("Segoe UI", 13)
FONT_BOLD = ("Segoe UI", 13, "bold")
FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_TITLE_SM = ("Segoe UI", 17, "bold")
FONT_MONO = ("Cascadia Code", 12)
FONT_MONO_BOLD = ("Cascadia Code", 12, "bold")
FONT_MONO_SM = ("Cascadia Code", 11)
FONT_SMALL = ("Segoe UI", 11)
FONT_SMALL_BOLD = ("Segoe UI", 11, "bold")
FONT_TINY = ("Cascadia Code", 10)
FONT_TINY_BOLD = ("Cascadia Code", 10, "bold")
FONT_ICON = ("Segoe UI", 18)
FONT_GAUGE = ("Cascadia Code", 36, "bold")
FONT_GAUGE_SM = ("Cascadia Code", 14)
FONT_GAUGE_LABEL = ("Segoe UI", 10, "bold")

# ──────────────── COLOR HELPERS ────────────────

def _dim_color(hex_color, factor=0.5):
    """Dim a hex color by blending toward the background."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    br, bg, bb = int(T["bg"][1:3], 16), int(T["bg"][3:5], 16), int(T["bg"][5:7], 16)
    r = int(r * factor + br * (1 - factor))
    g = int(g * factor + bg * (1 - factor))
    b = int(b * factor + bb * (1 - factor))
    return f"#{r:02x}{g:02x}{b:02x}"

def _glow_color(hex_color, intensity=4):
    """Create a glow (dimmed) version of a color."""
    return _dim_color(hex_color, intensity / 16)

# ──────────────── AI PROVIDERS ────────────────

AI_PROVIDERS = {
    "OpenAI": {
        "url": "https://api.openai.com/v1/chat/completions",
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "format": "openai"
    },
    "Google Gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "env_key": "GEMINI_API_KEY",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-1.5-flash"],
        "format": "gemini"
    },
    "Anthropic Claude": {
        "url": "https://api.anthropic.com/v1/messages",
        "env_key": "ANTHROPIC_API_KEY",
        "models": ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
        "format": "anthropic",
        "extra": "header: x-api-key"
    },
    "OpenRouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "env_key": "OPENROUTER_API_KEY",
        "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "google/gemini-2.5-flash"],
        "format": "openai"
    },
    "Groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "env_key": "GROQ_API_KEY",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        "format": "openai"
    },
    "Mistral AI": {
        "url": "https://api.mistral.ai/v1/chat/completions",
        "env_key": "MISTRAL_API_KEY",
        "models": ["mistral-large-latest", "mistral-small-latest", "open-mistral-nemo"],
        "format": "openai"
    },
    "Deepseek": {
        "url": "https://api.deepseek.com/v1/chat/completions",
        "env_key": "DEEPSEEK_API_KEY",
        "models": ["deepseek-chat", "deepseek-coder"],
        "format": "openai"
    },
    "Cloudflare Workers AI": {
        "url": "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/meta/llama-3-8b-instruct",
        "env_key": "CF_API_TOKEN",
        "account_id_key": "CF_ACCOUNT_ID",
        "models": ["@cf/meta/llama-3-8b-instruct", "@cf/mistral/mistral-7b-instruct-v0.2"],
        "format": "cloudflare"
    },
    "Pollinations.ai": {
        "url": "https://gen.pollinations.ai/v1/chat/completions",
        "models_url": "https://gen.pollinations.ai/v1/models",
        "env_key": "POLLINATIONS_API_KEY",
        "models": ["openai", "openai-large", "claude", "gemini", "mistral", "deepseek", "grok"],
        "format": "openai"
    },
}

# ──────────────── LANGUAGE ────────────────

# Locales module exposes LANG; re-export here so existing imports
# (`from config import LANG`) keep working.
from locales import LANG  # noqa: E402,F401
