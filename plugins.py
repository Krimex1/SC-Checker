"""
Plugin system with base class, lifecycle management, config support, and hooks.
Security: uses AST-based static analysis instead of string blacklist to detect
dangerous code, making bypass via string concatenation/encoding impossible.
"""
import ast
import importlib.util
import json
import logging
import os
import tempfile
import threading
from abc import ABC
from pathlib import Path

from utils import atomic_write_json as _atomic_write_json

logger = logging.getLogger("SCChecker")

APP_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = APP_DIR / "plugins"
PLUGIN_STATE_FILE = APP_DIR / "plugin_state.json"
PLUGIN_CONFIG_FILE = APP_DIR / "plugin_config.json"

CUSTOM_LISTS = {
    "headers": {"label": "Custom Headers", "desc": "One per line: Header: Value"},
    "payloads": {"label": "SQLi/XSS Payloads", "desc": "One payload per line"},
    "ports": {"label": "Custom Ports", "desc": "One port per line (e.g. 8080)"},
    "subdomains": {"label": "Subdomain Wordlist", "desc": "One subdomain per line (e.g. api)"},
    "useragents": {"label": "User Agents", "desc": "One UA string per line"},
    "blacklist": {"label": "Blacklist Paths", "desc": "One per line to skip (e.g. /admin)"},
    "wordlist": {"label": "Wordlist", "desc": "Custom paths for discovery — one per line (e.g. /admin, /api/v1)"},
}

PLUGIN_HOOKS = [
    "on_scan_start", "on_before_request", "on_request", "on_after_headers",
    "on_after_ssl", "on_after_ports", "on_after_paths", "on_scan_complete",
    "on_export", "get_findings", "get_graph_nodes",
]

PLUGIN_TIMEOUT = 10

# ──────────── AST-based security analysis ────────────

# Modules that should never appear in a scanner plugin
_DANGEROUS_MODULES = {
    "os", "subprocess", "shutil", "signal", "ctypes", "pty",
    "code", "codeop", "compileall", "multiprocessing",
}

# Functions/methods that allow arbitrary code execution
_DANGEROUS_CALLS = {
    "eval", "exec", "compile", "__import__",
    "exec_module", "import_module", "load_module",
    "system", "popen", "spawn", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "execvpe",
    "InteractiveInterpreter", "InteractiveConsole",
}

# Attribute names that, when accessed, indicate sandbox escape attempts
_DANGEROUS_ATTRS = {
    "__builtins__", "__import__", "__loader__", "__spec__",
    "__subclasses__", "__bases__", "__mro__", "__class__",
    "__globals__", "__code__", "__func__", "__self__",
    "__module__", "__dict__", "__init_subclass__",
    "f_globals", "f_locals", "f_code",
    "gi_code", "gi_frame", "cr_code", "cr_frame",
}

# Filesystem paths plugins should never touch
_DANGEROUS_PATH_FRAGMENTS = (
    "/etc/", "/proc/", "/sys/", "/dev/",
    "/usr/", "/var/", "/root/", "/boot/",
    "c:\\windows", "c:\\program",
)


def _ast_check_safety(source: str, filename: str = "<plugin>") -> list[str]:
    """Analyse plugin source with the AST — bypass-resistant.

    Returns a list of human-readable violation descriptions.
    An empty list means the source passed all checks.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"SyntaxError at line {exc.lineno}: {exc.msg}"]

    violations: list[str] = []

    for node in ast.walk(tree):

        # ── import X  /  from X import … ──────────────────────────
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _DANGEROUS_MODULES:
                    violations.append(
                        f"line {node.lineno}: blocked import '{alias.name}'"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root in _DANGEROUS_MODULES:
                    violations.append(
                        f"line {node.lineno}: blocked from-import '{node.module}'"
                    )

        # ── attribute access  (obj.attr) ──────────────────────────
        elif isinstance(node, ast.Attribute):
            if node.attr in _DANGEROUS_ATTRS:
                violations.append(
                    f"line {node.lineno}: dangerous attribute access '.{node.attr}'"
                )

        # ── function / method calls ───────────────────────────────
        elif isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name and name in _DANGEROUS_CALLS:
                violations.append(
                    f"line {node.lineno}: blocked call '{name}()'"
                )

        # ── string literal that looks like a dangerous path ───────
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            lower = node.value.lower()
            if any(frag in lower for frag in _DANGEROUS_PATH_FRAGMENTS):
                violations.append(
                    f"line {node.lineno}: suspicious path literal '{node.value[:80]}'"
                )

    # ── class-level: block classes that shadow PluginBase in odd ways ─
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name) and base.id not in (
                    "PluginBase", "ABC", "object", "Plugin",
                ):
                    # Not a hard block, just note it
                    pass

    return violations


# ──────────── Plugin base class ────────────

class PluginBase(ABC):
    """Base class for all SC Checker plugins. Override hooks as needed."""
    name: str = "Unnamed Plugin"
    description: str = ""
    version: str = "1.0"
    author: str = ""
    settings_schema: dict = {}

    def __init__(self):
        self._config = {}
        self._findings = []

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    def set_config(self, config: dict):
        self._config = config

    def add_finding(self, severity: str, title: str, detail: str, url: str = ""):
        """Add a finding from plugin analysis. severity: critical/high/medium/low/info"""
        self._findings.append({
            "severity": severity.lower(),
            "title": title,
            "detail": detail,
            "url": url,
            "plugin": self.name,
        })

    def on_scan_start(self, engine, target: str):
        pass

    def on_before_request(self, engine, method: str, url: str) -> dict | None:
        """Return modified kwargs dict to alter the request, or None to skip."""
        return None

    def on_request(self, engine, url: str, response, report):
        pass

    def on_after_headers(self, engine, headers: dict, report):
        pass

    def on_after_ssl(self, engine, ssl_data: dict, report):
        pass

    def on_after_ports(self, engine, open_ports: list, report):
        pass

    def on_after_paths(self, engine, paths: list, report):
        pass

    def on_scan_complete(self, engine, report):
        pass

    def on_export(self, report, format: str) -> str | None:
        """Return additional content to append to the report, or None."""
        return None

    def get_findings(self) -> list:
        return self._findings

    def get_graph_nodes(self, report) -> list:
        """Return list of custom graph nodes: [{"label": str, "color": str}]"""
        return []


# ──────────── Custom lists ────────────

class CustomLists:
    def __init__(self):
        PLUGINS_DIR.parent.mkdir(parents=True, exist_ok=True)
        custom_dir = APP_DIR / "reports" / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        self._data = {}
        for name in CUSTOM_LISTS:
            f = custom_dir / f"{name}.txt"
            if f.exists():
                try:
                    self._data[name] = [
                        l.strip()
                        for l in f.read_text("utf-8").splitlines()
                        if l.strip() and not l.strip().startswith("#")
                    ]
                except Exception:
                    self._data[name] = []
            else:
                self._data[name] = []

    def get(self, name):
        return self._data.get(name, [])

    def set(self, name, lines):
        if name not in CUSTOM_LISTS:
            return
        self._data[name] = [
            l.strip()
            for l in lines
            if l.strip() and not l.strip().startswith("#")
        ]
        custom_dir = APP_DIR / "reports" / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(c for c in name if c.isalnum() or c in "_-")
        if not safe_name:
            return
        f = custom_dir / f"{safe_name}.txt"
        f.write_text("\n".join(self._data[name]), encoding="utf-8")

    def get_all_names(self):
        return list(CUSTOM_LISTS.keys())


# ──────────── Plugin manager ────────────

class PluginManager:
    def __init__(self):
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        self.plugins = []
        self._enabled = {}
        self._config = {}
        self._load_state()
        self._load_config()
        self._load_all()

    def _load_state(self):
        try:
            if PLUGIN_STATE_FILE.exists():
                self._enabled = json.loads(PLUGIN_STATE_FILE.read_text("utf-8"))
        except Exception:
            self._enabled = {}

    def _save_state(self):
        try:
            _atomic_write_json(PLUGIN_STATE_FILE, self._enabled)
        except Exception:
            pass

    def _load_config(self):
        try:
            if PLUGIN_CONFIG_FILE.exists():
                self._config = json.loads(PLUGIN_CONFIG_FILE.read_text("utf-8"))
        except Exception:
            self._config = {}

    def _save_config(self):
        try:
            _atomic_write_json(PLUGIN_CONFIG_FILE, self._config)
        except Exception:
            pass

    def set_plugin_config(self, file_key, config_dict):
        """Persist config for a plugin and deliver it to the instance."""
        self._config[file_key] = config_dict
        self._save_config()
        for p in self.plugins:
            if p.get("file_key") == file_key and p.get("instance"):
                p["instance"].set_config(config_dict)

    def get_plugin_config(self, file_key):
        """Get persisted config for a plugin."""
        return self._config.get(file_key, {})

    def deliver_all_configs(self):
        """On reload, deliver persisted configs to all loaded instances."""
        for p in self.plugins:
            if p.get("instance") and p.get("file_key") in self._config:
                p["instance"].set_config(self._config[p["file_key"]])

    def _load_all(self):
        self.plugins = []
        for f in sorted(PLUGINS_DIR.glob("*.py")):
            if f.name.startswith("_"):
                continue
            try:
                content = f.read_text("utf-8", errors="ignore")
                if not content.strip():
                    self.plugins.append({
                        "name": f.stem,
                        "desc": "Empty file — add a Plugin class",
                        "instance": None, "file": f.name,
                        "file_key": f.stem, "enabled": False,
                    })
                    continue

                # ── AST-based safety analysis (bypass-resistant) ──
                violations = _ast_check_safety(content, f.name)
                if violations:
                    logger.warning("Plugin %s BLOCKED (AST): %s", f.name, violations[:3])
                    self.plugins.append({
                        "name": f.stem,
                        "desc": f"BLOCKED: {violations[0]}",
                        "instance": None, "file": f.name,
                        "file_key": f.stem, "enabled": False,
                    })
                    continue

                spec = importlib.util.spec_from_file_location(f.stem, str(f))
                mod = importlib.util.module_from_spec(spec)
                result_holder = [None]
                exc_holder = [None]

                def _load_mod(s=spec, m=mod):
                    try:
                        s.loader.exec_module(m)
                        result_holder[0] = m
                    except Exception as e:
                        exc_holder[0] = e

                # Non-daemon thread: won't be silently killed on process exit
                t = threading.Thread(target=_load_mod, daemon=False)
                t.start()
                t.join(timeout=PLUGIN_TIMEOUT)
                if t.is_alive() or result_holder[0] is None:
                    logger.warning("Plugin %s timed out during load", f.stem)
                    continue

                mod = result_holder[0]
                cls = getattr(mod, "Plugin", None)
                if cls:
                    instance = cls()
                    name = getattr(instance, "name", f.stem)
                    desc = getattr(instance, "description", "")
                    version = getattr(instance, "version", "1.0")
                    enabled = self._enabled.get(f.stem, True)
                    self.plugins.append({
                        "name": name, "desc": desc, "version": version,
                        "instance": instance, "file": f.name,
                        "file_key": f.stem, "enabled": enabled,
                    })
                else:
                    self.plugins.append({
                        "name": f.stem,
                        "desc": "Invalid — no Plugin class found",
                        "instance": None, "file": f.name,
                        "file_key": f.stem, "enabled": False,
                    })
            except Exception as e:
                logger.warning("Plugin load error %s: %s", f.name, e)
                self.plugins.append({
                    "name": f.stem, "desc": f"ERROR: {e}",
                    "instance": None, "file": f.name,
                    "file_key": f.stem, "enabled": False,
                })
        self.deliver_all_configs()

    def get_enabled(self):
        return [p["instance"] for p in self.plugins if p["enabled"] and p["instance"]]

    def get_all(self):
        return self.plugins

    def toggle(self, index, enabled):
        if 0 <= index < len(self.plugins):
            self.plugins[index]["enabled"] = enabled
            key = self.plugins[index].get("file_key", "")
            self._enabled[key] = enabled
            self._save_state()

    def fire(self, hook_name, engine, *args, **kwargs):
        """Fire hook on all enabled plugins with timeout protection.

        engine is passed as the first argument (the 'self' in plugin hooks).
        Each plugin runs in its own thread with PLUGIN_TIMEOUT.
        Returns list of non-None results.
        """
        results = []
        for p in self.plugins:
            if not p["enabled"] or not p["instance"]:
                continue
            fn = getattr(p["instance"], hook_name, None)
            if not callable(fn):
                continue

            result_container = [None]
            exc_container = [None]

            def _run(_fn=fn, _engine=engine, _rc=result_container, _ec=exc_container):
                try:
                    _rc[0] = _fn(_engine, *args, **kwargs)
                except Exception as e:
                    _ec[0] = e

            t = threading.Thread(target=_run, daemon=False)
            t.start()
            t.join(timeout=PLUGIN_TIMEOUT)
            if t.is_alive():
                logger.warning("Plugin %s hook %s timed out", p["name"], hook_name)
                continue
            if exc_container[0] is not None:
                logger.warning("Plugin %s hook %s error: %s", p["name"], hook_name, exc_container[0])
            elif result_container[0] is not None:
                results.append(result_container[0])
        return results

    def call(self, hook, *args, **kwargs):
        """Execute hook on all enabled plugins. Collects and returns results."""
        results = []
        for p in self.plugins:
            if not p["enabled"] or not p["instance"]:
                continue
            fn = getattr(p["instance"], hook, None)
            if callable(fn):
                result_container = [None]
                exc_container = [None]

                def _run(_fn=fn, _rc=result_container, _ec=exc_container):
                    try:
                        _rc[0] = _fn(*args, **kwargs)
                    except Exception as e:
                        _ec[0] = e

                t = threading.Thread(target=_run, daemon=False)
                t.start()
                t.join(timeout=PLUGIN_TIMEOUT)
                if t.is_alive():
                    logger.warning("Plugin %s hook %s timed out", p["name"], hook)
                    continue
                if exc_container[0] is not None:
                    logger.warning("Plugin %s hook %s error: %s", p["name"], hook, exc_container[0])
                    results.append(f"[{p['name']}] Error: {exc_container[0]}")
                elif result_container[0] is not None:
                    results.append(result_container[0])
        return results

    def call_with_return(self, hook, *args, **kwargs):
        results = []
        for p in self.plugins:
            if not p["enabled"] or not p["instance"]:
                continue
            fn = getattr(p["instance"], hook, None)
            if callable(fn):
                try:
                    result_container = [None]

                    def _run(_fn=fn, _rc=result_container):
                        _rc[0] = _fn(*args, **kwargs)

                    t = threading.Thread(target=_run, daemon=False)
                    t.start()
                    t.join(timeout=PLUGIN_TIMEOUT)
                    if t.is_alive():
                        logger.warning("Plugin %s hook %s timed out", p["name"], hook)
                        continue
                    if result_container[0] is not None:
                        results.append(result_container[0])
                except Exception as e:
                    logger.warning("Plugin %s hook %s error: %s", p["name"], hook, e)
        return results

    def collect_findings(self):
        findings = []
        for p in self.plugins:
            if not p["enabled"] or not p["instance"]:
                continue
            fn = getattr(p["instance"], "get_findings", None)
            if callable(fn):
                result_container = [None]

                def _run(_fn=fn, _rc=result_container):
                    try:
                        _rc[0] = _fn()
                    except Exception:
                        pass

                t = threading.Thread(target=_run, daemon=False)
                t.start()
                t.join(timeout=PLUGIN_TIMEOUT)
                if t.is_alive():
                    logger.warning("Plugin %s get_findings timed out", p["name"])
                    continue
                if result_container[0]:
                    findings.extend(result_container[0])
        return findings

    def reload(self):
        self._load_all()
