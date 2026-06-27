"""
Auto-updater for SC Checker.
Checks GitHub Releases for new versions, downloads and installs.
"""
import json
import hashlib
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CTX = ssl.create_default_context()

from config import VERSION

GITHUB_REPO = "Krimex1/SC-Checker"  # <-- change to your repo
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
CHECK_INTERVAL = 3600  # 1 hour


class Updater:
    def __init__(self):
        self._last_check = 0
        self._new_version = None
        self._download_url = None
        self._changelog = ""
        self._expected_sha256 = ""
        self._checking = False
        self._error = ""

    @property
    def update_available(self):
        return self._new_version is not None

    @property
    def latest_version(self):
        return self._new_version

    @property
    def changelog(self):
        return self._changelog

    def check_for_update(self, callback=None):
        if self._checking:
            return
        self._checking = True

        def _check():
            self._error = ""
            try:
                req = urllib.request.Request(GITHUB_API, headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": f"SC-Checker/{VERSION}",
                })
                with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
                    data = json.loads(resp.read().decode())
                tag = data.get("tag_name", "")
                tag = tag[1:] if tag.startswith("v") else tag
                if not tag:
                    self._checking = False
                    return
                if self._parse_version(tag) > self._parse_version(VERSION):
                    self._new_version = tag
                    body = data.get("body", "")
                    self._changelog = body[:500]
                    sha_match = re.search(r'SHA256:\s*([a-fA-F0-9]{64})', body)
                    self._expected_sha256 = sha_match.group(1) if sha_match else ""
                    exe_asset = None
                    for asset in data.get("assets", []):
                        name = asset.get("name", "")
                        if name == "SC-Checker.exe":
                            exe_asset = asset
                            break
                    if not exe_asset:
                        self._checking = False
                        return
                    self._download_url = exe_asset.get("browser_download_url", "")
                self._last_check = time.time()
            except Exception as e:
                self._error = str(e)
            self._checking = False
            if callback:
                callback(self.update_available, self._new_version)

        threading.Thread(target=_check, daemon=True).start()

    def download_and_install(self, progress_cb=None):
        if not self._download_url:
            return False, "No download URL"
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="sc_checker_update_"))
            exe_name = f"SC-Checker-{self._new_version}.exe"
            tmp_exe = tmp_dir / exe_name
            expected_sha = self._expected_sha256

            def _download():
                req = urllib.request.Request(self._download_url, headers={
                    "User-Agent": f"SC-Checker/{VERSION}",
                })
                with urllib.request.urlopen(req, timeout=120, context=_SSL_CTX) as resp:
                    with open(str(tmp_exe), "wb") as f:
                        while True:
                            chunk = resp.read(1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)

            if progress_cb:
                progress_cb("Downloading...", 0)
            _download()

            # Verify SHA256 — REQUIRED
            if not expected_sha:
                return False, "SHA256 not provided in release — refusing to install (security)"
            h = hashlib.sha256()
            with open(str(tmp_exe), "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            actual_sha = h.hexdigest()
            if actual_sha.lower() != expected_sha.lower():
                tmp_exe.unlink(missing_ok=True)
                return False, f"SHA256 mismatch: expected {expected_sha[:16]}..., got {actual_sha[:16]}..."

            if progress_cb:
                progress_cb("Downloaded", 50)

            current_exe = Path(sys.executable) if getattr(sys, 'frozen', False) else None
            if current_exe and current_exe.suffix == ".exe":
                tmp_exe_escaped = str(tmp_exe).replace('"', '""')
                current_exe_escaped = str(current_exe).replace('"', '""')
                backup_exe = tmp_dir / "SC-Checker-backup.exe"
                backup_escaped = str(backup_exe).replace('"', '""')
                # Safer batch script: backs up old exe before replacing,
                # verifies copy success, and restores from backup on failure.
                bat_content = f"""@echo off
setlocal
timeout /t 3 /nobreak >nul
taskkill /pid {os.getpid()} >nul 2>&1
timeout /t 2 /nobreak >nul

:: Backup current exe before overwriting
if exist "{current_exe_escaped}" (
    copy /y "{current_exe_escaped}" "{backup_escaped}" >nul 2>&1
)

:: Attempt to copy new exe (with retry)
copy /y "{tmp_exe_escaped}" "{current_exe_escaped}" >nul 2>&1
if errorlevel 1 (
    timeout /t 3 /nobreak >nul
    copy /y "{tmp_exe_escaped}" "{current_exe_escaped}" >nul 2>&1
    if errorlevel 1 (
        :: Copy failed — restore from backup
        if exist "{backup_escaped}" (
            copy /y "{backup_escaped}" "{current_exe_escaped}" >nul 2>&1
        )
        exit /b 1
    )
)

:: Success — start new exe and clean up
start "" "{current_exe_escaped}"
del /f "{tmp_exe_escaped}" >nul 2>&1
del /f "{backup_escaped}" >nul 2>&1
rmdir /s /q "{tmp_dir}" >nul 2>&1
endlocal
"""
                bat_path = tmp_dir / "update.bat"
                bat_path.write_text(bat_content, encoding="utf-8")
                if progress_cb:
                    progress_cb("Installing...", 90)
                subprocess.Popen(
                    ["cmd", "/c", str(bat_path)],
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                sys.exit(0)
            else:
                if progress_cb:
                    progress_cb("Done", 100)
                return True, str(tmp_exe)
        except Exception as e:
            return False, str(e)[:200]

    @staticmethod
    def _parse_version(v):
        parts = []
        for p in v.split("."):
            p = re.split(r'[-+]', p)[0]
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])


_updater = Updater()

def get_updater():
    return _updater
