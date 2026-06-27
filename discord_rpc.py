# -*- coding: utf-8 -*-
"""Discord Rich Presence integration for SC Checker."""

import json
import time
import queue
import threading
import logging
import warnings

# Suppress the "coroutine was never awaited" RuntimeWarning emitted by
# pypresence's internal read_output() on disconnect/close.  This is a known
# library bug in its sync wrapper and is harmless.
warnings.filterwarnings("ignore", message=".*coroutine.*was never awaited.*")

logger = logging.getLogger("SCChecker.DiscordRPC")
# Surface RPC diagnostics even though the root logger defaults to WARNING.
# Without this the per-update errors (_safe_update / worker) are hidden as
# DEBUG and we cannot tell why a presence silently stops updating.
if not logger.level:
    logger.setLevel(logging.DEBUG)

try:
    from pypresence import Presence
    HAS_PYPRESENCE = True
except ImportError:
    HAS_PYPRESENCE = False


DEFAULT_SETTINGS = {
    "enabled": False,
    "client_id": "123456789012345678",   # User must set their own Discord App ID
    "app_name": "SC Checker",            # Custom name shown as activity title
    "details_idle": "Idle - Ready to scan",
    "details_scanning": "Scanning {target}...",
    "details_done": "Reviewing results for {target}",
    "state_idle": "SC Checker v{version}",
    "state_scanning": "{phase} ({progress}%)",
    "state_done": "Risk: {risk_level} ({risk_score}/100)",
    "large_image_key": "logo",
    "large_image_text": "SC Checker - Web Security Scanner",
    "small_image_key": "",
    "small_image_text": "",
    "elapsed_mode": "since_launch",       # since_launch | frozen_time | countdown | custom_time | hidden
    "frozen_time": "11:11:11",            # HH:MM:SS shown as always-frozen elapsed timer
    "custom_elapsed": "",                 # HH:MM:SS or YYYY-MM-DD HH:MM:SS or epoch int
    "button_label": "",
    "button_url": "",
    "button2_label": "",                  # Second button (Discord allows up to 2)
    "button2_url": "",
}

# Discord Rich Presence button constraints (enforced by Discord itself)
BUTTON_LABEL_MAX = 32      # max characters for the button label
BUTTON_URL_MAX = 512       # max characters for the button URL
BUTTON_MAX_COUNT = 2       # Discord allows at most 2 buttons per activity

# Discord renders elapsed time as (now - start) and updates it client-side
# every second, so a "frozen" time only stays frozen while we keep re-sending
# the presence with start = now - frozen_seconds. This interval bounds how
# often we re-send. Discord rate-limits SET_ACTIVITY to ~1 per 15 seconds,
# so 20s keeps us safely under the limit while maintaining a stable display.
FROZEN_REFRESH_SECONDS = 20


def _normalize_button_url(url):
    """Ensure a button URL has an http:// or https:// scheme.

    Discord strictly requires an absolute URL with an http/https scheme.
    A bare value like "example.com" or "discord.com/invite/abc" is silently
    rejected by Discord and the button simply does not appear, so we
    auto-prefix https:// to make user input work out of the box.

    If the URL already has a non-http scheme (e.g. ftp://, file://), that
    scheme is stripped and replaced with https://. This matches what users
    typically expect when they paste a URL with the wrong protocol.

    Returns None if the URL is empty or cannot be made valid.
    """
    if not url:
        return None
    val = str(url).strip()
    if not val:
        return None

    low = val.lower()
    if low.startswith("https://") or low.startswith("http://"):
        # Already valid scheme — keep as-is
        pass
    elif "://" in low:
        # Has some OTHER scheme (ftp://, file://, etc.) — strip and re-prefix https
        val = "https://" + val.split("://", 1)[1]
    else:
        # No scheme at all — add https://
        val = "https://" + val

    # Final sanity check: a valid URL must contain a dot in the host part
    rest = val.split("://", 1)[1] if "://" in val.lower() else val
    if "." not in rest:
        return None
    return val[:BUTTON_URL_MAX]


def _settings_path():
    from config import APP_DIR
    return APP_DIR / "discord_settings.json"


def _profiles_path():
    from config import APP_DIR
    return APP_DIR / "discord_profiles.json"


def load_settings():
    """Load Discord RPC settings from file."""
    settings = dict(DEFAULT_SETTINGS)
    path = _settings_path()
    if path.exists():
        try:
            data = json.loads(path.read_text("utf-8"))
            settings.update(data)
        except json.JSONDecodeError as e:
            # OneDrive sync can append duplicate JSON objects to the file.
            # Fall back to parsing just the first valid object.
            try:
                decoder = json.JSONDecoder()
                data, _ = decoder.raw_decode(path.read_text("utf-8"))
                settings.update(data)
                logger.info("Discord settings: recovered first JSON object from corrupted file")
            except Exception:
                logger.warning(f"Failed to load Discord settings: {e}")
        except Exception as e:
            logger.warning(f"Failed to load Discord settings: {e}")
    return settings


def save_settings(settings):
    """Save Discord RPC settings to file (atomic write)."""
    path = _settings_path()
    try:
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
        if path.exists():
            path.unlink()
        tmp.rename(path)
    except Exception as e:
        logger.error(f"Failed to save Discord settings: {e}")


def load_profiles():
    """Load all Discord RPC profiles from file.
    
    Returns dict: {"active_profile": "profile_name", "profiles": {"name": {...}, ...}}
    """
    path = _profiles_path()
    if path.exists():
        try:
            data = json.loads(path.read_text("utf-8"))
            if isinstance(data, dict) and "profiles" in data:
                return data
        except Exception as e:
            logger.warning(f"Failed to load Discord profiles: {e}")
    return {"active_profile": None, "profiles": {}}


def save_profiles(profiles_data):
    """Save Discord RPC profiles to file (atomic write)."""
    path = _profiles_path()
    try:
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(profiles_data, indent=2, ensure_ascii=False), encoding="utf-8")
        if path.exists():
            path.unlink()
        tmp.rename(path)
    except Exception as e:
        logger.error(f"Failed to save Discord profiles: {e}")


def save_profile(name, settings):
    """Save a single profile by name."""
    data = load_profiles()
    data["profiles"][name] = settings
    if data["active_profile"] is None:
        data["active_profile"] = name
    save_profiles(data)


def load_profile(name):
    """Load a single profile by name. Returns None if not found."""
    data = load_profiles()
    return data["profiles"].get(name)


def delete_profile(name):
    """Delete a profile by name. Returns True if deleted."""
    data = load_profiles()
    if name in data["profiles"]:
        del data["profiles"][name]
        if data["active_profile"] == name:
            data["active_profile"] = None
        save_profiles(data)
        return True
    return False


def switch_profile(name):
    """Switch to a profile and save its settings as active."""
    data = load_profiles()
    if name in data["profiles"]:
        data["active_profile"] = name
        save_profiles(data)
        # Load profile settings into active settings file
        save_settings(data["profiles"][name])
        return True
    return False


def get_active_profile_name():
    """Get the name of the currently active profile."""
    data = load_profiles()
    return data.get("active_profile")


class DiscordRPC:
    """Manages Discord Rich Presence lifecycle.

    Simple approach: call pypresence's sync API directly.
    pypresence manages its own event loop internally via
    loop.run_until_complete() for each operation.
    """

    def __init__(self):
        self.settings = load_settings()
        self._rpc = None
        self._connected = False
        self._start_time = int(time.time())

        # All pypresence calls (Presence.update / connect / close) drive a
        # single asyncio event loop owned by the thread that created the
        # Presence object. Calling them from any other thread raises
        # RuntimeError and silently kills the connection — which is exactly
        # why "Scan Complete" presence never showed up (progress callbacks
        # ran on the scanner worker thread).
        #
        # To stay thread-safe we funnel every request through a dedicated
        # worker thread + queue. Public methods (update_idle/scanning/done,
        # connect/disconnect) only enqueue work and return immediately.
        self._queue = queue.Queue()
        self._pending = None          # latest presence payload (kept across reconnects)

        # Connect listeners. The worker fires every callback here once a
        # connect attempt resolves (success or failure). The GUI uses this
        # to know when the async connect actually finished, instead of
        # polling is_connected() too early and always seeing "Disconnected".
        self._connect_listeners = []
        self._connect_lock = threading.Lock()

        self._worker = threading.Thread(target=self._run, name="DiscordRPCWorker", daemon=True)
        self._worker_started = False

        # Frozen-time keep-alive. When elapsed_mode == "frozen_time" the
        # elapsed counter in Discord would otherwise tick up between rare
        # presence updates (idle→scanning→done). A daemon timer re-sends
        # self._pending every FROZEN_REFRESH seconds so the displayed time
        # stays pinned to the configured value. See _start_frozen_refresh.
        self._frozen_timer = None

    def _ensure_worker(self):
        """Start the worker thread on first use (idempotent)."""
        if not self._worker_started:
            self._worker.start()
            self._worker_started = True

    def _run(self):
        """Worker loop — single owner of the pypresence event loop."""
        while True:
            try:
                item = self._queue.get()
            except Exception:
                continue
            try:
                if item is None:
                    # Sentinel: stop requested
                    self._do_close()
                    self._queue.task_done()
                    break

                kind, payload = item
                if kind == "connect":
                    self._do_connect()
                elif kind == "disconnect":
                    self._do_close()
                elif kind == "presence":
                    self._safe_update(payload)
            except Exception as e:
                logger.debug(f"Discord RPC worker error: {e}")
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    # ─── Connection (enqueued, run on worker thread) ───

    def connect(self):
        """Connect to Discord RPC (async via worker thread). Returns True if
        the request could be enqueued / is already connected."""
        if not HAS_PYPRESENCE:
            logger.info("pypresence not installed — Discord RPC disabled")
            return False
        if not self.settings.get("enabled"):
            return False
        client_id = self.settings.get("client_id", "")
        if not client_id or client_id == DEFAULT_SETTINGS["client_id"]:
            logger.info("Discord RPC: no valid client_id configured")
            return False
        self._ensure_worker()
        self._queue.put(("connect", None))
        return True

    def disconnect(self):
        """Disconnect from Discord RPC (async via worker thread)."""
        if not self._worker_started:
            return
        self._queue.put(("disconnect", None))

    def force_reconnect(self):
        """Guarantee a real disconnect→connect cycle on the worker thread.

        Unlike connect(), this ALWAYS tears down the existing connection
        first (even if _connected is True), so it is the right call for the
        GUI's Reconnect button. Returns False if RPC can't run at all
        (no pypresence / disabled / bad client_id).
        """
        if not HAS_PYPRESENCE:
            logger.info("pypresence not installed — Discord RPC disabled")
            return False
        if not self.settings.get("enabled"):
            return False
        client_id = self.settings.get("client_id", "")
        if not client_id or client_id == DEFAULT_SETTINGS["client_id"]:
            logger.info("Discord RPC: no valid client_id configured")
            return False
        self._ensure_worker()
        # disconnect first, then connect — processed in order on the worker.
        self._queue.put(("disconnect", None))
        self._queue.put(("connect", None))
        return True

    def _do_connect(self):
        """Actual pypresence connect — worker thread only."""
        client_id = self.settings.get("client_id", "")
        if self._connected:
            # Already connected — just re-send the latest idle presence so
            # any settings changes (details, state, images, elapsed mode)
            # are applied immediately without a full reconnect cycle.
            idle = self._build_idle_payload()
            self._pending = idle
            self._safe_update(idle)
            self._stop_frozen_refresh()
            self._start_frozen_refresh()
            self._notify_connect_listeners(True)
            return
        try:
            rpc = Presence(client_id)
            rpc.connect()
            self._rpc = rpc
            self._connected = True
            self._start_time = int(time.time())
            logger.info("Discord RPC connected")
            # Re-apply the last known presence (or idle) right after connect.
            payload = self._pending if self._pending is not None else self._build_idle_payload()
            self._safe_update(payload)
            self._start_frozen_refresh()
        except Exception as e:
            err_msg = str(e) if e else type(e).__name__
            logger.warning(f"Discord RPC connect failed: {err_msg}")
            self._rpc = None
            self._connected = False
        finally:
            # Always tell listeners the attempt resolved, regardless of result.
            self._notify_connect_listeners(self._connected)

    def _do_close(self):
        """Actual pypresence close — worker thread only."""
        self._stop_frozen_refresh()
        if self._rpc:
            try:
                self._rpc.close()
            except Exception:
                pass
        self._rpc = None
        self._connected = False
        logger.info("Discord RPC disconnected")

    def is_connected(self):
        # _connected is written by the worker thread and read here from the
        # GUI thread. Python's GIL makes a plain bool read/write atomic, so
        # this is safe as a best-effort status flag for the UI.
        return self._connected

    # ─── Connect listeners (for reliable Reconnect feedback) ───

    def add_connect_listener(self, cb):
        """Register a one-shot callback fired when the next connect attempt
        resolves on the worker thread. cb receives a single bool: connected?

        Used by the GUI's Reconnect button so the status label reflects the
        real outcome instead of racing the async connect.
        """
        with self._connect_lock:
            self._connect_listeners.append(cb)

    def _notify_connect_listeners(self, connected):
        """Fire + clear all pending connect listeners (worker thread)."""
        with self._connect_lock:
            listeners = self._connect_listeners
            self._connect_listeners = []
        for cb in listeners:
            try:
                cb(bool(connected))
            except Exception as e:
                logger.debug(f"connect listener error: {e}")

    # ─── Presence Updates ───

    def _get_elapsed_start(self):
        """Get the start timestamp for elapsed time based on settings.

        Modes:
          - since_launch: timestamp of when app connected to Discord
          - frozen_time: always show a fixed time (e.g. 11:11:11)
          - custom_time: user-specified start time (HH:MM:SS / datetime / epoch)
          - hidden: no timer at all

        Discord requires ``start >= 1``; any smaller value (0 or negative)
        is rejected with a server error.  We clamp to 1 as a safety net.
        """
        mode = self.settings.get("elapsed_mode", "since_launch")
        if mode == "hidden":
            return None

        if mode == "frozen_time":
            start = self._parse_frozen_time(self.settings.get("frozen_time", "11:11:11"))
        elif mode == "custom_time":
            start = self._parse_custom_time(self.settings.get("custom_elapsed", ""))
        else:
            start = self._start_time

        return max(1, start) if start is not None else None

    def _parse_frozen_time(self, time_str):
        """Parse HH:MM:SS and return a fake start timestamp so elapsed = that fixed time.

        Discord shows elapsed as (now - start_timestamp).
        To show a frozen "HH:MM:SS", we set start = now - seconds(HH:MM:SS).
        This way the elapsed counter always shows the frozen time
        (it will tick up in real-time, but re-send on each update keeps it ~frozen).
        """
        try:
            parts = str(time_str).split(":")
            h, m, s = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0, int(parts[2]) if len(parts) > 2 else 0
            total_seconds = h * 3600 + m * 60 + s
            return int(time.time()) - total_seconds
        except (ValueError, TypeError, IndexError):
            return self._start_time

    def _parse_frozen_seconds(self):
        """Parse frozen_time (HH:MM:SS) and return total seconds.

        Used by both frozen_time mode (for start timestamp) and countdown
        mode (for end timestamp). Same field, different direction.
        """
        try:
            parts = str(self.settings.get("frozen_time", "11:11:11")).split(":")
            h = int(parts[0])
            m = int(parts[1]) if len(parts) > 1 else 0
            s = int(parts[2]) if len(parts) > 2 else 0
            return max(1, h * 3600 + m * 60 + s)
        except (ValueError, TypeError, IndexError):
            return 39671  # 11:11:11 default

    def _parse_custom_time(self, value):
        """Parse custom start time in multiple formats:
        - HH:MM:SS → today at that time
        - YYYY-MM-DD HH:MM:SS → specific datetime
        - integer → epoch timestamp
        """
        if not value:
            return self._start_time
        val = str(value).strip()

        # Try as epoch integer
        try:
            ts = int(val)
            if ts > 1000000000:  # reasonable epoch (> year 2001)
                return ts
            # Small number might be seconds, treat as invalid
        except (ValueError, TypeError):
            pass

        # Try YYYY-MM-DD HH:MM:SS
        try:
            from datetime import datetime
            dt = datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
            return int(dt.timestamp())
        except (ValueError, TypeError):
            pass

        # Try HH:MM:SS → today at that time
        try:
            parts = val.split(":")
            if len(parts) >= 2:
                from datetime import datetime
                now = datetime.now()
                h = int(parts[0])
                m = int(parts[1])
                s = int(parts[2]) if len(parts) > 2 else 0
                dt = now.replace(hour=h, minute=m, second=s, microsecond=0)
                return int(dt.timestamp())
        except (ValueError, TypeError):
            pass

        logger.warning(f"Could not parse custom elapsed time: {val}")
        return self._start_time

    def _get_name(self):
        """Get the custom activity name."""
        name = self.settings.get("app_name", "")
        return name if name else None

    def update_idle(self):
        """Set idle presence (app open, no scan). Thread-safe: enqueues work."""
        self._enqueue(self._build_idle_payload())

    def _build_idle_payload(self):
        """Build the idle presence payload (worker-facing helper)."""
        payload = {
            "name": self._get_name(),
            "details": self._fmt(self.settings.get("details_idle", "Idle")),
            "state": self._fmt(self.settings.get("state_idle", "SC Checker")),
            "large_image": self.settings.get("large_image_key", "logo") or None,
            "large_text": self.settings.get("large_image_text", "") or None,
            "small_image": self.settings.get("small_image_key", "") or None,
            "small_text": self.settings.get("small_image_text", "") or None,
        }
        # Countdown mode: send `end` (counts down from frozen_time)
        if self.settings.get("elapsed_mode") == "countdown":
            payload["end"] = self._get_countdown_end()
        else:
            payload["start"] = self._get_elapsed_start()
        return payload

    def update_scanning(self, target="", phase="", progress=0,
                        party_size=None, party_max=None):
        """Set scanning presence. Thread-safe: enqueues work.

        party_size / party_max: when both given (e.g. 3, 10 during a batch
        scan) Discord shows a "3 of 10" party indicator. Pass None for a
        single-target scan (no party shown).
        """
        ctx = {
            "target": target or "target",
            "phase": phase or "scanning",
            "progress": progress,
        }
        payload = {
            "name": self._get_name(),
            "details": self._fmt(self.settings.get("details_scanning", ""), ctx),
            "state": self._fmt(self.settings.get("state_scanning", ""), ctx),
            "large_image": self.settings.get("large_image_key", "logo") or None,
            "large_text": self.settings.get("large_image_text", "") or None,
            "small_image": self.settings.get("small_image_key", "") or None,
            "small_text": self.settings.get("small_image_text", "") or None,
            "is_scanning": True,
        }
        # Countdown vs elapsed are mutually exclusive in Discord (end wins).
        if self.settings.get("elapsed_mode") == "countdown":
            payload["end"] = self._get_countdown_end()
        else:
            payload["start"] = self._get_elapsed_start()
        if party_size is not None and party_max:
            payload["party_size"] = party_size
            payload["party_max"] = party_max
        self._enqueue(payload)

    def _get_countdown_end(self):
        """Epoch timestamp at which the countdown reaches zero.

        Computed fresh on each send as now + frozen_seconds so the timer
        always starts at the full duration and ticks down.
        """
        return int(time.time()) + self._parse_frozen_seconds()

    def update_done(self, target="", risk_level="", risk_score=0):
        """Set scan-complete presence. Thread-safe: enqueues work."""
        ctx = {
            "target": target or "target",
            "risk_level": (risk_level or "unknown").upper(),
            "risk_score": risk_score if risk_score is not None else 0,
        }
        payload = {
            "name": self._get_name(),
            "details": self._fmt(self.settings.get("details_done", ""), ctx),
            "state": self._fmt(self.settings.get("state_done", ""), ctx),
            "large_image": self.settings.get("large_image_key", "logo") or None,
            "large_text": self.settings.get("large_image_text", "") or None,
            "small_image": self.settings.get("small_image_key", "") or None,
            "small_text": self.settings.get("small_image_text", "") or None,
        }
        if self.settings.get("elapsed_mode") == "countdown":
            payload["end"] = self._get_countdown_end()
        else:
            payload["start"] = self._get_elapsed_start()
        self._enqueue(payload)

    # ─── Internal ───

    def _enqueue(self, payload):
        """Stash the latest payload and hand it to the worker.

        Coalescing: only the most recent presence matters, so we drop stale
        queued items before pushing the new one. This also bounds the queue
        size during fast progress callbacks.
        """
        self._pending = payload
        self._ensure_worker()
        # Drain any not-yet-processed items so the worker always picks the
        # freshest state. Presence items can be safely superseded.
        drained = 0
        while True:
            try:
                item = self._queue.get_nowait()
                self._queue.task_done()
                if item is None or (isinstance(item, tuple) and item[0] != "presence"):
                    # Keep control items (connect/disconnect/stop); re-enqueue.
                    self._queue.put(item)
                else:
                    drained += 1
            except queue.Empty:
                break
        self._queue.put(("presence", payload))

    def _build_activity(self, kwargs):
        """Build the activity dict from kwargs — worker only."""
        activity = {}
        if kwargs.get("name"):
            activity["name"] = str(kwargs["name"])[:128]
        if kwargs.get("details"):
            activity["details"] = str(kwargs["details"])[:128]
        if kwargs.get("state"):
            activity["state"] = str(kwargs["state"])[:128]
        if kwargs.get("large_image"):
            activity["large_image"] = str(kwargs["large_image"])[:256]
        if kwargs.get("large_text"):
            activity["large_text"] = str(kwargs["large_text"])[:128]
        if kwargs.get("small_image"):
            activity["small_image"] = str(kwargs["small_image"])[:256]
        if kwargs.get("small_text"):
            activity["small_text"] = str(kwargs["small_text"])[:128]
        # Timer: prefer `end` (countdown) when present, otherwise `start`
        # (elapsed). Discord treats end as authoritative — sending both
        # would hide elapsed behind the countdown, so we pick one.
        if kwargs.get("end") is not None:
            try:
                activity["end"] = max(1, int(kwargs["end"]))
            except (TypeError, ValueError):
                pass
        elif kwargs.get("start") is not None:
            try:
                activity["start"] = max(1, int(kwargs["start"]))
            except (TypeError, ValueError):
                pass

        # Party info: "3 of 10" indicator. Shown during batch scans when
        # party_size/party_max are provided. A stable party_id keeps the
        # same party slot across updates.
        if kwargs.get("party_size") is not None and kwargs.get("party_max"):
            try:
                cur = int(kwargs["party_size"])
                mx = int(kwargs["party_max"])
                if 0 < mx and 0 < cur <= mx:
                    activity["party_size"] = [cur, mx]
                    activity["party_id"] = "sc-checker-batch"
            except (TypeError, ValueError):
                pass

        # Buttons: Discord allows up to 2. Build the list from button1 +
        # button2 settings, validating each URL.
        buttons = []
        for key_lbl, key_url in (("button_label", "button_url"),
                                 ("button2_label", "button2_url")):
            lbl = self.settings.get(key_lbl, "").strip()
            raw = self.settings.get(key_url, "").strip()
            if not lbl:
                continue
            url = _normalize_button_url(raw)
            if url:
                buttons.append({"label": lbl[:BUTTON_LABEL_MAX], "url": url})
                if raw != url:
                    logger.info(f"Discord RPC {key_lbl} URL normalized: '{raw}' -> '{url}'")
            elif raw:
                logger.warning(
                    f"Discord RPC {key_lbl} skipped — invalid URL '{raw}'. "
                    f"Discord requires a full http(s):// URL."
                )
        if buttons:
            activity["buttons"] = buttons[:BUTTON_MAX_COUNT]

        return activity

    def _do_update_with_fallback(self, kwargs):
        """Try updating with custom name, retry without it if Discord rejects."""
        if not self._rpc or not self._connected:
            return
        try:
            activity = self._build_activity(kwargs)
            self._rpc.update(**activity)
        except Exception as e:
            err = str(e).lower()
            # Discord rejected the custom name — retry without it
            if "name" in err and kwargs.get("name"):
                logger.warning(f"Discord rejected activity name '{kwargs['name']}', retrying without it")
                try:
                    retry_kw = {k: v for k, v in kwargs.items() if k != "name"}
                    retry_activity = self._build_activity(retry_kw)
                    self._rpc.update(**retry_activity)
                except Exception as e2:
                    logger.warning(f"Discord RPC update failed (retry): {e2}")
            else:
                logger.warning(f"Discord RPC update failed: {e}")

    def _safe_update(self, kwargs):
        """Top-level update dispatcher — worker thread only."""
        self._do_update_with_fallback(kwargs)

    # ─── Frozen-time keep-alive ───

    def _is_frozen_mode(self):
        """True when the periodic refresh timer should run.

        Runs for two reasons:
        - elapsed_mode == frozen_time: re-send so Discord's elapsed counter
          stays pinned to the configured frozen value.
        - elapsed_mode == countdown: re-send so the countdown timer keeps
          ticking between scan progress callbacks.
        """
        mode = self.settings.get("elapsed_mode", "since_launch")
        if mode in ("frozen_time", "countdown"):
            return True
        return False

    def _start_frozen_refresh(self):
        """Start the periodic re-send that keeps a frozen elapsed time pinned.

        Discord computes elapsed = (now - start) on its own client and ticks
        it every second. There is no "pause" API, so the only way to show a
        constant value is to re-send the presence with start recomputed as
        now - frozen_seconds on a regular cadence. We run this from the
        worker thread (which owns the pypresence loop) via a daemon Timer
        that re-arms itself until stopped.
        """
        self._stop_frozen_refresh()
        if not self._is_frozen_mode():
            return

        def _tick():
            # Cancelled between scheduling and firing — bail out cleanly.
            if self._frozen_timer is None:
                return
            if self._connected and self._rpc:
                self._refresh_frozen()
                # Re-arm for the next tick.
                self._frozen_timer = threading.Timer(FROZEN_REFRESH_SECONDS, _tick)
                self._frozen_timer.daemon = True
                self._frozen_timer.start()

        self._frozen_timer = threading.Timer(FROZEN_REFRESH_SECONDS, _tick)
        self._frozen_timer.daemon = True
        self._frozen_timer.start()

    def _stop_frozen_refresh(self):
        """Cancel any running frozen-time refresh timer."""
        t = self._frozen_timer
        self._frozen_timer = None
        if t is not None:
            try:
                t.cancel()
            except Exception:
                pass

    def _refresh_frozen(self):
        """Recompute the timer timestamp on the latest payload and re-send it.

        - For frozen-time: re-pin start so elapsed stays fixed.
        - For countdown: recompute end so the countdown keeps ticking.

        IMPORTANT: This runs on the Timer thread, NOT the worker thread.
        We must enqueue the update so pypresence is only ever called from
        the single worker thread that owns its event loop.
        """
        payload = self._pending if self._pending is not None else self._build_idle_payload()
        if self.settings.get("elapsed_mode") == "countdown":
            payload["end"] = self._get_countdown_end()
            payload.pop("start", None)
        else:
            payload["start"] = self._get_elapsed_start()
        # Keep _pending in sync for subsequent reconnects / refreshes.
        self._pending = payload
        # Route through the queue so the worker thread makes the actual
        # pypresence API call (single owner of the event loop).
        self._queue.put(("presence", payload))

    def _fmt(self, template, extra_ctx=None):
        """Format a template string with built-in + extra variables."""
        from config import VERSION
        ctx = {"version": VERSION}
        if extra_ctx:
            ctx.update(extra_ctx)
        try:
            return template.format(**ctx)
        except (KeyError, IndexError, ValueError):
            return template

    def reload_settings(self):
        """Reload settings from disk and reconnect if needed.

        The stale self._pending payload is invalidated so that the next
        _do_connect picks up freshly-built presence using the new settings.
        """
        self.settings = load_settings()
        # Invalidate cached payload so _do_connect rebuilds idle presence
        # with the updated settings (details, state, images, elapsed, etc.).
        self._pending = None
        # Stop any running frozen-time refresh (will restart on connect
        # if the new mode is still frozen_time).
        self._stop_frozen_refresh()
        # Disconnect first (if any), then reconnect if enabled — both run on
        # the worker thread in order, so there's no race with in-flight updates.
        if self.settings.get("enabled"):
            self._ensure_worker()
            self._queue.put(("disconnect", None))
            self._queue.put(("connect", None))
        else:
            self.disconnect()
