import sqlite3
import time
import threading
from collections import OrderedDict
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent / "reports" / "cache"

# Default TTL for ScanCache entries (seconds) — 1 day
SCAN_CACHE_TTL = 86400

# Global singleton: one connection + one lock for all ScanCache instances.
_db_lock = threading.Lock()
_db_conn = None


def _get_conn():
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _db_conn = sqlite3.connect(
        str(CACHE_DIR / "cache.db"), check_same_thread=False, timeout=10
    )
    _db_conn.execute("PRAGMA journal_mode=WAL")
    _db_conn.execute("PRAGMA synchronous=NORMAL")
    _db_conn.execute("PRAGMA cache_size=-8000")
    _db_conn.execute("PRAGMA temp_store=MEMORY")
    _db_conn.execute("CREATE TABLE IF NOT EXISTS dns (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    _db_conn.execute("CREATE TABLE IF NOT EXISTS tcp (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    return _db_conn


# ──── Per-key locking for ScanCache ────
_key_locks = {}
_key_locks_lock = threading.Lock()


def _get_key_lock(key):
    """Return a per-key lock. Multiple keys can be locked independently."""
    with _key_locks_lock:
        if key not in _key_locks:
            _key_locks[key] = threading.Lock()
        return _key_locks[key]


class ScanCache:
    def __init__(self):
        pass  # All state is in the module-global singleton.

    def _evict_if_needed(self, conn, table):
        """Periodically evict old entries and checkpoint WAL."""
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if count > 5000:
            conn.execute(
                f"DELETE FROM {table} WHERE key IN "
                f"(SELECT key FROM {table} ORDER BY ts ASC LIMIT 2500)"
            )

    def get_dns(self, host):
        klock = _get_key_lock(host)
        with klock:
            with _db_lock:
                row = _get_conn().execute(
                    "SELECT value, ts FROM dns WHERE key=?", (host,)
                ).fetchone()
            if row and (time.time() - row[1]) < SCAN_CACHE_TTL:
                return row[0]
            return None

    def set_dns(self, host, ip):
        klock = _get_key_lock(host)
        with klock:
            with _db_lock:
                conn = _get_conn()
                conn.execute(
                    "REPLACE INTO dns (key, value, ts) VALUES (?, ?, ?)",
                    (host, ip, time.time()),
                )
                self._evict_if_needed(conn, "dns")

    def get_tcp(self, key):
        klock = _get_key_lock(key)
        with klock:
            with _db_lock:
                row = _get_conn().execute(
                    "SELECT value, ts FROM tcp WHERE key=?", (key,)
                ).fetchone()
            if row and (time.time() - row[1]) < SCAN_CACHE_TTL:
                return row[0]
            return None

    def set_tcp(self, key, result):
        klock = _get_key_lock(key)
        with klock:
            with _db_lock:
                conn = _get_conn()
                conn.execute(
                    "REPLACE INTO tcp (key, value, ts) VALUES (?, ?, ?)",
                    (key, result, time.time()),
                )
                self._evict_if_needed(conn, "tcp")

    def checkpoint_wal(self):
        """Passive WAL checkpoint — call periodically to prevent WAL bloat."""
        with _db_lock:
            try:
                _get_conn().execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass

    def close(self):
        pass  # Global connection lives for the process lifetime.


class SessionCache:
    """In-memory LRU with TTL — session-scoped dedup on top of SQLite.

    Thread-safe: get/set use the main lock for fast path (cache hit).
    get_or_set() uses per-key Events to prevent thundering herd WITHOUT
    blocking all cache access during factory() execution.
    """

    def __init__(self, ttl=300, max_size=4096):
        self._store = OrderedDict()  # key -> (value, ts); oldest-first order
        self._lock = threading.Lock()
        self._ttl = ttl
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
        self._inflight = {}  # key -> threading.Event (factory in progress)
        self._evictions = 0

    def get(self, key):
        with self._lock:
            entry = self._store.get(key)
            if entry and time.time() - entry[1] < self._ttl:
                self._store.move_to_end(key)  # mark as recently used
                self._hits += 1
                return entry[0]
            if entry:
                del self._store[key]
            self._misses += 1
            return None

    def set(self, key, value):
        with self._lock:
            self._put(key, value)

    def _put(self, key, value):
        """Insert into store. Caller must hold self._lock."""
        if key in self._store:
            del self._store[key]
        elif len(self._store) >= self._max_size:
            self._store.popitem(last=False)  # evict oldest (LRU)
            self._evictions += 1
        self._store[key] = (value, time.time())

    def get_or_set(self, key, factory):
        """Get cached value or compute it.

        Uses per-key threading.Event to prevent thundering herd:
        - First thread computes; others wait on the Event (without holding the lock).
        - After computation, all waiters re-check cache and get the result.
        """
        # Fast path: check cache
        with self._lock:
            entry = self._store.get(key)
            if entry and time.time() - entry[1] < self._ttl:
                self._store.move_to_end(key)
                self._hits += 1
                return entry[0]
            if entry:
                del self._store[key]
            # Check if another thread is already computing this key
            if key in self._inflight:
                event = self._inflight[key]
                self._lock.release()
                event.wait()  # Wait without holding the main lock
                self._lock.acquire()
                # Re-check cache after waiting
                entry = self._store.get(key)
                if entry and time.time() - entry[1] < self._ttl:
                    self._store.move_to_end(key)
                    self._hits += 1
                    return entry[0]
                # If still not found (factory failed), fall through to compute
            else:
                event = threading.Event()
                self._inflight[key] = event

        # Compute outside the main lock
        self._misses += 1
        try:
            v = factory()
        except Exception:
            # Signal waiters so they don't hang forever
            with self._lock:
                if key in self._inflight:
                    self._inflight[key].set()
                    del self._inflight[key]
            raise

        # Store result and signal waiters
        with self._lock:
            self._put(key, v)
            if key in self._inflight:
                self._inflight[key].set()
                del self._inflight[key]
        return v

    @property
    def stats(self):
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "size": len(self._store),
                "ratio": self._hits / total if total else 0,
            }

    def clear(self):
        with self._lock:
            self._store.clear()
            self._inflight.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
