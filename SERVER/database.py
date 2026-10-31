"""SQLite access. One shared connection guarded by a lock keeps things simple and
makes every request atomic, which is what the policy engine needs when it
evaluates a new account and writes its blocks in the same step."""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA_FILE = Path(__file__).with_name("database_schema.sql")


class Database:
    def __init__(self, path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))

    @contextmanager
    def transaction(self):
        """All statements inside commit together or not at all."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def execute(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def all(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def insert(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).lastrowid

    def close(self):
        with self._lock:
            self._conn.close()
