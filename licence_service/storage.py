"""Durable licence storage on SQLite (one file). Every check-and-bind runs in one IMMEDIATE transaction,
so two simultaneous activations can never exceed the account or device limit."""
import sqlite3, threading, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS licences (
  serial TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('OK','REVOKED','SUSPENDED')),
  expiry TEXT NOT NULL,                 -- 'LIFETIME' or YYYYMMDD
  features TEXT NOT NULL,
  max_accounts INTEGER NOT NULL CHECK (max_accounts >= 1),
  max_devices INTEGER NOT NULL CHECK (max_devices >= 1),
  min_version TEXT NOT NULL,
  is_test INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bindings (
  serial TEXT NOT NULL REFERENCES licences(serial) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('login','device')),
  value TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (serial, kind, value)
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  serial_ref TEXT,
  ip_ref TEXT,
  status TEXT,
  reason TEXT
);
"""


class Storage:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        c = self._conn()
        c.executescript(SCHEMA)
        c.commit()

    def _conn(self):
        c = getattr(self._local, 'c', None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('PRAGMA busy_timeout=10000')
            c.row_factory = sqlite3.Row
            self._local.c = c
        return c

    def health(self):
        self._conn().execute('SELECT 1').fetchone()
        return True

    def transaction(self):
        return _Tx(self._conn())

    # ---- used inside a transaction
    @staticmethod
    def get_licence(c, serial):
        return c.execute('SELECT * FROM licences WHERE serial=?', (serial,)).fetchone()

    @staticmethod
    def bound_values(c, serial, kind):
        return [r['value'] for r in c.execute('SELECT value FROM bindings WHERE serial=? AND kind=?', (serial, kind))]

    @staticmethod
    def bind(c, serial, kind, value, now):
        c.execute('INSERT INTO bindings(serial,kind,value,first_seen,last_seen) VALUES(?,?,?,?,?) '
                  'ON CONFLICT(serial,kind,value) DO UPDATE SET last_seen=excluded.last_seen', (serial, kind, value, now, now))

    @staticmethod
    def audit(c, event, serial_ref, ip_ref, status, reason):
        c.execute('INSERT INTO audit(ts,event,serial_ref,ip_ref,status,reason) VALUES(?,?,?,?,?,?)',
                  (int(time.time()), event, serial_ref, ip_ref, status, reason))


class _Tx:
    def __init__(self, c):
        self.c = c

    def __enter__(self):
        self.c.execute('BEGIN IMMEDIATE')
        return self.c

    def __exit__(self, et, ev, tb):
        self.c.execute('ROLLBACK' if et else 'COMMIT')
        return False
