"""SQLite storage (design section 2.5). One short-lived connection per use; WAL; fail closed on errors."""

import os
import sqlite3

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces(
  workspace_id TEXT PRIMARY KEY,
  wsk_pub TEXT NOT NULL,
  owner_person_id TEXT NOT NULL,
  owner_pk TEXT NOT NULL,
  card_seq INTEGER NOT NULL,
  card_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS owners(
  person_id TEXT PRIMARY KEY,
  added_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces(
  ws TEXT NOT NULL,
  nonce TEXT NOT NULL,
  until_ms INTEGER NOT NULL,
  UNIQUE(ws, nonce)
);
CREATE INDEX IF NOT EXISTS nonces_until ON nonces(until_ms);
CREATE TABLE IF NOT EXISTS shares(
  id TEXT PRIMARY KEY,
  owner_ws TEXT NOT NULL REFERENCES workspaces(workspace_id),
  ticket TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('secret','once')),
  token_hash TEXT NOT NULL,
  expires_ms INTEGER NOT NULL,
  view_limit INTEGER NOT NULL DEFAULT 0,
  views INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'staged' CHECK(state IN ('staged','live','revoked','expired')),
  manifest_hash TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS shares_owner ON shares(owner_ws);
CREATE TABLE IF NOT EXISTS views(
  view_id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id),
  until_ms INTEGER NOT NULL
);
"""


def prepare_dir(data_dir):
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    return os.path.join(data_dir, "publish.db")


def connect(path):
    """Autocommit connection (callers use explicit BEGIN IMMEDIATE for read-check-write)."""
    old = os.umask(0o077)
    try:
        conn = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    finally:
        os.umask(old)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init(path):
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    finally:
        conn.close()
