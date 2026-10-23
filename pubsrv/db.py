"""SQLite storage (design section 2.5). One short-lived connection per use; WAL; fail closed on errors."""

import os
import sqlite3

SCHEMA_VERSION = 3  # 2: workspaces.delegation_json replaces card_seq/card_json (design 2.6b)
# 3: hub path (orch-core #898): hub_bindings, hub_cards, hub_op_revoked, hub_revoked_devices (additive only)
MIGRATABLE_FROM = 2


class SchemaError(Exception):
    """The data dir was made by an older version of orch-publish."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces(
  workspace_id TEXT PRIMARY KEY,
  wsk_pub TEXT NOT NULL,
  owner_person_id TEXT NOT NULL,
  owner_pk TEXT NOT NULL,
  delegation_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS owners(
  person_id TEXT PRIMARY KEY,
  added_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS prebinds(
  workspace_id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  added_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces(
  ws TEXT NOT NULL,
  nonce TEXT NOT NULL,
  until_ms INTEGER NOT NULL,
  UNIQUE(ws, nonce)
);
CREATE INDEX IF NOT EXISTS nonces_until ON nonces(until_ms);
CREATE TABLE IF NOT EXISTS hub_bindings(
  workspace_id TEXT PRIMARY KEY,  -- no FK: the unbound record outlives an unbind/re-register of the workspace
  binding_seq INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('bound','unbound')),
  hub_id TEXT NOT NULL,
  binding_json TEXT,
  updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hub_cards(
  hub_id TEXT PRIMARY KEY,
  card_json TEXT NOT NULL,
  updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hub_op_revoked(
  hub_id TEXT NOT NULL,
  cert_id TEXT NOT NULL,
  revoked_ms INTEGER NOT NULL,
  PRIMARY KEY(hub_id, cert_id)
);
CREATE TABLE IF NOT EXISTS hub_revoked_devices(
  device_id TEXT PRIMARY KEY,
  revoked_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS shares(
  id TEXT PRIMARY KEY,
  owner_ws TEXT NOT NULL,  -- no FK: tombstones outlive an unbind
  ticket TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('secret','once')),
  token_hash TEXT NOT NULL,
  expires_ms INTEGER NOT NULL,
  view_limit INTEGER NOT NULL DEFAULT 0,
  views INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'staged' CHECK(state IN ('staged','live','revoked','expired')),
  manifest_hash TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL,
  ended_ms INTEGER
);
CREATE INDEX IF NOT EXISTS shares_owner ON shares(owner_ws);
CREATE TABLE IF NOT EXISTS share_files(
  share_id TEXT NOT NULL REFERENCES shares(id),
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  present INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(share_id, path)
);
CREATE TABLE IF NOT EXISTS views(
  view_id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id),
  until_ms INTEGER NOT NULL
);
"""


def prepare_dir(data_dir):
    """Create the data dir 0700. An existing dir that is not ours is refused; a looser mode is
    tightened, and if that fails we refuse to start (L5)."""
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    st = os.stat(data_dir)
    if st.st_uid != os.getuid():
        raise PermissionError("data dir is not owned by this user")
    if st.st_mode & 0o077:
        os.chmod(data_dir, 0o700)
        if os.stat(data_dir).st_mode & 0o077:
            raise PermissionError("data dir must be 0700")
    path = os.path.join(data_dir, "publish.db")
    if os.path.exists(path) and os.stat(path).st_mode & 0o077:
        os.chmod(path, 0o600)
    return path


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
        have = conn.execute("PRAGMA user_version").fetchone()[0]
        has_tables = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone()
        # version 2 -> 3 only adds tables (CREATE IF NOT EXISTS below), so it migrates in place
        if (has_tables and have not in (SCHEMA_VERSION, MIGRATABLE_FROM)) or have > SCHEMA_VERSION:
            raise SchemaError(
                "this data dir was made by an older orch-publish (dev only, no upgrade path): "
                "stop the server and delete the data dir, then start again"
            )
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    finally:
        conn.close()
