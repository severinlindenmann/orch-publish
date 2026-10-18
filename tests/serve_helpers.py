"""Shared setup for the share-server tests: rows are inserted straight into the DB (no upload API)."""

import hashlib
import os
import time

from fastapi.testclient import TestClient

from pubsrv import db
from pubsrv.serve import create_share_app, token_hash

SID = "a" * 32
TOKEN = "T0kenForTestsOnly_0123456789abcdefghijklmnopq"
NOW = 1_790_000_000_000


class Env:
    def __init__(self, tmp_path, now=NOW):
        self.data = str(tmp_path / "data")
        self.now = now
        self.app = create_share_app(self.data, clock=lambda: self.now)
        self.path = self.app.db_path
        conn = db.connect(self.path)
        t = int(time.time() * 1000)
        conn.execute(
            "INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?,?)",
            ("b" * 32, "k", "p", "pk", 1, "{}", "active", t, t),
        )
        conn.close()
        self.c = TestClient(self.app, base_url="http://127.0.0.1:8104", follow_redirects=False)

    def share(
        self, files, sid=SID, token=TOKEN, kind="once", limit=1, state="live", expires=None, views=0
    ):
        top = os.path.join(self.data, "shares", sid, "files")
        for name, data in files.items():
            p = os.path.join(top, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        conn = db.connect(self.path)
        conn.execute(
            "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, view_limit,"
            " views, state, manifest_hash, bytes, created_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                "b" * 32,
                "T-1",
                kind,
                token_hash(token),
                expires or self.now + 86_400_000,
                limit,
                views,
                state,
                hashlib.sha256(b"m").hexdigest(),
                0,
                self.now,
            ),
        )
        conn.close()
        return sid

    def row(self, sid=SID):
        conn = db.connect(self.path)
        try:
            return dict(conn.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone())
        finally:
            conn.close()

    def set(self, sql, *args):
        conn = db.connect(self.path)
        conn.execute(sql, args)
        conn.close()

    def open(self, sid=SID, token=TOKEN, client=None):
        return (client or self.c).post(f"/s/{sid}/open", data={"t": token})

    def view_url(self, sid=SID, token=TOKEN):
        r = self.open(sid, token)
        assert r.status_code == 303, r.text
        return r.headers["location"]
