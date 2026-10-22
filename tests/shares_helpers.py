"""Shared fixtures for the shares tests: two admitted workspaces on one server, signed requests."""

import hashlib
import json
import os
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization

from pubsrv import db
from pubsrv import relay_proto as proto
from tests.test_publish_api_auth import PERSON, WS_A, WS_B, Env, _priv

BOB = "42f83168aabd846982483297b14e7301"
DAY = 86_400_000


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Two(Env):
    """Env plus workspace B (admitted directly in the DB: the register flow is P1's tests)."""

    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.allow()
        assert self.register().status_code == 200
        self.wsk_b = _priv("wsk_b.sig")
        pub = self.wsk_b.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.sql("INSERT OR IGNORE INTO owners VALUES (?,?)", BOB, self.now)
        self.sql(
            "INSERT INTO workspaces VALUES (?,?,?,?,?,'active',?,?)",
            WS_B,
            proto.b64u(pub),
            BOB,
            "",
            "{}",
            self.now,
            self.now,
        )

    def req(self, who, method, path, body=b"", **kw):
        ws, priv = (WS_A, self.wsk) if who == "a" else (WS_B, self.wsk_b)
        return self.send(method, f"/v1/ws/{ws}{path}", body, ws=ws, priv=priv, **kw)

    def meta(self, files, kind="secret", days=7, view_limit=None, ticket="TST-0001", token="t"):
        return {
            "ticket": ticket,
            "kind": kind,
            "expires_ms": self.now + days * DAY,
            "view_limit": (1 if kind == "once" else 0) if view_limit is None else view_limit,
            "token_hash": sha(token.encode()),
            "files": [
                {"path": p, "size": len(b), "sha256": sha(b)} for p, b in sorted(files.items())
            ],
        }

    def put_meta(self, who, sid, m):
        return self.req(who, "PUT", f"/shares/{sid}", json.dumps(m).encode())

    def put_file(self, who, sid, path, data):
        return self.req(who, "PUT", f"/shares/{sid}/files/{quote(path)}", data)

    def share(self, who="a", sid=None, files=None, commit=True, **kw):
        sid = sid or os.urandom(16).hex()
        files = files or {"index.html": b"<h1>hi</h1>", "sub/a.txt": b"aaa"}
        assert self.put_meta(who, sid, self.meta(files, **kw)).status_code == 200
        for p, b in files.items():
            assert self.put_file(who, sid, p, b).status_code == 200
        if commit:
            r = self.req(who, "POST", f"/shares/{sid}/commit")
            assert r.status_code == 200, r.text
        return sid

    def on_disk(self):
        out = []
        for top in ("incoming", "shares"):
            for dp, _, fs in os.walk(os.path.join(self.data, top)):
                out += [os.path.relpath(os.path.join(dp, f), self.data) for f in fs]
        return sorted(out)

    def row(self, sid):
        r = self.sql("SELECT * FROM shares WHERE id=?", sid)
        return dict(r[0]) if r else None


__all__ = ["BOB", "DAY", "PERSON", "WS_A", "WS_B", "Two", "db", "sha"]
