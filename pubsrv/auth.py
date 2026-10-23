"""Request header syntax and the nonce store (protocol-v2 section 12.1, as used by the hub path, protocol 11).

Steps 1 (header syntax -> 400 malformed) and 2 (|now - ts| <= 120 s -> 401 stale_timestamp, +server_ms) run here before
the body is read (M1); the signatures and the order of the rest are `hub_path.check_hub_publish`. There is no direct
signature check any more: a request without `Orch-Hub` is refused (V3-D36). An expired nonce is purged when
until_ms < now (L1), so a replay exactly at the end of retention is still a replay.
"""

import re

from . import relay_proto as proto

WINDOW_MS = 120_000
NONCE_RETENTION_MS = 2 * WINDOW_MS
_TS = re.compile(r"0|[1-9][0-9]{0,15}")


class Refusal(Exception):
    def __init__(self, status, error, **extra):
        super().__init__(error)
        self.status, self.error, self.extra = status, error, extra

    def body(self):
        return {"error": self.error, **self.extra}


class Credentials:
    __slots__ = ("nonce", "sig", "ts", "ws")

    def __init__(self, ws, ts, nonce, sig):
        self.ws, self.ts, self.nonce, self.sig = ws, ts, nonce, sig


def step1_headers(headers):
    """headers: any mapping; names are matched case-insensitively. Anything odd is malformed."""
    try:
        h = {str(k).lower(): v for k, v in headers.items()}
        ws = proto.unhex(h["orch-workspace"], 16)
        ts_s = h["orch-ts"]
        if not isinstance(ts_s, str) or not _TS.fullmatch(ts_s):
            raise ValueError("ts")
        nonce = proto.unhex(h["orch-nonce"], 16)
        sig = proto.unb64u(h["orch-signature"], 64)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Refusal(400, "malformed") from None
    return Credentials(ws, int(ts_s), nonce, sig)


def step2_window(cred, now_ms):
    if abs(now_ms - cred.ts) > WINDOW_MS:
        raise Refusal(401, "stale_timestamp", server_ms=now_ms)


class MemoryNonces:
    """The reference shape {ws hex: {nonce hex: until_ms}} (used by the protocol vectors)."""

    def __init__(self, seen=None):
        self.seen = seen if seen is not None else {}

    def record(self, ws_hex, nonce_hex, now_ms):
        seen = self.seen.setdefault(ws_hex, {})
        for n, until in list(seen.items()):
            if until < now_ms:
                del seen[n]
        if nonce_hex in seen:
            return False
        seen[nonce_hex] = now_ms + NONCE_RETENTION_MS
        return True


class DbNonces:
    """Nonce store in SQLite: expired rows are pruned and the new row inserted in one transaction;
    the UNIQUE(ws, nonce) constraint decides a race between two identical requests."""

    def __init__(self, conn):
        self.conn = conn

    def record(self, ws_hex, nonce_hex, now_ms):
        import sqlite3

        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            c.execute("DELETE FROM nonces WHERE until_ms < ?", (now_ms,))
            try:
                c.execute(
                    "INSERT INTO nonces(ws, nonce, until_ms) VALUES (?,?,?)",
                    (ws_hex, nonce_hex, now_ms + NONCE_RETENTION_MS),
                )
            except sqlite3.IntegrityError:
                c.execute("COMMIT")
                return False
            c.execute("COMMIT")
            return True
        except BaseException:
            c.execute("ROLLBACK")
            raise
