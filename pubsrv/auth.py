"""Signed-request check, protocol-v2 section 12.1 (orch-publish).

Order (exact):
  1 header syntax                 -> 400 malformed
  2 |now - ts| <= 120 s           -> 401 stale_timestamp (+ server_ms)
  3 the workspace's card is known -> 401 unknown_workspace
  4 the signature                 -> 401 bad_signature
  5 the nonce is unseen           -> 401 replay; then it is recorded for 240 s
The signature comes before the nonce store, so junk cannot fill it. Policy checks that are not part of
12.1 (blocked workspace, owner no longer on the allowlist, path workspace) sit between 4 and 5: they
need an authenticated caller and they never record a nonce.
"""

import hashlib
import re
import struct

from . import relay_proto as proto

WINDOW_MS = 120_000
NONCE_RETENTION_MS = 2 * WINDOW_MS
LABEL = "orch/v2/publish|"  # sig_publish (protocol section 3)
SUITE_ID = 2  # relay_proto implements suite 2 (P-256) only; other suites are refused as unknown
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


def _lp16(b):
    if len(b) >= 1 << 16:
        raise ValueError("too long")
    return struct.pack(">H", len(b)) + b


def signed_bytes(ws, ts_ms, nonce, method, host, target, body):
    """The exact bytes of 12.1. ws and nonce are 16 raw bytes."""
    return (
        LABEL.encode("ascii")
        + bytes([SUITE_ID])
        + ws
        + struct.pack(">Q", ts_ms)
        + nonce
        + _lp16(method.encode("ascii"))
        + _lp16(host.encode("ascii"))
        + _lp16(target.encode("ascii"))
        + hashlib.sha256(body).digest()
    )


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


def step4_signature(cred, wsk_pub_b64u, method, host, target, body):
    try:
        wsk = proto.unb64u(wsk_pub_b64u, 65)
        msg = signed_bytes(cred.ws, cred.ts, cred.nonce, method, host, target, body)
    except (ValueError, TypeError, UnicodeError):
        raise Refusal(401, "bad_signature") from None
    if not proto.SUITE.verify(wsk, cred.sig, msg):
        raise Refusal(401, "bad_signature")


class MemoryNonces:
    """The reference shape {ws hex: {nonce hex: until_ms}} (used by the protocol vectors)."""

    def __init__(self, seen=None):
        self.seen = seen if seen is not None else {}

    def record(self, ws_hex, nonce_hex, now_ms):
        seen = self.seen.setdefault(ws_hex, {})
        for n, until in list(seen.items()):
            if until <= now_ms:
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
            c.execute("DELETE FROM nonces WHERE until_ms <= ?", (now_ms,))
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


def step5_nonce(cred, nonces, now_ms):
    if not nonces.record(cred.ws.hex(), cred.nonce.hex(), now_ms):
        raise Refusal(401, "replay")


def publish_check(headers, method, host, target, body, cards, nonces, now_ms):
    """Pure 12.1 check against {ws hex: wsk_pub b64u} and a nonce dict; same shape as the protocol
    reference `publish_check`, used to run the shared vectors. Returns the reference's result dict."""
    try:
        cred = step1_headers(headers)
        step2_window(cred, now_ms)
        wsk = cards.get(cred.ws.hex())
        if wsk is None:
            raise Refusal(401, "unknown_workspace")
        step4_signature(cred, wsk, method, host, target, body)
        step5_nonce(cred, MemoryNonces(nonces), now_ms)
    except Refusal as r:
        return {"status": r.status, "error": r.error, **r.extra}
    return {"status": 200, "workspace": cred.ws.hex()}
