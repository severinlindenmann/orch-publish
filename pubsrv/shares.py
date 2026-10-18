"""Shares API (design 2.5): PUT meta, PUT files, commit, DELETE (revoke), list.

Namespace isolation (I3): every route reads the workspace from the signed request (scope["orch_ws"],
set by the middleware) and reaches a share only through `owned_share`. A foreign id looks exactly like a
missing one (404). Nothing in this module trusts a workspace taken from the URL.
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from collections import defaultdict, deque

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from . import db, pathrules, registry
from .auth import WINDOW_MS, Refusal

MAX_FILE = 25 * 1024 * 1024
MAX_SHARE = 50 * 1024 * 1024
MAX_WORKSPACE = 500 * 1024 * 1024
MAX_SHARES = 100
MAX_DAYS = 30
MAX_VIEW_LIMIT = 10
MAX_META_BODY = 512 * 1024
WRITES_PER_MIN = 60
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}
_ID = re.compile(registry.ID32)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TICKET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_META_KEYS = {"ticket", "kind", "expires_ms", "view_limit", "token_hash", "files"}
_FILE_KEYS = {"path", "size", "sha256"}


# --- helpers -------------------------------------------------------------------------------------


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def owned_share(conn, ws, share_id):
    """The only way a route reaches a share row: it must belong to the signed workspace."""
    row = conn.execute("SELECT * FROM shares WHERE id=? AND owner_ws=?", (share_id, ws)).fetchone()
    if row is None:
        raise Refusal(404, "not_found")
    return row


def _gone(row):
    raise Refusal(410, "gone", state=row["state"])


def _no_dup_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def parse_meta(raw, now_ms):
    """Strict: unknown or duplicate keys, wrong types, bad paths -> 400. Returns the canonical dict."""
    try:
        m = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dup_pairs)
    except (UnicodeError, ValueError):
        raise Refusal(400, "malformed") from None
    if not isinstance(m, dict) or set(m) != _META_KEYS:
        raise Refusal(400, "malformed")
    if not (isinstance(m["ticket"], str) and _TICKET.fullmatch(m["ticket"])):
        raise Refusal(400, "bad_ticket")
    if m["kind"] not in ("secret", "once"):
        raise Refusal(400, "bad_kind")
    vl = m["view_limit"]
    if not _int(vl) or (m["kind"] == "secret" and vl != 0):
        raise Refusal(400, "bad_view_limit")
    if m["kind"] == "once" and not 1 <= vl <= MAX_VIEW_LIMIT:
        raise Refusal(400, "bad_view_limit")
    exp = m["expires_ms"]
    if not _int(exp) or exp <= now_ms or exp > now_ms + MAX_DAYS * 86400_000 + WINDOW_MS:
        raise Refusal(400, "bad_expiry")
    if not (isinstance(m["token_hash"], str) and _HEX64.fullmatch(m["token_hash"])):
        raise Refusal(400, "bad_token_hash")
    files = m["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= pathrules.MAX_FILES:
        raise Refusal(400, "bad_files")
    total = 0
    for f in files:
        if not isinstance(f, dict) or set(f) != _FILE_KEYS:
            raise Refusal(400, "bad_files")
        try:
            pathrules.check(f["path"])
        except pathrules.BadPath:
            raise Refusal(400, "bad_path") from None
        if not _int(f["size"]) or not 0 <= f["size"] <= MAX_FILE:
            raise Refusal(400, "bad_size")
        if not (isinstance(f["sha256"], str) and _HEX64.fullmatch(f["sha256"])):
            raise Refusal(400, "bad_sha256")
        total += f["size"]
    try:
        pathrules.check_set([f["path"] for f in files])
    except pathrules.BadPath:
        raise Refusal(400, "bad_path") from None
    if total > MAX_SHARE:
        raise Refusal(413, "share_too_large")
    m["files"] = sorted(files, key=lambda f: f["path"])
    return m, total


def manifest_hash(m):
    return hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# --- file system (all through directory fds; nothing follows a symlink) --------------------------


class Store:
    def __init__(self, data_dir):
        self.root = os.path.abspath(data_dir)
        for d in ("incoming", "shares"):
            os.makedirs(os.path.join(self.root, d), mode=0o700, exist_ok=True)

    def share_dir(self, kind, sid):
        return os.path.join(self.root, kind, sid)

    @staticmethod
    def _open_dir(name, dir_fd=None):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)

    def make_incoming(self, sid):
        base = self.share_dir("incoming", sid)
        os.makedirs(base, mode=0o700, exist_ok=True)
        for sub in ("files", ".tmp"):
            os.makedirs(os.path.join(base, sub), mode=0o700, exist_ok=True)

    def write_file(self, sid, path, data):
        """Write one file into incoming/<sid>/files/<path>. Directories are walked and created with
        O_NOFOLLOW from a dir fd; the bytes go to a fresh O_EXCL temp file and are renamed into place."""
        parts = path.split("/")
        base = self._open_dir(self.share_dir("incoming", sid))
        fds = [base]
        try:
            tmp_dir = self._open_dir(".tmp", base)
            fds.append(tmp_dir)
            cur = self._open_dir("files", base)
            fds.append(cur)
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=cur)
                except FileExistsError:
                    pass
                cur = self._open_dir(part, cur)
                fds.append(cur)
            tmp = secrets.token_hex(16)
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=tmp_dir,
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, parts[-1], src_dir_fd=tmp_dir, dst_dir_fd=cur)
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=tmp_dir)
                except OSError:
                    pass
                raise
        finally:
            for fd in fds:
                os.close(fd)

    def verify_file(self, kind, sid, path, size, sha256):
        """True iff a regular file (not a symlink) with exactly this size and hash is in place."""
        parts = path.split("/")
        fds = []
        try:
            cur = self._open_dir(self.share_dir(kind, sid))
            fds.append(cur)
            cur = self._open_dir("files", cur)
            fds.append(cur)
            for part in parts[:-1]:
                cur = self._open_dir(part, cur)
                fds.append(cur)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=cur)
            with os.fdopen(fd, "rb") as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_size != size:
                    return False
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest() == sha256
        except OSError:
            return False
        finally:
            for fd in fds:
                os.close(fd)

    def go_live(self, sid):
        """Move incoming/<sid>/files to shares/<sid>/files with one rename."""
        dest = self.share_dir("shares", sid)
        os.makedirs(dest, mode=0o700, exist_ok=True)
        os.rename(
            os.path.join(self.share_dir("incoming", sid), "files"), os.path.join(dest, "files")
        )

    def undo_live(self, sid):
        os.rename(
            os.path.join(self.share_dir("shares", sid), "files"),
            os.path.join(self.share_dir("incoming", sid), "files"),
        )

    def drop_incoming(self, sid):
        import shutil

        shutil.rmtree(self.share_dir("incoming", sid), ignore_errors=True)

    def remove(self, sid):
        import shutil

        for kind in ("incoming", "shares"):
            shutil.rmtree(self.share_dir(kind, sid), ignore_errors=True)


# --- operations (sync; run in a thread) ----------------------------------------------------------


def _txn(conn):
    conn.execute("BEGIN IMMEDIATE")


def op_put_meta(settings, store, ws, sid, raw):
    now = settings.clock()
    m, total = parse_meta(raw, now)
    mh = manifest_hash(m)
    conn = db.connect(settings.db_path)
    try:
        _txn(conn)
        try:
            row = conn.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
            if row is not None:
                if row["owner_ws"] != ws:
                    conn.execute("ROLLBACK")
                    # same answer whether the other workspace's share is live or a tombstone,
                    # and nothing about who owns it
                    raise Refusal(409, "conflict")
                if row["state"] in ("revoked", "expired"):
                    conn.execute("ROLLBACK")
                    _gone(row)
                if row["manifest_hash"] != mh:
                    conn.execute("ROLLBACK")
                    raise Refusal(409, "conflict")
                conn.execute("COMMIT")  # identical re-PUT: nothing changes
                return {"id": sid, "state": row["state"], "result": "unchanged"}
            n, used = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM shares"
                " WHERE owner_ws=? AND state IN ('staged','live')",
                (ws,),
            ).fetchone()
            if n >= MAX_SHARES:
                raise Refusal(429, "too_many_shares")
            if used + total > MAX_WORKSPACE:
                raise Refusal(413, "quota_exceeded")
            conn.execute(
                "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, view_limit,"
                " state, manifest_hash, bytes, created_ms) VALUES (?,?,?,?,?,?,?,'staged',?,?,?)",
                (sid, ws, m["ticket"], m["kind"], m["token_hash"], m["expires_ms"],
                 m["view_limit"], mh, total, now),
            )  # fmt: skip
            conn.executemany(
                "INSERT INTO share_files(share_id, path, size, sha256) VALUES (?,?,?,?)",
                [(sid, f["path"], f["size"], f["sha256"]) for f in m["files"]],
            )
            store.make_incoming(sid)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return {"id": sid, "state": "staged", "result": "created"}
    finally:
        conn.close()


def op_put_file(settings, store, ws, sid, path, body):
    conn = db.connect(settings.db_path)
    try:
        row = owned_share(conn, ws, sid)
        if row["state"] in ("revoked", "expired"):
            _gone(row)
        try:
            pathrules.check(path)
        except pathrules.BadPath:
            raise Refusal(400, "bad_path") from None
        f = conn.execute(
            "SELECT * FROM share_files WHERE share_id=? AND path=?", (sid, path)
        ).fetchone()
        if f is None:
            raise Refusal(404, "not_in_manifest")
        if len(body) != f["size"] or hashlib.sha256(body).hexdigest() != f["sha256"]:
            raise Refusal(422, "content_mismatch")
        if row["state"] == "live":
            if store.verify_file("shares", sid, path, f["size"], f["sha256"]):
                return {"path": path, "result": "unchanged"}
            raise Refusal(409, "committed")
        if settings.clock() >= row["expires_ms"]:
            raise Refusal(410, "gone", state="expired")
        store.write_file(sid, path, body)
        conn.execute("UPDATE share_files SET present=1 WHERE share_id=? AND path=?", (sid, path))
        return {"path": path, "result": "stored"}
    finally:
        conn.close()


def op_commit(settings, store, ws, sid):
    conn = db.connect(settings.db_path)
    try:
        _txn(conn)
        try:
            row = owned_share(conn, ws, sid)
            if row["state"] in ("revoked", "expired"):
                _gone(row)
            if row["state"] == "live":
                conn.execute("COMMIT")
                return {"id": sid, "state": "live", "result": "unchanged"}
            if settings.clock() >= row["expires_ms"]:
                raise Refusal(410, "gone", state="expired")
            files = conn.execute("SELECT * FROM share_files WHERE share_id=?", (sid,)).fetchall()
            missing = [
                f["path"]
                for f in files
                if not f["present"]
                or not store.verify_file("incoming", sid, f["path"], f["size"], f["sha256"])
            ]
            if missing:
                raise Refusal(409, "incomplete", missing=sorted(missing))
            store.go_live(sid)
            try:
                conn.execute("UPDATE shares SET state='live' WHERE id=?", (sid,))
                conn.execute("COMMIT")
            except BaseException:
                try:
                    store.undo_live(sid)
                except OSError:
                    pass
                raise
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        store.drop_incoming(sid)
        return {"id": sid, "state": "live", "result": "committed"}
    finally:
        conn.close()


def op_revoke(settings, store, ws, sid):
    conn = db.connect(settings.db_path)
    try:
        _txn(conn)
        try:
            row = owned_share(conn, ws, sid)
            if row["state"] == "revoked":
                conn.execute("COMMIT")
                store.remove(sid)
                return {"id": sid, "state": "revoked", "result": "unchanged"}
            # the tombstone keeps the id (so it cannot be re-created) but no token hash
            conn.execute(
                "UPDATE shares SET state='revoked', ended_ms=?, token_hash=? WHERE id=?",
                (settings.clock(), "0" * 64, sid),
            )
            conn.execute("DELETE FROM views WHERE share_id=?", (sid,))
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        store.remove(sid)  # files go now; a failure here is picked up by the sweep
        return {"id": sid, "state": "revoked", "result": "revoked"}
    finally:
        conn.close()


def _view(row, now):
    state = row["state"]
    if state == "live" and row["expires_ms"] <= now:
        state = "expired"
    return {
        "id": row["id"],
        "ticket": row["ticket"],
        "kind": row["kind"],
        "state": state,
        "expires_ms": row["expires_ms"],
        "view_limit": row["view_limit"],
        "views": row["views"],
        "bytes": row["bytes"],
        "created_ms": row["created_ms"],
    }


def op_list(settings, ws):
    conn = db.connect(settings.db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM shares WHERE owner_ws=? ORDER BY created_ms, id", (ws,)
        ).fetchall()
        now = settings.clock()
        return {"shares": [_view(r, now) for r in rows]}
    finally:
        conn.close()


def op_get(settings, ws, sid):
    conn = db.connect(settings.db_path)
    try:
        row = owned_share(conn, ws, sid)
        if row["state"] in ("revoked", "expired"):
            _gone(row)
        out = _view(row, settings.clock())
        out["files"] = [
            {"path": f["path"], "size": f["size"], "present": bool(f["present"])}
            for f in conn.execute(
                "SELECT * FROM share_files WHERE share_id=? ORDER BY path", (sid,)
            )
        ]
        return out
    finally:
        conn.close()


# --- HTTP ----------------------------------------------------------------------------------------


class _Limiter:
    """60 writes per minute per workspace (I14)."""

    def __init__(self, clock):
        self.clock, self.hits = clock, defaultdict(deque)

    def allow(self, ws):
        now = self.clock()
        q = self.hits[ws]
        while q and q[0] <= now - 60_000:
            q.popleft()
        if len(q) >= WRITES_PER_MIN:
            return False
        q.append(now)
        return True


def install(app, settings):
    store = Store(os.path.dirname(settings.db_path))
    limiter = _Limiter(settings.clock)
    router = APIRouter(prefix="/v1/ws/{ws}")

    def ok(body, status=200):
        return JSONResponse(body, status, _HEADERS)

    async def guarded(request, fn, *a, write=True):
        """Resolve the signed workspace, rate-limit writes, run the sync op in a thread."""
        ws = request.scope.get("orch_ws")
        if not ws or request.path_params.get("ws") != ws:
            raise Refusal(403, "wrong_workspace")  # the middleware already enforced this
        if write and not limiter.allow(ws):
            raise Refusal(429, "rate_limited")
        sid = request.path_params.get("sid")
        if sid is not None and not _ID.fullmatch(sid):
            raise Refusal(404, "not_found")  # indistinguishable from a missing share
        return ok(await run_in_threadpool(fn, *a, ws))

    @router.get("/shares")
    async def list_shares(request: Request):
        return await guarded(request, lambda ws: op_list(settings, ws), write=False)

    @router.get("/shares/{sid}")
    async def get_share(sid: str, request: Request):
        return await guarded(request, lambda ws: op_get(settings, ws, sid), write=False)

    @router.put("/shares/{sid}")
    async def put_meta(sid: str, request: Request):
        raw = await request.body()
        if len(raw) > MAX_META_BODY:
            raise Refusal(413, "too_large")
        return await guarded(request, lambda ws: op_put_meta(settings, store, ws, sid, raw))

    @router.put("/shares/{sid}/files/{fpath:path}")
    async def put_file(sid: str, fpath: str, request: Request):
        body = await request.body()
        return await guarded(request, lambda ws: op_put_file(settings, store, ws, sid, fpath, body))

    @router.post("/shares/{sid}/commit")
    async def commit(sid: str, request: Request):
        return await guarded(request, lambda ws: op_commit(settings, store, ws, sid))

    @router.delete("/shares/{sid}")
    async def revoke(sid: str, request: Request):
        return await guarded(request, lambda ws: op_revoke(settings, store, ws, sid))

    @app.exception_handler(Refusal)
    async def _refusal(request, exc):
        return JSONResponse(exc.body(), exc.status, _HEADERS)

    @app.exception_handler(sqlite3.Error)
    async def _db_error(request, exc):
        return JSONResponse({"error": "unavailable"}, 503, _HEADERS)

    @app.exception_handler(OSError)
    async def _os_error(request, exc):
        return JSONResponse({"error": "unavailable"}, 503, _HEADERS)

    app.include_router(router)
    app.state.store = store


__all__ = ["Store", "install", "owned_share", "parse_meta"]
