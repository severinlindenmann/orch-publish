"""The share server (design section 2.5, invariants I9-I11, I13, I15): the public-facing origin.

Hand-routed ASGI on purpose: every response, error pages included, is built by one function
(`_Resp.send`) that adds the full security header set, so no response type can miss it.

Flow: GET /s/<id> is a static landing page and never counts. The link token sits in the URL
fragment, so a small script copies it into a form field; the "Open" click POSTs it to
/s/<id>/open, which spends one view atomically and redirects into a 30-minute view session.
"""

import asyncio
import base64
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from collections import deque
from urllib.parse import parse_qs, quote

from . import db

ID32 = r"[0-9a-f]{32}"
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,64}")
VIEW_MS = 30 * 60 * 1000
OPEN_LIMIT_PER_MIN = 30  # I14, per share, counted for requests that carry the right token
MAX_POST = 2048
_ROUTE_SHARE = re.compile(rf"/s/({ID32})")
_ROUTE_OPEN = re.compile(rf"/s/({ID32})/open")
_ROUTE_VIEW = re.compile(rf"/s/({ID32})/v/({ID32})/(.*)", re.DOTALL)

# Fixed extension allowlist (I9). Anything else: octet-stream + attachment.
INLINE_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
}
# Known types that must be saved, not rendered (viewer plugins run their own scripts).
ATTACHMENT_TYPES = {
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".xml": "application/octet-stream",
}
# Rendered only inside an opaque origin; the sandbox applies to every file response (I9).
FILE_CSP = "sandbox allow-scripts allow-forms allow-popups allow-downloads; frame-ancestors 'none'"

_STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:12vh auto;padding:0 20px;"
    "color:#1d1d1f}button{font:inherit;padding:.6em 1.4em;border:0;border-radius:8px;"
    "background:#1d1d1f;color:#fff;cursor:pointer}h1{font-size:1.4rem}p.s{color:#6e6e73}"
    "li{margin:.2em 0}@media(prefers-color-scheme:dark){body{background:#111;color:#f5f5f7}"
    "button{background:#f5f5f7;color:#111}p.s{color:#a1a1a6}}"
)
_SCRIPT = (
    "var m=/[#&]t=([A-Za-z0-9_-]+)/.exec(location.hash);"
    "var f=document.getElementById('f');"
    "if(m){f.t.value=m[1];f.hidden=false}"
    "else{document.getElementById('x').hidden=false}"
)


def _sri(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


PAGE_CSP = (
    f"default-src 'none'; style-src {_sri(_STYLE)}; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
LANDING_CSP = PAGE_CSP.replace(
    "default-src 'none';", f"default-src 'none'; script-src {_sri(_SCRIPT)};"
)

_PAGE = (
    '<!doctype html><html lang="en"><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">'
    "<title>@TITLE@</title><style>" + _STYLE + "</style>@BODY@</html>"
)
_LANDING_BODY = (
    "<h1>Someone shared files with you</h1>"
    '<form id="f" method="post" action="@ACTION@" hidden>'
    '<input type="hidden" name="t" value="">'
    "<p>Nothing has been opened yet. Opening may use up one of the views this link allows.</p>"
    '<button type="submit">Open</button></form>'
    '<p id="x" hidden>This address is incomplete. Use the whole link you were given, '
    "including the part after the # sign.</p>"
    f"<script>{_SCRIPT}</script>"
)
NOT_FOUND = ("Not found", "Nothing is shared at this address.")
GONE = {
    "opened": ("Already opened", "This link was already opened and cannot be used again."),
    "expired": ("Expired", "This link has expired."),
    "removed": ("Removed", "This link was removed by the person who shared it."),
    "view": ("Ended", "This viewing session has ended. Use your link again if it still works."),
}
TOO_MANY = ("Slow down", "Too many attempts. Wait a minute and try again.")


def _now():
    return int(time.time() * 1000)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100] or "file"


class _Resp:
    """Builds every response; the security headers live here and nowhere else."""

    def __init__(
        self, status, body=b"", ctype="text/html; charset=utf-8", csp=PAGE_CSP, extra=None
    ):
        self.status, self.body, self.ctype, self.csp = status, body, ctype, csp
        self.extra = extra or {}

    def headers(self, head):
        h = {
            "content-type": self.ctype,
            "content-length": str(len(self.body)),
            "content-security-policy": self.csp,
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "cache-control": "no-store",
            "x-robots-tag": "noindex, nofollow",
            "cross-origin-opener-policy": "same-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
        }
        h.update(self.extra)
        return [(k.encode(), v.encode("latin-1")) for k, v in h.items()]

    async def send(self, send, head=False):
        await send(
            {"type": "http.response.start", "status": self.status, "headers": self.headers(head)}
        )
        await send({"type": "http.response.body", "body": b"" if head else self.body})


def page(status, title_text, body=None, csp=PAGE_CSP, extra=None):
    title, text = title_text
    inner = body if body is not None else f"<h1>{html.escape(title)}</h1><p>{html.escape(text)}</p>"
    out = _PAGE.replace("@TITLE@", html.escape(title)).replace("@BODY@", inner)
    return _Resp(status, out.encode(), csp=csp, extra=extra)


def gone(kind):
    return page(410, GONE[kind])


def not_found():
    return page(404, NOT_FOUND)


class ShareServer:
    def __init__(self, data_dir, clock=None):
        self.db_path = db.prepare_dir(data_dir)
        self.shares_dir = os.path.realpath(os.path.join(data_dir, "shares"))
        self.clock = clock or _now
        self._opens = {}  # share_id -> deque of recent open times (ms)
        db.init(self.db_path)

    # -- ASGI -----------------------------------------------------------------------------------

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                kind = "shutdown" if msg["type"] == "lifespan.shutdown" else "startup"
                await send({"type": f"lifespan.{kind}.complete"})
                if kind == "shutdown":
                    return
        if scope["type"] != "http":
            return
        method = scope["method"]
        try:
            resp = await self._route(scope, receive, method)
        except (sqlite3.Error, OSError):
            resp = page(503, ("Unavailable", "This service is not available right now."))
        except Exception:  # noqa: BLE001 - fail closed, never echo details
            resp = page(500, ("Error", "Something went wrong."))
        await resp.send(send, head=method == "HEAD")

    async def _route(self, scope, receive, method):
        # The raw path is matched as is. Percent-escapes survive into the view-file path, where
        # they are decoded once and checked (I8); the share id and view id are strict hex.
        try:
            path = scope["raw_path"].decode("ascii").split("?", 1)[0]
        except (KeyError, AttributeError, UnicodeError):
            return not_found()
        if method not in ("GET", "HEAD", "POST"):
            return page(
                405,
                ("Not allowed", "This request is not allowed."),
                extra={"allow": "GET, HEAD, POST"},
            )
        m = _ROUTE_OPEN.fullmatch(path)
        if m:
            if method != "POST":
                return page(
                    405,
                    ("Not allowed", "Use the Open button on the link page."),
                    extra={"allow": "POST"},
                )
            raw = await self._body(receive)
            if raw is None:
                return page(413, ("Too large", "That request is too large."))
            return await asyncio.to_thread(self._open, m.group(1), raw)
        if method == "POST":
            return page(
                405, ("Not allowed", "This request is not allowed."), extra={"allow": "GET, HEAD"}
            )
        m = _ROUTE_VIEW.fullmatch(path)
        if m:
            return await asyncio.to_thread(self._view, m.group(1), m.group(2), m.group(3))
        m = _ROUTE_SHARE.fullmatch(path)
        if m:
            return await asyncio.to_thread(self._landing, m.group(1))
        return not_found()

    @staticmethod
    async def _body(receive):
        chunks, size = [], 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return None
            size += len(msg.get("body", b""))
            if size > MAX_POST:
                return None
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body"):
                return b"".join(chunks)

    # -- state ----------------------------------------------------------------------------------

    @staticmethod
    def _why_gone(row, now):
        """None if the link still has views; else the plain-words reason."""
        if row["state"] == "revoked":
            return "removed"
        if row["state"] != "live":
            return "expired" if row["state"] == "expired" else "removed"  # staged is not live
        if row["expires_ms"] <= now:
            return "expired"
        if row["view_limit"] and row["views"] >= row["view_limit"]:
            return "opened"
        return None

    def _landing(self, share_id):
        conn = db.connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM shares WHERE id=?", (share_id,)).fetchone()
        finally:
            conn.close()
        if row is None or row["state"] == "staged":
            return not_found()
        why = self._why_gone(row, self.clock())
        if why:
            return gone(why)
        body = _LANDING_BODY.replace("@ACTION@", f"/s/{share_id}/open")
        return page(200, ("Open shared files", ""), body=body, csp=LANDING_CSP)

    def _rate_ok(self, share_id, now):
        q = self._opens.setdefault(share_id, deque())
        while q and q[0] <= now - 60_000:
            q.popleft()
        if len(q) >= OPEN_LIMIT_PER_MIN:
            return False
        q.append(now)
        if len(self._opens) > 10_000:
            self._opens = {share_id: q}
        return True

    def _open(self, share_id, raw):
        try:
            form = parse_qs(raw.decode("ascii"), strict_parsing=False, max_num_fields=4)
        except (UnicodeError, ValueError):
            return not_found()
        token = (form.get("t") or [""])[0]
        if not TOKEN.fullmatch(token):
            return not_found()
        want = token_hash(token)
        now = self.clock()
        conn = db.connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM shares WHERE id=?", (share_id,)).fetchone()
            # wrong token and missing share look the same, and neither spends anything
            if (
                row is None
                or row["state"] == "staged"
                or not hmac.compare_digest(row["token_hash"], want)
            ):
                return not_found()
            if not self._rate_ok(share_id, now):
                return page(429, TOO_MANY, extra={"retry-after": "60"})
            view = secrets.token_hex(16)
            conn.execute("BEGIN IMMEDIATE")
            try:
                # I11: the check and the count are one statement; rowcount says who won
                n = conn.execute(
                    "UPDATE shares SET views=views+1 WHERE id=? AND state='live' AND expires_ms>?"
                    " AND (view_limit=0 OR views<view_limit)",
                    (share_id, now),
                ).rowcount
                if n == 1:
                    conn.execute("DELETE FROM views WHERE until_ms<?", (now,))
                    conn.execute(
                        "INSERT INTO views(view_id, share_id, until_ms) VALUES (?,?,?)",
                        (view, share_id, now + VIEW_MS),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            if n != 1:
                row = conn.execute("SELECT * FROM shares WHERE id=?", (share_id,)).fetchone()
                return gone(self._why_gone(row, now) or "opened")
        finally:
            conn.close()
        return _Resp(303, b"", extra={"location": f"/s/{share_id}/v/{view}/"})

    # -- files ----------------------------------------------------------------------------------

    def _view(self, share_id, view_id, rest):
        now = self.clock()
        conn = db.connect(self.db_path)
        try:
            v = conn.execute(
                "SELECT until_ms FROM views WHERE view_id=? AND share_id=?", (view_id, share_id)
            ).fetchone()
            row = conn.execute("SELECT * FROM shares WHERE id=?", (share_id,)).fetchone()
        finally:
            conn.close()
        if v is None or row is None:
            return not_found()
        # I13: revocation and expiry bite on every request, even inside a running view session
        if row["state"] == "revoked":
            return gone("removed")
        if row["state"] != "live" or row["expires_ms"] <= now:
            return gone("expired")
        if v["until_ms"] <= now:
            return gone("view")
        return self._file(share_id, view_id, rest)

    def _file(self, share_id, view_id, rest):
        top = os.path.join(self.shares_dir, share_id, "files")
        rel = self._clean(rest)
        if rel is None:
            return not_found()
        if rel == "" and os.path.isfile(os.path.join(top, "index.html")):
            rel = "index.html"
        if rel == "":
            return self._listing(top, share_id, view_id)
        path = os.path.join(top, rel)
        # no symlink anywhere on the way, and the real path stays under files/
        real_top = os.path.realpath(top)
        if os.path.realpath(path) != os.path.join(real_top, rel) or not path.startswith(
            top + os.sep
        ):
            return not_found()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return not_found()
        try:
            st = os.fstat(fd)
            if not os.path.isfile(path) or st.st_size > 60 * 1024 * 1024:
                return not_found()
            data = os.read(fd, st.st_size) if st.st_size else b""
            while len(data) < st.st_size:
                more = os.read(fd, st.st_size - len(data))
                if not more:
                    break
                data += more
        finally:
            os.close(fd)
        ext = os.path.splitext(rel)[1].lower()
        extra = {"access-control-allow-origin": "*"}
        if ext in INLINE_TYPES:
            ctype = INLINE_TYPES[ext]
        else:
            ctype = ATTACHMENT_TYPES.get(ext, "application/octet-stream")
            name = os.path.basename(rel)
            extra["content-disposition"] = (
                f"attachment; filename=\"{safe_name(name)}\"; filename*=UTF-8''{quote(name)}"
            )
        return _Resp(200, data, ctype, csp=FILE_CSP, extra=extra)

    @staticmethod
    def _clean(rest):
        """The path inside files/ or None. Decoded once; same character rules as the upload (I8)."""
        from urllib.parse import unquote

        try:
            rel = unquote(rest, errors="strict")
        except UnicodeError:
            return None
        if rel == "":
            return ""
        if rel.endswith("/") or unicodedata.normalize("NFC", rel) != rel:
            return None
        parts = rel.split("/")
        if len(parts) > 8:
            return None
        for p in parts:
            if not re.fullmatch(r"[A-Za-z0-9._ -]+", p) or p.startswith(".") or p in ("..", "."):
                return None
        return rel

    def _listing(self, top, share_id, view_id):
        names = []
        for root, dirs, files in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for f in files:
                p = os.path.join(root, f)
                if not os.path.islink(p):
                    names.append(os.path.relpath(p, top).replace(os.sep, "/"))
        if not names:
            return not_found()
        items = "".join(
            f'<li><a href="/s/{share_id}/v/{view_id}/{quote(n)}">{html.escape(n)}</a></li>'
            for n in sorted(names)[:500]
        )
        return page(200, ("Shared files", ""), body=f"<h1>Shared files</h1><ul>{items}</ul>")


def create_share_app(data_dir, clock=None):
    return ShareServer(data_dir, clock)
