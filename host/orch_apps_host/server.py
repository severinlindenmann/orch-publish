"""The share server on 127.0.0.1:8790, run as orch-apps-web behind Caddy.

Routes:
  /s/<id>/...              a share: public files, or the sealed loader and its blob
  /s/<id>.<token>/...      a secret share: every file under its own address, which carries the token
  /<slug>.<token>/         a secret app's link: same, cookie for /<slug>/
  /_auth/app/<slug>        Caddy forward_auth for secret apps (only reachable from 127.0.0.1)

Share documents are served with CSP `sandbox`, so their scripts run in an opaque origin and cannot reach the apps
that share the domain. The server never logs paths, because secret links carry their token in the path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import posixpath
import secrets
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import shares, util

LOADER = (Path(__file__).with_name("loader.html")).read_text()
SANDBOX = "sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads"
_views_lock = threading.Lock()

PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>body{{font:15px/1.6 system-ui,sans-serif;max-width:34em;margin:22vh auto 0;padding:0 20px;
color:#495159;background:#F2F3F5}}@media (prefers-color-scheme:dark){{body{{color:#A3ABB5;background:#15171A}}}}</style>
<p>{text}</p>"""


def _secret() -> bytes:
    path = util.P.web_state / "secret"
    try:
        return bytes.fromhex(path.read_text().strip())
    except FileNotFoundError:
        util.P.web_state.mkdir(parents=True, exist_ok=True)
        value = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value.hex())
        return value


def _cookie_value(scope: str, token_hash: str) -> str:
    return hmac.new(_secret(), f"{scope}|{token_hash}".encode(), hashlib.sha256).hexdigest()


def _count_view(share_id: str) -> None:
    with _views_lock:
        path = util.P.web_state / "views.json"
        data = util.read_json(path, {})
        data[share_id] = int(data.get(share_id, 0)) + 1
        util.write_json(path, data, mode=0o644)


class Handler(BaseHTTPRequestHandler):
    server_version = "orch-apps"
    sys_version = ""

    def log_message(self, fmt, *args):  # paths may hold tokens: log nothing
        pass

    # -- responses ----------------------------------------------------------------------------------------------

    def _send(self, status: int, body: bytes = b"", ctype: str = "text/html; charset=utf-8",
              headers: dict | None = None, head: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _page(self, status: int, text: str, title: str = "Share") -> None:
        body = PAGE.format(title=title, text=text).encode()
        self._send(status, body, headers={"Cache-Control": "no-store"}, head=self.command == "HEAD")

    def _not_found(self) -> None:
        self._page(404, "Nothing is shared at this address.", "Not found")

    def _redirect(self, to: str, cookie: str | None = None) -> None:
        headers = {"Location": to, "Cache-Control": "no-store"}
        if cookie:
            headers["Set-Cookie"] = cookie
        self._send(303, b"", headers=headers, head=True)

    # -- routing ------------------------------------------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        parts = path.split("/")
        try:
            if path.startswith("/_auth/app/") and len(parts) == 4:
                return self._auth_app(parts[3])
            if len(parts) >= 3 and parts[1] == "s":
                return self._share(parts[2], "/".join(parts[3:]), has_slash=len(parts) > 3)
            if len(parts) >= 2 and "." in parts[1]:
                return self._app_token(parts[1])
        except util.Refused:
            pass
        return self._not_found()

    # -- apps ---------------------------------------------------------------------------------------------------

    def _app_with_hash(self, slug: str) -> dict | None:
        util.check_slug(slug)
        app = util.read_json(util.P.apps_file, {"apps": {}})["apps"].get(slug)
        return app if app and app.get("access") == "secret" and app.get("token_hash") else None

    def _auth_app(self, slug: str) -> None:
        app = self._app_with_hash(slug)
        want = _cookie_value(f"app:{slug}", app["token_hash"]) if app else None
        got = self._cookie(f"oa_app_{slug.replace('-', '_')}")
        if want and got and hmac.compare_digest(want, got):
            return self._send(200, b"", head=True)
        return self._page(404, "This app needs its secret link.", "Not found")

    def _app_token(self, segment: str) -> None:
        slug, _, token = segment.partition(".")
        app = self._app_with_hash(slug)
        util.check(token, util.TOKEN, "token")
        if not app or not hmac.compare_digest(util.token_hash(token), app["token_hash"]):
            return self._not_found()
        cookie = (f"oa_app_{slug.replace('-', '_')}={_cookie_value(f'app:{slug}', app['token_hash'])}; "
                  f"Path=/{slug}/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000")
        return self._redirect(f"/{slug}/", cookie)

    # -- shares -------------------------------------------------------------------------------------------------

    def _share(self, segment: str, rest: str, has_slash: bool) -> None:
        share_id, dot, token = segment.partition(".")
        util.check(share_id, util.SHARE_ID, "share id")
        meta = shares.read_meta(share_id)
        if not meta:
            return self._not_found()
        st = shares.state_of(meta)
        if st != "live" or not (util.P.shares / share_id / "files").exists():
            return self._page(410, "This share has expired or was revoked.", "Share ended")
        access = meta["access"]

        # A secret share lives only under /s/<id>.<token>/: every file the page loads, data files fetched by its
        # scripts included, resolves relative to that address and so carries the token (INT-0027 Q1). A cookie
        # would not work, because the page runs sandboxed and browsers send no cookie with its fetches.
        if access == "secret":
            if not dot:
                return self._page(404, "This share needs its secret link.", "Not found")
            util.check(token, util.TOKEN, "token")
            if not hmac.compare_digest(util.token_hash(token), meta["token_hash"]):
                return self._not_found()
        elif dot:
            return self._not_found()
        if not has_slash:
            return self._redirect(f"/s/{segment}/")

        if access == "sealed":
            if rest == "":
                body = LOADER.replace("__SHARE_ID__", share_id).encode()
                return self._send(200, body, headers={
                    "Cache-Control": "no-store", "Content-Security-Policy": "frame-ancestors 'none'"},
                    head=self.command == "HEAD")
            if rest == "blob":
                blob = (util.P.shares / share_id / "files" / "sealed.bin").read_bytes()
                if self.command == "GET":
                    _count_view(share_id)
                return self._send(200, blob, "application/octet-stream", {"Cache-Control": "no-store"},
                                  head=self.command == "HEAD")
            return self._not_found()
        return self._file(share_id, rest, access)

    def _file(self, share_id: str, rest: str, access: str) -> None:
        clean = posixpath.normpath("/" + urllib.parse.unquote(rest)).lstrip("/")
        if clean.startswith("..") or "\0" in clean:
            return self._not_found()
        top = (util.P.shares / share_id / "files").resolve()
        target = (top / clean).resolve() if clean not in ("", ".") else top
        if top not in target.parents and target != top:
            return self._not_found()
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            return self._not_found()
        if target == top / "index.html" and self.command == "GET":
            _count_view(share_id)
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json", "image/svg+xml"):
            ctype += "; charset=utf-8"
        # The sandboxed page has an opaque origin, so its fetches are cross-origin; whoever has the address may read
        # the file anyway, so "*" gives away nothing.
        headers = {"Cache-Control": "no-store" if access == "secret" else "public, max-age=60",
                   "Content-Security-Policy": SANDBOX, "Access-Control-Allow-Origin": "*"}
        return self._send(200, target.read_bytes(), ctype, headers, head=self.command == "HEAD")

    # -- helpers ------------------------------------------------------------------------------------------------

    def _cookie(self, name: str) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None


def make_server(port: int | None = None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", util.P.share_port if port is None else port), Handler)


def main() -> None:
    _secret()
    make_server().serve_forever()


if __name__ == "__main__":
    main()
