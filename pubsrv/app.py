"""FastAPI app + the signed-request middleware (hub protocol section 11, design section 3 I3-I7): every request comes
through a hub (`Orch-Hub`); a request without one is refused, there is no direct path (V3-D36)."""

import json
import re
import sqlite3
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import auth, db, hub_admin, hub_path, registry, shares
from . import relay_proto as proto
from .auth import Refusal

MAX_FILE_BODY = 26 * 1024 * 1024  # design I14: 25 MB per file PUT plus slack; known workspaces only
MAX_BODY = 1024 * 1024  # any other route of a known workspace (manifests, commit, ...)
_FILE_ROUTE = re.compile(rf"/v1/ws/{registry.ID32}/shares/[0-9a-f]{{32}}/files/.+")
_WS_PATH = re.compile(rf"/v1/ws/({registry.ID32})(/.*)?")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?|\[::1\](:[1-9][0-9]{0,4})?")
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


class Settings:
    """api_host is the host clients sign (design I6): the configured value, never the Host header."""

    def __init__(self, data_dir, api_host, clock=None, dev_mode=False):
        if not isinstance(api_host, str) or not _HOST.fullmatch(api_host):
            raise ValueError("api_host must be a lower-case host[:port]")
        self.api_host = api_host
        self.dev_mode = bool(
            dev_mode
        )  # a dev publish accepts only dev hub objects, a real one only real (2.4)
        self.db_path = db.prepare_dir(data_dir)
        self.clock = clock or (lambda: int(time.time() * 1000))


def _json(status, body):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = [(k.encode(), v.encode()) for k, v in _HEADERS.items()]
    headers += [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]
    return status, headers, raw


async def _respond(send, refusal):
    status, headers, raw = _json(refusal.status, refusal.body())
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": raw})


class _TooLarge(Exception):
    pass


async def _read_body(receive, limit):
    chunks, size = [], 0
    while True:
        msg = await receive()
        if msg["type"] == "http.disconnect":
            raise ConnectionError
        size += len(msg.get("body", b""))
        if size > limit:
            raise _TooLarge
        chunks.append(msg.get("body", b""))
        if not msg.get("more_body"):
            return b"".join(chunks)


class _Ctx:
    """What the header-only phase learned (no body read yet)."""

    __slots__ = (
        "cred",
        "hdrs",
        "hub",
        "limit",
        "m",
        "method",
        "now",
        "path",
        "register",
        "row",
        "target",
        "ws_hex",
    )


class SignedRequestMiddleware:
    """Every HTTP request is signed; there is no unsigned route. Fail closed: any internal error
    (unreadable DB, parse error) is a refusal, never an accept.

    Two phases (M1): `_admit` looks only at headers and the DB row (12.1 steps 1-3 and the route's
    body limit); the body is read after that, capped by the route, and only then `_verify` runs
    steps 4-5 (the signature covers the body hash)."""

    def __init__(self, app, settings):
        self.app, self.s = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                return await self.app(scope, receive, send)
            return  # websockets etc.: not served
        if hub_admin.is_admin_path(
            scope.get("path")
        ):  # self-authenticating hub objects, no request signature
            return await hub_admin.handle(scope, receive, send, self.s)
        try:
            ctx = self._admit(scope)
            declared = dict(scope["headers"]).get(b"content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > ctx.limit):
                raise _TooLarge
            body = await _read_body(receive, ctx.limit)
            scope["orch_ws"] = self._verify(ctx, body)
            scope["orch_wsk"] = ctx.row["wsk_pub"] if ctx.row is not None else None
        except _TooLarge:
            return await _respond(send, Refusal(413, "too_large"))
        except ConnectionError:
            return
        except Refusal as r:
            return await _respond(send, r)
        except (sqlite3.Error, OSError):
            return await _respond(send, Refusal(503, "unavailable"))
        except Exception:  # noqa: BLE001 - fail closed on anything unexpected
            return await _respond(send, Refusal(500, "internal"))

        sent = False

        async def replay():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)

    def _admit(self, scope):
        s = self.s
        c = _Ctx()
        c.now = s.clock()
        raw_headers = {}
        for k, v in scope["headers"]:
            k = k.decode("latin-1").lower()
            if k.startswith("orch-"):
                if k in raw_headers:
                    raise Refusal(400, "malformed")  # a repeated signed header is ambiguous
                raw_headers[k] = v.decode("latin-1")
        raw_path = scope.get("raw_path")
        if raw_path is None:
            raise Refusal(400, "malformed")
        try:
            c.target = raw_path.decode("ascii")
            if scope.get("query_string"):
                c.target += "?" + scope["query_string"].decode("ascii")
        except UnicodeError:
            raise Refusal(400, "malformed") from None
        c.method = scope["method"]
        c.hdrs, c.path = raw_headers, scope["path"]
        # Every request is on the hub path (protocol 11). Without Orch-Hub / Orch-Hub-Signature it is refused: there
        # is no direct path (V3-D36). Half a hub header pair is ambiguous, so it is malformed.
        hub_hdrs = {"orch-hub", "orch-hub-signature"} & set(raw_headers)
        if not hub_hdrs:
            raise Refusal(403, "hub_required")
        if len(hub_hdrs) != 2:
            raise Refusal(400, "malformed")
        c.hub = raw_headers["orch-hub"]
        try:  # 1 (hub syntax, approval strictly parsed, ASCII method/host/target) and 2
            parsed = hub_path.parse_headers(raw_headers, c.method, s.api_host, c.target)
            hub_path.check_window(parsed["ts"], c.now)
        except hub_path.Refused as r:
            raise r.refusal() from None
        c.cred = auth.step1_headers(raw_headers)  # 1
        auth.step2_window(c.cred, c.now)  # 2
        c.ws_hex = c.cred.ws.hex()
        c.m = _WS_PATH.fullmatch(scope["path"])
        conn = db.connect(s.db_path)
        try:
            c.row = registry.get_workspace(conn, c.ws_hex)
        finally:
            conn.close()
        if c.row is None:
            raise Refusal(401, "unknown_workspace")  # 3, before any body byte is read
        is_file_put = c.method == "PUT" and _FILE_ROUTE.fullmatch(scope["path"]) is not None
        c.limit = MAX_FILE_BODY if is_file_put else MAX_BODY
        return c

    def _verify(self, c, body):
        conn = db.connect(self.s.db_path)
        try:
            return self._verify_hub(c, body, conn)
        finally:
            conn.close()

    def _verify_hub(self, c, body, conn):
        """Protocol 11.2 steps 3-9 on the hub path (1-2 ran in `_admit`); policy checks come after, as on the
        direct path (L2), on freshly read state."""
        s = self.s
        try:
            req = {
                "method": c.method,
                "host": s.api_host,
                "target": c.target,
                "headers": c.hdrs,
                "body": body,
                "access": hub_path.request_access(c.method, c.path),
            }
            st = hub_path.load_state(conn, c.ws_hex, c.hub, c.now, s.dev_mode)
            hub_path.check_hub_publish(req, st, auth.DbNonces(conn), c.now, s.dev_mode)
            hub_path.still_bound(
                conn, c.ws_hex, c.hub
            )  # an unbound since admission refuses this request
        except hub_path.Refused as r:
            raise r.refusal() from None
        registry.require_binding(conn, c.ws_hex, c.row["wsk_pub"])
        if c.m is not None and c.m.group(1) != c.ws_hex:
            raise Refusal(403, "wrong_workspace")  # I3
        if c.m is None:
            raise Refusal(404, "not_found")
        return c.ws_hex


def create_app(data_dir, api_host, clock=None, dev_mode=False):
    settings = Settings(data_dir, api_host, clock, dev_mode)
    db.init(settings.db_path)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    @app.get("/v1/ws/{ws}/status")
    async def status(ws: str):
        conn = db.connect(settings.db_path)
        try:
            row = registry.get_workspace(conn, ws)
        finally:
            conn.close()
        if row is None:  # unbound between the middleware and this handler
            return JSONResponse({"error": "unknown_workspace"}, 401, _HEADERS)
        return JSONResponse({"workspace": ws, "status": row["status"]}, 200, _HEADERS)

    shares.install(app, settings)
    app.add_middleware(SignedRequestMiddleware, settings=settings)
    return app


__all__ = ["Settings", "SignedRequestMiddleware", "create_app", "proto"]
