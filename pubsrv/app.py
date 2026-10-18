"""FastAPI app + the signed-request middleware (protocol-v2 section 12.1, design section 3 I3-I7)."""

import json
import re
import sqlite3
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import auth, db, registry
from . import relay_proto as proto
from .auth import Refusal

MAX_FILE_BODY = 26 * 1024 * 1024  # design I14: 25 MB per file PUT plus slack; known workspaces only
MAX_BODY = 1024 * 1024  # any other route of a known workspace (manifests, commit, ...)
MAX_REGISTER_BODY = 64 * 1024  # register, and anything from a workspace not bound yet
_FILE_ROUTE = re.compile(rf"/v1/ws/{registry.ID32}/shares/[0-9a-f]{{32}}/files/.+")
_WS_PATH = re.compile(rf"/v1/ws/({registry.ID32})(/.*)?")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?|\[::1\](:[1-9][0-9]{0,4})?")
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


class Settings:
    """api_host is the host clients sign (design I6): the configured value, never the Host header."""

    def __init__(self, data_dir, api_host, clock=None):
        if not isinstance(api_host, str) or not _HOST.fullmatch(api_host):
            raise ValueError("api_host must be a lower-case host[:port]")
        self.api_host = api_host
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

    __slots__ = ("cred", "limit", "m", "method", "now", "register", "row", "target", "ws_hex")


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
        try:
            ctx = self._admit(scope)
            declared = dict(scope["headers"]).get(b"content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > ctx.limit):
                raise _TooLarge
            body = await _read_body(receive, ctx.limit)
            scope["orch_ws"] = self._verify(ctx, body)
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
        c.cred = auth.step1_headers(raw_headers)  # 1
        auth.step2_window(c.cred, c.now)  # 2
        c.ws_hex = c.cred.ws.hex()
        c.m = _WS_PATH.fullmatch(scope["path"])
        c.register = c.method == "POST" and c.m is not None and c.m.group(2) == "/register"
        conn = db.connect(s.db_path)
        try:
            c.row = registry.get_workspace(conn, c.ws_hex)
        finally:
            conn.close()
        if c.row is not None and not c.register:
            is_file_put = c.method == "PUT" and _FILE_ROUTE.fullmatch(scope["path"]) is not None
            c.limit = MAX_FILE_BODY if is_file_put else MAX_BODY
        elif c.row is None and not c.register:
            raise Refusal(401, "unknown_workspace")  # 3, before any body byte is read
        else:
            c.limit = MAX_REGISTER_BODY  # register, and an unknown workspace asking to register
        return c

    def _verify(self, c, body):
        s = self.s
        conn = db.connect(s.db_path)
        try:
            if c.row is not None:
                wsk = c.row[
                    "wsk_pub"
                ]  # 3: a known workspace is checked against the stored key only
            else:
                card, pk = registry.parse_register_body(body)
                # L3: cheap admission test first; the same 401 whatever the reason, so the answer
                # does not reveal which owners or workspaces are known
                registry.require_prebound(conn, c.ws_hex, proto.identifier("person", pk))
                wsk = registry.card_key(card, pk, c.ws_hex)  # 3: the self-presented card
            auth.step4_signature(c.cred, wsk, c.method, s.api_host, c.target, body)  # 4
            auth.step5_nonce(c.cred, auth.DbNonces(conn), c.now)  # 5 (L2: before policy refusals)
            if c.row is not None:
                registry.check_admitted(conn, c.row)  # blocked / owner off the allowlist
            if c.m is not None and c.m.group(1) != c.ws_hex:
                raise Refusal(403, "wrong_workspace")  # I3: the path workspace is the signed one
            if c.m is None:
                raise Refusal(404, "not_found")  # authenticated, but not a route this server has
        finally:
            conn.close()
        return c.ws_hex


def create_app(data_dir, api_host, clock=None):
    settings = Settings(data_dir, api_host, clock)
    db.init(settings.db_path)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    @app.post("/v1/ws/{ws}/register")
    async def register(ws: str, request: Request):
        raw = await request.body()
        if len(raw) > MAX_REGISTER_BODY:
            return JSONResponse({"error": "too_large"}, 413, _HEADERS)
        try:
            card, pk = registry.parse_register_body(raw)
            conn = db.connect(settings.db_path)
            try:
                outcome, seq = registry.register(conn, ws, card, pk, settings.clock())
            finally:
                conn.close()
        except Refusal as r:
            return JSONResponse(r.body(), r.status, _HEADERS)
        except (sqlite3.Error, OSError):
            return JSONResponse({"error": "unavailable"}, 503, _HEADERS)
        return JSONResponse({"workspace": ws, "result": outcome, "card_seq": seq}, 200, _HEADERS)

    @app.get("/v1/ws/{ws}/status")
    async def status(ws: str):
        conn = db.connect(settings.db_path)
        try:
            row = registry.get_workspace(conn, ws)
        finally:
            conn.close()
        return JSONResponse(
            {"workspace": ws, "card_seq": row["card_seq"], "status": row["status"]}, 200, _HEADERS
        )

    app.add_middleware(SignedRequestMiddleware, settings=settings)
    return app


__all__ = ["Settings", "SignedRequestMiddleware", "create_app", "proto"]
