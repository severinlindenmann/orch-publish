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

MAX_BODY = 26 * 1024 * 1024  # design I14: 25 MB per file request plus slack
MAX_REGISTER_BODY = 64 * 1024
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


class SignedRequestMiddleware:
    """Every HTTP request is signed; there is no unsigned route. Fail closed: any internal error
    (unreadable DB, parse error) is a refusal, never an accept."""

    def __init__(self, app, settings):
        self.app, self.s = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                return await self.app(scope, receive, send)
            return  # websockets etc.: not served
        try:
            declared = dict(scope["headers"]).get(b"content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
                raise _TooLarge
            body = await _read_body(receive, MAX_BODY)
        except _TooLarge:
            return await _respond(send, Refusal(413, "too_large"))
        except ConnectionError:
            return
        try:
            scope["orch_ws"] = self._authenticate(scope, body)
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

    def _authenticate(self, scope, body):
        s = self.s
        now = s.clock()
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
            target = raw_path.decode("ascii")
            if scope.get("query_string"):
                target += "?" + scope["query_string"].decode("ascii")
        except UnicodeError:
            raise Refusal(400, "malformed") from None
        method = scope["method"]

        cred = auth.step1_headers(raw_headers)  # 1
        auth.step2_window(cred, now)  # 2
        ws_hex = cred.ws.hex()
        conn = db.connect(s.db_path)
        try:
            row = registry.get_workspace(conn, ws_hex)
            m = _WS_PATH.fullmatch(scope["path"])
            is_register = method == "POST" and m is not None and m.group(2) == "/register"
            if row is not None:
                wsk = row["wsk_pub"]  # 3: a known workspace is checked against the stored key only
            elif is_register:
                if len(body) > MAX_REGISTER_BODY:
                    raise Refusal(413, "too_large")
                card, pk = registry.parse_register_body(body)
                wsk = registry.card_key(card, pk, ws_hex)  # 3: the self-presented card
            else:
                raise Refusal(401, "unknown_workspace")
            auth.step4_signature(cred, wsk, method, s.api_host, target, body)  # 4
            if row is not None:
                registry.check_admitted(
                    conn, row
                )  # blocked / owner off the allowlist: no nonce spent
            if m is not None and m.group(1) != ws_hex:
                raise Refusal(403, "wrong_workspace")  # I3: the path workspace is the signed one
            auth.step5_nonce(cred, auth.DbNonces(conn), now)  # 5
            if m is None:
                raise Refusal(404, "not_found")  # authenticated, but not a route this server has
        finally:
            conn.close()
        return ws_hex


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
