"""HTTP endpoints through which a hub hands orch-publish its card, op-cert revocations and workspace bindings
(docs/protocol.md 4, 5, 9.2-9.4; orch-core #899).

    PUT /v2/hub/card                    body: signed hub.card (with its op_cert)
    PUT /v2/hub/op-revoked              body: root-signed hub.op_revoked
    PUT /v2/hub/bindings/{workspace_id} body: WSK-signed hub.binding or hub.unbound (chosen by o.kind)

No transport authentication, by design (V3-D16): every object authenticates itself (a card by its HK_root and op
cert, a revocation by HK_root, a binding / unbound by the WSK of the workspace card orch-publish itself stores), and
the hub id derives from HK_root. The caller proves nothing; verification, the size cap and strict JSON keep junk
out. Rate limiting is hardening. Success is `200 {"ok": true}` and an identical re-push is a 200 no-op; a refusal
is `{"error": code}` with the status of hub_path.STATUS. Nothing but the code is ever returned.
"""

import json
import re
import sqlite3

from . import db
from . import hub_path as H
from . import relay_proto as proto
from .auth import Refusal
from .registry import ID32

MAX_BODY = 64 * 1024
PREFIX = "/v2/hub/"
_BINDING = re.compile(rf"/v2/hub/bindings/({ID32})")
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


def is_admin_path(path):
    return isinstance(path, str) and path.startswith(PREFIX)


async def _send(send, status, body, extra=()):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = [(k.encode(), v.encode()) for k, v in _HEADERS.items()] + [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(raw)).encode()),
    ]
    headers += [(k.encode(), v.encode()) for k, v in extra]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": raw})


async def _read(receive, scope):
    declared = dict(scope["headers"]).get(b"content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
        raise Refusal(413, "too_large")
    chunks, size = [], 0
    while True:
        msg = await receive()
        if msg["type"] == "http.disconnect":
            raise ConnectionError
        chunk = msg.get("body", b"")
        size += len(chunk)
        if size > MAX_BODY:
            raise Refusal(413, "too_large")
        chunks.append(chunk)
        if not msg.get("more_body"):
            return b"".join(chunks)


def _parse(raw):
    try:
        obj = proto.parse_json(raw)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise H.Refused("malformed") from None
    if type(obj) is not dict:
        raise H.Refused("malformed")
    return obj


def _apply(conn, path, obj, now, dev):
    if path == PREFIX + "card":
        H.accept_hub_card(conn, obj, now, dev)
    elif path == PREFIX + "op-revoked":
        H.accept_op_revoked(conn, obj, now)
    else:
        ws = _BINDING.fullmatch(path).group(1)
        o = obj.get("o")
        kind = o.get("kind") if type(o) is dict else None
        if kind == "hub.binding":
            H.accept_binding(conn, ws, obj, now, dev)
        elif kind == "hub.unbound":
            H.accept_unbound(conn, ws, obj, now, dev)
        else:
            raise H.Refused("malformed")


def _route_ok(path):
    return path in (PREFIX + "card", PREFIX + "op-revoked") or _BINDING.fullmatch(path) is not None


async def handle(scope, receive, send, settings):
    """ASGI handler for everything under /v2/hub/. Fail closed: an unexpected error is a generic 500."""
    path = scope.get("path", "")
    try:
        if not _route_ok(path):
            raise Refusal(404, "not_found")
        if scope["method"] != "PUT":
            raise Refusal(405, "method_not_allowed")
        raw = await _read(receive, scope)
        obj = _parse(raw)
        conn = db.connect(settings.db_path)
        try:
            _apply(conn, path, obj, settings.clock(), settings.dev_mode)
        finally:
            conn.close()
    except ConnectionError:
        return
    except Refusal as r:
        extra = [("allow", "PUT")] if r.status == 405 else []
        return await _send(send, r.status, r.body(), extra)
    except H.Refused as r:
        return await _send(send, r.refusal().status, {"error": r.code})
    except (sqlite3.Error, OSError):
        return await _send(send, 503, {"error": "unavailable"})
    except Exception:  # noqa: BLE001 - fail closed, no detail
        return await _send(send, 500, {"error": "internal"})
    await _send(send, 200, {"ok": True})
