"""HTTP endpoints through which a hub hands orch-publish its card, op-cert revocations and workspace bindings
(docs/protocol.md 4, 5, 9.2-9.4; orch-core #899).

    PUT /v2/hub/card                    body: signed hub.card (with its op_cert)
    PUT /v2/hub/op-revoked              body: root-signed hub.op_revoked
    PUT /v2/hub/bindings/{workspace_id} body: WSK-signed hub.binding or hub.unbound (chosen by o.kind)
    PUT /v2/hub/cards/{workspace_id}    body: {card, pk_pub}: the workspace's v2 card as it reached the hub (card_put);
                                        the only way a workspace is admitted (V3-D36: no direct register)

No transport authentication, by design (V3-D16): every object authenticates itself (a card by its HK_root and op
cert, a revocation by HK_root, a binding / unbound by the WSK of the workspace card orch-publish itself stores), and
the hub id derives from HK_root. The caller proves nothing; verification, the size cap and strict JSON keep junk
out. Rate limiting is hardening. Success is `200 {"ok": true}` and an identical re-push is a 200 no-op; a refusal
is `{"error": code}` with the status of hub_path.STATUS. Nothing but the code is ever returned.
"""

import hashlib
import json
import re
import sqlite3

from . import db, registry
from . import hub_admin_read as R
from . import hub_path as H
from . import relay_proto as proto
from .auth import Refusal
from .registry import ID32

MAX_BODY = 64 * 1024
PREFIX = "/v2/hub/"
_BINDING = re.compile(rf"/v2/hub/bindings/({ID32})")
_CARD = re.compile(rf"/v2/hub/cards/({ID32})")
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


def is_admin_path(path):
    return isinstance(path, str) and path.startswith(PREFIX)


async def _send(send, status, body, extra=(), head=False):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = [(k.encode(), v.encode()) for k, v in _HEADERS.items()] + [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(raw)).encode()),
    ]
    headers += [(k.encode(), v.encode()) for k, v in extra]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b"" if head else raw})


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
    elif _CARD.fullmatch(path):
        _accept_workspace_card(conn, _CARD.fullmatch(path).group(1), obj, now)
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


def _accept_workspace_card(conn, ws, obj, now):
    """A workspace's v2 card (card_put through the hub). Verified here, never trusted from the hub: the owner's PK
    signed the delegation, WSK signed the card. Admission is exactly the old direct register: the admin's pre-bind, the
    owner allowlist, no block, and a delegation that never changes (`registry.register`). Identical re-push: 200."""
    if set(obj) != {"card", "pk_pub"} or type(obj["card"]) is not dict:
        raise H.Refused("malformed")
    try:
        pk = proto.unb64u(obj["pk_pub"], 65)
        if not proto.SUITE.pub_ok(pk):
            raise ValueError("pk")
    except (ValueError, TypeError):
        raise H.Refused("malformed") from None
    res = proto.verify_card(obj["card"], pk)
    if "refuse" in res:
        raise H.Refused(res["refuse"] if res["refuse"] in _CARD_REFUSALS else "malformed")
    if res["ok"]["workspace_id"] != ws:
        raise H.Refused("other_workspace")
    o = res["ok"]
    digest = hashlib.sha256(proto.cj(obj["card"])).hexdigest()

    def guard(conn, admitted):
        # Freshness (v2 card update rules, protocol.md 16 #18): card_seq never goes back. The highest ever admitted is
        # kept across an unbind, so an old card cannot re-register a workspace. The very same card again is a no-op
        # only while the workspace is still admitted (a retry after a lost answer). Read inside the write lock.
        floor = conn.execute(
            "SELECT card_seq, card_hash FROM card_floor WHERE workspace_id=?", (ws,)
        ).fetchone()
        if floor is not None:
            if o["card_seq"] < floor["card_seq"]:
                raise H.Refused("stale_card")
            if o["card_seq"] == floor["card_seq"] and (
                not admitted or digest != floor["card_hash"]
            ):
                raise H.Refused("stale_card")
        if not admitted and not now - CARD_MAX_AGE_MS <= o["issued_ms"] <= now + CARD_SKEW_MS:
            raise H.Refused("stale_card")  # a new admission needs a card issued recently

    def after(conn):
        conn.execute(
            "INSERT INTO card_floor(workspace_id, card_seq, card_hash) VALUES (?,?,?)"
            " ON CONFLICT(workspace_id) DO UPDATE SET card_seq=excluded.card_seq, card_hash=excluded.card_hash"
            " WHERE excluded.card_seq > card_floor.card_seq",
            (ws, o["card_seq"], digest),
        )

    registry.register(conn, ws, obj["card"]["delegation"], pk, now, guard=guard, after=after)


CARD_MAX_AGE_MS = (
    30 * 24 * 3600 * 1000
)  # a card that admits a workspace for the first time was issued within 30 days
CARD_SKEW_MS = 120_000

_CARD_REFUSALS = frozenset(
    [
        "malformed",
        "wrong_suite",
        "other_person",
        "delegation_mismatch",
        "bad_signature",
        "delegation_refused",
    ]
)


def _route_ok(path):
    return (
        path in (PREFIX + "card", PREFIX + "op-revoked")
        or _BINDING.fullmatch(path) is not None
        or _CARD.fullmatch(path) is not None
    )


RELEASES = PREFIX + "releases"


def _raw_target(scope):
    """The request target exactly as sent (ASGI raw_path + raw query); None when it is not ASCII."""
    raw = scope.get("raw_path")
    if raw is None:
        raw = scope.get("path", "").encode()
    qs = scope.get("query_string") or b""
    t = raw + (b"?" + qs if qs else b"")
    return t.decode("ascii") if t.isascii() else None


def _admin_read(scope, settings):
    """GET / HEAD /v2/hub/releases[?workspace=<id32hex>]: protocol.md 10.6. Returns the JSON body."""
    target = _raw_target(scope)
    if target is None:
        raise H.Refused("malformed")
    headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
    req = {"method": scope["method"], "target": target, "headers": headers}
    now = settings.clock()
    conn = db.connect(settings.db_path)
    try:
        hub = headers.get("orch-hub", "")
        st = R.load_state(
            conn, hub if re.fullmatch(r"[0-9a-f]{32}", hub) else "0" * 32, now, settings.dev_mode
        )
        res = R.check_admin_read(req, st, now)
        return R.list_releases(conn, res["workspaces"], now, res["named"])
    finally:
        conn.close()


async def handle(scope, receive, send, settings):
    """ASGI handler for everything under /v2/hub/. Fail closed: an unexpected error is a generic 500."""
    path = scope.get("path", "")
    try:
        if scope["method"] in ("GET", "HEAD") and path == RELEASES:
            body = _admin_read(scope, settings)
            return await _send(send, 200, body, head=scope["method"] == "HEAD")
        if path == RELEASES:
            raise Refusal(405, "method_not_allowed")  # GET / HEAD were handled above
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
        if r.status == 405 and path == RELEASES:
            extra = [("allow", "GET, HEAD")]
        return await _send(send, r.status, r.body(), extra)
    except H.Refused as r:
        return await _send(send, r.refusal().status, {"error": r.code})
    except (sqlite3.Error, OSError):
        return await _send(send, 503, {"error": "unavailable"})
    except Exception:  # noqa: BLE001 - fail closed, no detail
        return await _send(send, 500, {"error": "internal"})
    await _send(send, 200, {"ok": True})
