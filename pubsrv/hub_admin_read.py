"""Hub admin read at orch-publish (orch-hub docs/protocol.md 10.6, orch-core #900): release metadata of the
workspaces bound to the calling hub, for the hub console.

`check_admin_read` is the contract's check in order (syntax, window, held hub card, signature, scope). The scope is
workspaces with a CURRENT binding to this hub in `full` mode whose wsk_pub equals the workspace card's current WSK;
it applies to the workspace the target names and to every row returned (`check_admin_rows`). Only metadata leaves
here: never content, paths, the ticket, the token hash or any link that grants access. `public_url` is always null
(hv 0: orch-publish has no public kind). No nonce store, by design (idempotent metadata, +-120 s window).
"""

import re
import struct

from . import hub_path as H
from . import relay_proto as proto

WINDOW_MS = 120_000
TARGET_MAX = 2048
_SEG = re.compile(r"[a-z0-9][a-z0-9_-]*")
_QKEY = re.compile(r"[a-z][a-z_]*")
_QVAL = re.compile(r"[a-z0-9][a-z0-9_-]*")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_TS = re.compile(r"0|[1-9][0-9]{0,15}")

FIELDS = (
    "workspace_id", "release_id", "kind", "state", "created_ms", "expires_ms", "revoked", "bytes", "public_url",
)  # fmt: skip


def _text(n):
    return lambda x: type(x) is str and 0 < len(x) <= n


def _nat(x):
    return type(x) is int and x >= 0


_ROW = {
    "workspace_id": lambda x: type(x) is str and _HEX32.fullmatch(x) is not None,
    "release_id": _text(64),
    "kind": _text(32),
    "state": _text(32),
    "created_ms": _nat,
    "expires_ms": lambda x: x is None or _nat(x),
    "revoked": lambda x: type(x) is bool,
    "bytes": _nat,
    "public_url": lambda x: x is None,
}


def check_row(row):
    """The only shape of a release row an admin read returns."""
    if (
        type(row) is not dict
        or set(row) != set(_ROW)
        or not all(ok(row[k]) for k, ok in _ROW.items())
    ):
        raise H.Refused("malformed")
    return row


def check_rows(rows, scope):
    """Every row is shape-checked and must belong to the scope; one outside it is never emitted."""
    for r in rows:
        check_row(r)
        if r["workspace_id"] not in scope:
            raise H.Refused("not_bound")
    return rows


def parse_target(target):
    """Canonical targets only (10.6): ASCII, no `%`, non-empty lower-case segments, unique `key=value` query pairs.
    Returns the workspace the target names (path `/v1/ws/<id>/...` or the single `workspace=` key; both must agree),
    or None."""
    if (
        type(target) is not str
        or not target.isascii()
        or not target.startswith("/")
        or len(target) > TARGET_MAX
    ):
        raise H.Refused("malformed")
    path, sep, query = target.partition("?")
    segs = path[1:].split("/")
    if not all(_SEG.fullmatch(x) for x in segs):
        raise H.Refused("malformed")
    named = []
    if len(segs) >= 3 and segs[0] == "v1" and segs[1] == "ws":
        named.append(segs[2])
    if sep:
        keys = set()
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            if not eq or not _QKEY.fullmatch(k) or not _QVAL.fullmatch(v) or k in keys:
                raise H.Refused("malformed")
            keys.add(k)
            if k == "workspace":
                named.append(v)
    if not all(_HEX32.fullmatch(x) for x in named) or len(set(named)) > 1:
        raise H.Refused("malformed")
    return named[0] if named else None


def query_keys(target):
    return {p.partition("=")[0] for p in target.partition("?")[2].split("&") if p}


def signed_bytes(hub_hex, ts_ms, method, target):
    """label || suite || hub_id (16) || u64(ts_ms) || lp16(METHOD) || lp16(path + raw query)"""
    return (
        H.LABELS["sig_hub_admin_read"]
        + bytes([H.SUITE_ID])
        + proto.unhex(hub_hex, 16)
        + struct.pack(">Q", ts_ms)
        + H._lp16(method.encode("ascii"))
        + H._lp16(target.encode("ascii"))
    )


def scope_of(bindings, cards, hub_hex, root_b64):
    return sorted(
        ws
        for ws, b in bindings.items()
        if b["status"] == "bound"
        and b["binding"]["mode"] == "full"
        and b["binding"]["hub_id"] == hub_hex
        and b["binding"]["hk_root_pub"] == root_b64
        and ws in cards
        and b["binding"]["wsk_pub"] == cards[ws]["wsk_pub"]
    )


def check_admin_read(req, st, now_ms):
    """`req` = {method, target (path + raw query), headers}; `st` = {cards: {ws: {wsk_pub}}, bindings: {ws: store
    state}, held: callable(hub hex) -> the verified held hub card (raises Refused, or returns None, when none)}.
    Returns {hub, workspaces, named}. Order: syntax, window, held card, signature, scope."""
    try:
        h = {str(k).lower(): v for k, v in req["headers"].items()}
        hub = h["orch-hub"]
        proto.unhex(hub, 16)
        ts_s = h["orch-hub-ts"]
        if type(ts_s) is not str or not _TS.fullmatch(ts_s):
            raise ValueError("ts")
        ts = int(ts_s)
        sig = proto.unb64u(h["orch-hub-signature"], 64)
        if req["method"] not in ("GET", "HEAD"):
            raise ValueError("method")
        named = parse_target(req["target"])
        msg = signed_bytes(hub, ts, req["method"], req["target"])
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError, struct.error):
        raise H.Refused("malformed") from None
    if abs(now_ms - ts) > WINDOW_MS:
        raise H.Refused("stale_timestamp", server_ms=now_ms)
    try:
        held = st["held"](hub)
    except H.Refused:
        held = None
    if held is None:
        raise H.Refused("unknown_hub")
    if not proto.SUITE.verify(held["hk_op_pub"], sig, msg):
        raise H.Refused("bad_hub_signature")
    scope = scope_of(st["bindings"], st["cards"], hub, proto.b64u(held["hk_root_pub"]))
    if named is not None and named not in scope:
        raise H.Refused("not_bound")
    return {"hub": hub, "workspaces": scope, "named": named}


def load_state(conn, hub_hex, now_ms, dev_mode):
    """Cards and binding states of the workspaces that have a binding row for this hub (the scope is computed from
    them by check_admin_read); the hub card is resolved lazily and re-verified now."""
    cards, bindings = {}, {}
    for r in conn.execute(
        "SELECT w.workspace_id, w.wsk_pub, w.owner_person_id FROM hub_bindings b"
        " JOIN workspaces w ON w.workspace_id=b.workspace_id WHERE b.hub_id=? AND b.status='bound'",
        (hub_hex,),
    ):
        cards[r["workspace_id"]] = {
            "wsk_pub": r["wsk_pub"],
            "owner_person_id": r["owner_person_id"],
        }
        bindings[r["workspace_id"]] = H.binding_state(conn, r["workspace_id"])
    return {
        "cards": cards,
        "bindings": bindings,
        "held": lambda h: H.held_hub_card(conn, h, now_ms, dev_mode),
    }


def _row(r, now_ms):
    state = r["state"]
    if state == "live" and r["expires_ms"] <= now_ms:
        state = "expired"
    return {
        "workspace_id": r["owner_ws"],
        "release_id": r["id"],
        "kind": r["kind"],
        "state": state,
        "created_ms": r["created_ms"],
        "expires_ms": r["expires_ms"],
        "revoked": state == "revoked",
        "bytes": r["bytes"],
        "public_url": None,
    }


def list_releases(conn, scope, now_ms, workspace=None):
    """Release metadata (never staged shares) of `workspace` or of every workspace in `scope`, oldest first. The
    rows are re-checked against `scope` before they are returned."""
    wss = scope if workspace is None else [workspace]
    rows = []
    for ws in wss:
        for r in conn.execute(
            "SELECT id, owner_ws, kind, state, created_ms, expires_ms, bytes FROM shares"
            " WHERE owner_ws=? AND state!='staged' ORDER BY created_ms, id",
            (ws,),
        ):
            rows.append(_row(r, now_ms))
    return {"releases": check_rows(rows, scope)}
