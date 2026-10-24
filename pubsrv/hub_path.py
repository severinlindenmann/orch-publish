"""Hub-forwarded publish requests (orch hub protocol H0, docs/protocol.md section 9 and 11; orch-core #898).

orch-publish accepts a request carrying `Orch-Hub` + `Orch-Hub-Signature` only while the workspace holds a
live `hub.binding` for that hub (signed by the card's current WSK), and for public access only with the owner's
single-use `hub.publish_approval`. Nothing here imports the orch_hub package: the checks are implemented again
on top of the vendored `relay_proto` and proved equal by the shared vectors (`tests/vectors/vectors_hub.json`).

Order of 11.2 (a signature always comes before the nonce store):
  1 header syntax  2 window  3 card known  4 WSK (hub-path label, hub_id + approval hash)  5 binding bound
  by the card's current WSK  5b binding hub == Orch-Hub  6 hub card verified, root == binding's  7 HK_op
  transport signature  8 nonce  9 owner approval (required for public access, verified whenever present).

The direct v2 12.1 path (`auth.py`) is untouched; a request without `Orch-Hub` never reaches this module, and a
hub-path WSK signature never verifies there (different label).
"""

import hashlib
import re
import sqlite3
import struct

from . import relay_proto as proto
from .auth import WINDOW_MS, Refusal

SUITE_ID = 2
HV = 0
CLOCK_SKEW_MS = 300_000
MODES = ("selective", "full")
_TS = re.compile(r"0|[1-9][0-9]{0,15}")

LABELS = {
    "sig_hub_op_cert": b"orch/v2/hub-op-cert|",
    "sig_hub_op_revoked": b"orch/v2/hub-op-revoked|",
    "sig_hub_card": b"orch/v2/hub-card|",
    "sig_hub_publish": b"orch/v2/hub-publish|",
    "sig_hub_admin_read": b"orch/v2/hub-admin-read|",
    "sig_hub_binding": b"orch/v2/sig/hub-binding|",
    "sig_hub_unbound": b"orch/v2/sig/hub-unbound|",
    "sig_publish_hub": b"orch/v2/publish-hub|",
    "sig_hub_publish_approval": b"orch/v2/sig/hub-publish-approval|",
    "h_hub_id": b"orch/v2/id/hub|",
    "h_hub_publish_request": b"orch/v2/hub-publish-request|",
}

# HTTP status of every code this module raises (docs/protocol.md 11.2, 14); anything else is 400.
STATUS = {
    "stale_timestamp": 401,
    "unknown_workspace": 401,
    "bad_signature": 401,
    "unknown_hub": 401,
    "bad_hub_signature": 401,
    "replay": 401,
    "not_bound": 403,
    "other_hub": 403,
    "approval_required": 403,
    "bad_approval": 403,
    "other_person": 403,
    "other_workspace": 403,
    "revoked": 403,
    "dev_refused": 403,
    "dev_mismatch": 403,
    "unbound": 409,
    "binding_conflict": 409,
    "stale_binding": 409,
    "stale_card": 409,
    "reader_downgrade": 409,
    "stale_op_cert": 409,
}

# Which requests grant public access (11.2: "F1 fixes the list"). Today no route does: shares are `secret`
# or `once` (token links) and a manifest has no public flag, so every forwarded request keeps the v2 charter
# path. A future public route is added HERE as (method, path regex) and then needs the owner's approval.
PUBLIC_ROUTES = ()


class Refused(Exception):
    def __init__(self, code, **extra):
        super().__init__(code)
        self.code, self.extra = code, extra

    def refusal(self):
        return Refusal(STATUS.get(self.code, 400), self.code, **self.extra)


def request_access(method, path):
    """ "public" when this route grants public access, else None."""
    for m, rx in PUBLIC_ROUTES:
        if method == m and re.fullmatch(rx, path):
            return "public"
    return None


# --- primitives -------------------------------------------------------------------------------------------------


def sha256(b):
    return hashlib.sha256(b).digest()


def _bad(fn, *a):
    """Run a vendored parser; anything it cannot read is malformed (fail closed)."""
    try:
        return fn(*a)
    except (ValueError, TypeError, UnicodeError, AttributeError, KeyError, RecursionError):
        raise Refused("malformed") from None


def _cj(o):
    return _bad(proto.cj, o)


def hub_id(hk_root_pub):
    if not proto.SUITE.pub_ok(hk_root_pub):
        raise Refused("malformed")
    return sha256(LABELS["h_hub_id"] + bytes([SUITE_ID]) + hk_root_pub)[:16].hex()


def _lp16(b):
    if len(b) >= 1 << 16:
        raise Refused("malformed")
    return struct.pack(">H", len(b)) + b


def _hex16(x):
    try:
        proto.unhex(x, 16)
        return True
    except (ValueError, TypeError):
        return False


def _pub(x):
    try:
        return proto.SUITE.pub_ok(proto.unb64u(x, 65))
    except (ValueError, TypeError):
        return False


def _b64u32(x):
    try:
        proto.unb64u(x, 32)
        return True
    except (ValueError, TypeError):
        return False


def _int_min(lo):
    return lambda x: type(x) is int and x >= lo


def _uint31(x):
    return type(x) is int and 0 <= x <= 2**31 - 1


def _enum(*vals):
    return lambda x: type(x) is str and x in vals


def _bool(x):
    return type(x) is bool


def _relay_url(x):
    return x is None or (
        type(x) is str
        and re.fullmatch(
            r"https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?|http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?",
            x,
        )
        is not None
    )


FIELDS = {
    "hub.op_cert": {
        "hub_id": _hex16,
        "cert_id": _hex16,
        "op_seq": _int_min(1),
        "hk_op_pub": _pub,
        "issued_ms": _int_min(0),
        "expires_ms": _int_min(1),
        "dev": _bool,
    },
    "hub.op_revoked": {
        "hub_id": _hex16,
        "cert_id": _hex16,
        "revoked_ms": _int_min(0),
        "dev": _bool,
    },
    "hub.card": {
        "hub_id": _hex16,
        "hk_root_pub": _pub,
        "hxk_pub": _pub,
        "relay_url": _relay_url,
        "tls_spki_sha256": _b64u32,
        "card_seq": _int_min(1),
        "reader": _uint31,
        "issued_ms": _int_min(0),
        "dev": _bool,
    },
    "hub.binding": {
        "workspace_id": _hex16,
        "wsk_pub": _pub,
        "hub_id": _hex16,
        "hk_root_pub": _pub,
        "mode": _enum(*MODES),
        "binding_seq": _int_min(1),
        "valid_from_ms": _int_min(0),
        "dev": _bool,
    },
    "hub.unbound": {
        "workspace_id": _hex16,
        "hub_id": _hex16,
        "binding_seq": _int_min(1),
        "unbound_ms": _int_min(0),
        "dev": _bool,
    },
    "hub.publish_approval": {
        "workspace_id": _hex16,
        "hub_id": _hex16,
        "device_id": _hex16,
        "request_hash": _b64u32,
        "access": _enum("public"),
    },
}


def _envelope(signed, kind, extra_keys=()):
    """Envelope and header (v2 2.4 steps 1-2, hub 2.2)."""
    if type(signed) is not dict or set(signed) != {"o", "sig", *extra_keys}:
        raise Refused("malformed")
    o = signed["o"]
    if type(o) is not dict or o.get("kind") != kind:
        raise Refused("malformed")
    if type(o.get("suite")) is not int or o["suite"] != SUITE_ID:
        raise Refused("wrong_suite")
    if not (type(o.get("v")) is int and o["v"] == 2 and type(o.get("hv")) is int and o["hv"] == HV):
        raise Refused("malformed")
    _cj(signed)
    return o


def _signature(signed, label, pub):
    sig = _bad(proto.unb64u, signed["sig"], 64)
    if not proto.SUITE.verify(pub, sig, label + _cj(signed["o"])):
        raise Refused("bad_signature")


def _fields(o, kind):
    spec = FIELDS[kind]
    if set(o) != {"v", "suite", "kind", "hv", *spec}:
        raise Refused("malformed")
    for name, ok in spec.items():
        if not ok(o[name]):
            raise Refused("malformed")


def _key_field(o, name):
    v = o.get(name)
    if not _pub(v):
        raise Refused("malformed")
    return proto.unb64u(v, 65)


def _dev(o, dev_mode):
    """A real orch-publish refuses `dev: true`; a dev one refuses `dev: false` (2.4)."""
    if o["dev"] is True and not dev_mode:
        raise Refused("dev_refused")
    if o["dev"] is False and dev_mode:
        raise Refused("dev_mismatch")


# --- the hub card -----------------------------------------------------------------------------------------------


def verify_op_cert(signed, hk_root_pub, now_ms, dev_mode, revoked_op_certs=frozenset()):
    o = _envelope(signed, "hub.op_cert")
    _signature(signed, LABELS["sig_hub_op_cert"], hk_root_pub)
    _fields(o, "hub.op_cert")
    if o["hub_id"] != hub_id(hk_root_pub):
        raise Refused("other_hub")
    _dev(o, dev_mode)
    if o["expires_ms"] <= o["issued_ms"] or o["issued_ms"] > now_ms + CLOCK_SKEW_MS:
        raise Refused("cert_invalid")
    if now_ms >= o["expires_ms"]:
        raise Refused("cert_expired")
    if o["cert_id"] in revoked_op_certs:
        raise Refused("revoked")
    return o


def verify_op_revoked(signed, hk_root_pub):
    """No dev check (L2-8): a revocation only removes authority."""
    o = _envelope(signed, "hub.op_revoked")
    _signature(signed, LABELS["sig_hub_op_revoked"], hk_root_pub)
    _fields(o, "hub.op_revoked")
    if o["hub_id"] != hub_id(hk_root_pub):
        raise Refused("other_hub")
    return o


def verify_card(card, now_ms, dev_mode, pinned_root=None, revoked_op_certs=frozenset(), held=None):
    """Hub card, section 5. `held` is the result of an earlier call. Returns
    {card, op_cert, hk_op_pub, hk_root_pub, signed}."""
    o = _envelope(card, "hub.card", ("op_cert",))
    root = _key_field(o, "hk_root_pub")
    if pinned_root is not None and root != pinned_root:
        raise Refused("other_hub")
    if o.get("hub_id") != hub_id(root):
        raise Refused("hub_id_mismatch")
    op = verify_op_cert(card["op_cert"], root, now_ms, dev_mode, revoked_op_certs)
    hk_op = proto.unb64u(op["hk_op_pub"], 65)
    _signature(card, LABELS["sig_hub_card"], hk_op)
    _fields(o, "hub.card")
    _dev(o, dev_mode)
    if o["issued_ms"] > now_ms + CLOCK_SKEW_MS:
        raise Refused("cert_invalid")
    if held is not None:
        if root != held["hk_root_pub"]:
            raise Refused("other_hub")
        hop = held["op_cert"]
        if op["op_seq"] < hop["op_seq"] or (
            op["op_seq"] == hop["op_seq"] and op["cert_id"] != hop["cert_id"]
        ):
            raise Refused("stale_op_cert")
        if op["op_seq"] == hop["op_seq"]:
            if o["card_seq"] < held["card"]["card_seq"]:
                raise Refused("stale_card")
            if o["card_seq"] == held["card"]["card_seq"] and _cj(card) != _cj(held["signed"]):
                raise Refused("stale_card")
        if o["reader"] < held["card"]["reader"]:  # a hub never lowers its level (protocol.md section 5 step 7)
            raise Refused("reader_downgrade")
    return {"card": o, "op_cert": op, "hk_op_pub": hk_op, "hk_root_pub": root, "signed": card}


# --- binding and unbound (WSK), and the store transition -------------------------------------------------------


def verify_binding(signed, workspace_id, wsk_pub, now_ms, dev_mode):
    """`workspace_id` is the workspace the binding is presented for, `wsk_pub` the key of its card."""
    o = _envelope(signed, "hub.binding")
    _signature(signed, LABELS["sig_hub_binding"], wsk_pub)
    _fields(o, "hub.binding")
    if o["workspace_id"] != workspace_id:
        raise Refused("other_workspace")
    if proto.unb64u(o["wsk_pub"], 65) != wsk_pub:
        raise Refused("wsk_mismatch")
    if o["hub_id"] != hub_id(proto.unb64u(o["hk_root_pub"], 65)):
        raise Refused("hub_id_mismatch")
    _dev(o, dev_mode)
    if o["valid_from_ms"] > now_ms + CLOCK_SKEW_MS:
        raise Refused("not_yet_valid")
    return o


def verify_unbound(signed, workspace_id, wsk_pub, dev_mode):
    o = _envelope(signed, "hub.unbound")
    _signature(signed, LABELS["sig_hub_unbound"], wsk_pub)
    _fields(o, "hub.unbound")
    if o["workspace_id"] != workspace_id:
        raise Refused("other_workspace")
    _dev(o, dev_mode)
    return o


def apply_binding(state, b):
    """State is {binding_seq, status: bound|unbound, binding} or None (9.4). A binding at or below an unbound
    sequence never comes back."""
    if state is not None:
        if b["binding_seq"] <= state["binding_seq"] and state["status"] == "unbound":
            raise Refused("unbound")
        if b["binding_seq"] < state["binding_seq"]:
            raise Refused("stale_binding")
        if b["binding_seq"] == state["binding_seq"]:
            if _cj(b) != _cj(state["binding"]):
                raise Refused("binding_conflict")
            return dict(state)
    return {"binding_seq": b["binding_seq"], "status": "bound", "binding": dict(b)}


def apply_unbound(state, u):
    """An unbound at `binding_seq` ends that binding and every lower one, also one not yet seen."""
    if state is not None and u["binding_seq"] < state["binding_seq"]:
        raise Refused("stale_binding")
    if (
        state is not None
        and state["status"] == "bound"
        and u["binding_seq"] == state["binding_seq"]
        and u["hub_id"] != state["binding"]["hub_id"]
    ):
        raise Refused("other_hub")
    return {
        "binding_seq": u["binding_seq"],
        "status": "unbound",
        "binding": None if state is None else state["binding"],
    }


# --- the request ------------------------------------------------------------------------------------------------


def _request_fields(ws, ts_ms, nonce, method, host, target, body):
    return (
        bytes([SUITE_ID])
        + ws
        + struct.pack(">Q", ts_ms)
        + nonce
        + _lp16(_bad(str.encode, method, "ascii"))
        + _lp16(_bad(str.encode, host, "ascii"))
        + _lp16(_bad(str.encode, target, "ascii"))
        + sha256(body)
    )


def approval_hash(approval):
    return bytes(32) if approval is None else sha256(_cj(approval))


def hub_path_signed_bytes(ws, ts_ms, nonce, method, host, target, body, hub_hex, approval):
    """What WSK signs on the hub path (11.1): own label, the 12.1 fields, the hub, the approval as attached."""
    return (
        LABELS["sig_publish_hub"]
        + _request_fields(ws, ts_ms, nonce, method, host, target, body)
        + proto.unhex(hub_hex, 16)
        + approval_hash(approval)
    )


def hub_publish_bytes(hub_hex, wsk_bytes):
    """What HK_op signs when forwarding: the exact hub-path WSK bytes, by hash, bound to the hub."""
    return (
        LABELS["sig_hub_publish"] + bytes([SUITE_ID]) + proto.unhex(hub_hex, 16) + sha256(wsk_bytes)
    )


def publish_request_hash(ws, ts_ms, nonce, method, host, target, body, hub_hex):
    """What the owner's approval names: the one exact request, ts and nonce included, through this hub."""
    return sha256(
        LABELS["h_hub_publish_request"]
        + _request_fields(ws, ts_ms, nonce, method, host, target, body)
        + proto.unhex(hub_hex, 16)
    )


def parse_headers(headers, method, host, target):
    """11.2 step 1. `headers` maps lower-case names to str. Returns a dict of the parsed fields."""
    try:
        h = {str(k).lower(): v for k, v in headers.items()}
        ts_s = h["orch-ts"]
        if not isinstance(ts_s, str) or not _TS.fullmatch(ts_s):
            raise ValueError("ts")
        hub = h["orch-hub"]
        proto.unhex(hub, 16)
        out = {
            "ws": proto.unhex(h["orch-workspace"], 16),
            "ts": int(ts_s),
            "nonce": proto.unhex(h["orch-nonce"], 16),
            "wsig": proto.unb64u(h["orch-signature"], 64),
            "hub": hub,
            "hsig": proto.unb64u(h["orch-hub-signature"], 64),
            "approval": None,
        }
        if "orch-owner-approval" in h:
            out["approval"] = proto.parse_json(proto.unb64u(h["orch-owner-approval"]))
        for part in (method, host, target):
            if type(part) is not str or not part.isascii():
                raise ValueError("ascii")  # L2-10: refused, never an uncaught encoding error
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise Refused("malformed") from None
    return out


def check_window(ts, now_ms):
    if abs(now_ms - ts) > WINDOW_MS:
        raise Refused("stale_timestamp", server_ms=now_ms)


# --- the owner's approval ---------------------------------------------------------------------------------------


def verify_device_cert(signed, pk_pub, now_ms, revoked_devices):
    """v2 6.1 as the approval's chain: scopes include `decide`."""
    if type(signed) is not dict or set(signed) != {"o", "sig"} or type(signed["o"]) is not dict:
        raise Refused("cert_invalid")
    o = signed["o"]
    try:
        ok = proto.SUITE.verify(
            pk_pub, proto.unb64u(signed["sig"], 64), proto.L["sig_device_cert"] + proto.cj(o)
        )
    except (ValueError, TypeError, UnicodeError):
        ok = False
    want = {
        "v", "suite", "kind", "device_id", "person_id", "dk_sig_pub", "dk_kx_pub", "label_sealed",
        "created_ms", "expires_ms", "scopes_max",
    }  # fmt: skip
    if (
        not ok
        or set(o) != want
        or o["v"] != 2
        or o["suite"] != SUITE_ID
        or o["kind"] != "device_cert"
    ):
        raise Refused("cert_invalid")
    try:
        sc = o["scopes_max"]
        sig_pub, kx_pub = proto.unb64u(o["dk_sig_pub"], 65), proto.unb64u(o["dk_kx_pub"], 65)
        proto.unb64u(o["label_sealed"])
        good = (
            proto.SUITE.pub_ok(sig_pub)
            and proto.SUITE.pub_ok(kx_pub)
            and o["person_id"] == proto.identifier("person", pk_pub)
            and o["device_id"] == proto.identifier("device", sig_pub)
            and type(sc) is list
            and bool(sc)
            and sc == ["look", "decide", "operate", "type"][: len(sc)]
            and "decide" in sc
            and type(o["created_ms"]) is int
            and o["created_ms"] <= now_ms + CLOCK_SKEW_MS
        )
        exp = o["expires_ms"]
        if exp is not None and (type(exp) is not int or exp <= o["created_ms"]):
            good = False
    except (ValueError, TypeError, KeyError):
        good = False
    if not good:
        raise Refused("cert_invalid")
    if exp is not None and now_ms >= exp:
        raise Refused("cert_expired")
    if o["device_id"] in revoked_devices:
        raise Refused("revoked")
    return o


def verify_approval(
    raw, workspace_id, hub_hex, owner_person_id, request_hash, access, now_ms, revoked_devices
):
    if type(raw) is not dict or set(raw) != {"o", "sig", "device_cert", "pk_pub"}:
        raise Refused("malformed")
    o = _envelope(raw, "hub.publish_approval", ("device_cert", "pk_pub"))
    if not _pub(raw["pk_pub"]):
        raise Refused("malformed")
    pk = proto.unb64u(raw["pk_pub"], 65)
    if proto.identifier("person", pk) != owner_person_id:
        raise Refused("other_person")
    cert = verify_device_cert(raw["device_cert"], pk, now_ms, revoked_devices)
    try:
        _signature(raw, LABELS["sig_hub_publish_approval"], proto.unb64u(cert["dk_sig_pub"], 65))
    except Refused as r:
        raise Refused("bad_approval" if r.code == "bad_signature" else r.code) from None
    _fields(o, "hub.publish_approval")
    if o["device_id"] != cert["device_id"]:
        raise Refused("bad_approval")
    if o["workspace_id"] != workspace_id:
        raise Refused("other_workspace")
    if o["hub_id"] != hub_hex:
        raise Refused("other_hub")
    if proto.unb64u(o["request_hash"], 32) != request_hash or o["access"] != access:
        raise Refused("bad_approval")
    return o


class State:
    """What a check reads. `cards`: {ws hex: {wsk_pub, owner_person_id}}; `bindings`: {ws hex: store state};
    `hub_card(hub hex)`: the verified held card or None (may raise Refused: dev, revoked, expired);
    `revoked_devices`: device ids."""

    def __init__(self, cards, bindings, hub_card, revoked_devices=frozenset()):
        self.cards, self.bindings = cards, bindings
        self.hub_card, self.revoked_devices = hub_card, revoked_devices


def check_hub_publish(req, st, nonces, now_ms, dev_mode):
    """11.2 in order. `req` = {method, host, target, headers (lower-case names), body (bytes), access}. `nonces`
    has `record(ws_hex, nonce_hex, now_ms) -> bool` (auth.MemoryNonces / auth.DbNonces). Returns
    {workspace, hub, approved}."""
    method, host, target, body = req["method"], req["host"], req["target"], req["body"]
    if type(body) is not bytes:
        raise Refused("malformed")
    p = parse_headers(req["headers"], method, host, target)  # 1
    check_window(p["ts"], now_ms)  # 2
    ws, wsx, hub = p["ws"], p["ws"].hex(), p["hub"]
    card = st.cards.get(wsx)  # 3
    if card is None:
        raise Refused("unknown_workspace")
    pbytes = hub_path_signed_bytes(
        ws, p["ts"], p["nonce"], method, host, target, body, hub, p["approval"]
    )
    wsk = proto.unb64u(card["wsk_pub"], 65)
    if not proto.SUITE.verify(wsk, p["wsig"], pbytes):  # 4
        raise Refused("bad_signature")
    b = st.bindings.get(wsx)  # 5: only a binding under the card's CURRENT WSK counts
    if b is None or b["status"] != "bound" or b["binding"]["wsk_pub"] != card["wsk_pub"]:
        raise Refused("not_bound")
    if b["binding"]["hub_id"] != hub:  # 5b
        raise Refused("other_hub")
    held = st.hub_card(hub)  # 6
    if held is None or proto.b64u(held["hk_root_pub"]) != b["binding"]["hk_root_pub"]:
        raise Refused("unknown_hub")
    if not proto.SUITE.verify(held["hk_op_pub"], p["hsig"], hub_publish_bytes(hub, pbytes)):  # 7
        raise Refused("bad_hub_signature")
    if not nonces.record(wsx, p["nonce"].hex(), now_ms):  # 8
        raise Refused("replay")
    approval = p["approval"]  # 9
    if approval is None:
        if req.get("access") == "public":
            raise Refused("approval_required")
        return {"workspace": wsx, "hub": hub, "approved": False}
    verify_approval(
        approval,
        wsx,
        hub,
        card["owner_person_id"],
        publish_request_hash(ws, p["ts"], p["nonce"], method, host, target, body, hub),
        req.get("access") or "",
        now_ms,
        st.revoked_devices,
    )
    return {"workspace": wsx, "hub": hub, "approved": True}


# --- SQLite store -----------------------------------------------------------------------------------------------


def _row_state(row):
    if row is None:
        return None
    return {
        "binding_seq": row["binding_seq"],
        "status": row["status"],
        "binding": None
        if row["binding_json"] is None
        else proto.parse_json(row["binding_json"].encode()),
    }


def binding_state(conn, ws_hex):
    return _row_state(
        conn.execute("SELECT * FROM hub_bindings WHERE workspace_id=?", (ws_hex,)).fetchone()
    )


def _write_state(conn, ws_hex, state, hub_hex, now_ms):
    bj = None if state["binding"] is None else _cj(state["binding"]).decode()
    conn.execute(
        "INSERT INTO hub_bindings(workspace_id, binding_seq, status, hub_id, binding_json, updated_ms)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET binding_seq=excluded.binding_seq,"
        " status=excluded.status, hub_id=excluded.hub_id, binding_json=excluded.binding_json,"
        " updated_ms=excluded.updated_ms",
        (ws_hex, state["binding_seq"], state["status"], hub_hex, bj, now_ms),
    )


def _store_update(conn, ws_hex, now_ms, dev_mode, signed, kind):
    """Verify and apply one binding / unbound inside one BEGIN IMMEDIATE, on freshly read state. The key is the
    workspace card's CURRENT WSK (a binding under an old key is refused). Returns the new state."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT wsk_pub FROM workspaces WHERE workspace_id=?", (ws_hex,)
        ).fetchone()
        if row is None:
            raise Refused("unknown_workspace")
        wsk = proto.unb64u(row["wsk_pub"], 65)
        state = binding_state(conn, ws_hex)
        if kind == "binding":
            o = verify_binding(signed, ws_hex, wsk, now_ms, dev_mode)
            new = apply_binding(state, o)
            hub_hex = o["hub_id"]
        else:
            o = verify_unbound(signed, ws_hex, wsk, dev_mode)
            new = apply_unbound(state, o)
            hub_hex = o["hub_id"]
        _write_state(conn, ws_hex, new, hub_hex, now_ms)
        conn.execute("COMMIT")
        return new
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def accept_binding(conn, ws_hex, signed, now_ms, dev_mode):
    return _store_update(conn, ws_hex, now_ms, dev_mode, signed, "binding")


def accept_unbound(conn, ws_hex, signed, now_ms, dev_mode):
    return _store_update(conn, ws_hex, now_ms, dev_mode, signed, "unbound")


def revoked_op_certs(conn, hub_hex):
    return frozenset(
        r["cert_id"]
        for r in conn.execute("SELECT cert_id FROM hub_op_revoked WHERE hub_id=?", (hub_hex,))
    )


def held_hub_card(conn, hub_hex, now_ms, dev_mode):
    """The stored card of a hub, verified again NOW (clock, dev marker and the current revoked set apply at every
    use, L2-1). None when no card is stored."""
    row = conn.execute("SELECT card_json FROM hub_cards WHERE hub_id=?", (hub_hex,)).fetchone()
    if row is None:
        return None
    return verify_card(
        proto.parse_json(row["card_json"].encode()), now_ms, dev_mode,
        revoked_op_certs=revoked_op_certs(conn, hub_hex),
    )  # fmt: skip


def _held_for_order(conn, hub_hex, dev_mode):
    """The stored card as the reference for card ordering only (L2-1): checked at its own issue time and without
    the revoked set, so an expired or revoked held card never blocks the newer card that replaces it."""
    row = conn.execute("SELECT card_json FROM hub_cards WHERE hub_id=?", (hub_hex,)).fetchone()
    if row is None:
        return None
    card = proto.parse_json(row["card_json"].encode())
    return verify_card(card, card["o"]["issued_ms"], dev_mode)


def accept_hub_card(conn, card, now_ms, dev_mode):
    """Store a hub's card (section 5) against the one already held. A card names its own root, and the binding
    then ties the hub to a workspace; publish never pins a root by itself."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        o = _envelope(card, "hub.card", ("op_cert",))
        hub_hex = o.get("hub_id")
        if not _hex16(hub_hex):
            raise Refused("malformed")
        res = verify_card(
            card, now_ms, dev_mode, revoked_op_certs=revoked_op_certs(conn, hub_hex),
            held=_held_for_order(conn, hub_hex, dev_mode),
        )  # fmt: skip
        conn.execute(
            "INSERT INTO hub_cards(hub_id, card_json, updated_ms) VALUES (?,?,?)"
            " ON CONFLICT(hub_id) DO UPDATE SET card_json=excluded.card_json, updated_ms=excluded.updated_ms",
            (hub_hex, _cj(card).decode(), now_ms),
        )
        conn.execute("COMMIT")
        return res
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def accept_op_revoked(conn, signed, now_ms):
    """Record a root-signed op-cert revocation of a hub whose card is stored."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        o = _envelope(signed, "hub.op_revoked")
        hub_hex = o.get("hub_id")
        if not _hex16(hub_hex):
            raise Refused("malformed")
        row = conn.execute("SELECT card_json FROM hub_cards WHERE hub_id=?", (hub_hex,)).fetchone()
        if row is None:
            raise Refused("unknown_hub")
        root = proto.unb64u(proto.parse_json(row["card_json"].encode())["o"]["hk_root_pub"], 65)
        o = verify_op_revoked(signed, root)
        conn.execute(
            "INSERT OR IGNORE INTO hub_op_revoked(hub_id, cert_id, revoked_ms) VALUES (?,?,?)",
            (hub_hex, o["cert_id"], now_ms),
        )
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def load_state(conn, ws_hex, hub_hex, now_ms, dev_mode):
    """A snapshot of what a check for this workspace and hub reads. The hub card is resolved lazily (step 6)."""
    row = conn.execute(
        "SELECT wsk_pub, owner_person_id FROM workspaces WHERE workspace_id=?", (ws_hex,)
    ).fetchone()
    cards = (
        {}
        if row is None
        else {ws_hex: {"wsk_pub": row["wsk_pub"], "owner_person_id": row["owner_person_id"]}}
    )
    bindings = {}
    b = binding_state(conn, ws_hex)
    if b is not None:
        bindings[ws_hex] = b
    revoked = frozenset(
        r["device_id"] for r in conn.execute("SELECT device_id FROM hub_revoked_devices")
    )
    return State(cards, bindings, lambda h: held_hub_card(conn, h, now_ms, dev_mode), revoked)


def still_bound(conn, ws_hex, hub_hex):
    """After the nonce is spent: the binding is re-read on fresh state, so an unbound that landed since the
    request was admitted refuses it (like registry.require_binding)."""
    b = binding_state(conn, ws_hex)
    if b is None or b["status"] != "bound" or b["binding"]["hub_id"] != hub_hex:
        raise Refused("not_bound")
