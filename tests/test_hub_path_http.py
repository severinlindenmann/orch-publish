"""Hub-forwarded publish over HTTP (orch-core #898, docs/protocol.md 9 and 11): a request carrying Orch-Hub +
Orch-Hub-Signature is accepted only with a live hub.binding, and for public access only with the owner's
single-use approval. Keys are generated here (test only); the shared vectors are in test_hub_path_vectors.py."""

import json
import os
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pubsrv import auth, db
from pubsrv import hub_path as H
from pubsrv import relay_proto as proto
from tests.test_publish_api_auth import HOST, NOW, WS_A, WS_B, Env, _priv, err, sign_headers

PUBLIC_PATH = f"/v1/ws/{WS_A}/status"


def pub(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def sign(priv, msg):
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signed(priv, label, o, **extra):
    return {"o": o, **extra, "sig": sign(priv, label + proto.cj(o))}


def newkey():
    return ec.generate_private_key(ec.SECP256R1())


class Hub:
    def __init__(self, dev=True, cert_seq=1):
        self.root, self.op = newkey(), newkey()
        self.id = H.hub_id(pub(self.root))
        hdr = {"v": 2, "suite": 2, "hv": 0}
        op_cert = signed(
            self.root,
            H.LABELS["sig_hub_op_cert"],
            {
                **hdr, "kind": "hub.op_cert", "hub_id": self.id, "cert_id": os.urandom(16).hex(),
                "op_seq": cert_seq, "hk_op_pub": proto.b64u(pub(self.op)), "issued_ms": NOW - 1000,
                "expires_ms": NOW + 10**9, "dev": dev,
            },
        )  # fmt: skip
        self.card = signed(
            self.op,
            H.LABELS["sig_hub_card"],
            {
                **hdr, "kind": "hub.card", "hub_id": self.id, "hk_root_pub": proto.b64u(pub(self.root)),
                "hxk_pub": proto.b64u(pub(newkey())), "relay_url": None,
                "tls_spki_sha256": proto.b64u(os.urandom(32)), "card_seq": 1, "issued_ms": NOW - 1000, "dev": dev,
            },
            op_cert=op_cert,
        )  # fmt: skip


def binding(wsk, hub, ws=WS_A, seq=1, dev=True, wsk_pub=None, **over):
    o = {
        "v": 2, "suite": 2, "hv": 0, "kind": "hub.binding", "workspace_id": ws,
        "wsk_pub": proto.b64u(wsk_pub or pub(wsk)), "hub_id": hub.id,
        "hk_root_pub": proto.b64u(pub(hub.root)), "mode": "selective", "binding_seq": seq,
        "valid_from_ms": NOW - 1000, "dev": dev,
    }  # fmt: skip
    o.update(over)
    return signed(wsk, H.LABELS["sig_hub_binding"], o)


def unbound(wsk, hub, ws=WS_A, seq=1, dev=True):
    o = {
        "v": 2, "suite": 2, "hv": 0, "kind": "hub.unbound", "workspace_id": ws, "hub_id": hub.id,
        "binding_seq": seq, "unbound_ms": NOW, "dev": dev,
    }  # fmt: skip
    return signed(wsk, H.LABELS["sig_hub_unbound"], o)


class Owner:
    """The owner's PK (vector key) and a device key with a PK-signed certificate that includes `decide`."""

    def __init__(self, pk=None, scopes=("look", "decide")):
        self.pk = pk or _priv("person_alice.sig")
        self.dk, self.kx = newkey(), newkey()
        self.cert = signed(
            self.pk,
            proto.L["sig_device_cert"],
            {
                "v": 2, "suite": 2, "kind": "device_cert",
                "device_id": proto.identifier("device", pub(self.dk)),
                "person_id": proto.identifier("person", pub(self.pk)),
                "dk_sig_pub": proto.b64u(pub(self.dk)), "dk_kx_pub": proto.b64u(pub(self.kx)),
                "label_sealed": proto.b64u(b"x"), "created_ms": NOW - 1000, "expires_ms": None,
                "scopes_max": list(scopes),
            },
        )  # fmt: skip

    def approve(self, req, **over):
        """Signs the approval for exactly this request (ts and nonce included)."""
        o = {
            "v": 2, "suite": 2, "hv": 0, "kind": "hub.publish_approval", "workspace_id": WS_A,
            "hub_id": req["hub"].id, "device_id": self.cert["o"]["device_id"],
            "request_hash": proto.b64u(
                H.publish_request_hash(
                    bytes.fromhex(WS_A), req["ts"], req["nonce"], req["method"], HOST, req["target"],
                    req["body"], req["hub"].id,
                )
            ),
            "access": "public",
        }  # fmt: skip
        o.update(over)
        return signed(
            self.dk,
            H.LABELS["sig_hub_publish_approval"],
            o,
            device_cert=self.cert,
            pk_pub=proto.b64u(pub(self.pk)),
        )


def build(
    hub,
    wsk,
    method="GET",
    target=PUBLIC_PATH,
    body=b"",
    ts=NOW,
    nonce=None,
    approval=None,
    hub_op=None,
):
    """The headers the host builds and the hub forwards (11.1)."""
    nonce = nonce or os.urandom(16)
    pb = H.hub_path_signed_bytes(
        bytes.fromhex(WS_A), ts, nonce, method, HOST, target, body, hub.id, approval
    )
    h = {
        "Orch-Workspace": WS_A, "Orch-Ts": str(ts), "Orch-Nonce": nonce.hex(), "Orch-Signature": None,
        "Orch-Hub": hub.id,
    }  # fmt: skip
    r, s = decode_dss_signature(wsk.sign(pb, ec.ECDSA(hashes.SHA256())))
    h["Orch-Signature"] = proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    r, s = decode_dss_signature(
        (hub_op or hub.op).sign(H.hub_publish_bytes(hub.id, pb), ec.ECDSA(hashes.SHA256()))
    )
    h["Orch-Hub-Signature"] = proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    if approval is not None:
        h["Orch-Owner-Approval"] = proto.b64u(proto.cj(approval))
    return h, {
        "hub": hub,
        "ts": ts,
        "nonce": nonce,
        "method": method,
        "target": target,
        "body": body,
    }


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    assert e.register().status_code == 200
    e.app.state.settings.dev_mode = True
    return e


def wsk_a():
    return _priv("wsk_a.sig")


def conn_of(e):
    return db.connect(e.path)


def bound(e, hub=None, seq=1, **kw):
    hub = hub or Hub()
    c = conn_of(e)
    try:
        H.accept_hub_card(c, hub.card, NOW, True)
        H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=seq, **kw), NOW, True)
    finally:
        c.close()
    return hub


def go(e, hub, **kw):
    h, req = build(hub, kw.pop("wsk", wsk_a()), **kw)
    return e.c.request(req["method"], req["target"], content=req["body"], headers=h), h, req


# --- accepted / refused by the binding -------------------------------------------------------------------------


def test_forwarded_request_with_binding_is_accepted(env):
    hub = bound(env)
    r, _, _ = go(env, hub)
    assert (r.status_code, r.json()) == (200, {"workspace": WS_A, "status": "active"})


def test_no_binding_is_refused_not_bound(env):
    hub = Hub()
    c = conn_of(env)
    H.accept_hub_card(c, hub.card, NOW, True)
    c.close()
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "not_bound")


def test_binding_of_another_hub_header_is_other_hub(env):
    bound(env)
    rogue = Hub()
    c = conn_of(env)
    H.accept_hub_card(c, rogue.card, NOW, True)
    c.close()
    r, _, _ = go(env, rogue)  # a rogue hub forwarding a real workspace's request
    assert (r.status_code, err(r)) == (403, "other_hub")


def test_binding_for_another_workspace_is_refused_by_the_store(env):
    hub = Hub()
    c = conn_of(env)
    H.accept_hub_card(c, hub.card, NOW, True)
    try:
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, ws=WS_B), NOW, True)
        assert x.value.code == "other_workspace"
        assert H.binding_state(c, WS_A) is None
    finally:
        c.close()
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "not_bound")


def test_unknown_hub_card(env):
    hub = Hub()
    c = conn_of(env)
    H.accept_binding(
        c, WS_A, binding(wsk_a(), hub), NOW, True
    )  # a binding does not carry the hub card
    c.close()
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (401, "unknown_hub")


def test_hub_signature_by_another_key(env):
    hub = bound(env)
    r, _, _ = go(env, hub, hub_op=newkey())
    assert (r.status_code, err(r)) == (401, "bad_hub_signature")


def test_binding_signed_by_a_rogue_key_is_refused(env):
    hub = Hub()
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_A, binding(newkey(), hub, wsk_pub=pub(wsk_a())), NOW, True)
        assert x.value.code == "bad_signature"
    finally:
        c.close()


def test_unbound_ends_publish_and_a_binding_never_comes_back(env):
    hub = bound(env)
    assert go(env, hub)[0].status_code == 200
    c = conn_of(env)
    try:
        H.accept_unbound(c, WS_A, unbound(wsk_a(), hub, seq=1), NOW, True)
        for old in (1,):
            with pytest.raises(H.Refused) as x:
                H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=old), NOW, True)
            assert x.value.code == "unbound"
    finally:
        c.close()
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "not_bound")
    bound(env, hub=hub, seq=2)  # a rejoin at a higher seq is a new binding
    assert go(env, hub)[0].status_code == 200


def test_unbound_by_the_hub_is_refused(env):
    hub = bound(env)
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as x:
            H.accept_unbound(c, WS_A, unbound(hub.op, hub), NOW, True)
        assert x.value.code == "bad_signature"
    finally:
        c.close()
    assert go(env, hub)[0].status_code == 200


def test_binding_state_survives_a_restart(env, tmp_path):
    hub = bound(env)
    from fastapi.testclient import TestClient

    from pubsrv.app import create_app

    app2 = create_app(env.data, HOST, clock=lambda: NOW, dev_mode=True)
    c2 = TestClient(app2, base_url="http://" + HOST)
    h, _req = build(hub, wsk_a())
    assert c2.get(PUBLIC_PATH, headers=h).status_code == 200


def test_binding_signed_by_an_old_wsk_after_rotation_is_refused(env):
    hub = bound(env)
    new = newkey()
    env.sql(
        "UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", proto.b64u(pub(new)), WS_A
    )  # card rotated
    r, _, _ = go(env, hub, wsk=new)
    assert (r.status_code, err(r)) == (403, "not_bound")  # the stored binding names the old key
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as x:  # and the old key can no longer bind
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=2), NOW, True)
        assert x.value.code == "bad_signature"
        H.accept_binding(c, WS_A, binding(new, hub, seq=2), NOW, True)
    finally:
        c.close()
    assert go(env, hub, wsk=new)[0].status_code == 200


# --- the request itself ----------------------------------------------------------------------------------------


def test_replayed_nonce(env):
    hub = bound(env)
    r, h, _req = go(env, hub)
    assert r.status_code == 200
    r2 = env.c.get(PUBLIC_PATH, headers=h)
    assert (r2.status_code, err(r2)) == (401, "replay")


def test_stale_timestamp(env):
    hub = bound(env)
    r, _, _ = go(env, hub, ts=NOW - 200_000)
    assert (r.status_code, err(r)) == (401, "stale_timestamp")


def test_wsk_signature_by_another_key(env):
    hub = bound(env)
    r, _, _ = go(env, hub, wsk=newkey())
    assert (r.status_code, err(r)) == (401, "bad_signature")


def test_hub_request_replayed_on_the_direct_path_and_back(env):
    """L2-2: the hub-path WSK signature never verifies as a v2 12.1 request, and the reverse."""
    hub = bound(env)
    h, _ = build(hub, wsk_a())
    direct = {
        k: v
        for k, v in h.items()
        if k in ("Orch-Workspace", "Orch-Ts", "Orch-Nonce", "Orch-Signature")
    }
    r = env.c.get(PUBLIC_PATH, headers=direct)
    assert (r.status_code, err(r)) == (401, "bad_signature")
    # a genuine direct request, with hub headers added by a hub, is no hub request either
    dh = sign_headers(wsk_a(), WS_A, "GET", HOST, PUBLIC_PATH, ts=NOW)
    forged = {**dh, "Orch-Hub": hub.id, "Orch-Hub-Signature": h["Orch-Hub-Signature"]}
    r = env.c.get(PUBLIC_PATH, headers=forged)
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert (
        env.c.get(
            PUBLIC_PATH, headers=sign_headers(wsk_a(), WS_A, "GET", HOST, PUBLIC_PATH, ts=NOW)
        ).status_code
        == 200
    )


def test_half_a_hub_header_pair_is_malformed(env):
    hub = bound(env)
    h, _ = build(hub, wsk_a())
    for drop in ("Orch-Hub", "Orch-Hub-Signature"):
        r = env.c.get(PUBLIC_PATH, headers={k: v for k, v in h.items() if k != drop})
        assert (r.status_code, err(r)) == (400, "malformed")


@pytest.mark.parametrize("bad", ["", "not base64!", proto.b64u(b'{"a":1,"a":2}'), proto.b64u(b"{")])
def test_garbage_approval_header_is_malformed(env, bad):
    hub = bound(env)
    h, _ = build(hub, wsk_a())
    r = env.c.get(PUBLIC_PATH, headers={**h, "Orch-Owner-Approval": bad})
    assert (r.status_code, err(r)) == (400, "malformed")


def test_non_ascii_host_target_or_method_is_malformed_not_a_crash():
    h = {
        "orch-workspace": WS_A, "orch-ts": str(NOW), "orch-nonce": "00" * 16, "orch-signature": proto.b64u(bytes(64)),
        "orch-hub": "11" * 16, "orch-hub-signature": proto.b64u(bytes(64)),
    }  # fmt: skip
    for method, host, target in (
        ("GET", "pübl.example", "/x"),
        ("GET", "h", "/é"),
        ("GÉT", "h", "/x"),
    ):
        with pytest.raises(H.Refused) as x:
            H.parse_headers(h, method, host, target)
        assert x.value.code == "malformed"
    req = {"method": "GET", "host": "pübl.example", "target": "/x", "headers": h, "body": b""}
    with pytest.raises(H.Refused) as x:
        H.check_hub_publish(req, H.State({}, {}, lambda _: None), auth.MemoryNonces(), NOW, True)
    assert x.value.code == "malformed"


def test_non_ascii_target_at_the_asgi_layer_is_malformed(env):
    """A raw non-ASCII request target (the HTTP client would percent-encode it, a raw socket may not)."""
    import asyncio

    hub = bound(env)
    h, _ = build(hub, wsk_a())
    out = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        out.append(m)

    scope = {
        "type": "http", "method": "GET", "path": "/v1/ws/\u00e9", "raw_path": "/v1/ws/\u00e9".encode(),
        "query_string": b"", "headers": [(k.lower().encode(), v.encode()) for k, v in h.items()],
    }  # fmt: skip
    asyncio.run(env.app(scope, receive, send))
    assert out[0]["status"] == 400
    assert json.loads(out[1]["body"]) == {"error": "malformed"}


def test_dev_hub_is_refused_by_a_real_publish(env):
    hub = bound(env)
    env.app.state.settings.dev_mode = False
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "dev_refused")
    env.app.state.settings.dev_mode = True


def test_real_hub_objects_are_refused_by_a_dev_publish(env):
    hub = Hub(dev=False)
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as x:
            H.accept_hub_card(c, hub.card, NOW, True)
        assert x.value.code == "dev_mismatch"
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, dev=False), NOW, True)
        assert x.value.code == "dev_mismatch"
    finally:
        c.close()


def test_blocked_workspace_is_refused_after_authentication(env):
    hub = bound(env)
    env.sql("UPDATE workspaces SET status='blocked' WHERE workspace_id=?", WS_A)
    r, h, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "workspace_blocked")
    assert err(env.c.get(PUBLIC_PATH, headers=h)) == "replay"  # a refused request spends its nonce


def test_a_hub_cannot_register_a_workspace(env):
    hub = bound(env)
    r, _, _ = go(env, hub, method="POST", target=f"/v1/ws/{WS_A}/register", body=b"{}")
    assert (r.status_code, err(r)) == (404, "not_found")


def test_unknown_workspace(env):
    hub = bound(env)
    env.sql("DELETE FROM workspaces WHERE workspace_id=?", WS_A)
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (401, "unknown_workspace")


# --- public access and the owner's approval --------------------------------------------------------------------


@pytest.fixture
def public(monkeypatch):
    """Make the status route grant public access (no real route does yet, see PUBLIC_ROUTES)."""
    monkeypatch.setattr(H, "PUBLIC_ROUTES", (("GET", PUBLIC_PATH),))


def test_public_access_without_approval_is_refused(env, public):
    hub = bound(env)
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "approval_required")


def test_secret_access_needs_no_approval(env):
    hub = bound(env)
    assert go(env, hub)[0].status_code == 200  # PUBLIC_ROUTES is empty: the charter path


def test_public_access_with_the_owners_approval(env, public):
    hub, owner = bound(env), Owner()
    nonce = os.urandom(16)
    probe = {
        "hub": hub,
        "ts": NOW,
        "nonce": nonce,
        "method": "GET",
        "target": PUBLIC_PATH,
        "body": b"",
    }
    r, _h, _ = go(env, hub, nonce=nonce, approval=owner.approve(probe))
    assert (r.status_code, r.json()["status"]) == (200, "active")


def test_approval_cannot_be_reused_for_a_second_request(env, public):
    hub, owner = bound(env), Owner()
    n1 = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n1, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    assert go(env, hub, nonce=n1, approval=ap)[0].status_code == 200
    r, _, _ = go(env, hub, approval=ap)  # same approval, fresh nonce, correctly WSK-signed
    assert (r.status_code, err(r)) == (403, "bad_approval")
    r, _h, _ = go(
        env, hub, nonce=n1, approval=ap
    )  # the approval with its own request: the nonce is spent
    assert (r.status_code, err(r)) == (401, "replay")


def test_approval_by_another_person(env, public):
    hub = bound(env)
    stranger = Owner(pk=_priv("wsk_b.sig"))
    n = os.urandom(16)
    ap = stranger.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    r, _, _ = go(env, hub, nonce=n, approval=ap)
    assert (r.status_code, err(r)) == (403, "other_person")


def test_approval_for_another_hub(env, public):
    hub, owner = bound(env), Owner()
    n = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""},
        hub_id="22" * 16,
    )
    r, _, _ = go(env, hub, nonce=n, approval=ap)
    assert (r.status_code, err(r)) == (403, "other_hub")


def test_approval_with_a_device_without_decide(env, public):
    hub, owner = bound(env), Owner(scopes=("look",))
    n = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    r, _, _ = go(env, hub, nonce=n, approval=ap)
    assert (r.status_code, err(r)) == (400, "cert_invalid")


def test_approval_of_a_revoked_device(env, public):
    hub, owner = bound(env), Owner()
    env.sql("INSERT INTO hub_revoked_devices VALUES (?,?)", owner.cert["o"]["device_id"], NOW)
    n = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    r, _, _ = go(env, hub, nonce=n, approval=ap)
    assert (r.status_code, err(r)) == (403, "revoked")


def test_approval_added_or_stripped_after_the_host_signed_is_bad_signature(env, public):
    hub, owner = bound(env), Owner()
    n = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    h, _ = build(hub, wsk_a(), nonce=n, approval=ap)
    stripped = {k: v for k, v in h.items() if k != "Orch-Owner-Approval"}
    r = env.c.get(PUBLIC_PATH, headers=stripped)
    assert (r.status_code, err(r)) == (401, "bad_signature")
    h2, _ = build(hub, wsk_a())  # signed without an approval; the hub attaches one
    r = env.c.get(PUBLIC_PATH, headers={**h2, "Orch-Owner-Approval": h["Orch-Owner-Approval"]})
    assert (r.status_code, err(r)) == (401, "bad_signature")


def test_approval_on_a_non_public_request_is_bad_approval(env):
    hub, owner = bound(env), Owner()
    n = os.urandom(16)
    ap = owner.approve(
        {"hub": hub, "ts": NOW, "nonce": n, "method": "GET", "target": PUBLIC_PATH, "body": b""}
    )
    r, _, _ = go(env, hub, nonce=n, approval=ap)  # an approval that is present is always verified
    assert (r.status_code, err(r)) == (403, "bad_approval")


# --- store and migration ---------------------------------------------------------------------------------------


def test_binding_store_transitions(env):
    hub = Hub()
    c = conn_of(env)
    try:
        H.accept_hub_card(c, hub.card, NOW, True)
        b1 = binding(wsk_a(), hub, seq=1)
        assert H.accept_binding(c, WS_A, b1, NOW, True)["status"] == "bound"
        assert H.accept_binding(c, WS_A, b1, NOW, True)["binding_seq"] == 1  # idempotent
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=1, mode="full"), NOW, True)
        assert x.value.code == "binding_conflict"
        assert (
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=3, mode="full"), NOW, True)[
                "binding_seq"
            ]
            == 3
        )
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_A, binding(wsk_a(), hub, seq=2), NOW, True)
        assert x.value.code == "stale_binding"
        # a failed update leaves the stored state untouched
        assert H.binding_state(c, WS_A)["binding_seq"] == 3
    finally:
        c.close()


def test_binding_for_a_workspace_without_a_card_is_unknown_workspace(env):
    hub = Hub()
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as x:
            H.accept_binding(c, WS_B, binding(wsk_a(), hub, ws=WS_B), NOW, True)
        assert x.value.code == "unknown_workspace"
    finally:
        c.close()


def test_hub_card_rotation_and_rollback(env):
    hub = Hub()
    c = conn_of(env)
    try:
        H.accept_hub_card(c, hub.card, NOW, True)
        # same hub id needs the same root: build a rotated op cert + card under the same root
        nxt = Hub.__new__(Hub)
        nxt.root, nxt.op, nxt.id = hub.root, newkey(), hub.id
        op_cert = signed(
            hub.root,
            H.LABELS["sig_hub_op_cert"],
            {
                "v": 2, "suite": 2, "hv": 0, "kind": "hub.op_cert", "hub_id": hub.id,
                "cert_id": os.urandom(16).hex(), "op_seq": 2, "hk_op_pub": proto.b64u(pub(nxt.op)),
                "issued_ms": NOW - 500, "expires_ms": NOW + 10**9, "dev": True,
            },
        )  # fmt: skip
        o = dict(hub.card["o"], card_seq=1, issued_ms=NOW - 500)
        nxt.card = signed(nxt.op, H.LABELS["sig_hub_card"], o, op_cert=op_cert)
        H.accept_hub_card(c, nxt.card, NOW, True)
        with pytest.raises(H.Refused) as x:  # the old HK_op cannot roll the rotation back
            H.accept_hub_card(c, hub.card, NOW, True)
        assert x.value.code == "stale_op_cert"
    finally:
        c.close()


def test_op_cert_revocation_stops_the_hub_at_once(env):
    hub = bound(env)
    assert go(env, hub)[0].status_code == 200
    cert_id = hub.card["op_cert"]["o"]["cert_id"]
    rev = signed(
        hub.root,
        H.LABELS["sig_hub_op_revoked"],
        {"v": 2, "suite": 2, "hv": 0, "kind": "hub.op_revoked", "hub_id": hub.id, "cert_id": cert_id,
         "revoked_ms": NOW, "dev": True},
    )  # fmt: skip
    c = conn_of(env)
    try:
        H.accept_op_revoked(c, rev, NOW)
    finally:
        c.close()
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "revoked")


def test_migration_from_schema_2_keeps_data_and_adds_the_hub_tables(tmp_path):
    path = db.prepare_dir(str(tmp_path / "d"))
    conn = sqlite3.connect(path)
    conn.executescript(db.SCHEMA)
    for t in ("hub_bindings", "hub_cards", "hub_op_revoked", "hub_revoked_devices"):
        conn.execute(f"DROP TABLE {t}")
    conn.execute("INSERT INTO owners VALUES ('p', 1)")
    conn.execute("PRAGMA user_version=2")
    conn.commit()
    conn.close()
    db.init(path)
    conn = db.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION == 3
    assert conn.execute("SELECT person_id FROM owners").fetchone()[0] == "p"
    assert conn.execute("SELECT count(*) FROM hub_bindings").fetchone()[0] == 0
    conn.close()
    db.init(path)  # idempotent


def test_schema_1_is_still_refused(tmp_path):
    path = db.prepare_dir(str(tmp_path / "d"))
    conn = sqlite3.connect(path)
    conn.executescript(db.SCHEMA)
    conn.execute("PRAGMA user_version=1")
    conn.commit()
    conn.close()
    with pytest.raises(db.SchemaError):
        db.init(path)


def test_direct_path_unchanged_for_a_bound_workspace(env):
    """Until H6 a bound workspace may still publish directly (11.2 'Direct requests')."""
    bound(env)
    r = env.c.get(
        PUBLIC_PATH, headers=sign_headers(wsk_a(), WS_A, "GET", HOST, PUBLIC_PATH, ts=NOW)
    )
    assert r.status_code == 200


def test_json_body_is_covered_by_the_hub_path_signature(env):
    hub = bound(env)
    body = json.dumps({"x": 1}).encode()
    h, req = build(hub, wsk_a(), method="POST", target=f"/v1/ws/{WS_A}/nothing", body=body)
    r = env.c.post(req["target"], content=b'{"x":2}', headers=h)
    assert (r.status_code, err(r)) == (401, "bad_signature")
