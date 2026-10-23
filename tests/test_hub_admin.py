"""Hub push endpoints (orch-core #899): PUT /v2/hub/card, /v2/hub/op-revoked, /v2/hub/bindings/{workspace_id}."""

import json
import os

import pytest

from pubsrv import hub_admin
from pubsrv import hub_path as H
from pubsrv import relay_proto as proto
from tests.test_hub_path_http import Hub, binding, err, go, newkey, pub, signed, unbound, wsk_a
from tests.test_publish_api_auth import NOW, WS_A, WS_B, Env


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    assert e.register().status_code == 200
    e.app.state.settings.dev_mode = True
    return e


def put(e, path, obj, raw=None):
    body = raw if raw is not None else json.dumps(obj).encode()
    return e.c.put(path, content=body)


def card(e, hub):
    return put(e, "/v2/hub/card", hub.card)


def bind(e, obj, ws=WS_A):
    return put(e, f"/v2/hub/bindings/{ws}", obj)


def rotated(hub, op_seq=2, card_seq=1):
    nxt = Hub.__new__(Hub)
    nxt.root, nxt.op, nxt.id = hub.root, newkey(), hub.id
    op_cert = signed(
        hub.root, H.LABELS["sig_hub_op_cert"],
        {"v": 2, "suite": 2, "hv": 0, "kind": "hub.op_cert", "hub_id": hub.id, "cert_id": os.urandom(16).hex(),
         "op_seq": op_seq, "hk_op_pub": proto.b64u(pub(nxt.op)), "issued_ms": NOW - 500, "expires_ms": NOW + 10**9,
         "dev": True},
    )  # fmt: skip
    nxt.card = signed(nxt.op, H.LABELS["sig_hub_card"], dict(hub.card["o"], card_seq=card_seq, issued_ms=NOW - 500),
                      op_cert=op_cert)  # fmt: skip
    return nxt


def revocation(hub, cert_id):
    return signed(
        hub.root, H.LABELS["sig_hub_op_revoked"],
        {"v": 2, "suite": 2, "hv": 0, "kind": "hub.op_revoked", "hub_id": hub.id, "cert_id": cert_id,
         "revoked_ms": NOW, "dev": True},
    )  # fmt: skip


def test_first_card_is_stored_and_repush_is_a_noop(env):
    hub = Hub()
    r = card(env, hub)
    assert (r.status_code, r.json()) == (200, {"ok": True})
    assert card(env, hub).status_code == 200
    assert len(env.sql("SELECT * FROM hub_cards")) == 1


def test_card_rotation_under_op_seq_and_rollback_refused(env):
    hub = Hub()
    assert card(env, hub).status_code == 200
    nxt = rotated(hub)
    assert card(env, nxt).status_code == 200
    r = card(env, hub)
    assert (r.status_code, err(r)) == (409, "stale_op_cert")


def test_card_not_signed_by_its_root_is_refused(env):
    hub = Hub()
    other = Hub()
    forged = dict(hub.card, op_cert=other.card["op_cert"])  # op cert of another hub root
    r = put(env, "/v2/hub/card", forged)
    assert r.status_code in (400, 401, 403)
    assert env.sql("SELECT * FROM hub_cards") == []


def test_card_claiming_a_hub_id_of_another_root_is_refused(env):
    hub, other = Hub(), Hub()
    assert card(env, hub).status_code == 200
    o = dict(other.card["o"], hub_id=hub.id)  # other root, victim's hub id
    forged = signed(other.op, H.LABELS["sig_hub_card"], o, op_cert=other.card["op_cert"])
    r = put(env, "/v2/hub/card", forged)
    assert (r.status_code, err(r)) == (400, "hub_id_mismatch")
    held = env.sql("SELECT card_json FROM hub_cards WHERE hub_id=?", hub.id)
    assert len(held) == 1 and json.loads(held[0]["card_json"]) == hub.card


def test_dev_mismatch_and_dev_refused(env):
    r = card(env, Hub(dev=False))  # the dev publish refuses a real card
    assert (r.status_code, err(r)) == (403, "dev_mismatch")
    env.app.state.settings.dev_mode = False  # a real publish refuses a dev card
    r = card(env, Hub(dev=True))
    assert (r.status_code, err(r)) == (403, "dev_refused")
    assert env.sql("SELECT * FROM hub_cards") == []


def test_revocation_push_stops_the_hub_and_is_idempotent(env):
    hub = Hub()
    assert card(env, hub).status_code == 200
    rev = revocation(hub, hub.card["op_cert"]["o"]["cert_id"])
    assert put(env, "/v2/hub/op-revoked", rev).status_code == 200
    assert put(env, "/v2/hub/op-revoked", rev).status_code == 200
    assert len(env.sql("SELECT * FROM hub_op_revoked")) == 1
    r = card(env, hub)  # a revoked op cert cannot be pushed again
    assert (r.status_code, err(r)) == (403, "revoked")


def test_revocation_for_an_unknown_hub_or_by_another_root_is_refused(env):
    hub, other = Hub(), Hub()
    rev = revocation(hub, hub.card["op_cert"]["o"]["cert_id"])
    r = put(env, "/v2/hub/op-revoked", rev)
    assert (r.status_code, err(r)) == (401, "unknown_hub")
    assert card(env, hub).status_code == 200
    forged = signed(other.root, H.LABELS["sig_hub_op_revoked"], dict(rev["o"]))
    r = put(env, "/v2/hub/op-revoked", forged)
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert env.sql("SELECT * FROM hub_op_revoked") == []


def test_binding_push_accepted_and_idempotent(env):
    hub = Hub()
    assert card(env, hub).status_code == 200
    b = binding(wsk_a(), hub)
    assert bind(env, b).json() == {"ok": True}
    assert bind(env, b).status_code == 200
    assert env.sql("SELECT status, binding_seq FROM hub_bindings")[0]["status"] == "bound"
    r = bind(env, binding(wsk_a(), hub, mode="full"))
    assert (r.status_code, err(r)) == (409, "binding_conflict")


def test_binding_of_another_workspace_is_refused(env):
    hub = Hub()
    b_for_b = binding(wsk_a(), hub, ws=WS_B)
    r = bind(env, b_for_b, ws=WS_A)  # path says A, object says B
    assert (r.status_code, err(r)) == (403, "other_workspace")
    r = bind(env, b_for_b, ws=WS_B)  # B has no workspace card here
    assert (r.status_code, err(r)) == (401, "unknown_workspace")
    assert env.sql("SELECT * FROM hub_bindings") == []


def test_binding_under_a_wsk_that_is_not_the_cards_is_refused(env):
    hub = Hub()
    rogue = newkey()
    r = bind(env, binding(rogue, hub))
    assert (r.status_code, err(r)) == (401, "bad_signature")
    r = bind(env, binding(wsk_a(), hub, wsk_pub=pub(rogue)))  # names a key that is not the card's
    assert r.status_code in (400, 401, 403)
    assert env.sql("SELECT * FROM hub_bindings") == []


def test_binding_from_an_old_wsk_after_rotation_is_refused(env):
    hub = Hub()
    new = newkey()
    env.sql("UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", proto.b64u(pub(new)), WS_A)
    r = bind(env, binding(wsk_a(), hub))
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert bind(env, binding(new, hub)).status_code == 200


def test_unbound_push_evicts_end_to_end_and_cannot_be_resurrected(env):
    hub = Hub()
    assert card(env, hub).status_code == 200
    assert bind(env, binding(wsk_a(), hub, seq=2)).status_code == 200
    assert go(env, hub)[0].status_code == 200  # forwarded request admitted
    u = unbound(wsk_a(), hub, seq=2)
    assert bind(env, u).status_code == 200
    assert bind(env, u).status_code == 200  # idempotent
    r, _, _ = go(env, hub)
    assert (r.status_code, err(r)) == (403, "not_bound")
    for seq in (1, 2):  # the same or an older binding, pushed again, never comes back
        r = bind(env, binding(wsk_a(), hub, seq=seq))
        assert (r.status_code, err(r)) == (409, "unbound")
    r = bind(env, unbound(wsk_a(), hub, seq=1))
    assert (r.status_code, err(r)) == (409, "stale_binding")  # sequence is monotonic
    assert go(env, hub)[0].status_code == 403
    assert bind(env, binding(wsk_a(), hub, seq=3)).status_code == 200  # a rejoin is a higher seq
    assert go(env, hub)[0].status_code == 200


def test_unbound_signed_by_the_hub_is_refused(env):
    hub = Hub()
    assert card(env, hub).status_code == 200
    assert bind(env, binding(wsk_a(), hub)).status_code == 200
    r = bind(env, unbound(hub.op, hub))
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert go(env, hub)[0].status_code == 200


@pytest.mark.parametrize("path", ["/v2/hub/card", "/v2/hub/op-revoked", f"/v2/hub/bindings/{WS_A}"])
@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b"null",
        b'{"o":1,"sig":2}',
        b'{"o":{},"o":{}}',
        b'{"a":1.5}',
        b"\xff\xfe",
        b"{}",
    ],
)
def test_malformed_bodies_are_refused_without_detail(env, path, raw):
    r = env.c.put(path, content=raw)
    assert r.status_code == 400 and r.json() == {"error": "malformed"}
    assert env.sql("SELECT * FROM hub_cards") == [] and env.sql("SELECT * FROM hub_bindings") == []


def test_oversize_is_refused_before_parsing(env):
    r = env.c.put("/v2/hub/card", content=b"{" + b" " * (hub_admin.MAX_BODY + 1))
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    r = env.c.put("/v2/hub/card", content=b" " * hub_admin.MAX_BODY + b"{}")
    assert r.status_code == 413


def test_unknown_kind_and_wrong_routes(env):
    hub = Hub()
    r = bind(env, hub.card)  # a card at the binding route
    assert (r.status_code, err(r)) == (400, "malformed")
    r = put(env, "/v2/hub/card", binding(wsk_a(), hub))  # a binding at the card route
    assert r.status_code == 400
    assert env.c.get("/v2/hub/card").status_code == 405
    assert env.c.put("/v2/hub/other", content=b"{}").status_code == 404
    assert env.c.put("/v2/hub/bindings/XYZ", content=b"{}").status_code == 404
    assert env.c.put("/v2/hub/card/", content=b"{}").status_code == 404


def test_internal_errors_leak_nothing(env, monkeypatch):
    def boom(*a):
        raise RuntimeError("secret detail /etc/passwd")

    monkeypatch.setattr(H, "accept_hub_card", boom)
    r = card(env, Hub())
    assert (r.status_code, r.json()) == (500, {"error": "internal"})
    assert "secret" not in r.text


def test_the_signed_routes_still_need_a_signature(env):
    assert env.c.get(f"/v1/ws/{WS_A}/status").status_code == 400


@pytest.mark.parametrize("flag,want", [([], False), (["--dev-mode"], True)])
def test_serve_dev_mode_flag_reaches_the_app(monkeypatch, tmp_path, flag, want):
    import uvicorn

    from pubsrv import app as app_mod
    from pubsrv import cli

    seen = {}
    real = app_mod.create_app

    def spy(data, host, clock=None, dev_mode=False):
        a = real(data, host, clock, dev_mode)
        seen["dev"] = a.state.settings.dev_mode
        return a

    monkeypatch.setattr(app_mod, "create_app", spy)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    assert cli.main(["serve", "--data", str(tmp_path / "d"), *flag]) == 0
    assert seen["dev"] is want
