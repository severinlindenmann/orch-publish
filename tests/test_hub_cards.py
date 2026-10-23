"""PUT /v2/hub/cards/{ws}: a workspace is admitted through the card the hub carried (card_put), V3-D36 / R5a."""

import copy
import io
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pubsrv import db
from pubsrv import relay_proto as proto
from tests.test_publish_api_auth import CARD1, CARD2, NOW, PK_B64, WS_A, WS_B, Env, _priv


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    return e


def put(e, ws, card=CARD1, pk=PK_B64, extra=None):
    body = {"card": card, "pk_pub": pk, **(extra or {})}
    return e.c.put(f"/v2/hub/cards/{ws}", content=json.dumps(body).encode())


def rows(e):
    return e.sql("SELECT workspace_id, owner_person_id, status FROM workspaces")


def test_card_admits_a_prebound_workspace(env):
    r = put(env, WS_A)
    assert (r.status_code, r.json()) == (200, {"ok": True})
    assert rows(env)[0][0] == WS_A


def test_same_card_again_and_a_newer_card_are_noops(env):
    assert put(env, WS_A).status_code == 200
    assert put(env, WS_A).status_code == 200
    assert put(env, WS_A, CARD2).status_code == 200  # card_seq 2, same delegation
    assert len(rows(env)) == 1


def test_not_prebound_is_unknown_workspace(tmp_path):
    e = Env(tmp_path)
    e.allow(ws=None)
    r = put(e, WS_A)
    assert (r.status_code, r.json()["error"]) == (401, "unknown_workspace")
    assert rows(e) == []


def test_owner_not_on_allowlist_is_refused_and_leaves_nothing(tmp_path):
    e = Env(tmp_path)
    r = put(e, WS_A)
    assert r.status_code == 401 and rows(e) == []


def test_card_for_another_workspace_path(env):
    env.allow(ws=WS_B)
    r = put(env, WS_B)
    assert (r.status_code, r.json()["error"]) == (403, "other_workspace")
    assert rows(env) == []


def test_forged_card_signature_is_refused(env):
    bad = copy.deepcopy(CARD1)
    bad["sig"] = proto.b64u(bytes(64))
    r = put(env, WS_A, bad)
    assert r.status_code == 401 and r.json()["error"] == "bad_signature"
    assert rows(env) == []


def test_wrong_owner_key_is_refused(env):
    r = put(env, WS_A, pk=proto.b64u(b"\x04" + bytes(64)))
    assert r.status_code == 400 and rows(env) == []


def test_delegation_never_changes(env):
    assert put(env, WS_A).status_code == 200
    env.sql("UPDATE workspaces SET delegation_json='{}' WHERE workspace_id=?", WS_A)
    r = put(env, WS_A)
    assert (r.status_code, r.json()["error"]) == (409, "delegation_changed")


def test_blocked_workspace_stays_blocked(env):
    assert put(env, WS_A).status_code == 200
    env.sql("UPDATE workspaces SET status='blocked' WHERE workspace_id=?", WS_A)
    r = put(env, WS_A)
    assert (r.status_code, r.json()["error"]) == (403, "workspace_blocked")


@pytest.mark.parametrize("extra", [{"x": 1}])
def test_extra_field_and_bad_shapes_are_malformed(env, extra):
    assert put(env, WS_A, extra=extra).status_code == 400
    assert env.c.put(f"/v2/hub/cards/{WS_A}", content=b"[]").status_code == 400
    assert env.c.put(f"/v2/hub/cards/{WS_A}", content=b"not json").status_code == 400
    assert env.c.get(f"/v2/hub/cards/{WS_A}").status_code == 405
    assert env.c.put("/v2/hub/cards/nothex", content=b"{}").status_code == 404
    assert rows(env) == []


def sign_card(o):
    msg = proto.L["sig_card_wsk"] + proto.cj(o)
    r, s = decode_dss_signature(_priv("wsk_a.sig").sign(msg, ec.ECDSA(hashes.SHA256())))
    return proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def unbind(e, ws=WS_A):
    from pubsrv import cli

    conn = db.connect(e.path)
    try:
        cli._unbind(conn, ws, io.StringIO())
    finally:
        conn.close()
    e.allow()  # the admin pre-binds it again


def test_replay_of_the_same_card_after_unbind_is_refused(env):
    assert put(env, WS_A).status_code == 200
    unbind(env)
    r = put(env, WS_A)
    assert (r.status_code, r.json()["error"]) == (409, "stale_card")
    assert rows(env) == []


def test_older_card_after_unbind_is_refused_and_a_fresh_one_accepted(env):
    assert put(env, WS_A, CARD2).status_code == 200  # card_seq 2 is the floor
    unbind(env)
    assert put(env, WS_A, CARD1).json()["error"] == "stale_card"  # card_seq 1 < 2
    fresh = copy.deepcopy(CARD2)
    fresh["o"]["card_seq"] = 3
    fresh["sig"] = sign_card(fresh["o"])
    assert put(env, WS_A, fresh).status_code == 200


def test_older_card_while_admitted_is_refused(env):
    assert put(env, WS_A, CARD2).status_code == 200
    assert put(env, WS_A, CARD1).json()["error"] == "stale_card"


def test_a_card_too_old_cannot_admit(tmp_path):
    e = Env(tmp_path)
    e.allow()
    e.now = NOW + 31 * 24 * 3600 * 1000
    r = put(e, WS_A)
    assert (r.status_code, r.json()["error"]) == (409, "stale_card")
    assert rows(e) == []
