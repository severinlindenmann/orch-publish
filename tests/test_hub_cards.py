"""PUT /v2/hub/cards/{ws}: a workspace is admitted through the card the hub carried (card_put), V3-D36 / R5a."""

import copy
import json

import pytest

from pubsrv import relay_proto as proto
from tests.test_publish_api_auth import CARD1, CARD2, PK_B64, WS_A, WS_B, Env


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
