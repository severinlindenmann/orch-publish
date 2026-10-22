"""Hub console admin read model (orch-core #900): release metadata, scoped to the calling hub's bound workspaces."""

import pytest

from pubsrv import hub_admin_read as R
from pubsrv import hub_path as H
from tests.test_hub_path_http import Hub, bound, conn_of, unbound, wsk_a
from tests.test_publish_api_auth import NOW, WS_A, WS_B, Env


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    assert e.register().status_code == 200
    e.app.state.settings.dev_mode = True
    return e


def share(e, sid, ws=WS_A, kind="secret", state="live", exp=NOW + 10**6, created=1, nbytes=7):
    e.sql(
        "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, state, bytes, created_ms)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        sid, ws, "TICKET-SECRET", kind, "HASH-SECRET", exp, state, nbytes, created,
    )  # fmt: skip


def lst(e, hub_id, **kw):
    c = conn_of(e)
    try:
        return R.list_releases(c, hub_id, NOW, **kw)
    finally:
        c.close()


def test_lists_metadata_only(env):
    hub = bound(env)
    share(env, "a" * 32, kind="once", created=2)
    share(env, "b" * 32, state="revoked", created=1)
    share(env, "c" * 32, state="staged", created=3)  # never published: not a release
    out = lst(env, hub.id)
    assert [r["release_id"] for r in out["releases"]] == ["b" * 32, "a" * 32]
    first = out["releases"][0]
    assert set(first) == set(R.FIELDS)
    assert first["revoked"] is True and first["public_url"] is None and first["bytes"] == 7
    blob = repr(out)
    assert "SECRET" not in blob and "token" not in blob and "ticket" not in blob


def test_live_share_past_expiry_reads_expired(env):
    hub = bound(env)
    share(env, "a" * 32, exp=NOW - 1)
    assert lst(env, hub.id)["releases"][0]["state"] == "expired"


def test_scope_is_workspaces_bound_to_this_hub(env):
    hub = bound(env)
    share(env, "a" * 32)
    other = Hub()
    assert lst(env, other.id) == {"releases": []}
    with pytest.raises(H.Refused) as e:
        lst(env, other.id, workspace=WS_A)
    assert e.value.code == "not_bound"
    with pytest.raises(H.Refused):
        lst(env, hub.id, workspace=WS_B)


def test_unbound_workspace_drops_out(env):
    hub = bound(env)
    share(env, "a" * 32)
    c = conn_of(env)
    try:
        H.accept_unbound(c, WS_A, unbound(wsk_a(), hub, seq=2), NOW, True)
    finally:
        c.close()
    assert lst(env, hub.id) == {"releases": []}


def test_binding_under_rotated_wsk_does_not_count(env):
    hub = bound(env)
    share(env, "a" * 32)
    env.sql("UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", "A" * 87, WS_A)
    assert lst(env, hub.id) == {"releases": []}
