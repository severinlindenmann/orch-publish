"""GET /v2/hub/releases (orch-core #900, protocol.md 10.6): release metadata for the calling hub's full-mode
workspaces. The contract vectors are run in test_hub_path_vectors.py; this file covers the data layer and the route."""

import pytest

from pubsrv import hub_admin_read as R
from pubsrv import hub_path as H
from tests.hub_helpers import Hub, sign, unbound
from tests.test_hub_path_http import bound, conn_of, wsk_a
from tests.test_publish_api_auth import NOW, WS_A, WS_B, Env

SECRETS = ("TICKET-SECRET", "HASH-SECRET")


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
        sid, ws, SECRETS[0], kind, SECRETS[1], exp, state, nbytes, created,
    )  # fmt: skip


def read(e, hub, target="/v2/hub/releases", method="GET", ts=NOW, key=None, sig=None):
    msg = R.signed_bytes(hub.id, ts, method, target)
    h = {
        "Orch-Hub": hub.id,
        "Orch-Hub-Ts": str(ts),
        "Orch-Hub-Signature": sig or sign(key or hub.op, msg),
    }
    return e.c.request(method, target, headers=h)


def full(e, **kw):
    return bound(e, mode="full", **kw)


def test_lists_metadata_only(env):
    hub = full(env)
    share(env, "a" * 32, kind="once", created=2)
    share(env, "b" * 32, state="revoked", created=1)
    share(env, "c" * 32, state="staged", created=3)  # never published: not a release
    r = read(env, hub)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    rows = r.json()["releases"]
    assert [x["release_id"] for x in rows] == ["b" * 32, "a" * 32]
    assert all(set(x) == set(R.FIELDS) and x["public_url"] is None for x in rows)
    assert rows[0]["revoked"] is True and rows[0]["bytes"] == 7 and rows[1]["kind"] == "once"
    assert not any(s in r.text for s in SECRETS)


def test_workspace_filter_and_out_of_scope(env):
    hub = full(env)
    share(env, "a" * 32)
    assert len(read(env, hub, f"/v2/hub/releases?workspace={WS_A}").json()["releases"]) == 1
    r = read(env, hub, f"/v2/hub/releases?workspace={WS_B}")
    assert (r.status_code, r.json()) == (403, {"error": "not_bound"})


def test_head_has_no_body(env):
    hub = full(env)
    r = read(env, hub, method="HEAD")
    assert r.status_code == 200 and r.content == b""


def test_live_share_past_expiry_reads_expired(env):
    hub = full(env)
    share(env, "a" * 32, exp=NOW - 1)
    assert read(env, hub).json()["releases"][0]["state"] == "expired"


def test_selective_binding_is_out_of_scope(env):
    hub = bound(env)  # default mode: selective
    share(env, "a" * 32)
    assert read(env, hub).json() == {"releases": []}
    assert read(env, hub, f"/v2/hub/releases?workspace={WS_A}").status_code == 403


def test_other_hub_sees_nothing(env):
    full(env)
    share(env, "a" * 32)
    other = Hub()
    c = conn_of(env)
    try:
        H.accept_hub_card(c, other.card, NOW, True)
    finally:
        c.close()
    assert read(env, other).json() == {"releases": []}
    assert read(env, other, f"/v2/hub/releases?workspace={WS_A}").status_code == 403


def test_unbound_workspace_drops_out(env):
    hub = full(env)
    share(env, "a" * 32)
    c = conn_of(env)
    try:
        H.accept_unbound(c, WS_A, unbound(wsk_a(), hub, seq=2), NOW, True)
    finally:
        c.close()
    assert read(env, hub).json() == {"releases": []}


def test_binding_under_rotated_wsk_does_not_count(env):
    hub = full(env)
    share(env, "a" * 32)
    env.sql("UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", "A" * 87, WS_A)
    assert read(env, hub).json() == {"releases": []}


def test_auth_failures(env):
    hub = full(env)
    share(env, "a" * 32)
    code = lambda r: (r.status_code, r.json()["error"])
    assert code(read(env, hub, key=Hub().op)) == (401, "bad_hub_signature")
    assert code(read(env, hub, ts=NOW - 121_000)) == (401, "stale_timestamp")
    assert code(read(env, Hub())) == (401, "unknown_hub")
    assert code(read(env, hub, "/v2/hub/releases?workspace=" + WS_A.upper())) == (400, "malformed")
    assert code(read(env, hub, "/v2/hub/releases?state=live")) == (400, "malformed")
    assert code(read(env, hub, "/v2/hub/releases?workspace=" + WS_A, sig=sign(hub.op, b"x"))) == (
        401,
        "bad_hub_signature",
    )
    # no headers at all
    assert code(env.c.get("/v2/hub/releases")) == (400, "malformed")


def test_signature_does_not_cover_other_target(env):
    hub = full(env)
    msg = R.signed_bytes(hub.id, NOW, "GET", "/v2/hub/releases")
    h = {"Orch-Hub": hub.id, "Orch-Hub-Ts": str(NOW), "Orch-Hub-Signature": sign(hub.op, msg)}
    r = env.c.get(f"/v2/hub/releases?workspace={WS_A}", headers=h)
    assert (r.status_code, r.json()["error"]) == (401, "bad_hub_signature")


def test_revoked_op_cert_is_refused(env):
    hub = full(env)
    cert_id = hub.card["op_cert"]["o"]["cert_id"]
    env.sql("INSERT INTO hub_op_revoked VALUES (?,?,?)", hub.id, cert_id, NOW)
    assert read(env, hub).status_code == 401


def test_write_methods_are_refused(env):
    hub = full(env)
    r = env.c.put("/v2/hub/releases", content=b"{}")
    assert r.status_code == 405 and r.headers["allow"] == "GET, HEAD"
    assert read(env, hub, method="POST").status_code == 405


def test_rows_outside_scope_are_never_emitted(env):
    hub = full(env)
    share(env, "a" * 32)
    share(env, "b" * 32, ws=WS_B)  # no binding for WS_B
    c = conn_of(env)
    try:
        with pytest.raises(H.Refused) as e:
            R.list_releases(c, [WS_A, WS_B][:1], NOW, WS_B)
        assert e.value.code == "not_bound"
    finally:
        c.close()
    assert [x["workspace_id"] for x in read(env, hub).json()["releases"]] == [WS_A]


# --- the contract vectors through the REAL route ------------------------------------------------------------------

import json
import pathlib

from pubsrv import db

_VEC = json.loads((pathlib.Path(__file__).parent / "vectors/vectors_hub.json").read_text())
_ROUTE_CASES = [
    c
    for c in _VEC["cases"]
    if c["check"] == "admin_read"
    and c["args"]["request"]["target"].partition("?")[0] == R.ROUTE
    and c["args"]["request"]["method"] in ("GET", "HEAD")
    and "#" not in c["args"]["request"]["target"]
]


def test_route_cases_are_most_of_them():
    assert len(_ROUTE_CASES) >= 30


@pytest.mark.parametrize("case", _ROUTE_CASES, ids=lambda c: c["name"])
def test_vector_through_the_route(case, tmp_path):
    a = case["args"]
    e = Env(tmp_path)
    e.now = a["now_ms"]
    e.app.state.settings.dev_mode = (
        True  # stored with the dev marker; flipped below for the real-verifier case
    )
    conn = db.connect(e.path)
    try:
        for ws, card in a["cards"].items():
            conn.execute(
                "INSERT INTO workspaces(workspace_id, wsk_pub, owner_person_id, owner_pk, delegation_json,"
                " created_ms, updated_ms) VALUES (?,?,?,?,?,0,0)",
                (ws, card["wsk_pub"], card["owner_person_id"], "pk", "{}"),
            )
            conn.execute(
                "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, state, bytes, created_ms)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (ws[:30] + "00", ws, SECRETS[0], "secret", SECRETS[1], 2**50, "live", 1, 1),
            )
        H.accept_hub_card(conn, a["hub_card"], a["now_ms"], True)
        for ws, steps in a.get("bindings", {}).items():
            for st in steps:
                if "binding" in st:
                    H.accept_binding(conn, ws, st["binding"], a["now_ms"], True)
                else:
                    H.accept_unbound(conn, ws, st["unbound"], a["now_ms"], True)
        for cert in a.get("revoked_op_certs", []):
            conn.execute(
                "INSERT INTO hub_op_revoked VALUES (?,?,?)", (a["hub_id"], cert, a["now_ms"])
            )
    finally:
        conn.close()
    e.app.state.settings.dev_mode = a.get("dev_mode", True)
    r = e.c.request(a["request"]["method"], a["request"]["target"], headers=a["request"]["headers"])
    if "error" in case["expect"]:
        code = case["expect"]["error"]
        assert r.status_code == H.STATUS.get(code, 400)
        if a["request"]["method"] == "GET":  # a HEAD response has no body
            assert r.json()["error"] == code
        return
    assert r.status_code == 200
    if a["request"]["method"] == "GET":
        want = case["expect"]["ok"]["workspaces"]
        named = a["request"]["target"].partition("workspace=")[2]
        got = sorted(x["workspace_id"] for x in r.json()["releases"])
        assert got == (want if not named else [w for w in want if w == named])
