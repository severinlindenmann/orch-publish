"""Signed-request auth for pubsrv (protocol-v2 12.1, design 2.5/2.6/3). Fake keys only (vectors)."""

import hashlib
import json
import os
import pathlib
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from pubsrv import auth, cli, db, hub_path
from pubsrv import relay_proto as proto
from pubsrv.app import create_app
from tests.hub_helpers import Hub, binding, build

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = json.loads((ROOT / "tests/vectors/publish_v2.json").read_text())
VENDORED_SHA256 = "4b7cd9aa524b5d808859b9cff54ea3c025dab5791c13966683e9f88657b9c1b0"
HOST = "127.0.0.1:8103"
NOW = 1_790_000_000_000
WS_A = VEC["ids"]["workspace_a"]
WS_B = VEC["ids"]["workspace_b"]
PERSON = VEC["ids"]["person_alice"]
CARD1 = VEC["card"]["card"]
CARD2 = VEC["card"]["card_seq_2"]
DELEG1 = CARD1["delegation"]
PK = bytes.fromhex(VEC["card"]["cases"][0]["owner_pk_pub"])
PK_B64 = proto.b64u(PK)


def _priv(name):
    """Same derivation as the protocol reference (suite 2 `_priv`)."""
    n = proto.P256_N
    scalar = int.from_bytes(bytes.fromhex(VEC["keys"][name]["seed"]), "big") % (n - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def make_delegation(**over):
    """A delegation signed by the owner PK of the vectors (core certs.make_delegation shape)."""
    o = dict(DELEG1["o"])
    o.update(over)
    msg = proto.L["sig_ws_delegation"] + proto.cj(o)
    r, s = decode_dss_signature(_priv("person_alice.sig").sign(msg, ec.ECDSA(hashes.SHA256())))
    return {"o": o, "sig": proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


HUB = (
    Hub()
)  # the one hub of these tests: its card and the workspaces' bindings are what pubsrv holds


def sign_headers(priv, ws, method, host, target, body=b"", ts=NOW, nonce=None):
    """The headers of a hub-path request (11.1): the host's signature plus the hub's two (V3-D36: the only kind)."""
    return build(HUB, priv, method, target, body, ts=ts, nonce=nonce, ws=ws, host=host)[0]


class Env:
    """pubsrv with a clock, a data dir and a hub. Every request is a hub-path request (V3-D36): ``send`` builds it the
    way the host does and the hub forwards it; ``register`` admits a workspace through its card (``card_put``),
    ``bind`` gives the hub's card and the workspace's binding, ``admit`` does both."""

    def __init__(self, tmp_path):
        self.data = str(tmp_path / "data")
        self.now = NOW
        self.app = create_app(self.data, HOST, clock=lambda: self.now)
        self.app.state.settings.dev_mode = True
        self.c = TestClient(self.app, base_url="http://" + HOST)
        self.wsk = _priv("wsk_a.sig")
        self.path = self.app.state.settings.db_path
        self.hub = HUB

    def sql(self, q, *a):
        conn = db.connect(self.path)
        try:
            return conn.execute(q, a).fetchall()
        finally:
            conn.close()

    def allow(self, person=PERSON, ws=WS_A):
        """Owner on the allowlist and the workspace pre-bound to it (M2)."""
        self.sql("INSERT OR IGNORE INTO owners VALUES (?,?)", person, NOW)
        if ws:
            self.sql("INSERT OR REPLACE INTO prebinds VALUES (?,?,?)", ws, person, NOW)

    def send(
        self,
        method,
        path,
        body=b"",
        ws=WS_A,
        priv=None,
        sign_host=HOST,
        sign_target=None,
        headers=None,
        **kw,
    ):
        if headers is None:
            headers, _ = build(
                self.hub,
                priv or self.wsk,
                method,
                sign_target or path,
                body,
                ts=kw.pop("ts", self.now),
                nonce=kw.pop("nonce", None),
                ws=ws,
                host=sign_host,
            )
        return self.c.request(method, path, content=body, headers=headers)

    def register(self, card=CARD1, ws=WS_A, pk=PK_B64):
        """The card as the hub hands it to publish (`PUT /v2/hub/cards/{ws}`)."""
        body = json.dumps({"card": card, "pk_pub": pk}).encode()
        return self.c.put(f"/v2/hub/cards/{ws}", content=body)

    def bind(self, ws=WS_A, seq=1, wsk=None):
        conn = db.connect(self.path)
        try:
            hub_path.accept_hub_card(conn, self.hub.card, self.now, True)
            hub_path.accept_binding(
                conn, ws, binding(wsk or self.wsk, self.hub, ws=ws, seq=seq), self.now, True
            )
        finally:
            conn.close()

    def admit(self, ws=WS_A):
        r = self.register(ws=ws)
        assert r.status_code == 200, r.text
        self.bind(ws)

    def status(self, **kw):
        return self.send("GET", f"/v1/ws/{WS_A}/status", **kw)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    e.admit()
    return e


def err(r):
    return r.json()["error"]


# --- the vendored card code ---------------------------------------------------------------------


def test_vendored_proto_is_pinned():
    raw = (ROOT / "pubsrv/relay_proto.py").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == VENDORED_SHA256


def test_vendored_proto_matches_relay_checkout_if_present():
    src = os.environ.get("ORCH_RELAY_SRC")
    if not src or not pathlib.Path(src).exists():
        pytest.skip("set ORCH_RELAY_SRC=/path/to/orch-relay/src/orch_relay/proto/__init__.py")
    assert pathlib.Path(src).read_bytes() == (ROOT / "pubsrv/relay_proto.py").read_bytes()


def test_block_bites_on_the_next_request(env):
    assert env.status().status_code == 200
    cli.main(["admin", "--data", env.data, "ws", "block", WS_A])
    r = env.status()
    assert (r.status_code, err(r)) == (403, "workspace_blocked")
    assert err(env.register()) == "workspace_blocked"
    cli.main(["admin", "--data", env.data, "ws", "unblock", WS_A])
    assert env.status().status_code == 200


def test_blocked_request_records_its_nonce_and_cannot_be_replayed(env):
    """L2: the nonce is spent before the policy refusals."""
    env.sql("UPDATE workspaces SET status='blocked'")
    n = env.sql("SELECT COUNT(*) FROM nonces")[0][0]
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    assert err(env.status(headers=hdr)) == "workspace_blocked"
    assert env.sql("SELECT COUNT(*) FROM nonces")[0][0] == n + 1
    assert err(env.status(headers=hdr)) == "replay"


def test_removing_owner_from_allowlist_bites_on_the_next_request(env):
    cli.main(["admin", "--data", env.data, "owners", "remove", PERSON])
    r = env.status()
    assert (r.status_code, err(r)) == (403, "owner_not_allowed")
    cli.main(["admin", "--data", env.data, "owners", "add", PERSON])
    assert env.status().status_code == 200


# --- the binding is permanent (design 2.6b) -----------------------------------------------------


def test_identical_reregister_is_unchanged(env):
    assert env.register().json() == {"ok": True}  # the same card again: a no-op
    assert env.sql("SELECT COUNT(*) FROM workspaces")[0][0] == 1


def test_stored_binding_fields(env):
    row = env.sql("SELECT * FROM workspaces")[0]
    assert (row["workspace_id"], row["wsk_pub"], row["owner_person_id"], row["owner_pk"]) == (
        WS_A,
        DELEG1["o"]["wsk_pub"],
        PERSON,
        PK_B64,
    )
    assert row["delegation_json"] == proto.cj(DELEG1).decode()
    assert "card_seq" not in row.keys() and "card_json" not in row.keys()  # noqa: SIM118


def test_not_bound_unknown_workspace_with_valid_delegation_is_401(tmp_path):
    e = Env(tmp_path)
    e.allow(ws=None)
    r = e.register()
    assert (r.status_code, err(r)) == (401, "unknown_workspace")


def test_older_data_dir_refuses_to_start(tmp_path):
    data = str(tmp_path / "old")
    path = db.prepare_dir(data)
    conn = db.connect(path)
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT, card_seq INTEGER, card_json TEXT)")
    conn.execute("PRAGMA user_version=1")
    conn.close()
    with pytest.raises(db.SchemaError, match="delete the data dir"):
        create_app(data, HOST)
    assert cli.main(["admin", "--data", data, "owners", "list"]) == 2


# --- concurrency / nonce store ----------------------------------------------------------------


def test_two_identical_requests_race_one_wins(env):
    import concurrent.futures as cf

    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")

    def go():
        return env.c.get(f"/v1/ws/{WS_A}/status", headers=hdr).status_code

    with cf.ThreadPoolExecutor(4) as ex:
        codes = sorted(ex.map(lambda _: go(), range(4)))
    assert codes == [200, 401, 401, 401]


def test_nonce_unique_constraint_is_in_the_schema(env):
    with pytest.raises(sqlite3.IntegrityError):
        env.sql("INSERT INTO nonces VALUES ('a','b',1)")
        env.sql("INSERT INTO nonces VALUES ('a','b',2)")


def test_schema_has_the_design_tables(env):
    names = {r[0] for r in env.sql("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"workspaces", "nonces", "shares", "views", "owners"} <= names
    cols = {r[1] for r in env.sql("PRAGMA table_info(shares)")}
    assert {
        "id",
        "owner_ws",
        "ticket",
        "kind",
        "token_hash",
        "expires_ms",
        "view_limit",
        "views",
        "state",
        "manifest_hash",
        "bytes",
        "created_ms",
    } <= cols
    assert env.sql("PRAGMA journal_mode")[0][0] == "wal"


# --- admin CLI and serve ----------------------------------------------------------------------


def test_admin_cli(tmp_path, capsys):
    d = str(tmp_path / "d")
    assert cli.main(["admin", "--data", d, "owners", "add", PERSON]) == 0
    assert cli.main(["admin", "--data", d, "owners", "list"]) == 0
    assert PERSON in capsys.readouterr().out
    assert cli.main(["admin", "--data", d, "owners", "remove", PERSON]) == 0
    assert cli.main(["admin", "--data", d, "ws", "block", WS_A]) == 1  # unknown workspace
    with pytest.raises(SystemExit):
        cli.main(["admin", "--data", d, "owners", "add", "not-hex"])


def test_serve_refuses_non_loopback_bind(tmp_path, monkeypatch):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start"))
    for bind in ("0.0.0.0:8103", "pub.example.com:80", "10.0.0.5:8103", "127.0.0.1"):
        assert cli.main(["serve", "--data", str(tmp_path / "s"), "--bind", bind]) == 2


def test_serve_api_host_is_separate_from_bind(tmp_path, monkeypatch):
    """L4: a public name to sign, a loopback address to listen on."""
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **k: seen.update(k, app=app))
    assert (
        cli.main(
            [
                "serve",
                "--data",
                str(tmp_path / "s"),
                "--bind",
                "127.0.0.1:9103",
                "--api-host",
                "pub.dev.severin.io",
            ]
        )
        == 0
    )
    assert (seen["host"], seen["port"], seen["access_log"]) == ("127.0.0.1", 9103, False)
    assert seen["app"].state.settings.api_host == "pub.dev.severin.io"
    assert cli.main(["serve", "--data", str(tmp_path / "s"), "--bind", "127.0.0.1:9104"]) == 0
    assert seen["app"].state.settings.api_host == "127.0.0.1:9104"


def test_no_secret_or_key_in_logs(env, caplog):
    caplog.set_level("DEBUG")
    n = os.urandom(16)
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status", nonce=n)
    env.status(headers=hdr)
    text = caplog.text
    assert hdr["Orch-Signature"] not in text and VEC["keys"]["wsk_a.sig"]["seed"] not in text


def test_data_dir_and_db_are_private(env):
    assert (os.stat(env.data).st_mode & 0o777) == 0o700
    assert (os.stat(env.path).st_mode & 0o777) == 0o600


# --- P1b hardening: M2 pre-binding, L1, L3, L5 ---------------------------------------------------


def test_unknown_workspace_registers_only_if_prebound_to_that_owner(tmp_path):
    e = Env(tmp_path)
    e.allow(ws=None)  # owner on the allowlist, workspace NOT pre-bound
    assert err(e.register()) == "unknown_workspace"
    e.sql("INSERT INTO prebinds VALUES (?,?,?)", WS_A, VEC["ids"]["person_bob"], NOW)
    assert err(e.register()) == "unknown_workspace"  # pre-bound to somebody else
    e.sql("UPDATE prebinds SET person_id=?", PERSON)
    assert e.register().status_code == 200


def test_prebind_is_checked_inside_the_register_transaction(tmp_path):
    from pubsrv import registry

    e = Env(tmp_path)
    e.allow(ws=None)
    conn = db.connect(e.path)
    try:
        with pytest.raises(auth.Refusal) as x:
            registry.register(conn, WS_A, DELEG1, PK, NOW)
        assert x.value.error == "unknown_workspace"
        assert e.sql("SELECT COUNT(*) FROM workspaces")[0][0] == 0
    finally:
        conn.close()


def test_prebinding_without_allowlist_is_not_enough(tmp_path):
    e = Env(tmp_path)
    e.sql("INSERT INTO prebinds VALUES (?,?,?)", WS_A, PERSON, NOW)
    assert err(e.register()) == "unknown_workspace"


def test_all_unknown_register_failures_look_alike(tmp_path):
    """L3: no allowlist / not pre-bound / other owner: the same 401 and the same body."""
    e = Env(tmp_path)
    a = e.register()
    e.sql("INSERT INTO owners VALUES (?,?)", PERSON, NOW)
    b = e.register()
    assert (
        (a.status_code, a.json())
        == (b.status_code, b.json())
        == (401, {"error": "unknown_workspace"})
    )


def test_admin_ws_allow_and_unbind(tmp_path):
    e = Env(tmp_path)
    d = e.data
    assert cli.main(["admin", "--data", d, "owners", "add", PERSON]) == 0
    assert cli.main(["admin", "--data", d, "ws", "allow", WS_A, PERSON]) == 0
    assert e.register().status_code == 200
    e.sql(
        "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, state, created_ms)"
        " VALUES ('s1', ?, 'T-1', 'secret', 'h', 1, 'live', 1)",
        WS_A,
    )
    assert cli.main(["admin", "--data", d, "ws", "unbind", WS_A]) == 0
    row = e.sql("SELECT state, owner_ws FROM shares WHERE id='s1'")[0]
    assert row[0] == "revoked" and row[1].startswith("unbound:" + WS_A)  # tombstone kept, re-keyed
    assert e.sql("SELECT COUNT(*) FROM workspaces")[0][0] == 0
    assert e.sql("SELECT COUNT(*) FROM prebinds")[0][0] == 0
    assert err(e.status()) == "unknown_workspace"
    assert (
        err(e.register(CARD2)) == "unknown_workspace"
    )  # needs a new allow (and a newer card than the floor)
    assert cli.main(["admin", "--data", d, "ws", "unbind", WS_A]) == 0  # idempotent


def test_db_nonce_purge_is_strictly_before_now(env):
    t0 = NOW
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status", ts=t0 + 120_000)
    assert env.status(headers=hdr).status_code == 200
    env.now = t0 + 240_000
    assert err(env.status(headers=hdr)) == "replay"
    env.now = t0 + 240_001
    assert err(env.status(headers=hdr)) == "stale_timestamp"


def test_data_dir_is_tightened_to_0700(tmp_path):
    d = tmp_path / "loose"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    create_app(str(d), HOST)
    assert (os.stat(d).st_mode & 0o777) == 0o700


def test_loose_db_file_is_tightened(tmp_path):
    e = Env(tmp_path)
    os.chmod(e.path, 0o644)
    create_app(e.data, HOST)
    assert (os.stat(e.path).st_mode & 0o777) == 0o600


def test_data_dir_that_cannot_be_secured_refuses_to_start(tmp_path, monkeypatch):
    d = tmp_path / "loose"
    d.mkdir()
    os.chmod(d, 0o755)
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)
    with pytest.raises(PermissionError):
        create_app(str(d), HOST)


def test_data_dir_owned_by_someone_else_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: os.stat(tmp_path).st_uid + 1)
    with pytest.raises(PermissionError):
        create_app(str(tmp_path / "x"), HOST)


# --- P1b delta: unbind racing a live request, tombstones, nonces ---------------------------------


def _unbind_during_body(env, mutate, chunks=3):
    """Admit the headers, then run `mutate()` while the body arrives in delayed chunks."""
    import asyncio

    body = b"x" * 30
    path = f"/v1/ws/{WS_A}/x"
    hdr = sign_headers(env.wsk, WS_A, "POST", HOST, path, body)
    k = len(body) // chunks
    parts = [body[i * k : (i + 1) * k] for i in range(chunks - 1)] + [body[(chunks - 1) * k :]]
    state = {"i": 0}
    out = []
    reached = []

    async def receive():
        i = state["i"]
        state["i"] += 1
        await asyncio.sleep(0)
        if i == 1:
            mutate()
        return {"type": "http.request", "body": parts[i], "more_body": i < len(parts) - 1}

    async def send(m):
        out.append(m)

    async def inner(scope, receive, send):
        reached.append(1)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    from pubsrv.app import SignedRequestMiddleware

    mw = SignedRequestMiddleware(inner, env.app.state.settings)
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in hdr.items()],
    }
    asyncio.run(mw(scope, receive, send))
    return reached, out[0]["status"], out[1]["body"]


def test_unbind_between_admission_and_body_refuses(env):
    reached, status, body = _unbind_during_body(
        env, lambda: cli.main(["admin", "--data", env.data, "ws", "unbind", WS_A])
    )
    assert (reached, status) == ([], 401) and b"unknown_workspace" in body


def test_block_between_admission_and_body_refuses(env):
    reached, status, body = _unbind_during_body(
        env, lambda: cli.main(["admin", "--data", env.data, "ws", "block", WS_A])
    )
    assert (reached, status) == ([], 403) and b"workspace_blocked" in body


def test_unbind_and_reregister_with_new_card_between_admission_and_body_refuses(env):
    def swap():
        cli.main(["admin", "--data", env.data, "ws", "unbind", WS_A])
        env.sql(
            "INSERT INTO workspaces(workspace_id, wsk_pub, owner_person_id, owner_pk,"
            " delegation_json, created_ms, updated_ms) VALUES (?,?,?,?,?,?,?)",
            WS_A,
            proto.b64u(bytes.fromhex(VEC["keys"]["wsk_b.sig"]["pub"])),
            PERSON,
            PK_B64,
            "{}",
            NOW,
            NOW,
        )

    reached, status, _ = _unbind_during_body(env, swap)
    assert (reached, status) == ([], 401)


def test_untouched_binding_still_passes_the_recheck(env):
    reached, status, _ = _unbind_during_body(env, lambda: None)
    assert (reached, status) == ([1], 200)


def test_require_binding_helper(env):
    from pubsrv import registry

    conn = db.connect(env.path)
    try:
        wsk = CARD1["o"]["wsk_pub"]
        assert registry.require_binding(conn, WS_A, wsk)["workspace_id"] == WS_A
        with pytest.raises(auth.Refusal) as x:
            registry.require_binding(conn, WS_A, "other-key")
        assert x.value.error == "unknown_workspace"
        env.sql("UPDATE workspaces SET status='blocked'")
        with pytest.raises(auth.Refusal) as x:
            registry.require_binding(conn, WS_A, wsk)
        assert x.value.error == "workspace_blocked"
    finally:
        conn.close()


def test_reregister_after_unbind_does_not_see_old_tombstones(env):
    env.sql(
        "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, state, created_ms)"
        " VALUES ('old', ?, 'T-1', 'secret', 'h', 1, 'live', 1)",
        WS_A,
    )
    assert cli.main(["admin", "--data", env.data, "ws", "unbind", WS_A]) == 0
    assert cli.main(["admin", "--data", env.data, "ws", "allow", WS_A, PERSON]) == 0
    assert (
        env.register(CARD2).status_code == 200
    )  # a newer card than the floor (the same one is a replay)
    assert env.sql("SELECT COUNT(*) FROM shares WHERE owner_ws=?", WS_A)[0][0] == 0
    assert env.sql("SELECT state FROM shares WHERE id='old'")[0][0] == "revoked"


def test_unbind_keeps_nonces_so_a_replay_after_reregister_is_refused(env):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    assert env.status(headers=hdr).status_code == 200
    n = env.sql("SELECT COUNT(*) FROM nonces WHERE ws=?", WS_A)[0][0]
    cli.main(["admin", "--data", env.data, "ws", "unbind", WS_A])
    assert env.sql("SELECT COUNT(*) FROM nonces WHERE ws=?", WS_A)[0][0] == n
    cli.main(["admin", "--data", env.data, "ws", "allow", WS_A, PERSON])
    assert env.register(CARD2).status_code == 200
    assert err(env.status(headers=hdr)) == "replay"


def test_status_row_vanishing_after_the_middleware_is_401_not_500(env, monkeypatch):
    from pubsrv import registry

    real = registry.get_workspace
    calls = []

    def vanishing(conn, ws):
        calls.append(ws)
        return real(conn, ws) if len(calls) == 1 else None  # middleware sees it, handler does not

    monkeypatch.setattr(registry, "get_workspace", vanishing)
    r = env.status()
    assert (r.status_code, err(r)) == (401, "unknown_workspace")
