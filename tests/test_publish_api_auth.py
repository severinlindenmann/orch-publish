"""Signed-request auth for pubsrv (protocol-v2 12.1, design 2.5/2.6/3). Fake keys only (vectors)."""

import copy
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

from pubsrv import auth, cli, db
from pubsrv import relay_proto as proto
from pubsrv.app import create_app

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
PK = bytes.fromhex(VEC["card"]["cases"][0]["owner_pk_pub"])
PK_B64 = proto.b64u(PK)


def _priv(name):
    """Same derivation as the protocol reference (suite 2 `_priv`)."""
    n = proto.P256_N
    scalar = int.from_bytes(bytes.fromhex(VEC["keys"][name]["seed"]), "big") % (n - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def sign_headers(priv, ws, method, host, target, body=b"", ts=NOW, nonce=None):
    nonce = nonce or os.urandom(16)
    msg = auth.signed_bytes(bytes.fromhex(ws), ts, nonce, method, host, target, body)
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return {
        "Orch-Workspace": ws,
        "Orch-Ts": str(ts),
        "Orch-Nonce": nonce.hex(),
        "Orch-Signature": proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    }


class Env:
    def __init__(self, tmp_path):
        self.data = str(tmp_path / "data")
        self.now = NOW
        self.app = create_app(self.data, HOST, clock=lambda: self.now)
        self.c = TestClient(self.app, base_url="http://" + HOST)
        self.wsk = _priv("wsk_a.sig")
        self.path = self.app.state.settings.db_path

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
        hdr = headers or sign_headers(
            priv or self.wsk,
            ws,
            method,
            sign_host,
            sign_target or path,
            body,
            ts=kw.pop("ts", self.now),
            nonce=kw.pop("nonce", None),
        )
        return self.c.request(method, path, content=body, headers=hdr)

    def register(self, card=CARD1, ws=WS_A, **kw):
        body = json.dumps({"card": card, "owner_pk": PK_B64}).encode()
        return self.send("POST", f"/v1/ws/{ws}/register", body, ws=ws, **kw)

    def status(self, **kw):
        return self.send("GET", f"/v1/ws/{WS_A}/status", **kw)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.allow()
    assert e.register().status_code == 200
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


@pytest.mark.parametrize("case", VEC["card"]["cases"], ids=lambda c: c["name"])
def test_card_vectors_with_vendored_code(case):
    pk = bytes.fromhex(case["owner_pk_pub"])
    got = proto.relay_accept_card(case["stored"], case["card"], pk)
    assert got == case["expect"]


# --- protocol vectors (12.1), same file orch-core P4 checks -------------------------------------


@pytest.mark.parametrize("case", VEC["publish"]["cases"], ids=lambda c: c["name"])
def test_publish_vectors_pure(case):
    cards = {WS_A: CARD1["o"]["wsk_pub"]}
    got = auth.publish_check(
        case["headers"],
        case["method"],
        case["host"],
        case["target"],
        bytes.fromhex(case["body"]),
        cards,
        copy.deepcopy(case["nonces"]),
        case["now_ms"],
    )
    assert got == case["expect"]


def test_publish_vector_signed_bytes_and_headers():
    c = VEC["publish"]["cases"][0]
    h = c["headers"]
    sb = auth.signed_bytes(
        bytes.fromhex(h["Orch-Workspace"]),
        int(h["Orch-Ts"]),
        bytes.fromhex(h["Orch-Nonce"]),
        c["method"],
        c["host"],
        c["target"],
        bytes.fromhex(c["body"]),
    )
    assert sb.hex() == VEC["publish"]["signed_bytes"]
    assert h == VEC["publish"]["headers"]


@pytest.mark.parametrize("case", VEC["publish"]["cases"], ids=lambda c: c["name"])
def test_publish_vectors_through_the_middleware(tmp_path, case):
    """The same vectors, over HTTP: the refusal reasons must match. The vector paths are not
    /v1/ws/ paths, so an accepted request ends in 404 not_found after authentication."""
    e = Env(tmp_path)
    e.allow()
    assert e.register().status_code == 200
    e.now = case["now_ms"]
    for ws, nonces in case["nonces"].items():
        for n, until in nonces.items():
            e.sql("INSERT INTO nonces VALUES (?,?,?)", ws, n, until)
    e.app.state.settings.api_host = case["host"]
    path = case["target"].split("?")[0]
    r = e.c.request(
        case["method"], case["target"], content=bytes.fromhex(case["body"]), headers=case["headers"]
    )
    exp = case["expect"]
    if exp["status"] == 200:
        assert (r.status_code, err(r)) == (404, "not_found")
    else:
        assert (r.status_code, err(r)) == (exp["status"], exp["error"]), path
        if "server_ms" in exp:
            assert r.json()["server_ms"] == exp["server_ms"]


# --- middleware: the 12.1 refusals --------------------------------------------------------------


def test_valid_request(env):
    r = env.status()
    assert r.status_code == 200 and r.json() == {
        "workspace": WS_A,
        "card_seq": 1,
        "status": "active",
    }


def test_replay_is_refused_once_accepted(env):
    n = os.urandom(16)
    assert env.status(nonce=n).status_code == 200
    r = env.status(nonce=n)
    assert (r.status_code, err(r)) == (401, "replay")


def test_replay_of_identical_bytes_refused(env):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    assert env.status(headers=hdr).status_code == 200
    assert err(env.status(headers=hdr)) == "replay"


def test_nonce_expires_after_240s_but_ts_is_stale_by_then(env):
    n = os.urandom(16)
    assert env.status(nonce=n).status_code == 200
    env.now += 241_000
    r = env.status(nonce=n, ts=NOW)
    assert (r.status_code, err(r)) == (401, "stale_timestamp")


@pytest.mark.parametrize(
    "skew,ok", [(120_000, True), (-120_000, True), (121_000, False), (-121_000, False)]
)
def test_skew_window(env, skew, ok):
    r = env.status(ts=NOW + skew)
    if ok:
        assert r.status_code == 200
    else:
        assert (r.status_code, err(r)) == (401, "stale_timestamp")
        assert r.json()["server_ms"] == NOW


def test_wrong_host_in_signature(env):
    r = env.status(sign_host="pub.example.com")
    assert (r.status_code, err(r)) == (401, "bad_signature")


def test_host_header_is_not_trusted(env):
    """Signed for the configured host, sent with another Host header: the signature decides (I6)."""
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    r = env.c.get(f"/v1/ws/{WS_A}/status", headers={**hdr, "Host": "evil.example"})
    assert r.status_code == 200
    hdr = sign_headers(env.wsk, WS_A, "GET", "evil.example", f"/v1/ws/{WS_A}/status")
    r = env.c.get(f"/v1/ws/{WS_A}/status", headers={**hdr, "Host": "evil.example"})
    assert err(r) == "bad_signature"


def test_wrong_path(env):
    r = env.status(sign_target=f"/v1/ws/{WS_A}/other")
    assert (r.status_code, err(r)) == (401, "bad_signature")


def test_wrong_query(env):
    p = f"/v1/ws/{WS_A}/status"
    assert env.send("GET", p + "?a=1", sign_target=p).status_code == 401
    assert err(env.send("GET", p + "?a=1", sign_target=p)) == "bad_signature"
    assert err(env.send("GET", p, sign_target=p + "?a=1")) == "bad_signature"
    assert env.send("GET", p + "?a=1", sign_target=p + "?a=1").status_code == 200


def test_target_is_not_normalised(env):
    p = f"/v1/ws/{WS_A}/status"
    # same route after decoding, different bytes on the wire: the signature covers the raw target
    r = env.send("GET", f"/v1/ws/{WS_A}/%73tatus", sign_target=p)
    assert err(r) == "bad_signature"
    assert (
        env.send(
            "GET", f"/v1/ws/{WS_A}/%73tatus", sign_target=f"/v1/ws/{WS_A}/%73tatus"
        ).status_code
        == 200
    )


def test_wrong_method(env):
    p = f"/v1/ws/{WS_A}/status"
    hdr = sign_headers(env.wsk, WS_A, "POST", HOST, p)
    assert err(env.c.get(p, headers=hdr)) == "bad_signature"


def test_body_tamper(env):
    p = f"/v1/ws/{WS_A}/status"
    hdr = sign_headers(env.wsk, WS_A, "POST", HOST, p, b"one")
    r = env.c.post(p, content=b"two", headers=hdr)
    assert err(r) == "bad_signature"


def test_bad_signature_other_key(env):
    r = env.status(priv=_priv("wsk_b.sig"))
    assert (r.status_code, err(r)) == (401, "bad_signature")


def test_flipped_signature_bit(env):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    sig = bytearray(proto.unb64u(hdr["Orch-Signature"]))
    sig[5] ^= 1
    hdr["Orch-Signature"] = proto.b64u(bytes(sig))
    assert err(env.status(headers=hdr)) == "bad_signature"


def test_bad_signature_does_not_fill_nonce_store(env):
    before = env.sql("SELECT COUNT(*) FROM nonces")[0][0]
    for _ in range(5):
        env.status(priv=_priv("wsk_b.sig"))
    assert env.sql("SELECT COUNT(*) FROM nonces")[0][0] == before


@pytest.mark.parametrize(
    "mut",
    [
        {"Orch-Nonce": "AB" * 16},
        {"Orch-Nonce": "ab" * 15},
        {"Orch-Ts": "01790000000000"},
        {"Orch-Ts": "-1"},
        {"Orch-Ts": "1.5"},
        {"Orch-Workspace": WS_A.upper()},
        {"Orch-Workspace": "zz"},
        {"Orch-Signature": "!!"},
        {"Orch-Signature": "AA"},
    ],
)
def test_malformed_headers(env, mut):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    hdr.update(mut)
    r = env.status(headers=hdr)
    assert (r.status_code, err(r)) == (400, "malformed")


def test_missing_header_and_duplicated_header(env):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    del hdr["Orch-Nonce"]
    assert err(env.status(headers=hdr)) == "malformed"
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    r = env.c.get(
        f"/v1/ws/{WS_A}/status",
        headers=[(k, v) for k, v in hdr.items()] + [("Orch-Nonce", os.urandom(16).hex())],
    )
    assert (r.status_code, err(r)) == (400, "malformed")


def test_no_headers_at_all_is_refused(env):
    assert env.c.get(f"/v1/ws/{WS_A}/status").status_code == 400


def test_check_order_malformed_before_stale_before_unknown_before_signature(env):
    stranger = _priv("wsk_b.sig")
    # stale + unknown workspace + bad signature: stale wins
    r = env.send("GET", f"/v1/ws/{WS_B}/status", ws=WS_B, priv=stranger, ts=NOW + 500_000)
    assert err(r) == "stale_timestamp"
    # unknown workspace + bad signature: unknown wins
    r = env.send("GET", f"/v1/ws/{WS_B}/status", ws=WS_B, priv=stranger)
    assert err(r) == "unknown_workspace"
    # replayed nonce + bad signature: the signature is checked first
    n = os.urandom(16)
    assert env.status(nonce=n).status_code == 200
    assert err(env.status(nonce=n, priv=stranger)) == "bad_signature"


def test_unknown_workspace(env):
    r = env.send("GET", f"/v1/ws/{WS_B}/status", ws=WS_B, priv=_priv("wsk_b.sig"))
    assert (r.status_code, err(r)) == (401, "unknown_workspace")


def test_path_workspace_must_equal_signed_workspace(env):
    env.allow(VEC["ids"]["person_bob"])
    r = env.send("GET", f"/v1/ws/{WS_B}/status", ws=WS_A)
    assert (r.status_code, err(r)) == (403, "wrong_workspace")
    assert env.sql("SELECT COUNT(*) FROM nonces")[0][0] == 2  # register + this one (L2)


def test_unknown_route_is_404_after_auth_and_unauthenticated_is_never_served(env):
    assert env.send("GET", f"/v1/ws/{WS_A}/nope").status_code == 404
    assert env.c.get("/docs").status_code == 400
    assert env.c.get("/openapi.json").status_code == 400


def _signed_big(env, method, path, size, ws=WS_A):
    body = b"x" * size
    hdr = sign_headers(env.wsk, ws, method, HOST, path, body)
    return env.c.request(method, path, content=body, headers=hdr)


def test_body_limits_are_per_route(env):
    sid = "ab" * 16
    file_path = f"/v1/ws/{WS_A}/shares/{sid}/files/a.txt"
    # a known workspace: 1 MiB for ordinary routes, 26 MiB only for a file PUT
    assert _signed_big(env, "POST", f"/v1/ws/{WS_A}/x", 1024 * 1024 + 1).status_code == 413
    r = _signed_big(env, "PUT", file_path, 1024 * 1024 + 1)
    assert r.status_code == 404  # size accepted (past auth), no such route yet
    assert _signed_big(env, "PUT", file_path, 26 * 1024 * 1024 + 1).status_code == 413
    # register is 64 KiB
    assert _signed_big(env, "POST", f"/v1/ws/{WS_A}/register", 64 * 1024 + 1).status_code == 413
    # a GET/POST to the file path is not a file PUT
    assert _signed_big(env, "POST", file_path, 2 * 1024 * 1024).status_code == 413


def test_unknown_workspace_gets_only_64k(tmp_path):
    e = Env(tmp_path)
    e.allow()
    big = _signed_big(e, "POST", f"/v1/ws/{WS_A}/register", 64 * 1024 + 1)
    assert big.status_code == 413


def _asgi(app, scope_extra, headers, body=b""):
    import asyncio

    reads = []
    out = []

    async def receive():
        reads.append(1)
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        out.append(m)

    scope = {
        "type": "http",
        "method": "POST",
        "path": f"/v1/ws/{WS_A}/x",
        "raw_path": f"/v1/ws/{WS_A}/x".encode(),
        "query_string": b"",
        "headers": headers,
        **scope_extra,
    }
    asyncio.run(app(scope, receive, send))
    return reads, out


@pytest.mark.parametrize("kind", ["malformed", "stale", "unknown"])
def test_body_is_not_read_before_steps_1_to_3(env, kind):
    hdr = sign_headers(env.wsk, WS_A, "POST", HOST, f"/v1/ws/{WS_A}/x")
    if kind == "malformed":
        del hdr["Orch-Nonce"]
    if kind == "stale":
        hdr = sign_headers(env.wsk, WS_A, "POST", HOST, f"/v1/ws/{WS_A}/x", ts=NOW + 500_000)
    if kind == "unknown":
        hdr = sign_headers(_priv("wsk_b.sig"), WS_B, "POST", HOST, f"/v1/ws/{WS_B}/x")
    reads, out = _asgi(env.app, {}, [(k.lower().encode(), v.encode()) for k, v in hdr.items()])
    assert reads == []
    assert out[0]["status"] == (400 if kind == "malformed" else 401)


def test_db_failure_fails_closed(env):
    pathlib.Path(env.path).write_bytes(b"not a database" * 100)
    for ext in ("-wal", "-shm"):
        pathlib.Path(env.path + ext).unlink(missing_ok=True)
    r = env.status()
    assert r.status_code in (500, 503) and r.json()["error"] in ("unavailable", "internal")


# --- admission: allowlist, block ----------------------------------------------------------------


def test_register_requires_allowlisted_owner(tmp_path):
    e = Env(tmp_path)
    r = e.register()
    assert (r.status_code, err(r)) == (401, "unknown_workspace")
    assert e.sql("SELECT COUNT(*) FROM workspaces")[0][0] == 0
    e.allow()
    assert e.register().json() == {"workspace": WS_A, "result": "registered", "card_seq": 1}


def test_unregistered_workspace_cannot_use_other_routes(tmp_path):
    e = Env(tmp_path)
    e.allow()
    assert err(e.status()) == "unknown_workspace"


def test_register_signature_must_match_card_key(tmp_path):
    e = Env(tmp_path)
    e.allow()
    r = e.register(priv=_priv("wsk_b.sig"))
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert e.sql("SELECT COUNT(*) FROM workspaces")[0][0] == 0


def test_register_card_for_another_workspace_refused(tmp_path):
    e = Env(tmp_path)
    e.allow()
    e.allow(ws=WS_B)
    r = e.register(ws=WS_B, priv=_priv("wsk_b.sig"))
    assert (r.status_code, err(r)) == (400, "card_refused")


def test_register_tampered_card_refused(tmp_path):
    e = Env(tmp_path)
    e.allow()
    bad = copy.deepcopy(CARD1)
    bad["o"]["relay_url"] = "https://relay.example.org"
    r = e.register(card=bad)
    assert r.status_code == 400 and r.json()["reason"] == "bad_signature"


def test_register_wrong_owner_pk_refused(tmp_path):
    e = Env(tmp_path)
    e.allow()
    body = json.dumps(
        {"card": CARD1, "owner_pk": proto.b64u(bytes.fromhex(VEC["keys"]["wsk_a.sig"]["pub"]))}
    ).encode()
    r = e.send("POST", f"/v1/ws/{WS_A}/register", body)
    assert (r.status_code, err(r)) == (401, "unknown_workspace")  # person id not pre-bound (L3)


@pytest.mark.parametrize(
    "body", [b"{}", b"[]", b"not json", b'{"card":{},"owner_pk":"x"}', b'{"card":1,"owner_pk":"x"}']
)
def test_register_malformed_body(tmp_path, body):
    e = Env(tmp_path)
    e.allow()
    r = e.send("POST", f"/v1/ws/{WS_A}/register", body)
    assert r.status_code == 400 and err(r) in ("malformed", "card_refused")


def test_register_extra_field_refused(tmp_path):
    e = Env(tmp_path)
    e.allow()
    body = json.dumps({"card": CARD1, "owner_pk": PK_B64, "x": 1}).encode()
    assert err(e.send("POST", f"/v1/ws/{WS_A}/register", body)) == "malformed"


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


# --- card_seq ---------------------------------------------------------------------------------


def test_card_seq_rollback_refused(env):
    r = env.register(card=CARD2)
    assert r.json() == {"workspace": WS_A, "result": "updated", "card_seq": 2}
    r = env.register(card=CARD1)
    assert (r.status_code, err(r), r.json()["reason"]) == (409, "card_refused", "stale_card")
    assert env.sql("SELECT card_seq FROM workspaces")[0][0] == 2
    assert env.status().json()["card_seq"] == 2


def test_identical_card_is_idempotent_and_same_seq_other_card_refused(env):
    assert env.register().json()["result"] == "unchanged"
    same_seq = next(c for c in VEC["card"]["cases"] if c["name"] == "same_seq_other_sealed")
    r = env.register(card=same_seq["card"])
    assert r.status_code in (400, 409) and err(r) == "card_refused"
    assert env.sql("SELECT card_seq FROM workspaces")[0][0] == 1


def test_binding_is_permanent_wsk_and_owner_never_change(env):
    row = env.sql("SELECT wsk_pub, owner_person_id FROM workspaces")[0]
    c = next(c for c in VEC["card"]["cases"] if c["name"] == "wsk_changed")
    r = env.register(card=c["card"])
    assert err(r) == "card_refused"
    assert tuple(env.sql("SELECT wsk_pub, owner_person_id FROM workspaces")[0]) == tuple(row)


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
            registry.register(conn, WS_A, CARD1, PK, NOW)
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


def test_card_is_not_verified_for_a_non_allowlisted_owner(tmp_path, monkeypatch):
    from pubsrv import registry

    e = Env(tmp_path)
    monkeypatch.setattr(registry.proto, "verify_card", lambda *a: pytest.fail("verify_card ran"))
    assert err(e.register()) == "unknown_workspace"


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
    assert err(e.register()) == "unknown_workspace"  # needs a new allow
    assert cli.main(["admin", "--data", d, "ws", "unbind", WS_A]) == 0  # idempotent


def test_nonce_survives_exactly_until_the_end_of_retention(env):
    """L1/edge vector: a nonce recorded at t0 with a ts 120 s ahead is still a replay at exactly
    t0+240000 (the ts is then still inside the window)."""
    extra = json.loads((ROOT / "tests/vectors/publish_v2_extra.json").read_text())
    for c in extra["cases"]:
        cards = {WS_A: CARD1["o"]["wsk_pub"]}
        nonces = copy.deepcopy(c["nonces"])
        got = auth.publish_check(
            c["headers"],
            c["method"],
            c["host"],
            c["target"],
            bytes.fromhex(c["body"]),
            cards,
            nonces,
            c["now_ms"],
        )
        assert got == c["expect"], c["name"]


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
            "INSERT INTO workspaces(workspace_id, wsk_pub, owner_person_id, owner_pk, card_seq,"
            " card_json, created_ms, updated_ms) VALUES (?,?,?,?,?,?,?,?)",
            WS_A,
            "another-key",
            PERSON,
            PK_B64,
            1,
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
    assert env.register().status_code == 200
    assert env.sql("SELECT COUNT(*) FROM shares WHERE owner_ws=?", WS_A)[0][0] == 0
    assert env.sql("SELECT state FROM shares WHERE id='old'")[0][0] == "revoked"


def test_unbind_keeps_nonces_so_a_replay_after_reregister_is_refused(env):
    hdr = sign_headers(env.wsk, WS_A, "GET", HOST, f"/v1/ws/{WS_A}/status")
    assert env.status(headers=hdr).status_code == 200
    n = env.sql("SELECT COUNT(*) FROM nonces WHERE ws=?", WS_A)[0][0]
    cli.main(["admin", "--data", env.data, "ws", "unbind", WS_A])
    assert env.sql("SELECT COUNT(*) FROM nonces WHERE ws=?", WS_A)[0][0] == n
    cli.main(["admin", "--data", env.data, "ws", "allow", WS_A, PERSON])
    assert env.register().status_code == 200
    assert err(env.status(headers=hdr)) == "replay"
