"""Namespace isolation (design I3): workspace B cannot see or touch A's shares, by id or by path."""

import os

import pytest

from tests.shares_helpers import WS_A, WS_B, Two, sha


@pytest.fixture
def two(tmp_path):
    return Two(tmp_path)


def err(r):
    return r.json()["error"]


def test_b_cannot_read_modify_or_delete_a_share_by_id(two):
    sid = two.share("a", files={"index.html": b"A-secret"})
    before = (two.row(sid), two.on_disk())
    files = {"index.html": b"B-evil"}

    r = two.req("b", "GET", f"/shares/{sid}")
    assert (r.status_code, err(r)) == (404, "not_found")
    r = two.put_file("b", sid, "index.html", b"B-evil")
    assert (r.status_code, err(r)) == (404, "not_found")
    r = two.req("b", "POST", f"/shares/{sid}/commit")
    assert (r.status_code, err(r)) == (404, "not_found")
    r = two.req("b", "DELETE", f"/shares/{sid}")
    assert (r.status_code, err(r)) == (404, "not_found")
    # creating an id that exists for A: a flat conflict that says nothing about the owner
    r = two.put_meta("b", sid, two.meta(files))
    assert (r.status_code, r.json()) == (409, {"error": "conflict"})
    assert sid not in two.req("b", "GET", "/shares").text
    assert (two.row(sid), two.on_disk()) == before
    assert two.row(sid)["state"] == "live"


def test_foreign_and_missing_ids_are_indistinguishable(two):
    sid = two.share("a")
    missing = os.urandom(16).hex()
    for method, tail in [
        ("GET", ""),
        ("DELETE", ""),
        ("POST", "/commit"),
        ("PUT", "/files/index.html"),
    ]:
        a = two.req("b", method, f"/shares/{sid}{tail}", b"x")
        b = two.req("b", method, f"/shares/{missing}{tail}", b"x")
        assert (a.status_code, a.json()) == (b.status_code, b.json()), (method, tail)


def test_b_cannot_reach_a_through_the_path_workspace(two):
    sid = two.share("a")
    # B signs as itself but names A in the path: refused before any route code runs
    r = two.send("DELETE", f"/v1/ws/{WS_A}/shares/{sid}", ws=WS_B, priv=two.wsk_b)
    assert (r.status_code, err(r)) == (403, "wrong_workspace")
    # B signs as A with B's key: bad signature
    r = two.send("DELETE", f"/v1/ws/{WS_A}/shares/{sid}", ws=WS_A, priv=two.wsk_b)
    assert (r.status_code, err(r)) == (401, "bad_signature")
    assert two.row(sid)["state"] == "live"


def test_each_workspace_lists_only_its_own(two):
    a = two.share("a")
    b = two.share("b")
    la = [s["id"] for s in two.req("a", "GET", "/shares").json()["shares"]]
    lb = [s["id"] for s in two.req("b", "GET", "/shares").json()["shares"]]
    assert (la, lb) == ([a], [b])


def test_list_never_carries_a_token_or_hash(two):
    two.share("a", token="very-secret-token")
    text = two.req("a", "GET", "/shares").text
    assert "very-secret-token" not in text
    assert sha(b"very-secret-token") not in text
    assert "token" not in text


def test_quota_is_per_workspace(two):
    big = {"f": b"x" * 10}
    for _ in range(3):
        two.share("a", files=big)
    # A filling its own quota must not touch B
    two.sql("UPDATE shares SET bytes=? WHERE owner_ws=?", 500 * 1024 * 1024, WS_A)
    r = two.put_meta("a", os.urandom(16).hex(), two.meta(big))
    assert (r.status_code, err(r)) == (413, "quota_exceeded")
    assert two.put_meta("b", os.urandom(16).hex(), two.meta(big)).status_code == 200


def test_tombstone_id_cannot_be_taken_by_another_workspace(two):
    sid = two.share("a")
    assert two.req("a", "DELETE", f"/shares/{sid}").status_code == 200
    r = two.put_meta("b", sid, two.meta({"f": b"y"}))
    assert (r.status_code, err(r)) == (409, "conflict")
    assert two.row(sid)["owner_ws"] == WS_A


def test_every_share_route_goes_through_owned_share():
    """Structural guard: route operations must not query shares by id alone."""
    import pathlib

    src = (pathlib.Path(__file__).parent.parent / "pubsrv/shares.py").read_text()
    for fn in ("op_put_file", "op_commit", "op_revoke", "op_get"):
        body = src.split(f"def {fn}(")[1].split("\ndef ")[0]
        assert "owned_share(conn, ws, sid)" in body, fn


# --- binding re-check inside each write transaction (P1b require_binding) -------------------------


def _unbind_after_middleware(two, monkeypatch, how):
    """Run the real _txn start, but change the workspace's binding first: this is the window between
    the middleware check and the handler's transaction."""
    from pubsrv import shares

    real = shares._txn
    done = []

    def txn(conn, ws, wsk):
        if not done:
            done.append(1)
            if how == "unbind":
                two.sql("DELETE FROM workspaces WHERE workspace_id=?", WS_A)
            elif how == "rekey":
                two.sql("UPDATE workspaces SET wsk_pub='other' WHERE workspace_id=?", WS_A)
            else:
                two.sql("UPDATE workspaces SET status='blocked' WHERE workspace_id=?", WS_A)
        return real(conn, ws, wsk)

    monkeypatch.setattr(shares, "_txn", txn)


@pytest.mark.parametrize("how,code", [("unbind", 401), ("rekey", 401), ("block", 403)])
@pytest.mark.parametrize("op", ["put_meta", "put_file", "commit", "revoke"])
def test_binding_change_before_the_write_transaction_leaves_no_write(
    two, monkeypatch, op, how, code
):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    if op in ("commit", "revoke"):
        two.put_file("a", sid, "a.txt", b"one")
    new = os.urandom(16).hex()
    before = (two.sql("SELECT * FROM shares"), two.sql("SELECT * FROM share_files"), two.on_disk())
    _unbind_after_middleware(two, monkeypatch, how)
    if op == "put_meta":
        r = two.put_meta("a", new, two.meta({"b.txt": b"two"}))
    elif op == "put_file":
        r = two.put_file("a", sid, "a.txt", b"one")
        before = (before[0], two.sql("SELECT * FROM share_files"), before[2])
    elif op == "commit":
        r = two.req("a", "POST", f"/shares/{sid}/commit")
    else:
        r = two.req("a", "DELETE", f"/shares/{sid}")
    assert r.status_code == code, r.text
    after = (two.sql("SELECT * FROM shares"), two.sql("SELECT * FROM share_files"), two.on_disk())
    if op == "put_file":
        # the file was already present before this request only if it was uploaded earlier
        assert after[0] == before[0]
    else:
        assert [dict(x) for x in after[0]] == [dict(x) for x in before[0]]
        assert [dict(x) for x in after[1]] == [dict(x) for x in before[1]]
        assert after[2] == before[2]
    assert two.row(new) is None


def test_put_file_after_unbind_writes_nothing(two, monkeypatch):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    _unbind_after_middleware(two, monkeypatch, "unbind")
    r = two.put_file("a", sid, "a.txt", b"one")
    assert r.status_code == 401
    assert two.on_disk() == []
    assert two.sql("SELECT present FROM share_files")[0]["present"] == 0


def test_unbind_keeps_ids_reserved(two):
    """P1b re-keys the share rows on unbind; their ids stay primary keys, so nobody can re-create them."""
    from pubsrv import cli

    live = two.share("a")
    gone = two.share("a")
    two.req("a", "DELETE", f"/shares/{gone}")
    r = two.sql("SELECT * FROM workspaces WHERE workspace_id=?", WS_A)[0]
    saved = (
        r["workspace_id"], r["wsk_pub"], r["owner_person_id"], r["owner_pk"], r["card_seq"],
        r["card_json"], r["created_ms"], r["updated_ms"],
    )  # fmt: skip
    assert cli.main(["admin", "--data", two.data, "ws", "unbind", WS_A]) == 0
    assert {two.row(live)["state"], two.row(gone)["state"]} == {"revoked"}
    assert two.row(live)["token_hash"] == "0" * 64
    for sid in (live, gone):
        r = two.put_meta("b", sid, two.meta({"f": b"y"}))
        assert (r.status_code, err(r)) == (409, "conflict")
    # a re-registered A (same row back) sees none of them: re-keyed rows never match owned_share
    two.sql(
        "INSERT INTO workspaces VALUES (?,?,?,?,?,?,'active',?,?)",
        *saved,
    )
    assert two.req("a", "GET", "/shares").json() == {"shares": []}
    for sid in (live, gone):
        assert two.req("a", "GET", f"/shares/{sid}").status_code == 404
        r = two.put_meta("a", sid, two.meta({"f": b"y"}))
        assert (r.status_code, err(r)) == (409, "conflict")
