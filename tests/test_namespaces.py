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
