"""Shares API: meta + per-file PUT, commit, revoke, list; path rules (I8), caps (I14), sweep."""

import os
import pathlib

import pytest

from pubsrv import cli, shares, sweep
from tests.shares_helpers import DAY, WS_A, Two, sha


@pytest.fixture
def two(tmp_path):
    return Two(tmp_path)


def err(r):
    return r.json()["error"]


# --- lifecycle -----------------------------------------------------------------------------------


def test_create_upload_commit_list_revoke(two):
    files = {"index.html": b"<h1>hi</h1>", "sub/a.txt": b"aaa"}
    sid = two.share("a", files=files)
    row = two.row(sid)
    assert (row["state"], row["bytes"], row["owner_ws"]) == ("live", 14, WS_A)
    live = pathlib.Path(two.data, "shares", sid, "files")
    assert (live / "index.html").read_bytes() == files["index.html"]
    assert (live / "sub/a.txt").read_bytes() == b"aaa"
    assert not pathlib.Path(two.data, "incoming", sid).exists()
    (item,) = two.req("a", "GET", "/shares").json()["shares"]
    assert (item["id"], item["state"], item["kind"], item["views"]) == (sid, "live", "secret", 0)
    r = two.req("a", "DELETE", f"/shares/{sid}")
    assert (r.status_code, r.json()["state"]) == (200, "revoked")
    assert not pathlib.Path(two.data, "shares", sid).exists()
    assert two.row(sid)["state"] == "revoked"
    assert two.row(sid)["token_hash"] == "0" * 64  # the tombstone keeps no token hash


def test_revoke_then_access_is_gone(two):
    sid = two.share("a")
    assert two.req("a", "DELETE", f"/shares/{sid}").status_code == 200
    for method, tail in [("GET", ""), ("POST", "/commit"), ("PUT", "/files/index.html")]:
        r = two.req("a", method, f"/shares/{sid}{tail}", b"<h1>hi</h1>")
        assert (r.status_code, err(r)) == (410, "gone"), (method, tail)
    r = two.put_meta("a", sid, two.meta({"index.html": b"<h1>hi</h1>"}))
    assert (r.status_code, err(r)) == (410, "gone")
    assert two.req("a", "DELETE", f"/shares/{sid}").status_code == 200  # idempotent
    assert [s["state"] for s in two.req("a", "GET", "/shares").json()["shares"]] == ["revoked"]
    assert two.on_disk() == []


def test_idempotent_re_put(two):
    files = {"a.txt": b"one", "b.txt": b"two"}
    sid = os.urandom(16).hex()
    m = two.meta(files)
    assert two.put_meta("a", sid, m).json()["result"] == "created"
    assert two.put_meta("a", sid, m).json()["result"] == "unchanged"
    assert two.put_file("a", sid, "a.txt", b"one").json()["result"] == "stored"
    assert two.put_file("a", sid, "a.txt", b"one").json()["result"] == "stored"  # resend
    two.put_file("a", sid, "b.txt", b"two")
    assert two.req("a", "POST", f"/shares/{sid}/commit").json()["result"] == "committed"
    # everything may be sent again after the commit (a lost reply)
    assert two.put_meta("a", sid, m).json()["result"] == "unchanged"
    assert two.put_file("a", sid, "a.txt", b"one").json()["result"] == "unchanged"
    assert two.req("a", "POST", f"/shares/{sid}/commit").json()["result"] == "unchanged"
    assert len(two.sql("SELECT * FROM shares")) == 1
    # a different manifest for the same id is a conflict, not an overwrite
    r = two.put_meta("a", sid, two.meta(files, token="other"))
    assert (r.status_code, err(r)) == (409, "conflict")
    r = two.put_file("a", sid, "a.txt", b"changed")  # not the declared hash
    assert (r.status_code, err(r)) == (422, "content_mismatch")
    assert (pathlib.Path(two.data, "shares", sid, "files/a.txt")).read_bytes() == b"one"


def test_file_must_match_manifest(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    r = two.put_file("a", sid, "a.txt", b"onX")
    assert (r.status_code, err(r)) == (422, "content_mismatch")
    r = two.put_file("a", sid, "other.txt", b"one")
    assert (r.status_code, err(r)) == (404, "not_in_manifest")
    assert two.on_disk() == []


def test_commit_needs_every_file(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one", "b.txt": b"two"}))
    two.put_file("a", sid, "a.txt", b"one")
    r = two.req("a", "POST", f"/shares/{sid}/commit")
    assert (r.status_code, err(r), r.json()["missing"]) == (409, "incomplete", ["b.txt"])
    assert two.row(sid)["state"] == "staged"
    assert not pathlib.Path(two.data, "shares", sid).exists()


def test_commit_rechecks_the_files_on_disk(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    two.put_file("a", sid, "a.txt", b"one")
    pathlib.Path(two.data, "incoming", sid, "files/a.txt").write_bytes(b"tampered")
    r = two.req("a", "POST", f"/shares/{sid}/commit")
    assert (r.status_code, err(r)) == (409, "incomplete")
    assert two.row(sid)["state"] == "staged"


def test_commit_rolls_the_rename_back_if_the_state_update_fails(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    two.put_file("a", sid, "a.txt", b"one")
    two.sql(
        "CREATE TRIGGER nolive BEFORE UPDATE OF state ON shares WHEN NEW.state='live'"
        " BEGIN SELECT RAISE(ABORT,'no'); END"
    )
    r = two.req("a", "POST", f"/shares/{sid}/commit")
    assert r.status_code == 503
    assert two.row(sid)["state"] == "staged"
    assert pathlib.Path(two.data, "incoming", sid, "files/a.txt").read_bytes() == b"one"
    assert not pathlib.Path(two.data, "shares", sid, "files").exists()
    two.sql("DROP TRIGGER nolive")
    assert two.req("a", "POST", f"/shares/{sid}/commit").status_code == 200  # retry works


def test_expired_share_cannot_be_committed_and_shows_expired(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}, days=1))
    two.put_file("a", sid, "a.txt", b"one")
    two.now += 2 * DAY
    r = two.req("a", "POST", f"/shares/{sid}/commit")
    assert (r.status_code, err(r)) == (410, "gone")


# --- meta validation -----------------------------------------------------------------------------


def _bad(two, **change):
    m = two.meta({"a.txt": b"one"})
    m.update(change)
    return two.put_meta("a", os.urandom(16).hex(), m)


@pytest.mark.parametrize(
    "change,code",
    [
        ({"kind": "public"}, "bad_kind"),
        ({"ticket": "../x"}, "bad_ticket"),
        ({"ticket": ""}, "bad_ticket"),
        ({"view_limit": 3}, "bad_view_limit"),  # secret with a limit
        ({"kind": "once", "view_limit": 0}, "bad_view_limit"),
        ({"kind": "once", "view_limit": 11}, "bad_view_limit"),
        ({"kind": "once", "view_limit": True}, "bad_view_limit"),
        ({"expires_ms": 1}, "bad_expiry"),
        ({"expires_ms": "9" * 3}, "bad_expiry"),
        ({"token_hash": "abc"}, "bad_token_hash"),
        ({"token_hash": "A" * 64}, "bad_token_hash"),
        ({"files": []}, "bad_files"),
        ({"files": "x"}, "bad_files"),
    ],
)
def test_bad_meta(two, change, code):
    r = _bad(two, **change)
    assert (r.status_code, err(r)) == (400, code)


def test_expiry_is_capped_at_30_days(two):
    assert _bad(two, expires_ms=two.now + 30 * DAY).status_code == 200
    r = _bad(two, expires_ms=two.now + 31 * DAY)
    assert (r.status_code, err(r)) == (400, "bad_expiry")


def test_meta_unknown_and_duplicate_keys_and_junk(two):
    sid = os.urandom(16).hex()
    import json

    m = two.meta({"a.txt": b"one"})
    assert (
        two.req("a", "PUT", f"/shares/{sid}", json.dumps({**m, "extra": 1}).encode()).status_code
        == 400
    )
    dup = json.dumps(m)[:-1] + ', "kind": "once"}'
    assert two.req("a", "PUT", f"/shares/{sid}", dup.encode()).status_code == 400
    for junk in (b"", b"[]", b"\xff\xfe", b"{"):
        assert two.req("a", "PUT", f"/shares/{sid}", junk).status_code == 400
    assert two.sql("SELECT * FROM shares") == []


def test_bad_share_id_is_404(two):
    for sid in ("short", "G" * 32, "A" * 32, "0" * 31, "0" * 33):
        r = two.req("a", "GET", f"/shares/{sid}")
        assert r.status_code == 404, sid


# --- path rules (I8) -----------------------------------------------------------------------------

BAD_PATHS = [
    "../x",
    "a/../b",
    "a/..",
    "..",
    ".",
    "./a",
    "a/./b",
    "/abs",
    "a//b",
    "a/",
    ".hidden",
    "a/.hidden",
    "a\\b",
    "a\\..\\b",
    "C:\\x",
    "a\x00b",
    "a\nb",
    "a:b",
    "a?b",
    "a#b",
    "a%2Fb",
    "%2e%2e/x",
    "%2e%2e%2fx",
    "..%2fx",
    "a%00b",
    "a\u202eb",  # right-to-left override
    "a\u2024b",  # one dot leader
    "\uff0e\uff0e/x",  # fullwidth dots
    "a\uff0fb",  # fullwidth solidus
    "a\u2215b",  # division slash
    "e\u0301.txt",  # not NFC
    "\u00e9.txt",  # NFC but non-ASCII is not allowed
    "a" * 101,
    "/".join(["d"] * 9) + "/f",
    "x" * 401,
    "file.",
    "file ",
    "a/ ",
    "a/b/",
    "CON\\x",
    "~/x",
    "a b/../../c",
    "",
]


@pytest.mark.parametrize("path", BAD_PATHS, ids=lambda p: repr(p)[:40])
def test_manifest_refuses_bad_paths(two, path):
    m = two.meta({"ok.txt": b"one"})
    m["files"] = [{"path": path, "size": 3, "sha256": sha(b"one")}]
    r = two.put_meta("a", os.urandom(16).hex(), m)
    assert (r.status_code, err(r)) == (400, "bad_path")
    assert two.sql("SELECT * FROM shares") == [] and two.on_disk() == []


GOOD_PATHS = ["a", "a.txt", "My File-1_x.pdf", "d/e/f.txt", "/".join(["d"] * 7) + "/f", "a..b"]


@pytest.mark.parametrize("path", GOOD_PATHS)
def test_manifest_accepts_normal_paths(two, path):
    sid = two.share("a", files={path: b"data"})
    parts = pathlib.Path(two.data, "shares", sid, "files", *path.split("/"))
    assert parts.read_bytes() == b"data"


def test_manifest_refuses_duplicates_and_collisions(two):
    def attempt(paths):
        m = two.meta({"ok": b"o"})
        m["files"] = [{"path": p, "size": 1, "sha256": sha(b"o")} for p in paths]
        return two.put_meta("a", os.urandom(16).hex(), m)

    for paths in (["a", "a"], ["a.TXT", "a.txt"], ["Dir/x", "dir/x"], ["a", "a/b"], ["A/b", "a"]):
        r = attempt(paths)
        assert (r.status_code, err(r)) == (400, "bad_path"), paths
    assert attempt(["a/b", "a/c", "ab"]).status_code == 200


@pytest.mark.parametrize(
    "url_path",
    [
        "../../../../etc/passwd",
        "%2e%2e/%2e%2e/x",
        "%2e%2e%2f%2e%2e%2fx",
        "..%2f..%2fx",
        "%252e%252e/x",  # double-encoded
        "a%5c..%5cb",
        "a%00.txt",
        "%c0%ae%c0%ae/x",  # overlong utf-8 dots
        "%ef%bc%8e%ef%bc%8e/x",  # fullwidth dots
        "a/%00",
        "/etc/passwd",
        "%2fetc%2fpasswd",
        "a//b",
        "a/",
        ".hidden",
        "e%cc%81.txt",  # decomposed e + combining accent
    ],
)
def test_file_put_url_tricks_cannot_write_outside(two, url_path):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    before = two.on_disk()
    r = two.req("a", "PUT", f"/shares/{sid}/files/{url_path}", b"one")
    # 401: the HTTP client itself normalises some dot segments, so the signed target no longer matches
    assert r.status_code in (400, 401, 404, 405), (url_path, r.status_code, r.text)
    assert two.on_disk() == before
    root = pathlib.Path(two.data).parent
    assert sorted(p.name for p in root.iterdir()) == ["data"]  # nothing next to the data dir


def test_symlink_in_incoming_is_never_followed(two, tmp_path):
    """Even if a symlink were planted in the stage, a write refuses to follow it."""
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"d/a.txt": b"one"}))
    outside = tmp_path / "outside"
    outside.mkdir()
    stage = pathlib.Path(two.data, "incoming", sid, "files")
    os.symlink(outside, stage / "d")
    r = two.put_file("a", sid, "d/a.txt", b"one")
    assert r.status_code == 503
    assert list(outside.iterdir()) == []


# --- caps (I14) ----------------------------------------------------------------------------------


def test_per_file_cap(two):
    m = two.meta({"a.txt": b"x"})
    m["files"][0]["size"] = shares.MAX_FILE + 1
    r = two.put_meta("a", os.urandom(16).hex(), m)
    assert (r.status_code, err(r)) == (400, "bad_size")
    m["files"][0]["size"] = -1
    assert two.put_meta("a", os.urandom(16).hex(), m).status_code == 400


def test_per_share_cap_is_50mb_at_the_manifest(two):
    m = two.meta({"a": b"x"})
    m["files"] = [
        {"path": f"f{i}", "size": 20 * 1024 * 1024, "sha256": sha(b"x")} for i in range(3)
    ]
    r = two.put_meta("a", os.urandom(16).hex(), m)
    assert (r.status_code, err(r)) == (413, "share_too_large")
    m["files"] = m["files"][:2]  # 40 MB: fine
    assert two.put_meta("a", os.urandom(16).hex(), m).status_code == 200


def test_file_count_cap(two):
    m = two.meta({"a": b"x"})
    m["files"] = [{"path": f"f{i}", "size": 1, "sha256": sha(b"x")} for i in range(501)]
    r = two.put_meta("a", os.urandom(16).hex(), m)
    assert (r.status_code, err(r)) == (400, "bad_files")


def test_workspace_byte_quota(two):
    two.share("a", files={"a": b"x"})
    two.sql("UPDATE shares SET bytes=? WHERE owner_ws=?", 480 * 1024 * 1024, WS_A)
    m = two.meta({"a": b"x"})
    m["files"] = [{"path": "big", "size": 25 * 1024 * 1024, "sha256": sha(b"x")}]
    r = two.put_meta("a", os.urandom(16).hex(), m)
    assert (r.status_code, err(r)) == (413, "quota_exceeded")
    # revoking gives the space back
    sid = two.sql("SELECT id FROM shares")[0]["id"]
    two.req("a", "DELETE", f"/shares/{sid}")
    assert two.put_meta("a", os.urandom(16).hex(), m).status_code == 200


def test_workspace_share_count_cap(two):
    for i in range(shares.MAX_SHARES):
        two.sql(
            "INSERT INTO shares(id, owner_ws, ticket, kind, token_hash, expires_ms, state,"
            " created_ms) VALUES (?,?,?,?,?,?,?,?)",
            f"{i:032x}", WS_A, "T", "secret", "0" * 64, two.now + DAY, "live", two.now,
        )  # fmt: skip
    r = two.put_meta("a", os.urandom(16).hex(), two.meta({"a": b"x"}))
    assert (r.status_code, err(r)) == (429, "too_many_shares")


def test_oversize_request_body_is_refused_by_the_middleware(two):
    sid = os.urandom(16).hex()
    two.put_meta("a", sid, two.meta({"a.txt": b"one"}))
    r = two.req("a", "PUT", f"/shares/{sid}/files/a.txt", b"x" * (27 * 1024 * 1024))
    assert r.status_code == 413


def test_write_rate_limit(two):
    sid = os.urandom(16).hex()
    codes = [
        two.req("a", "DELETE", f"/shares/{sid}").status_code
        for _ in range(shares.WRITES_PER_MIN + 3)
    ]
    assert codes[: shares.WRITES_PER_MIN] == [404] * shares.WRITES_PER_MIN
    assert codes[-1] == 429
    assert two.req("b", "DELETE", f"/shares/{sid}").status_code == 404  # B has its own budget
    assert two.req("a", "GET", "/shares").status_code == 200  # reads are not limited


# --- no unsigned route ---------------------------------------------------------------------------


def test_no_share_route_works_unsigned(two):
    sid = two.share("a")
    for method, tail in [
        ("GET", "/shares"),
        ("GET", f"/shares/{sid}"),
        ("PUT", f"/shares/{sid}"),
        ("PUT", f"/shares/{sid}/files/index.html"),
        ("POST", f"/shares/{sid}/commit"),
        ("DELETE", f"/shares/{sid}"),
    ]:
        r = two.c.request(method, f"/v1/ws/{WS_A}{tail}", content=b"{}")
        assert r.status_code == 400 and err(r) == "malformed", (method, tail)
    assert two.row(sid)["state"] == "live"


def test_app_routes_all_sit_behind_the_middleware(two):
    from starlette.routing import Route

    paths = [r.path for r in two.app.routes if isinstance(r, Route)]
    assert paths and all(p.startswith("/v1/ws/{ws}") for p in paths), paths


def test_nothing_secret_is_logged(two, caplog):
    caplog.set_level("DEBUG")
    two.share("a", token="tok-needle-123")
    assert "tok-needle-123" not in caplog.text and sha(b"tok-needle-123") not in caplog.text


# --- sweep ---------------------------------------------------------------------------------------


def test_sweep_expires_cleans_and_drops_tombstones(two):
    live = two.share("a", days=1)
    keep = two.share("a", days=7)
    stale = os.urandom(16).hex()
    two.put_meta("a", stale, two.meta({"a.txt": b"one"}))
    two.put_file("a", stale, "a.txt", b"one")
    revoked = two.share("a")
    two.req("a", "DELETE", f"/shares/{revoked}")
    orphan = pathlib.Path(two.data, "shares", "f" * 32, "files")
    orphan.mkdir(parents=True)
    (orphan / "x").write_text("x")
    link = pathlib.Path(two.data, "incoming", "e" * 32)
    os.symlink("/tmp", link)

    two.now += 2 * DAY  # share `live` has expired; `stale` is a day old
    two.sql("UPDATE shares SET created_ms=? WHERE id=?", two.now - 7 * 3600_000, stale)
    counts = sweep.run(two.app.state.settings.db_path, two.data, two.now)
    assert counts == {"expired": 1, "stale_staged": 1, "tombstones_dropped": 0, "orphans": 4}
    assert two.row(live)["state"] == "expired" and two.row(stale)["state"] == "expired"
    assert two.row(keep)["state"] == "live"
    assert not link.is_symlink() and os.path.isdir("/tmp")  # the link is removed, never followed
    assert not pathlib.Path(two.data, "shares", live).exists()
    assert pathlib.Path(two.data, "shares", keep, "files").is_dir()
    assert not orphan.exists()

    two.now += 31 * DAY
    counts = sweep.run(two.app.state.settings.db_path, two.data, two.now)
    assert counts["tombstones_dropped"] == 3 and counts["expired"] == 1  # `keep` ran out too
    assert (
        two.row(revoked) is None
        and two.sql("SELECT * FROM share_files WHERE share_id=?", revoked) == []
    )


def test_admin_sweep_command(two, capsys):
    two.share("a", days=1)
    two.now += 2 * DAY
    import time

    # the CLI uses the wall clock: a share that expired in the past is swept
    two.sql("UPDATE shares SET expires_ms=? WHERE owner_ws=?", int(time.time() * 1000) - 1, WS_A)
    assert cli.main(["admin", "--data", two.data, "sweep"]) == 0
    out = capsys.readouterr().out
    assert "expired=1" in out
    assert two.sql("SELECT state FROM shares")[0]["state"] == "expired"
