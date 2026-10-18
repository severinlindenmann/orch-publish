"""Share server: landing, open, view sessions, file serving, headers (design I8-I10, I13, I15)."""

import logging
import re

import pytest

from pubsrv import cli
from pubsrv.serve import FILE_CSP, INLINE_TYPES
from tests.serve_helpers import NOW, SID, TOKEN, Env

REQUIRED = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


def check_headers(r):
    for k, v in REQUIRED.items():
        assert r.headers.get(k) == v, (k, r.status_code)
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-robots-tag"].startswith("noindex")


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_landing_is_static_and_never_counts(env):
    env.share({"index.html": b"<p>hi</p>"})
    for _ in range(3):
        r = env.c.get(f"/s/{SID}")
        assert r.status_code == 200 and "Open" in r.text
        assert TOKEN not in r.text
        check_headers(r)
        assert "script-src 'sha256-" in r.headers["content-security-policy"]
    assert env.c.head(f"/s/{SID}").status_code == 200
    assert env.row()["views"] == 0


def test_token_never_in_a_get_and_page_reads_fragment(env):
    env.share({"index.html": b"x"})
    r = env.c.get(f"/s/{SID}")
    assert "location.hash" in r.text and 'method="post"' in r.text
    # a token in the path or query is just another address: it opens nothing and counts nothing
    assert env.c.get(f"/s/{SID}?t={TOKEN}").status_code == 200
    assert env.c.get(f"/s/{SID}/{TOKEN}").status_code == 404
    assert env.row()["views"] == 0


def test_open_then_files(env):
    env.share({"index.html": b"<h1>hello</h1>", "a/b.txt": b"text"})
    loc = env.view_url()
    assert re.fullmatch(rf"/s/{SID}/v/[0-9a-f]{{32}}/", loc)
    r = env.c.get(loc)
    assert r.status_code == 200 and r.content == b"<h1>hello</h1>"
    check_headers(r)
    assert r.headers["content-security-policy"] == FILE_CSP
    r2 = env.c.get(loc + "a/b.txt")
    assert r2.content == b"text" and r2.headers["content-type"].startswith("text/plain")
    # reloads inside the view session are free
    for _ in range(3):
        assert env.c.get(loc).status_code == 200
    assert env.row()["views"] == 1
    assert env.c.head(loc).status_code == 200


def test_listing_when_no_index(env):
    env.share({"r.md": b"# r", "d/x.txt": b"x"})
    loc = env.view_url()
    r = env.c.get(loc)
    assert "r.md" in r.text and "d/x.txt" in r.text
    check_headers(r)


def test_wrong_token_is_404_and_free(env):
    env.share({"index.html": b"x"})
    for bad in ("x" * 43, "short", "", TOKEN[:-1] + "Z"):
        r = env.open(token=bad)
        assert r.status_code == 404
        check_headers(r)
    assert env.c.post(f"/s/{SID}/open", data={}).status_code == 404
    assert env.row()["views"] == 0
    # wrong token on a spent link still says nothing about the link
    env.set("UPDATE shares SET views=1")
    assert env.open(token="x" * 43).status_code == 404


def test_missing_share_and_unknown_routes(env):
    for path in (
        f"/s/{'c' * 32}",
        "/",
        "/s/zz",
        f"/s/{SID}/nope",
        f"/s/{SID}/v/short/x",
        "/v1/ws/x/shares",
    ):
        r = env.c.get(path)
        assert r.status_code == 404, path
        check_headers(r)
    r = env.open("c" * 32)
    assert r.status_code == 404
    assert env.c.delete(f"/s/{SID}").status_code == 405
    check_headers(env.c.put(f"/s/{SID}"))
    assert env.c.get(f"/s/{SID}/open").status_code == 405
    assert env.c.post(f"/s/{SID}").status_code == 405


def test_staged_share_is_not_found(env):
    env.share({"index.html": b"x"}, state="staged")
    assert env.c.get(f"/s/{SID}").status_code == 404
    assert env.open().status_code == 404


def test_gone_pages_in_plain_words(env):
    env.share({"index.html": b"x"}, limit=1, views=1)
    r = env.c.get(f"/s/{SID}")
    assert r.status_code == 410 and "already opened" in r.text
    check_headers(r)
    r = env.open()
    assert r.status_code == 410 and "already opened" in r.text
    env.set("UPDATE shares SET state='revoked'")
    assert "removed" in env.open().text
    env.set("UPDATE shares SET state='live', views=0, expires_ms=?", NOW - 1)
    r = env.open()
    assert r.status_code == 410 and "expired" in r.text
    assert env.row()["views"] == 0


def test_revoke_and_expiry_bite_inside_a_view_session(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    loc = env.view_url()
    assert env.c.get(loc).status_code == 200
    env.set("UPDATE shares SET state='revoked'")
    r = env.c.get(loc)
    assert r.status_code == 410 and "removed" in r.text
    check_headers(r)
    env.set("UPDATE shares SET state='live', expires_ms=?", NOW + 1000)
    assert env.c.get(loc).status_code == 200
    env.now = NOW + 2000
    r = env.c.get(loc)
    assert r.status_code == 410 and "expired" in r.text


def test_view_session_lasts_30_minutes_and_is_bound_to_its_share(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    env.share({"index.html": b"y"}, sid="d" * 32, token="Q" * 43, kind="secret", limit=0)
    loc = env.view_url()
    other = loc.replace(SID, "d" * 32, 1)
    assert env.c.get(other).status_code == 404  # view id belongs to another share
    env.now = NOW + 30 * 60 * 1000 + 1
    r = env.c.get(loc)
    assert r.status_code == 410 and "ended" in r.text


def test_secret_link_counts_but_is_unlimited(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    for _ in range(5):
        assert env.open().status_code == 303
    assert env.row()["views"] == 5


def test_content_types_and_disposition(env):
    files = {
        "index.html": b"<p>x</p>",
        "p.svg": b"<svg onload=alert(1)/>",
        "d.pdf": b"%PDF",
        "x.exe": b"MZ",
        "noext": b"zz",
        "e.xml": b"<a/>",
        "i.png": b"\x89PNG",
        "n.js": b"1",
        "UP.HTML": b"<p>",
        "my file.txt": b"t",
    }
    env.share(files, kind="secret", limit=0)
    base = env.view_url()
    for name in files:
        r = env.c.get(base + name.replace(" ", "%20"))
        assert r.status_code == 200, name
        check_headers(r)
        assert r.headers["content-security-policy"] == FILE_CSP
        assert "sandbox" in r.headers["content-security-policy"]
        assert "allow-same-origin" not in r.headers["content-security-policy"]
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in INLINE_TYPES:
            assert "content-disposition" not in r.headers, name
            assert r.headers["content-type"] == INLINE_TYPES[ext]
        else:
            assert r.headers["content-disposition"].startswith("attachment"), name
            assert r.headers["content-type"] in ("application/octet-stream", "application/pdf")
    assert env.c.get(base + "x.exe").headers["content-type"] == "application/octet-stream"
    assert env.c.get(base + "p.svg").headers["content-type"].startswith("image/svg+xml")


def test_path_traversal_on_file_fetch(env, tmp_path):
    env.share({"index.html": b"x", "sub/ok.txt": b"ok"}, kind="secret", limit=0)
    secret = tmp_path / "data" / "shares" / SID / "secret.txt"
    secret.write_text("TOP-SECRET")
    other = tmp_path / "data" / "shares" / ("d" * 32) / "files"
    other.mkdir(parents=True)
    (other / "o.txt").write_text("OTHER-SHARE")
    (tmp_path / "data" / "publish.db-extra").write_text("DB")
    base = env.view_url()
    evil = [
        "../secret.txt",
        "..%2fsecret.txt",
        "%2e%2e/secret.txt",
        "%2e%2e%2fsecret.txt",
        "sub/../../secret.txt",
        "sub/%2e%2e/%2e%2e/secret.txt",
        "..%5csecret.txt",
        "....//secret.txt",
        f"../../{'d' * 32}/files/o.txt",
        "/etc/passwd",
        "%2Fetc%2Fpasswd",
        "sub/ok.txt%00.png",
        "sub/ok.txt%00",
        ".hidden",
        "sub//ok.txt",
        "sub/ok.txt/",
        "%252e%252e/secret.txt",
        "..;/secret.txt",
        "sub\\ok.txt",
        "%ff",
        "é.txt",
        "../../publish.db",
        "..%2f..%2fpublish.db",
    ]
    for e in evil:
        r = env.c.get(base + e)
        assert r.status_code in (404, 400), (e, r.status_code)
        assert b"TOP-SECRET" not in r.content and b"OTHER-SHARE" not in r.content, e
        check_headers(r)
    assert env.c.get(base + "sub/ok.txt").content == b"ok"


def test_symlinks_are_not_followed(env, tmp_path):
    env.share({"index.html": b"x", "d/f.txt": b"f"}, kind="secret", limit=0)
    top = tmp_path / "data" / "shares" / SID / "files"
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE")
    (top / "link.txt").symlink_to(outside)
    (top / "dirlink").symlink_to(tmp_path)
    base = env.view_url()
    for p in ("link.txt", "dirlink/outside.txt"):
        r = env.c.get(base + p)
        assert r.status_code == 404 and b"OUTSIDE" not in r.content


def test_oversized_open_body(env):
    env.share({"index.html": b"x"})
    r = env.c.post(
        f"/s/{SID}/open",
        content=b"t=" + b"a" * 5000,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 413
    check_headers(r)
    assert env.row()["views"] == 0


def test_open_rate_limit_per_share(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    codes = [env.open().status_code for _ in range(32)]
    assert codes[:30] == [303] * 30 and codes[30:] == [429, 429]
    env.now += 61_000
    assert env.open().status_code == 303
    # wrong tokens never use up the allowance
    assert env.open(token="y" * 43).status_code == 404


def test_no_logs_carry_the_token(env, caplog, capfd):
    caplog.set_level(logging.DEBUG)
    env.share({"index.html": b"x"})
    env.c.get(f"/s/{SID}")
    loc = env.view_url()
    env.c.get(loc)
    env.open()
    env.open(token="N" * 43)
    out, err = capfd.readouterr()
    assert TOKEN not in caplog.text + out + err
    assert ("N" * 43) not in caplog.text + out + err


def test_internal_error_fails_closed(env, monkeypatch):
    env.share({"index.html": b"x"})
    monkeypatch.setattr(env.app, "db_path", "/nonexistent/dir/x.db")
    r = env.c.get(f"/s/{SID}")
    assert r.status_code == 503
    check_headers(r)
    assert TOKEN not in r.text


def test_dev_runner_validation(capsys, tmp_path):
    d = str(tmp_path / "d")
    assert cli.main(["dev", "--data", d, "--api", "0.0.0.0:8103", "--share", "127.0.0.1:8104"]) == 2
    assert (
        cli.main(["dev", "--data", d, "--api", "127.0.0.1:8103", "--share", "127.0.0.1:8103"]) == 2
    )
    assert cli.main(["share", "--data", d, "--share-host", "8.8.8.8:80"]) == 2


def test_large_file_is_streamed_whole_and_head_sends_no_body(env):
    data = bytes(range(256)) * 2000  # 512000 bytes, several chunks
    env.share({"big.bin": data, "index.html": b"x"}, kind="secret", limit=0)
    base = env.view_url()
    r = env.c.get(base + "big.bin")
    assert r.content == data and r.headers["content-length"] == str(len(data))
    h = env.c.head(base + "big.bin")
    assert h.content == b"" and h.headers["content-length"] == str(len(data))


def test_landing_script_disables_the_button_after_submit(env):
    env.share({"index.html": b"x"})
    page = env.c.get(f"/s/{SID}").text
    assert "disabled=true" in page


def test_short_tokens_are_refused_before_any_lookup(env):
    env.share({"index.html": b"x"}, token="s" * 20)  # a host that made a short token
    assert env.open(token="s" * 20).status_code == 404


def test_per_ip_bucket_limits_landing_and_open_including_wrong_tokens(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    codes = [env.c.get(f"/s/{SID}").status_code for _ in range(130)]
    assert codes[:100].count(200) == 100 and 429 in codes
    r = env.open(token="w" * 43)
    assert r.status_code == 429 and env.row()["views"] == 0
    check_headers(r)


def test_script_clears_fragment_and_incomplete_hint(env):
    env.share({"index.html": b"x"})
    page = env.c.get(f"/s/{SID}").text
    assert "history.replaceState" in page and "Open the original link again" in page
