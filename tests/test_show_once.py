"""Show-once semantics (design I11): atomic count, GET never counts, retries and prefetchers."""

import asyncio
import http.client
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from pubsrv import cli, db
from tests.serve_helpers import NOW, SID, TOKEN, Env


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@pytest.mark.parametrize("limit,tries", [(1, 16), (3, 16), (10, 24)])
def test_concurrent_opens_exactly_n_succeed(env, limit, tries):
    env.share({"index.html": b"x"}, limit=limit)
    barrier = threading.Barrier(tries)

    def go(_):
        c = TestClient(env.app, base_url="http://127.0.0.1:8104", follow_redirects=False)
        barrier.wait()
        return env.open(client=c).status_code

    with ThreadPoolExecutor(tries) as ex:
        codes = list(ex.map(go, range(tries)))
    assert codes.count(303) == limit, codes
    assert codes.count(410) == tries - limit, codes
    row = env.row()
    assert row["views"] == limit
    conn = db.connect(env.path)
    assert conn.execute("SELECT COUNT(*) FROM views").fetchone()[0] == limit
    conn.close()


def test_get_and_head_never_count(env):
    env.share({"index.html": b"x"})
    for _ in range(5):
        env.c.get(f"/s/{SID}")
        env.c.head(f"/s/{SID}")
        env.c.get(f"/s/{SID}?t={TOKEN}")
        env.c.get(f"/s/{SID}/open")
        env.c.get(f"/s/{SID}/v/{'e' * 32}/")
        env.c.options(f"/s/{SID}/open")
    assert env.row()["views"] == 0
    assert env.open().status_code == 303  # the one view is still there
    assert env.open().status_code == 410


def test_only_the_post_counts_and_second_open_is_refused(env):
    env.share({"index.html": b"x"})
    loc = env.view_url()
    second = env.open()
    assert second.status_code == 410 and "already opened" in second.text
    # the first opener keeps working for the length of the view session
    assert env.c.get(loc).status_code == 200
    env.now += 31 * 60 * 1000
    assert env.c.get(loc).status_code == 410


def test_expired_link_never_counts(env):
    env.share({"index.html": b"x"}, kind="secret", limit=0, expires=NOW + 1000)
    env.now = NOW + 1000
    assert env.open().status_code == 410
    assert env.row()["views"] == 0


def test_revoked_link_never_counts(env):
    env.share({"index.html": b"x"}, state="revoked", limit=3)
    assert env.open().status_code == 410
    assert env.row()["views"] == 0


def test_expired_state_row(env):
    env.share({"index.html": b"x"}, state="expired", limit=3)
    r = env.open()
    assert r.status_code == 410 and "expired" in r.text


def test_a_lost_redirect_does_not_refund_the_view(env):
    """The open spent the view even if the browser never followed the redirect (documented)."""
    env.share({"index.html": b"x"})
    assert env.open().status_code == 303
    assert env.row()["views"] == 1
    assert env.open().status_code == 410


def _raw_get(app, raw_path):
    """Drive the ASGI app with an exact raw_path (HTTP clients normalise dot segments)."""
    out = {}

    async def run():
        scope = {
            "type": "http",
            "method": "GET",
            "raw_path": raw_path,
            "path": "ignored",
            "query_string": b"",
            "headers": [],
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
                out["headers"] = dict(msg["headers"])
            else:
                out["body"] = msg["body"]

        await app(scope, receive, send)

    asyncio.run(run())
    return out


def test_raw_traversal_through_the_app(env, tmp_path):
    env.share({"index.html": b"x"}, kind="secret", limit=0)
    (tmp_path / "data" / "shares" / SID / "secret.txt").write_text("TOP-SECRET")
    base = env.view_url()
    ok = _raw_get(env.app, (base + "index.html").encode())
    assert ok["status"] == 200
    for evil in (
        "../secret.txt",
        "..%2Fsecret.txt",
        "%2e%2e/secret.txt",
        "a/../../secret.txt",
        "%2e%2e%2f%2e%2e%2fpublish.db",
        "..\\secret.txt",
    ):
        r = _raw_get(env.app, (base + evil).encode())
        assert r["status"] in (404, 400), evil
        assert b"TOP-SECRET" not in r["body"]
        assert r["headers"][b"x-content-type-options"] == b"nosniff"
    # a path that does not even match a route
    assert _raw_get(env.app, f"/s/{SID}/v/../..//etc".encode())["status"] == 404


def test_real_server_end_to_end_and_fragment_never_on_the_wire(tmp_path, capfd):
    """Real sockets via the dev runner's server class: the browser never sends a fragment; the
    token travels only in the POST body, and nothing is printed."""
    e = Env(tmp_path)
    e.share({"index.html": b"<p>real</p>"})
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = cli._uvicorn_server(e.app, "127.0.0.1", port)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", f"/s/{SID}")
        r = c.getresponse()
        page = r.read().decode()
        assert r.status == 200 and "location.hash" in page and TOKEN not in page
        c.request(
            "POST",
            f"/s/{SID}/open",
            body=f"t={TOKEN}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r = c.getresponse()
        r.read()
        assert r.status == 303
        loc = r.getheader("location")
        assert TOKEN not in loc
        c.request("GET", loc)
        r = c.getresponse()
        assert r.read() == b"<p>real</p>"
        for h in ("content-security-policy", "x-content-type-options", "referrer-policy"):
            assert r.getheader(h)
        assert r.getheader("server") is None or "uvicorn" in r.getheader("server")
    finally:
        srv.should_exit = True
        t.join(timeout=5)
    out, err = capfd.readouterr()
    assert TOKEN not in out + err
