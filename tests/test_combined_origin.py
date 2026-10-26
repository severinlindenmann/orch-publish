"""No-domain mode: API and path-based share links on one origin (`orch-publish run`)."""

from fastapi.testclient import TestClient

from pubsrv import cli
from tests.serve_helpers import SID, Env


def test_one_port_serves_share_and_api(tmp_path):
    env = Env(tmp_path)
    env.share({"index.html": b"<p>hi</p>"}, expires=4_000_000_000_000)
    app = cli.combined_app(env.data, "100.64.0.5:8102")
    c = TestClient(app, base_url="http://100.64.0.5:8102", follow_redirects=False)
    r = c.get(f"/s/{SID}")
    assert r.status_code == 200 and "Open" in r.text  # share landing on the api origin
    r = c.get("/v1/ws/" + "b" * 32 + "/status")
    assert r.status_code == 403 and r.json()["error"] == "hub_required"  # still the signed api
    assert c.get("/s/nope").status_code == 404


def test_run_rejects_bad_origin(tmp_path, capsys):
    rc = cli.main(["run", "--data", str(tmp_path / "d"), "--listen", "127.0.0.1:1", "--public-origin", "http://x/p"])
    assert rc == 2
