"""End to end against the real orch-apps server: the addon's own resolve() and act() (what the Mission Control buttons
call) with the real orch-apps CLI, in a throwaway test workspace. Creates and removes its own test app and shares.

Run: ORCH_APPS_LIVE=1 pytest addon/tests/test_live.py -s
"""
import datetime as dt
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from orch.addons.api import Reveal
from orch.addons.manifest import load_manifest
from orch.addons.runtime import SlotView
from orch.errors import ValidationError

pytestmark = pytest.mark.skipif(os.environ.get("ORCH_APPS_LIVE") != "1",
                                reason="live test against the configured orch-apps server; set ORCH_APPS_LIVE=1")

ADDON = Path(__file__).resolve().parents[1]
NAME = load_manifest(ADDON).name
TICKET = "INT-0029"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c63f8cfc0f00f0004860280f62a8e2d0000000049454e44ae426082")


def step(text):
    print(f"{dt.datetime.now().strftime('%H:%M:%S')}  {text}", flush=True)


def cli(*argv, env=None):
    r = subprocess.run(["orch-apps", *argv, "--json"], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def http(url):
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def fetch(ws, addon):
    ctx = addon.ctx.provider_context()
    for p in addon.obj.providers:
        for scope in p.scopes(ctx):
            snap = p.fetch(ctx, scope, None)
            assert snap.health == "ok", f"{p.id}/{scope}: {snap.message}"
            ws.cache(NAME, snap)


def status_of(kind, ref):
    data = cli("status")
    key = "slug" if kind == "apps" else "id"
    return next((x for x in data[kind] if x[key] == ref), None)


def test_everything_the_buttons_do(orch_workspace, tmp_path):
    slug = f"live-{secrets.token_hex(3)}"
    env = {**os.environ, "ORCH_APPS_DIR": str(tmp_path / "apps")}
    page = tmp_path / "page"
    page.mkdir()
    (page / "dot.png").write_bytes(PNG)
    (page / "index.html").write_text('<!doctype html><meta charset="utf-8"><title>live</title><h1>Live check</h1>'
                                     '<img src="dot.png" alt="dot">')
    addon = orch_workspace.load(ADDON)  # no runner given: the real one, allowed to run orch-apps only
    ctx = lambda: addon.ctx.provider_context()  # noqa: E731

    step(f"deploy test app {slug} on {TICKET}")
    cli("new", slug, "--stack", "node", "--store", "sqlite", env=env)
    deployed = cli("deploy", slug, "--ticket", TICKET, env=env)
    app_url = deployed["url"]
    assert http(app_url) == 200

    step("stage a sealed share; the addon offers a Publish decision")
    sid = cli("share", str(page), "--ticket", TICKET, "--access", "sealed", "--expires", "7d")["id"]
    fetch(orch_workspace, addon)
    view = SlotView(orch_workspace.ws, addon, "today.from_addons")
    assert f"publish|{sid}" in [d.id for d in addon.obj.decisions(view)]

    step("Publish")
    msg = addon.obj.resolve(f"publish|{sid}", "publish", ctx())
    assert "Show link once" in msg, msg
    fetch(orch_workspace, addon)
    card = addon.obj.widgets("ticket.external", SlotView(orch_workspace.ws, addon, "ticket.external",
                                                         ticket=SimpleNamespace(id=TICKET)))
    assert any(getattr(w, "action", "") == "reveal" for c in card for w in c.body), "no Show link once on the card"

    step("Show link once, then a second press")
    revealed = addon.obj.act("reveal", sid, ctx())
    assert isinstance(revealed, Reveal) and "#k=" in revealed.text
    base = revealed.text.split("#")[0]
    assert http(base) == 200 and http(base + "blob") == 200
    with pytest.raises(ValidationError):
        addon.obj.act("reveal", sid, ctx())

    step("Revoke the share")
    fetch(orch_workspace, addon)
    assert "revoked" in addon.obj.act("revoke", sid, ctx())
    assert status_of("shares", sid)["state"] == "revoked" and http(base) == 410

    step("Stop, Start, Restart the app")
    fetch(orch_workspace, addon)
    assert "stopped" in addon.obj.act("stop", slug, ctx())
    assert status_of("apps", slug)["status"] == "stopped" and http(app_url) == 503
    fetch(orch_workspace, addon)
    assert "started" in addon.obj.act("start", slug, ctx())
    time.sleep(1)
    assert status_of("apps", slug)["status"] == "running" and http(app_url) == 200
    before = status_of("apps", slug)["active_since"]
    time.sleep(1.2)
    fetch(orch_workspace, addon)
    assert "restarted" in addon.obj.act("restart", slug, ctx())
    time.sleep(1)
    assert status_of("apps", slug)["active_since"] != before and http(app_url) == 200

    step("Delete the app; its logs then read as empty, not as a failure")
    fetch(orch_workspace, addon)
    assert "deleted" in addon.obj.act("delete", slug, ctx())
    assert status_of("apps", slug) is None and http(app_url) == 404
    fetch(orch_workspace, addon)  # asserts every provider is healthy, logs of the deleted app included

    step("A ticket moves to done: its open-ended share gets an end 7 days out")
    did = cli("share", str(page), "--ticket", "INT-0031", "--access", "public", "--expires", "done")["id"]
    cli("publish", did)
    box = []
    addon.obj.on_event(SimpleNamespace(kind="ticket.moved", ticket="INT-0031", data={"to": "done"}, seq=1,
                                       at="now"), SimpleNamespace(put=lambda data, item_id=None: box.append(
                                           {"id": item_id, "data": data}) or item_id))
    assert addon.obj.drain(ctx(), box) == [box[0]["id"]]
    end = dt.datetime.fromisoformat(status_of("shares", did)["expires"].replace("Z", "+00:00"))
    assert dt.timedelta(days=6, hours=23) < end - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(days=7)

    step("clean up: revoke the remaining test share")
    cli("revoke", did)
    step("all checks passed")
