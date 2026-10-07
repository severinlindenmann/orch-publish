import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from orch.addons.api import Reveal, Snapshot
from orch.addons.design_lint import own_names, widget_warnings
from orch.addons.manifest import load_manifest
from orch.addons.runtime import SlotView
from orch.addons.widgets import widget_problems
from orch.errors import ValidationError
from orch.testing import AddonContract, FakeRunner, ProviderContract
from orch_apps_addon.providers import LogsProvider, StagedProvider, StatusProvider

ADDON = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).with_name("fixtures")
MANIFEST = load_manifest(ADDON)
NAME = MANIFEST.name
PAGE = f"page.{NAME}"
SECRET_URL = "https://app.severin.io/s/stg0000002.SuperSecretTokenValue1234/"


def recordings():
    out = []
    for f in sorted(FIXTURES.glob("*.json")):
        data = json.loads(f.read_text())
        out += data if isinstance(data, list) else [data]
    return out


def runner(*extra):
    return FakeRunner([*extra, *recordings()], strict=False)


@pytest.fixture
def loaded(orch_workspace):
    """The addon with its three providers fetched once from the recorded CLI output."""
    run = runner()
    addon = orch_workspace.load(ADDON, runner=run)
    ctx = addon.ctx.provider_context()
    orch_workspace.cache(NAME, StatusProvider().fetch(ctx, "host", None))
    orch_workspace.cache(NAME, StagedProvider().fetch(ctx, "local", None))
    orch_workspace.cache(NAME, LogsProvider().fetch(ctx, "dodly", None))
    return addon


def render(orch_workspace, addon, slot, ticket=None, **params):
    view = SlotView(orch_workspace.ws, addon, slot, ticket=SimpleNamespace(id=ticket) if ticket else None, params=params)
    widgets = addon.obj.widgets(slot, view)
    problems = [p for w in widgets for p in widget_problems(w, slot=slot, manifest=MANIFEST)]
    assert problems == [], problems
    assert widget_warnings(widgets, slot, names=own_names(MANIFEST)) == []
    return widgets


def walk(widgets):
    for w in widgets:
        yield w
        for child in getattr(w, "body", ()) or ():
            yield from walk([child])
        for row in getattr(w, "rows", ()) or ():
            if isinstance(row, (tuple, list)):
                yield from walk([c for c in row if hasattr(c, "kind")])
        for item in getattr(w, "items", ()) or ():
            if hasattr(item, "kind"):
                yield from walk([item])


def texts(widgets):
    parts = [str(getattr(w, a, "")) for w in walk(widgets) for a in ("text", "title", "label") if getattr(w, a, "")]
    parts += [str(c) for w in walk(widgets) for row in (getattr(w, "rows", ()) or ())
              if isinstance(row, (tuple, list)) for c in row if isinstance(c, (str, int))]
    return " | ".join(parts)


# -- providers ------------------------------------------------------------------------------------------------------

def test_status_items(orch_workspace):
    snap = StatusProvider().fetch(orch_workspace.provider_context(MANIFEST, runner=runner()), "host", None)
    assert snap.health == "ok"
    by_id = {i["id"]: i for i in snap.items}
    assert by_id["app:dodly"]["role"] == "info" and by_id["app:notes"]["role"] == "neu"
    assert by_id["share:sec0000001"]["ref"] == "sec0000001" and by_id["share:old0000001"]["text"] == "revoked"
    assert by_id["host"]["domain"] == "app.severin.io"


@pytest.mark.parametrize("stderr, health", [
    ("refused: no host set up yet: run `orch-apps setup ...`", "auth_required"),
    ("failed: orch-apps@tix.severin.io: Permission denied (publickey).", "auth_required"),
    ("failed: ssh: Could not resolve hostname tix.severin.io", "offline"),
    ("failed: something else", "error"),
])
def test_cli_failures_become_health(orch_workspace, stderr, health):
    run = FakeRunner([{"argv": ["orch-apps", "status", "--json"], "returncode": 2, "stderr": stderr}])
    snap = StatusProvider().fetch(orch_workspace.provider_context(MANIFEST, runner=run), "host", None)
    assert snap.health == health and snap.message


def test_logs_of_a_deleted_app_are_empty_not_a_failure(orch_workspace):
    run = FakeRunner([{"argv": ["orch-apps", "logs", "gone-app", "--lines", "20"], "returncode": 2,
                       "stderr": "refused: no app gone-app"}])
    snap = LogsProvider().fetch(orch_workspace.provider_context(MANIFEST, runner=run), "gone-app", None)
    assert snap.health == "ok" and snap.items == ()


# -- views ----------------------------------------------------------------------------------------------------------

def card(widgets, title):
    return next(w for w in widgets if getattr(w, "title", None) == title)


def test_apps_tab_and_app_detail(orch_workspace, loaded):
    widgets = render(orch_workspace, loaded, PAGE, tab="apps", app="dodly")
    t = texts(widgets)
    assert "Dodly" in t and "Kassenbuch" in t and "listening" in t
    rows = {(a.action, a.target) for a in walk([card(widgets, "Apps")]) if a.kind == "action"}
    assert rows == {("stop", "dodly"), ("start", "notes"), ("stop", "kassenbuch")}  # one start or stop per row
    detail = card(widgets, "Dodly")
    assert {(a.action, a.target) for a in walk([detail]) if a.kind == "action"} == {("restart", "dodly"), ("stop", "dodly")}
    assert "https://app.severin.io/dodly/" in [getattr(w, "text", "") for w in walk([detail]) if w.kind == "copy"]


def test_stopped_app_offers_start(orch_workspace, loaded):
    detail = card(render(orch_workspace, loaded, PAGE, app="notes"), "Notes")
    assert [(a.action, a.target) for a in walk([detail]) if a.kind == "action"] == [("start", "notes")]


def test_delete_needs_the_typed_slug(orch_workspace, loaded):
    assert not [w for w in walk(render(orch_workspace, loaded, PAGE)) if getattr(w, "action", "") == "delete"]
    assert "No app is called dodl" in texts(render(orch_workspace, loaded, PAGE, delete="dodl"))
    [delete] = [w for w in walk(render(orch_workspace, loaded, PAGE, delete="dodly")) if getattr(w, "action", "") == "delete"]
    assert delete.target == "dodly"


def test_shares_tab_and_server_tab(orch_workspace, loaded):
    widgets = render(orch_workspace, loaded, PAGE, tab="shares", share="pub0000001")
    rows = [(a.action, a.target) for a in walk([card(widgets, "Shares")]) if a.kind == "action"]
    assert sorted(rows) == [("revoke", "pub0000001"), ("revoke", "sea0000001"), ("revoke", "sec0000001")]
    assert "old0000001" not in texts([card(widgets, "Shares")])  # ended shares sit behind the Ended chip
    detail = card(widgets, "s/pub0000001")
    assert [(a.action, a.target) for a in walk([detail]) if a.kind == "action"] == [("revoke", "pub0000001")]
    assert "https://app.severin.io/s/pub0000001/" in [getattr(w, "text", "") for w in walk([detail]) if w.kind == "copy"]
    ended = render(orch_workspace, loaded, PAGE, tab="shares", show="ended", share="old0000001")
    assert "s/old0000001" in texts([card(ended, "Shares")])
    assert not [w for w in walk(ended) if w.kind == "action"]
    assert "node 24.21.0" in texts(render(orch_workspace, loaded, PAGE, tab="server")) or \
        any("node 24.21.0" in str(r) for w in walk(render(orch_workspace, loaded, PAGE, tab="server")) for r in getattr(w, "rows", ()))


def test_empty_page_before_the_first_fetch(orch_workspace):
    addon = orch_workspace.load(ADDON, runner=runner())
    assert "press Refresh" in texts(render(orch_workspace, addon, PAGE))


def test_ticket_card(orch_workspace, loaded):
    widgets = render(orch_workspace, loaded, "ticket.external", ticket="INT-0001")
    actions = [(a.action, a.target) for a in walk(widgets) if a.kind == "action"]
    assert ("reveal", "stg0000002") in actions
    assert sorted(a for a in actions if a[0] == "revoke") == [("revoke", "pub0000001"), ("revoke", "sec0000001")]
    assert "old0000001" not in texts(widgets)  # an ended share is not on the ticket
    assert render(orch_workspace, loaded, "ticket.external", ticket="INT-9999") == []


def test_today_tile(orch_workspace, loaded):
    [tile] = render(orch_workspace, loaded, "today.summary")
    assert tile.value == 5 and tile.sub == "2 apps · 3 shares"  # dodly and kassenbuch run; three shares are live


# -- decisions ------------------------------------------------------------------------------------------------------

def test_publish_decision_and_resolve(orch_workspace, loaded):
    view = SlotView(orch_workspace.ws, loaded, "today.from_addons")
    [d] = [d for d in loaded.obj.decisions(view) if d.id.startswith("publish|")]
    assert d.ticket == "INT-0001" and d.id == "publish|stg0000001"
    assert [c[0] for c in d.choices] == ["publish", "public", "later"]
    run = runner({"argv": ["orch-apps", "publish", "stg0000001", "--hold", "--json"], "stdout_json":
                  {"id": "stg0000001", "published": "2026-10-07T19:05:00Z", "url": None}})
    addon = orch_workspace.load(ADDON, runner=run)
    msg = addon.obj.resolve(d.id, "publish", addon.ctx.provider_context())
    assert "Show link once" in msg and "http" not in msg
    assert ("orch-apps", "publish", "stg0000001", "--hold", "--json") in run.calls
    records = json.loads((addon.ctx.records_dir / "shares.json").read_text())
    assert records == {"stg0000001": {"ticket": "INT-0001", "published": "2026-10-07T19:05:00Z"}}


def test_publish_as_public_restages_and_discards(orch_workspace, loaded):
    run = runner(
        {"argv": ["orch-apps", "share", "*", "--ticket", "INT-0001", "--access", "public", "--expires", "done", "--json"],
         "stdout_json": {"id": "pubnew0001"}},
        {"argv": ["orch-apps", "discard", "stg0000001", "--json"], "stdout_json": {"id": "stg0000001"}},
        {"argv": ["orch-apps", "publish", "pubnew0001", "--hold", "--json"], "stdout_json": {"id": "pubnew0001"}})
    addon = orch_workspace.load(ADDON, runner=run)
    assert "s/pubnew0001" in addon.obj.resolve("publish|stg0000001", "public", addon.ctx.provider_context())
    assert ("orch-apps", "discard", "stg0000001", "--json") in run.calls


def test_not_now_hides_the_decision_for_a_day(orch_workspace, loaded):
    addon = orch_workspace.load(ADDON, runner=runner())
    addon.obj.resolve("publish|stg0000001", "later", addon.ctx.provider_context())
    view = SlotView(orch_workspace.ws, addon, "today.from_addons")
    assert not [d for d in addon.obj.decisions(view) if d.id == "publish|stg0000001"]


def test_expiry_decision_and_extend(orch_workspace, loaded):
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=5)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    week_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=6)).replace(microsecond=0).isoformat()
    item = {"id": "share:end0000001", "ref": "end0000001", "label": "s/end0000001", "role": "info", "text": "live",
            "type": "share", "access": "secret", "ticket": "INT-0001", "expires": soon, "state": "live", "views": 4,
            "created": week_ago}
    one_day = dict(item, id="share:day0000001", ref="day0000001",
                   created=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=19)).isoformat())
    orch_workspace.cache(NAME, Snapshot("status", "host", dt.datetime.now(dt.timezone.utc), items=(item, one_day)))
    view = SlotView(orch_workspace.ws, loaded, "today.from_addons")
    [d] = [d for d in loaded.obj.decisions(view) if d.id.startswith("expire|")]
    assert d.id == "expire|end0000001" and [c[0] for c in d.choices] == ["extend", "let"]  # not the one-day share
    assert "T" not in d.title.split("ends ")[1] and "opened 4 times" in d.body
    run = runner({"argv": ["orch-apps", "extend", "end0000001", "--expires", "7d", "--json"],
                  "stdout_json": {"id": "end0000001", "expires": "2026-10-14T19:00:00Z"}})
    addon = orch_workspace.load(ADDON, runner=run)
    assert "2026-10-14" in addon.obj.resolve(d.id, "extend", addon.ctx.provider_context())


# -- actions --------------------------------------------------------------------------------------------------------

def test_reveal_once(orch_workspace, loaded):
    run = runner({"argv": ["orch-apps", "reveal", "stg0000002", "--json"], "stdout_json": {"url": SECRET_URL}})
    addon = orch_workspace.load(ADDON, runner=run)
    out = addon.obj.act("reveal", "stg0000002", addon.ctx.provider_context())
    assert isinstance(out, Reveal) and out.text == SECRET_URL and SECRET_URL not in repr(out)
    with pytest.raises(ValidationError):
        addon.obj.act("reveal", "stg0000002", addon.ctx.provider_context())
    assert not [w for w in walk(render(orch_workspace, addon, "ticket.external", ticket="INT-0001"))
                if getattr(w, "action", "") == "reveal"]


def test_actions_recheck_their_target(orch_workspace, loaded):
    run = runner({"argv": ["orch-apps", "revoke", "pub0000001", "--json"], "stdout_json": {"id": "pub0000001"}},
                 {"argv": ["orch-apps", "stop", "dodly", "--json"], "stdout_json": {"slug": "dodly"}},
                 {"argv": ["orch-apps", "delete", "kassenbuch", "--json"], "stdout_json": {"slug": "kassenbuch"}})
    addon = orch_workspace.load(ADDON, runner=run)
    ctx = addon.ctx.provider_context()
    assert "revoked" in addon.obj.act("revoke", "pub0000001", ctx)
    assert "stopped" in addon.obj.act("stop", "dodly", ctx)
    assert "deleted" in addon.obj.act("delete", "kassenbuch", ctx)
    for action, target in (("revoke", "old0000001"), ("revoke", "nothere001"), ("start", "dodly"), ("delete", "ghost")):
        with pytest.raises(ValidationError):
            addon.obj.act(action, target, ctx)


# -- events ---------------------------------------------------------------------------------------------------------

class Box:
    def __init__(self):
        self.items = []

    def put(self, data, *, item_id=None):
        self.items.append({"id": item_id, "data": data})
        return item_id


def test_done_ticket_sets_the_expiry_of_its_open_ended_shares(orch_workspace, loaded):
    box = Box()
    event = SimpleNamespace(kind="ticket.moved", ticket="INT-0001", data={"from": "testing", "to": "done"},
                            seq=7, at="2026-10-07T19:00:00Z")
    loaded.obj.on_event(event, box)
    loaded.obj.on_event(SimpleNamespace(kind="ticket.moved", ticket="INT-0002", data={"to": "testing"}, seq=8, at=""), box)
    assert [i["data"]["ticket"] for i in box.items] == ["INT-0001"]
    run = runner({"argv": ["orch-apps", "extend", "sec0000001", "--expires", "*", "--json"],
                  "stdout_json": {"id": "sec0000001"}})
    addon = orch_workspace.load(ADDON, runner=run)
    assert addon.obj.drain(addon.ctx.provider_context(), box.items) == [box.items[0]["id"]]
    extends = [c for c in run.calls if c[1] == "extend"]
    assert [c[2] for c in extends] == ["sec0000001"]  # pub0000001 already has an end; sea0000001 is another ticket
    end = dt.datetime.fromisoformat(extends[0][4].replace("Z", "+00:00"))
    assert dt.timedelta(days=6, hours=23) < end - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(days=7)


def test_records_and_local_state_hold_no_secret(orch_workspace, loaded):
    run = runner({"argv": ["orch-apps", "publish", "stg0000001", "--hold", "--json"], "stdout_json": {"id": "stg0000001"}},
                 {"argv": ["orch-apps", "reveal", "stg0000002", "--json"], "stdout_json": {"url": SECRET_URL}})
    addon = orch_workspace.load(ADDON, runner=run)
    ctx = addon.ctx.provider_context()
    addon.obj.resolve("publish|stg0000001", "publish", ctx)
    addon.obj.act("reveal", "stg0000002", ctx)
    stored = "".join(p.read_text() for p in (addon.ctx.records_dir, addon.ctx.state_dir)
                     for p in p.rglob("*.json") if p.is_file())
    assert "SuperSecretToken" not in stored and "https://" not in stored


# -- contracts ------------------------------------------------------------------------------------------------------

class TestStatusProvider(ProviderContract):
    @pytest.fixture
    def provider(self):
        return StatusProvider()

    @pytest.fixture
    def provider_ctx(self, orch_workspace):
        return orch_workspace.provider_context(MANIFEST, runner=runner())


class TestStagedProvider(ProviderContract):
    @pytest.fixture
    def provider(self):
        return StagedProvider()

    @pytest.fixture
    def provider_ctx(self, orch_workspace):
        return orch_workspace.provider_context(MANIFEST, runner=runner())


class TestAddon(AddonContract):
    addon_dir = ADDON
    runner = FakeRunner(recordings(), strict=False)
