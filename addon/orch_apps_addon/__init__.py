"""orch-apps: publish a ticket's web page as a share and run mini apps on your orch-apps host, from Mission Control.

Everything goes through one allowlisted binary, the orch-apps CLI. The addon never sees a share's key or token: the
CLI keeps them in its own stage folder, and the one place a link with a secret appears is the Reveal of
"Show link once", which core shows once and never logs.
"""
from __future__ import annotations

import datetime as dt
import json

from orch.addons.api import PendingDecision, Reveal
from orch.errors import ValidationError

from . import state, views
from .providers import LogsProvider, StagedProvider, StatusProvider, run_json, share_name

PUT_OFF_HOURS = 24


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _iso(t: dt.datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


class OrchApps:
    def __init__(self, ctx):
        self.ctx = ctx
        self.page = f"page.{ctx.name}"
        self.providers = [StatusProvider(), StagedProvider(), LogsProvider()]

    # -- widgets ------------------------------------------------------------------------------------------------

    def widgets(self, slot, view):
        if slot == self.page:
            return views.page(view)
        if slot == "ticket.external":
            return views.ticket_card(view)
        if slot == "today.summary":
            return views.tile(view)
        return []

    # -- decisions ----------------------------------------------------------------------------------------------

    def decisions(self, view):
        local = state.local(view.state_dir)
        now = _now()
        put_off = {k for k, until in local["put_off"].items() if until > _iso(now)}
        out = []
        for s in views.staged(view):
            did = f"publish|{s['ref']}"
            if s.get("published") or did in put_off or not s.get("ticket"):
                continue
            ends = "7 days after the ticket is done" if s.get("expires_choice") == "done" else f"{s.get('expires_choice')}"
            body = (f"{s['label']}: {s.get('files')} file(s), {views.human_size(s.get('size'))}, staged by an agent. "
                    f"Publish puts it on {views.domain(view) or 'your orch-apps server'}; its link is shown once "
                    f"afterwards on this ticket.")
            if s.get("warnings"):
                body += " Note: " + " ".join(s["warnings"])[:600]
            choices = (("publish", "Publish"), ("later", "Not now"))
            if s.get("access") != "public":
                choices = (("publish", "Publish"), ("public", "Publish as public"), ("later", "Not now"))
            out.append(PendingDecision(id=did, title=f"Publish {s['label']} ({s['access']}, ends {ends})?",
                                       body=body[:2000], ticket=s["ticket"], choices=choices, role="info"))
        for s in views.of_type(view, "share"):
            did = f"expire|{s['ref']}"
            if did in put_off or not views.soon(s, now):
                continue
            out.append(PendingDecision(
                id=did, title=f"{views.share_label(view, s)} ends within a day",
                body=f"The {s['access']} share of {s.get('ticket')} was opened {s.get('views') or 0} times. "
                     f"It ends {s['expires']}.",
                ticket=s.get("ticket"), choices=(("extend", "Extend 7 days"), ("let", "Let it expire")), role="info"))
        return out

    def resolve(self, decision_id, choice, ctx):
        kind, _, ident = decision_id.partition("|")
        if kind == "publish":
            return self._publish(ident, choice, ctx)
        if kind == "expire":
            if choice == "extend":
                data, problem = run_json(ctx, ["orch-apps", "extend", ident, "--expires", "7d", "--json"])
                if problem:
                    return f"Could not extend s/{ident}: {problem[1]}"
                return f"s/{ident} now ends {data.get('expires')}."
            self._put_off(decision_id, until=_now() + dt.timedelta(days=2))
            return f"s/{ident} ends as planned."
        return None

    def _publish(self, stage_id, choice, ctx):
        staged = {s["ref"]: s for snap in ctx.snapshots("staged") for s in snap.items
                  if s.get("type") == "stage" and s.get("ref")}
        s = staged.get(stage_id)
        if choice == "later":
            self._put_off(f"publish|{stage_id}", until=_now() + dt.timedelta(hours=PUT_OFF_HOURS))
            return "Put off for a day. It stays staged on this machine."
        if not s:
            return "That share is no longer staged here. Press Refresh."
        if choice == "public":
            data, problem = run_json(ctx, ["orch-apps", "share", s["source"], "--ticket", s["ticket"], "--access",
                                           "public", "--expires", s.get("expires_choice") or "7d", "--json"], timeout=60)
            if problem:
                return f"Could not stage it as public: {problem[1]}"
            run_json(ctx, ["orch-apps", "discard", stage_id, "--json"])
            stage_id = data["id"]
        data, problem = run_json(ctx, ["orch-apps", "publish", stage_id, "--hold", "--json"], timeout=120)
        if problem:
            return f"Publishing failed: {problem[1]}"
        local = state.local(self.ctx.state_dir)
        local["names"][stage_id] = share_name(s.get("source")) or stage_id
        state.save_local(self.ctx.state_dir, local)
        state.record_share(self.ctx.records_dir, stage_id, s["ticket"], data.get("published") or _iso(_now()))
        return f"Published s/{stage_id}. Press Show link once on {s['ticket']} to get the link."

    def _put_off(self, decision_id, until):
        local = state.local(self.ctx.state_dir)
        local["put_off"][decision_id] = _iso(until)
        state.save_local(self.ctx.state_dir, local)

    # -- actions ------------------------------------------------------------------------------------------------

    def _snapshot_item(self, ctx, provider, item_id):
        for snap in ctx.snapshots(provider):
            for item in snap.items:
                if item["id"] == item_id:
                    return item
        return None

    def act(self, action_id, target, ctx):
        if action_id == "reveal":
            item = self._snapshot_item(ctx, "staged", f"stage:{target}")
            local = state.local(self.ctx.state_dir)
            if not item or not item.get("published") or target in local["revealed"]:
                raise ValidationError("This link was already shown once. If it is lost, revoke the share and "
                                      "publish it again.")
            data, problem = run_json(ctx, ["orch-apps", "reveal", target, "--json"])
            local["revealed"].append(target)
            state.save_local(self.ctx.state_dir, local)
            if problem:
                return ("The link was already shown once and is gone. If it is lost, revoke the share and publish "
                        "it again.")
            return Reveal(f"Link to {item.get('label') or 's/' + target}", data["url"])
        if action_id == "revoke":
            item = self._snapshot_item(ctx, "status", f"share:{target}")
            if not item or item.get("state") != "live":
                raise ValidationError(f"s/{target} is not a live share any more. Press Refresh.")
            data, problem = run_json(ctx, ["orch-apps", "revoke", target, "--json"])
            return f"Could not revoke s/{target}: {problem[1]}" if problem else f"s/{target} is revoked; its link no longer works."
        if action_id in ("start", "stop", "restart", "delete"):
            item = self._snapshot_item(ctx, "status", f"app:{target}")
            if not item:
                raise ValidationError(f"There is no app {target} any more. Press Refresh.")
            if action_id == "start" and item.get("text") != "stopped":
                raise ValidationError(f"{target} is not stopped.")
            data, problem = run_json(ctx, ["orch-apps", action_id, target, "--json"], timeout=90)
            if problem:
                return f"Could not {action_id} {target}: {problem[1]}"
            done = {"start": "started", "stop": "stopped", "restart": "restarted",
                    "delete": "deleted; its data is in the server's archive"}[action_id]
            return f"{target} {done}. The list updates with the next fetch; press Refresh to see it now."
        return None

    # -- events -------------------------------------------------------------------------------------------------

    def on_event(self, event, outbox):
        if event.kind == "ticket.moved" and (event.data or {}).get("to") == "done" and event.ticket:
            outbox.put({"ticket": event.ticket, "at": event.at}, item_id=f"done-{event.ticket}-{event.seq}")

    def drain(self, ctx, items):
        """A ticket is done: its shares that end "7 days after the ticket is done" (no end yet) get that end now."""
        data, problem = run_json(ctx, ["orch-apps", "status", "--json"])
        if problem:
            return []
        acked = []
        for item in items:
            ticket = (item.get("data") or {}).get("ticket")
            end = _iso(_now() + dt.timedelta(days=7))
            ok = True
            for s in data.get("shares", []):
                if s.get("ticket") == ticket and s.get("state") == "live" and not s.get("expires"):
                    _, problem = run_json(ctx, ["orch-apps", "extend", s["id"], "--expires", end, "--json"])
                    ok = ok and not problem
            if ok:
                acked.append(item["id"])
        return acked


def create(ctx):
    return OrchApps(ctx)
