"""Providers: everything shown comes from the orch-apps CLI's JSON, fetched in the background (never during a render).

status  `orch-apps status --json`  every 5 minutes: apps, shares, the host
staged  `orch-apps staged --json`  every minute: shares staged on this machine (never their key or token)
logs    `orch-apps logs <slug>`    every 5 minutes, one scope per app with a process
"""
from __future__ import annotations

import json
from pathlib import Path

from orch.addons.api import Snapshot
from orch.addons.runner import AddonRunError

STATUS_ARGV = ["orch-apps", "status", "--json"]
STAGED_ARGV = ["orch-apps", "staged", "--json"]
SETUP = "orch-apps setup --ssh orch-apps@<server> --domain <domain>"

APP_ROLE = {"running": "info", "stopped": "neu", "failed": "err", "deploying": "info", "new": "info"}
SHARE_ROLE = {"live": "info", "expired": "neu", "revoked": "neu"}


def run_json(ctx, argv, timeout=40):
    """(data, None) or (None, Snapshot health and message)."""
    try:
        r = ctx.run(argv, timeout=timeout)
    except AddonRunError as e:
        return None, ("error", e.message)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        first = msg[0] if msg else f"{argv[1]} failed"
        if "no host set up" in first:
            return None, ("auth_required", f"orch-apps has no server yet: run {SETUP}")
        if "Permission denied" in first or "Host key verification failed" in first:
            return None, ("auth_required", "the server refused this machine's SSH key: run orch-apps status")
        if "Could not resolve" in first or "timed out" in first or "Connection refused" in first:
            return None, ("offline", first.removeprefix("failed: "))
        return None, ("error", first.removeprefix("failed: ").removeprefix("refused: "))
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, ("error", "orch-apps answered something that is not JSON")


def share_name(source: str | None) -> str:
    if not source:
        return ""
    p = Path(source)
    return f"{p.parent.name}/" if p.name == "index.html" and p.parent.name else p.name


class StatusProvider:
    id = "status"
    kind = "status"
    interval_s = 300

    def scopes(self, ctx):
        return ["host"]

    def fetch(self, ctx, scope, previous):
        data, problem = run_json(ctx, STATUS_ARGV)
        if problem:
            return Snapshot(self.id, scope, ctx.now(), health=problem[0], message=problem[1])
        items = [{"id": "host", "label": data.get("host") or "server", "role": "ok", "text": "reachable", "type": "host",
                  "checked": data.get("at"), "domain": data.get("domain"), "runtimes": data.get("runtimes") or {},
                  "backup": data.get("backup") or {}}]
        for a in data.get("apps", []):
            status = a.get("status") or "unknown"
            items.append({"id": f"app:{a['slug']}", "label": a.get("name") or a["slug"], "role": APP_ROLE.get(status, "neu"),
                          "text": status, "type": "app", **{k: a.get(k) for k in (
                              "slug", "name", "stack", "store", "access", "ticket", "version", "deployed_at",
                              "memory_bytes", "data_bytes", "message", "held", "active_since")}})
        for s in data.get("shares", []):
            state = s.get("state") or "unknown"
            items.append({"id": f"share:{s['id']}", "label": f"s/{s['id']}", "role": SHARE_ROLE.get(state, "neu"),
                          "text": state, "type": "share", "ref": s["id"], **{k: s.get(k) for k in (
                              "access", "ticket", "expires", "state", "views", "size", "created", "revoked")}})
        return Snapshot(self.id, scope, ctx.now(), items=tuple(items))


class StagedProvider:
    id = "staged"
    kind = "status"
    interval_s = 60

    def scopes(self, ctx):
        return ["local"]

    def fetch(self, ctx, scope, previous):
        data, problem = run_json(ctx, STAGED_ARGV, timeout=20)
        if problem:
            return Snapshot(self.id, scope, ctx.now(), health=problem[0], message=problem[1])
        items = []
        for s in data.get("staged", []):
            published = bool(s.get("published"))
            items.append({"id": f"stage:{s['id']}", "label": share_name(s.get("source")) or s["id"],
                          "role": "info", "text": "published, link not shown yet" if published else "staged",
                          "type": "stage", "ref": s["id"], "published": s.get("published"), **{k: s.get(k) for k in (
                              "ticket", "access", "expires", "expires_choice", "source", "files", "size",
                              "warnings")}})
        return Snapshot(self.id, scope, ctx.now(), items=tuple(items))


class LogsProvider:
    id = "logs"
    kind = "status"
    interval_s = 300

    def scopes(self, ctx):
        slugs = []
        for snap in ctx.snapshots("status"):
            slugs += [i["slug"] for i in snap.items if i.get("type") == "app" and i.get("stack") != "static"]
        return sorted(set(slugs))

    def fetch(self, ctx, scope, previous):
        try:
            r = ctx.run(["orch-apps", "logs", scope, "--lines", "20"], timeout=30)
        except AddonRunError as e:
            return Snapshot(self.id, scope, ctx.now(), health="error", message=e.message)
        if r.returncode != 0:
            first = ((r.stderr or "").strip().splitlines() or ["orch-apps logs failed"])[0]
            return Snapshot(self.id, scope, ctx.now(), health="error", message=first)
        lines = [line for line in r.stdout.splitlines() if line.strip()][-20:]
        items = []
        for n, line in enumerate(lines):
            at, _, text = line.partition(" ")
            items.append({"id": f"{scope}:{n}", "label": at, "role": "neu", "text": text.strip() or line})
        return Snapshot(self.id, scope, ctx.now(), items=tuple(items))
