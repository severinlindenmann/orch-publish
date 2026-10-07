"""Widgets for the Apps page, the ticket card and the Today tile. Read-only: everything comes from the cached
snapshots and the addon's own small files."""
from __future__ import annotations

import datetime as dt
import urllib.parse

from orch.addons.widgets import KV, Action, Badge, Card, Copy, Link, Search, Table, Tabs, Text, Tile, Time

from . import state

TABS = (("apps", "Apps"), ("shares", "Shares"), ("server", "Server"))


# -- reading the snapshots ------------------------------------------------------------------------------------------

def items(view, provider: str, scope: str | None = None) -> list[dict]:
    out = []
    for snap in view.snapshots(provider):
        if scope is None or snap.scope == scope:
            out += list(snap.items)
    return out


def of_type(view, kind: str) -> list[dict]:
    """Items of one type that carry what the views need; anything else in a snapshot is ignored."""
    need = {"app": "slug", "share": "ref", "host": "id"}[kind]
    return [i for i in items(view, "status") if i.get("type") == kind and i.get(need)]


def staged(view) -> list[dict]:
    return [i for i in items(view, "staged") if i.get("type") == "stage" and i.get("ref")]


def host(view) -> dict:
    found = of_type(view, "host")
    return found[0] if found else {}


def domain(view) -> str:
    return (view.settings.get("domain") or host(view).get("domain") or "").strip().strip("/")


def share_url(view, share: dict) -> str | None:
    d = domain(view)
    return f"https://{d}/s/{share['ref']}/" if d and share.get("access") == "public" else None


def app_url(view, app: dict) -> str | None:
    d = domain(view)
    return f"https://{d}/{app['slug']}/" if d else None


def names(view) -> dict:
    return state.local(view.state_dir)["names"]


def mb(value) -> int | None:
    return round(value / 1_000_000) if isinstance(value, (int, float)) else None


def human_size(value) -> str:
    if not isinstance(value, (int, float)):
        return "unknown"
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if value >= size:
            return f"{value / size:.1f} {unit}"
    return f"{int(value)} bytes"


def page_link(view, **params) -> str:
    return f"/addons/{view.addon}/?" + urllib.parse.urlencode({k: v for k, v in params.items() if v})


def ticket_id(view) -> str | None:
    t = view.ticket
    return getattr(t, "id", None) or (t if isinstance(t, str) else None)


def share_label(view, share: dict) -> str:
    name = names(view).get(share["ref"])
    return f"{name} (s/{share['ref']})" if name else f"s/{share['ref']}"


def ends(share: dict):
    if share.get("state") != "live":
        return share.get("state") or "ended"
    return Time(share["expires"], "at") if share.get("expires") else "when its ticket is done"


# -- Today ----------------------------------------------------------------------------------------------------------

def tile(view) -> list:
    if not view.snapshots("status"):
        return [Tile("Live", None, "neu", sub="not fetched yet")]
    apps = [a for a in of_type(view, "app") if a.get("text") == "running"]
    shares = [s for s in of_type(view, "share") if s.get("state") == "live"]
    return [Tile("Live", len(apps) + len(shares), "neu", href=f"/addons/{view.addon}/",
                 sub=f"{len(apps)} apps · {len(shares)} shares")]


# -- ticket card ----------------------------------------------------------------------------------------------------

def ticket_card(view) -> list:
    tid = ticket_id(view)
    if not tid:
        return []
    local = state.local(view.state_dir)
    held = [s for s in staged(view) if s.get("ticket") == tid and s.get("published")
            and s["ref"] not in local["revealed"]]
    shares = [s for s in of_type(view, "share") if s.get("ticket") == tid]
    apps = [a for a in of_type(view, "app") if a.get("ticket") == tid]
    if not (held or shares or apps):
        return []
    rows = []
    for a in apps:
        url = app_url(view, a)
        rows.append((Link(a["slug"], url) if url else a["slug"], Badge(a["role"], a["text"]), "permanent app"))
    for s in shares:
        url = share_url(view, s) if s.get("state") == "live" else None
        label = share_label(view, s)
        rows.append((Link(label, url) if url else label, Badge(s["role"], f"{s['access']}, {s['state']}"), ends(s)))
    body = [Table(("Published", "Status", "Ends"), tuple(rows), empty="Nothing published from this ticket yet.")]
    actions = []
    for s in held[:1]:
        actions.append(Action("reveal", "Show link once", s["ref"],
                              detail=f"{s['label']} ({s['access']}) is published. Its link is shown once."))
    for s in [s for s in shares if s.get("state") == "live"][: 3 - len(actions)]:
        actions.append(Action("revoke", f"Revoke s/{s['ref']}", s["ref"], quiet=True))
    if held:
        body.insert(0, Text(f"{len(held)} share(s) published from this ticket wait for their link to be shown once."))
    return [Card("Published", tuple(body + actions))]


# -- the Apps page --------------------------------------------------------------------------------------------------

def page(view) -> list:
    tab = view.params.get("tab") if view.params.get("tab") in dict(TABS) else "apps"
    if view.params.get("share"):
        tab = "shares"
    if not view.snapshots("status"):
        return [Card("Apps", (Text("Nothing fetched from the server yet. It shows up after the first fetch; "
                                   "press Refresh."),))]
    apps, shares = of_type(view, "app"), of_type(view, "share")
    live = [s for s in shares if s.get("state") == "live"]
    attention = [a for a in apps if a.get("role") == "err"]
    memory = sum(a.get("memory_bytes") or 0 for a in apps if a.get("text") == "running")
    out = [Card("Overview", (KV((("Apps running", sum(1 for a in apps if a.get("text") == "running")),
                                 ("Shares live", len(live)), ("Need attention", len(attention)),
                                 ("App memory, MB", mb(memory) or 0)), layout="stats"),)),
           Tabs(tuple(Link(label, page_link(view, tab=key), current=(key == tab)) for key, label in TABS),
                label="Apps page views")]
    if tab == "apps":
        out += apps_tab(view, apps)
    elif tab == "shares":
        out += shares_tab(view, shares)
    else:
        out += server_tab(view, apps)
    return out


def apps_tab(view, apps: list[dict]) -> list:
    rows = tuple((Link(a["label"], page_link(view, tab="apps", app=a["slug"])), Badge(a["role"], a["text"]),
                  f"{a.get('stack')} · {a.get('store')}", a.get("ticket") or "",
                  Time(a["deployed_at"]) if a.get("deployed_at") else "")
                 for a in apps)
    out = [Card("Apps", (Table(("App", "Status", "Stack", "Ticket", "Deployed"), rows,
                               empty="No apps yet. Ask an agent for a mini app on a ticket; it builds it with "
                                     "orch-apps and deploys it after your yes."),))]
    chosen = next((a for a in apps if a["slug"] == view.params.get("app")), None)
    if chosen:
        out.append(app_card(view, chosen))
    if apps:
        typed = (view.params.get("delete") or "").strip()
        target = next((a for a in apps if a["slug"] == typed), None)
        body = [Text("To delete an app, type its slug. Delete stops the app, removes its address and moves its "
                     "data to the server's archive."),
                Search("delete", typed, placeholder="slug of the app to delete")]
        if typed and not target:
            body.append(Text(f"No app is called {typed}."))
        if target:
            body.append(Action("delete", f"Delete {target['slug']}", target["slug"],
                               detail=f"{target['label']} at /{target['slug']}/ stops now; its data is archived."))
        out.append(Card("Delete an app", tuple(body)))
    return out


def app_card(view, a: dict) -> Card:
    url = app_url(view, a)
    rows = [("Address", Link(f"/{a['slug']}/", url) if url else f"/{a['slug']}/"),
            ("Access", "secret link" if a.get("access") == "secret" else "public"),
            ("Version", a.get("version") or "unknown"),
            ("Memory", f"{mb(a['memory_bytes'])} of 128 MB" if a.get("memory_bytes") else "no process"),
            ("Data", human_size(a.get("data_bytes"))),
            ("Deployed", Time(a["deployed_at"]) if a.get("deployed_at") else "unknown")]
    body = [Badge(a["role"], a["text"]), KV(tuple(rows))]
    if a.get("message"):
        body.append(Text(a["message"]))
    logs = items(view, "logs", a["slug"])
    if logs:
        body.append(Table(("Time", "Log line"), tuple((i["label"][:19].replace("T", " "), i["text"]) for i in logs[-12:]),
                          key=1, empty="No log lines in the last fetch. They show up after the app writes some."))
    elif a.get("stack") == "static":
        body.append(Text("A static app has no process and no log."))
    if a.get("text") == "stopped":
        body.append(Action("start", "Start app", a["slug"]))
    else:
        if a.get("stack") != "static":
            body.append(Action("restart", "Restart app", a["slug"]))
        body.append(Action("stop", "Stop app", a["slug"], quiet=True))
    return Card(a["label"], tuple(body), role="err" if a.get("role") == "err" else None)


def shares_tab(view, shares: list[dict]) -> list:
    order = {"live": 0, "expired": 1, "revoked": 2}
    shares = sorted(shares, key=lambda s: (order.get(s.get("state"), 3), s.get("expires") or "9999"))
    rows = tuple((Link(share_label(view, s), page_link(view, tab="shares", share=s["ref"])),
                  Badge(s["role"], s["access"] if s.get("state") == "live" else f"{s['access']}, {s['state']}"),
                  s.get("ticket") or "", s.get("views") or 0, ends(s)) for s in shares)
    out = [Card("Shares", (Table(("Share", "Access", "Ticket", "Views", "Ends"), rows,
                                 empty="No shares yet. An agent stages one with orch-apps share; you publish it "
                                       "from the ticket."),))]
    chosen = next((s for s in shares if s["ref"] == view.params.get("share")), None)
    if chosen:
        url = share_url(view, chosen)
        address = Link("Open the shared page", url) if url and chosen.get("state") == "live" else (
            "secret: the link was shown once at publish" if chosen["access"] != "public" else f"/s/{chosen['ref']}/")
        body = [KV((("Address", address), ("Access", chosen["access"]), ("Ticket", chosen.get("ticket") or ""),
                    ("Views", chosen.get("views") or 0), ("Size", human_size(chosen.get("size"))),
                    ("Ends", ends(chosen))))]
        if chosen.get("state") == "live":
            body.append(Action("revoke", "Revoke share", chosen["ref"]))
        out.append(Card(share_label(view, chosen), tuple(body)))
    return out


def server_tab(view, apps: list[dict]) -> list:
    h = host(view)
    rt = h.get("runtimes") or {}
    backup = h.get("backup") or {}
    memory = sum(a.get("memory_bytes") or 0 for a in apps if a.get("text") == "running")
    rows = (("Server", view.settings.get("host") or h.get("label") or "unknown"),
            ("Domain", domain(view) or "unknown"),
            ("Checked", Time(h["checked"]) if h.get("checked") else "unknown"),
            ("Runtimes", ", ".join(f"{k} {v}" for k, v in sorted(rt.items()) if v) or "unknown"),
            ("App memory", f"{mb(memory) or 0} MB, 128 MB per app"),
            ("Last backup", backup.get("last") or "none yet"),
            ("Backups kept", backup.get("kept") or 0))
    return [Card("Server", (Badge("ok", "reachable"), KV(rows), Copy("Check from a terminal", "orch-apps status")))]


# -- decisions ------------------------------------------------------------------------------------------------------

def soon(share: dict, now: dt.datetime) -> bool:
    if share.get("state") != "live" or not share.get("expires"):
        return False
    end = dt.datetime.fromisoformat(share["expires"].replace("Z", "+00:00"))
    return now < end <= now + dt.timedelta(days=1)
