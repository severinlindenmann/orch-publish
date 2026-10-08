"""Widgets for the Apps page, the ticket card and the Today tile. Read-only: everything comes from the cached
snapshots and the addon's own small files."""
from __future__ import annotations

import datetime as dt
import urllib.parse

from orch.addons.widgets import KV, Action, Badge, Card, Chips, Copy, Link, Table, Tabs, Text, Tile, Time

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


# -- Today ----------------------------------------------------------------------------------------------------------

def tile(view) -> list:
    if not view.snapshots("status"):
        return [Tile("Live", None, "neu", sub="not fetched yet")]
    apps = [a for a in of_type(view, "app") if a.get("text") == "running"]
    shares = [s for s in of_type(view, "share") if s.get("state") == "live"]
    return [Tile("Live", len(apps) + len(shares), "neu", href=f"/addons/{view.addon}/",
                 sub=f"{len(apps)} apps · {len(shares)} shares")]


# -- ticket card ----------------------------------------------------------------------------------------------------

def local_time(value: str | None) -> str:
    """08.10. 21:04 in this machine's time zone (for text that cannot hold a Time widget)."""
    if not value:
        return ""
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone()
    return t.strftime("%d.%m. %H:%M")


def until(share: dict):
    return Time(share["expires"], "at") if share.get("expires") else "the ticket is done"


def ticket_card(view) -> list:
    """Only what is live: ended shares belong to the Shares tab, not to the ticket."""
    tid = ticket_id(view)
    if not tid:
        return []
    local = state.local(view.state_dir)
    held = [s for s in staged(view) if s.get("ticket") == tid and s.get("published")
            and s["ref"] not in local["revealed"]]
    shares = [s for s in of_type(view, "share") if s.get("ticket") == tid and s.get("state") == "live"]
    apps = [a for a in of_type(view, "app") if a.get("ticket") == tid]
    if not (held or shares or apps):
        return []
    rows = []
    for a in apps:
        url = app_url(view, a)
        rows.append((Link(f"/{a['slug']}/", url) if url and a.get("text") == "running" else f"/{a['slug']}/",
                     Badge(a["role"], f"app, {a['text']}"),
                     Link("Manage", page_link(view, tab="apps", app=a["slug"]))))
    for s in shares:
        url = share_url(view, s)
        label = share_label(view, s)
        when = f"until {local_time(s['expires'])}" if s.get("expires") else "until the ticket is done"
        rows.append((Link(label, url) if url else label, f"{s['access']} share, {when}",
                     Action("revoke", "Revoke", s["ref"], quiet=True, detail=f"{label} stops working at once.")))
    body = []
    if held:
        body.append(Text(f"{held[0]['label']} is published. Its link is shown once; press Show link once and copy it."))
    body.append(Table(("Published", "Status", "Action"), tuple(rows), key=0,
                      empty="Nothing live from this ticket. Ended shares are on the Apps page."))
    for s in held[:1]:
        body.append(Action("reveal", "Show link once", s["ref"],
                           detail=f"{s['label']} ({s['access']}) is published. Its link is shown once."))
    return [Card("Published", tuple(body))]


# -- the Apps page --------------------------------------------------------------------------------------------------

def page(view) -> list:
    tab = view.params.get("tab") if view.params.get("tab") in dict(TABS) else "apps"
    if view.params.get("share") or view.params.get("show"):
        tab = "shares"
    if not view.snapshots("status"):
        return [Card("Apps", (Text("Nothing fetched from the server yet. It shows up after the first fetch; "
                                   "press Refresh."),))]
    apps, shares = of_type(view, "app"), of_type(view, "share")
    live = [s for s in shares if s.get("state") == "live"]
    memory = sum(a.get("memory_bytes") or 0 for a in apps if a.get("text") == "running")
    out = needs_you(view, apps)
    out += [Card("Overview", (KV((("Apps running", sum(1 for a in apps if a.get("text") == "running")),
                                  ("Shares live", len(live)), ("Shares waiting", len(waiting(view))),
                                  ("App memory, MB", mb(memory) or 0)), layout="stats"),)),
            Tabs(tuple(Link(label, page_link(view, tab=key), current=(key == tab)) for key, label in TABS),
                 label="Apps page views")]
    if tab == "apps":
        chosen = next((a for a in apps if a["slug"] == view.params.get("app")), None)
        out += app_view(view, chosen) if chosen else apps_tab(view, apps)
    elif tab == "shares":
        out += shares_tab(view, shares)
    else:
        out += server_tab(view, apps)
    return out


def waiting(view) -> list[dict]:
    """Staged shares: not published yet, or published with the link not shown yet."""
    local = state.local(view.state_dir)
    return [s for s in staged(view) if not s.get("published") or s["ref"] not in local["revealed"]]


def needs_you(view, apps: list[dict]) -> list:
    """One card at the top, only when something waits: links to show, shares to publish, failed apps."""
    rows = []
    for s in waiting(view):
        ticket = s.get("ticket") or ""
        if s.get("published"):
            rows.append((s["label"], f"{s['access']} share of {ticket}, link not shown yet",
                         Action("reveal", "Show link once", s["ref"],
                                detail=f"{s['label']} ({s['access']}) is published. Its link is shown once.")))
        else:
            rows.append((s["label"], f"{s['access']} share staged on {ticket}, waiting to be published",
                         Link("Open the ticket", f"/t/{ticket}")))
    for a in apps:
        if a.get("role") == "err" or a.get("message"):
            rows.append((a["label"], a.get("message") or f"{a['slug']} {a['text']}",
                         Link("Details and logs", page_link(view, tab="apps", app=a["slug"]))))
    if not rows:
        return []
    return [Card("Needs you", (Badge("warn", f"{len(rows)} waiting"), Table(("What", "Why", "Next"), tuple(rows), key=0,
                                     empty="Nothing waits for you."),), role="warn")]


def app_actions(a: dict) -> list:
    out = []
    if a.get("text") == "stopped":
        out.append(Action("start", "Start", a["slug"], detail=f"/{a['slug']}/ starts answering again."))
    else:
        if a.get("stack") != "static":
            out.append(Action("restart", "Restart", a["slug"], detail=f"/{a['slug']}/ restarts with the same version."))
        out.append(Action("stop", "Stop", a["slug"], quiet=True, detail=f"/{a['slug']}/ answers that it is stopped."))
    out.append(Action("delete", "Delete", a["slug"], quiet=True,
                      detail=f"{a['label']} at /{a['slug']}/ stops now, its address goes away and its data moves to "
                             f"the server's archive."))
    return out


def app_summary(a: dict) -> str:
    parts = [f"{a.get('stack')} · {a.get('store')}"]
    if a.get("access") == "secret":
        parts.append("secret link")
    if a.get("ticket"):
        parts.append(a["ticket"])
    return " · ".join(parts)


def apps_tab(view, apps: list[dict]) -> list:
    if not apps:
        return [Card("Apps", (Text("No apps yet. Ask an agent for a mini app on a ticket; it builds it with orch-apps "
                                   "and deploys it after your yes."),))]
    cards = []
    for a in apps:
        url = app_url(view, a)
        running = a.get("text") == "running"
        body = [Badge(a["role"], a["text"]),
                Link(f"/{a['slug']}/", url) if url and running else Text(f"/{a['slug']}/"),
                Text(app_summary(a)),
                KV((("Memory, MB", mb(a.get("memory_bytes")) or 0), ("Data, kB", round((a.get("data_bytes") or 0) / 1000))),
                   layout="stats")]
        if url and running and a.get("access") != "secret":
            body.append(Copy("Copy address", url))
        body.append(Link("Details and logs", page_link(view, tab="apps", app=a["slug"])))
        body += app_actions(a)
        cards.append(Card(a["label"], tuple(body), role="err" if a.get("role") == "err" else None))
    return [Card("Apps", tuple(cards), layout="grid")]


def app_view(view, a: dict) -> list:
    url = app_url(view, a)
    rows = [("Address", Link(f"/{a['slug']}/", url) if url else f"/{a['slug']}/"),
            ("Access", "secret link" if a.get("access") == "secret" else "public"),
            ("Stack", f"{a.get('stack')} · {a.get('store')}"),
            ("Ticket", a.get("ticket") or ""),
            ("Version", a.get("version") or "unknown"),
            ("Memory", f"{mb(a['memory_bytes'])} of 128 MB" if a.get("memory_bytes") else "no process"),
            ("Data", human_size(a.get("data_bytes"))),
            ("Deployed", Time(a["deployed_at"]) if a.get("deployed_at") else "unknown")]
    body = [Link("All apps", page_link(view, tab="apps")), Badge(a["role"], a["text"]), KV(tuple(rows))]
    if url and a.get("access") != "secret":
        body.append(Copy("Copy address", url))
    if a.get("message"):
        body.append(Text(a["message"]))
    body += app_actions(a)
    out = [Card(a["label"], tuple(body), role="err" if a.get("role") == "err" else None)]
    logs = items(view, "logs", a["slug"])
    if a.get("stack") == "static":
        out.append(Card("Log", (Text("A static app has no process and no log."),)))
    else:
        out.append(Card("Log", (Table(("Time", "Log line"),
                                      tuple((i["label"][:19].replace("T", " "), i["text"]) for i in logs[-20:]),
                                      key=1, empty="No log lines in the last fetch. They show up after the app "
                                                   "writes some; press Refresh."),)))
    return out


def shares_tab(view, shares: list[dict]) -> list:
    live = [s for s in shares if s.get("state") == "live"]
    ended = [s for s in shares if s.get("state") != "live"]
    wait = waiting(view)
    show = view.params.get("show") if view.params.get("show") in ("waiting", "ended") else "live"
    chips = Chips((Link(f"Live ({len(live)})", page_link(view, tab="shares"), current=show == "live"),
                   Link(f"Waiting for you ({len(wait)})", page_link(view, tab="shares", show="waiting"),
                        current=show == "waiting"),
                   Link(f"Ended ({len(ended)})", page_link(view, tab="shares", show="ended"), current=show == "ended")),
                  label="Show", show_label=False)
    out = [chips]
    chosen = next((s for s in shares if s["ref"] == view.params.get("share")), None)
    if chosen:
        out.append(share_card(view, chosen))
    if show == "live":
        if not live:
            out.append(Card("No live shares", (Text("An agent stages a share with orch-apps share; you publish it "
                                                    "from its ticket."),)))
        for ticket in sorted({s.get("ticket") or "" for s in live}):
            rows = []
            for s in sorted((s for s in live if (s.get("ticket") or "") == ticket), key=lambda s: s.get("expires") or "~"):
                url = share_url(view, s)
                rows.append((Link(f"{share_label(view, s)} · {s['access']}",
                                  page_link(view, tab="shares", share=s["ref"])),
                             Time(s["expires"], "at") if s.get("expires") else "when the ticket is done",
                             Copy("Copy link", url) if url else None,  # a secret or sealed link was shown once
                             Action("revoke", "Revoke", s["ref"], quiet=True,
                                    detail=f"{share_label(view, s)} stops working at once.")))
            out.append(Card(ticket or "No ticket", (Table(("Share", "Ends", "Link", "Action"), tuple(rows),
                                                          empty="No live shares on this ticket."),)))
    elif show == "waiting":
        rows = tuple((s["label"], s.get("ticket") or "",
                      "published, link not shown yet" if s.get("published") else "staged, waiting to be published",
                      Action("reveal", "Show link once", s["ref"]) if s.get("published")
                      else Link("Open the ticket", f"/t/{s.get('ticket')}")) for s in wait)
        out.append(Card("Waiting for you", (Table(("Share", "Ticket", "State", "Next"), rows,
                                                  empty="Nothing waits: every staged share is published and its "
                                                        "link was shown."),)))
    else:
        rows = tuple((Link(share_label(view, s), page_link(view, tab="shares", show="ended", share=s["ref"])),
                      Badge(s["role"], s["access"]), s.get("ticket") or "", s.get("state") or "ended",
                      Time(s.get("revoked") or s.get("expires"), "at") if (s.get("revoked") or s.get("expires")) else "")
                     for s in sorted(ended, key=lambda s: s.get("revoked") or s.get("expires") or "", reverse=True))
        out.append(Card("Ended", (Table(("Share", "Access", "Ticket", "Ended", "When"), rows,
                                        empty="No ended shares. The server forgets them 30 days after they end."),)))
    return out


def share_card(view, s: dict) -> Card:
    url = share_url(view, s) if s.get("state") == "live" else None
    address = Link("Open the shared page", url) if url else (
        "secret or sealed: the link was shown once at publish" if s["access"] != "public"
        else "ended, the link no longer works")
    body = [KV((("Address", address), ("Access", s["access"]), ("Ticket", s.get("ticket") or ""),
                ("Views", s.get("views") or 0), ("Size", human_size(s.get("size"))),
                ("Until", until(s) if s.get("state") == "live" else s.get("state") or "ended")))]
    if url:
        body.append(Copy("Copy link", url))
    if s.get("state") == "live":
        body.append(Action("revoke", "Revoke share", s["ref"]))
    return Card(share_label(view, s), tuple(body))


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
    """Ends within a day, and was meant to live longer than a day: a share published for one day is not asked
    about the moment it is published."""
    if share.get("state") != "live" or not share.get("expires"):
        return False
    end = dt.datetime.fromisoformat(share["expires"].replace("Z", "+00:00"))
    if share.get("created"):
        start = dt.datetime.fromisoformat(share["created"].replace("Z", "+00:00"))
        if end - start <= dt.timedelta(days=1, hours=1):
            return False
    return now < end <= now + dt.timedelta(days=1)
