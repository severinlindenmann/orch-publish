# orch-apps

An orch-core addon that publishes from a ticket: a web artifact as a temporary **share** (public, secret link or
sealed) and a mini app as a permanent **app**, both on your own server.

| Folder | What it is |
|---|---|
| `host/` | The server half: share server, app runtime, forced SSH command, systemd units, Caddy site, installer |
| `cli/` | The `orch-apps` command for agents and the addon (pack, seal, scaffold, test, deploy) |
| `addon/` | The orch-core addon: ticket card, Apps page, Today tile, decisions |

Status: in development (INT-0026). `host/` comes first.
