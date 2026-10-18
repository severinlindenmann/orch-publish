# orch-apps

An orch-core addon that publishes from a ticket: a web artifact as a temporary **share** (public, secret link or
sealed) and a mini app as a permanent **app**, both on your own server.

| Folder | What it is |
|---|---|
| `host/` | The server half: share server, app runtime, forced SSH command, systemd units, Caddy site, installer |
| `cli/` | The `orch-apps` command for agents and the addon (pack, seal, scaffold, test, deploy) |
| `addon/` | The orch-core addon: ticket card, Apps page, Today tile, decisions |

Status: in development (INT-0026). `host/` comes first.

## License

Licensed under the PolyForm Noncommercial License 1.0.0. Commercial use requires a separate license from the author. See [LICENSE](LICENSE).

## pubsrv share server: single worker

`orch-publish share` and `orch-publish dev` run exactly one uvicorn worker (`workers=1`, set explicitly). The
per-share open limit (30/min) and the per-IP bucket for landing GETs and opens live in process memory; more
workers would multiply them. The view count itself is atomic in SQLite and does not depend on this. Behind a
proxy the per-IP bucket sees the proxy's address, so put a per-IP limit in Caddy as well.
