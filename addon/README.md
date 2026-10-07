# orch-apps addon

Mission Control for [orch-apps](../README.md): publish a ticket's web page as a share, and look after the mini apps
on your orch-apps server.

## What it adds

| Where | What |
|---|---|
| Ticket page (`ticket.external`) | **Published**: the ticket's shares and apps, **Show link once** for a share just published, **Revoke** |
| Today and the ticket | A decision for every share an agent staged: **Publish**, **Publish as public**, **Not now**; and one a day before a share ends: **Extend 7 days**, **Let it expire** |
| Today (`today.summary`) | **Live**: running apps plus live shares |
| Menu **Apps** | Tabs **Apps** (status, logs, Restart, Stop or Start, Delete after typing the slug), **Shares** (Revoke), **Server** |
| Events | When a ticket moves to done, its shares set to end "7 days after the ticket is done" get that end on the server |

## Needs

- The `orch-apps` command on the `PATH` of `orch serve` (`bash cli/install.sh`), set up with
  `orch-apps setup --ssh orch-apps@<server> --domain <domain>`.
- Nothing else: the addon runs only `orch-apps` (`binaries: ["orch-apps"]`) and holds no secret.

## Settings

| Key | Use |
|---|---|
| `host` | The server name shown on the Server tab |
| `domain` | Domain for links; empty means the one `orch-apps setup` chose |

## Where secrets are

Nowhere in orch. A share's key or token stays in the CLI's stage folder (mode 0700) until **Show link once**; core
shows that Reveal once and never logs it, and the CLI then forgets it. `records/shares.json` holds only share id,
ticket and publish time.

## Install

```
orch addon install <path or git URL of orch-apps> --path addon
orch addon trust orch-apps
orch addon enable orch-apps
```

## Tests

```
uv run --project <orch-core plugin folder> pytest addon/tests
orch addon check addon --strict
```
