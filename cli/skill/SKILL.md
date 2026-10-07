---
name: orch-apps
description: Use when the user wants something from a ticket published on the web, or a small web app built and run for them - "share this page", "send the team a link to the report", "make a sealed link", "build me a mini app / tool / poll / form", "deploy it as a permanent app", "is my app running", "stop / delete the app", "revoke the share". Covers temporary shares of HTML pages (public, secret link, sealed) and permanent mini apps on the user's orch-apps host, with the orch-apps CLI.
---

# orch-apps: shares and mini apps

orch-apps puts two kinds of things on the user's own server, under one domain (for example `app.severin.io`):

| | Share | App |
|---|---|---|
| What | An HTML page or a folder of static files (HTML, CSS, JS, images, data files) | A small web app with a server and data |
| Lives | 1, 7 or 30 days, or 7 days after its ticket is done | Until it is deleted |
| Address | `/s/<id>/` | `/<slug>/` |
| Access | public, secret link, or sealed | public or secret link |

Run `orch-apps --help` for every command. Add `--json` to any command for machine-readable output.

## The two rules

1. **Publishing and deploying need the human's yes.** Prepare, build and test freely. Do not run `orch-apps publish` or `orch-apps deploy` until the human said yes to that exact share or app in this session, or pressed Publish in Mission Control. Revoke, stop and delete also need their yes.
2. **Only the menu below.** If a request needs anything that is not on it (a database server, Docker, a system package, a build step, a native module, a separate domain, background workers beyond the app itself), do not install it and do not work around it. Say plainly that it is not on the orch-apps menu, and offer the closest thing that is.

## The menu

| Stack | Use | What it may use |
|---|---|---|
| `static` | Pages, cheat sheets, calculators that run in the browser | HTML, CSS, JavaScript, Markdown files in `content/`. No server process. |
| `python` | Forms, small APIs, data tools | Python 3.13, the standard library or FastAPI/Jinja2, dependencies with `uv` and `uv.lock`, pure-Python wheels only (nothing that needs a compiler). |
| `node` | Polls, boards, small interactive tools | Node 24, `node:http` or Hono, built-in `node:sqlite`, `package-lock.json`, no native modules, no build step (no webpack, Vite, TypeScript compile). |

| Store | Means |
|---|---|
| `sqlite` | One SQLite file in `$DATA_DIR` (python `sqlite3`, node `node:sqlite`) |
| `json` | JSON files in `$DATA_DIR`, written to a temporary file and renamed |
| `markdown` | Markdown files in the app's `content/` folder, read-only at run time |
| `none` | Nothing kept; memory only |

A static app may use `markdown` or `none`. Python and node apps may use any store.

### Limits per app

128 MB memory and 25 % of one CPU (enforced by the host), 1 MB per request body (enforced by the web server). Keep data under 200 MB: that is not enforced, but nightly backups and the Apps page assume small apps. The app runs as its own unprivileged user and can write only to `$DATA_DIR`. `$DATA_DIR` survives deploys and is backed up every night.

### What every app gets and must do

| Variable | Value on the host | In `orch-apps test` |
|---|---|---|
| `PORT` | the port to listen on, on 127.0.0.1 | a free local port |
| `BASE_PATH` | `/<slug>` | `/<slug>` |
| `DATA_DIR` | `/var/lib/orch-apps-data/<slug>` | a fresh temporary folder |
| `APP_ENV` | `prod` | `local` |

- **Health:** answer `GET /health` with 200 within 30 seconds of starting. A deploy whose new version does not, is rolled back to the version before.
- **Base path:** requests arrive without the `/<slug>` prefix (`/<slug>/items` reaches the app as `/items`). Every link, form action, script and stylesheet in the pages must start with `BASE_PATH` or be relative. `orch-apps test` fails on links that leave the base path.
- **Manifest:** `app.toml` with `name`, `about`, `stack`, `store`, `start` (not for static), `health` (default `/health`) and `test` (the unit test command).

## Building an app

```bash
orch-apps new <slug> --stack node --store sqlite   # scaffolds apps/<slug>/ at the top of this repository
# write the app in apps/<slug>/, keep the template's structure, add tests
orch-apps test <slug>                               # must pass; runs it the way the host does
```

- The slug is 2 to 29 lowercase letters, digits and hyphens; `admin`, `s`, `api`, `health`, `static`, `assets` are taken.
- Escape everything users type before it goes into HTML. Cap request sizes and list lengths.
- Commit `apps/<slug>/` with the ticket key. Never commit `.venv`, `node_modules` or data.
- Then ask the human: "Deploy `<slug>` as a public app (or with a secret link)?" Only after their yes:

```bash
orch-apps deploy <slug> --ticket INT-0042 [--access secret]
```

A secret app's link is printed once; tell the human to keep it. `orch-apps deploy` runs `test` again first and uploads only changed files.

## Sharing a page

```bash
orch-apps share <file.html | folder> --ticket INT-0042 --access sealed --expires 7d
```

- `public`: anyone with the address. `secret`: the address carries a token (`/s/<id>.<token>/`), and the server keeps only its hash. `sealed`: the page is packed into one file and encrypted here, and the key travels only after `#`, so the server never sees the content.
- `share` only stages: nothing is uploaded. It prints notes (missing files, internet resources). A sealed page that loads anything from the internet is refused unless you pass `--allow-external`; say which resources load from where before you do.
- After the human's yes: `orch-apps publish <id>` prints the link **once**. Give it to the human right away; orch-apps forgets the key or token afterwards. With `--hold`, publish keeps the link for one `orch-apps reveal <id>` (the Mission Control button uses this).
- `orch-apps revoke <id>` ends a share now; `orch-apps extend <id> --expires 7d` moves its end.

## Looking after things

```bash
orch-apps status            # every app and share: state, memory, views, ticket, end
orch-apps logs <slug>       # recent log lines of an app
orch-apps stop|start|restart|delete <slug>
```

`delete` stops the app, removes its address and archives its data on the server. Ask first.

## Errors

The CLI exits 2 when something was refused (invalid input, not allowed, not set up) and 1 when it failed. Read the message: it says what to change. "no host set up yet" means the human has to run `orch-apps setup --ssh orch-apps@<server> --domain <domain>` once (add `--identity-file <path>` when the deploy key is a file their SSH config does not offer for that server). "Permission denied (publickey)" means the same: the key is not reaching the server.
