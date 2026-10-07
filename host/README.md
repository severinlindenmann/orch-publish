# orch-apps host

Serves shares at `https://<domain>/s/<id>/` and apps at `https://<domain>/<slug>/` on one Debian server behind Caddy.

## How it fits together

```
your machine ──ssh (key limited to one forced command)──▶ orch-apps-gate
                                                          ├─ rsync  → /srv/orch-apps/incoming   (as orch-apps)
                                                          └─ sudo orch-apps-host <command>       (validated)
orch-apps-host  → /srv/orch-apps/{shares,apps,deps,state}, systemd orch-app@<slug>, /etc/caddy/orch-apps/<slug>.caddy
orch-apps-web   → 127.0.0.1:8790, serves /s/<id>/ and checks secret links (runs as orch-apps-web, reads only)
```

## Access

| Access | Link | The server stores |
|---|---|---|
| public | `/s/<id>/` | the files |
| secret link | `/s/<id>.<token>/` (every file, data files included, under that address) | the files and the token's SHA-256 |
| sealed | `/s/<id>/#k=<key>` | `sealed.bin` only: `OAS1` · 12-byte nonce · AES-256-GCM ciphertext, additional data `orch-apps:<id>` |

Share documents get `Content-Security-Policy: sandbox …`, so their scripts run in an opaque origin and cannot reach
the apps on the same domain. Sealed pages are decrypted by `loader.html` in the browser and shown in a sandboxed
frame; the key never leaves the fragment.

## Commands (through the gate)

```
share put <id> --access public|secret|sealed --ticket INT-1 --expires <ISO>|none [--token-hash <sha256>]
share revoke <id>          share extend <id> --expires <ISO>|none
app deploy <slug> --ticket INT-1 --access public|secret [--token-hash <sha256>]
app start|stop|restart|delete <slug>      app logs <slug> [--lines N]
status --json              backup
```

Upload first with rsync into `incoming/shares/<id>/` or `incoming/apps/<slug>/`. Exit codes: 0 ok, 1 failed,
2 refused.

## Install

```
sudo bash host/install.sh app.severin.io /path/to/orch-apps-key.pub
```

## Tests

```
cd host && python3 -m unittest discover -s tests -t .
node --test host/tests/
```
