#!/bin/bash
# Installs or updates the orch-apps host on a Debian server with Caddy. Idempotent.
#
#   sudo bash host/install.sh app.severin.io [path/to/orch-apps-key.pub]
#
# Creates the users orch-apps (SSH entry, no sudo except one line for orch-apps-host) and orch-apps-web (share
# server), the folders under /srv/orch-apps, the systemd units and timers, and the Caddy site file
# /etc/caddy/sites/<domain>.caddy. Caddy is validated before the reload; a refused config is rolled back.
set -euo pipefail

DOMAIN="${1:?usage: install.sh <domain> [public key file]}"
PUBKEY="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || { echo "invalid domain: $DOMAIN" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
say() { printf '== %s\n' "$*"; }

say "users"
id orch-apps >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/orch-apps --shell /bin/sh orch-apps
id orch-apps-web >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin orch-apps-web
id orch-apps orch-apps-web

say "uv"
if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi
uv --version

say "folders"
install -d -m 755 -o root -g root /srv/orch-apps /srv/orch-apps/apps /srv/orch-apps/deps
install -d -m 750 -o orch-apps -g orch-apps /srv/orch-apps/incoming /srv/orch-apps/incoming/shares \
  /srv/orch-apps/incoming/apps
install -d -m 750 -o root -g orch-apps-web /srv/orch-apps/shares /srv/orch-apps/state
install -d -m 700 -o root -g root /srv/orch-apps/archive /srv/orch-apps/cache /var/backups/orch-apps
install -d -m 755 -o root -g root /etc/caddy/orch-apps
[ -f /etc/caddy/orch-apps/_readme.caddy ] || \
  printf '# Generated per-app snippets of orch-apps live here. Do not edit by hand.\n' > /etc/caddy/orch-apps/_readme.caddy

say "program"
rm -rf /usr/local/lib/orch-apps.new
install -d -m 755 /usr/local/lib/orch-apps.new
cp -r "$HERE/orch_apps_host" /usr/local/lib/orch-apps.new/
find /usr/local/lib/orch-apps.new -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root /usr/local/lib/orch-apps.new
find /usr/local/lib/orch-apps.new -type d -exec chmod 755 {} +
find /usr/local/lib/orch-apps.new -type f -exec chmod 644 {} +
rm -rf /usr/local/lib/orch-apps.old
[ -d /usr/local/lib/orch-apps ] && mv /usr/local/lib/orch-apps /usr/local/lib/orch-apps.old
mv /usr/local/lib/orch-apps.new /usr/local/lib/orch-apps
install -m 755 -o root -g root "$HERE/bin/orch-apps-host" "$HERE/bin/orch-apps-gate" /usr/local/bin/

say "sudoers"
tmp="$(mktemp)"
printf 'orch-apps ALL=(root) NOPASSWD: /usr/local/bin/orch-apps-host\n' > "$tmp"
visudo -cf "$tmp"
install -m 440 -o root -g root "$tmp" /etc/sudoers.d/orch-apps
rm -f "$tmp"

if [ -n "$PUBKEY" ]; then
  say "ssh key"
  key="$(head -n1 "$PUBKEY")"
  [[ "$key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo "expected one ssh-ed25519 public key" >&2; exit 2; }
  install -d -m 700 -o orch-apps -g orch-apps /home/orch-apps/.ssh
  printf 'restrict,command="/usr/local/bin/orch-apps-gate" %s\n' "$key" > /home/orch-apps/.ssh/authorized_keys
  chown orch-apps:orch-apps /home/orch-apps/.ssh/authorized_keys
  chmod 600 /home/orch-apps/.ssh/authorized_keys
fi

say "systemd"
install -m 644 -o root -g root "$HERE"/systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orch-apps-web.service orch-apps-sweep.timer orch-apps-backup.timer
systemctl restart orch-apps-web.service

say "caddy"
site="/etc/caddy/sites/$DOMAIN.caddy"
prev=""
if [ -f "$site" ]; then prev="$(mktemp)"; cp -a "$site" "$prev"; fi
sed "s/__DOMAIN__/$DOMAIN/g" "$HERE/caddy/site.caddy" > "$site.new"
chmod 644 "$site.new"
mv "$site.new" "$site"
# validate with Caddy's own service environment: other sites may use {$VARS} from a systemd drop-in
read -r -a caddy_env <<< "$(systemctl show caddy --property=Environment --value)"
if env "${caddy_env[@]}" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    >/dev/null 2>"/tmp/orch-apps-caddy.err"; then
  systemctl reload caddy
  [ -n "$prev" ] && rm -f "$prev"
  echo "caddy: valid, reloaded"
else
  if [ -n "$prev" ]; then mv "$prev" "$site"; else rm -f "$site"; fi
  echo "caddy refused the config, nothing applied:" >&2
  tail -n 5 /tmp/orch-apps-caddy.err >&2
  exit 1
fi

say "done"
systemctl is-active orch-apps-web.service orch-apps-sweep.timer orch-apps-backup.timer
