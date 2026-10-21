#!/usr/bin/env bash
# shellcheck disable=SC2029
# Deploy orch-publish (API :8103 + share server :8104) to a dev host (ssh alias "orch-edge-deploy", user "deploy").
# Run from the dev machine: infra/dev/deploy.sh      (modeled on orch-relay infra/dev/deploy.sh)
# Refuses a dirty git tree unless ORCH_DEPLOY_ALLOW_DIRTY=1 (release is then named ...-dirty-<hash>).
# The units (orch-publish-api, orch-publish-share) come from the orch-dev-kit provisioning scripts.
# Health: the API has no unauthenticated route, so a signed-route probe must answer 401 (unknown workspace), the
# share server must answer 404 for an unknown share. A failed check rolls back to the previous release.
set -euo pipefail

HOST="${ORCH_DEPLOY_HOST:-orch-edge-deploy}"
BASE=/opt/orch
KEEP=5

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

sha="$(git rev-parse --short HEAD)"
dirty=""
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    if [ "${ORCH_DEPLOY_ALLOW_DIRTY:-}" != 1 ]; then
        echo "working tree is dirty; commit or set ORCH_DEPLOY_ALLOW_DIRTY=1" >&2
        exit 1
    fi
    dirty=1
fi

rm -rf dist
uv build --wheel
wheel="$(ls dist/orch_publish-*.whl)"
wheel_name="$(basename "$wheel")"
version="$(printf '%s' "$wheel_name" | cut -d- -f2)"
wheel_sha="$(shasum -a 256 "$wheel" | cut -d' ' -f1)"
if [ -n "$dirty" ]; then
    release="publish-${version}-dirty-${wheel_sha:0:8}"
else
    release="publish-${version}-${sha}"
fi
rdir="${BASE}/releases/${release}"
echo "deploying ${release}"

ssh "$HOST" "mkdir -p '${rdir}' '${BASE}/publish'"
rsync -a "$wheel" "${HOST}:${rdir}/${wheel_name}"

# Everything below runs on the host under the shared deploy lock.
ssh "$HOST" bash -s -- "$rdir" "$wheel_name" "$wheel_sha" "$BASE" "$KEEP" <<'REMOTE'
set -euo pipefail
rdir="$1"; wheel_name="$2"; wheel_sha="$3"; base="$4"; keep="$5"
units="orch-publish-api orch-publish-share"

exec 9>"$base/.deploy.lock"
flock -n 9 || { echo "another deploy is running" >&2; exit 1; }

if [ "$(cat "$rdir/.wheel.sha256" 2>/dev/null || true)" != "$wheel_sha" ] \
        || [ ! -x "$rdir/venv/bin/orch-publish" ]; then
    py="$(command -v python3.14 || command -v python3)"
    rm -rf "$rdir/venv" "$rdir/.wheel.sha256"
    uv venv --python "$py" "$rdir/venv"
    uv pip install --python "$rdir/venv/bin/python" "$rdir/$wheel_name"
    printf '%s' "$wheel_sha" > "$rdir/.wheel.sha256"
fi
mkdir -p "$rdir/bin"
ln -sfn "$rdir/venv/bin/orch-publish" "$rdir/bin/orch-publish"
touch "$rdir"

switch() {
    ln -sfn "$1" "$base/publish/.current.new"
    mv -T "$base/publish/.current.new" "$base/publish/current"
}
restart_all() {
    local rc=0 u
    for u in $units; do
        sudo orch-unit enable "$u" || rc=1
        sudo orch-unit restart "$u" || rc=1
    done
    return "$rc"
}
probe() { # port path want-code
    local i code
    for i in 1 2 3 4 5 6 7 8 9 10; do
        code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1$2" || true)"
        if [ "$code" = "$3" ]; then echo "$1$2: $code"; return 0; fi
        sleep 1
    done
    echo "health check failed on :$1 (got ${code:-none}, want $3)" >&2
    return 1
}
check_all() {
    local rc=0
    probe 8103 /v1/ws/00000000000000000000000000000000/status 401 || rc=1
    probe 8104 /s/00000000000000000000000000000000 404 || rc=1
    return "$rc"
}

prev="$(readlink "$base/publish/current" || true)"
switch "$rdir"
if restart_all && check_all; then
    :
else
    echo "deploy failed" >&2
    for u in $units; do sudo orch-unit logs "$u" 50 || true; done
    if [ -n "$prev" ] && [ "$prev" != "$rdir" ]; then
        echo "rolling back to $prev" >&2
        switch "$prev"
        restart_all || true
    fi
    exit 1
fi

# shellcheck disable=SC2012
ls -1dt "$base"/releases/publish-* | tail -n +"$((keep + 1))" | while read -r old; do
    [ "$old" = "$rdir" ] || [ "$old" = "$prev" ] || rm -rf "$old"
done
REMOTE
