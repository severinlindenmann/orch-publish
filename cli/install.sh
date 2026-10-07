#!/bin/bash
# Installs the orch-apps command for this user: a small launcher in ~/.local/bin that runs cli/orch_apps.py from this
# checkout with uv. With --skill <dir>, also copies the agent skill to <dir>/orch-apps/ (for example
# ~/.claude/skills or a repository's .claude/skills).
#
#   bash cli/install.sh [--skill ~/.claude/skills]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${ORCH_APPS_BIN:-$HOME/.local/bin}"
SKILL_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skill) SKILL_DIR="${2:?--skill needs a folder}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
command -v uv >/dev/null || { echo "orch-apps needs uv: https://docs.astral.sh/uv/" >&2; exit 1; }

mkdir -p "$BIN"
cat > "$BIN/orch-apps" <<EOF
#!/bin/sh
# orch-apps launcher, written by $HERE/install.sh
exec uv run --quiet --script "$HERE/orch_apps.py" "\$@"
EOF
chmod 755 "$BIN/orch-apps"
echo "installed $BIN/orch-apps"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: $BIN is not on your PATH" ;; esac

if [ -n "$SKILL_DIR" ]; then
  mkdir -p "$SKILL_DIR/orch-apps"
  cp "$HERE/skill/SKILL.md" "$SKILL_DIR/orch-apps/SKILL.md"
  echo "installed the skill in $SKILL_DIR/orch-apps"
fi
"$BIN/orch-apps" --help >/dev/null && echo "orch-apps runs"
