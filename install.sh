#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
ENGINE_DIR="$CONFIG_DIR/apollo-engine"

mkdir -p "$CONFIG_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --exclude '.git' \
    --exclude '.env' \
    --exclude 'node_modules' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'apollo-engine/apollo.db' \
    --exclude 'apollo-engine/.active_project' \
    --exclude 'apollo-engine/.nvd_cache.json' \
    --exclude 'apollo-engine/projects' \
    --exclude 'apollo-engine/reports' \
    "$REPO_DIR/" "$CONFIG_DIR/"
else
  cp -R "$REPO_DIR/." "$CONFIG_DIR/"
  rm -rf "$CONFIG_DIR/.git" "$CONFIG_DIR/node_modules" "$ENGINE_DIR/__pycache__" "$ENGINE_DIR/projects" "$ENGINE_DIR/reports"
  rm -f "$CONFIG_DIR/.env" "$ENGINE_DIR/apollo.db" "$ENGINE_DIR/.active_project" "$ENGINE_DIR/.nvd_cache.json"
fi

chmod +x "$CONFIG_DIR/apollo_activate.sh" "$ENGINE_DIR/setup_kali.sh" 2>/dev/null || true

if [ ! -f "$CONFIG_DIR/.env" ]; then
  cp "$CONFIG_DIR/.env.example" "$CONFIG_DIR/.env"
fi

python3 "$ENGINE_DIR/kb_manager.py" init >/dev/null 2>&1 || true
python3 "$ENGINE_DIR/kb_manager.py" project default >/dev/null 2>&1 || true

cat <<EOF
APOLLO ULTRA installed to: $CONFIG_DIR

Next steps:
1. Edit API keys only if needed:
   nano "$CONFIG_DIR/.env"

2. Load the environment:
   source "$CONFIG_DIR/.env"

3. Start Apollo Ultra in OpenCode:
   bash "$CONFIG_DIR/apollo_activate.sh" ultra default

4. Optional Kali/tooling setup:
   bash "$ENGINE_DIR/setup_kali.sh"
EOF
