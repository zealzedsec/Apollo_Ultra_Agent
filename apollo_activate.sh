#!/usr/bin/env bash
set -euo pipefail

# APOLLO ULTRA - OpenCode activation helper
# Usage: bash ~/.config/opencode/apollo_activate.sh [agent] [project]
# Agents: ultra, big-pickle, nemotron, north, mimo, pro, build, plan, general, explore, scout

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
ENGINE_DIR="$CONFIG_DIR/apollo-engine"
ENV_FILE="$CONFIG_DIR/.env"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

MODEL="${1:-ultra}"
PROJECT="${2:-${APOLLO_PROJECT:-default}}"

case "$MODEL" in
  big-pickle)
    export APOLLO_MODEL="opencode/big-pickle"
    export APOLLO_SMALL_MODEL="opencode/big-pickle"
    AGENT="apollo-big-pickle"; DESC="big-pickle" ;;
  deepseek|ultra)
    export APOLLO_MODEL="${APOLLO_MODEL:-opencode/deepseek-v4-flash-free}"
    export APOLLO_SMALL_MODEL="${APOLLO_SMALL_MODEL:-opencode/north-mini-code-free}"
    AGENT="apollo-ultra"; DESC="default Apollo agent" ;;
  nemotron)
    export APOLLO_MODEL="opencode/nemotron-3-ultra-free"
    export APOLLO_SMALL_MODEL="opencode/north-mini-code-free"
    AGENT="apollo-nemotron"; DESC="nemotron" ;;
  north)
    export APOLLO_MODEL="opencode/north-mini-code-free"
    export APOLLO_SMALL_MODEL="opencode/north-mini-code-free"
    AGENT="apollo-north"; DESC="north mini" ;;
  mimo)
    export APOLLO_MODEL="opencode/mimo-v2.5-free"
    export APOLLO_SMALL_MODEL="opencode/north-mini-code-free"
    AGENT="apollo-mimo"; DESC="mimo" ;;
  pro|v4)
    export APOLLO_MODEL="deepseek/deepseek-v4-pro"
    export APOLLO_SMALL_MODEL="opencode/north-mini-code-free"
    AGENT="apollo-deepseek-v4"; DESC="DeepSeek Pro" ;;
  build|plan|general|explore|scout)
    AGENT="$MODEL"; DESC="built-in OpenCode agent" ;;
  *)
    AGENT="apollo-ultra"; DESC="default Apollo agent" ;;
esac

export APOLLO_PROJECT="$PROJECT"
export OPENCODE_CONFIG="$CONFIG_DIR/opencode.jsonc"

python3 "$ENGINE_DIR/kb_manager.py" init >/dev/null 2>&1 || true
python3 "$ENGINE_DIR/kb_manager.py" project "$PROJECT" >/dev/null 2>&1 || true

cat <<EOF
APOLLO ULTRA ready
Agent : $AGENT ($DESC)
Project: $PROJECT
Config : $OPENCODE_CONFIG

Use /agents to list agents and /status to inspect the knowledge base.
EOF

exec opencode --agent "$AGENT"
