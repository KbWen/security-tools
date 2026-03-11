#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL="$SCRIPT_DIR/agentcortex/bin/deploy.sh"

if [[ ! -f "$CANONICAL" ]]; then
  echo "cannot find canonical deploy script: $CANONICAL" >&2
  exit 1
fi

exec bash "$CANONICAL" "$@"