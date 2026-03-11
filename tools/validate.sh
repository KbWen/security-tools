#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL="$ROOT/agentcortex/bin/validate.sh"

if [[ ! -f "$CANONICAL" ]]; then
  echo "cannot find canonical validate script: $CANONICAL" >&2
  exit 1
fi

exec bash "$CANONICAL" "$@"