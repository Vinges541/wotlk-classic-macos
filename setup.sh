#!/bin/sh
set -eu
WRATH_REPO=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$WRATH_REPO/scripts/bootstrap.py" "$@"
