#!/usr/bin/env sh
# Lightweight launcher to run the package as a CLI command from the project tree.
# Usage: copy or symlink this file to /usr/local/bin/grudarin and ensure it's executable.

PY="python3"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

RUN_CODE="import runpy, sys; sys.path.insert(0, '$DIR'); sys.argv[0]='grudarin'; runpy.run_module('grudarin', run_name='__main__')"

exec "$PY" -c "$RUN_CODE" "$@"
