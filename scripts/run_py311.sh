#!/bin/sh
set -eu

for PY_CAND in \
  "${ZCODE_SIDE_SESSIONS_PYTHON:-}" \
  "${ZCODE_SIDE_SESSIONS_PYTHON3:-}" \
  "/opt/homebrew/bin/python3" \
  "/usr/local/bin/python3" \
  "python3.14" \
  "python3.13" \
  "python3.12" \
  "python3.11" \
  "python3" \
  "${HOME:-}/.pyenv/shims/python3" \
  "/Library/Frameworks/Python.framework/Versions/Current/bin/python3"
do
  [ -n "$PY_CAND" ] || continue
  case "$PY_CAND" in
    */*) PY="$PY_CAND" ;;
    *) PY="$(command -v "$PY_CAND" 2>/dev/null || true)" ;;
  esac
  [ -n "$PY" ] && [ -x "$PY" ] && [ ! -d "$PY" ] || continue
  if "$PY" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    exec "$PY" -I -B "$@"
  fi
done

echo "side-sessions requires Python >= 3.11" >&2
exit 1
