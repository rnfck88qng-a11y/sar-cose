#!/usr/bin/env bash
# Shows the gap tests discriminate: the harness's illustrative stub is expected to FAIL them.
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_stub
cd "$HERE" || exit 2
"$PY" -m unittest -v test_sar_gaps
