#!/usr/bin/env bash
# Runs the original 12 harness tests (unmodified, from the investigation brief) + gap tests +
# COSE-specific tests against sar_cose. Usage: PYTHON=/path/to/python ./run_tests.sh
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_cose
cd "$HERE" || exit 2
"$PY" -m unittest -v test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties
