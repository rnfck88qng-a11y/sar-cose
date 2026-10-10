#!/usr/bin/env bash
# Runs every suite. Usage: PYTHON=/path/to/python ./run_tests.sh   (SAR_DEEP=1 for 10x scenarios)
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
cd "$HERE" || exit 2
rc=0
echo "== sar_cose: original harness, gap, COSE, property, hardening and cross-implementation suites"
PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_cose "$PY" -m unittest -v \
  test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties test_sar_hardening test_sar_cross || rc=1
echo "== independent (blind) implementation: original harness"
PYTHONPATH="$HERE/independent:$HARNESS" SAR_IMPL=sar_indep "$PY" -m unittest test_sar_conformance || rc=1
echo "== independent (blind) implementation: its own tests"
(cd independent && PYTHONPATH=. "$PY" -m unittest test_indep) || rc=1
rm -rf .hypothesis independent/.hypothesis
exit $rc
