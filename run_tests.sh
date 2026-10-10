#!/usr/bin/env bash
# Runs every suite. Usage: PYTHON=/path/to/python ./run_tests.sh   (SAR_DEEP=1 for 10x scenarios)
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
cd "$HERE" || exit 2
rc=0
echo "== sar_cose and sar_scitt: original harness, gap, COSE, property, hardening, cross-implementation and SCITT suites"
PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_cose "$PY" -m unittest -v \
  test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties test_sar_hardening test_sar_cross \
  test_sar_scitt || rc=1
echo "== second implementation (independent/, as amended): original harness"
PYTHONPATH="$HERE/independent:$HARNESS" SAR_IMPL=sar_indep "$PY" -m unittest test_sar_conformance || rc=1
echo "== second implementation (independent/, as amended): its own tests"
(cd independent && PYTHONPATH=. "$PY" -m unittest test_indep) || rc=1
echo "== reconstructed blind version (independent/original_blind/): original harness and its own tests"
PYTHONPATH="$HERE/independent/original_blind:$HARNESS" SAR_IMPL=sar_indep "$PY" -m unittest test_sar_conformance || rc=1
(cd independent/original_blind && PYTHONPATH=. "$PY" -m unittest test_indep) || rc=1
if [ -f independent/scitt/test_indep_scitt.py ]; then
  echo "== second SCITT implementation (independent/scitt/): its own tests"
  (cd independent/scitt && PYTHONPATH=.:.. "$PY" -m unittest test_indep_scitt) || rc=1
fi
rm -rf .hypothesis independent/.hypothesis independent/original_blind/.hypothesis independent/scitt/.hypothesis
exit $rc
