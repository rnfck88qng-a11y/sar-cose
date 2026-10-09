#!/usr/bin/env bash
# Test-the-tests: the full suite must PASS on sar_cose and FAIL on every mutant
# (each mutant disables exactly one guard; see MUTANTS in sar_cose.py).
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_cose
cd "$HERE" || exit 2
SUITE="test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties"
fail=0; killed=0; total=0
if SAR_MUTANT= "$PY" -m unittest $SUITE >/dev/null 2>&1; then echo "PASS baseline"; else echo "FAIL baseline"; fail=1; fi
for m in $("$PY" -c 'import sar_cose; print(" ".join(sar_cose.MUTANTS))'); do
  total=$((total+1))
  out=$(SAR_MUTANT=$m "$PY" -m unittest $SUITE 2>&1)
  if echo "$out" | tail -1 | grep -q '^OK'; then
    echo "FAIL mutant $m SURVIVED"; fail=1
  else
    killed=$((killed+1)); n=$(echo "$out" | grep -E '^(FAIL|ERROR):' | wc -l | tr -d ' ')
    echo "PASS mutant $m killed ($n failing tests)"
  fi
done
echo "mutants killed: $killed/$total"
exit $fail
