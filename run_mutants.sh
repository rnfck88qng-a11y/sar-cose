#!/usr/bin/env bash
# Test-the-tests: the full suite must PASS on sar_cose/sar_scitt and FAIL on every mutant
# (each mutant disables exactly one guard; see MUTANTS in sar_cose.py and sar_scitt.py).
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/harness}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE:$HARNESS" SAR_IMPL=sar_cose
cd "$HERE" || exit 2
SUITE="test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties test_sar_hardening test_sar_cross test_sar_scitt"
fail=0; killed=0; total=0
if SAR_MUTANT= "$PY" -m unittest $SUITE >/dev/null 2>&1; then echo "PASS baseline"; else echo "FAIL baseline"; fail=1; fi
for m in $("$PY" -c 'import sar_cose, sar_scitt; print(" ".join(sar_cose.MUTANTS + sar_scitt.MUTANTS))'); do
  total=$((total+1))
  suite=$SUITE; "$PY" -c "import sar_scitt,sys; sys.exit(0 if '$m' in sar_scitt.MUTANTS else 1)" && suite=test_sar_scitt
  # decided by the exit code: test modules print statistics to stdout, so the last line of the
  # combined output is not necessarily unittest's OK/FAILED line
  out=$(SAR_MUTANT=$m "$PY" -m unittest $suite 2>&1); mrc=$?
  if [ "$mrc" = 0 ]; then
    echo "FAIL mutant $m SURVIVED"; fail=1
  else
    killed=$((killed+1)); n=$(echo "$out" | grep -E '^(FAIL|ERROR):' | wc -l | tr -d ' ')
    echo "PASS mutant $m killed ($n failing tests)"
  fi
done
echo "mutants killed: $killed/$total"
exit $fail
