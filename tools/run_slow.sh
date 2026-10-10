#!/usr/bin/env bash
# Slow runs, each archived in results/runs/ (tools/archive_run.py):
#   deep      SAR_DEEP=1 SAR_SEEDS=101,202,303,404,505 over the property, cross, hardening, gap, COSE,
#             conformance and SCITT suites
#   sweep     tools/mutation_sweep.py over sar_cose.py and sar_scitt.py (classified JSON in results/)
#   bench     5 x bench.py 2000, each with its load average
#   PYTHON=... tools/run_slow.sh [deep] [sweep] [bench]
HERE="$(cd "$(dirname "$0")/.." && pwd)"; cd "$HERE" || exit 2
export PYTHON="${PYTHON:-python3}" PYTHONDONTWRITEBYTECODE=1
A() { "$PYTHON" -B tools/archive_run.py "$@" > /dev/null; echo "$1: exit=$?"; }
what="${*:-deep sweep bench}"
SUITES="test_sar_properties test_sar_cross test_sar_hardening test_sar_gaps test_sar_cose_specific test_sar_conformance"
[ -f test_sar_scitt.py ] && SUITES="$SUITES test_sar_scitt"
for w in $what; do case $w in
  deep) A deep --env SAR_DEEP=1 --env SAR_SEEDS=101,202,303,404,505 --env PYTHONPATH="$HERE:$HERE/harness" --env SAR_IMPL=sar_cose \
          -- "$PYTHON" -B -m unittest -v $SUITES ;;
  sweep) A sweep_sar_cose -- "$PYTHON" -B tools/mutation_sweep.py --module sar_cose.py --jobs 12 --python "$PYTHON" --json results/sweep_sar_cose.json
         [ -f sar_scitt.py ] && A sweep_sar_scitt -- "$PYTHON" -B tools/mutation_sweep.py --module sar_scitt.py --jobs 12 --python "$PYTHON" --json results/sweep_sar_scitt.json ;;
  bench) for i in 1 2 3 4 5; do A "bench_$i" -- "$PYTHON" -B bench.py 2000; done ;;
esac; done
rm -rf .hypothesis independent/.hypothesis
