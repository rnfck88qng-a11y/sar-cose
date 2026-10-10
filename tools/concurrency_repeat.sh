#!/usr/bin/env bash
# Repeats the two concurrency tests (threads 50x, processes 10x) and the deferred_tx mutant (10x).
#   PYTHON=... tools/concurrency_repeat.sh [THREAD_RUNS] [PROCESS_RUNS] [MUTANT_RUNS]
HERE="$(cd "$(dirname "$0")/.." && pwd)"; cd "$HERE" || exit 2
PY="${PYTHON:-python3}"; export PYTHONDONTWRITEBYTECODE=1
NT="${1:-50}"; NP="${2:-10}"; NM="${3:-10}"
T=test_sar_properties.StoreConcurrencyTests
ok=0; for _ in $(seq "$NT"); do PYTHONPATH=. "$PY" -m unittest $T.test_concurrent_presentations_allow_exactly_once >/dev/null 2>&1 && ok=$((ok+1)); done
echo "threads, fixed code: $ok/$NT passed"; okt=$ok
ok=0; for _ in $(seq "$NP"); do PYTHONPATH=. "$PY" -m unittest $T.test_concurrent_processes_allow_exactly_once >/dev/null 2>&1 && ok=$((ok+1)); done
echo "processes, fixed code: $ok/$NP passed"; okp=$ok
k=0; for _ in $(seq "$NM"); do SAR_MUTANT=deferred_tx PYTHONPATH=. "$PY" -m unittest $T.test_concurrent_presentations_allow_exactly_once >/dev/null 2>&1 || k=$((k+1)); done
echo "deferred_tx mutant: killed $k/$NM"
rm -rf .hypothesis
[ "$okt" = "$NT" ] && [ "$okp" = "$NP" ] && [ "$k" = "$NM" ]
