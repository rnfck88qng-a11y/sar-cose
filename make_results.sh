#!/usr/bin/env bash
# Regenerates RESULTS.md: full test run (both implementations), hand-written mutants, the
# external audit mutants, concurrency stability, stub discrimination, the reproduction of the
# pre-resolution cross-implementation comparison, and the benchmark. The automated mutation
# sweep, the deep run and repeated benchmarks are slow and are appended separately.
# Local home-directory paths are replaced by "~".
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2
export PYTHON="${PYTHON:-python3}" PYTHONDONTWRITEBYTECODE=1
V() { "$PYTHON" -c "import importlib.metadata as m; print(m.version('$1'))"; }
CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)
{
  echo "# Results (raw output)"; echo
  echo "Run: $(date -u +%FT%TZ) · $CPU · $(uname -s) $(uname -r) · $("$PYTHON" --version) · cbor2 $(V cbor2) · cryptography $(V cryptography) · pycose $(V pycose) · hypothesis $(V hypothesis)"; echo
  echo "sar_cose.py sha256: \`$(shasum -a 256 sar_cose.py | cut -d' ' -f1)\` · independent/sar_indep.py sha256: \`$(shasum -a 256 independent/sar_indep.py | cut -d' ' -f1)\`"; echo
  echo '## ./run_tests.sh'; echo '```'; ./run_tests.sh 2>&1; echo "exit=$?"; echo '```'; echo
  echo '## ./run_mutants.sh'; echo '```'; ./run_mutants.sh 2>&1; echo "exit=$?"; echo '```'; echo
  echo '## Concurrency stability'; echo '```'
  T=test_sar_properties.StoreConcurrencyTests
  ok=0; for _ in $(seq 50); do PYTHONPATH=. "$PYTHON" -m unittest $T.test_concurrent_presentations_allow_exactly_once >/dev/null 2>&1 && ok=$((ok+1)); done
  echo "threads, fixed code: $ok/50 passed"
  ok=0; for _ in $(seq 10); do PYTHONPATH=. "$PYTHON" -m unittest $T.test_concurrent_processes_allow_exactly_once >/dev/null 2>&1 && ok=$((ok+1)); done
  echo "processes, fixed code: $ok/10 passed"
  k=0; for _ in $(seq 10); do SAR_MUTANT=deferred_tx PYTHONPATH=. "$PYTHON" -m unittest $T.test_concurrent_presentations_allow_exactly_once >/dev/null 2>&1 || k=$((k+1)); done
  echo "deferred_tx mutant: killed $k/10"; echo '```'; echo
  echo '## ./run_stub_against_gaps.sh (illustrative harness stub; failures expected)'; echo '```'; ./run_stub_against_gaps.sh 2>&1 | grep -E '\.\.\. |^Ran|^OK|FAILED'; echo '```'; echo
  echo '## tools/audit_mutants.py (20 semantic mutants from the external audit of v1.2)'; echo '```'; "$PYTHON" -B tools/audit_mutants.py --jobs 8 --python "$PYTHON" 2>&1 | cut -c1-140; echo '```'; echo
  echo '## tools/reproduce_blind_diff.sh (sar_cose at e2e39dd vs reconstructed blind version, 6,000 decisions)'; echo '```'; PYTHON="$PYTHON" tools/reproduce_blind_diff.sh 2>&1; echo '```'; echo
  echo '## bench.py 2000 (indicative only)'; echo '```'; "$PYTHON" bench.py 2000; echo '```'
} 2>&1 | sed -e "s#$HOME#~#g" > RESULTS.md
rm -rf .hypothesis independent/.hypothesis
grep -E '^Ran|^OK|^FAILED|mutants killed|passed$|killed [0-9]+/' RESULTS.md
