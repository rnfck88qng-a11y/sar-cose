#!/usr/bin/env bash
# Runs the default checks and archives each run as results/runs/<name>.{json,log} (tools/archive_run.py):
# full test run (both implementations), hand-written mutants, external audit mutants, concurrency
# repeats, stub discrimination, the reproduction of the pre-resolution comparison, the normative
# test vectors, CDDL and conformance manifest, and which hand mutants the vectors detect. The slow runs (deep run, mutation
# sweeps, repeated benchmarks) are archived by tools/run_slow.sh. Afterwards
# tools/make_claims.py derives results/paper_claims.json from the archived runs and
# tools/render_results.py regenerates RESULTS.md from both. Local home paths become "~".
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2
export PYTHON="${PYTHON:-python3}" PYTHONDONTWRITEBYTECODE=1
A() { "$PYTHON" -B tools/archive_run.py "$@" > /dev/null; echo "$1: exit=$?"; }
A tests -- ./run_tests.sh
A hand_mutants -- ./run_mutants.sh
A audit_mutants -- "$PYTHON" -B tools/audit_mutants.py --jobs 8 --python "$PYTHON"
A concurrency -- tools/concurrency_repeat.sh 50 10 10
A stub_gaps --expect-fail -- ./run_stub_against_gaps.sh
A blind_diff -- tools/reproduce_blind_diff.sh
A vectors_regen -- "$PYTHON" -B spec/gen_vectors.py --check
A cddl -- "$PYTHON" -B spec/cddl_check.py
A vectors -- "$PYTHON" -B spec/run_vectors.py
A manifest -- "$PYTHON" -B spec/check_manifest.py --check
A vectors_vs_mutants -- tools/vectors_vs_mutants.sh
rm -rf .hypothesis independent/.hypothesis independent/original_blind/.hypothesis
"$PYTHON" -B tools/make_claims.py && "$PYTHON" -B tools/render_results.py && "$PYTHON" -B tools/render_docs.py
