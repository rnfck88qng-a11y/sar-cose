#!/usr/bin/env bash
# Which hand-written mutants do the normative test vectors alone detect? Runs spec/run_vectors.py
# against sar_cose (core mutants) or sar_scitt (SCITT mutants) with each SAR_MUTANT.
HERE="$(cd "$(dirname "$0")/.." && pwd)"; cd "$HERE" || exit 2
PY="${PYTHON:-python3}"; export PYTHONDONTWRITEBYTECODE=1
det=0; tot=0
for m in $("$PY" -c 'import sar_cose, sar_scitt; print(" ".join(sar_cose.MUTANTS + sar_scitt.MUTANTS))'); do
  impl=sar_cose; "$PY" -c "import sar_scitt,sys; sys.exit(0 if '$m' in sar_scitt.MUTANTS else 1)" && impl=sar_scitt
  tot=$((tot+1))
  line=$(SAR_MUTANT=$m "$PY" -B spec/run_vectors.py --impl $impl --out /dev/null 2>&1 | head -1)
  f=$(echo "$line" | sed -E 's/.*fail ([0-9]+).*/\1/')
  if [ "$f" != "0" ]; then det=$((det+1)); echo "DETECTED $m ($impl, $f failing vectors)"; else echo "NOT-DETECTED $m ($impl)"; fi
done
echo "hand mutants detected by the vectors: $det/$tot"
