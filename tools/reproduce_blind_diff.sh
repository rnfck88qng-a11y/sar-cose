#!/usr/bin/env bash
# Reproduces the pre-resolution comparison behind "disagreements in 6,000 decisions" (paper §6.4):
# sar_cose as published at commit e2e39dd (v1.1.0 code plus a README change) against the blind
# version of the second implementation reconstructed in independent/original_blind/
# (MAX_FUTURE_SKEW = 0, i.e. before the D1 amendment), using tools/cross_diff.py with
# N = 1500 scenarios per generator (2 generators x 1500 x 2 artifact makers = 6,000 decisions).
# The scenario generators in test_sar_properties.py are identical at e2e39dd and today.
#   PYTHON=/path/to/python tools/reproduce_blind_diff.sh [N]
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
N="${1:-1500}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
git -C "$HERE" archive e2e39dd sar_cose.py test_sar_properties.py | tar -x -C "$T"
echo "reference: sar_cose.py at $(git -C "$HERE" rev-parse --short e2e39dd) (sha256 $(shasum -a 256 "$T/sar_cose.py" | cut -d' ' -f1))"
echo "blind:     independent/original_blind/sar_indep.py (sha256 $(shasum -a 256 "$HERE/independent/original_blind/sar_indep.py" | cut -d' ' -f1))"
cd "$T"
PYTHONDONTWRITEBYTECODE=1 SAR_REF_DIR="$T" SAR_INDEP_DIR="$HERE/independent/original_blind" "$PY" -B "$HERE/tools/cross_diff.py" "$N"
