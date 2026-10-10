# Reconstructed blind version of the second implementation

The blind version of `sar_indep.py`, as it was before it was compared with `sar_cose`, was not committed at the time. This folder reconstructs it from the current files by reverting the documented amendments (`../DECISIONS.md`, "Amendments after the blind phase"):

- `sar_indep.py` differs from `../sar_indep.py` (as of commit d8ff22c) only in one line: `MAX_FUTURE_SKEW = 0` with the comment `# D1: no tolerance for future-dated statements` (the D1 amendment set it to 30). The round-2 change to offline verification with `at` (D5 amended) is not included either.
- `test_indep.py` differs from `../test_indep.py` (as of commit d8ff22c) only in the import line (`import sar_indep as S`, without importing `MAX_FUTURE_SKEW`) and in the two future-dated tests, where `MAX_FUTURE_SKEW` is replaced by 0. The exact literal text of those two lines in the blind phase is not preserved; the reconstruction substitutes 0.

It passes the original 12-test harness and its own 86 tests (`../../run_tests.sh` runs both).

`../../tools/reproduce_blind_diff.sh` compares it with `sar_cose` at commit e2e39dd (the version the blind implementation was compared with) on 2 × 1,500 scenarios built by each implementation (6,000 decisions). The reconstruction gives 128 disagreements; the paper's v1.2 draft reported 118 from the original, unpreserved run.
