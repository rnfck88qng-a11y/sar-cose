# sar-cose: minimal SAR reference implementation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23270796.svg)](https://doi.org/10.5281/zenodo.23270796)

This is a small working implementation of the Sovereign Acceptance Runtime (SAR) authorization path described in the working paper *Sovereign Acceptance Runtime: Verifiable Human Ratification and Evidentiary Audit Trails for Autonomous AI Agents under the EU AI Act* (v1.2, October 2026; §4 and §6). It exists so that the paper's implementation claims rest on code and tests anyone can re-run.

It comes with a second implementation written blind from the paper (`independent/`). The two are checked against each other.

> **Status:** research prototype. It is not production software and has not had an independent security review. See *Limits* below.

## What it does

- **Proposal and Ratification Statements** are tagged `COSE_Sign1` objects (RFC 9052).
- **Payloads** are deterministic CBOR (RFC 8949 §4.2.1, checked against the Appendix A vectors).
- **Signatures** are Ed25519 with the fully specified algorithm identifier `-19` (RFC 9864).
- **The Execution Gate** follows the decision rules in [`SEMANTICS.md`](SEMANTICS.md) (S1–S13). It:
  - verifies both statement types;
  - enforces separation of roles in the policy;
  - denies on any invalid, expired, duplicate or rejecting ratification;
  - compares the runtime payload digest with the ratified one;
  - requires a common validity interval, so every ALLOW passes offline verification;
  - consumes the proposal id, nonce and transaction id atomically with recording the decision.
- **The store** is a SQLite hash chain. Its head is signed as a checkpoint after each commit, and the signing key can be kept across restarts. A checkpoint kept outside the database detects later truncation or rewriting. Writers take the database write lock before reading the chain tip (`BEGIN IMMEDIATE`), so several gates can share one database file.
- **Offline verification** needs only the artifacts and the policy's trust anchors. It uses no clock.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHON=.venv/bin/python ./run_tests.sh              # 115 tests on sar_cose + blind implementation (~15 s)
SAR_DEEP=1 PYTHON=.venv/bin/python ./run_tests.sh   # 10x scenarios, 1,000 Hypothesis examples (~10 min)
SAR_SEEDS=1,2,3 PYTHON=.venv/bin/python ./run_tests.sh  # add fresh seeds to the randomized tests
PYTHON=.venv/bin/python ./run_mutants.sh            # 26 hand-written mutants, each must be killed
.venv/bin/python tools/mutation_sweep.py            # automated mutation sweep (~10 min)
PYTHON=.venv/bin/python ./run_stub_against_gaps.sh  # gap tests vs the harness stub (failures expected)
.venv/bin/python bench.py 2000                      # indicative micro-benchmark
```

`RESULTS.md` holds the raw output of the last full run. `make_results.sh` regenerates it.

## Layout

| Path | Contents |
|---|---|
| `sar_cose.py` | The reference implementation |
| `SEMANTICS.md` | Normative decision rules S1–S13, and why each was chosen |
| `independent/` | Second implementation, written blind from the paper, with its own 86 tests and `DECISIONS.md` |
| `harness/` | Original 12-test conformance harness and illustrative stub (unmodified) |
| `test_sar_*.py` | Test suites (see below) |
| `tools/mutation_sweep.py`, `tools/EQUIVALENT_MUTANTS.md` | Automated mutation sweep, and the equivalence argument for every survivor |
| `tools/cross_diff.py` | Ad-hoc report of disagreements between the two implementations |
| `run_tests.sh`, `run_mutants.sh`, `run_stub_against_gaps.sh`, `make_results.sh`, `bench.py` | Runners |

## Test suites (115 tests on sar_cose)

| File | Tests | Purpose |
|---|---|---|
| `harness/test_sar_conformance.py` | 12 | Original scenario tests, written before the implementation, used unmodified |
| `test_sar_gaps.py` | 11 | Defects the original tests missed (C07c–C13); the harness stub fails 9 of 11 |
| `test_sar_cose_specific.py` | 16 | RFC 8949 vectors, COSE structure, algorithm/kid/content-type confusion, non-deterministic CBOR, pycose interop in both directions |
| `test_sar_properties.py` | 18 | Differential vs a reference model, bit flips, payload properties, time boundaries, concurrency (threads and processes), persistence |
| `test_sar_hardening.py` | 55 | Rules S1–S13, coverage gaps, external checkpoints, tests added for mutation-sweep survivors |
| `test_sar_cross.py` | 3 | sar_cose vs the blind implementation: byte-identical artifacts, identical decisions |

## Results (see `RESULTS.md`)

| Check | Default run | Deep run (`SAR_DEEP=1`, 5 extra seeds) |
|---|---|---|
| Gate vs model, randomized | 3,000 scenarios, 0 disagreements | 180,000, 0 disagreements |
| Gate vs model, single fault | 2,000; all 557 fault-free allowed, all 16 fault types always denied | 120,000; all 32,483 fault-free allowed, all faults denied |
| sar_cose vs blind implementation | 6,000 decision pairs, 0 disagreements | 360,000, 0 disagreements |
| Replay (where the first presentation was allowed) | 701 cases, second always denied | 41,891 cases, second always denied |
| Every ALLOW passes offline verification | checked in every allowed scenario | same |
| Concurrency | 16 threads and 8 processes on one database, 5 rounds each: exactly one ALLOW per round | thread test 50/50, process test 10/10 runs |
| Hand-written mutants | 26/26 killed | |
| Automated mutation sweep | 431/444 killed (97.1%); the 13 survivors are argued equivalent in `tools/EQUIVALENT_MUTANTS.md` | |

The randomized tests use fixed seeds by default, which makes them a reproducible test set. `SAR_SEEDS` and `SAR_DEEP` add fresh seeds and scale.

## What testing found

1. **Ratification binding untested.** The original harness never presented an approval issued for one proposal with a different proposal. Test C13 was added.
2. **Concurrent writers forked the hash chain.** Fixed with `BEGIN IMMEDIATE`; the `deferred_tx` mutant is killed 10/10.
3. **Found by the blind second implementation.** The differential found 118 disagreements in 6,000 decisions, all traced to choices the paper left open, now resolved in `SEMANTICS.md`. They exposed:
   - expired approvals ignored instead of denied, contrary to paper §4.7;
   - **no separation of roles**: one key under two overseer ids could meet a quorum of 2, and an agent listed as an overseer could approve its own proposal;
   - the gate could allow what offline verification later rejects.
4. **Gaps found by the automated mutation sweep.** These included missing tests for chained-comparison boundaries, ratifications with the right digest but the wrong id, touching but disjoint validity intervals, and ratified proposals with a bad agent signature. Tests were added; the remaining survivors are argued equivalent in `tools/EQUIVALENT_MUTANTS.md`.

## Limits

- **Origin of the tests.** The reference model, the extra tests and `sar_cose` were written by the author with AI assistance in one session. `independent/` was written blind from the paper by a separate instance of the same AI assistant. It catches misreadings shared by `sar_cose` and its tests, and it caught several. It cannot catch misreadings the paper induces in every reader, or tendencies shared by the model family. An implementation by an unrelated party is still the strongest check.
- **No SCITT Transparency Service.** Policy evaluation runs inside the gate, and no Receipts are issued or verified. Receipt-gated execution, R6 and T6 remain [Specified].
- **Checkpoints.** Signed checkpoints are produced, but where they are retained is up to the deployment. Tamper evidence holds relative to a retained checkpoint.
- **Replay** is covered for gates sharing one database (threads and processes tested). Gates on different machines need a shared consumed-key service.
- **The blind implementation keeps no checkpoint.** It fails gap test C10b (log truncation), a known limitation recorded in its `DECISIONS.md` (D18).
- **Interop:** pycose 1.1.0 lacks algorithm `-19`, so the pycose checks use `-8`, which the gate rejects. pycose is also incompatible with cbor2 6, so `requirements.txt` pins `cbor2<6`.
- **Performance:** indicative single-thread figures on an Apple M5 Pro, as medians over three runs:
  - signing: 76–109 µs;
  - offline verification: 0.30–0.42 ms;
  - authorization: 0.41–0.57 ms in memory, 1.1–1.3 ms file-backed.
- **Keys:** keys are generated in memory, with no HSM, rotation or revocation. The overseer's review interface is not addressed.
- **Not a security audit.** Tests and mutants show that the specified guards exist and are exercised. They do not show the absence of other bugs.

## License

Apache License 2.0. See `LICENSE`.

## Citing

Archived on Zenodo: [doi:10.5281/zenodo.23270796](https://doi.org/10.5281/zenodo.23270796) (v1.1.0). For all versions, use [doi:10.5281/zenodo.23270795](https://doi.org/10.5281/zenodo.23270795).

> Mikulić, A. (2026). *sar-cose: minimal reference implementation of the Sovereign Acceptance Runtime (SAR)*. Zenodo. https://doi.org/10.5281/zenodo.23270795

Please also cite the SARWP working paper.
