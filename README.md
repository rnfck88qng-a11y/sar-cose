# sar-cose: minimal SAR reference implementation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23270795.svg)](https://doi.org/10.5281/zenodo.23270795)

This is a small working implementation of the Sovereign Acceptance Runtime (SAR) authorization path described in the working paper *Sovereign Acceptance Runtime: Verifiable Human Ratification and Evidentiary Audit Trails for Autonomous AI Agents under the EU AI Act* (v1.2, October 2026; §4 and §6). It exists so that the paper's implementation claims rest on code and tests anyone can re-run.

It comes with a second implementation (`independent/`), written by a separate instance of the same AI assistant from the paper's §3–4 (v1.1) plus a fixed wire-format specification (`independent/BRIEF.md`), without access to `sar_cose`, and amended afterwards. The two are checked against each other. The blind version is reconstructed in `independent/original_blind/`.

> **Status:** research prototype. It is not production software and has not had an independent security review. See *Limits* below.

## What it does

- **Proposal and Ratification Statements** are tagged `COSE_Sign1` objects (RFC 9052).
- **Payloads** are deterministic CBOR (RFC 8949 §4.2.1, checked against the Appendix A vectors).
- **Signatures** are Ed25519 with the fully specified algorithm identifier `-19` (RFC 9864).
- **The Execution Gate** follows the decision rules in [`SEMANTICS.md`](SEMANTICS.md) (S1–S13). It:
  - verifies both statement types;
  - enforces separation of roles in the policy, which it re-reads on every request (revocation takes effect immediately);
  - denies on any invalid, expired, duplicate or rejecting ratification;
  - compares the full runtime payload digest with the ratified one;
  - applies one time rule (S2) to its clock, so that it allows at an instant exactly when offline verification at that instant succeeds;
  - consumes the proposal id, nonce and transaction id atomically with recording the decision, before returning ALLOW (consume-then-execute: at most once).
- **`Gate.authorize_bytes`** takes the payload as deterministic CBOR bytes and returns exactly those bytes on ALLOW, so the executor can send what was checked.
- **The store** is a SQLite hash chain. Its head is signed as a checkpoint after each commit, and the signing key can be kept across restarts. A checkpoint kept outside the database detects later truncation or rewriting. Writers take the database write lock before reading the chain tip (`BEGIN IMMEDIATE`), so several gates can share one database file. With an optional **anchor** (`FileAnchor`, or a retained checkpoint), every ALLOW first checks that the database has not been rolled back, truncated or had consumed keys deleted.
- **Offline verification** needs only the artifacts and the policy's trust anchors. It uses no clock; an optional evaluation instant is checked with the gate's rule.

**Trust assumptions.** The gate, its store, its clock (the caller supplies `now`) and the anchor must be outside the agent's control, and protected tools must be reachable only through the gate. None of this is enforced by the code; see paper §3.8.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHON=.venv/bin/python ./run_tests.sh              # 137 tests on sar_cose + second implementation (~30 s)
SAR_DEEP=1 PYTHON=.venv/bin/python ./run_tests.sh   # 10x scenarios, 1,000 Hypothesis examples
SAR_SEEDS=101,202,303,404,505 PYTHON=.venv/bin/python ./run_tests.sh  # add seeds (the deep run in RESULTS.md uses these)
PYTHON=.venv/bin/python ./run_mutants.sh            # 37 hand-written mutants, each must be killed
.venv/bin/python tools/audit_mutants.py --jobs 8    # 20 semantic mutants from an external audit
.venv/bin/python tools/mutation_sweep.py --jobs 12  # automated mutation sweep
PYTHON=.venv/bin/python tools/reproduce_blind_diff.sh  # sar_cose@e2e39dd vs reconstructed blind version
PYTHON=.venv/bin/python ./run_stub_against_gaps.sh  # gap tests vs the harness stub (failures expected)
.venv/bin/python bench.py 2000                      # indicative micro-benchmark
```

`RESULTS.md` holds the raw output of the last full run. `make_results.sh` regenerates it.

## Layout

| Path | Contents |
|---|---|
| `sar_cose.py` | The reference implementation |
| `SEMANTICS.md` | Normative decision rules S1–S13, and why each was chosen |
| `independent/` | Second implementation, with its own 86 tests, `DECISIONS.md` and the verbatim brief it was given (`BRIEF.md`); `original_blind/` reconstructs the blind version |
| `harness/` | Original 12-test conformance harness and illustrative stub (unmodified) |
| `test_sar_*.py` | Test suites (see below) |
| `tools/mutation_sweep.py`, `tools/EQUIVALENT_MUTANTS.md` | Automated mutation sweep, and the equivalence argument for every survivor |
| `tools/audit_mutants.py` | The 20 semantic mutants of the external audit, ported to the current code |
| `tools/cross_diff.py`, `tools/reproduce_blind_diff.sh` | Report of disagreements between the two implementations; reproduction of the pre-resolution comparison |
| `CHANGES_v1.2_round2.md` | What changed in the second fix round of v1.2, and why |
| `run_tests.sh`, `run_mutants.sh`, `run_stub_against_gaps.sh`, `make_results.sh`, `bench.py` | Runners |

## Test suites (137 tests on sar_cose)

| File | Tests | Purpose |
|---|---|---|
| `harness/test_sar_conformance.py` | 12 | Original scenario tests, written before the implementation, used unmodified |
| `test_sar_gaps.py` | 11 | Defects the original tests missed (C07c–C13); the harness stub fails 9 of 11 |
| `test_sar_cose_specific.py` | 16 | RFC 8949 vectors, COSE structure, algorithm/kid/content-type confusion, non-deterministic CBOR, pycose interop in both directions |
| `test_sar_properties.py` | 19 | Differential vs a reference model, gate/offline equivalence at every interval bound, bit flips, payload properties, time boundaries, concurrency (threads and processes), persistence |
| `test_sar_hardening.py` | 75 | Rules S1–S13, coverage gaps, external checkpoints, tests for mutation-sweep and audit survivors, revocation, rollback with and without anchor, crash injection, exact-bytes interface |
| `test_sar_cross.py` | 4 | sar_cose vs the second implementation: byte-identical artifacts, identical decisions, gate/offline equivalence in both |

## Results (see `RESULTS.md`)

| Check | Default run | Deep run (`SAR_DEEP=1`, seeds 101, 202, 303, 404, 505 added) |
|---|---|---|
| Gate vs model, randomized | 3,000 scenarios, 0 disagreements | 180,000, 0 disagreements |
| Gate vs model, single fault | 2,000; all 557 fault-free allowed, all 16 fault types always denied | 120,000; all 32,483 fault-free allowed, all faults denied |
| Gate allows at t ⇔ offline verification at t (S13) | 12,653 instants of 1,000 scenarios; both implementations: 7,569 instants of 600 scenarios | 747,658 instants of 60,000 scenarios; both implementations: 448,137 instants each |
| sar_cose vs second implementation | 6,000 decision pairs, 0 disagreements | 360,000, 0 disagreements |
| Replay (where the first presentation was allowed) | 701 cases, second always denied | 41,891 cases, second always denied |
| Concurrency | 16 threads and 8 processes on one database, 5 rounds each: exactly one ALLOW per round | thread test 50/50, process test 10/10 runs; `deferred_tx` mutant killed 10/10 |
| Crash injection at every DB statement | at most one ALLOW overall; ALLOW record iff keys consumed | |
| Rollback of the database file | without anchor: replay possible (demonstrated); with anchor: every ALLOW refused | |
| Hand-written mutants | 37/37 killed | |
| External audit mutants (`tools/audit_mutants.py`) | 20/20 killed | |
| Automated mutation sweep | 476/491 killed (96.9%); the 15 survivors are argued decision-equivalent in `tools/EQUIVALENT_MUTANTS.md` | |
| Pre-resolution comparison (`tools/reproduce_blind_diff.sh`) | 128 disagreements in 6,000 decisions (sar_cose@e2e39dd vs reconstructed blind version) | |

All randomized tests use fixed seeds, which makes them a reproducible test set. `SAR_SEEDS` adds seeds and `SAR_DEEP` scales.

## What testing found

1. **Ratification binding untested.** The original harness never presented an approval issued for one proposal with a different proposal. Test C13 was added.
2. **Concurrent writers forked the hash chain.** Fixed with `BEGIN IMMEDIATE`; the `deferred_tx` mutant is killed by the thread test.
3. **Found by the second implementation.** The original differential reported 118 disagreements in 6,000 decisions (raw output not preserved); the reproducible reconstruction gives 128. All trace to choices the paper left open, now resolved in `SEMANTICS.md`. They exposed:
   - expired approvals ignored instead of denied, contrary to paper §4.7;
   - **no separation of roles**: one key under two overseer ids could meet a quorum of 2, and an agent listed as an overseer could approve its own proposal;
   - the gate could allow what offline verification later rejects.
4. **Gaps found by the automated mutation sweep.** These included missing tests for chained-comparison boundaries, ratifications with the right digest but the wrong id, touching but disjoint validity intervals, ratified proposals with a bad agent signature, and two anchor paths. Tests were added.
5. **Found by an external audit** (see `CHANGES_v1.2_round2.md`): the time rules S1/S2/S13 contradicted each other (offline verification at the gate's own instant could reject an ALLOW); seven semantic mutants survived, including replay one second later and an 8-byte digest comparison; a failed COMMIT could leave the store's connection inside a transaction. All fixed and tested.

## Limits

- **Trust boundary.** SAR protects only actions routed through the gate. The gate, its store, its clock (the caller supplies `now`) and the anchor must be outside the agent's control, and protected tools must be reachable only through the gate. Nothing here demonstrates bypass resistance (paper §3.8).
- **Origin of the tests.** The reference model, the extra tests and `sar_cose` were written by the author with AI assistance in one session. `independent/` was written by a separate instance of the same AI assistant from the paper plus a fixed wire-format specification, without access to `sar_cose`, and amended afterwards. It catches misreadings shared by `sar_cose` and its tests, and it caught several. It cannot catch misreadings the paper or the shared wire-format specification induce in every reader, or tendencies shared by the model family. An implementation by an unrelated party is still the strongest check.
- **No SCITT Transparency Service.** Policy evaluation runs inside the gate, and no Receipts are issued or verified. Receipt-gated execution, R6 and T6 remain [Specified].
- **Checkpoints and rollback.** Without an anchor, anyone who can write the database file can re-enable a consumed authorization (restoring an old copy, deleting consumed keys). The optional anchor detects this only if it lives in a separate trust domain; it costs O(n) per ALLOW.
- **At most once, not exactly once.** A crash after the gate commits leaves the authorization consumed and unexecuted.
- **Replay** is covered for gates sharing one database (threads and processes tested). Gates on different machines need a shared consumed-key service. Transaction ids are compared as CBOR values (`"5"` ≠ `5`) and only at the top level of the payload.
- **The second implementation keeps no checkpoint.** It fails gap test C10b (log truncation), a known limitation recorded in its `DECISIONS.md` (D18).
- **Interop:** pycose 1.1.0 lacks algorithm `-19`, so the pycose checks use `-8`, which the gate rejects. pycose is also incompatible with cbor2 6, so `requirements.txt` pins `cbor2<6`.
- **Performance:** indicative single-thread medians on an Apple M5 Pro, five runs of `bench.py 2000` (load average about 4.7 from another application):
  - signing: 31–33 µs; offline verification: 0.11–0.12 ms;
  - authorization: 0.16 ms in memory, 0.46–0.49 ms file-backed;
  - baselines: unsigned flag in memory about 0.1 µs; unsigned flag in a file-backed SQLite table with payload comparison and consumption 0.20–0.21 ms.
- **Keys:** keys are generated in memory, with no HSM or rotation procedure; revocation is a policy change. The overseer's review interface (what the human actually saw) is not addressed.
- **Not a security audit.** Tests and mutants show that the specified guards exist and are exercised. They do not show the absence of other bugs.

## License

Apache License 2.0. See `LICENSE`.

## Citing

Version v1.2.0 (used in the SARWP v1.2 paper): [doi:10.5281/zenodo.23279965](https://doi.org/10.5281/zenodo.23279965). For all versions, use [doi:10.5281/zenodo.23270795](https://doi.org/10.5281/zenodo.23270795).

> Mikulić, A. (2026). *sar-cose: minimal reference implementation of the Sovereign Acceptance Runtime (SAR)* (v1.2.0). Zenodo. https://doi.org/10.5281/zenodo.23279965

Please also cite the SARWP working paper.
