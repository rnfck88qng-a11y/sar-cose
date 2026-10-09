# sar-cose: minimal SAR reference implementation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23270796.svg)](https://doi.org/10.5281/zenodo.23270796)

This is a small working implementation of the Sovereign Acceptance Runtime (SAR) authorization path described in the working paper *Sovereign Acceptance Runtime: Verifiable Human Ratification and Evidentiary Audit Trails for Autonomous AI Agents under the EU AI Act* (v1.1, October 2026; §4 and §6). It exists so that the paper's implementation claims rest on code and tests anyone can re-run.

> **Status:** research prototype. It is not production software and has not had an independent security review. See *Limits* below.

- **Proposal and Ratification Statements** are tagged `COSE_Sign1` objects (RFC 9052).
- **Payloads** are deterministic CBOR (RFC 8949 §4.2.1, implemented and checked against the Appendix A vectors).
- **Signatures** are Ed25519 using the fully-specified algorithm identifier `-19` (RFC 9864).
- **The Execution Gate** does the following before allowing an action:
  - evaluates the Registration Policy (authorized agents and overseers, distinct-overseer quorum, policy binding, validity windows, clock skew);
  - verifies both statement types, including algorithm, content type and kid;
  - checks that each ratification is bound to the exact proposal bytes;
  - compares the runtime payload digest with the ratified digest;
  - consumes the nonce atomically with recording the decision.
- **The store** is a SQLite hash chain whose head is signed as a checkpoint after each commit. Writes take the database write lock up front (`BEGIN IMMEDIATE`), so several gates can safely share one database file.
- **Offline verification** needs only the artifacts and trust anchors.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHON=.venv/bin/python ./run_tests.sh              # 55 tests (~5 s)
PYTHON=.venv/bin/python ./run_mutants.sh            # 19 mutants, each must be killed (~90 s)
PYTHON=.venv/bin/python ./run_stub_against_gaps.sh  # gap tests vs the harness stub (failures expected)
PYTHON=.venv/bin/python bench.py 2000               # indicative micro-benchmark
```

`run_tests.sh` runs the original conformance harness in `harness/` (included verbatim, with checksums in `harness/README.md`) against `sar_cose` via `SAR_IMPL=sar_cose`. Raw output from the last run is in `RESULTS.md`.

## Layout

| Path | Contents |
|---|---|
| `sar_cose.py` | The implementation: deterministic CBOR, COSE_Sign1, protocol objects, store, gate, offline verifier, mutants |
| `harness/` | Original 12-test conformance harness and illustrative stub (unmodified) |
| `test_sar_gaps.py`, `test_sar_cose_specific.py`, `test_sar_properties.py` | Additional tests (see below) |
| `run_tests.sh`, `run_mutants.sh`, `run_stub_against_gaps.sh` | Test, mutation-analysis and discrimination runners |
| `bench.py` | Indicative micro-benchmark |
| `RESULTS.md`, `make_results.sh` | Raw output of the last full run, and the script that regenerates it |

## What the suite contains

| File | Tests | Purpose |
|---|---|---|
| `harness/test_sar_conformance.py` (original, unmodified) | 12 | Paper §6.4 scenarios (01–08, 07a/b), RQ3 offline verification (09), tamper evidence (10), quorum (11) |
| `test_sar_gaps.py` | 11 | C07c, C07d, C09b, C10b, C11b, C12 (the audit gaps), plus **C13**, found while building this |
| `test_sar_cose_specific.py` | 16 | RFC 8949 vectors, COSE_Sign1 structure, algorithm/kid/content-type confusion, protected-header tampering, non-deterministic and duplicate-key CBOR, unprotected headers, cross-library verification (cbor2 + cryptography; pycose in both directions) |
| `test_sar_properties.py` | 16 | See "Extended tests" below |

The gap tests use only the harness interface. The harness's illustrative stub **fails 9 of 11** of them, which shows they detect the defects they were written for. It passes C07d and C13 because the stub already enforces those two checks.

## Extended tests (`test_sar_properties.py`)

| Test | What it does | Result |
|---|---|---|
| Differential, randomized | 3,000 scenarios from a fixed seed (quorum, timing, signatures, binding, verdicts, policy, payload), compared with a separately written reference model of the spec (`model_allows`). The seed makes this a fixed, reproducible test set, not fresh random sampling | 0 disagreements (182 allowed, 2,818 denied) |
| Differential, single fault | 2,000 valid scenarios from a fixed seed, each with zero or one of 16 injected faults | 0 disagreements. All 557 fault-free scenarios allowed; the 14 always-deny fault types denied in every case. The other two types are not always-deny: a duplicated approval is allowed exactly when the quorum is 1 (40/40) and denied at quorum 2–3 (54/54); an expired approval was denied in all 77 cases because it always left the quorum unmet |
| Differential, Hypothesis | The same comparison driven by Hypothesis (shrinks counterexamples; `derandomize=True`, so also a fixed input set) | Pass |
| Replay invariant | Present the same authorization a second time. This is only meaningful where the first presentation was allowed: 779 of the 5,000 scenarios (182 randomized + 597 single-fault) | Second presentation denied in all 779; in the rest the second denial is trivial |
| Bit flips | Every single-bit flip in every byte of a signed proposal and ratification (>3,000 variants) | All rejected; unmodified control allowed |
| CBOR properties | Random nested values: round-trip, idempotence, bytewise-sorted map keys | Pass |
| Parser fuzzing | Random bytes into `from_cose`; random junk statements into the gate | Only expected exception types; the gate never raises and never allows |
| Payload mutation | Random payloads; change, drop or add any field after approval | Denied unless the encoding is byte-identical; map insertion order irrelevant |
| Unicode | NFC vs NFD encoding of the same visible string | Treated as different actions (byte-exact binding; normalise before proposing if required) |
| Time boundaries | Exact edges of proposal expiry, ratification expiry, clock skew and review-before-proposal | Inclusive bounds as specified |
| Concurrency | 16 threads, each with its own gate and connection to one shared database file, presenting the same authorization at once (5 rounds) | Exactly one allow per round; the hash chain stays intact; stable 20/20 runs |
| Persistence | Authorize, close the store, reopen, present again | Denied as replay |

**Second finding: the concurrency test exposed a real bug.** Replay protection held under concurrency (exactly one allow), but concurrent writers could read the same chain tip and both append to it, which **forked the hash chain**. The fix is to take the write lock before reading the tip (`BEGIN IMMEDIATE`). Mutant `deferred_tx` restores the old behaviour and is killed 10 of 10 times.

## Mutation check (test-the-tests)

Each mutant disables exactly one guard, selected with `SAR_MUTANT=<name>` (see `MUTANTS` in `sar_cose.py`). **All 19 are killed**: with any single guard removed, at least one test fails.

The first mutation run found a real gap. With `skip_binding` (the gate does not check that a ratification refers to *this* proposal), **all 38 tests then in the suite still passed**. Test C13 was added in response: it presents an approval issued for one proposal with a different proposal. This gap was present in the original harness as well.

## Claim mapping (for SARWP §6.6)

| Property | Tests | Mutants killed | Supported tag *for this implementation* |
|---|---|---|---|
| Proposal authenticity | 03, cose: tamper/kid/ctype/alg | skip_sig, skip_kid_check, skip_ctype_check, skip_alg_check | [Proven] |
| Ratification authenticity | 03, 09, cose: kid/ctype | same | [Proven] |
| Ratification binding (I2) | C13 | skip_binding, offline_skip_binding | [Proven] |
| Payload binding (I4) | 05, digest test | skip_digest | [Proven] |
| Fail-closed execution (I5) | 02, 04, 07a–d, 08, C11b, C12 | skip_expiry, skip_rat_expiry, allow_rejected, dedup_overseer, skip_policy_bind, skip_future_check | [Proven] |
| Offline verification (RQ3) | 09, C09b, C12-offline, C13, cross-library tests | offline_skip_quorum, offline_skip_binding | [Proven] |
| Replay detection | 06, replay invariant in 5,000 differential scenarios, concurrency, persistence | skip_replay, deferred_tx | [Proven] for gates sharing one database |
| Tamper-evident history | 10, C10b | chain_noop, skip_head_check | [Partially Enforced]: see limits |
| SCITT registration, Receipts, inclusion proofs, consistency | — | — | **[Specified]: not implemented** |

## Limits (state these in the paper)

- **Shared origin.** The reference model used for differential testing, the extra tests and the implementation were written by the same author, with AI assistance, in one working session. Agreement shows that the gate matches the author's reading of the spec, not that the reading is right: a misreading shared by model and gate would pass undetected. Only `harness/` predates the implementation. An independently written implementation or model would close this gap.
- **No SCITT Transparency Service.** Registration Policy evaluation runs inside the gate rather than at a Transparency Service, and no Receipts are issued or verified. The paper's Receipt-gated execution step, R6 and T6 remain [Specified].
- **Truncation detection** relies on the last signed checkpoint, which this implementation holds in the `Store` object. Real protection requires publishing the checkpoint outside the store (for example by registering it with a transparency service). Until then, tamper-evident history is [Partially Enforced].
- **Replay protection** covers gates that share one SQLite database (tested with 16 concurrent gates). Gates on different machines need a shared consumed-nonce service; that case is not implemented.
- **Performance:** `bench.py` gives indicative single-thread figures only. On an Apple M5 Pro (`RESULTS.md`) they were about 40 µs to sign a statement, about 0.14 ms for offline verification, and about 0.2 ms (in-memory) or 1.3 ms (file-backed) per authorization, varying by about a factor of two with system load.
- **Cross-library interop:** pycose 1.1.0 does not implement algorithm `-19`. The pycose checks therefore use statements signed with the deprecated `-8` (EdDSA), which the gate rejects by default. pycose 1.1.0 is also incompatible with cbor2 6.x, so `requirements.txt` pins `cbor2<6`. `sar_cose` itself works with both.
- **Key management:** keys are generated in memory, with no HSM, rotation or revocation. The overseer's UI and what-you-see-is-what-you-sign rendering are not addressed.
- **Not a security audit.** Tests and mutants show that the specified guards exist and are exercised. They do not show the absence of other bugs.

## License

Apache License 2.0. See `LICENSE`.

## Citing

Archived on Zenodo: [doi:10.5281/zenodo.23270796](https://doi.org/10.5281/zenodo.23270796) (v1.1.0). To cite all versions, use [doi:10.5281/zenodo.23270795](https://doi.org/10.5281/zenodo.23270795).

> Mikulić, A. (2026). *sar-cose: minimal reference implementation of the Sovereign Acceptance Runtime (SAR)* (v1.1.0). Zenodo. https://doi.org/10.5281/zenodo.23270796

Please also cite the SARWP working paper (v1.1, October 2026).
