# Changes in v1.3

Inputs: two external reviews of SARWP v1.2 and the author's v1.3 brief. Released as tag `v1.3.0`; the Zenodo version DOI is added once the deposit exists. Figures are deliberately not repeated in this file: they are in `results/paper_claims.json`, generated from the archived runs in `results/runs/`, and rendered into `README.md`, `RESULTS.md` and the paper.

## Step 1 — terminology, mutation classification, archived runs

- **Tags.** `[Proven]` → `[Empirically Verified]` ("demonstrated in the reference implementation by automated tests whose adequacy is checked by mutation analysis; not a formal proof"); `[Partially Enforced]` replaced per occurrence by `[Implemented]` or by separate tags for implemented and unimplemented parts. Paper §1.3, §3.5, §4, §5.2, §6.6, §6.8; README; `tools/EQUIVALENT_MUTANTS.md`.
- **Qualifications.** O4, R5 and the §4.15 claim hold "within the enforcement boundary of §3.8"; "human ratification" defined as *human-attributed* (abstract, §1); R2 renamed "Tamper Evidence Relative to an Externally Retained Checkpoint"; new paper §8.5 privacy architecture; §5 states that it has not had a legal review.
- **Mutation classification.** `tools/mutation_sweep.py --module … --json …` classifies every survivor as `equivalent` (exact match in `tools/equivalent_mutants.json`, pointing to an argument id `EQ-nn` in `tools/EQUIVALENT_MUTANTS.md`) or `live`. Finding recorded (paper §6.4): the mechanical sweep did not generate the semantic security mutants that the hand-written and audit mutants caught.
- **Archived runs.** `tools/archive_run.py` writes `results/runs/<name>.json` (command, seeds, environment, load, git SHA and dirty flag, module hashes, unittest counts, pass/fail) and the full log. `make_results.sh` and `tools/run_slow.sh` archive every run.
- **Runner fix.** `run_mutants.sh` decided "killed" from the last output line; because test modules print statistics to stdout, a surviving mutant could have been reported as killed. It now uses the exit code. (No misclassification had occurred in v1.2: every mutant listed there had at least one failing test.)

## Step 2 — normative profile

`spec/sar-profile.md` (BCP 14), `spec/sar-profile.cddl`, `spec/cddl_check.py` (subset CDDL parser and validator; no CDDL tool was available), `spec/gen_vectors.py` (vectors from RFC 8032 test keys, built without importing either implementation; `--check` verifies byte-identical regeneration), `spec/test-vectors/`, `spec/run_vectors.py` (adapters for four implementations), `spec/req_map.json`, `spec/check_manifest.py`, `spec/conformance_manifest.csv/.json`, `spec/ISSUES.md`. `SEMANTICS.md` now points to the profile.

## Step 3 — SCITT Transparency Service and Receipt-gated execution

- Primary sources opened: RFC 9943, RFC 9942 (COSE Receipts, formerly draft-ietf-cose-merkle-tree-proofs), draft-ietf-scitt-scrapi-11, RFC 9162, RFC 9597, RFC 8392, RFC 8032. Profile §15–18 quote what is relied on and list five deviations.
- Profile first (§15–18, CDDL, vectors, manifest rows, ISS-101–110), then `sar_scitt.py`: `TransparencyService` (policy evaluation at the registration instant, registration uniqueness, registered veto, rejection entries, RFC 9162 Merkle log with cached complete subtrees, Receipts, signed checkpoints, consistency proofs), `ReceiptGate` (wraps `sar_cose.Gate`), `verify_tar_offline`, `make_tar`/`parse_tar`. Hand mutants in `sar_scitt.MUTANTS`, one per guard; all are killed.
- **Trusted time** treated as a hypothesis (profile §18.1, paper §4.18): the registration time bounds when the policy was satisfied but is not trusted time for execution; rules SAR-REQ-134, 135, 138.
- **Tests** `test_sar_scitt.py`: end to end to execution of exact bytes; adversarial Receipts; trusted time in both clock directions; registration (policy failure, rejection, veto, duplicates, concurrency); Merkle roots, inclusion and consistency for all sizes; a registration/receipt-gate differential against the reference model; tests added for live survivors of the first sweep of `sar_scitt.py`; a test that the implementation reproduces the byte-exact normative vectors.
- **Second SCITT implementation** `independent/scitt/` written by a sub-agent from the profile only (brief recorded verbatim in `independent/scitt/BRIEF.md`; compliance with the read restrictions rests on the agent's report). It passes all SCITT, registration and Merkle vectors and reported ten profile gaps, decided as ISS-111–120 (profile text clarified; no code change needed in either implementation).
- **Notable vector:** changing the unsigned tree size in an RFC 9942 inclusion proof from 7 to 8 (leaf 4) still verifies against the signed root (ISS-108); harmless for the gate, recorded.

## Paper v1.3 (outside this repository)

Template `SARWP_working_paper_v1.3.template.md` with `{{placeholders}}`, rendered by `build/render_claims.py` (which calls `tools/render_docs.py --paper`) and checked by `tools/check_claims.py`. New §4.18; §6 rewritten; §2.7, C2, C3, §3.5, §4.5.3–4.13, §5.2, §7.4, §8, conclusion, data availability, references [30]–[35] and revision notes updated.

## Open items

- An implementation by a party unrelated to the author, from `spec/`.
- Legal review of paper §5.
- Policy extensions (`policy_version`, action types, targets, max validity, replay policy): specified, not implemented.
- Persistent Transparency Service, SCRAPI, independent checkpoint monitoring, federation; per-statement registration as in RFC 9943 (ISS-102).
- Interoperable checkpoint envelope (ISS-114).
- The enforcement boundary and a trusted clock remain deployment assumptions.
- Release, tag and DOI (not done; the paper keeps `DOI-V13-PLACEHOLDER`).
