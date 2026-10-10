# Changes in v1.2, round 2 (after two independent reviews)

Inputs: the adversarial verification of the v1.2 draft (`claude-investigation-brief/deep-verification-v1.2/`, not part of this repository) and an external reviewer's report on the v1.1.0 software record. Nothing here has been pushed, tagged or released.

## 1. One time rule (S1, S2, S11, S13)

**Problem.** The draft's S2 said a proposal is valid for `issued_at <= now < expires_at`, but S1 lets the gate accept statements dated up to 30 s in the future. The gate could therefore allow at an instant where `verify_record_offline(..., at=now)` returned False. Both implementations and the reference model shared this reading.

**Rule adopted.** Each statement has a nominal half-open interval: proposal `[issued_at, expires_at)`, ratification `[reviewed_at, valid_until)`. The common interval is `[lo, hi)` with `lo = max(starts)` and `hi = min(ends)`. An evaluation at instant `t` accepts iff `lo < hi` **and** `lo − SKEW <= t < hi` (tolerance at the start only; expiry exact). The gate applies it to `now`; `verify_record_offline(at=t)` applies it to `t`; without `at`, offline verification requires `lo < hi`. Hence for every `t`, ignoring replay and payload: gate allows at `t` ⇔ `offline(at=t)`.

**Difference from the recommended rule.** The recommendation was to require the *skewed* interval `[lo − SKEW, hi)` to be non-empty. That would make the gate allow two approvals that were never jointly valid by their own clocks (approval A valid `[NOW, NOW+5)`, approval B dated `NOW+30`), which S13 had been introduced to deny (`test_s13_no_common_validity_interval_denied_at_gate`). Requiring the nominal interval to be non-empty keeps that denial, and the equivalence above holds either way. Gate decisions are unchanged from the draft; only `verify_record_offline(at=…)` changed.

**Where.** `sar_cose.accepts_at` (used by `verify_record_offline`; the gate's per-statement checks are equivalent, see the comment in `_authorize`); `independent/sar_indep.py` (`_evaluate`, offline branch) and `independent/DECISIONS.md` ("Second amendment", D5); `model_allows` in `test_sar_properties.py` (rewritten in interval form, with a `now` parameter); `SEMANTICS.md` S1, S2, S11, S13; paper §4.17 (and §4.6, §6).

**Tests.** `test_sar_properties.DifferentialTests.test_gate_allows_at_t_iff_offline_verification_at_t` (sar_cose, model and offline verification at every interval bound of 1,000 scenarios: 12,653 instants, 1,709 allowed) and `test_sar_cross.CrossImplementation.test_gate_offline_equivalence_in_both_implementations` (both implementations, 600 scenarios, 7,569 instants each). `build_and_run` also re-verifies every ALLOW offline with `at=NOW`. Two hardening tests and one test in `test_indep.py` were adjusted to the new offline rule. New hand mutant `offline_at_unskewed` (the old offline rule) is killed.

## 2. Surviving semantic mutants

Before: of the audit's 20 mutants, 7 survived the full suite (N02 nonce case-folding, N07 8-byte digest comparison, N09 replay key including the presentation time, N12 case-insensitive policy binding, N15 non-atomic consumption (caught only intermittently by the thread test), N16 non-text transaction ids not consumed, N20 denial record without proposal id).

After: **20/20 killed** (`tools/audit_mutants.py`, the audit's mutants ported to the current code where the code moved). New tests in `test_sar_hardening.AuditSurvivors` (one per survivor) and `RollbackAndCrash.test_crash_at_every_statement_allows_at_most_once`, which injects a failure at every database statement of an authorization and kills the non-atomic variant deterministically (also verified separately: it fails in 3/3 runs on N15). The seven survivors were added as hand mutants (`nonce_casefold`, `digest_prefix_only`, `replay_key_with_time`, `policy_bind_casefold`, `split_consume_tx`, `txn_key_str_only`, `deny_record_without_pid`), plus four for new features (`offline_at_unskewed`, `payload_bytes_lenient`, `skip_anchor_check`, `skip_anchor_save`): **37/37 killed**.

Automated sweep: first run 474/491 killed; two survivors were missing tests (static anchor accepted only in the refusing case; record rewritten with its hash kept, under an anchor) and got a test. Final run **476/491 killed (96.9%)**; the 15 survivors are argued decision-equivalent in `tools/EQUIVALENT_MUTANTS.md` (13 as before, with the `policy_valid` argument corrected to "decision-equivalent", plus two textually identical mutants).

## 3. Related work (paper §2.6–2.8, references)

- **He & Yu [18]** re-read in full (arXiv:2606.11632v1 PDF). SAB compiles proposals into typed execution contracts bound to an evidence digest and policy version; on high-consequence paths the signed certificate includes human multi-signatures; a broker verifies certificate and revocation state before mutating, and infrastructure is assumed to accept mutations only from the broker. Quote used: "cryptographically binds human signatures to specific contracts and evidence snapshots". No COSE, SCITT or AI Act. The draft's "does not involve human ratification" was wrong and is removed.
- **Novelty (§2.7) narrowed.** Re-tested against SAB and against drafts re-fetched on 2026-10-10: draft-morrison-ot-command-authority-03 (normative refusal; SCITT record references human authorization by digest), draft-das-eu-ai-act-execution-enforcement-02 (HumanApproval bound to a Candidate digest; Articles 12, 14, 26; "does not by itself determine" quote against receipt-gated execution), draft-marques-asqav-compliance-receipts-09 (Articles 12, 19, 26; no Article 14). Fail-closed gating on human evidence and digest-bound human signatures are now stated as not new. Remaining claim: human ratification itself as SCITT Signed Statement; Registration Policy at the TS as pre-execution gate with Receipt-gated execution (specified, not implemented); joint mapping to Articles 12, 14, 19 and 26. New refs [24]–[26].
- **New §2.8** compares with capability-based security (Dennis & Van Horn 1966 [27]), OAuth 2.0 RAR (RFC 9396 [28]) and PSD2 dynamic linking (Delegated Regulation (EU) 2018/389 Art. 5 [29]); all three opened.
- **[17]** datatracker: -00 dated 2 April 2026, expired (expiry 2026-10-05 per API). Now "April 2026 (expired October 2026)".
- **Racioppi [19]**: "standing" removed; mandates are signed by a principal (natural or legal person or organizational role); the per-call "confirm" oversight class is mentioned (verified in the PDF).
- **[13]** -11 (2026-10-09, retitled) noted; "primarily" a scope; Micro-Receipt mentioned. **[14]** its TS Registration Policy for post-execution records mentioned. **[16]** Ed25519-signed human decisions, normative hold and Article 14 mapping mentioned (verified in -07).
- **Article 50(2)**: Regulation (EU) 2026/1744 Art. 1(39)(b) adds Art. 111(4): providers of generative systems placed on the market before 2 August 2026 must comply with Art. 50(2) by 2 December 2026 (verified on EUR-Lex). Stated in §1, the only place where Art. 50 dates appear.

## 4. Provenance of the second implementation; reproducible comparison

- `independent/original_blind/` reconstructs the blind version: `sar_indep.py` differs from the d8ff22c version only in `MAX_FUTURE_SKEW = 0` with comment `# D1: no tolerance for future-dated statements`; `test_indep.py` only in the import line and the two future-dated tests (MAX_FUTURE_SKEW replaced by 0; the exact original literals are not preserved). It passes the 12-test harness and its 86 tests, and fails gap test C10b like the current version.
- `tools/reproduce_blind_diff.sh` archives `sar_cose.py` and `test_sar_properties.py` at e2e39dd into a temp dir and runs `tools/cross_diff.py` (now accepting `SAR_REF_DIR`/`SAR_INDEP_DIR`) against `original_blind`, N = 1,500 per generator. **Result: 128 disagreements in 6,000 decisions** (deterministic over repeated runs): 80 duplicate ratifications (S5), 26 clock tolerance (S1), 10 ratification after proposal expiry (S3), 12 common interval (S11/S13). **This differs from the 118 reported in the draft**; the original run's raw output and exact inputs were not preserved. The audit's own reconstruction (different method: decision triples incl. second presentation, separate seeds 7 and 8) gave 138. The paper now cites 128 as the reproducible figure and 118 as the unpreserved original.
- Wording in abstract, C3, §4.17, §6.2, §6.7, §6.9, §8.4, §9, README, SEMANTICS.md and `independent/README.md`: "written from the paper's Sections 3–4 (v1.1) plus a fixed wire-format specification, by a separate instance of the same AI assistant, without access to the reference implementation; amended afterwards". The 24 decisions were counted (D1–D24). The process claims remain the author's records and are stated as such (§6.7).

## 5. Release wording

The paper no longer says the code is published or released: Data and Code Availability, the §6.6 footnote and [23] say "to be released as v1.2.0 (all versions: doi:10.5281/zenodo.23270795)"; [23] cites v1.1.0 (doi:10.5281/zenodo.23270796) as the archived version. The paper's own DOI placeholder is kept on purpose. `.zenodo.json` now names the paper (v1.1: doi:10.5281/zenodo.23270905) in its description and as a related identifier (`isSupplementTo`). `CITATION.cff` still says `version: 1.2.0`, `date-released: 2026-10-10`; adjust the date when releasing.

## 6. Benchmarks

`bench.py` gained two baselines (unsigned approval flag in memory; the same flag in a file-backed SQLite table with exact payload comparison and consumption in one transaction) and an `authorize_bytes` row. Five runs of `bench.py 2000`, alternating with five runs of the v1.1 code (commit e2e39dd, its own `bench.py`), on the Apple M5 Pro (15 cores). The machine was not idle: 1-minute load average 4.7–4.8 throughout, mostly Obsidian indexing the vault at about 200% CPU; waiting ~20 min did not bring it below 4.5. Medians (range over 5 runs):

| Operation | current | e2e39dd |
|---|---|---|
| make_proposal / ratify (sign) | 30.6–33.2 µs | 31.3–32.9 µs |
| verify_record_offline | 0.112–0.116 ms | 0.103–0.108 ms |
| Gate.authorize, in-memory | 0.155–0.163 ms | 0.142–0.146 ms |
| Gate.authorize_bytes, in-memory | 0.159–0.165 ms | n/a |
| Gate.authorize, file-backed | 0.463–0.487 ms | 0.420–0.430 ms |
| baseline: unsigned flag, in memory | 0.1 µs | n/a |
| baseline: unsigned flag, file-backed | 0.203–0.208 ms | n/a |

The draft's ranges (76–109 µs, 0.30–0.42 ms, 0.41–0.57 ms, 1.1–1.3 ms) were measured under heavy CPU contention and are withdrawn. The draft's claim that the gate is "two to three times slower than an earlier version" is **refuted** by this same-conditions comparison: the current gate is about 10% slower than e2e39dd. Paper §6.5 and README now give the new ranges, the baselines and the 10% figure.

## 7. Tags

Rule added to §1.3: a tag attaches to a mechanism; a requirement or regulatory row carries the weakest tag of its mechanisms. §3.5: R1 [Proven], R2 [Partially Enforced] (chain [Proven] relative to a retained checkpoint; transparency registration [Specified]), R3 [Partially Enforced], R4 [Partially Enforced], R5 [Proven], R6 [Specified]. §4.7 explains [Partially Enforced] vs I5 [Proven]. §4.9, §4.10 and §6.6 state their scope (exact-bytes obligation; anchored or intact store). New §6.6 rows for at-most-once, rollback, revocation and bypass resistance ([Specified]). §8.4/§8.5 stale "planned"/"would" wording removed.

## 8. Trusted components and enforcement boundary

New paper §3.8: trusted gate/store/clock/policy source outside the agent's control; enforcement boundary and bypass (architectural requirement, not demonstrated); exact bytes; crash behaviour; rollback; revocation; key compromise; definition of "cryptographically verifiable ratification" versus human-intent assurance (WYSIWYS out of scope; R1 mitigates T3 only as to key use). §3.2 trust model, §4.1, §4.6 Phase 5 and §4.15 refer to it; §7.6 (MCP middleware holds tool credentials).

Code: `Gate.authorize_bytes(payload_bytes, proposal, ratifications, now=None) -> (allowed, reason, payload_bytes|None)`: accepts only deterministic CBOR, digests a private immutable copy and returns it on ALLOW. Tests in `test_sar_hardening.ExactBytes` (exact immutable bytes; buffer mutated after the call; unsorted map, trailing byte, non-bytes, text and changed payload denied; unloggable denial).

## 9. Rollback, revocation, crash

- **Revocation** (`test_sar_hardening.Revocation`): overseer removed, agent removed, overseer key replaced after ratification → denied; offline verification under the old policy still succeeds.
- **Rollback.** Without an anchor, restoring an older database file or deleting consumed keys re-enables a consumed authorization — demonstrated and recorded as a limitation (`test_rollback_without_anchor_reenables_a_consumed_authorization`). Mitigation: `Store(path, signing_key=…, anchor=FileAnchor(path) | checkpoint dict)`. Before each ALLOW (inside the write transaction) it verifies the checkpoint signature, the whole chain, that the chain extends the anchored checkpoint, and that no chained ALLOW record lists the same replay keys (ALLOW records now list their keys); it advances the anchor before COMMIT (fail closed: a failed commit leaves the anchor ahead and every later ALLOW is refused). A non-empty log is never anchored implicitly. Tests: restored copies before the first and second ALLOW, truncation, deleted consumed keys, static checkpoint (consistent and inconsistent), rewritten record, missing anchor. Cost: O(n) per ALLOW. The anchor must live in a separate trust domain.
- **Crash.** `_write` now rolls back if COMMIT itself fails (previously the connection stayed inside a transaction). Fault injection at every statement, with and without anchor: at most one ALLOW overall, an ALLOW record iff keys consumed, and a failure after commit leaves the authorization consumed and unexecuted (DENY returned; retries get `replay`). Executor crash after ALLOW: authorization stays consumed.

## 10. EU AI Act table

§5.2 has a fifth column "Limitation: what SAR does not guarantee" per article (Art. 14(4)(a)/(b) and 26(2) wording checked on EUR-Lex), stated as technical observation, not legal assessment.

## 11. Other REFUTED / CORRECTED rows of claims.csv

| Row | Action |
|---|---|
| C002 DOI placeholder | Kept deliberately (to be filled on deposit). |
| C014 adequacy by mutation analysis | Audit mutants added and killed (§2 above). |
| C019 tags consistent | Rule in §1.3 and re-tagging (§7 above). |
| C066 / C083 runtime trust, security claim | §3.2, §3.8, §4.15. |
| C067 R1 mitigates T3 | Qualified (as to key use). |
| C072 / C081 policy fields, step 7 | §4.5.3 and §4.12 status corrected. |
| C077 / C078 / C163 / C168 payload, replay tags | Killing tests added; scope stated. |
| C085 / C096 / C098 / C112 S2, S13, strict reading, docstring | §1 above; S1 named as the exception to "strict"; Gate docstring S1–S13. |
| C092 / C093 S9, S10 | Recomputation function and transaction-id semantics (top-level, CBOR-typed) stated in §4.17 and SEMANTICS.md; type sensitivity pinned by a test. Canonicalizing transaction ids was not adopted. |
| C097 / C115 / C008 provenance | §4 above. |
| C128 first sweep 61/325 | Marked "(raw output not preserved)". |
| C130 / C182 equivalence | "decision-equivalent (reason may differ)"; `policy_valid` argument corrected. |
| C131 / C132 118 | Reproduced figure 128 used; categories listed. |
| C146 fresh seeds | Seeds 101–505 stated; "fresh" removed. |
| C158 / C159 benchmarks | Re-measured (§6 above). |
| C171 / C179 / C180 / C207 release | §5 above. |
| C173 I1/I4 caveats | §6.8 rows qualified. |
| C177 / C178 stale wording | §8.4, §8.5 rewritten. |
| C047 / C050 / C052 / C053 / C054 / C056 / C058 / C059 / C197 / C201 | §3 above. |
| C009 Art. 50 | §3 above. |
| Reviewer objection 10 (privacy, log growth) | One bullet in §8.4. |
| Not addressed | C004, C011, C025, C031 (UNVERIFIED general statements about standards and HITL practice) are left as framed; no survey was added. RFC 9338 (updates RFC 9052) is not mentioned: it concerns countersignatures, which SAR does not use. The CEN/CENELEC status was not checked. |
