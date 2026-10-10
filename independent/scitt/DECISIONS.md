# Interpretation decisions: independent SCITT implementation (`sar_indep_scitt.py`)

This file lists every point where profile Sections 15–18 (and the core sections they rely on) were silent or ambiguous, the choice made, and the profile section involved. It also lists what looked like errors or gaps in the profile. The profile was not changed. Sources used: `spec/sar-profile.md`, `spec/sar-profile.cddl`, `spec/README.md`, `spec/ISSUES.md`, `spec/test-vectors/*`, `../sar_indep.py` and `../DECISIONS.md`. RFC 9162 §2.1 was applied from its published algorithms.

Tie-break rule: when two readings were possible, the stricter one was chosen, unless it contradicted a test vector. Where a vector settled a question, that is noted.

## Choices

**SD1. τ is not configurable; it is taken from the core (§10, SAR-REQ-050, SAR-REQ-134, SAR-REQ-135).** `TAU = sar_indep.MAX_FUTURE_SKEW = 30`. §10 says τ SHOULD be configurable and MUST be the same at the gate and in offline verification. The core hard-codes it. Making it configurable here alone would break that equality, so this module uses the core's value for the TS (t_reg rule), for SAR-REQ-134 and SAR-REQ-135, and (through the core) for SAR-REQ-050. §18.1 reuses τ for TS–gate skew, and so does this module.

**SD2. Deny-reason classes (§13.1, SAR-REQ-095).** Every DENY and refusal reason has the form `<class>: <detail>`. The core (`sar_indep`) gives free-text reasons. This module maps them by **message prefix**, not substring, because later parts of a core message can contain signer identifiers, and those must not affect the class. Any evaluation failure the table does not recognise is classed `invalid_statement`, and internal errors in the decision store are classed `store_failure`. §13.1 has no class for a malformed **registration request** (wrong `kind`, extra member, not deterministic CBOR, `proposal` not a byte string). These are reported as `invalid_statement`. A request with no `proposal` member or an empty `ratifications` array is reported as `missing_evidence` (SAR-REQ-063).

**SD3. Evaluation order at the Receipt-gated gate (§18).** The order is: (1) all core checks of Sections 5–13 except replay consumption, at the gate's own instant `t` (SAR-REQ-137, 138), including the payload digest; (2) the Receipt checks SAR-REQ-130–135; (3) one atomic step that consumes the replay keys and records the ALLOW (the core's `Store.consume_and_log_allow`). §13.1 makes evaluation order non-normative, and no vector has two faults. The consequences are: a request with no Receipt and a bad statement is reported as `invalid_statement`, not `receipt_invalid`; and a valid Receipt presented twice is reported as `replay` (sc-018), because replay is checked last. Exactly one decision record is written per call, whether ALLOW or DENY.

**SD4. Evaluation order at the TS (§15.2).** The order is: TS clock sanity → policy validity → request shape → request `policy_id` → statement evaluation (core) → registration conflicts (SAR-REQ-122, 123) → append. Conflicts are checked only after the statements verify, so that the (`policy_id`, `proposal_id`) key comes from a verified proposal, and an invalid request is never reported as a conflict. In reg-007 and reg-008, the conflicting request is otherwise valid, so this ordering gives the expected class.

**SD5. Which rules apply to a `rejection` request (SAR-REQ-124).** The text says each statement is "checked as in SAR-REQ-120" and that "quorum and the temporal rule at `t_reg` do not apply".
- **Applied:** statement validity, policy validity, signer authorization, binding (digest, id, `policy_id`), duplicate overseers (SAR-REQ-060), verdict values, and the review window S3 (SAR-REQ-051, which is "independent of `t`").
- **Not applied:** quorum (SAR-REQ-061), S2 at `t_reg` (SAR-REQ-050), and the non-empty common interval (SAR-REQ-053). The profile does not say whether SAR-REQ-053 applies to a rejection. It was left out because it is a temporal-window rule and a rejection "is recorded whenever it is presented".
- **Mixed sets:** a set may also contain `APPROVED` ratifications, as long as all of them are valid.
- **No `REJECTED` ratification:** such a request is refused as `invalid_statement`. The profile gives no class for this case; vector reg-010 expects `invalid_statement`.
- **How it is implemented:** the core is run without an instant. Reaching its "rejected" outcome means every statement was valid and at least one was `REJECTED`. Reaching its quorum or common-interval checks, or succeeding, means no `REJECTED` ratification was present.

**SD6. Several rejections, and a rejection after an authorization (SAR-REQ-122–124).** SAR-REQ-122 limits only `authorization` entries. Any number of `rejection` entries per pair is accepted. A rejection registered after an authorization is recorded, but it does not invalidate the earlier Receipt (ISS-105, limitation).

**SD7. A TS holds one policy (SAR-REQ-120, deviation 4).** The interface gives the TS one policy. A request whose `policy_id` differs from that policy's id is refused as `binding_mismatch` (vector reg-012). The profile's wording "the policy identified by `policy_id`" would also allow a TS with several policies. The TS policy is re-validated on every request (the TS analogue of SAR-REQ-043), and an invalid policy refuses everything with `policy_invalid` (reg-011).

**SD8. Inputs at the gate.** The gate receives the runtime payload as a CBOR data item, as in the core gate. It does not offer the octet-string interface of SAR-REQ-071 (ISS-004 allows this). Statements may be given as `sar_indep` statement dicts (the fixed interface) or as COSE_Sign1 octets. Octets are parsed strictly, and a parse failure is `invalid_statement`.

**SD9. Signed checkpoints (SAR-REQ-128, SHOULD).** The CDDL gives only the payload, `["sar-ts-checkpoint", log_id, tree_size, root]`. The envelope chosen here is a COSE_Sign1 (tag 18) with:
- protected header exactly `{1: -19, 3: "application/sar-ts-checkpoint+cbor", 4: UTF-8(log_id)}`;
- an empty unprotected header;
- the payload embedded as deterministic CBOR.

The content type is an invention of this implementation. It is unregistered and exists only to keep checkpoints from being confused with statements or Receipts. `TransparencyService.checkpoint()` issues checkpoints and `verify_checkpoint()` checks them; consistency proofs come from `TransparencyService.consistency_proof()`.

**SD10. Edge cases in the RFC 9162 Merkle proofs.**
- `verify_consistency` returns `False` for `m == 0` and for `m > n`, because RFC 9162 defines consistency only for `0 < m <= n`.
- For `m == n`, the proof must be empty and the two roots equal.
- `inclusion_proof` and `consistency_proof` raise `ValueError` outside their domains.
- `verify_inclusion` returns `False` when `leaf_index >= tree_size` (SAR-REQ-127), when a path element is not 32 bytes long, or when the path has too few or too many elements. That last case is the `sn == 0` condition of RFC 9162 §2.1.3.2.

**SD11. Clock values.**
- The gate's evaluation instant must be an `int` in `[0, 2^64)` (ISS-005 allows rejecting non-integers). Anything else is denied as `time_invalid`; `bool` is rejected.
- The TS clock value `now` must be an unsigned integer, because it becomes `registered_at`, a CDDL `time`. Otherwise the request is refused as `time_invalid`.
- `max_receipt_age` must be a non-negative `int`. Otherwise every Receipt is `receipt_invalid`.

**SD12. Strict Receipt parsing (SAR-REQ-130).** The profile requires the inclusion proof to be deterministic CBOR and the headers to be "exactly" as given. This implementation also requires deterministic CBOR for the whole Receipt and for its protected header. It also requires:
- the `iss` value to be an identifier (1–256 code points, as in the CDDL `identifier`);
- `iat`, `tree_size` and `leaf_index` to be unsigned integers;
- every path element to be exactly 32 bytes (CDDL `.size 32`);
- all header labels to be integers, never `bool`, and `vdp` to be exactly `{-1: [one bstr]}`.

A `kid` that differs from `UTF-8(iss)` is malformed (sc-027).

**SD13. Format of trusted-log keys (SAR-REQ-131).** The profile does not give a key format. It is taken to be the same as policy keys: 64 lowercase hexadecimal characters of a valid Ed25519 point, which is also what `trusted_logs` in the vectors uses. A malformed configured key gives `receipt_invalid`, never an exception.

**SD14. Receipt content at registration (SAR-REQ-130, deviation 4).** Registration is synchronous. The Receipt is issued for the tree immediately after the append (`tree_size` = new log size, `leaf_index` = position of the entry) and is signed over the root at that size. The receipt and the new state are built completely before anything is mutated, so a failure appends nothing. Registrations are serialized by a lock, which gives SAR-REQ-122 under concurrency.

**SD15. TS state is in memory.** The registered pairs (authorization and veto) are kept in memory next to `entries`. They could be rebuilt from `entries`, since each entry carries `kind`, `policy_id` and `proposal_id`. Persistence is out of scope: the profile models an in-process TS (deviation 4).

**SD16. Offline TAR verification (SAR-REQ-139).** `verify_tar_offline` performs SAR-REQ-100 (the core's offline check without `at`) and SAR-REQ-130–134. It uses no clock and no store and does not check freshness (SAR-REQ-135, ISS-110). It needs the trusted-log set as configuration (SAR-REQ-131) and reconstructs kind `authorization` under the given policy's `policy_id`. If it succeeds, `verify_record_offline(..., at=registered_at)` also succeeds. That follows from SAR-REQ-134 because SAR-REQ-101 uses the same window, and a test checks it.

**SD17. The ALLOW record names the Receipt.** The ALLOW record written to the core's hash-chained decision log also includes `log_id`, `registered_at`, `tree_size` and `leaf_index` of the Receipt. The log format is local (SAR-REQ-092).

## Suspected errors, gaps and inconsistencies in the profile and its documentation

1. **SAR-REQ-124 does not name the class** for a `rejection` request that contains no `REJECTED` ratification. Nor does the §13.1 table list this as a subclass. Vector reg-010 uses `invalid_statement` (SD5).
2. **SAR-REQ-124 does not say** whether SAR-REQ-051 (review window) and SAR-REQ-053 (non-empty common interval) apply to rejections. "Temporal rule at `t_reg`" clearly means SAR-REQ-050 only (SD5).
3. **§13.1 has no class for a malformed registration request**, as distinct from a malformed statement (SD2).
4. **SAR-REQ-128 checkpoints are not interoperable.** The CDDL gives `sar-checkpoint-payload`, but no envelope (signature structure, headers, content type) is specified (SD9).
5. **SAR-REQ-131 does not specify the encoding of the trusted-log public key** (SD13).
6. **SAR-REQ-130 does not say whether the Receipt as a whole must be deterministic CBOR.** Only the proof is said to be deterministic, and "exactly" is used for the header shapes. If two implementations differ here, one may accept a non-deterministically encoded but otherwise valid Receipt that the other rejects (SD12).
7. **Mismatches between `spec/README.md` and the vectors:**
   - README says `scitt` vectors carry `max_receipt_age` (300 s) in their inputs, but none of the `sc-*` vectors has that member. The runner defaults to 300, which §18 gives as the vector value.
   - `expected.steps[i]` in the `sc-*` vectors carries a `deny_subclass` member that README does not document. It is `null` everywhere.
8. **§18.1 (normative document) refers to `test_sar_scitt.py` (class `TrustedTime`),** a file of the other implementation. Readers of the profile alone cannot follow that reference, and implementers working blind are told not to open it.
9. **RFC 9162 consistency for `m = 0` is undefined.** The profile does not say what a verifier should do with it (SD10). This is harmless, because the vectors start at `m = 1`.
10. **A Receipt does not authenticate `tree_size`** (deviation 5, ISS-108): the leaf index is effectively bound, but the size is not. The profile acknowledges this. A verifier that wants the size must use a signed checkpoint, and checkpoints are under-specified (item 4).
11. **The vector set changed during this work.** `sc-007b` and `sc-007c` appeared in `spec/test-vectors/` after the first listing. Both pass. This is noted because the vector count reported below may differ from the count in an earlier `index.json`.
