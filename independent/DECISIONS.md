# Interpretation decisions (independent implementation)

These are the points where SARWP v1.1 §3–4 is silent or ambiguous. Each one records the choice made in `sar_indep.py` and the paper section that drove it. The fixed wire format and interface given with the task are taken as given and are not listed, except where they conflict with the paper (D18–D20).

General rule used for every tie-break: §4.7 says that "ambiguous policy results are treated as failures", and §4.14 I5 says the gate starts in DENY. When the paper allows either a lenient or a strict reading, this implementation picks the strict one.

## Time and validity intervals

**D1. Clock skew for future-dated statements: none.** A proposal with `issued_at > now`, or a ratification with `reviewed_at > now`, is denied. `MAX_FUTURE_SKEW = 0`. Paper: §4.7 lists expiry but says nothing about statements from the future. §3.2 treats the runtime as untrusted, and §4.7 says to fail closed. A statement dated in the future cannot have been reviewed yet, so it is treated as malformed evidence. Deployments with skewed clocks would need to change the constant explicitly.

**D2. Interval bounds are half-open.** A statement is valid for `issued_at <= now < expires_at` and `reviewed_at <= now < valid_until`. At exactly `expires_at` or `valid_until` it is already expired. Paper: §4.7 "Expired proposal / Expired ratification" with no boundary given. Half-open intervals mean a ttl of N seconds gives exactly N valid seconds.

**D3. Ordering constraints between ratification and proposal.** `reviewed_at < issued_at` is denied ("ratification predates proposal"). `reviewed_at >= expires_at` is also denied: a ratification issued after the proposal expired does not count. `issued_at >= expires_at` and `reviewed_at >= valid_until` (empty intervals, including ttl <= 0) are denied. Paper: §4.6 phases 1→2 are sequential (review follows proposal). §4.14 I2 binds the ratification to the proposal, and a human cannot have reviewed a proposal that did not exist yet.

**D4. An expired ratification denies the whole request. It does not just fail to count.** The same strict-set rule applies to any ratification in the presented set that is invalid in any way: bad signature, unknown overseer, wrong binding, wrong policy_id, unknown verdict, malformed fields, future-dated, or expired. The request is denied even if the remaining valid approvals would meet quorum. Paper: §4.7 lists "Invalid overseer signature" and "Expired ratification" as unconditional denial conditions, not as "ignore this one". §4.6 phase 3: "Any validation failure terminates the registration attempt." The caller can drop stale ratifications and retry.

**D5. The offline verifier does not use the wall clock.** `verify_record_offline(p, rs, policy)` checks that the intervals are internally consistent and that at least one instant exists when the proposal and every ratification were all valid: `max(issued_at, reviewed_at*) < min(expires_at, valid_until*)`. It does not compare against current time, because evidence must stay verifiable after execution (§3.1 O3, §4.12 "after execution"). An optional extra keyword `at=<time>` also checks that the given instant is inside that common window. This is for an auditor who knows the execution time from a separate record (§4.12 step 11). Paper: §4.12 step 10 "Confirm validity intervals" does not say relative to what.

## Verdicts and quorum

**D6. Any REJECTED verdict is a veto.** If any valid ratification in the set says `REJECTED`, the gate denies, even when other overseers' APPROVED ratifications reach quorum. The offline verifier likewise returns False. Paper: §4.11 says a rejection "must not issue an authorization Receipt permitting execution" and that "the runtime was expected to remain in the deny state". §4.7 lists "Rejected verdict" without a quorum qualifier.

**D7. Unknown verdict strings cause denial.** Only the exact strings `"APPROVED"` and `"REJECTED"` are accepted. Anything else (case variants, trailing whitespace, empty, non-text) is malformed, and the request is denied (per D4). It is not just treated as "not an approval". Paper: §4.5.2 says the verdict is `"APPROVED" / "REJECTED"`, and §4.7 treats parsing errors as failures.

**D8. Duplicate ratifications from one overseer cause denial.** If the same `overseer_id` appears more than once in the set, the request is denied. This applies even when the two are byte-identical or both APPROVED. Quorum counts distinct `overseer_id`s, and D10 additionally guarantees that distinct ids have distinct keys. Paper: §4.5.3 "required reviewer quorum". Duplicates are ambiguous evidence (which one is the decision?), and §4.7 says to fail on ambiguity. Silently deduplicating them would also hide a confused or malicious submitter.

## Policy

**D9. What counts as an invalid policy (deny everything).** The policy is re-validated on every `authorize` call, so a policy mutated after the Gate was built is checked again. It is invalid if:
- it is not a map;
- its keys are not exactly `{policy_id, quorum, authorized_agents, authorized_overseers}`;
- `policy_id` is not a non-empty string;
- `quorum` is not an `int` >= 1 (`bool` is rejected);
- `authorized_agents` or `authorized_overseers` is empty or not a map;
- `quorum` is greater than the number of authorized overseers (unsatisfiable);
- any id is not a non-empty string;
- any key is not 64 lowercase hex characters decoding to a valid Ed25519 public key.

Paper: §4.7 "Invalid or unrecognized policy version"; §4.5.3.

**D10. Unknown policy fields are refused, not ignored.** Examples are `permitted_action_types`, `target_constraints`, `contextual_constraints`, and validity windows. §4.5.3 lists them as things a policy may specify. This implementation cannot enforce them. If it accepted them silently, a policy author could believe a constraint is enforced when it is not. Paper: §4.6 phase 3 lists "permitted action type" and "contextual policy constraints" as verifications. §4.7 says to fail closed.

**D11. Role and key separation.** A policy is invalid if two overseer ids share one public key, because one key-holder would then count twice toward quorum (§4.5.3 quorum, §3.1 O1). It is also invalid if any key or id appears both as an agent and as an overseer: the untrusted agent (§3.2) must not be able to ratify its own proposal (§4.5.1 "The agent signature does not authorize execution").

**D12. `policy_id` inside statements must equal the gate's policy.** This applies to the proposal and every ratification. A mismatch is denied. Paper: §4.5.3 "an auditor must be able to determine which policy governed an authorization", and §4.6 phase 3 "policy version". Evidence produced under one policy must not be redeemed under another.

**D13. There is no separate policy version field.** The interface's policy has no `policy_version`. `policy_id` is treated as the versioned identifier, so a new version must use a new `policy_id`. Paper: §4.5.3 "identified by a versioned `policy_id`".

## Statement validation

**D14. Strict statement shape.** Bodies must have exactly the specified key set. `v` must be the integer 1 (`True` is not accepted). Timestamps must be unsigned integers. `payload_digest` and `proposal_digest` must be 32-byte byte strings. The nonce must be a non-empty text or byte string of at most 256 units. Ids must be non-empty text of at most 256 characters. `sig` must be exactly 128 lowercase hex characters, because the proposal digest hashes the COSE bytes and a second hex spelling must not exist. The protected header must contain exactly `{1: -19, 3: <expected content type>, 4: kid}`, with kid equal to the UTF-8 of the signer id in the body. A proposal presented as a ratification, or the reverse, is rejected by content type. Paper: §4.5.1, §4.5.2 ("illustrative"), §4.7 "parsing errors ... treated as failures".

**D15. `proposal_id` is recomputed and must match.** It is derived from the body's content (first 32 hex characters of SHA-256 over the body without `proposal_id`), so a validly signed proposal with an arbitrary id is still denied. Paper: §4.14 I1 "one canonical Proposal Statement" and §4.10 "a unique `proposal_id`". A content-derived id makes the identifier unforgeable as well as unique.

**D16. Every statement is snapshotted before evaluation.** Each statement is re-encoded to COSE bytes and strictly re-parsed, and verification runs on that copy. The runtime payload digest is computed once. Paper: §4.9 TOCTOU, and §3.3 (the adversary can modify application memory).

## Replay and store

**D17. Replay keys consumed on ALLOW (§4.10).** All of the following are recorded atomically with the ALLOW log entry, in one SQLite `BEGIN IMMEDIATE` transaction:
- `proposal_id` within the policy;
- the SHA-256 of the proposal's COSE bytes;
- `(policy_id, nonce)`. The nonce is unique per policy domain, across all agents and proposals (§4.10 "each nonce be unique within a policy domain").
- `(policy_id, transaction_id)`, if the runtime payload is a map with a `transaction_id` field (§4.10 "each transaction identifier map to only one successful execution"; §4.6 `ReplayCheck(proposal_id, nonce, transaction_id)`).

DENY decisions consume nothing, so a request denied for missing quorum can be retried with more ratifications.

**D18. The decision log is tamper-evident, not tamper-proof.** Every decision (ALLOW and DENY) is appended as one row: `record = "ALLOW {json}"` or `"DENY {json}"`, `prev = <previous hash>`, and `hash = SHA-256(dcbor([seq, prev, record]))`. The first row's `prev` is 64 zeros, and `seq` must be contiguous starting at 1. No SQLite triggers block UPDATE or DELETE: §3.3 assumes the adversary controls storage, so detection rather than prevention is the stated property (§3.5 R2 "capable of revealing unauthorized modification").

Known limitation: truncating the tail of the log is not detectable from the chain alone. That would need an external anchor, i.e. the transparency service and signed roots of §4.13, which are out of scope here. `test_truncate_tail_is_not_detected_by_chain_alone` documents this.

**D19. The gate refuses to ALLOW over a broken history.** Before every ALLOW, the chain is verified inside the same transaction; if it fails, the gate denies. Replay keys are also written into the chained ALLOW record, and the replay check consults both the `consumed` table and the ALLOW records. Deleting rows from `consumed` alone therefore does not re-enable a replay. Paper: §4.7 "Unavailable verification dependency" and §4.15 "Log modification". The chain check makes ALLOW O(n) in log size; this implementation accepts that cost for clarity.

**D20. If a DENY cannot be logged, the call still returns DENY.** The reason string is annotated. If an ALLOW cannot be logged or consumed, the transaction rolls back and the call returns DENY. `authorize` catches every `Exception` and returns `(False, "DENY: ...")`. Paper: §4.7, §4.14 I5.

## Deviations from the paper forced by the fixed interface

**D21. No Receipt and no transparency service.** `authorize` has no receipt argument, so `VerifyReceipt` (§4.6 phase 5) and §4.12 step 9 cannot be performed. "Invalid Receipt" (§4.7) is not a reachable condition. The gate performs the phase-3 policy evaluation itself. The local hash-chained store stands in for R2 but is not a SCITT ledger.

**D22. Field subset.** Proposals have no `payload_media_type`, `action_type`, or `target`, and the nonce is text rather than bytes (both are accepted, per D14). Ratifications have no `ratification_id` or `reviewer_context`. Policies have no `policy_version` or validity windows (D13). These follow the interface as given. Action type and target are still bound, because they live inside the payload, which is covered by `payload_digest` (§4.4).

**D23. The runtime payload must be deterministically encodable.** That means ints, text, bytes, arrays, maps, bools, and null; no floats. Otherwise the gate denies. `make_proposal` raises on such a payload, since it is a producer rather than the gate. Paper: §4.4 requires a stable canonical representation, and floats have multiple encodings and NaN issues.

**D24. `now` handling.** In `make_proposal` and `ratify`, `now=None` means wall clock. Any provided value, including 0, is used. The interface text `int(now or time.time())` would treat 0 as "unset"; this implementation deliberately does not. In the gate, a `now` that is not a finite int or float (or is a bool) causes denial.

---

## Amendments after the blind phase

After the blind implementation was finished, it was compared with `sar_cose` by a cross-implementation differential (`../tools/cross_diff.py`). The differences were resolved into one normative rule set, `../SEMANTICS.md`.

For almost every difference, the stricter choice made here was adopted and `sar_cose` was changed: D2, D3, D4, D8, D9, D11, D14, D15, D17 and D20.

Only one change was made to this implementation:

- **D1 amended:** `MAX_FUTURE_SKEW` changed from 0 to 30 seconds (SEMANTICS.md S1). A deployment tolerance for clock differences between the agent, overseer and gate hosts was judged necessary, and it is a parameter rather than a semantic choice. Apart from this and the second amendment below, everything in this file reflects the blind phase unchanged.

### Second amendment (round 2 of v1.2, after an external audit)

- **D5 amended:** with an explicit evaluation instant `at`, the offline verifier now accepts `window_lo - MAX_FUTURE_SKEW <= at < window_hi` instead of `window_lo <= at < window_hi`. Before this change the gate could allow at an instant (within the clock tolerance before the common window) at which `verify_record_offline(..., at=now)` returned False. Both functions now apply the same rule (SEMANTICS.md S2, S13), and `test_sar_cross.py` checks that, for every tested instant `t`, the gate allows at `t` exactly when offline verification with `at=t` succeeds (ignoring replay and payload). `test_independent_of_wallclock_and_store` was changed accordingly. Gate decisions are unchanged.

The blind version, as reconstructed before both amendments, is kept in `original_blind/` (see `BRIEF.md`).
