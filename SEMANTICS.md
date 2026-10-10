# Authorization semantics (normative for sar-cose v1.2)

The SARWP paper (§4.5–4.12) leaves several decisions open. A second implementation written blind from the paper (`independent/`) made different choices from `sar_cose` in places. A cross-implementation differential then found **118 disagreements in 6,000 decisions**, and every one traced to one of the gaps below.

Each rule fixes one reading. Where the paper allows a lenient and a strict reading, the strict one is chosen, following §4.7 ("ambiguous policy results are treated as failures") and invariant I5 (deny by default). Both implementations follow these rules, and `test_sar_cross.py` checks that they agree.

Time is in integer seconds. `SKEW` = 30 s.

| Rule | Decision | Paper basis | Previously in sar_cose |
|---|---|---|---|
| **S1 Clock skew** | A proposal or ratification dated more than `SKEW` in the future is denied. | §4.7 (validity), §3.2 (no trusted runtime) | same |
| **S2 Validity intervals** | Intervals are half-open: a proposal is valid for `issued_at <= now < expires_at`, a ratification for `now < valid_until`. Empty intervals (`ttl <= 0`) are invalid. | §4.5.1–4.5.2 | inclusive end (`now <= expires_at`) |
| **S3 Review window** | A ratification must be issued within its proposal's validity: `issued_at <= reviewed_at < expires_at`. | §4.6 phases 1→2; I2 | end of window not checked at the gate |
| **S4 Invalid ratification** | One invalid ratification in the set denies the request, even if the others reach quorum. Invalid means: unauthorized overseer, bad signature, wrong binding or policy, malformed, out of window, **expired**, or unknown verdict. | §4.7 lists "Expired ratification" and "Invalid overseer signature" as denial conditions; §4.6 phase 3 "Any validation failure terminates" | expired approvals were silently not counted |
| **S5 Duplicates** | Two ratifications from the same overseer deny the request. Quorum counts distinct overseers. | §4.5.3 quorum; §4.7 ambiguity → failure | duplicates ignored |
| **S6 Rejection veto** | Any `REJECTED` ratification denies the request, regardless of other approvals. | §4.11, §4.7 "Rejected verdict" | same |
| **S7 Verdicts** | Only the exact strings `APPROVED` and `REJECTED` are valid. Anything else denies. | §4.5.2 | same |
| **S8 Policy validity** | The policy has exactly the keys `policy_id`, `quorum`, `authorized_agents` and `authorized_overseers`. Ids are non-empty strings; keys are valid Ed25519 public keys in lowercase hex; `1 <= quorum <= #overseers`. **Separation of roles:** no key is shared by two overseers, and no identity or key is both an agent and an overseer. Otherwise every request is denied. | §4.5.3; O1 (an *authorized human* ratifies); §4.7 "Invalid … policy" | role separation not enforced (**security gap**: one key under two overseer ids could meet a quorum of 2; an agent listed as overseer could ratify its own proposal) |
| **S9 Statement shape** | Bodies have exactly the v1 field set, with `v = 1`, typed fields and 32-byte digests. `proposal_id` must equal its recomputation from the proposal body. The signature is exactly 128 lowercase hex characters. | §4.5.1–4.5.2; I1 | extra fields and arbitrary `proposal_id` accepted |
| **S10 Replay keys** | An ALLOW atomically consumes `proposal_id`, the nonce (unique per policy, across agents) and, if the payload has a `transaction_id`, that transaction id. A DENY consumes nothing. | §4.10 | only (policy, agent, nonce) consumed |
| **S11 Offline verification** | Uses no wall clock. Requires everything in S3–S9 that can be checked from the artifacts, plus a non-empty interval in which the proposal and all ratifications were valid together. An optional `at` must fall in that interval. | §4.12, O3 | per-ratification window only |
| **S13 Gate–audit consistency** | The gate allows only if the proposal and all ratifications share a non-empty common validity interval (the S11 condition), so **every ALLOW passes offline verification**. | §4.12 (auditors must be able to verify the authorization), O5 | an ALLOW could fail later offline verification (e.g. one approval issued within the skew window after another had expired), found by the cross-implementation test |
| **S12 Logging failures** | A failure to log never turns into ALLOW. If a denial cannot be logged, the call still returns DENY. | §4.7, I5 | an unloggable denial could raise |

## Deliberate implementation differences (not decision semantics)

- **Chain check before ALLOW.** `independent/` re-verifies the whole hash chain before every ALLOW and refuses if it is broken. `sar_cose` does not: that costs O(n) per decision, and integrity is checked by `verify_chain` against a retained checkpoint instead. This can only make a difference on a database that has already been tampered with, which is outside the cross-differential's scenario space.
- **Replay key on COSE bytes.** `independent/` also consumes a key derived from the proposal's COSE bytes. Given S9, `proposal_id` determines the proposal, so this adds nothing.
