---
title: "Sovereign Acceptance Runtime (SAR) Profile: Human-Attributed Ratification as COSE Signed Statements with Fail-Closed, Payload-Bound Execution"
abbrev: SAR Profile
docname: sar-profile (repository document, not submitted to the IETF)
version: 1.3-draft (profile version 1; this file is the normative reference for sar-cose v1.3)
status: Experimental profile, work in progress. Not an IETF document; no IANA registrations have been made.
author: A. Mikulić (with AI assistance; see the SARWP paper, "Use of AI Tools")
---

# SAR Profile, version 1

## Abstract

This document specifies a profile for representing an AI agent's proposed action and the human-attributed ratifications of that action as COSE_Sign1 Signed Statements over deterministically encoded CBOR, together with the Registration Policy that decides whether the action may execute, the deterministic decision procedure of an Execution Gate, its replay and logging rules, and a stateless offline verification procedure. Sections 15–18 add registration of the statements at a Transparency Service in the sense of RFC 9943, Receipts with Merkle inclusion proofs, and a Receipt-gated execution rule. It is written so that an implementer who has not seen the reference implementation can build an interoperable implementation and check it against the published test vectors.

## Status of This Document

This is a repository document that accompanies the SARWP working paper v1.3. It is not an Internet-Draft, has not been reviewed by any IETF working group, and has no IANA registrations. Requirement identifiers (`SAR-REQ-nnn`) are stable within profile version 1. Decisions taken while writing and implementing this profile are recorded in `spec/ISSUES.md`; the profile is changed first and implementations follow (the author's "spec-first" rule).

## 1. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

Each normative requirement is written as a paragraph that starts with its identifier in bold, followed by its level in parentheses, for example **SAR-REQ-001** (MUST). `spec/conformance_manifest.csv` lists every requirement with its section, level, CDDL rule, test vectors and implementation tests; `spec/check_manifest.py` regenerates the manifest from this file and fails if a MUST has no test vector.

CDDL (RFC 8610) for all data items is in `spec/sar-profile.cddl` and is normative. Where this text and the CDDL disagree, this text wins and the disagreement is a bug to be recorded in `spec/ISSUES.md`.

Times are POSIX times in integer seconds. "Deterministic CBOR" means the core deterministic encoding requirements of RFC 8949, Section 4.2.1, restricted as in Section 6. `H(x)` is SHA-256 (FIPS 180-4) of the octet string `x`. `dcbor(v)` is the deterministic CBOR encoding of the data item `v`.

## 2. Terminology

- **Agent**: software that proposes actions. Not trusted.
- **Overseer**: a principal whose signing credential the Registration Policy attributes to a named human. An overseer's signature is a *human-attributed ratification*: it proves use of that credential over the statement, not that the human was present, understood or intended the action (Section 13).
- **Payload**: the canonical execution payload, a CBOR data item describing exactly the action to be executed.
- **Proposal Statement** ("proposal"): a COSE_Sign1 Signed Statement by an agent naming the digest of a payload.
- **Ratification Statement** ("ratification"): a COSE_Sign1 Signed Statement by an overseer recording the verdict `APPROVED` or `REJECTED` over one exact proposal.
- **Registration Policy** ("policy"): the configuration that names the authorized agents and overseers, their keys, and the quorum.
- **Execution Gate** ("gate"): the trusted component that decides ALLOW or DENY immediately before a protected action, records the decision and consumes replay keys.
- **Evaluation instant** `t`: the gate's clock reading at decision time, in integer seconds.
- **Clock tolerance** `τ` (tau): a deployment parameter, the number of seconds by which the gate's clock may run behind the signers' clocks. Test vectors use τ = 30.
- **Transparency Service (TS)**, **Receipt**, **Registration Policy**, **Signed Statement**: as in RFC 9943; their use in this profile is defined in Sections 15–18.
- **Enforcement boundary**: the deployment property that every protected operation passes through the gate. This profile cannot establish it; Section 13 states the consequences.

## 3. Overview

1. The agent builds the payload `P` and signs a proposal containing `H(dcbor(P))`.
2. Each overseer reviews the proposal (and a rendering of `P`) and signs a ratification bound to the SHA-256 digest of the proposal's exact COSE_Sign1 bytes.
3. The gate receives `P` (as deterministic CBOR bytes or as a data item), the proposal and the ratification set, evaluates them against the policy at instant `t` (Sections 7–11), atomically consumes the replay keys and records ALLOW, or records DENY. It starts from DENY.
4. A verifier holding only the statements and the policy can re-check the authorization offline (Section 12).
5. With Sections 15–18, the proposal and ratification set are first registered at a Transparency Service, whose Registration Policy evaluation and Receipt become a precondition of execution.

## 4. Data Model

A proposal body and a ratification body are CBOR maps with text keys (CDDL rules `proposal-body`, `ratification-body`). A policy is a map (`registration-policy`). The Transparent Authorization Record (`transparent-authorization-record`) groups a proposal, its ratification set, a policy reference and, with Sections 15–18, a Receipt.

## 5. Wire Format of Statements

**SAR-REQ-001** (MUST) A statement MUST be a COSE_Sign1 structure (RFC 9052, Section 4.2) carrying CBOR tag 18, that is a tagged array of exactly four elements `[protected, unprotected, payload, signature]`. A receiver MUST reject an untagged array, another tag, or an array of another length.

**SAR-REQ-002** (MUST) `protected` MUST be a byte string containing the deterministic CBOR encoding of a map with exactly the three labels 1 (alg), 3 (content type) and 4 (kid). A receiver MUST reject a protected header with any other label, a missing label, or a non-deterministic encoding.

**SAR-REQ-003** (MUST) The algorithm (label 1) MUST be -19 (Ed25519, fully specified; RFC 9864). A gate and an offline verifier MUST reject any other value, including the deprecated polymorphic identifier -8 (EdDSA), even when the signature verifies under it.

**SAR-REQ-004** (MUST) The content type (label 3) MUST be the text string `application/sar-proposal+cbor` for a proposal and `application/sar-ratification+cbor` for a ratification. A receiver MUST reject a statement whose content type does not match the role in which it is presented (a proposal presented as a ratification, or the reverse).

**SAR-REQ-005** (MUST) The kid (label 4) MUST be a byte string equal to the UTF-8 encoding of the signer identifier in the body (`agent_id` for a proposal, `overseer_id` for a ratification). A receiver MUST reject a statement whose kid differs.

**SAR-REQ-006** (MUST) `unprotected` MUST be an empty map. A receiver MUST reject a statement with any unprotected header parameter.

**SAR-REQ-007** (MUST) `payload` MUST be an embedded byte string (no detached payload) containing the deterministic CBOR encoding of a map, the statement body. A receiver MUST reject a statement whose payload is nil, not a byte string, not a map, or not deterministically encoded.

**SAR-REQ-008** (MUST) `signature` MUST be the 64-byte Ed25519 signature (RFC 8032) by the signer's key over the COSE Sig_structure `dcbor(["Signature1", protected, h'', payload])` (RFC 9052, Section 4.4). A receiver MUST reject a statement whose signature does not verify under the key that the policy assigns to the signer identifier in the body, or whose signature is not exactly 64 bytes.

Because every element is deterministic, a statement has exactly one valid encoding; the proposal digest (Section 8) depends on it.

## 6. Deterministic CBOR

**SAR-REQ-010** (MUST) An encoder MUST produce the core deterministic encoding of RFC 8949, Section 4.2.1: preferred (shortest) argument encoding, definite lengths only, map keys sorted by the bytewise lexicographic order of their deterministic encodings, and no duplicate map keys. The vectors in `test-vectors/enc-*.json` are taken from RFC 8949, Appendix A (integer, string, array, map and tag examples only).

**SAR-REQ-011** (MUST) A decoder MUST reject, wherever this profile requires deterministic CBOR (protected headers, statement bodies, COSE_Sign1 structures, and payloads presented as bytes), any input that is not in that encoding: non-preferred integer or length arguments, indefinite-length items, unsorted or duplicate map keys, and trailing bytes after the data item. The check MAY be implemented by decoding and re-encoding and comparing the octets.

**SAR-REQ-012** (MUST) Floating-point values (major type 7, additional information 25, 26, 27) MUST NOT appear in statements or payloads. An encoder MUST refuse to encode them and a decoder MUST reject them. (Floats have several encodings and NaN payloads; see `spec/ISSUES.md` ISS-013.)

Simple values `false`, `true` and `null`, integers (major types 0 and 1, magnitude below 2^64), byte and text strings, arrays, maps and tags MAY appear in payloads. Text strings are compared as octet sequences; no Unicode normalization is applied, so two strings that differ only in normalization form are different payloads.

## 7. Statement Bodies

**SAR-REQ-020** (MUST) A proposal body MUST have exactly the members `v`, `agent_id`, `payload_digest`, `issued_at`, `expires_at`, `nonce`, `policy_id` and `proposal_id`, with: `v` the integer 1; `agent_id` and `policy_id` identifiers (SAR-REQ-023); `payload_digest` a 32-byte byte string; `issued_at` and `expires_at` unsigned integers below 2^64; `nonce` a non-empty text or byte string of at most 256 units (characters for text, octets for bytes); `proposal_id` a text string. A gate and an offline verifier MUST reject a proposal with any additional, missing or wrongly typed member, even if it is validly signed (rule S9).

**SAR-REQ-021** (MUST) A statement's nominal validity interval MUST be non-empty: `issued_at < expires_at` for a proposal and `reviewed_at < valid_until` for a ratification. A statement with an empty interval MUST be rejected.

**SAR-REQ-022** (MUST) A ratification body MUST have exactly the members `v`, `proposal_digest`, `proposal_id`, `overseer_id`, `verdict`, `reviewed_at`, `valid_until` and `policy_id`, with `v` the integer 1, `proposal_digest` a 32-byte byte string, `proposal_id` a text string, `overseer_id` and `policy_id` identifiers, `verdict` a text string, and `reviewed_at` and `valid_until` unsigned integers below 2^64. A gate and an offline verifier MUST reject a ratification with any additional, missing or wrongly typed member.

**SAR-REQ-023** (MUST) An identifier (`agent_id`, `overseer_id`, `policy_id`, and the identifiers in a policy) MUST be a text string of 1 to 256 Unicode code points. Identifiers MUST be compared exactly, code point by code point, without case folding or normalization. (Length is counted in code points, not octets; see ISS-010.)

**SAR-REQ-024** (MUST) `verdict` MUST be exactly one of the text strings `APPROVED` and `REJECTED`. Any other value, including a different case, MUST cause denial (rule S7).

Fields that the SARWP paper shows as illustrative (`payload_media_type`, `action_type`, `target`, `ratification_id`, `reviewer_context`) are not part of version 1. Action type and target are bound through the payload, which the payload digest covers.

## 8. Digests and Identifiers

**SAR-REQ-030** (MUST) `payload_digest` MUST be `H(dcbor(P))`. The gate MUST compute the digest of the runtime payload itself and MUST deny unless it equals `payload_digest` in all 32 octets.

**SAR-REQ-031** (MUST) A ratification's `proposal_digest` MUST be `H(proposal_bytes)`, where `proposal_bytes` is the exact COSE_Sign1 encoding of the proposal (tag 18 included). A ratification whose `proposal_digest` differs MUST be treated as not bound to the proposal.

**SAR-REQ-032** (MUST) `proposal_id` MUST be the first 32 lowercase hexadecimal characters (128 bits) of `H(dcbor(B'))`, where `B'` is the proposal body without the `proposal_id` member. A gate and an offline verifier MUST recompute it and MUST deny if it differs, even if the proposal is validly signed.

**SAR-REQ-033** (MUST) A ratification's `proposal_id` MUST equal the proposal's `proposal_id`; a ratification whose digest matches but whose `proposal_id` differs, or the reverse, MUST be treated as not bound.

**SAR-REQ-034** (MUST) Digests MUST be compared over all octets, and identifiers, nonces and policy identifiers MUST be compared exactly (Section 7). In particular a gate MUST NOT case-fold `policy_id` or `nonce`.

## 9. Registration Policy

**SAR-REQ-040** (MUST) A version 1 policy MUST be a map with exactly the members `policy_id`, `quorum`, `authorized_agents` and `authorized_overseers`, where `policy_id` is an identifier, `authorized_agents` and `authorized_overseers` are non-empty maps from identifier to public key, each key being the 32-byte Ed25519 public key encoded as 64 lowercase hexadecimal characters and decoding to a valid point, and `quorum` is an integer with `1 <= quorum <= number of authorized overseers`. If the policy is not valid, the gate MUST deny every request and the offline verifier MUST reject every record (rule S8).

**SAR-REQ-041** (MUST) Roles MUST be separated: no public key may be registered for two overseers; no identifier may appear both as an agent and as an overseer; and no public key may be registered both for an agent and for an overseer. A policy that violates this is not valid (SAR-REQ-040). (Without this, one key under two overseer identifiers satisfies a quorum of two, and an agent registered as an overseer ratifies its own proposals.)

**SAR-REQ-042** (MUST) A gate or verifier implementing version 1 of this profile MUST treat a policy containing any member other than the four of SAR-REQ-040, including the future members of Section 9.1, as not valid. It MUST NOT ignore unknown members, because ignoring a constraint the author believes is enforced is a silent failure (ISS-001).

**SAR-REQ-043** (MUST) The gate MUST evaluate the policy in force at the evaluation instant, on every request. Removing an agent or overseer, or replacing its key, MUST cause denial of every later request that depends on it, including requests ratified before the change (revocation). Offline verification against the earlier policy is unaffected (Section 12).

**SAR-REQ-044** (MUST) The `policy_id` of the proposal and of every ratification MUST equal the policy's `policy_id`; otherwise the request MUST be denied.

**SAR-REQ-045** (MUST) The proposal's `agent_id` MUST be a key of `authorized_agents`, and every ratification's `overseer_id` MUST be a key of `authorized_overseers`; each statement's signature MUST verify under the key registered for that identifier. Otherwise the request MUST be denied.

### 9.1 Future policy members (specified, not part of version 1)

The following members are specified for a later profile version. A version 1 implementation rejects them (SAR-REQ-042). An implementation of a later version that accepts a member MUST enforce it; it MUST NOT accept a member it does not enforce.

| Member | Type | Meaning |
|---|---|---|
| `policy_version` | uint | Version of this policy under the same `policy_id`. Statements would then carry the version, and a gate MUST deny on mismatch. |
| `permitted_action_types` | [+ tstr] | The payload's top-level `action_type` MUST be one of these. |
| `target_constraints` | { * tstr => any } | Constraints on payload members that name the target system; the constraint language is not defined. |
| `max_validity` | { ? "proposal": uint, ? "ratification": uint } | Upper bounds on `expires_at - issued_at` and `valid_until - reviewed_at`. Without it, validity is bounded only by what the signers chose. |
| `replay_policy` | { ? "nonce_scope": "policy" / "agent", ? "transaction_id": bool } | Selects replay scopes (Section 11). Version 1 behaves as `{"nonce_scope": "policy", "transaction_id": true}`. |

## 10. Temporal Semantics (rules S1, S2, S3, S11, S13)

Let a proposal have nominal interval `[issued_at, expires_at)` and each ratification `[reviewed_at, valid_until)`. The common interval of a proposal and its ratifications is `[lo, hi)` with `lo = max(issued_at, all reviewed_at)` and `hi = min(expires_at, all valid_until)`.

**SAR-REQ-050** (MUST) A gate evaluating at instant `t` MUST accept the temporal conditions of a request if and only if `lo < hi` and `lo - τ <= t < hi` (S1, S2). The tolerance applies to the start only: a statement dated up to `τ` seconds after `t` is accepted, one dated more than `τ` after `t` is denied, and expiry is exact (at `t = hi` the request is denied).

**SAR-REQ-051** (MUST) Every ratification MUST have been issued within its proposal's validity: `issued_at <= reviewed_at < expires_at` (S3). Otherwise the request MUST be denied, independently of `t` and `τ`.

**SAR-REQ-052** (MUST) The set of ratifications is evaluated as a whole: if any ratification in the presented set is invalid (malformed, unauthorized, badly signed, not bound, bound to another policy, outside the review window, expired at `t`, or with an unknown verdict), the request MUST be denied, even if the other ratifications reach the quorum (S4). A gate MUST NOT silently ignore an invalid ratification.

**SAR-REQ-053** (MUST) A request whose common interval is empty (`lo >= hi`) MUST be denied even if each statement is individually within its own interval at `t` within the tolerance (for example one approval that has expired and one dated within `τ` after it).

`τ` is a deployment parameter; implementations SHOULD make it configurable and MUST apply the same value at the gate and in offline verification (Section 12). The evaluation instant is an integer number of seconds; an implementation MAY reject a non-integer instant (ISS-005).

## 11. Quorum, Duplicates, Rejection, Replay

**SAR-REQ-060** (MUST) Two or more ratifications in the presented set with the same `overseer_id` MUST cause denial (S5), whether or not they are identical.

**SAR-REQ-061** (MUST) The request MUST be denied unless the number of distinct overseers with a valid `APPROVED` ratification is at least `quorum`.

**SAR-REQ-062** (MUST) Any valid ratification with verdict `REJECTED` in the presented set MUST cause denial, regardless of other approvals (S6).

**SAR-REQ-063** (MUST) A request without a proposal, or with an empty ratification set, MUST be denied.

**SAR-REQ-070** (MUST) The gate MUST compute the digest of the payload it is given and deny unless it equals the proposal's `payload_digest` (Section 8), immediately before returning ALLOW.

**SAR-REQ-071** (MUST) A gate that accepts the payload as an octet string MUST deny unless the octets are deterministic CBOR (Section 6), MUST compute the digest over a private copy of exactly those octets, and on ALLOW MUST hand exactly that copy to the executor. (A gate that accepts only a decoded data item does not offer this interface and is not subject to this requirement; ISS-004.)

**SAR-REQ-072** (SHOULD) The executor SHOULD transmit exactly the octets returned by the gate (SAR-REQ-071), or the target system SHOULD recompute the digest itself; executing a separately held or re-encoded object reintroduces payload substitution.

**SAR-REQ-080** (MUST) An ALLOW MUST consume the proposal's `proposal_id`, scoped to the policy; a later presentation of the same proposal under the same policy MUST be denied as replay.

**SAR-REQ-081** (MUST) An ALLOW MUST consume the proposal's `nonce`, scoped to the policy and across all agents, compared as a deterministic CBOR value (so the text "n1" and the bytes h'6e31' are different nonces, and "N1" and "n1" are different nonces). A later proposal with a consumed nonce MUST be denied as replay.

**SAR-REQ-082** (MUST) If the payload is a map with a top-level member `transaction_id`, an ALLOW MUST consume that value, scoped to the policy and compared as a deterministic CBOR value (the text "5" and the integer 5 are different). Values nested deeper in the payload MUST NOT be consumed. A later request with a consumed transaction identifier MUST be denied as replay.

**SAR-REQ-083** (MUST) Consumption MUST NOT depend on the evaluation instant: a replay presented at any later instant MUST be denied.

**SAR-REQ-084** (MUST) A denial MUST consume nothing; a request denied for any reason other than replay can be presented again (for example with further ratifications) and allowed.

**SAR-REQ-085** (MUST) Consumption of all replay keys and recording of the ALLOW decision MUST be one atomic step that completes before the gate returns ALLOW (consume-then-execute: at most once), and consumed keys MUST persist across restarts of the gate. Several gates that share a replay store MUST serialize this step so that a given authorization is allowed at most once.

An implementation MAY consume additional keys that are functions of the proposal alone (for example a digest of its COSE bytes); because `proposal_id` determines the proposal (SAR-REQ-032), such keys add no denials (ISS-007).

## 12. Offline Verification (rules S11, S13)

**SAR-REQ-100** (MUST) An offline verifier MUST decide, using only the proposal, the ratification set and the policy (no store and no clock), whether they constitute a valid authorization: everything in Sections 5–9 and SAR-REQ-051, SAR-REQ-060–063 that can be checked from the artifacts, with every ratification `APPROVED`, plus `lo < hi`.

**SAR-REQ-101** (MUST) If the verifier is given an evaluation instant `at`, it MUST additionally require `lo - τ <= at < hi` (the gate's rule, SAR-REQ-050).

**SAR-REQ-102** (MUST) Gate and offline verification MUST agree (S13): ignoring replay and payload binding, the gate allows at instant `t` if and only if offline verification with `at = t` succeeds, and every request the gate allows also passes offline verification without `at`.

Offline verification establishes that the record was a valid authorization under the given policy; it does not establish that the action was executed, nor which policy was in force at execution (SAR-REQ-043). The algorithm is:

```
verify_offline(proposal, rats, policy, at=None):
  require policy valid (SAR-REQ-040..042)
  require proposal well-formed, proposal_id recomputed (SAR-REQ-020..023, 032)
  require proposal.policy_id == policy.policy_id; agent authorized; signature, alg, ct, kid valid
  d := H(cose_bytes(proposal)); lo, hi := issued_at, expires_at; seen := {}
  for r in rats:
     require r well-formed, overseer authorized, signature/alg/ct/kid valid
     require r.proposal_digest == d and r.proposal_id == proposal.proposal_id
     require r.policy_id == policy.policy_id and r.verdict == "APPROVED"
     require r.overseer_id not in seen; seen += r.overseer_id
     require issued_at <= r.reviewed_at < expires_at
     lo, hi := max(lo, r.reviewed_at), min(hi, r.valid_until)
  require |seen| >= quorum and lo < hi
  if at is given: require lo - τ <= at < hi
```

## 13. Decision Recording and Denial Semantics (rule S12)

**SAR-REQ-090** (MUST) The gate MUST start from DENY and MUST record every decision, ALLOW and DENY, in its decision log before returning it. Each DENY record SHOULD name the proposal identifier claimed by the request, if any.

**SAR-REQ-091** (MUST) A failure to record a decision MUST NOT result in ALLOW. If an ALLOW cannot be recorded, the gate MUST deny and consume nothing; if a denial cannot be recorded, the gate MUST still return DENY. Any internal error MUST result in DENY.

**SAR-REQ-092** (SHOULD) The decision log SHOULD be tamper-evident relative to an externally retained checkpoint: for example a hash chain whose head is signed after every commit, so that anyone retaining a signed checkpoint outside the store can detect later modification, truncation or rewriting. The log format is local to an implementation and is not part of the wire profile.

**SAR-REQ-093** (SHOULD) A gate SHOULD be able to check, before every ALLOW, that its replay store has not been rolled back relative to a checkpoint retained in a separate trust domain (an anchor), and SHOULD refuse every ALLOW otherwise. Without such a check, anyone who can replace the store with an older copy can re-enable consumed authorizations.

### 13.1 Deny-reason taxonomy

**SAR-REQ-095** (MUST) Every DENY, and every refusal by a Transparency Service (Section 15), MUST carry a reason that maps to exactly one of the following classes, and an implementation MUST distinguish the classes from each other. Within a class, the subclasses SHOULD be reported and MAY be merged. The order in which an implementation evaluates conditions is not normative; when several conditions fail at once, any of the failing classes is a conforming reason. Test vectors therefore contain one fault each.

| Class | Subclasses (SHOULD distinguish, MAY merge) | Requirements |
|---|---|---|
| `policy_invalid` | malformed policy; role overlap; unknown member | 040–042 |
| `missing_evidence` | no proposal; no ratification | 063 |
| `invalid_statement` | not COSE_Sign1 or not deterministic; protected header; algorithm; content type; kid; bad signature; body shape; empty interval; `proposal_id` not derived; unknown verdict; (TS) malformed registration request; (TS) rejection request without a valid rejection | 001–012, 020–024, 032 |
| `unauthorized_signer` | agent not authorized; overseer not authorized | 045 |
| `binding_mismatch` | ratification not bound (digest or id); policy_id of a statement differs from the policy | 031, 033, 044 |
| `duplicate_ratification` | — | 060 |
| `rejected` | — | 062 |
| `quorum_not_met` | — | 061 |
| `time_invalid` | proposal expired; ratification expired; dated more than τ in the future; outside review window; no common interval | 050–053 |
| `payload_mismatch` | digest differs; payload octets not deterministic CBOR | 030, 070, 071 |
| `replay` | proposal id, nonce or transaction id consumed | 080–083 |
| `store_failure` | decision could not be recorded; store inconsistent with its anchor | 091, 093 |
| `receipt_invalid` | (Sections 15–18) missing; malformed; untrusted log or key; inclusion proof fails (including a Receipt for another statement set, proposal, policy or kind); registration time outside validity; stale or future-dated Receipt | 130–136 |
| `registration_conflict` | (TS only) authorization already registered for the proposal; registered rejection (veto) | 122, 123 |

Implementations that check a statement's header and signature before its body shape, or the reverse, report different subclasses of `invalid_statement` for some faults; this is conforming.

## 14. Security and Privacy Considerations

**Enforcement boundary.** The guarantees hold only for actions that pass through the gate. The gate, its replay store, its decision log, its clock and the source of its policy are trusted and must be outside the agent's control; credentials for protected tools must be held by the gate or by an executor behind it.

**Human attribution.** A ratification proves that the overseer's credential signed one exact proposal. It does not prove the human's presence, understanding or intent, nor that the rendering shown to the human matched the payload ("what you see is what you sign"). Key compromise produces evidence indistinguishable from genuine ratification.

**Time.** The gate's clock is trusted. A gate whose clock is set back accepts expired statements; one set forward denies valid ones. Section 18 analyses which of these properties a Transparency Service timestamp can and cannot replace.

**Replay store integrity.** Replay protection is only as good as the integrity of the replay store (SAR-REQ-093).

**Algorithm agility.** Version 1 fixes Ed25519 and SHA-256. A later version may add algorithms; a gate MUST NOT accept algorithms the policy does not name.

**Privacy.** Statements carry signer identifiers. Deployments SHOULD use opaque, pseudonymous identifiers in `agent_id` and `overseer_id`, keep the mapping from pseudonym to person outside the log (off-ledger identity resolution), and avoid personal data in payloads where a digest suffices. The identity mapping can be erased; signed statements, Receipts and log entries cannot be altered without destroying the evidence, and after erasure of the mapping they remain verifiable but refer to an unresolvable pseudonym. Registration at a Transparency Service discloses the existence and timing of statements to whoever can read the log; confidential transparency is future work.

**Denial flooding.** Every denial is logged; rate limiting is outside this profile.

## 15. Registration at a Transparency Service

Sections 15–18 make the SCITT Registration Policy the pre-execution gate: a set of statements is registered at a Transparency Service (TS) only if the policy is satisfied, the TS issues a Receipt for the registration, and the Execution Gate executes only with a valid Receipt. They follow RFC 9943 (architecture), RFC 9942 (COSE Receipts) and RFC 9162 (Merkle tree hashing) where feasible; Section 15.4 lists every deviation.

Primary sources consulted on 10 October 2026: RFC 9943 (June 2026); RFC 9942 "COSE Receipts" (June 2026; formerly draft-ietf-cose-merkle-tree-proofs, last revision -18); draft-ietf-scitt-scrapi-11 (26 June 2026; not an RFC); RFC 9162; RFC 9597 (CWT Claims header parameter, label 15); RFC 8392 (claim keys `iss` = 1, `iat` = 6). Statements relied on:
- RFC 9943 §3 defines the Registration Policy as "the precondition enforced by the TS before registering a Signed Statement"; §6.3: "A TS MUST ensure that a Signed Statement is registered before releasing its Receipt."
- RFC 9943 §7: "The Registration time is recorded as the timestamp when the TS added the Signed Statement to its VDS." RFC 9943 does not define a trust model for the TS clock.
- RFC 9943 §6.3: the unprotected header "MUST be set to an empty map before the Signed Statement can be included in a Statement Sequence."
- RFC 9942: the Receipt's protected header carries `vds` (label 395, value 1 = RFC9162_SHA256); the unprotected header carries `vdp` (label 396) whose key -1 holds inclusion proofs `[tree-size, leaf-index, inclusion-path]`; "the payload is the Merkle Tree root that corresponds to the log at size tree-size", and payloads "SHOULD be detached".
- RFC 9162 §2.1.1: `MTH({d[0]}) = HASH(0x00 || d[0])`; for n > 1, `MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` with k the largest power of two smaller than n.
- SCRAPI: a client registers with `POST /entries` (`application/cose`); a synchronous response (201) contains the Receipt.

### 15.1 Registration request

A registration request (CDDL `registration-request`) is a map `{"v": 1, "kind": "authorization" / "rejection", "policy_id": identifier, "proposal": bstr, "ratifications": [+ bstr]}` in deterministic CBOR, where `proposal` and each element of `ratifications` are the exact COSE_Sign1 octets of the statements. A request that does not satisfy the CDDL is refused with class `invalid_statement`; a request whose ratification list is empty MAY instead be reported as `missing_evidence` (ISS-112). This profile does not fix a transport; with SCRAPI it would be the body of `POST /entries` with the provisional content type `application/sar-registration+cbor`.

### 15.2 Registration Policy evaluation at the TS

Let `t_reg` be the TS clock reading when it adds the entry to its log (the registration time).

**SAR-REQ-120** (MUST) For a request of kind `authorization`, the TS MUST register an entry only if the statements satisfy, under the policy identified by `policy_id`, every requirement that can be checked without the payload and without the replay store: Sections 5–9 (SAR-REQ-001–045), SAR-REQ-051–053 and SAR-REQ-060–063, and the temporal rule of SAR-REQ-050 evaluated at `t_reg` (`lo - τ <= t_reg < hi`). If any check fails, the TS MUST NOT add an entry and MUST NOT issue a Receipt, and it SHOULD report the failure with the deny-reason classes of Section 13.1.

**SAR-REQ-121** (MUST) The TS MUST NOT consume replay keys, and registration MUST NOT be treated as execution. The payload binding (SAR-REQ-070, 071) and replay rules (SAR-REQ-080–085) are evaluated only by the gate.

**SAR-REQ-122** (MUST) The TS MUST register at most one entry of kind `authorization` per (`policy_id`, `proposal_id`). A later request for the same pair MUST be refused (class `registration_conflict`); concurrent requests MUST be serialized so that exactly one succeeds.

**SAR-REQ-123** (MUST) If the TS has registered an entry of kind `rejection` for a (`policy_id`, `proposal_id`), it MUST refuse every later `authorization` request for that pair (registered veto; class `registration_conflict`). This closes a gap of the gate-only architecture, in which whoever presents the ratification set can omit a rejection.

**SAR-REQ-124** (MUST) A request of kind `rejection` MUST contain a valid proposal and at least one valid `REJECTED` ratification by an authorized overseer. Each statement is checked as in SAR-REQ-120, including the review window (SAR-REQ-051) and duplicates (SAR-REQ-060); the quorum (SAR-REQ-061), the temporal rule at `t_reg` (SAR-REQ-050) and the common-interval rule (SAR-REQ-053) do not apply: a rejection is recorded whenever it is presented, and the set may also contain valid approvals. A request without a valid `REJECTED` ratification MUST be refused with class `invalid_statement` (ISS-111). A request of kind `authorization` that contains a `REJECTED` ratification MUST be refused (S6, class `rejected`).

Which rules are evaluated where:

| Rule | At registration (TS, instant `t_reg`) | At the gate (instant `t`) |
|---|---|---|
| Statement validity, policy, binding, roles, quorum, duplicates, verdicts (S4–S9) | yes | yes (again: the gate does not trust the TS to have evaluated the policy) |
| Review window (S3), non-empty common interval | yes | yes |
| S2 temporal rule | at `t_reg` | at `t` (own clock) |
| Registration time within validity (SAR-REQ-134) | by construction | yes, from the Receipt |
| Receipt freshness (SAR-REQ-135) | — | yes |
| Payload binding, exact bytes | — | yes |
| Replay consumption (S10) | registration uniqueness only (SAR-REQ-122) | yes |
| Registered veto | yes (SAR-REQ-123) | not visible to an offline gate |

### 15.3 Registration entry

**SAR-REQ-125** (MUST) The TS MUST record each registration as the deterministic CBOR encoding of the map (CDDL `registration-entry`) `{"v": 1, "kind": kind, "log_id": log_id, "policy_id": policy_id, "proposal_id": proposal_id, "set_digest": set_digest, "registered_at": t_reg}`, where `log_id` is the TS's log identifier (a text string) and `set_digest = H(dcbor([H(proposal_bytes), R]))` with `R` the list of `H(ratification_bytes)` for all ratifications of the request, sorted in bytewise order. The entry is the leaf data `d` of the log. A different set of statements, a different proposal, policy, kind, log or registration time therefore yields a different leaf.

### 15.4 Deviations from RFC 9943, RFC 9942 and SCRAPI

1. **A set, not a Signed Statement, is the log entry.** RFC 9943 registers individual Signed Statements and gives each a Receipt. SAR's Registration Policy is a property of a *set* (proposal plus ratifications: quorum, veto, common interval), so SAR registers one TS-constructed entry per set and issues one Receipt for it. Each statement in the set is a COSE Signed Statement, but the leaf is not. A fully RFC 9943-conformant alternative (register each statement and attach a policy-evaluation statement by the TS) is future work (ISS-102).
2. **Receipts are carried beside the statements, not in their unprotected header.** RFC 9943 forms a Transparent Statement by adding the Receipt to the unprotected header (RFC 9942 label 394). SAR keeps statements with an empty unprotected header (SAR-REQ-006) because the ratification binds to the exact octets of the proposal; the Receipt travels in the Transparent Authorization Record (`receipt` member) and as a separate gate argument (ISS-103).
3. **Receipt header constraints are stricter than RFC 9942**: the CWT Claims header (label 15, RFC 9597) with `iss` (1) = `log_id` and `iat` (6) = `t_reg` is mandatory, the payload MUST be detached (nil), and exactly one inclusion proof is allowed.
4. **No HTTP API.** The reference implementation exposes `register()` and the receipt in-process; SCRAPI's asynchronous registration is not modelled.
5. **Tree size and leaf index are not signed** (as in RFC 9942: the signature covers the root; the proof parameters are in the unprotected header). Consistency between signed checkpoints is provided separately (SAR-REQ-128).

## 16. Append-only Log

**SAR-REQ-126** (MUST) The TS MUST keep its entries in an append-only sequence and MUST compute the Merkle Tree Hash with SHA-256 exactly as RFC 9162 §2.1.1 (leaf `H(0x00 || d)`, interior node `H(0x01 || left || right)`, split at the largest power of two smaller than n). Entries MUST NOT be modified, removed or reordered.

**SAR-REQ-127** (MUST) Inclusion proofs MUST be the audit path of RFC 9162 §2.1.3.1 and MUST be verified by the algorithm of RFC 9162 §2.1.3.2, which in particular fails if `leaf_index >= tree_size`.

**SAR-REQ-128** (SHOULD) The TS SHOULD issue signed checkpoints (log id, tree size, root) and consistency proofs between tree sizes (RFC 9162 §2.1.4; a verifier MUST reject a consistency claim with an older size of 0 or an older size larger than the newer one), so that monitors can detect a TS that shows different logs to different parties (requirement R6). A verifier SHOULD reject a checkpoint whose consistency with an earlier retained checkpoint cannot be proven. The envelope of a signed checkpoint (CDDL `sar-checkpoint-payload` gives only its content) is not specified in version 1, so checkpoints are not interoperable between implementations (ISS-114).

## 17. Receipt

**SAR-REQ-130** (MUST) A Receipt MUST be a COSE_Sign1 (tag 18) whose protected header is exactly `{1: -19, 4: kid, 395: 1, 15: {1: log_id, 6: registered_at}}` with `kid` the UTF-8 encoding of `log_id`; whose unprotected header is exactly `{396: {-1: [proof]}}` with `proof` the deterministic CBOR encoding of `[tree_size, leaf_index, [* bstr .size 32]]`; whose payload is nil (detached); and whose signature is the Ed25519 signature over `dcbor(["Signature1", protected, h'', root])`, where `root` is the Merkle Tree Hash of the log at `tree_size`. The whole Receipt, its protected header and the encoded proof MUST be deterministic CBOR (Section 6). A receipt that is not in this form MUST be rejected (class `receipt_invalid`) (ISS-115).

**SAR-REQ-131** (MUST) A gate or verifier MUST be configured with the set of trusted logs, each a `log_id` and an Ed25519 public key encoded as 64 lowercase hexadecimal characters (as in SAR-REQ-040), outside the Registration Policy (whose version 1 member set is closed, SAR-REQ-042). It MUST reject a Receipt whose `log_id` is not trusted or whose signature does not verify under that log's key.

## 18. Receipt-gated Execution

**SAR-REQ-132** (MUST) A gate that requires Receipts MUST deny (class `receipt_invalid`) any request without a Receipt or with a Receipt that fails SAR-REQ-130–135.

**SAR-REQ-133** (MUST) The gate MUST reconstruct the registration entry from the presented proposal and ratification set, kind `authorization`, its own policy's `policy_id`, and the Receipt's `log_id` and `registered_at` (Section 15.3), compute the leaf hash, verify the inclusion proof to obtain the root and verify the Receipt signature over that root. A Receipt for another set of statements, another proposal, another policy, another log or another kind therefore fails.

**SAR-REQ-134** (MUST) The registration time MUST lie within the statements' validity: `lo - τ <= registered_at < hi`, with `lo` and `hi` as in Section 10. Otherwise the gate MUST deny (`receipt_invalid`).

**SAR-REQ-135** (MUST) The Receipt MUST be fresh under the gate's own clock: `registered_at <= t + τ` and `t < registered_at + max_receipt_age`, where `max_receipt_age` is a deployment parameter (vectors: 300 s). Otherwise the gate MUST deny (`receipt_invalid`).

**SAR-REQ-136** (MUST) An entry of kind `rejection` MUST NOT authorize execution (by SAR-REQ-133 the gate reconstructs kind `authorization`, so a rejection Receipt fails).

**SAR-REQ-137** (MUST) A valid Receipt MUST NOT replace any check of Sections 5–13: the gate MUST still verify the statements and the policy, apply SAR-REQ-050 at its own instant `t`, compare the payload digest and consume the replay keys. In particular a Receipt reused with another payload is denied (`payload_mismatch`), a Receipt presented again is denied (`replay`), and a Receipt that a faulty or compromised TS issued for an invalid set is denied for the statement fault.

**SAR-REQ-138** (MUST) The gate MUST use its own trusted clock for SAR-REQ-050 and SAR-REQ-135. It MUST NOT use `registered_at` as the evaluation instant.

**SAR-REQ-139** (MUST) Offline verification of a Transparent Authorization Record with a Receipt MUST perform SAR-REQ-100 and SAR-REQ-130–134, using no clock. If it succeeds, `registered_at` is an instant, attested by the TS, at which the statements were valid, and offline verification with `at = registered_at` (SAR-REQ-101) succeeds.

### 18.1 Can the TS registration time serve as trusted time? (analysis)

This section was written as a hypothesis to be tested, not as a design decision taken in advance. The vectors `sc-011`–`sc-016`, `sc-022`, `sc-025` and `sc-026` exercise each case (the reference implementation's tests in `test_sar_scitt.py`, class `TrustedTime`, do so as well; implementers do not need them).

*Freshness between ratification, registration and execution.* Three instants matter: the signers' dates (`issued_at`, `reviewed_at`), `t_reg` and the execution instant `t`. SAR-REQ-120 and SAR-REQ-134 make `t_reg` fall in the common interval (within τ of its start); SAR-REQ-050 makes `t` fall in it too, by the gate's clock. Neither instant constrains the other, so without SAR-REQ-135 a Receipt could be presented arbitrarily late within the statements' validity, and arbitrarily long after registration if the statements' validity is long.

*Delayed presentation.* A Receipt presented after the statements expire is denied by SAR-REQ-050 under the gate's clock, not by anything in the Receipt. If the gate used `registered_at` as "now", a Receipt registered during validity would authorize execution at any later time: `verify(at = registered_at)` remains true forever (SAR-REQ-139). The registration time attests *when the policy was satisfied*, not *that it is still satisfied*. Hence SAR-REQ-138.

*Malicious or misconfigured TS clock.* A TS that signs `registered_at` in the future of the gate's clock by more than τ is detected (SAR-REQ-135, first condition). A TS whose clock is behind can backdate registration only to an instant at which the statements were already valid (SAR-REQ-134) and not earlier than `t - max_receipt_age` (SAR-REQ-135); within that window it can make a Receipt look older, which only shortens its usable life, or (by up to τ) newer, which lengthens it by at most τ. A lying TS cannot extend execution beyond `hi`, because the gate checks expiry on its own clock, and it cannot make an invalid set executable, because the gate re-evaluates the policy (SAR-REQ-137). What a malicious TS *can* do is (a) refuse or delay registration (denial of service), (b) register sets that violate the policy, which the gate catches but an auditor who trusts Receipts alone would not, (c) attest a false registration time within the window above, and (d) show different logs to different parties unless monitored (SAR-REQ-128).

*What the gate still needs to know about time.* Expiry (`t < hi`), the start tolerance (`lo - τ <= t`), Receipt freshness and revocation all need the gate's own trusted clock: revocation is a change of the policy in force at `t` (SAR-REQ-043), and only the gate knows `t`. A TS timestamp cannot replace this clock; at most it can bound it from below for a gate that has none (a Receipt with `registered_at` proves that `t >= registered_at - τ_ts` if the TS is trusted), which is not sufficient for expiry.

*Skew between TS and gate.* The same τ is used for the TS–gate skew as for the signer–gate skew. A deployment whose TS and gate clocks differ by more than τ will see valid Receipts denied (TS ahead) or a shortened freshness window (TS behind).

**Conclusion.** The TS registration time is useful evidence: it bounds *when the Registration Policy was satisfied* by an independent party and orders registrations in the log. It does not serve as trusted time for execution: the gate still needs a local trusted (preferably monotonic and externally disciplined) clock for expiry, the start tolerance, Receipt freshness and revocation. The rules SAR-REQ-134, SAR-REQ-135 and SAR-REQ-138 are the minimum that makes a lying TS clock harmless beyond the window stated above.

## 19. IANA Considerations

This document makes no requests of IANA. The content types `application/sar-proposal+cbor`, `application/sar-ratification+cbor` and (Section 15.1) `application/sar-registration+cbor` are **unregistered and provisional**; they are used here only so that the two roles cannot be confused (SAR-REQ-004). A standards-track version would register them as media types with the "+cbor" structured syntax suffix (RFC 6838; RFC 8949, Section 9.5) or use CoAP content-format numbers. The Receipt of Section 17 uses the header labels registered by RFC 9942 (395 `vds`, 396 `vdp`) and RFC 9597 (15 `CWT Claims`); no private labels are used.

## 20. References

- RFC 2119, RFC 8174 — Key words for requirement levels (BCP 14).
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA); Section 7.1 test keys are used by the vectors.
- RFC 8610 — Concise Data Definition Language (CDDL).
- RFC 8949 — Concise Binary Object Representation (CBOR), Section 4.2.1 and Appendix A.
- RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures and Process.
- RFC 9864 — Fully-Specified Algorithms for JOSE and COSE.
- RFC 9943 — An Architecture for Trustworthy and Transparent Digital Supply Chains (SCITT).
- RFC 9162 — Certificate Transparency Version 2.0 (Merkle tree hashing, Section 2.1).
- RFC 9942 — CBOR Object Signing and Encryption (COSE) Receipts (formerly draft-ietf-cose-merkle-tree-proofs).
- RFC 9597 — CBOR Web Token (CWT) Claims in COSE Headers; RFC 8392 — CBOR Web Token.
- draft-ietf-scitt-scrapi-11 — SCITT Reference APIs (work in progress).
