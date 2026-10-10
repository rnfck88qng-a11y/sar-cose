# SAR profile decision log

Rule (from the author, binding): the implementation never silently drives the specification. When writing or implementing the profile reveals an ambiguity or a needed change, it is recorded here first, the profile text and test vectors are updated, and only then is code changed. Every behavioural code change after step 2 of v1.3 cites an `ISS-nnn` id in its commit message or in a code comment.

Format: id · discovered by · question · options · decision · rationale · consequences (profile sections, vectors, code).

## Found while writing the profile (step 2)

### ISS-001 Unknown policy members
- **Discovered by:** writing Section 9 (policy model review point: `policy_version`, action types, targets, max validity, replay policy).
- **Question:** what does a version 1 gate do with policy members it does not know?
- **Options:** (a) MUST-ignore unknown members (forward compatible); (b) MUST-reject the policy (deny everything); (c) reject only members marked critical.
- **Decision:** (b) for version 1 (SAR-REQ-042). The future members are specified in Section 9.1 with their intended semantics; a later version that accepts a member MUST enforce it.
- **Rationale:** a policy author who writes `permitted_action_types` believes it is enforced; ignoring it is a silent failure of a security control. Both implementations already reject unknown members (sar_cose `POLICY_KEYS`; sar_indep D10). (c) needs a criticality marker that version 1 does not have.
- **Consequences:** vectors gate-063, gate-064. No code change.

### ISS-002 Deny-reason taxonomy and evaluation order
- **Discovered by:** writing the vector format (expected deny reasons) and comparing the two implementations' reason strings.
- **Question:** must implementations report the same reason? The two implementations evaluate conditions in different orders (sar_indep checks all statement validity before the clock; sar_cose interleaves) and use different reason strings.
- **Options:** (a) normative reason codes and normative order; (b) normative classes, order not normative; (c) decision only.
- **Decision:** (b): thirteen classes that MUST be distinguished, subclasses that SHOULD be reported and MAY be merged, evaluation order not normative (Section 13.1, SAR-REQ-095). Vectors contain one fault each; where a fault necessarily implies a second class (a 31-byte digest also mismatches the payload; an empty proposal interval also fails the review window; see `deny_class` lists in gate-033 and gate-036) both classes are accepted.
- **Rationale:** operators and auditors need to tell replay from expiry from payload mismatch; fixing the order would over-specify implementations without improving security.
- **Consequences:** both implementations conform without code changes (adapters in `spec/run_vectors.py` map reason strings to classes).

### ISS-003 Header and signature faults vs body shape faults
- **Discovered by:** vector gate-021 (63-byte signature) and gate-022 (non-preferred protected header).
- **Question:** sar_indep rejects these in `from_cose`; sar_cose parses them and denies at the gate (`bad_proposal`). Is either non-conforming?
- **Decision:** both conform: all of these are subclasses of `invalid_statement` (SAR-REQ-095), and the profile does not say at which layer a statement is rejected.
- **Consequences:** `spec/run_vectors.py` records a `from_cose` rejection as DENY/invalid_statement without invoking the gate; for those steps the log-record expectation is not checked (the gate API takes parsed statements, so a statement that cannot be parsed never reaches it). No code change.

### ISS-004 Exact-bytes payload interface
- **Discovered by:** vectors gate-058, gate-059, gate-059b (non-deterministic payload octets).
- **Question:** sar_cose offers `Gate.authorize_bytes` (payload as octets, returns the exact octets); sar_indep only accepts a decoded payload. Is the bytes interface a MUST?
- **Options:** (a) MUST for every gate; (b) MUST for gates that accept octets, SHOULD for executors; (c) informative.
- **Decision:** (b): SAR-REQ-071 applies to a gate that accepts the payload as octets; SAR-REQ-072 (SHOULD) asks the executor to transmit exactly those octets.
- **Rationale:** the requirement is about what is checked versus what is executed (paper §3.8). A gate that receives a decoded item cannot enforce it, so the obligation moves to the integration; making it a universal MUST would make sar_indep non-conforming for an interface choice that the original brief fixed.
- **Consequences:** the three vectors carry `"interfaces": ["payload_bytes"]` and are reported **n/a** (not pass) for sar_indep. No code change.

### ISS-005 Type of the evaluation instant
- **Discovered by:** writing Section 10; known difference (SEMANTICS.md "Clock type").
- **Question:** sar_cose denies a non-integer `now` (`invalid_clock`); sar_indep accepts finite floats. Which is normative?
- **Decision:** the evaluation instant is an integer number of seconds; an implementation MAY reject a non-integer instant. Not a MUST, no vector.
- **Rationale:** statements carry integer times; the gate's clock source is a deployment matter. Accepting a float compares correctly against integer bounds.
- **Consequences:** none in code. Recorded as an open interoperability point.

### ISS-006 Clock tolerance as a parameter
- **Discovered by:** writing Section 10.
- **Decision:** τ is a deployment parameter; implementations SHOULD make it configurable and MUST use the same value at the gate and offline. Vectors fix τ = 30 and say so (`"tau": 30`).
- **Consequences:** neither implementation exposes τ other than as a module constant (`MAX_CLOCK_SKEW`, `MAX_FUTURE_SKEW`). Not changed (SHOULD).

### ISS-007 Additional replay keys
- **Discovered by:** writing Section 11; sar_indep also consumes a key derived from the proposal's COSE bytes.
- **Decision:** an implementation MAY consume additional keys that are functions of the proposal alone; given SAR-REQ-032 they cannot cause additional denials.
- **Consequences:** none.

### ISS-008 Decision log format
- **Discovered by:** writing Section 13. The two implementations hash their chains differently (sar_cose `SHA-256(prev ‖ record)`, sar_indep `SHA-256(dcbor([seq, prev, record]))`) and only sar_cose signs checkpoints.
- **Decision:** recording every decision is a MUST (SAR-REQ-090); the log format is local; tamper evidence relative to an externally retained checkpoint and the rollback anchor are SHOULD (SAR-REQ-092, SAR-REQ-093), checked by implementation tests, not by vectors.
- **Rationale:** the log is not exchanged between parties in version 1; with Sections 15–18 the Transparency Service log is the interoperable one.
- **Consequences:** sar_indep does not meet SAR-REQ-092 (no checkpoint; gap test C10b) — recorded as "not-implemented" in the manifest, which is allowed for a SHOULD.

### ISS-009 Form of proposal_id
- **Discovered by:** writing SAR-REQ-032.
- **Question:** sar_indep additionally requires `proposal_id` to match 32 lowercase hex characters before comparing; sar_cose only compares with the recomputed value.
- **Decision:** equivalent: the recomputed value is always 32 lowercase hex characters, so any other form fails the comparison. The profile states the comparison only. Vector gate-041.

### ISS-010 Length of identifiers: code points or octets?
- **Discovered by:** writing the CDDL (`tstr .size` counts octets).
- **Question:** both implementations count `len(str)` (Unicode code points) up to 256. The CDDL control `.size` counts octets.
- **Options:** (a) code points (as implemented); (b) octets (change both implementations).
- **Decision:** (a). SAR-REQ-023 states code points; the CDDL bounds the octet length loosely (1..1024, the maximum for 256 code points in UTF-8) and says that the code-point limit is not expressible in CDDL.
- **Consequences:** vectors gate-004 (256 two-octet code points accepted), gate-005, gate-006, gate-042. No code change.

### ISS-011 Nonce types
- **Decision:** text or bytes; compared as deterministic CBOR values, so text "n1" and bytes h'6e31' differ (SAR-REQ-081). Both implementations already do this (sar_cose `dcbor(nonce)`; sar_indep `t:`/`b:` prefixes). Vector seq-114.

### ISS-012 S4 vectors must keep the quorum met
- **Discovered by:** the first draft of the vectors: a single faulty ratification is also "quorum not met", so it cannot distinguish an implementation that ignores invalid ratifications (forbidden by S4) from one that denies on them.
- **Decision:** every vector for a ratification fault presents a valid approval by ov-1 that alone meets quorum 1 plus the faulty ratification by ov-2 (`ratfault` in `gen_vectors.py`).

### ISS-013 Floats
- **Decision:** forbidden in statements and payloads (SAR-REQ-012), as in both implementations. Vectors dec-010..012, gate-024, gate-059b.

### ISS-014 Missing proposal
- **Question:** is a request without a proposal "invalid_statement" or "missing_evidence"?
- **Decision:** `missing_evidence` (both implementations report it so). Vector gate-106.
