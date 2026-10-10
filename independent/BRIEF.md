# Brief given to the blind implementation (verbatim record)

`sar_indep.py` was written by a separate instance of the AI assistant (Claude) from the brief below. That instance had no access to `sar_cose.py` or its tests. This file records exactly what it was given, so readers can judge how blind the implementation really was.

**What it saw:**
- the paper, **v1.1 source**, Sections 3 and 4.4–4.16 (Section 6 excluded);
- the original 12-test harness;
- the wire format and interface below.

The wire format goes beyond the paper. It fixes field names, header labels, content types and the binding digest so that the two implementations can exchange artifacts. Those choices therefore come from the reference implementation's author, not from the paper.

**Amendment after the blind phase:** see `DECISIONS.md` § "Amendments after the blind phase". The blind original is reconstructed in `original_blind/`.

---

> HARD RULES
> - Do NOT open, read, grep, cat, or import any of these (they are the other implementation and its tests): anything in `.../SARWP/sar-cose/` EXCEPT the subfolder `harness/` (you may read and run `harness/test_sar_conformance.py`; do not read `harness/sar_stub.py` beyond confirming it exists). Do not read `sar_cose.py`, `test_sar_*.py`, `README.md`, `RESULTS.md`, `bench.py`, any `claude-findings*` folder, or the GitHub repo rnfck88qng-a11y/sar-cose. Do not search the web for "sar-cose".
> - Write ONLY into the new folder `.../SARWP/sar-cose/independent/`.
> - You may use cbor2 for DECODING, but write your own deterministic encoder (RFC 8949 §4.2.1 core deterministic: shortest-form heads, definite lengths, map keys sorted by bytewise order of their encodings, reject duplicates; floats not allowed).
>
> SPECIFICATION (behaviour)
> Read the paper `SARWP_working_paper_v1.1.md`, sections 3 (threat model, requirements), 4.4–4.15 (payload, protocol objects, protocol phases, fail-closed semantics, forgery, payload substitution, replay, rejection, independent verification, invariants). Do NOT read section 6 (it describes the other implementation's choices). Derive the gate's allow/deny behaviour from sections 3–4. Where the paper is silent or ambiguous (examples: clock-skew tolerance for future-dated statements; whether a ratification may predate its proposal; whether an expired APPROVED ratification causes denial or simply does not count; how duplicate ratifications by one overseer count toward quorum; what counts as an invalid policy; treatment of unknown verdict strings; whether the policy_id inside statements must equal the gate's policy), make a reasoned choice and record EVERY such choice in `independent/DECISIONS.md` with the paper section that motivated it.
>
> WIRE FORMAT AND INTERFACE (fixed, so the two implementations can exchange artifacts — follow exactly)
> Module `independent/sar_indep.py` exposing:
> - `new_keypair() -> (Ed25519PrivateKey from the 'cryptography' package, public_key_raw_32_bytes.hex())`
> - A statement is a Python dict `{"protected": bytes, "body": dict, "sig": hex_string}` where:
>   - `protected` = deterministic CBOR of map `{1: alg, 3: content_type_text, 4: kid_bytes}`; alg = -19 (Ed25519, RFC 9864); kid = signer id encoded UTF-8.
>   - content types: proposals `"application/sar-proposal+cbor"`, ratifications `"application/sar-ratification+cbor"`.
>   - `sig` = hex of Ed25519 signature over deterministic CBOR of `["Signature1", protected, b"", dcbor(body)]` (COSE Sig_structure, RFC 9052 §4.4).
>   - COSE_Sign1 bytes of a statement = deterministic CBOR of tag 18 wrapping `[protected, {}, dcbor(body), sig_bytes]`.
> - `make_proposal(agent_priv, agent_id, payload, ttl=60, nonce="n1", policy_id="p1", now=None)`: body keys exactly: `v`=1, `agent_id`, `payload_digest` = SHA-256 bytes of dcbor(payload), `issued_at` = int(now or time.time()), `expires_at` = issued_at+ttl, `nonce`, `policy_id`, and `proposal_id` = first 32 hex chars of SHA-256(dcbor(body-without-proposal_id)). Signed with kid=agent_id, proposal content type.
> - `ratify(overseer_priv, overseer_id, proposal, verdict="APPROVED", ttl=60, now=None)`: body keys exactly: `v`=1, `proposal_digest` = SHA-256 bytes of the proposal's COSE_Sign1 bytes, `proposal_id` (copied), `overseer_id`, `verdict`, `reviewed_at`=int(now), `valid_until`=reviewed_at+ttl, `policy_id` (copied from proposal). Signed with kid=overseer_id, ratification content type.
> - `to_cose(stmt) -> bytes`, `from_cose(bytes) -> stmt` (strict: reject non-deterministic encodings and any unprotected header parameters).
> - Policy is a dict: `{"policy_id": str, "quorum": int, "authorized_agents": {id: pub_hex}, "authorized_overseers": {id: pub_hex}}`.
> - `Store(path=":memory:")` — SQLite-backed, append-only, hash-chained decision log + consumed-authorization tracking; method `verify_chain() -> bool`; must expose `.db` (sqlite3 connection) with a table named `log` having columns `seq`, `record` (text containing the word DENY or ALLOW for decisions), `prev`, `hash` (the harness tampers with it).
> - `Gate(policy, store)` with `.policy` attribute and `authorize(runtime_payload, proposal, ratifications, now=None) -> (bool, reason_str)`. Must never raise; fail closed.
> - `verify_record_offline(proposal, ratifications, policy) -> bool` — stateless verification that the artifacts constitute a valid authorization (paper §4.12).
>
> TESTS YOU MUST RUN AND REPORT
> 1. The original harness, unmodified.
> 2. Write your own tests in `independent/test_indep.py` derived from the paper (not from any other test file), run them, report.
>
> DELIVERABLES (in independent/): `sar_indep.py`, `test_indep.py`, `DECISIONS.md` (every ambiguity and your choice, with paper section), `README.md`.

(Absolute paths shortened to `...`, and the Python interpreter path omitted; nothing else changed.)
