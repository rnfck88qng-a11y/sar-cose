# Brief given to the second SCITT implementation (verbatim record)

`sar_indep_scitt.py` in this folder was written by a separate instance of the same AI assistant (Claude), launched as a sub-agent, from the brief below. This file records exactly what it was given, so that readers can judge how independent it is. The reference SCITT implementation (`sar_scitt.py`) was being written by the launching instance at the same time; the sub-agent was instructed not to read it, and compliance rests on that instruction (it cannot be checked from version control).

---

> You are writing an independent implementation of the Transparency Service and Receipt-gated execution parts of a normative profile, from the profile text alone.
>
> REPOSITORY: `<V>/sar-cose` (V = the SARWP folder).
>
> HARD RULES
> - Do NOT open, read, grep, cat, import or otherwise inspect: `sar_scitt.py`, `test_sar_scitt.py`, `sar_cose.py`, any `test_sar_*.py`, `spec/gen_vectors.py`, `spec/run_vectors.py`, `spec/check_manifest.py`, anything under `tools/`, `results/`, `RESULTS.md`, `README.md` at the repository root, `CHANGES*.md`, any paper file, and the git history (`git log -p`, `git show`, etc.). These contain or describe the other implementation.
> - You MAY read: `spec/sar-profile.md` (normative; Sections 15–18 are your main source, Sections 5–13 the core rules), `spec/sar-profile.cddl`, `spec/README.md` (vector format), `spec/ISSUES.md`, every file in `spec/test-vectors/`, and everything in `independent/` outside `independent/scitt/` that already exists (`sar_indep.py` is the core implementation you build on; its `DECISIONS.md`). You may read RFC 9162, RFC 9942, RFC 9943, RFC 9597, RFC 8392, RFC 9052 online.
> - Write ONLY into `independent/scitt/`. Do not modify `independent/sar_indep.py` or anything outside `independent/scitt/`.
> - Do not change the profile. If the profile is ambiguous or seems wrong, make a reasoned choice, record it in `independent/scitt/DECISIONS.md` (with the profile section), and report it; do not edit `spec/`.
> - Write your own Merkle tree (RFC 9162 §2.1), your own Receipt construction and verification, your own registration logic. Use `sar_indep` (import it from `independent/`) for deterministic CBOR, COSE parsing and the core gate and offline checks; use `cbor2` only for decoding and `cryptography` for Ed25519.
> - Python: `<scratchpad>/sarvenv/bin/python`; always set `PYTHONDONTWRITEBYTECODE=1`; delete any `.hypothesis` directories you create. No network installs.
>
> INTERFACE (fixed so that a test-vector runner can drive it) — module `independent/scitt/sar_indep_scitt.py`:
> - `merkle_root(leaves: list[bytes]) -> bytes`; `inclusion_proof(leaves, index, size) -> list[bytes]`; `verify_inclusion(leaf_data, index, size, path, root) -> bool`; `consistency_proof(leaves, m, n) -> list[bytes]`; `verify_consistency(m, n, root_m, root_n, proof) -> bool`.
> - `class TransparencyService(log_id: str, signing_key: Ed25519PrivateKey, policy: dict)` with `register(request_bytes: bytes, now: int) -> (ok: bool, reason: str, receipt_bytes: bytes | None)` and an attribute `entries: list[bytes]` (the leaf data, in order). `request_bytes` is a `registration-request` (profile §15.1). `now` is the TS clock.
> - `class ReceiptGate(policy: dict, store, trusted_logs: dict[str, str], max_receipt_age: int = 300)` (store: a `sar_indep.Store`) with `authorize(runtime_payload, proposal, ratifications, receipt_bytes, now) -> (allowed: bool, reason: str)`. Statements are `sar_indep` statement dicts; `receipt_bytes` may be None.
> - `verify_tar_offline(proposal, ratifications, receipt_bytes, policy, trusted_logs) -> bool` (SAR-REQ-139).
> - Every denial or refusal reason MUST start with the profile's deny-reason class (§13.1) followed by `": "`, e.g. `"receipt_invalid: inclusion proof does not verify"`.
>
> TESTS: write `independent/scitt/test_indep_scitt.py` derived from the profile (not from any other test file); and write `independent/scitt/run_my_vectors.py` that runs the `scitt`, `registration` and `merkle` vectors in `spec/test-vectors/` against your module and prints per-vector pass/fail. Report both results.
>
> DELIVERABLES in `independent/scitt/`: `sar_indep_scitt.py`, `test_indep_scitt.py`, `run_my_vectors.py`, `DECISIONS.md` (every ambiguity and your choice), `README.md`. Final report: what you built, vector results, test results, every ambiguity or suspected error in the profile, and confirmation that you did not read the forbidden files.

---

(`<V>` and `<scratchpad>` stand for absolute paths that were given in full; nothing else changed.)
