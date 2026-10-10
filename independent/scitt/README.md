# Independent SCITT implementation (profile Sections 15–18)

`sar_indep_scitt.py` implements the Transparency Service and Receipt-gated execution parts of the SAR profile. It was written by a separate instance of the same AI assistant (Claude), launched as a sub-agent, from the brief recorded in `BRIEF.md`. Its sources were the profile text, the CDDL, `spec/README.md`, `spec/ISSUES.md` and the published test vectors. It did not read the reference SCITT implementation or any of the files the brief excludes.

It builds on `../sar_indep.py`, the independent core implementation, which it does not modify. From the core it uses:
- deterministic CBOR (`dcbor`, `dcbor_decode_strict`);
- COSE statement parsing (`from_cose`, `to_cose`);
- policy validation;
- the shared evaluation of Sections 5–13 (`_evaluate`);
- the replay keys (`_replay_keys`);
- the hash-chained `Store`.

The following are new code, written here:
- the RFC 9162 Merkle tree and its inclusion and consistency proofs;
- the registration logic;
- the registration entry and `set_digest`;
- Receipt construction and verification;
- signed checkpoints;
- the Receipt-gated gate;
- offline verification of a Transparent Authorization Record.

`cbor2` is used in the tests only to inspect what was built. `cryptography` provides Ed25519.

## Interface

| Name | Profile |
|---|---|
| `merkle_root`, `inclusion_proof`, `verify_inclusion`, `consistency_proof`, `verify_consistency` | SAR-REQ-126–128, RFC 9162 §2.1 |
| `TransparencyService(log_id, signing_key, policy)`: `register(request_bytes, now) -> (ok, reason, receipt)`, `entries`, `root()`, `inclusion_proof()`, `consistency_proof()`, `checkpoint()` | §15–17, SAR-REQ-120–130 |
| `ReceiptGate(policy, store, trusted_logs, max_receipt_age=300)`: `authorize(payload, proposal, ratifications, receipt_bytes, now) -> (allowed, reason)` | §18, SAR-REQ-131–138 |
| `verify_tar_offline(proposal, ratifications, receipt_bytes, policy, trusted_logs) -> bool` | SAR-REQ-139 |
| helpers: `make_registration_request`, `registration_entry`, `set_digest`, `build_receipt`, `parse_receipt`, `verify_receipt`, `verify_checkpoint` | §15.1, §15.3, §17 |

Every denial or refusal reason is `<class>: <detail>`, where `<class>` is one of the §13.1 deny-reason classes.

## Run

```
PY=<venv>/bin/python
cd independent/scitt
PYTHONDONTWRITEBYTECODE=1 $PY -m unittest -v test_indep_scitt   # tests derived from the profile
PYTHONDONTWRITEBYTECODE=1 $PY run_my_vectors.py [-v]             # scitt, registration, merkle vectors
```

`DECISIONS.md` lists every interpretation choice (SD1–SD17) and the suspected gaps in the profile.
