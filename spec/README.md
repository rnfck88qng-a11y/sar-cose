# SAR profile: specification, CDDL, test vectors, conformance

| File | Contents |
|---|---|
| `sar-profile.md` | The normative profile (BCP 14). Requirements are `**SAR-REQ-nnn** (LEVEL)` paragraphs. |
| `sar-profile.cddl` | CDDL for statements, bodies, policy and the Transparent Authorization Record. |
| `cddl_check.py` | Parses the CDDL (subset implementation, see its docstring: no full CDDL tool was available) and checks every artifact in every vector against it. |
| `gen_vectors.py` | Generates `test-vectors/` deterministically. It imports neither implementation: own deterministic CBOR encoder, COSE built by hand, Ed25519 keys from the RFC 8032 §7.1 test seeds (checked against the published public keys). `--check` regenerates in memory and fails on any difference. |
| `test-vectors/*.json` | One vector per file; `index.json` lists them. |
| `run_vectors.py` | Runs all vectors against the implementations through thin adapters; writes `vector_results.json`. |
| `req_map.json` | Hand-maintained links requirement → CDDL rule and implementation tests. |
| `check_manifest.py` | Regenerates `conformance_manifest.csv/.json` from the profile, vectors, `req_map.json` and `vector_results.json`; fails if a MUST has no vector, a referenced test does not exist, or a status is `fail`. |
| `ISSUES.md` | Decision log (spec-first rule). |

## Vector format

Common fields: `id`, `description`, `requirements` (ids covered), `kind`.

- `kind: "encoding"`: `inputs.value` is a CBOR data item in typed JSON (`{"int": "decimal string"}`, `{"text": …}`, `{"bytes": hex}`, `{"bool": …}`, `{"null": true}`, `{"array": [...]}`, `{"map": [[k, v], ...]}`, `{"tag": n, "value": …}`); `expected.cbor` is the hex of its deterministic encoding.
- `kind: "decoding"`: `inputs.cbor` (hex) MUST be rejected by a strict deterministic decoder.
- `kind: "decision"`: `inputs.keys` (role → RFC 8032 seed, public key, source), `inputs.policy`, and `inputs.steps`, each with `payload_cbor` (hex of the payload octets), `proposal_cose` (hex of the COSE_Sign1, or null), `ratifications_cose` (list of hex), `now` (evaluation instant), and optionally `policy` (overrides), `restart_before` (reopen the replay store before this step), `log_fails` (the decision log fails during this step). All steps of a vector share one replay store. `tau` is the clock tolerance the expectations assume (30 s). `interfaces` lists optional interfaces the vector needs (`payload_bytes`: the gate accepts payload octets, SAR-REQ-071). `cddl_invalid` lists artifacts that are deliberately not CDDL-valid.
  `expected.steps[i]`: `decision` (ALLOW/DENY), `deny_class` (a class of profile §13.1, or a list of acceptable classes when one fault necessarily implies another), `log_records_added` (1, or null if not checked). `expected.offline`: result of offline verification of the first step's statements under `expected.offline.policy`, without and with evaluation instants `at`.
- `kind: "scitt"` (profile §15–18): see the profile.

Times: `T0 = 1760000000`. Keys: `agent-1` = RFC 8032 TEST 1, `ov-1` = TEST 2, `ov-2` = TEST 3, `ov-3` = TEST 1024, `ts-1` = TEST SHA(abc); `outsider`, `agent-2`, `ts-2` use seed = SHA-256 of an ASCII label given in the vector.
