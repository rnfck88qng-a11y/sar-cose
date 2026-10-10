# SAR independent implementation

`sar_indep.py` is a second implementation of the Sovereign Acceptance Runtime gate. It was written by a separate instance of the same AI assistant (Claude) from SARWP v1.1 §3 and §4.4–4.15 plus a fixed wire-format and interface specification that goes beyond the paper (`BRIEF.md` records it verbatim). Its author did not read the other implementation, its tests, its README or results, or paper §6. After the comparison it was amended twice (`DECISIONS.md`, end); the blind version is reconstructed in `original_blind/`.

The only file read from outside this folder was `harness/test_sar_conformance.py`. Its role was to confirm the interface, not to supply behaviour.

- `sar_indep.py`: own deterministic CBOR encoder (RFC 8949 §4.2.1; `cbor2` is used only for decoding), COSE_Sign1 with Ed25519 (alg -19), proposals and ratifications, a fail-closed `Gate`, a SQLite hash-chained `Store`, and `verify_record_offline`.
- `DECISIONS.md`: every point where the paper was silent or ambiguous, the choice made, and the paper section behind it.
- `test_indep.py`: tests derived from the paper and from DECISIONS.md.

Run:

```
PY=<venv>/bin/python
PYTHONDONTWRITEBYTECODE=1 $PY -m unittest -v test_indep
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD:$PWD/../harness" SAR_IMPL=sar_indep $PY -m unittest -v test_sar_conformance
```
