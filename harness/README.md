# harness/ (original conformance tests, unmodified)

These two files are the implementation-independent conformance harness written for the SARWP investigation brief *before* `sar_cose` existed. They are included verbatim so the repository is self-contained. They are not modified, and `sar_cose` is tested against them as they are.

| File | SHA-256 |
|---|---|
| `test_sar_conformance.py` | `834a6335875ded6a367207af4d7988c34bdb1dc1db4633b31c89384e12db5287` |
| `sar_stub.py` | `984cfacc38f8422a4a6865db9a447a7fab677169178f8e64d6c5c12b5955301d` |

- `test_sar_conformance.py` contains the 12 scenario tests from SARWP §6.4 (v1.0 numbering). It selects the implementation under test through `SAR_IMPL`.
- `sar_stub.py` is a deliberately simple illustrative implementation (Ed25519 over canonical JSON, not COSE). It exists only to show that tests can fail; `run_stub_against_gaps.sh` uses it to show that the gap tests detect real defects. **It is not the reference implementation.**
