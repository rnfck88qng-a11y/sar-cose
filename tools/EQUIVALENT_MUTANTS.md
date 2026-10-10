# Surviving automated mutants: equivalence arguments

`tools/mutation_sweep.py` mutates `sar_cose.py` mechanically and runs the full suite against each mutant. Every surviving mutant is either a missing test or **decision-equivalent**: no input makes the gate, the offline verifier or the store decide differently from the original. For some survivors the denial *reason* or the exception type on an internal path may differ; the decision does not.

Last sweep (round 2 of v1.2): **476 of 491 mutants killed (96.9%), 15 survivors**, listed below (line numbers refer to that version of `sar_cose.py`). Each argument is a claim that can be attacked. If you find an input that distinguishes a mutant from the original in a decision, that is a bug report.

| Line | Mutation | Why it is decision-equivalent |
|---|---|---|
| 66 `_head`: `if n < 0: raise` | delete | `_head` is only called with lengths, tags and non-negative integers (`dcbor` maps negatives to `-1 - n`), so `n < 0` is unreachable. |
| 102 `dcbor`: final `raise TypeError` | delete | The function then returns `None` for an unsupported type, and the caller's `b"".join` or `+` raises `TypeError` instead. The same exception type is raised for the same inputs. |
| 159 `from_cose`: 4-element array check | delete; `and`→`or` (2 mutants) | Without the check, the 4-way unpack on the next line raises `ValueError` (wrong length) or `TypeError` (not iterable), and both are rejected the same way. With `or`, a list of wrong length passes the check and then fails the unpack. |
| 230 `_uint`: `x < 2**64` → `x <= 2**64` | cmp | 2⁶⁴ cannot occur: it has no CBOR major-type-0 encoding, so `dcbor` refuses to sign it and `strict_loads` can never produce it. |
| 285 `proposal_shape_ok`: `issued_at < expires_at` → `<=` | cmp | A proposal with `issued_at == expires_at` can never be authorized or verified: S3 needs a ratification with `issued_at <= reviewed_at < expires_at`, which is impossible. |
| 326 `policy_valid`: `except … return False` | `return True`; `False`→`True` (2 mutants) | For the `dict` policies the gate is given, nothing in the `try` can raise once the key-set check has passed: all ids and keys are type-checked before `set()` and `&` are applied. An external audit showed that the `except` *is* reachable for exotic `Mapping` types whose methods raise; with the mutant such a policy is reported valid, but every request under it is then denied when the gate indexes the policy (fail-closed `malformed:*` denial), and `verify_record_offline` returns False through its own `except`. Decision-equivalent; reason differs. |
| 330 `_canon_json`: `sort_keys=True` → `False` | const | Affects only the text of log records, which are written and hashed by the same code. Chain verification hashes the stored text, and `_check_anchor` parses records with `json.loads`, so the order of keys is not observable. |
| 368 `StaticAnchor.save`: `pass` | delete | The sweep replaces a deleted statement by `pass`, so this mutant is textually identical to the original. |
| 507 `consume_and_record`: `return None` | delete | A Python function without `return` returns `None`. |
| 623 `_authorize`: `now == expires_at` inside `MUT == "inclusive_expiry" and …` | cmp | Only evaluated when the hand-written mutant `inclusive_expiry` is active. It is part of the test hook, not the implementation. |
| 625 `_authorize`: proposal future-date check | delete | Implied. S3 requires every ratification to have `reviewed_at >= issued_at`, and the ratification future check requires `reviewed_at <= now + SKEW`. A proposal with `issued_at > now + SKEW` therefore always fails the ratification check, and with no ratifications the gate denies earlier. |
| 647 `_authorize`: `reviewed_at >= expires_at` → `>` | cmp | Implied by S13: a ratification with `reviewed_at == expires_at` makes the common interval start at `>= expires_at` and end at `<= expires_at`, so it is empty and the gate denies with `no_common_validity`. |
| 726 `verify_record_offline`: `reviewed_at < expires_at` → `<=` | cmp | Same as above: the empty common interval rejects it. |

The checks that are redundant here are kept on purpose. Each gives a specific denial reason and guards against future changes that remove the rule implying it.

## History

- v1.2 (first round): 431 of 444 killed, 13 survivors (the rows above except 368 and 507).
- v1.2 round 2, first sweep: 474 of 491 killed. Two further survivors revealed missing tests and were killed by `test_anchor_detects_a_modified_record_and_accepts_a_consistent_static_checkpoint`: `StaticAnchor.load` deleted (a static anchor was only ever tested in the refusing case) and `or`→`and` in the chain-link check of `_check_anchor` (a record rewritten with its old hash kept was not tested under an anchor).
- The 20 semantic mutants of the external audit are in `tools/audit_mutants.py`; all are killed (7 had survived the first-round suite).
