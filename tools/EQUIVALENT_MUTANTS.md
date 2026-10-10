# Surviving automated mutants: equivalence arguments

`tools/mutation_sweep.py` mutates `sar_cose.py` mechanically and runs the full suite against each mutant. Every surviving mutant is either a missing test or semantically **equivalent**: no input can make it behave differently from the original.

The mutants below survive and are argued equivalent. Each argument is a claim that can be attacked. If you find an input that distinguishes a mutant from the original, that is a bug report.

| Line | Mutation | Why it is equivalent |
|---|---|---|
| `_head`: `if n < 0: raise` | delete | `_head` is only called with lengths, tags and non-negative integers (`dcbor` maps negatives to `-1 - n`), so `n < 0` is unreachable. |
| `dcbor`: final `raise TypeError` | delete | The function then returns `None` for an unsupported type, and the caller's `b"".join` or `+` raises `TypeError` instead. The same exception type is raised for the same inputs. |
| `from_cose`: 4-element array check | delete; `and`→`or` | Without the check, the 4-way unpack on the next line raises `ValueError` (wrong length) or `TypeError` (not iterable), and both are rejected the same way. With `or`, a list of wrong length passes the check and then fails the unpack. |
| `_uint`: `x < 2**64` → `x <= 2**64` | cmp | 2⁶⁴ cannot occur: it has no CBOR major-type-0 encoding, so `dcbor` refuses to sign it and `strict_loads` can never produce it. |
| `proposal_shape_ok`: `issued_at < expires_at` → `<=` | cmp | A proposal with `issued_at == expires_at` can never be authorized or verified: S3 needs a ratification with `issued_at <= reviewed_at < expires_at`, which is impossible, and the gate denies first on expiry (`now < expires_at`) or on the review window. |
| `policy_valid`: `except … return False` | `return True` | Unreachable. `set(policy) != POLICY_KEYS` returns early for missing keys; all ids and keys are type-checked before `set()` and `&` are applied; values are strings. Nothing in the `try` can raise `KeyError`, `TypeError` or `AttributeError` once the earlier checks have passed. |
| `_canon_json`: `sort_keys=True` → `False` | const | Affects only the text of log records, which are written and hashed by the same code. Chain verification hashes the stored text, so the order of keys is not observable. |
| `_authorize`: proposal future-date check | delete | Implied. S3 requires every ratification to have `reviewed_at >= issued_at`, and the ratification future check requires `reviewed_at <= now + SKEW`. A proposal with `issued_at > now + SKEW` therefore always fails the ratification check, and with no ratifications the gate denies earlier. |
| `_authorize`: `now == expires_at` inside `MUT == "inclusive_expiry" and …` | cmp | Only evaluated when the hand-written mutant `inclusive_expiry` is active. It is part of the test hook, not the implementation. |
| `_authorize`: `reviewed_at >= expires_at` → `>` | cmp | Implied by S13: a ratification with `reviewed_at == expires_at` makes the common window start at `>= expires_at` and end at `<= expires_at`, so it is empty and the gate denies with `no_common_validity`. |
| `verify_record_offline`: `reviewed_at < expires_at` → `<=` | cmp | Same as above: the empty common interval rejects it. |

The checks that are redundant here are kept on purpose. Each gives a specific denial reason and guards against future changes that remove the rule implying it.
