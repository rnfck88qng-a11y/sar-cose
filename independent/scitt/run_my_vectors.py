"""Run the `scitt`, `registration` and `merkle` vectors of spec/test-vectors/
against sar_indep_scitt and print per-vector pass/fail.

Usage: PYTHONDONTWRITEBYTECODE=1 python run_my_vectors.py [-v]
Exit status 0 iff every vector passes.
"""
from __future__ import annotations

import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import sar_indep as core  # noqa: E402
import sar_indep_scitt as S  # noqa: E402

VEC_DIR = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "spec", "test-vectors")
VERBOSE = "-v" in sys.argv


def _stmt(hexstr):
    """Hand the gate a sar_indep statement dict (the fixed interface); if the
    octets do not even parse, hand it the octets so that it classifies them."""
    if hexstr is None:
        return None
    b = bytes.fromhex(hexstr)
    try:
        return core.from_cose(b)
    except Exception:  # noqa: BLE001
        return b


def _log_count(store) -> int:
    return store.db.execute("SELECT COUNT(*) FROM log").fetchone()[0]


def run_scitt(v):
    ins, exp = v["inputs"], v["expected"]
    problems = []
    for key in ("restart_before", "log_fails"):
        if any(key in s for s in ins["steps"]):
            problems.append(f"step option {key} not supported by this runner")
    store = core.Store()
    policy = ins["policy"]
    gate = S.ReceiptGate(policy, store, ins["trusted_logs"],
                         max_receipt_age=ins.get("max_receipt_age", 300))
    for i, (st, ex) in enumerate(zip(ins["steps"], exp["steps"])):
        if "policy" in st:
            gate.policy = st["policy"]
        try:
            payload = core.dcbor_decode_strict(bytes.fromhex(st["payload_cbor"]))
        except Exception:  # noqa: BLE001
            payload = object()  # not encodable: the core denies payload_mismatch
        proposal = _stmt(st["proposal_cose"])
        rats = [_stmt(r) for r in st.get("ratifications_cose") or []]
        receipt = bytes.fromhex(st["receipt_cose"]) if st.get("receipt_cose") else None
        before = _log_count(store)
        allowed, reason = gate.authorize(payload, proposal, rats, receipt, st["now"])
        added = _log_count(store) - before
        want_allow = ex["decision"] == "ALLOW"
        if allowed != want_allow:
            problems.append(f"step {i}: got {'ALLOW' if allowed else 'DENY'} ({reason}), want {ex['decision']}")
            continue
        if not allowed:
            cls = reason.split(":", 1)[0]
            want = ex["deny_class"]
            want = want if isinstance(want, list) else [want]
            if cls not in want:
                problems.append(f"step {i}: deny class {cls!r} ({reason}), want {want}")
            if not reason.startswith(cls + ": "):
                problems.append(f"step {i}: reason does not start with '<class>: '")
        if ex.get("log_records_added") is not None and added != ex["log_records_added"]:
            problems.append(f"step {i}: {added} log records added, want {ex['log_records_added']}")
        # Extra check (not part of the vector): an allowed request with its
        # Receipt also passes offline TAR verification (SAR-REQ-139).
        if allowed and not S.verify_tar_offline(proposal, rats, receipt, gate.policy,
                                                ins["trusted_logs"]):
            problems.append(f"step {i}: ALLOW but verify_tar_offline is False")
        if VERBOSE:
            print(f"      step {i}: {'ALLOW' if allowed else reason}")
    return problems


def run_registration(v):
    ins, exp = v["inputs"], v["expected"]
    problems = []
    seed = bytes.fromhex(ins["keys"][ins["ts_key"]]["seed"])
    ts = S.TransparencyService(ins["log_id"], Ed25519PrivateKey.from_private_bytes(seed),
                               ins["policy"])
    for i, (st, ex) in enumerate(zip(ins["steps"], exp["steps"])):
        n_before = len(ts.entries)
        ok, reason, receipt = ts.register(bytes.fromhex(st["request_cbor"]), st["ts_time"])
        if VERBOSE:
            print(f"      step {i}: {reason}")
        if ok != ex["registered"]:
            problems.append(f"step {i}: registered={ok} ({reason}), want {ex['registered']}")
            continue
        if ok:
            idx, size = ex["leaf_index"], ex["tree_size"]
            if len(ts.entries) != n_before + 1:
                problems.append(f"step {i}: log grew by {len(ts.entries) - n_before}")
            if ts.entries[-1].hex() != ex["entry_cbor"]:
                problems.append(f"step {i}: entry differs")
            if len(ts.entries) - 1 != idx or len(ts.entries) != size:
                problems.append(f"step {i}: index/size {len(ts.entries) - 1}/{len(ts.entries)}, want {idx}/{size}")
            if S.merkle_root(ts.entries[:size]).hex() != ex["root"]:
                problems.append(f"step {i}: root differs")
            if receipt is None or receipt.hex() != ex["receipt_cose"]:
                problems.append(f"step {i}: receipt differs")
        else:
            if receipt is not None:
                problems.append(f"step {i}: refusal returned a receipt")
            if len(ts.entries) != n_before:
                problems.append(f"step {i}: refusal appended an entry")
            cls = reason.split(":", 1)[0]
            if cls != ex["refusal_class"]:
                problems.append(f"step {i}: refusal class {cls!r} ({reason}), want {ex['refusal_class']!r}")
            if not reason.startswith(cls + ": "):
                problems.append(f"step {i}: reason does not start with '<class>: '")
    return problems


def run_merkle(v):
    leaves = [bytes.fromhex(x) for x in v["inputs"]["leaves"]]
    exp = v["expected"]
    problems = []
    for size, root in exp["roots"].items():
        if S.merkle_root(leaves[:int(size)]).hex() != root:
            problems.append(f"root of size {size} differs")
    for inc in exp["inclusion"]:
        i, n = inc["index"], inc["size"]
        path = S.inclusion_proof(leaves, i, n)
        if [p.hex() for p in path] != inc["path"]:
            problems.append(f"inclusion path ({i},{n}) differs")
        root = bytes.fromhex(exp["roots"][str(n)])
        want_path = [bytes.fromhex(p) for p in inc["path"]]
        if not S.verify_inclusion(leaves[i], i, n, want_path, root):
            problems.append(f"inclusion ({i},{n}) does not verify")
        if S.verify_inclusion(leaves[i] + b"x", i, n, want_path, root):
            problems.append(f"inclusion ({i},{n}) verifies for the wrong leaf")
    for c in exp["consistency"]:
        m, n = c["m"], c["n"]
        proof = S.consistency_proof(leaves, m, n)
        if [p.hex() for p in proof] != c["proof"]:
            problems.append(f"consistency proof ({m},{n}) differs")
        rm, rn = bytes.fromhex(exp["roots"][str(m)]), bytes.fromhex(exp["roots"][str(n)])
        want = [bytes.fromhex(p) for p in c["proof"]]
        if not S.verify_consistency(m, n, rm, rn, want):
            problems.append(f"consistency ({m},{n}) does not verify")
        if m < n and S.verify_consistency(m, n, rn, rm, want):
            problems.append(f"consistency ({m},{n}) verifies with swapped roots")
    return problems


RUNNERS = {"scitt": run_scitt, "registration": run_registration, "merkle": run_merkle}


def main() -> int:
    files = sorted(glob.glob(os.path.join(VEC_DIR, "*.json")))
    total = failed = 0
    for f in files:
        if f.endswith("index.json"):
            continue
        with open(f, encoding="utf-8") as fh:
            v = json.load(fh)
        run = RUNNERS.get(v.get("kind"))
        if run is None:
            continue
        total += 1
        try:
            problems = run(v)
        except Exception as e:  # noqa: BLE001
            problems = [f"runner exception: {type(e).__name__}: {e}"]
        status = "PASS" if not problems else "FAIL"
        failed += bool(problems)
        print(f"{status}  {v['id']:<10} {v['kind']:<13} {v['description']}")
        for p in problems:
            print(f"        - {p}")
    print(f"\n{total - failed}/{total} vectors passed ({failed} failed)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
