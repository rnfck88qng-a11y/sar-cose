"""Run the SAR profile test vectors against the implementations and report per-vector results.

    python3 spec/run_vectors.py [--impl sar_cose,sar_indep,...] [-v]

Implementations: sar_cose (reference), sar_indep (independent/; second implementation) and, for
the SCITT vectors of profile Sections 15-18, sar_scitt (reference). Each implementation is driven
through a thin adapter (below) that only translates between the vector format and the
implementation's own API: statements are parsed with the implementation's own from_cose, payloads
are handed to its gate, and its own reason strings are mapped onto the deny-reason classes of
profile Section 13.1. The adapter never decides an outcome itself, with one documented exception:
when the implementation's own from_cose rejects a statement, the vector's decision is recorded as
DENY / invalid_statement without invoking the gate (the gate API takes parsed statements), and the
log-record expectation is not checked for that step.

A vector that needs an interface an implementation does not offer (for example the exact-bytes
payload interface of SAR-REQ-071) is reported "n/a" for that implementation, never as a pass.

Writes spec/vector_results.json (no timestamps, so it is byte-stable for identical outcomes) and
exits 1 if any applicable vector fails on any selected implementation.
"""
import argparse
import contextlib
import importlib
import json
import pathlib
import re
import sqlite3
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
VEC = HERE / "test-vectors"
sys.path[:0] = [str(ROOT), str(ROOT / "independent")]


def from_json(j, tag_ctor):
    (k, v), = [(k, v) for k, v in j.items() if k != "value"] if "tag" not in j else [("tag", j["tag"])]
    if k == "int":
        return int(v)
    if k == "text":
        return v
    if k == "bytes":
        return bytes.fromhex(v)
    if k == "bool":
        return v
    if k == "null":
        return None
    if k == "array":
        return [from_json(x, tag_ctor) for x in v]
    if k == "map":
        return {from_json(a, tag_ctor): from_json(b, tag_ctor) for a, b in v}
    if k == "tag":
        return tag_ctor(v, from_json(j["value"], tag_ctor))
    raise ValueError(k)


# ------------------------------------------------------------------ adapters
class SarCose:
    name = "sar_cose"
    interfaces = {"payload_bytes"}
    CLASSES = {
        "policy_invalid": "policy_invalid", "missing_proposal": "missing_evidence",
        "missing_ratification": "missing_evidence", "malformed_proposal": "invalid_statement",
        "malformed_ratification": "invalid_statement", "proposal_id_mismatch": "invalid_statement",
        "bad_proposal": "invalid_statement", "bad_ratification": "invalid_statement",
        "unknown_verdict": "invalid_statement", "agent_not_authorized": "unauthorized_signer",
        "overseer_not_authorized": "unauthorized_signer", "policy_mismatch": "binding_mismatch",
        "ratification_not_bound": "binding_mismatch", "duplicate_ratification": "duplicate_ratification",
        "rejected": "rejected", "quorum_not_met": "quorum_not_met", "proposal_expired": "time_invalid",
        "proposal_from_future": "time_invalid", "ratification_time_invalid": "time_invalid",
        "ratification_expired": "time_invalid", "no_common_validity": "time_invalid",
        "payload_mismatch": "payload_mismatch", "payload_not_canonical": "payload_mismatch", "replay": "replay",
        "deny_unlogged": "store_failure", "store_inconsistent_with_anchor": "store_failure",
        "invalid_clock": "invalid_request",
    }

    def __init__(self):
        self.m = importlib.import_module("sar_cose")

    def encode(self, value):
        return self.m.dcbor(value)

    def tag(self, t, v):
        return self.m.cbor2.CBORTag(t, v)

    def strict_decode(self, b):
        return self.m.strict_loads(b)

    def from_cose(self, b):
        return self.m.from_cose(b)

    def store(self, path):
        return self.m.Store(path)

    def authorize(self, gate, payload_bytes, prop, rats, now):
        allowed, reason, _ = gate.authorize_bytes(payload_bytes, prop, rats, now=now)
        return allowed, reason

    def gate(self, policy, store):
        return self.m.Gate(policy, store)

    def offline(self, prop, rats, policy, at=None):
        return self.m.verify_record_offline(prop, rats, policy, at=at)

    @staticmethod
    def break_log(store):
        def fail(*a, **k):
            raise sqlite3.OperationalError("injected log failure")
        store._insert = fail

    @staticmethod
    def heal_log(store):
        store.__dict__.pop("_insert", None)

    def classify(self, reason):
        base = reason.split(":", 1)[0] if reason.startswith("malformed:") else reason
        if reason.startswith("malformed:"):
            return "invalid_statement"
        return self.CLASSES.get(base, "UNMAPPED:" + reason)


class SarIndep:
    name = "sar_indep"
    interfaces = set()  # authorize() takes a decoded payload only
    RULES = [
        (r"\(decision could not be logged\)", "store_failure"),
        (r"invalid policy", "policy_invalid"),
        (r"missing proposal|missing ratification", "missing_evidence"),
        (r"not authorized by policy", "unauthorized_signer"),
        (r"not bound to this proposal|proposal_id mismatch|policy_id does not match", "binding_mismatch"),
        (r"duplicate ratification", "duplicate_ratification"),
        (r"rejected by overseer", "rejected"),
        (r"insufficient quorum", "quorum_not_met"),
        (r"future-dated|expired|predates proposal|after proposal expiry|no instant at which", "time_invalid"),
        (r"payload digest mismatch|not canonically encodable|missing runtime payload", "payload_mismatch"),
        (r"^replay", "replay"),
        (r"decision log integrity", "store_failure"),
        (r"malformed|protected header|unsupported algorithm|wrong content type|unexpected or missing fields|"
         r"unsupported statement version|kid does not match|invalid signature|proposal_id is not derived|"
         r"unknown verdict|validity interval empty|ratification set too large|internal verification failure",
         "invalid_statement"),
        (r"invalid evaluation time", "invalid_request"),
    ]

    def __init__(self):
        self.m = importlib.import_module("sar_indep")

    def encode(self, value):
        return self.m.dcbor(value)

    def tag(self, t, v):
        return self.m.Tag(t, v)

    def strict_decode(self, b):
        return self.m.dcbor_decode_strict(b)

    def from_cose(self, b):
        return self.m.from_cose(b)

    def store(self, path):
        return self.m.Store(path)

    def authorize(self, gate, payload_bytes, prop, rats, now):
        payload = self.m.dcbor_decode_strict(payload_bytes)
        return gate.authorize(payload, prop, rats, now=now)

    def gate(self, policy, store):
        return self.m.Gate(policy, store)

    def offline(self, prop, rats, policy, at=None):
        return self.m.verify_record_offline(prop, rats, policy, at=at)

    @staticmethod
    def break_log(store):
        def fail(*a, **k):
            raise sqlite3.OperationalError("injected log failure")
        store._append = fail

    @staticmethod
    def heal_log(store):
        store.__dict__.pop("_append", None)

    def classify(self, reason):
        r = reason[len("DENY: "):] if reason.startswith("DENY: ") else reason
        for pat, cls in self.RULES:
            if re.search(pat, r):
                return cls
        return "UNMAPPED:" + reason


ADAPTERS = {"sar_cose": SarCose, "sar_indep": SarIndep}


# ------------------------------------------------------------------ runners
def run_encoding(ad, vec):
    value = from_json(vec["inputs"]["value"], ad.tag)
    got = ad.encode(value).hex()
    return got == vec["expected"]["cbor"], f"got {got}"


def run_decoding(ad, vec):
    try:
        ad.strict_decode(bytes.fromhex(vec["inputs"]["cbor"]))
    except Exception as e:  # noqa: BLE001
        return True, f"rejected ({type(e).__name__})"
    return False, "accepted"


def parse(ad, hexdata):
    if hexdata is None:
        return None, False
    try:
        return ad.from_cose(bytes.fromhex(hexdata)), False
    except Exception:  # noqa: BLE001
        return None, True


def log_count(store):
    return store.db.execute("select count(*) from log").fetchone()[0]


def run_decision(ad, vec):
    need = set(vec.get("interfaces", []))
    if not need <= ad.interfaces:
        return None, f"n/a (needs interface {sorted(need - ad.interfaces)})"
    inp, exp = vec["inputs"], vec["expected"]
    notes = []
    ok = True
    with tempfile.TemporaryDirectory() as d:
        path = str(pathlib.Path(d) / "store.db")
        store = ad.store(path)
        for i, (st, want) in enumerate(zip(inp["steps"], exp["steps"])):
            pol = st.get("policy", inp["policy"])
            if st.get("restart_before"):
                store.close()
                store = ad.store(path)
            gate = ad.gate(pol, store)
            prop, bad_p = parse(ad, st["proposal_cose"])
            rats, bad_r = [], False
            for h in st["ratifications_cose"]:
                r, b = parse(ad, h)
                rats.append(r)
                bad_r |= b
            if bad_p or bad_r:
                decision, cls, logged, reason = "DENY", "invalid_statement", None, "rejected by from_cose"
            else:
                before = log_count(store)
                if st.get("log_fails"):
                    ad.break_log(store)
                try:
                    allowed, reason = ad.authorize(gate, bytes.fromhex(st["payload_cbor"]), prop, rats, st["now"])
                finally:
                    ad.heal_log(store)
                decision = "ALLOW" if allowed else "DENY"
                cls = None if allowed else ad.classify(reason)
                logged = log_count(store) - before
            want_cls = want["deny_class"]
            cls_ok = (decision == "ALLOW") or (cls in want_cls if isinstance(want_cls, list) else cls == want_cls)
            log_ok = want["log_records_added"] is None or logged is None or logged == want["log_records_added"]
            if not (decision == want["decision"] and cls_ok and log_ok):
                ok = False
                notes.append(f"step {i}: got {decision}/{cls} ({reason}, log+{logged}); want {want['decision']}/"
                             f"{want_cls} log+{want['log_records_added']}")
        store.close()
    # offline verification on the first step's statements
    off = exp["offline"]
    st = inp["steps"][0]
    prop, bad_p = parse(ad, st["proposal_cose"])
    rats = [parse(ad, h) for h in st["ratifications_cose"]]
    unparsable = bad_p or any(b for _, b in rats) or prop is None
    rats = [r for r, _ in rats]
    got = False if unparsable else ad.offline(prop, rats, off["policy"])
    if got != off["result"]:
        ok = False
        notes.append(f"offline: got {got}, want {off['result']}")
    for a in off["at"]:
        got = False if unparsable else ad.offline(prop, rats, off["policy"], at=a["t"])
        if got != a["result"]:
            ok = False
            notes.append(f"offline(at={a['t']}): got {got}, want {a['result']}")
    return ok, "; ".join(notes)


RUNNERS = {"encoding": run_encoding, "decoding": run_decoding, "decision": run_decision}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", default=",".join(ADAPTERS))
    ap.add_argument("-v", action="store_true")
    ap.add_argument("--out", default=str(HERE / "vector_results.json"))
    a = ap.parse_args()
    vectors = [json.loads(p.read_text()) for p in sorted(VEC.glob("*.json")) if p.name != "index.json"]
    results = {}
    any_fail = False
    for name in a.impl.split(","):
        ad = ADAPTERS[name]()
        res = {}
        for vec in vectors:
            runner = getattr(ad, "run_" + vec["kind"], None) or RUNNERS.get(vec["kind"])
            if runner is None or vec["kind"] not in getattr(ad, "kinds", ("encoding", "decoding", "decision")):
                res[vec["id"]] = {"status": "n/a", "note": f"{name} does not implement {vec['kind']} vectors"}
                continue
            try:
                ok, note = runner(ad, vec)
            except Exception as e:  # noqa: BLE001
                ok, note = False, f"adapter/implementation raised {type(e).__name__}: {e}"
            status = "n/a" if ok is None else ("pass" if ok else "fail")
            res[vec["id"]] = {"status": status, "note": note} if status != "pass" or a.v else {"status": status}
            if status == "fail":
                any_fail = True
        results[name] = res
        c = {s: sum(1 for r in res.values() if r["status"] == s) for s in ("pass", "fail", "n/a")}
        print(f"{name}: {len(res)} vectors: pass {c['pass']}, fail {c['fail']}, n/a {c['n/a']}")
        for vid, r in res.items():
            if r["status"] == "fail" or (a.v and r["status"] == "n/a"):
                print(f"  {r['status'].upper():4s} {vid}: {r.get('note', '')}")
    summary = {"vectors": len(vectors), "results": results,
               "counts": {n: {s: sum(1 for r in res.values() if r["status"] == s) for s in ("pass", "fail", "n/a")}
                          for n, res in results.items()}}
    pathlib.Path(a.out).write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    sys.exit(1 if any_fail else 0)


if __name__ == "__main__":
    main()
