"""Extended tests for sar_cose: differential testing against an independent model of the
specification, exhaustive bit-flip tests, fuzzing, deterministic-CBOR properties, exact time
boundaries, concurrency and persistence of replay protection.

    python3 -m unittest -v test_sar_properties      (needs: hypothesis)
"""
import os
import random
import tempfile
import threading
import unittest

import cbor2
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import sar_cose as S

NOW = 1_800_000_000
SKEW = S.MAX_CLOCK_SKEW
PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00"}
HSET = settings(deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])

KEYS = {name: S.new_keypair() for name in ("agent-1", "agent-x", "ov-1", "ov-2", "ov-3", "ov-x")}


def _policy(quorum):
    return {"policy_id": "p1", "quorum": quorum,
            "authorized_agents": {"agent-1": KEYS["agent-1"][1]},
            "authorized_overseers": {o: KEYS[o][1] for o in ("ov-1", "ov-2", "ov-3")}}


def _break_sig(stmt):
    s = bytearray(bytes.fromhex(stmt["sig"]))
    s[0] ^= 0x01
    return dict(stmt, sig=s.hex())


# ------------------------------------------------------------------ independent model of the spec

def model_allows(sc):
    """SARWP v1.1 sections 4.5-4.10 written as a plain rule list, independent of sar_cose's code.
    Returns True iff the gate must allow the action."""
    issued = NOW + sc["issued_off"]
    if not sc["policy_ok"] or not sc["agent_ok"] or not sc["psig_ok"]:
        return False
    if NOW > issued + sc["ttl"] or issued > NOW + SKEW:
        return False
    if not sc["rats"]:
        return False
    approvers = set()
    for r in sc["rats"]:
        reviewed = NOW + r["rev_off"]
        if r["overseer"] == "ov-x" or not r["sig_ok"] or not r["bound"]:
            return False
        if reviewed > NOW + SKEW or reviewed < issued:
            return False
        if r["verdict"] not in ("APPROVED", "REJECTED") or r["verdict"] == "REJECTED":
            return False
        if NOW <= reviewed + r["ttl"]:
            approvers.add(r["overseer"])
    if len(approvers) < sc["quorum"]:
        return False
    return sc["payload_ok"]


def random_scenario(rng):
    p = 0.95  # bias towards valid components so that both outcomes occur often
    return {
        "quorum": rng.choice([1, 1, 2, 3]),
        "issued_off": rng.choice([-500, -60, -1, 0, 0, 0, 0, 30, 31, 200]),
        "ttl": rng.choice([10, 100, 1000, 1000]),
        "policy_ok": rng.random() < p, "agent_ok": rng.random() < p, "psig_ok": rng.random() < p,
        "payload_ok": rng.random() < p,
        "rats": [{
            "overseer": rng.choice(["ov-1", "ov-2", "ov-3"] * 4 + ["ov-x"]),
            "verdict": rng.choice(["APPROVED"] * 12 + ["REJECTED", "MAYBE"]),
            "rev_off": rng.choice([-1000, -500, -1, 0, 0, 0, 0, 30, 31]),
            "ttl": rng.choice([5, 1000, 1000]),
            "bound": rng.random() < 0.95, "sig_ok": rng.random() < 0.95,
        } for _ in range(rng.choice([0, 1, 1, 1, 2, 2, 3, 4]))],
    }


FAULTS = ["policy", "agent", "psig", "payload", "expired", "future_proposal", "no_rats", "rat_unauthorized",
          "rat_sig", "rat_unbound", "rat_rejected", "rat_unknown_verdict", "rat_future", "rat_before_proposal",
          "rat_expired", "duplicate_overseer"]


def single_fault_scenario(rng):
    """A valid scenario (quorum met by distinct, valid approvals) with at most one injected fault."""
    q = rng.choice([1, 2, 3])
    overseers = rng.sample(["ov-1", "ov-2", "ov-3"], q)
    sc = {"quorum": q, "issued_off": -10, "ttl": 1000, "policy_ok": True, "agent_ok": True, "psig_ok": True,
          "payload_ok": True,
          "rats": [{"overseer": o, "verdict": "APPROVED", "rev_off": -5, "ttl": 1000, "bound": True, "sig_ok": True}
                   for o in overseers]}
    fault = rng.choice(FAULTS + [None] * 6)
    r = rng.choice(sc["rats"])
    if fault in ("policy", "agent", "psig", "payload"):
        sc[{"policy": "policy_ok", "agent": "agent_ok", "psig": "psig_ok", "payload": "payload_ok"}[fault]] = False
    elif fault == "expired":
        sc["issued_off"], sc["ttl"] = -2000, 1000
        for x in sc["rats"]:
            x["rev_off"] = -1500
    elif fault == "future_proposal":
        sc["issued_off"] = SKEW + 1
        for x in sc["rats"]:
            x["rev_off"] = SKEW + 1
    elif fault == "no_rats":
        sc["rats"] = []
    elif fault == "rat_unauthorized":
        r["overseer"] = "ov-x"
    elif fault == "rat_sig":
        r["sig_ok"] = False
    elif fault == "rat_unbound":
        r["bound"] = False
    elif fault == "rat_rejected":
        r["verdict"] = "REJECTED"
    elif fault == "rat_unknown_verdict":
        r["verdict"] = "MAYBE"
    elif fault == "rat_future":
        r["rev_off"] = SKEW + 1
    elif fault == "rat_before_proposal":
        r["rev_off"] = -11
    elif fault == "rat_expired":
        r["ttl"] = 1
    elif fault == "duplicate_overseer":
        sc["rats"].append(dict(sc["rats"][0]))
        if q > 1:
            sc["rats"].pop(1)  # replace a distinct approver by a duplicate of the first
    return sc, fault


def build_and_run(sc, nonce):
    issued = NOW + sc["issued_off"]
    agent = "agent-1" if sc["agent_ok"] else "agent-x"
    pid = "p1" if sc["policy_ok"] else "OTHER"
    prop = S.make_proposal(KEYS[agent][0], agent, PAYLOAD, ttl=sc["ttl"], nonce=nonce, policy_id=pid, now=issued)
    decoy = S.make_proposal(KEYS[agent][0], agent, PAYLOAD, ttl=sc["ttl"], nonce=nonce + "-decoy", policy_id=pid, now=issued)
    rats = []
    for r in sc["rats"]:
        x = S.ratify(KEYS[r["overseer"]][0], r["overseer"], prop if r["bound"] else decoy,
                     verdict=r["verdict"], ttl=r["ttl"], now=NOW + r["rev_off"])
        rats.append(x if r["sig_ok"] else _break_sig(x))
    if not sc["psig_ok"]:
        prop = _break_sig(prop)
    runtime = PAYLOAD if sc["payload_ok"] else dict(PAYLOAD, amount=5001)
    gate = S.Gate(_policy(sc["quorum"]), S.Store())
    first = gate.authorize(runtime, prop, rats, now=NOW)[0]
    second = gate.authorize(runtime, prop, rats, now=NOW)[0]
    return first, second, gate.store


class DifferentialTests(unittest.TestCase):
    def test_gate_matches_spec_model_single_fault_injection(self):
        rng = random.Random(4242)
        seen = {}
        for i in range(2000):
            sc, fault = single_fault_scenario(rng)
            first, second, _ = build_and_run(sc, nonce=f"s{i}")
            self.assertEqual(first, model_allows(sc), f"scenario {i} fault={fault}: {sc}")
            self.assertFalse(second)
            seen.setdefault(fault, [0, 0])[first] += 1
        self.assertEqual(set(seen) - {None}, set(FAULTS), "every fault type must be exercised")
        self.assertGreater(seen[None][1], 300)  # valid scenarios allowed
        for fault in ("policy", "agent", "psig", "payload", "expired", "future_proposal", "no_rats",
                      "rat_unauthorized", "rat_sig", "rat_unbound", "rat_rejected", "rat_unknown_verdict",
                      "rat_future", "rat_before_proposal"):
            self.assertEqual(seen[fault][1], 0, f"fault {fault} was allowed")
        print(f"\n    single-fault: " + ", ".join(f"{k or 'none'}={v[1]}/{sum(v)} allowed" for k, v in sorted(seen.items(), key=lambda kv: str(kv[0]))), end=" ")

    def test_gate_matches_spec_model_on_3000_random_scenarios(self):
        rng = random.Random(20261009)
        allowed = denied = 0
        for i in range(3000):
            sc = random_scenario(rng)
            first, second, store = build_and_run(sc, nonce=f"n{i}")
            expected = model_allows(sc)
            self.assertEqual(first, expected, f"scenario {i}: {sc}")
            self.assertFalse(second, f"scenario {i}: second presentation must never be allowed")
            self.assertTrue(store.verify_chain())
            allowed += first
            denied += not first
        print(f"\n    differential: {allowed} allowed, {denied} denied, 0 disagreements with the model", end=" ")
        self.assertGreater(allowed, 100, "too few allow cases for a meaningful comparison")
        self.assertGreater(denied, 300)

    @HSET
    @given(st.randoms(use_true_random=False))
    def test_gate_matches_spec_model_hypothesis(self, rng):
        sc = random_scenario(rng)
        first, second, _ = build_and_run(sc, nonce="h")
        self.assertEqual(first, model_allows(sc))
        self.assertFalse(second)


class BitFlipTests(unittest.TestCase):
    def test_every_single_bit_flip_in_signed_statements_is_rejected(self):
        policy = _policy(1)
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", PAYLOAD, now=NOW)
        rat = S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)
        checked = 0
        for which, stmt in (("proposal", prop), ("ratification", rat)):
            data = S.to_cose(stmt)
            for i in range(len(data)):
                for bit in range(8):
                    mutated = bytearray(data)
                    mutated[i] ^= 1 << bit
                    checked += 1
                    try:
                        parsed = S.from_cose(bytes(mutated))
                    except (ValueError, TypeError, cbor2.CBORDecodeError):
                        continue  # rejected at parse time
                    p2, r2 = (parsed, rat) if which == "proposal" else (prop, parsed)
                    gate = S.Gate(policy, S.Store())
                    self.assertFalse(gate.authorize(PAYLOAD, p2, [r2], now=NOW)[0],
                                     f"{which}: flip of bit {bit} in byte {i} was accepted")
        self.assertGreater(checked, 3000)
        self.assertTrue(S.Gate(policy, S.Store()).authorize(PAYLOAD, prop, [rat], now=NOW)[0])  # control


# ------------------------------------------------------------------ CBOR and payload properties

cbor_values = st.recursive(
    st.one_of(st.integers(min_value=-(2**64), max_value=2**64 - 1), st.text(max_size=30),
              st.binary(max_size=30), st.booleans(), st.none()),
    lambda children: st.one_of(st.lists(children, max_size=5),
                               st.dictionaries(st.one_of(st.text(max_size=10), st.integers(-1000, 1000)),
                                               children, max_size=5)),
    max_leaves=25)


def _keys_sorted(obj):
    if isinstance(obj, dict):
        enc = [S.dcbor(k) for k in obj]
        return enc == sorted(enc) and all(_keys_sorted(v) for v in obj.values())
    if isinstance(obj, list):
        return all(_keys_sorted(v) for v in obj)
    return True


class CborPropertyTests(unittest.TestCase):
    @HSET
    @given(cbor_values)
    def test_roundtrip_and_canonical_form(self, v):
        try:
            enc = S.dcbor(v)
        except ValueError:  # e.g. True/1 collide as dict keys in Python; not a CBOR concern
            return
        self.assertEqual(S.strict_loads(enc), cbor2.loads(enc))
        self.assertEqual(S.dcbor(cbor2.loads(enc)), enc)  # idempotent
        self.assertTrue(_keys_sorted(cbor2.loads(enc)))

    @HSET
    @given(st.binary(max_size=200))
    def test_parser_fails_safely_on_garbage(self, data):
        try:
            S.from_cose(data)
        except (ValueError, TypeError, cbor2.CBORDecodeError, RecursionError):
            pass

    @HSET
    @given(st.dictionaries(st.text(max_size=8), cbor_values, min_size=1, max_size=6), st.data())
    def test_any_change_to_payload_after_approval_is_denied(self, payload, data):
        try:
            S.dcbor(payload)
        except ValueError:
            return
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", payload, now=NOW)
        rats = [S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)]
        key = data.draw(st.sampled_from(sorted(payload)))
        op = data.draw(st.sampled_from(["change", "drop", "add"]))
        mutated = dict(payload)
        if op == "change":
            mutated[key] = data.draw(cbor_values)
        elif op == "drop":
            del mutated[key]
        else:
            mutated[key + "_extra"] = 0
        try:
            same = S.dcbor(mutated) == S.dcbor(payload)
        except ValueError:
            return
        gate = S.Gate(_policy(1), S.Store())
        self.assertEqual(gate.authorize(mutated, prop, rats, now=NOW)[0], same)

    @HSET
    @given(st.dictionaries(st.text(max_size=8), st.integers(-(2**64), 2**64 - 1), min_size=1, max_size=8),
           st.randoms(use_true_random=False))
    def test_map_insertion_order_does_not_matter(self, payload, rng):
        items = list(payload.items())
        rng.shuffle(items)
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", payload, now=NOW)
        rats = [S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)]
        self.assertTrue(S.Gate(_policy(1), S.Store()).authorize(dict(items), prop, rats, now=NOW)[0])

    def test_unicode_normalisation_is_not_applied(self):
        # NFC "é" vs NFD "e" + combining accent: different bytes, so a different action
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", {"payee": "Café"}, now=NOW)
        rats = [S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)]
        self.assertFalse(S.Gate(_policy(1), S.Store()).authorize({"payee": "Café"}, prop, rats, now=NOW)[0])

    @HSET
    @given(st.dictionaries(st.text(max_size=5), st.one_of(st.integers(), st.text()), max_size=4),
           st.dictionaries(st.text(max_size=5), st.one_of(st.integers(), st.text(), st.none()), max_size=6))
    def test_gate_never_raises_and_never_allows_junk_statements(self, junk_body, junk_other):
        junk_p = {"protected": S.dcbor({1: -19}), "body": junk_body, "sig": "00" * 64}
        for p, r in ((junk_p, [junk_p]), (junk_other, [junk_other]), ({"body": {}}, [{}])):
            allowed, _reason = S.Gate(_policy(1), S.Store()).authorize(PAYLOAD, p, r, now=NOW)
            self.assertFalse(allowed)


# ------------------------------------------------------------------ exact boundaries

class BoundaryTests(unittest.TestCase):
    def _run(self, issued, ttl, reviewed, rttl):
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", PAYLOAD, ttl=ttl, now=issued)
        rats = [S.ratify(KEYS["ov-1"][0], "ov-1", prop, ttl=rttl, now=reviewed)]
        return S.Gate(_policy(1), S.Store()).authorize(PAYLOAD, prop, rats, now=NOW)[0]

    def test_proposal_expiry_boundary(self):
        self.assertTrue(self._run(NOW - 100, 100, NOW - 50, 1000))   # now == expires_at
        self.assertFalse(self._run(NOW - 101, 100, NOW - 50, 1000))  # now == expires_at + 1

    def test_ratification_expiry_boundary(self):
        self.assertTrue(self._run(NOW - 100, 1000, NOW - 50, 50))    # now == valid_until
        self.assertFalse(self._run(NOW - 100, 1000, NOW - 50, 49))   # now == valid_until + 1

    def test_clock_skew_boundary(self):
        self.assertTrue(self._run(NOW + SKEW, 100, NOW + SKEW, 100))
        self.assertFalse(self._run(NOW + SKEW + 1, 100, NOW + SKEW + 1, 100))

    def test_review_not_before_proposal_boundary(self):
        self.assertTrue(self._run(NOW - 100, 1000, NOW - 100, 1000))   # reviewed == issued
        self.assertFalse(self._run(NOW - 100, 1000, NOW - 101, 1000))  # reviewed == issued - 1


# ------------------------------------------------------------------ concurrency and persistence

class StoreConcurrencyTests(unittest.TestCase):
    def test_concurrent_presentations_allow_exactly_once(self):
        prop_rats = []
        for round_ in range(5):
            prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", PAYLOAD, nonce=f"c{round_}", now=NOW)
            prop_rats.append((prop, [S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)]))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            S.Store(path).db.close()
            for prop, rats in prop_rats:
                results, barrier = [], threading.Barrier(16)

                def worker():
                    store = S.Store(path)  # one connection per gate instance, shared database file
                    gate = S.Gate(_policy(1), store)
                    barrier.wait()
                    results.append(gate.authorize(PAYLOAD, prop, rats, now=NOW))
                    store.db.close()

                threads = [threading.Thread(target=worker) for _ in range(16)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                self.assertEqual(sum(ok for ok, _ in results), 1, results)
                self.assertTrue(all(reason in ("ok", "replay") for _, reason in results), results)
            check = S.Store(path)
            self.assertTrue(check.verify_links())
            allows = check.db.execute("select count(*) from log where record like '%\"ALLOW\"%'").fetchone()[0]
            self.assertEqual(allows, 5)

    def test_replay_protection_survives_restart(self):
        prop = S.make_proposal(KEYS["agent-1"][0], "agent-1", PAYLOAD, now=NOW)
        rats = [S.ratify(KEYS["ov-1"][0], "ov-1", prop, now=NOW)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s1 = S.Store(path)
            self.assertTrue(S.Gate(_policy(1), s1).authorize(PAYLOAD, prop, rats, now=NOW)[0])
            s1.db.close()
            s2 = S.Store(path)
            self.assertEqual(S.Gate(_policy(1), s2).authorize(PAYLOAD, prop, rats, now=NOW), (False, "replay"))
            self.assertTrue(s2.verify_links())


if __name__ == "__main__":
    unittest.main()
