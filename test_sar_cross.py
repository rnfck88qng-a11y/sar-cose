"""Cross-implementation tests: sar_cose vs the implementation written blind from the paper
(independent/sar_indep.py). Both must produce byte-identical artifacts and, on identical inputs,
identical gate decisions and offline-verification results (SEMANTICS.md).

    python3 -m unittest -v test_sar_cross        (SAR_DEEP=1 for 10x scenarios; SAR_SEEDS=a,b,c)
"""
import os
import pathlib
import random
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "independent"))
import sar_cose as A  # noqa: E402
import sar_indep as B  # noqa: E402
import test_sar_properties as T  # noqa: E402  (scenario generators and fixed keys)

NOW = T.NOW
N = 15000 if T.DEEP else 1500


def build(sc, nonce, maker):
    K = T.KEYS
    issued = NOW + sc["issued_off"]
    agent = "agent-1" if sc["agent_ok"] else "agent-x"
    pid = "p1" if sc["policy_ok"] else "OTHER"
    prop = maker.make_proposal(K[agent][0], agent, T.PAYLOAD, ttl=sc["ttl"], nonce=nonce, policy_id=pid, now=issued)
    decoy = maker.make_proposal(K[agent][0], agent, T.PAYLOAD, ttl=sc["ttl"], nonce=nonce + "-d", policy_id=pid, now=issued)
    rats = []
    for r in sc["rats"]:
        x = maker.ratify(K[r["overseer"]][0], r["overseer"], prop if r["bound"] else decoy,
                         verdict=r["verdict"], ttl=r["ttl"], now=NOW + r["rev_off"])
        rats.append(x if r["sig_ok"] else T._break_sig(x))
    if not sc["psig_ok"]:
        prop = T._break_sig(prop)
    runtime = T.PAYLOAD if sc["payload_ok"] else dict(T.PAYLOAD, amount=5001)
    return prop, rats, runtime


def decide(impl, quorum, prop, rats, runtime):
    pol = T._policy(quorum)
    gate = impl.Gate(pol, impl.Store())
    first = gate.authorize(runtime, prop, rats, now=NOW)[0]
    second = gate.authorize(runtime, prop, rats, now=NOW)[0]
    return first, second, impl.verify_record_offline(prop, rats, pol)


class CrossImplementation(unittest.TestCase):
    def _compare(self, gen, label):
        disagreements, allowed, n = [], 0, 0
        for i in range(N):
            sc = gen()
            for maker in (A, B):
                prop, rats, runtime = build(sc, f"{label}{i}", maker)
                da = decide(A, sc["quorum"], prop, rats, runtime)
                db = decide(B, sc["quorum"], prop, rats, runtime)
                n += 1
                allowed += da[0]
                if da != db:
                    disagreements.append((maker.__name__, sc, da, db))
                self.assertEqual(da[0], T.model_allows(sc), f"sar_cose vs model: {sc}")
        self.assertEqual(disagreements, [], f"{len(disagreements)} disagreements; first: {disagreements[:1]}")
        print(f"\n    cross {label}: {n} decision pairs, {allowed} allowed, 0 disagreements", end=" ")

    def test_randomized_scenarios_agree(self):
        for seed in [7] + T.EXTRA_SEEDS:
            rng = random.Random(seed)
            self._compare(lambda: T.random_scenario(rng), f"random/seed{seed}")

    def test_single_fault_scenarios_agree(self):
        for seed in [8] + T.EXTRA_SEEDS:
            rng = random.Random(seed)
            self._compare(lambda: T.single_fault_scenario(rng)[0], f"fault/seed{seed}")

    def test_gate_offline_equivalence_in_both_implementations(self):
        """SEMANTICS.md S13 for each implementation: gate allows at t iff offline(at=t)."""
        n = 3000 if T.DEEP else 300
        for seed in [9] + T.EXTRA_SEEDS:
            rng = random.Random(seed)
            instants = 0
            for label, gen in (("random", lambda: T.random_scenario(rng)), ("fault", lambda: T.single_fault_scenario(rng)[0])):
                for i in range(n):
                    sc = gen()
                    for impl in (A, B):
                        bad, _ = T.gate_offline_disagreements(impl, sc, f"x{label}{i}")
                        self.assertEqual(bad, [], f"{impl.__name__} seed {seed} {label} {i}: {bad} for {sc}")
                    instants += len(T.boundary_instants(sc))
            print(f"\n    gate/offline equivalence, both implementations, seed={seed}: {2 * n} scenarios, "
                  f"{instants} instants each, 0 disagreements", end=" ")

    def test_artifacts_are_byte_identical(self):
        K = T.KEYS
        for ttl, nonce, now in ((60, "n1", NOW), (1, "x" * 256, 0), (10**6, "é", 2**40)):
            pa = A.make_proposal(K["agent-1"][0], "agent-1", T.PAYLOAD, ttl=ttl, nonce=nonce, now=now)
            pb = B.make_proposal(K["agent-1"][0], "agent-1", T.PAYLOAD, ttl=ttl, nonce=nonce, now=now)
            self.assertEqual(A.to_cose(pa), B.to_cose(pb))
            ra = A.ratify(K["ov-1"][0], "ov-1", pa, now=now)
            rb = B.ratify(K["ov-1"][0], "ov-1", pb, now=now)
            self.assertEqual(A.to_cose(ra), B.to_cose(rb))
            self.assertEqual(A.from_cose(B.to_cose(rb))["body"], rb["body"])
            self.assertEqual(B.from_cose(A.to_cose(ra))["body"], ra["body"])


if __name__ == "__main__":
    unittest.main()
