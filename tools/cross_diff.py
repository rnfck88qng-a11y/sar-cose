"""Cross-implementation differential: run sar_cose and the blind independent implementation
(independent/sar_indep.py) on identical artifacts and report every decision disagreement.

    python3 tools/cross_diff.py [N]
"""
import collections, pathlib, random, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "independent")]
import sar_cose as A
import sar_indep as B
import test_sar_properties as T  # scenario generators

N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
NOW = T.NOW

def build(sc, nonce, impl):
    K = T.KEYS
    issued = NOW + sc["issued_off"]
    agent = "agent-1" if sc["agent_ok"] else "agent-x"
    pid = "p1" if sc["policy_ok"] else "OTHER"
    prop = impl.make_proposal(K[agent][0], agent, T.PAYLOAD, ttl=sc["ttl"], nonce=nonce, policy_id=pid, now=issued)
    decoy = impl.make_proposal(K[agent][0], agent, T.PAYLOAD, ttl=sc["ttl"], nonce=nonce + "-d", policy_id=pid, now=issued)
    rats = []
    for r in sc["rats"]:
        x = impl.ratify(K[r["overseer"]][0], r["overseer"], prop if r["bound"] else decoy,
                        verdict=r["verdict"], ttl=r["ttl"], now=NOW + r["rev_off"])
        rats.append(x if r["sig_ok"] else T._break_sig(x))
    if not sc["psig_ok"]:
        prop = T._break_sig(prop)
    runtime = T.PAYLOAD if sc["payload_ok"] else dict(T.PAYLOAD, amount=5001)
    return prop, rats, runtime

def decide(impl, sc, prop, rats, runtime):
    pol = T._policy(sc["quorum"])
    g = impl.Gate(pol, impl.Store())
    return g.authorize(runtime, prop, rats, now=NOW), impl.verify_record_offline(prop, rats, pol)

def main():
    rng = random.Random(7)
    diffs = collections.Counter(); examples = {}; total = 0; wire_mismatch = 0
    gens = [("random", lambda: (T.random_scenario(rng), None)), ("fault", lambda: T.single_fault_scenario(rng))]
    for name, gen in gens:
        for i in range(N):
            sc, fault = gen()
            # artifacts built by A, decided by both; then built by B, decided by both
            for maker in (A, B):
                prop, rats, runtime = build(sc, f"{name}{i}", maker)
                (ga, ra), oa = decide(A, sc, prop, rats, runtime)
                (gb, rb), ob = decide(B, sc, prop, rats, runtime)
                total += 1
                if ga != gb or oa != ob:
                    key = (name, fault, "gate" if ga != gb else "offline", f"A={ga}/{ra}", f"B={gb}/{rb}")
                    diffs[key] += 1; examples.setdefault(key, sc)
            pa, _, _ = build(sc, f"w{i}", A); pb, _, _ = build(sc, f"w{i}", B)
            if sc["psig_ok"] and A.to_cose(pa) != B.to_cose(pb):
                wire_mismatch += 1
    print(f"decisions compared: {total}; byte-level wire mismatches between makers: {wire_mismatch}")
    print(f"disagreements: {sum(diffs.values())}")
    for k, v in diffs.most_common():
        print(f"  {v:5d}  {k}")

main()
