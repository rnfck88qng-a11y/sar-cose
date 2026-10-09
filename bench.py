"""Indicative micro-benchmark for sar_cose (single process, single thread). Not a performance
evaluation: it only shows the order of magnitude of the cryptographic and storage overhead.

    python3 bench.py [N]
"""
import os
import platform
import statistics
import sys
import tempfile
import time

import sar_cose as S

N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00"}


def timed(fn, n):
    samples = []
    for i in range(n):
        t0 = time.perf_counter()
        fn(i)
        samples.append((time.perf_counter() - t0) * 1e6)
    return statistics.median(samples), sorted(samples)[int(0.99 * n) - 1]


def main():
    ak, apub = S.new_keypair()
    ok, opub = S.new_keypair()
    policy = {"policy_id": "p1", "quorum": 1, "authorized_agents": {"agent-1": apub},
              "authorized_overseers": {"ov-1": opub}}
    props = [S.make_proposal(ak, "agent-1", PAYLOAD, nonce=f"n{i}", ttl=10**6) for i in range(N)]
    rats = [[S.ratify(ok, "ov-1", p, ttl=10**6)] for p in props]
    rows = []
    rows.append(("make_proposal (sign)", *timed(lambda i: S.make_proposal(ak, "agent-1", PAYLOAD, nonce=f"x{i}"), N)))
    rows.append(("ratify (sign)", *timed(lambda i: S.ratify(ok, "ov-1", props[i]), N)))
    rows.append(("verify_record_offline", *timed(lambda i: S.verify_record_offline(props[i], rats[i], policy), N)))
    gate = S.Gate(policy, S.Store())
    rows.append(("Gate.authorize, in-memory store", *timed(lambda i: gate.authorize(PAYLOAD, props[i], rats[i]), N)))
    with tempfile.TemporaryDirectory() as d:
        gate_f = S.Gate(policy, S.Store(os.path.join(d, "bench.db")))
        rows.append(("Gate.authorize, file-backed store", *timed(lambda i: gate_f.authorize(PAYLOAD, props[i], rats[i]), N)))
        rows.append(("Store.verify_chain (N records)", *timed(lambda i: gate_f.store.verify_chain(), 5)))
    print(f"sar_cose micro-benchmark, N={N}, {platform.machine()} {platform.system()} {platform.release()}, "
          f"Python {platform.python_version()}")
    print(f"{'operation':40s} {'median us':>10s} {'p99 us':>10s}")
    for name, med, p99 in rows:
        print(f"{name:40s} {med:10.1f} {p99:10.1f}")


if __name__ == "__main__":
    main()
