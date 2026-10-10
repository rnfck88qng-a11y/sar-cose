"""Indicative micro-benchmark for sar_cose (single process, single thread). Not a performance
evaluation: it only shows the order of magnitude of the cryptographic and storage overhead.

Two baselines show the marginal cost of SAR over a conventional approval flag:
  - an unsigned approval flag looked up in memory (no signature, no payload binding, no log);
  - the same flag kept in a file-backed SQLite table, with an exact payload comparison and a
    consumed-flag update in one transaction (no signatures, no hash chain).

    python3 bench.py [N]
"""
import json
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import time

import sar_cose as S
import sar_scitt as X

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
    approved = {p["body"]["proposal_id"]: True for p in props}
    rows.append(("baseline: unsigned flag, in memory", *timed(lambda i: approved.get(props[i]["body"]["proposal_id"]) is True, N)))
    gate = S.Gate(policy, S.Store())
    rows.append(("Gate.authorize, in-memory store", *timed(lambda i: gate.authorize(PAYLOAD, props[i], rats[i]), N)))
    gate_b = S.Gate(policy, S.Store())
    pbytes = S.dcbor(PAYLOAD)
    rows.append(("Gate.authorize_bytes, in-memory store", *timed(lambda i: gate_b.authorize_bytes(pbytes, props[i], rats[i]), N)))
    # SCITT: registration at an in-memory Transparency Service (policy evaluation, Merkle append,
    # Receipt signature), receipt-gated authorization, and offline TAR verification
    now = props[0]["body"]["issued_at"] + 1
    ts = X.TransparencyService("log-1", None, policy)
    reqs = [X.make_request("authorization", "p1", props[i], rats[i]) for i in range(N)]
    receipts = [None] * N

    def reg(i):
        receipts[i] = ts.register(reqs[i], now=now).receipt
    rows.append((f"TS.register (log grows to {N})", *timed(reg, N)))
    rgate = X.ReceiptGate(policy, S.Store(), {"log-1": ts.public_key})
    rows.append(("ReceiptGate.authorize_bytes, in-memory", *timed(
        lambda i: rgate.authorize_bytes(pbytes, props[i], rats[i], receipts[i], now=now + 1), N)))
    rows.append(("verify_tar_offline", *timed(
        lambda i: X.verify_tar_offline(props[i], rats[i], receipts[i], policy, {"log-1": ts.public_key}), N)))
    with tempfile.TemporaryDirectory() as d:
        flags = sqlite3.connect(os.path.join(d, "flags.db"), isolation_level=None)
        flags.execute("create table approval(pid text primary key, payload text, approved int, consumed int)")
        flags.executemany("insert into approval values(?,?,1,0)",
                          [(p["body"]["proposal_id"], json.dumps(PAYLOAD, sort_keys=True)) for p in props])

        def flag_check(i):
            pid = props[i]["body"]["proposal_id"]
            flags.execute("BEGIN IMMEDIATE")
            row = flags.execute("select payload, approved, consumed from approval where pid=?", (pid,)).fetchone()
            ok = row is not None and row[1] == 1 and row[2] == 0 and row[0] == json.dumps(PAYLOAD, sort_keys=True)
            if ok:
                flags.execute("update approval set consumed=1 where pid=?", (pid,))
            flags.execute("COMMIT")
            return ok

        rows.append(("baseline: unsigned flag, file-backed", *timed(flag_check, N)))
        flags.close()
        gate_f = S.Gate(policy, S.Store(os.path.join(d, "bench.db")))
        rows.append(("Gate.authorize, file-backed store", *timed(lambda i: gate_f.authorize(PAYLOAD, props[i], rats[i]), N)))
        rgate_f = X.ReceiptGate(policy, S.Store(os.path.join(d, "bench_r.db")), {"log-1": ts.public_key})
        rows.append(("ReceiptGate.authorize_bytes, file-backed", *timed(
            lambda i: rgate_f.authorize_bytes(pbytes, props[i], rats[i], receipts[i], now=now + 1), N)))
        rows.append(("Store.verify_chain (N records)", *timed(lambda i: gate_f.store.verify_chain(), 5)))
    print(f"sar_cose micro-benchmark, N={N}, {platform.machine()} {platform.system()} {platform.release()}, "
          f"Python {platform.python_version()}, load average {' '.join(f'{x:.2f}' for x in os.getloadavg())}")
    print(f"{'operation':40s} {'median us':>10s} {'p99 us':>10s}")
    for name, med, p99 in rows:
        print(f"{name:40s} {med:10.1f} {p99:10.1f}")


if __name__ == "__main__":
    main()
