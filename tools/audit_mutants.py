"""Semantic mutants from the external audit of SARWP v1.2 (claude-investigation-brief/
deep-verification-v1.2/new_mutants/new_mutants.py, 20 mutants, 7 of which survived the v1.2
suite), with the replacement texts ported to the current sar_cose.py where the code has moved
(N02, N07, N09, N12, N15, N20). Each mutant is a list of exact (old, new) text replacements
applied to a copy of sar_cose.py; the full sar_cose suite is then run against it.

    python3 tools/audit_mutants.py [--jobs 12]

Prints KILLED or SURVIVED for each mutant. The repository itself is never modified.
"""
import argparse
import concurrent.futures as cf
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE = "test_sar_conformance test_sar_gaps test_sar_cose_specific test_sar_properties test_sar_hardening test_sar_cross test_sar_scitt".split()

MUTANTS = {'N01_future_skew_3600': [('MAX_CLOCK_SKEW = 30 ', 'MAX_CLOCK_SKEW = 3600 ')],
 'N02_nonce_casefold': [('keys.append(f\'nonce|{pol["policy_id"]}|{dcbor(nonce).hex()}\')',
                         'keys.append(f\'nonce|{pol["policy_id"]}|{dcbor(nonce.lower() if isinstance(nonce, str) else '
                         "nonce).hex()}')")],
 'N03_agent_overseer_same_identity_allowed': [('if set(agents) & set(overseers) or set(agents.values()) & set(okeys):',
                                               'if set(agents.values()) & set(okeys):')],
 'N04_quorum_off_by_one': [('if count < pol["quorum"]:', 'if count < pol["quorum"] - 1:')],
 'N05_checkpoint_signature_not_verified': [('            '
                                            'Ed25519PublicKey.from_public_bytes(bytes.fromhex(checkpoint_key or '
                                            'self.checkpoint_key)).verify(\n'
                                            '                bytes.fromhex(cp["sig"]), dcbor(["sar-checkpoint", '
                                            'cp["size"], cp["head"]]))',
                                            '            cp["sig"]')],
 'N06_digest_alg_sha3': [('def payload_digest(payload):\n    return H(dcbor(payload))',
                          'def payload_digest(payload):\n    return hashlib.sha3_256(dcbor(payload)).digest()')],
 'N07_digest_compare_truncated_8B': [('    return a == b\n', '    return a[:8] == b[:8]\n')],
 'N08_policy_unknown_keys_accepted': [('set(policy) != POLICY_KEYS', 'not POLICY_KEYS <= set(policy)')],
 'N09_replay_key_includes_time': [('keys = [f\'pid|{pol["policy_id"]}|{pid}\']',
                                   'keys = [f\'pid|{pol["policy_id"]}|{pid}|{now}\']'),
                                  ('keys.append(f\'nonce|{pol["policy_id"]}|{dcbor(nonce).hex()}\')',
                                   'keys.append(f\'nonce|{pol["policy_id"]}|{dcbor(nonce).hex()}|{now}\')'),
                                  ('keys.append(f\'txn|{pol["policy_id"]}|{dcbor(runtime_payload["transaction_id"]).hex()}\')',
                                   'keys.append(f\'txn|{pol["policy_id"]}|{dcbor(runtime_payload["transaction_id"]).hex()}|{now}\')')],
 'N10_expired_ratification_ignored_not_denied': [('            if MUT != "skip_rat_expiry" and now >= '
                                                  'rb["valid_until"]:\n'
                                                  '                return self._deny("ratification_expired", pid)',
                                                  '            if MUT != "skip_rat_expiry" and now >= '
                                                  'rb["valid_until"]:\n'
                                                  '                continue')],
 'N11_offline_skips_agent_signature': [('if ap is None or not verify_statement(proposal, ap, CT_PROPOSAL, '
                                        'pb["agent_id"]):',
                                        'if ap is None:')],
 'N12_policy_binding_casefold': [('    return a != b\n', '    return a.lower() != b.lower()\n')],
 'N13_gate_accepts_alg_-8': [('if not verify_statement(proposal, agent_pub, CT_PROPOSAL, pb["agent_id"]):',
                              'if not verify_statement(proposal, agent_pub, CT_PROPOSAL, pb["agent_id"], '
                              'allowed_algs=(ALG_ED25519, ALG_EDDSA)):'),
                             ('if not verify_statement(r, opub, CT_RATIFICATION, rb["overseer_id"]):',
                              'if not verify_statement(r, opub, CT_RATIFICATION, rb["overseer_id"], '
                              'allowed_algs=(ALG_ED25519, ALG_EDDSA)):')],
 'N14_review_before_issue_within_skew': [('or rb["reviewed_at"] < pb["issued_at"]\n',
                                          'or rb["reviewed_at"] < pb["issued_at"] - MAX_CLOCK_SKEW\n')],
 'N15_consume_in_separate_tx_after_record': [('                elif MUT != "skip_replay":\n'
                                              '                    for key in keys:\n'
                                              '                        self.db.execute("insert into consumed(k) '
                                              'values(?)", (key,))\n'
                                              '                self._insert(rec)',
                                              '                elif MUT != "skip_replay":\n'
                                              '                    for key in keys:\n'
                                              '                        if self.db.execute("select 1 from consumed '
                                              'where k=?", (key,)).fetchone():\n'
                                              '                            raise sqlite3.IntegrityError\n'
                                              '                self._insert(rec)'),
                                             ('            if MUT == "split_consume_tx":\n'
                                              '                with self._write():',
                                              '            if True:\n                with self._write():')],
 'N16_txn_only_if_str': [('if isinstance(runtime_payload, Mapping) and "transaction_id" in runtime_payload:',
                          'if isinstance(runtime_payload, Mapping) and '
                          'isinstance(runtime_payload.get("transaction_id"), str):')],
 'N17_proposal_id_16_hex': [('body["proposal_id"] = H(dcbor(body)).hex()[:32]',
                             'body["proposal_id"] = H(dcbor(body)).hex()[:16]'),
                            ('return H(dcbor({k: v for k, v in pb.items() if k != "proposal_id"})).hex()[:32]',
                             'return H(dcbor({k: v for k, v in pb.items() if k != "proposal_id"})).hex()[:16]')],
 'N18_expiry_grace_equal_to_skew': [('not (now < pb["expires_at"] or',
                                     'not (now < pb["expires_at"] + MAX_CLOCK_SKEW or'),
                                    ('now >= rb["valid_until"]:\n                return',
                                     'now >= rb["valid_until"] + MAX_CLOCK_SKEW:\n                return')],
 'N19_unknown_verdict_treated_as_approved': [('            if rb["verdict"] not in VERDICTS:\n'
                                              '                return self._deny("unknown_verdict", pid)\n',
                                              '')],
 'N20_deny_reason_logged_without_proposal_id': [('rec = {"decision": "DENY", "reason": reason, "proposal_id": '
                                                 'proposal_id}',
                                                 'rec = {"decision": "DENY", "reason": reason}')]}


def run_one(name, repl, py):
    code = (ROOT / "sar_cose.py").read_text()
    for old, new in repl:
        n = code.count(old)
        if n != 1:
            return name, f"PATCH-ERROR ({n} matches for {old[:50]!r})", ""
        code = code.replace(old, new)
    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, "sar_cose.py").write_text(code)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", SAR_IMPL="sar_cose", SAR_MUTANT="",
                   PYTHONPATH=os.pathsep.join([d, str(ROOT), str(ROOT / "harness")]))
        p = subprocess.run([py, "-B", "-m", "unittest", *SUITE], cwd=d, env=env, capture_output=True, text=True,
                           timeout=1800)
        shutil.rmtree(pathlib.Path(d, ".hypothesis"), ignore_errors=True)
    fails = [ln for ln in (p.stdout + p.stderr).splitlines() if ln.startswith(("FAIL:", "ERROR:"))]
    return name, ("SURVIVED" if p.returncode == 0 else "KILLED"), "; ".join(fails[:2])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        res = sorted(f.result() for f in [ex.submit(run_one, n, r, args.python) for n, r in MUTANTS.items()])
    for n, v, f in res:
        print(f"{n:46s} {v:9s} {f[:150]}")
    surv = [n for n, v, _ in res if v != "KILLED"]
    print(f"audit mutants killed: {len(res) - len(surv)}/{len(res)}; not killed: {surv}")
    sys.exit(1 if surv else 0)


if __name__ == "__main__":
    main()
