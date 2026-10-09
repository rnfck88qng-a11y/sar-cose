"""Gap tests C07c, C07d, C09b, C10b, C11b, C12 (SARWP v1.1 section 6.4).

Implementation-agnostic: they use only the harness interface, so they run against any
SAR_IMPL. They were written after a mutation review showed the original 12 harness tests do
not detect these defects; the illustrative harness stub (sar_stub) is expected to FAIL them.

    SAR_IMPL=sar_cose python3 -m unittest -v test_sar_gaps
"""
import importlib
import os
import time
import unittest

S = importlib.import_module(os.environ.get("SAR_IMPL", "sar_cose"))

PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00"}


class SarGapTests(unittest.TestCase):
    def setUp(self):
        self.ak, apub = S.new_keypair()
        self.ok, opub = S.new_keypair()
        self.ok2, opub2 = S.new_keypair()
        self.policy = {"policy_id": "p1", "quorum": 1,
                       "authorized_agents": {"agent-1": apub},
                       "authorized_overseers": {"ov-1": opub, "ov-2": opub2}}
        self.store = S.Store()
        self.gate = S.Gate(self.policy, self.store)

    # C07c: a ratification must not be dated in the future or before the proposal it approves
    def test_c07c_future_dated_ratification_denied(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="f1")
        r = [S.ratify(self.ok, "ov-1", p, now=time.time() + 10**6)]
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_c07c_ratification_before_proposal_denied(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100000, nonce="f2")
        r = [S.ratify(self.ok, "ov-1", p, ttl=100000, now=time.time() - 5000)]
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    # C07d: expired ratification issued *after* the proposal (isolates the ratification window)
    def test_c07d_expired_ratification_reviewed_after_proposal_denied(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100000, now=time.time() - 2000, nonce="f3")
        r = [S.ratify(self.ok, "ov-1", p, ttl=10, now=time.time() - 1000)]
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    # C09b: offline verification must check authorization, not just signature well-formedness
    def test_c09b_offline_rejects_record_without_ratification(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        self.assertFalse(S.verify_record_offline(p, [], self.policy))

    def test_c09b_offline_rejects_record_with_only_rejection(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        self.assertFalse(S.verify_record_offline(p, [S.ratify(self.ok, "ov-1", p, "REJECTED")], self.policy))

    def test_c09b_offline_rejects_record_below_quorum(self):
        self.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        r = S.ratify(self.ok, "ov-1", p)
        self.assertFalse(S.verify_record_offline(p, [r, r], self.policy))
        self.assertTrue(S.verify_record_offline(p, [r, S.ratify(self.ok2, "ov-2", p)], self.policy))

    # C10b: deleting the most recent record must be detectable
    def test_c10b_tail_truncation_detected(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        r = [S.ratify(self.ok, "ov-1", p)]
        self.gate.authorize(PAYLOAD, p, r)
        self.gate.authorize(PAYLOAD, p, r)  # replay -> DENY record
        self.assertTrue(self.store.verify_chain())
        self.store.db.execute("delete from log where seq = (select max(seq) from log)")
        self.assertFalse(self.store.verify_chain())

    # C11b: quorum counts distinct overseers
    def test_c11b_duplicate_overseer_does_not_meet_quorum(self):
        self.gate.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="q1")
        r = S.ratify(self.ok, "ov-1", p)
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [r, r])[0])
        r_again = S.ratify(self.ok, "ov-1", p, now=time.time() + 1)  # second, distinct signature by same overseer
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [r, r_again])[0])

    # C13: a ratification approves one proposal only (invariant I2). Added after mutation testing of
    # sar_cose showed that removing the gate's ratification-binding check was not detected by any test.
    def test_c13_ratification_cannot_be_moved_to_another_proposal(self):
        now = time.time()
        approved = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="a1", now=now)
        other = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="a2", now=now)
        r = [S.ratify(self.ok, "ov-1", approved, now=now)]
        self.assertFalse(self.gate.authorize(PAYLOAD, other, r)[0])
        self.assertFalse(S.verify_record_offline(other, r, self.policy))
        self.assertTrue(self.gate.authorize(PAYLOAD, approved, r)[0])

    # C12: statements bound to another policy must not be accepted
    def test_c12_policy_id_mismatch_denied(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, policy_id="OTHER", nonce="m1")
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p)])[0])

    def test_c12_policy_id_mismatch_denied_offline(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, policy_id="OTHER")
        self.assertFalse(S.verify_record_offline(p, [S.ratify(self.ok, "ov-1", p)], self.policy))


if __name__ == "__main__":
    unittest.main()
