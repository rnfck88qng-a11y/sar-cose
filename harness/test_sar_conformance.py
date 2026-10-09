"""Implementation-agnostic conformance tests for the SAR claims in SARWP v1.0 section 6.

Run against any implementation exposing the interface in sar_stub.py:
    SAR_IMPL=my_module python3 -m unittest -v test_sar_conformance
Default SAR_IMPL=sar_stub (harness self-test only; NOT evidence for the paper).

Test -> paper mapping:
  test_01..test_08  = scenarios (expiry split into 07a/07b so each window is tested independently) listed in SARWP v1.0 section 6.4 (lines 767-775)
  test_09           = RQ3 offline verification (section 6.5)
  test_10           = tamper-evident append-only history (section 6.3 Authorization Store)
  test_11           = multi-overseer quorum (section 4.5.3)
"""
import copy
import importlib
import os
import time
import unittest

S = importlib.import_module(os.environ.get("SAR_IMPL", "sar_stub"))

PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00"}


class SarTests(unittest.TestCase):
    def setUp(self):
        self.ak, apub = S.new_keypair()
        self.ok, opub = S.new_keypair()
        self.ok2, opub2 = S.new_keypair()
        self.policy = {"policy_id": "p1", "quorum": 1,
                       "authorized_agents": {"agent-1": apub},
                       "authorized_overseers": {"ov-1": opub, "ov-2": opub2}}
        self.store = S.Store()
        self.gate = S.Gate(self.policy, self.store)

    def _good(self, nonce="n1", verdict="APPROVED", payload=None):
        p = S.make_proposal(self.ak, "agent-1", payload or PAYLOAD, nonce=nonce)
        return p, [S.ratify(self.ok, "ov-1", p, verdict)]

    # --- paper section 6.4 scenarios ---
    def test_01_authorized_execution_allowed(self):
        p, r = self._good()
        self.assertTrue(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_02_missing_authorization_denied(self):
        p, _ = self._good()
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [])[0])
        self.assertFalse(self.gate.authorize(PAYLOAD, None, [])[0])

    def test_03_invalid_signature_denied(self):
        p, r = self._good()
        r[0]["sig"] = "00" * 64
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])
        p2, r2 = self._good(nonce="n2")
        p2["sig"] = "00" * 64
        self.assertFalse(self.gate.authorize(PAYLOAD, p2, r2)[0])

    def test_04_rejected_proposal_denied(self):
        p, r = self._good(verdict="REJECTED")
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_05_modified_payload_after_approval_denied(self):
        p, r = self._good()
        tampered = copy.deepcopy(PAYLOAD)
        tampered["destination_account"] = "ATTACKER"
        self.assertFalse(self.gate.authorize(tampered, p, r)[0])

    def test_06_replayed_authorization_denied(self):
        p, r = self._good()
        self.assertTrue(self.gate.authorize(PAYLOAD, p, r)[0])
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_07a_expired_proposal_denied_even_if_ratification_valid(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=10, now=time.time() - 1000)
        r = [S.ratify(self.ok, "ov-1", p, "APPROVED", ttl=100000)]  # ratification still valid
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_07b_expired_ratification_denied_even_if_proposal_valid(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100000)
        r = [S.ratify(self.ok, "ov-1", p, "APPROVED", ttl=10, now=time.time() - 1000)]
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_08_invalid_policy_configuration_denied(self):
        bad = S.Gate({"policy_id": "p1", "quorum": 0, "authorized_agents": {}, "authorized_overseers": {}}, self.store)
        p, r = self._good()
        self.assertFalse(bad.authorize(PAYLOAD, p, r)[0])

    # --- RQ3 / store / quorum ---
    def test_09_offline_verification_needs_only_artifacts(self):
        p, r = self._good()
        self.assertTrue(S.verify_record_offline(p, r, self.policy))
        r[0]["body"]["verdict"] = "APPROVED "  # any mutation breaks it
        self.assertFalse(S.verify_record_offline(p, r, self.policy))

    def test_10_history_is_tamper_evident(self):
        p, r = self._good()
        self.gate.authorize(PAYLOAD, p, r)
        self.gate.authorize(PAYLOAD, p, r)  # logs a DENY (replay)
        self.assertTrue(self.store.verify_chain())
        self.store.db.execute("update log set record = replace(record,'DENY','ALLOW') where seq = 2")
        self.assertFalse(self.store.verify_chain())

    def test_11_quorum_requires_distinct_approvals(self):
        self.gate.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        one = [S.ratify(self.ok, "ov-1", p)]
        self.assertFalse(self.gate.authorize(PAYLOAD, p, one)[0])
        two = one + [S.ratify(self.ok2, "ov-2", p)]
        self.assertTrue(self.gate.authorize(PAYLOAD, p, two)[0])


if __name__ == "__main__":
    unittest.main()
