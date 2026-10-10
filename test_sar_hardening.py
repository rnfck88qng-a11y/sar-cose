"""Hardening tests: paths that coverage analysis showed were not exercised by the other suites,
and the external-checkpoint feature.

    python3 -m unittest -v test_sar_hardening
"""
import os
import sqlite3
import tempfile
import time
import unittest

import cbor2

import sar_cose as S

NOW = 1_800_000_000
PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR"}


class Base(unittest.TestCase):
    def setUp(self):
        self.ak, self.apub = S.new_keypair()
        self.ok, self.opub = S.new_keypair()
        self.ok2, self.opub2 = S.new_keypair()
        self.xk, _ = S.new_keypair()
        self.policy = {"policy_id": "p1", "quorum": 1, "authorized_agents": {"agent-1": self.apub},
                       "authorized_overseers": {"ov-1": self.opub, "ov-2": self.opub2}}

    def good(self, now=NOW, ttl=100):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=ttl, now=now)
        return p, [S.ratify(self.ok, "ov-1", p, now=now)]

    def gate(self):
        return S.Gate(self.policy, S.Store())


class EncodingEdges(Base):
    def test_integers_outside_cbor_major_types_rejected(self):
        for v in (2**64, -(2**64) - 1):
            with self.assertRaises(ValueError):
                S.dcbor(v)
        self.assertEqual(S.dcbor(2**64 - 1).hex(), "1bffffffffffffffff")
        self.assertEqual(S.dcbor(-(2**64)).hex(), "3bffffffffffffffff")

    def test_unencodable_runtime_payload_is_denied_not_raised(self):
        p, r = self.good()
        self.assertEqual(self.gate().authorize({"amount": 1.5}, p, r, now=NOW)[0], False)

    def test_cose_array_must_have_four_elements(self):
        for arr in ([], [b"", {}, b""], [b"", {}, b"", b"", b""]):
            with self.assertRaises(ValueError):
                S.from_cose(S.dcbor(cbor2.CBORTag(18, arr)))

    def test_cose_wrong_tag_or_untagged_rejected(self):
        p, _ = self.good()
        inner = cbor2.loads(S.to_cose(p)).value
        for data in (S.dcbor(inner), S.dcbor(cbor2.CBORTag(98, inner))):
            with self.assertRaises(ValueError):
                S.from_cose(data)

    def test_cose_payload_must_be_a_map(self):
        p, _ = self.good()
        protected, _u, _pl, sig = cbor2.loads(S.to_cose(p)).value
        with self.assertRaises(ValueError):
            S.from_cose(S.dcbor(cbor2.CBORTag(18, [protected, {}, S.dcbor([1, 2]), sig])))

    def test_cose_fields_must_be_byte_strings(self):
        p, _ = self.good()
        protected, _u, payload, sig = cbor2.loads(S.to_cose(p)).value
        for arr in ([protected.hex(), {}, payload, sig], [protected, {}, payload, sig.hex()]):
            with self.assertRaises(ValueError):
                S.from_cose(S.dcbor(cbor2.CBORTag(18, arr)))

    def test_protected_header_with_extra_parameter_rejected(self):
        p, _ = self.good()
        hdr = S.dcbor({1: -19, 3: S.CT_PROPOSAL, 4: b"agent-1", 33: b"x"})
        sig = self.ak.sign(S.dcbor(["Signature1", hdr, b"", S.dcbor(p["body"])]))
        self.assertFalse(S.verify_statement(dict(p, protected=hdr, sig=sig.hex()), self.apub, S.CT_PROPOSAL, "agent-1"))


class PolicyValidation(Base):
    def test_malformed_policies_deny(self):
        p, r = self.good()
        bad = [None, {}, "p1", {"policy_id": "p1"},
               dict(self.policy, quorum=True),            # bool is not a valid quorum
               dict(self.policy, quorum=3),               # more than the authorized overseers
               dict(self.policy, quorum="1"),
               dict(self.policy, policy_id=""),
               dict(self.policy, authorized_agents={}),
               dict(self.policy, authorized_overseers={})]
        for pol in bad:
            with self.subTest(policy=pol):
                self.assertEqual(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "policy_invalid"))

    def test_quorum_equal_to_overseer_count_is_valid(self):
        self.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW), S.ratify(self.ok2, "ov-2", p, now=NOW)]
        self.assertTrue(self.gate().authorize(PAYLOAD, p, r, now=NOW)[0])


class GateEdges(Base):
    def test_ratification_bound_to_other_policy_denied_even_if_proposal_matches(self):
        p, r = self.good()
        body = dict(r[0]["body"], policy_id="OTHER")
        forged = S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, body)  # validly signed by ov-1
        self.assertEqual(self.gate().authorize(PAYLOAD, p, [forged], now=NOW), (False, "policy_mismatch"))

    def test_ratification_after_proposal_expiry_denied(self):
        # proposal valid until NOW+10; ratification dated NOW+20 (within clock skew of NOW)
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=10, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW + 20)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW)[0], False)
        self.assertFalse(S.verify_record_offline(p, r, self.policy))

    def test_ratification_window_is_half_open(self):
        # SEMANTICS.md S3: issued_at <= reviewed_at < expires_at
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=10, now=NOW)
        self.assertTrue(self.gate().authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p, now=NOW + 9)], now=NOW + 9)[0])
        self.assertFalse(self.gate().authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p, now=NOW + 10)], now=NOW + 9)[0])

    def test_unauthorized_agent_denied(self):
        p = S.make_proposal(self.xk, "agent-x", PAYLOAD, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "agent_not_authorized"))

    def test_agent_key_substitution_denied(self):
        # statement claims agent-1 but is signed with another key
        p = S.make_proposal(self.xk, "agent-1", PAYLOAD, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "bad_proposal"))

    def test_denials_are_recorded_in_the_log(self):
        g = self.gate()
        p, r = self.good()
        g.authorize(dict(PAYLOAD, amount=1), p, r, now=NOW)
        rows = [x[0] for x in g.store.db.execute("select record from log")]
        self.assertEqual(len(rows), 1)
        self.assertIn('"DENY"', rows[0])
        self.assertIn("payload_mismatch", rows[0])

    def test_expired_approval_denies_even_if_quorum_met_otherwise(self):
        # SEMANTICS.md S4 / paper section 4.7 "Expired ratification" is a denial condition
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=1000, now=NOW - 500)
        fresh = S.ratify(self.ok, "ov-1", p, ttl=1000, now=NOW - 100)
        stale = S.ratify(self.ok2, "ov-2", p, ttl=10, now=NOW - 100)
        self.assertTrue(self.gate().authorize(PAYLOAD, p, [fresh], now=NOW)[0])
        self.assertEqual(self.gate().authorize(PAYLOAD, p, [fresh, stale], now=NOW), (False, "ratification_expired"))


class OfflineEdges(Base):
    def test_unauthorized_overseer(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, now=NOW)
        self.assertFalse(S.verify_record_offline(p, [S.ratify(self.xk, "ov-x", p, now=NOW)], self.policy))

    def test_bad_ratification_signature(self):
        p, r = self.good()
        r[0]["sig"] = "00" * 64
        self.assertFalse(S.verify_record_offline(p, r, self.policy))

    def test_ratification_policy_mismatch(self):
        p, r = self.good()
        forged = S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, dict(r[0]["body"], policy_id="OTHER"))
        self.assertFalse(S.verify_record_offline(p, [forged], self.policy))

    def test_review_outside_validity_window(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100, now=NOW)
        for reviewed, rttl in ((NOW - 1, 1000), (NOW + 101, 1000)):
            with self.subTest(reviewed=reviewed):
                self.assertFalse(S.verify_record_offline(p, [S.ratify(self.ok, "ov-1", p, ttl=rttl, now=reviewed)], self.policy))

    def test_malformed_inputs(self):
        p, r = self.good()
        for args in ((None, r, self.policy), ({}, r, self.policy), (p, [None], self.policy),
                     (p, [{"body": {}}], self.policy), (p, r, None), (p, r, {})):
            with self.subTest(args=str(args)[:40]):
                self.assertFalse(S.verify_record_offline(*args))

    def test_valid_record_verifies_without_store_or_clock(self):
        p, r = self.good(now=NOW - 10**6)  # long expired: offline audit is about authorization at the time
        self.assertTrue(S.verify_record_offline(p, r, self.policy))


class ExternalCheckpoint(Base):
    def test_forged_or_mismatched_checkpoint_rejected(self):
        g = self.gate()
        p, r = self.good()
        g.authorize(PAYLOAD, p, r, now=NOW)
        cp = g.store.checkpoint()
        self.assertTrue(g.store.verify_chain(cp))
        self.assertFalse(g.store.verify_chain(dict(cp, sig="00" * 64)))
        self.assertFalse(g.store.verify_chain(dict(cp, size=cp["size"] + 1)))
        self.assertFalse(g.store.verify_chain(cp, checkpoint_key=S.new_keypair()[1]))
        self.assertFalse(g.store.verify_chain({"size": 0}))

    def test_truncation_detected_after_reopen_with_retained_checkpoint(self):
        key, _ = S.new_keypair()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s1 = S.Store(path, signing_key=key)
            g = S.Gate(self.policy, s1)
            for i in range(3):
                p = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce=f"t{i}", now=NOW)
                g.authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p, now=NOW)], now=NOW)
            retained, pub = s1.checkpoint(), s1.checkpoint_key   # kept outside the database
            s1.close()
            attacker = S.Store(path)                             # someone with file access
            attacker.db.execute("delete from log where seq = (select max(seq) from log)")
            attacker.close()
            s2 = S.Store(path, signing_key=key)                  # reopened; re-signs the *current* tip
            self.assertTrue(s2.verify_links())                   # linkage alone cannot see truncation
            self.assertTrue(s2.verify_chain())                   # nor can its own fresh checkpoint
            self.assertFalse(s2.verify_chain(retained, pub))     # the retained checkpoint can
            s2.close()

    def test_rewrite_detected_against_retained_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s1 = S.Store(path)
            S.Gate(self.policy, s1).authorize(PAYLOAD, None, [], now=NOW)
            retained, pub = s1.checkpoint(), s1.checkpoint_key
            s1.close()
            # attacker rewrites the whole chain consistently (valid links) with different content
            import hashlib, json
            attacker = S.Store(path)
            db = attacker.db
            rec = json.dumps({"decision": "ALLOW", "proposal_id": "x"}, sort_keys=True, separators=(",", ":"))
            db.execute("update log set record=?, hash=? where seq=1",
                       (rec, hashlib.sha256((S.Store.GENESIS + rec).encode()).hexdigest()))
            attacker.close()
            s2 = S.Store(path)
            self.assertTrue(s2.verify_links())
            self.assertFalse(s2.verify_chain(retained, pub))
            s2.close()


class SemanticsRules(Base):
    """One or more tests per rule in SEMANTICS.md that the other suites do not pin down."""

    def _resign(self, priv, kid, ctype, body):
        return S.sign_statement(priv, kid, ctype, body)

    # S6: a rejection vetoes even when quorum is met by others
    def test_s6_rejection_vetoes_met_quorum(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW), S.ratify(self.ok2, "ov-2", p, "REJECTED", now=NOW)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "rejected"))

    # S8: separation of roles and exact policy shape
    def test_s8_one_key_under_two_overseer_ids_invalidates_policy(self):
        self.policy["authorized_overseers"] = {"ov-1": self.opub, "ov-1b": self.opub}
        self.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW), S.ratify(self.ok, "ov-1b", p, now=NOW)]  # one human, two ids
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "policy_invalid"))

    def test_s8_agent_cannot_also_be_overseer(self):
        for overseers in ({"ov-1": self.opub, "agent-1": self.opub2},      # same identity in both roles
                          {"ov-1": self.opub, "ov-a": self.apub}):          # agent's key as an overseer
            with self.subTest(overseers=list(overseers)):
                pol = dict(self.policy, authorized_overseers=overseers)
                p, r = self.good()
                self.assertEqual(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "policy_invalid"))

    def test_s8_self_ratification_by_agent_key_denied(self):
        pol = dict(self.policy, authorized_overseers={"ov-1": self.opub, "ov-a": self.apub})
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, now=NOW)
        self.assertFalse(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, [S.ratify(self.ak, "ov-a", p, now=NOW)], now=NOW)[0])

    def test_s8_policy_shape(self):
        p, r = self.good()
        for pol in (dict(self.policy, extra=1), dict(self.policy, authorized_agents={"agent-1": self.apub.upper()}),
                    dict(self.policy, authorized_agents={"agent-1": "00" * 31}), dict(self.policy, authorized_agents={"": self.apub}),
                    dict(self.policy, authorized_agents={"agent-1": "zz" * 32})):
            with self.subTest(policy=str(pol)[:60]):
                self.assertEqual(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "policy_invalid"))
        self.assertFalse(S.verify_record_offline(p, r, dict(self.policy, extra=1)))

    # S9: statement shape and proposal_id
    def test_s9_extra_or_wrong_typed_body_fields_denied_even_if_validly_signed(self):
        p, r = self.good()
        cases = [dict(p["body"], extra="x"), dict(p["body"], v=2), dict(p["body"], v=True),
                 dict(p["body"], issued_at=-1), dict(p["body"], payload_digest=b"short"), dict(p["body"], nonce="")]
        for body in cases:
            with self.subTest(body=sorted(set(body) ^ set(p["body"])) or body.get("v")):
                body = dict(body)
                if "proposal_id" in body:
                    body["proposal_id"] = S.expected_proposal_id(body)
                bad = self._resign(self.ak, "agent-1", S.CT_PROPOSAL, body)
                rr = [S.ratify(self.ok, "ov-1", bad, now=NOW)]
                self.assertEqual(self.gate().authorize(PAYLOAD, bad, rr, now=NOW)[0], False)
                self.assertFalse(S.verify_record_offline(bad, rr, self.policy))

    def test_s9_ratification_shape(self):
        p, r = self.good()
        for body in (dict(r[0]["body"], extra=1), dict(r[0]["body"], v=0), dict(r[0]["body"], valid_until=NOW)):
            with self.subTest(body=str(body)[-40:]):
                bad = self._resign(self.ok, "ov-1", S.CT_RATIFICATION, body)
                self.assertEqual(self.gate().authorize(PAYLOAD, p, [bad], now=NOW), (False, "malformed_ratification"))

    def test_s9_attacker_chosen_proposal_id_denied(self):
        p, _ = self.good()
        body = dict(p["body"], proposal_id="0" * 32)              # agent signs a forged id
        bad = self._resign(self.ak, "agent-1", S.CT_PROPOSAL, body)
        rr = [S.ratify(self.ok, "ov-1", bad, now=NOW)]
        self.assertEqual(self.gate().authorize(PAYLOAD, bad, rr, now=NOW)[1], "proposal_id_mismatch")
        self.assertFalse(S.verify_record_offline(bad, rr, self.policy))

    def test_s9_signature_encoding_is_canonical(self):
        p, r = self.good()
        self.assertTrue(S.verify_statement(p, self.apub, S.CT_PROPOSAL, "agent-1"))
        self.assertFalse(S.verify_statement(dict(p, sig=p["sig"].upper()), self.apub, S.CT_PROPOSAL, "agent-1"))

    def test_s9_empty_validity_interval_denied(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=0, now=NOW)
        self.assertFalse(self.gate().authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p, now=NOW)], now=NOW)[0])

    # S10: replay keys
    def test_s10_nonce_reuse_by_a_new_proposal_denied(self):
        g = self.gate()
        p1 = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="same", now=NOW)
        p2 = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="same", now=NOW + 1)
        self.assertNotEqual(p1["body"]["proposal_id"], p2["body"]["proposal_id"])
        self.assertTrue(g.authorize(PAYLOAD, p1, [S.ratify(self.ok, "ov-1", p1, now=NOW)], now=NOW + 1)[0])
        self.assertEqual(g.authorize(PAYLOAD, p2, [S.ratify(self.ok, "ov-1", p2, now=NOW + 1)], now=NOW + 1), (False, "replay"))

    def test_s10_transaction_id_reuse_denied(self):
        g = self.gate()
        pay = dict(PAYLOAD, transaction_id="tx-42")
        p1 = S.make_proposal(self.ak, "agent-1", pay, nonce="a", now=NOW)
        p2 = S.make_proposal(self.ak, "agent-1", pay, nonce="b", now=NOW)
        self.assertTrue(g.authorize(pay, p1, [S.ratify(self.ok, "ov-1", p1, now=NOW)], now=NOW)[0])
        self.assertEqual(g.authorize(pay, p2, [S.ratify(self.ok, "ov-1", p2, now=NOW)], now=NOW), (False, "replay"))

    def test_s10_denial_consumes_nothing(self):
        g = self.gate()
        p, r = self.good()
        self.assertFalse(g.authorize(dict(PAYLOAD, amount=1), p, r, now=NOW)[0])
        self.assertTrue(g.authorize(PAYLOAD, p, r, now=NOW)[0])

    # S11: offline verification interval
    def test_s11_offline_requires_common_validity_interval(self):
        self.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=1000, now=NOW)
        a = S.ratify(self.ok, "ov-1", p, ttl=10, now=NOW)          # valid [NOW, NOW+10)
        b = S.ratify(self.ok2, "ov-2", p, ttl=10, now=NOW + 20)    # valid [NOW+20, NOW+30): no overlap
        self.assertFalse(S.verify_record_offline(p, [a, b], self.policy))
        c = S.ratify(self.ok2, "ov-2", p, ttl=10, now=NOW + 5)     # overlap [NOW+5, NOW+10)
        self.assertTrue(S.verify_record_offline(p, [a, c], self.policy))
        self.assertTrue(S.verify_record_offline(p, [a, c], self.policy, at=NOW + 9))
        self.assertFalse(S.verify_record_offline(p, [a, c], self.policy, at=NOW + 10))
        # S2: the start of the common interval [NOW+5, NOW+10) is tolerant by SKEW, the end is exact
        self.assertTrue(S.verify_record_offline(p, [a, c], self.policy, at=NOW + 5 - S.MAX_CLOCK_SKEW))
        self.assertFalse(S.verify_record_offline(p, [a, c], self.policy, at=NOW + 4 - S.MAX_CLOCK_SKEW))

    def test_s11_offline_rejects_duplicate_overseer(self):
        p, r = self.good()
        r2 = S.ratify(self.ok, "ov-1", p, now=NOW + 1)
        self.assertFalse(S.verify_record_offline(p, r + [r2], self.policy))

    # S13: the gate never allows what offline verification would reject
    def test_s13_no_common_validity_interval_denied_at_gate(self):
        # found by the cross-implementation test: approval A valid [NOW, NOW+5), approval B dated
        # NOW+30 (within clock skew): each passes on its own at NOW, but they were never valid together
        self.policy["quorum"] = 2
        self.policy["authorized_overseers"]["ov-3"] = S.new_keypair()[1]
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100, now=NOW)
        a = S.ratify(self.ok, "ov-1", p, ttl=5, now=NOW)
        b = S.ratify(self.ok2, "ov-2", p, ttl=1000, now=NOW + 30)
        self.assertFalse(S.verify_record_offline(p, [a, b], self.policy))
        self.assertEqual(self.gate().authorize(PAYLOAD, p, [a, b], now=NOW), (False, "no_common_validity"))

    # S12: logging failure never allows
    def test_s12_unloggable_decision_never_allows(self):
        g = self.gate()
        p, r = self.good()
        g.store.db.close()
        allowed, reason = g.authorize(PAYLOAD, p, r, now=NOW)
        self.assertFalse(allowed)
        self.assertEqual(reason, "deny_unlogged")

    def test_invalid_clock_values_deny(self):
        p, r = self.good()
        for now in ("now", 1.5, True):
            with self.subTest(now=now):
                self.assertFalse(self.gate().authorize(PAYLOAD, p, r, now=now)[0])


class MutationSweepGaps(Base):
    """Tests added for survivors of the automated mutation sweep (tools/mutation_sweep.py)."""

    def test_proposal_policy_checked_even_if_ratification_names_the_gate_policy(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, policy_id="OTHER", now=NOW)
        body = dict(S.ratify(self.ok, "ov-1", p, now=NOW)["body"], policy_id="p1")
        r = [S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, body)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "policy_mismatch"))
        self.assertFalse(S.verify_record_offline(p, r, self.policy))

    def test_non_integer_clock_is_rejected_as_such(self):
        p, r = self.good()
        for now in (NOW + 0.5, float(NOW), True):
            with self.subTest(now=now):
                self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=now), (False, "invalid_clock"))

    def test_binding_requires_both_digest_and_proposal_id(self):
        p, r = self.good()
        wrong_id = S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, dict(r[0]["body"], proposal_id="0" * 32))
        wrong_digest = S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, dict(r[0]["body"], proposal_digest=b"\0" * 32))
        for bad in (wrong_id, wrong_digest):
            self.assertEqual(self.gate().authorize(PAYLOAD, p, [bad], now=NOW), (False, "ratification_not_bound"))
            self.assertFalse(S.verify_record_offline(p, [bad], self.policy))

    def test_touching_but_disjoint_validity_intervals_denied(self):
        # A valid [NOW-5, NOW+5), B valid [NOW+5, NOW+105): no common instant (half-open)
        self.policy["quorum"] = 2
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=1000, now=NOW - 100)
        a = S.ratify(self.ok, "ov-1", p, ttl=10, now=NOW - 5)
        b = S.ratify(self.ok2, "ov-2", p, ttl=100, now=NOW + 5)
        self.assertEqual(self.gate().authorize(PAYLOAD, p, [a, b], now=NOW), (False, "no_common_validity"))
        self.assertFalse(S.verify_record_offline(p, [a, b], self.policy))

    def test_offline_rejects_bad_proposal_signature(self):
        p, r = self.good()
        self.assertFalse(S.verify_record_offline(dict(p, sig="00" * 64), r, self.policy))

    def test_offline_at_is_inclusive_at_start(self):
        p, r = self.good(now=NOW, ttl=100)          # common interval [NOW, NOW+60), accepted from NOW-SKEW
        self.assertTrue(S.verify_record_offline(p, r, self.policy, at=NOW - S.MAX_CLOCK_SKEW))
        self.assertFalse(S.verify_record_offline(p, r, self.policy, at=NOW - S.MAX_CLOCK_SKEW - 1))
        self.assertTrue(S.verify_record_offline(p, r, self.policy, at=NOW + 59))
        self.assertFalse(S.verify_record_offline(p, r, self.policy, at=NOW + 60))

    def test_epoch_zero_timestamp_is_valid(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, ttl=100, now=0)
        r = [S.ratify(self.ok, "ov-1", p, now=0)]
        self.assertTrue(self.gate().authorize(PAYLOAD, p, r, now=10)[0])
        self.assertTrue(S.verify_record_offline(p, r, self.policy))

    def test_single_character_identities_are_valid(self):
        pol = {"policy_id": "p", "quorum": 1, "authorized_agents": {"a": self.apub}, "authorized_overseers": {"o": self.opub}}
        p = S.make_proposal(self.ak, "a", PAYLOAD, policy_id="p", now=NOW)
        r = [S.ratify(self.ok, "o", p, now=NOW)]
        self.assertTrue(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, r, now=NOW)[0])

    def test_quorum_zero_with_valid_overseers_is_invalid(self):
        p, r = self.good()
        self.assertEqual(S.Gate(dict(self.policy, quorum=0), S.Store()).authorize(PAYLOAD, p, r, now=NOW),
                         (False, "policy_invalid"))

    def test_identifier_and_nonce_length_limits_are_inclusive(self):
        long_id, too_long = "a" * S.MAX_ID_LEN, "a" * (S.MAX_ID_LEN + 1)
        pol = {"policy_id": "p1", "quorum": 1, "authorized_agents": {long_id: self.apub},
               "authorized_overseers": {"ov-1": self.opub}}
        p = S.make_proposal(self.ak, long_id, PAYLOAD, nonce="n" * S.MAX_ID_LEN, now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW)]
        self.assertTrue(S.Gate(pol, S.Store()).authorize(PAYLOAD, p, r, now=NOW)[0])
        pol_bad = dict(pol, authorized_agents={too_long: self.apub})
        self.assertEqual(S.Gate(pol_bad, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "policy_invalid"))
        p2 = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="n" * (S.MAX_ID_LEN + 1), now=NOW)
        self.assertEqual(self.gate().authorize(PAYLOAD, p2, [S.ratify(self.ok, "ov-1", p2, now=NOW)], now=NOW),
                         (False, "malformed_proposal"))

    def test_offline_rejects_ratified_proposal_with_bad_agent_signature(self):
        # the overseer ratifies the exact (badly signed) bytes, so binding holds; only the agent
        # signature check can reject it
        p, _ = self.good()
        bad = dict(p, sig="00" * 64)
        r = [S.ratify(self.ok, "ov-1", bad, now=NOW)]
        self.assertFalse(S.verify_record_offline(bad, r, self.policy))
        self.assertEqual(self.gate().authorize(PAYLOAD, bad, r, now=NOW), (False, "bad_proposal"))

    def test_missing_inputs_are_denied_for_the_right_reason(self):
        p, r = self.good()
        self.assertEqual(self.gate().authorize(PAYLOAD, None, r, now=NOW), (False, "missing_proposal"))
        self.assertEqual(self.gate().authorize(PAYLOAD, p, [], now=NOW), (False, "missing_ratification"))
        self.assertEqual(self.gate().authorize(PAYLOAD, p, {"x": r[0]}, now=NOW), (False, "missing_ratification"))


class AuditSurvivors(Base):
    """Tests for semantic mutants that survived the whole suite in an external audit of v1.2
    (claude-investigation-brief/deep-verification-v1.2/new_mutants: N02, N07, N09, N12, N16, N20)."""

    def _resigned_proposal(self, **changes):
        p, _ = self.good()
        body = dict(p["body"], **changes)
        body["proposal_id"] = S.expected_proposal_id(body)
        return S.sign_statement(self.ak, "agent-1", S.CT_PROPOSAL, body)

    def test_payload_digest_is_compared_in_full(self):  # N07
        real = S.payload_digest(PAYLOAD)
        for digest in (real[:8] + b"\0" * 24, real[:31] + bytes([real[31] ^ 1])):
            bad = self._resigned_proposal(payload_digest=digest)
            r = [S.ratify(self.ok, "ov-1", bad, now=NOW)]
            self.assertEqual(self.gate().authorize(PAYLOAD, bad, r, now=NOW), (False, "payload_mismatch"))

    def test_replay_is_denied_at_any_later_instant(self):  # N09
        p, r = self.good(ttl=100)
        g = self.gate()
        self.assertTrue(g.authorize(PAYLOAD, p, r, now=NOW)[0])
        for later in (NOW + 1, NOW + 2, NOW + 59):
            self.assertEqual(g.authorize(PAYLOAD, p, r, now=later), (False, "replay"))
        p2 = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce="n1", now=NOW + 1)   # same nonce, new proposal
        self.assertEqual(g.authorize(PAYLOAD, p2, [S.ratify(self.ok, "ov-1", p2, now=NOW + 1)], now=NOW + 2),
                         (False, "replay"))

    def test_nonce_comparison_is_exact(self):  # N02: "ABC" and "abc" are different nonces
        g = self.gate()
        for nonce in ("ABC", "abc"):
            p = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce=nonce, now=NOW)
            self.assertEqual(g.authorize(PAYLOAD, p, [S.ratify(self.ok, "ov-1", p, now=NOW)], now=NOW), (True, "ok"))

    def test_policy_binding_is_exact(self):  # N12: "P1" is not policy "p1"
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, policy_id="P1", now=NOW)
        r = [S.ratify(self.ok, "ov-1", p, now=NOW)]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, r, now=NOW), (False, "policy_mismatch"))
        self.assertFalse(S.verify_record_offline(p, r, self.policy))
        p, r = self.good()
        rr = [S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, dict(r[0]["body"], policy_id="P1"))]
        self.assertEqual(self.gate().authorize(PAYLOAD, p, rr, now=NOW), (False, "policy_mismatch"))
        self.assertFalse(S.verify_record_offline(p, rr, self.policy))

    def test_non_text_transaction_id_is_consumed(self):  # N16
        for tid in (42, b"tx", ["a", 1]):
            with self.subTest(tid=tid):
                g = self.gate()
                pay = dict(PAYLOAD, transaction_id=tid)
                p1 = S.make_proposal(self.ak, "agent-1", pay, nonce="a", now=NOW)
                p2 = S.make_proposal(self.ak, "agent-1", pay, nonce="b", now=NOW)
                self.assertTrue(g.authorize(pay, p1, [S.ratify(self.ok, "ov-1", p1, now=NOW)], now=NOW)[0])
                self.assertEqual(g.authorize(pay, p2, [S.ratify(self.ok, "ov-1", p2, now=NOW)], now=NOW), (False, "replay"))

    def test_transaction_ids_are_compared_as_cbor_values(self):
        # S10: the text "42" and the integer 42 are different identifiers (documented limitation:
        # a target system that conflates them must canonicalize the identifier in the payload)
        g = self.gate()
        for i, tid in enumerate(("42", 42)):
            pay = dict(PAYLOAD, transaction_id=tid)
            p = S.make_proposal(self.ak, "agent-1", pay, nonce=f"t{i}", now=NOW)
            self.assertTrue(g.authorize(pay, p, [S.ratify(self.ok, "ov-1", p, now=NOW)], now=NOW)[0])

    def test_denial_record_names_the_proposal(self):  # N20
        import json
        g = self.gate()
        p, r = self.good()
        g.authorize(dict(PAYLOAD, amount=1), p, r, now=NOW)
        rec = json.loads(g.store.db.execute("select record from log").fetchone()[0])
        self.assertEqual(rec, {"decision": "DENY", "reason": "payload_mismatch", "proposal_id": p["body"]["proposal_id"]})


class Revocation(Base):
    """Authorization is evaluated against the policy in force at execution time."""

    def test_overseer_removed_after_ratification_is_denied(self):
        p, r = self.good()
        g = self.gate()
        g.policy = dict(self.policy, authorized_overseers={"ov-2": self.opub2})   # ov-1 revoked
        self.assertEqual(g.authorize(PAYLOAD, p, r, now=NOW), (False, "overseer_not_authorized"))
        self.assertFalse(S.verify_record_offline(p, r, g.policy))
        self.assertTrue(S.verify_record_offline(p, r, self.policy))   # still valid evidence under the old policy

    def test_agent_removed_after_ratification_is_denied(self):
        p, r = self.good()
        other = S.new_keypair()[1]
        revoked = dict(self.policy, authorized_agents={"agent-2": other})
        self.assertEqual(S.Gate(revoked, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "agent_not_authorized"))

    def test_overseer_key_rotated_after_ratification_is_denied(self):
        p, r = self.good()
        rotated = dict(self.policy, authorized_overseers={"ov-1": S.new_keypair()[1], "ov-2": self.opub2})
        self.assertEqual(S.Gate(rotated, S.Store()).authorize(PAYLOAD, p, r, now=NOW), (False, "bad_ratification"))


class FaultyConnection:
    """Wraps a sqlite3 connection and raises once, at the n-th execute() call (crash injection)."""

    def __init__(self, db, fail_at):
        self.db, self.fail_at, self.calls = db, fail_at, 0

    def execute(self, *args):
        self.calls += 1
        if self.calls == self.fail_at:
            raise sqlite3.OperationalError(f"injected failure at statement {self.calls}")
        return self.db.execute(*args)

    def close(self):
        self.db.close()


class RollbackAndCrash(Base):
    """Rollback of the database file, crash semantics (consume-then-execute: at most once)."""

    def _allow_count(self, path):
        import json
        st = S.Store(path)
        n = sum(json.loads(rec).get("decision") == "ALLOW" for (rec,) in st.db.execute("select record from log"))
        st.close()
        return n

    def test_rollback_without_anchor_reenables_a_consumed_authorization(self):
        # Documented limitation: without an anchor, restoring an older database file, or deleting
        # rows of `consumed`, lets the same authorization be allowed again.
        import shutil
        p, r = self.good()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            S.Store(path).close()
            shutil.copy(path, path + ".old")
            s = S.Store(path)
            self.assertTrue(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW)[0])
            s.close()
            shutil.copy(path + ".old", path)                       # attacker restores the old file
            s = S.Store(path)
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW), (True, "ok"))
            s.db.execute("delete from consumed")                    # or deletes consumed keys
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW), (True, "ok"))
            s.close()

    def test_anchor_refuses_a_rolled_back_or_truncated_database(self):
        import shutil
        key, _ = S.new_keypair()
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as elsewhere:
            path, anchor = os.path.join(d, "sar.db"), S.FileAnchor(os.path.join(elsewhere, "anchor.json"))
            S.Store(path, signing_key=key, anchor=anchor).close()
            shutil.copy(path, path + ".0")                          # before any ALLOW
            props = [S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce=f"a{i}", now=NOW) for i in range(3)]
            rats = [[S.ratify(self.ok, "ov-1", p, now=NOW)] for p in props]
            s = S.Store(path, signing_key=key, anchor=anchor)
            g = S.Gate(self.policy, s)
            self.assertTrue(g.authorize(PAYLOAD, props[0], rats[0], now=NOW)[0])
            g.authorize(PAYLOAD, None, [], now=NOW)                 # a denial after the ALLOW
            s.close()
            shutil.copy(path, path + ".1")                          # after the first ALLOW
            s = S.Store(path, signing_key=key, anchor=anchor)
            self.assertTrue(S.Gate(self.policy, s).authorize(PAYLOAD, props[1], rats[1], now=NOW)[0])
            s.close()
            self.assertEqual(anchor.load()["size"], self._log_size(path))
            for snapshot, replayed in ((".0", 0), (".1", 1)):
                with self.subTest(snapshot=snapshot):
                    shutil.copy(path + snapshot, path)              # attacker restores an older file
                    s = S.Store(path, signing_key=key, anchor=anchor)
                    self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, props[replayed], rats[replayed], now=NOW),
                                     (False, "store_inconsistent_with_anchor"))
                    self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, props[2], rats[2], now=NOW),
                                     (False, "store_inconsistent_with_anchor"))   # fail closed for everything
                    self.assertFalse(s.verify_chain(anchor.load()))
                    s.close()

    def _log_size(self, path):
        st = S.Store(path)
        n = st.db.execute("select count(*) from log").fetchone()[0]
        st.close()
        return n

    def test_anchor_detects_deleted_consumed_keys_and_static_checkpoints(self):
        key, _ = S.new_keypair()
        p, r = self.good()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            anchor = S.FileAnchor(os.path.join(d, "anchor.json"))
            s = S.Store(path, signing_key=key, anchor=anchor)
            self.assertTrue(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW)[0])
            s.db.execute("delete from consumed")                    # keys are also in the chained ALLOW record
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW), (False, "replay"))
            retained = s.checkpoint()
            s.db.execute("delete from log where seq = (select max(seq) from log)")   # truncate the denial
            s.db.execute("delete from log where seq = (select max(seq) from log)")   # and the ALLOW
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW),
                             (False, "store_inconsistent_with_anchor"))
            s.close()
            static = S.Store(path, signing_key=key, anchor=retained)  # a checkpoint dict retained elsewhere
            self.assertEqual(S.Gate(self.policy, static).authorize(PAYLOAD, p, r, now=NOW),
                             (False, "store_inconsistent_with_anchor"))
            static.close()

    def test_anchor_detects_a_modified_record_and_accepts_a_consistent_static_checkpoint(self):
        key, _ = S.new_keypair()
        props = [S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce=f"m{i}", now=NOW) for i in range(3)]
        rats = [[S.ratify(self.ok, "ov-1", p, now=NOW)] for p in props]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s = S.Store(path, signing_key=key)
            g = S.Gate(self.policy, s)
            g.authorize(PAYLOAD, None, [], now=NOW)                  # one denial record
            static = s.checkpoint()                                  # retained by an auditor
            s.close()
            s = S.Store(path, signing_key=key, anchor=static)        # consistent: allowed
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, props[0], rats[0], now=NOW), (True, "ok"))
            # rewrite the denial's text but keep its stored hash and link: only the hash check sees it
            s.db.execute("update log set record = replace(record, 'missing_proposal', 'xissing_proposal') where seq = 1")
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, props[1], rats[1], now=NOW),
                             (False, "store_inconsistent_with_anchor"))
            s.close()

    def test_missing_anchor_for_a_non_empty_log_refuses(self):
        key, _ = S.new_keypair()
        p, r = self.good()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s = S.Store(path, signing_key=key)
            S.Gate(self.policy, s).authorize(PAYLOAD, None, [], now=NOW)
            s.close()
            anchor = S.FileAnchor(os.path.join(d, "anchor.json"))
            s = S.Store(path, signing_key=key, anchor=anchor)       # not implicitly anchored
            self.assertIsNone(anchor.load())
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW),
                             (False, "store_inconsistent_with_anchor"))
            anchor.save(s.checkpoint())                             # explicit operator decision
            self.assertTrue(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW)[0])
            s.close()

    def test_crash_at_every_statement_allows_at_most_once(self):
        """Inject a failure at each database statement of an authorization, then retry twice after
        a restart. Consumption and the ALLOW record are one transaction, so an ALLOW record exists
        iff the keys were consumed, and the authorization is allowed at most once overall. A
        failure after the commit returns DENY although the authorization is consumed: it is then
        neither executed nor reusable (at-most-once, not exactly-once)."""
        p, r = self.good()
        probe = S.Store()
        probe.db = counter = FaultyConnection(probe.db, fail_at=None)
        self.assertTrue(S.Gate(self.policy, probe).authorize(PAYLOAD, p, r, now=NOW)[0])
        n_statements = counter.calls
        self.assertGreater(n_statements, 3)
        for use_anchor in (False, True):
            for fail_at in range(1, n_statements + 1):
                with self.subTest(fail_at=fail_at, anchor=use_anchor), tempfile.TemporaryDirectory() as d:
                    key, _ = S.new_keypair()
                    path = os.path.join(d, "sar.db")
                    anchor = S.FileAnchor(os.path.join(d, "anchor.json")) if use_anchor else None
                    s = S.Store(path, signing_key=key, anchor=anchor)
                    s.db = FaultyConnection(s.db, fail_at)
                    results = [S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW)]
                    s.close()
                    for _ in range(2):                              # restart and retry
                        s = S.Store(path, signing_key=key, anchor=anchor)
                        results.append(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW))
                        consumed = s.db.execute("select count(*) from consumed").fetchone()[0]
                        s.close()
                    allowed, records = sum(ok for ok, _ in results), self._allow_count(path)
                    self.assertLessEqual(allowed, 1, results)               # never executed twice
                    self.assertLessEqual(records, 1, results)               # never consumed twice
                    self.assertEqual(records == 1, consumed > 0, results)   # record and keys are atomic
                    self.assertLessEqual(allowed, records, results)         # every ALLOW was recorded first
                    if records == 0:   # only when the anchor got ahead of a failed commit: fail closed
                        self.assertTrue(use_anchor, results)
                        self.assertEqual(results[-1], (False, "store_inconsistent_with_anchor"))
                    elif allowed == 0:  # failure after the commit: consumed but not executed (at most once)
                        self.assertEqual(results[1:], [(False, "replay")] * 2, results)

    def test_failure_after_allow_never_reenables_the_authorization(self):
        # consume-then-execute: if the executor crashes after the gate allowed, the authorization
        # stays consumed (at most once); a retry needs a new proposal and a new ratification
        p, r = self.good()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sar.db")
            s = S.Store(path)
            self.assertTrue(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW)[0])
            s.close()                                               # executor crashes before executing
            s = S.Store(path)
            self.assertEqual(S.Gate(self.policy, s).authorize(PAYLOAD, p, r, now=NOW + 1), (False, "replay"))
            s.close()


class ExactBytes(Base):
    """Gate.authorize_bytes: the executor gets back exactly the bytes whose digest was checked."""

    def test_allow_returns_the_exact_immutable_bytes(self):
        p, r = self.good()
        data = bytearray(S.dcbor(PAYLOAD))
        allowed, reason, out = self.gate().authorize_bytes(data, p, r, now=NOW)
        self.assertEqual((allowed, reason), (True, "ok"))
        self.assertIs(type(out), bytes)
        self.assertEqual(out, bytes(data))
        data[-1] ^= 1                                               # caller mutates its buffer afterwards
        self.assertEqual(S.H(out), p["body"]["payload_digest"])     # the returned copy is unaffected

    def test_modified_or_non_canonical_bytes_are_denied(self):
        p, r = self.good()
        canonical = S.dcbor(PAYLOAD)
        items = sorted(PAYLOAD.items(), reverse=True)                # same map, keys out of order
        unsorted = bytes([0xa0 + len(items)]) + b"".join(S.dcbor(k) + S.dcbor(v) for k, v in items)
        self.assertEqual(cbor2.loads(unsorted), PAYLOAD)
        cases = {"unsorted map": (unsorted, "payload_not_canonical"),
                 "trailing byte": (canonical + b"\x00", "payload_not_canonical"),
                 "not bytes": (PAYLOAD, "payload_not_canonical"),
                 "text": (canonical.hex(), "payload_not_canonical"),
                 "changed amount": (S.dcbor(dict(PAYLOAD, amount=5001)), "payload_mismatch")}
        for name, (data, why) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.gate().authorize_bytes(data, p, r, now=NOW), (False, why, None))

    def test_denial_without_log_still_denies(self):
        g = self.gate()
        p, r = self.good()
        g.store.db.close()
        self.assertEqual(g.authorize_bytes(b"\xff", p, r, now=NOW), (False, "deny_unlogged", None))
        self.assertEqual(g.authorize_bytes(S.dcbor(PAYLOAD), p, r, now=NOW), (False, "deny_unlogged", None))


if __name__ == "__main__":
    unittest.main()
