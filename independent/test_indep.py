"""Tests for sar_indep derived from SARWP v1.1 sections 3-4 and DECISIONS.md.

Each test isolates one denial cause by using fixed timestamps and checking the
reason string, so a test cannot pass "for the wrong reason".
"""
import copy
import hashlib
import unittest

import cbor2

import sar_indep as S
from sar_indep import MAX_FUTURE_SKEW

T0 = 1_800_000_000
PAYLOAD = {"action_type": "wire_transfer", "source_account": "HR01",
           "destination_account": "DE00", "amount": 5000, "currency": "EUR",
           "execution_time": "2027-01-01T00:00:00Z", "transaction_id": "tx-1"}


class Base(unittest.TestCase):
    def setUp(self):
        self.ak, self.apub = S.new_keypair()
        self.o1, self.opub1 = S.new_keypair()
        self.o2, self.opub2 = S.new_keypair()
        self.o3, self.opub3 = S.new_keypair()
        self.policy = {"policy_id": "p1", "quorum": 1,
                       "authorized_agents": {"agent-1": self.apub},
                       "authorized_overseers": {"ov-1": self.opub1, "ov-2": self.opub2,
                                                "ov-3": self.opub3}}
        self.store = S.Store()
        self.gate = S.Gate(self.policy, self.store)

    def prop(self, payload=None, nonce="n1", ttl=600, now=T0, policy_id="p1"):
        return S.make_proposal(self.ak, "agent-1", payload or PAYLOAD, ttl=ttl,
                               nonce=nonce, policy_id=policy_id, now=now)

    def rat(self, p, key=None, oid="ov-1", verdict="APPROVED", ttl=300, now=T0 + 10):
        return S.ratify(key or self.o1, oid, p, verdict, ttl=ttl, now=now)

    def deny(self, payload, p, rs, now=T0 + 20, why=None, gate=None):
        ok, reason = (gate or self.gate).authorize(payload, p, rs, now=now)
        self.assertFalse(ok, reason)
        self.assertTrue(reason.startswith("DENY"), reason)
        if why:
            self.assertIn(why, reason)
        return reason

    def allow(self, payload, p, rs, now=T0 + 20):
        ok, reason = self.gate.authorize(payload, p, rs, now=now)
        self.assertTrue(ok, reason)


class Encoding(Base):
    """Paper 4.4: deterministic CBOR, stable digest."""

    def test_key_order_independent(self):
        a = {"b": 1, "a": 2, 10: 3, -1: 4}
        b = dict(reversed(list(a.items())))
        self.assertEqual(S.dcbor(a), S.dcbor(b))
        self.assertEqual(S.payload_digest(a), S.payload_digest(b))

    def test_bytewise_key_order(self):
        # shorter encodings sort first in bytewise order of encoded keys
        enc = S.dcbor({"aa": 0, "b": 0, 100: 0, 1: 0})
        self.assertEqual(enc, bytes.fromhex("a4" "0100" "186400" "616200" "62616100"))
        dec_keys = list(cbor2.loads(enc).keys())
        self.assertEqual(dec_keys, [1, 100, "b", "aa"])

    def test_shortest_heads(self):
        self.assertEqual(S.dcbor(23), b"\x17")
        self.assertEqual(S.dcbor(24), b"\x18\x18")
        self.assertEqual(S.dcbor(256), b"\x19\x01\x00")
        self.assertEqual(S.dcbor(-1), b"\x20")
        self.assertEqual(S.dcbor(2 ** 32), b"\x1b" + (2 ** 32).to_bytes(8, "big"))

    def test_matches_cbor2_canonical(self):
        v = {"z": [1, -500, b"\x00", "x", {3: None, 2: True}], "a": 2 ** 40}
        self.assertEqual(S.dcbor(v), cbor2.dumps(v, canonical=True))

    def test_floats_rejected(self):
        with self.assertRaises(ValueError):
            S.dcbor({"amount": 5000.0})

    def test_execution_relevant_change_changes_digest(self):
        for k in PAYLOAD:
            t = copy.deepcopy(PAYLOAD)
            t[k] = t[k] + 1 if isinstance(t[k], int) else t[k] + "x"
            self.assertNotEqual(S.payload_digest(t), S.payload_digest(PAYLOAD), k)

    def test_strict_decoder(self):
        self.assertEqual(S.dcbor_decode_strict(b"\x18\x18"), 24)
        for bad in (b"\x18\x01",            # non-shortest
                    b"\x9f\x01\xff",        # indefinite array
                    b"\xa2\x61b\x01\x61a\x02",  # unsorted keys
                    b"\xa2\x61a\x01\x61a\x02",  # duplicate keys
                    b"\xf9\x3c\x00",        # float
                    b"\x01\x01"):           # trailing data
            with self.assertRaises(ValueError, msg=bad.hex()):
                S.dcbor_decode_strict(bad)


try:
    from hypothesis import given, settings, strategies as st

    _scalar = st.one_of(st.integers(-2 ** 64, 2 ** 64 - 1), st.binary(max_size=40),
                        st.text(max_size=20), st.booleans(), st.none())
    _value = st.recursive(_scalar, lambda c: st.one_of(
        st.lists(c, max_size=5),
        st.dictionaries(st.one_of(st.integers(-1000, 1000), st.text(max_size=8)), c,
                        max_size=5)), max_leaves=25)

    class Properties(unittest.TestCase):
        @settings(max_examples=300, deadline=None, database=None)
        @given(_value)
        def test_roundtrip_strict(self, v):
            enc = S.dcbor(v)
            self.assertEqual(S.dcbor(S.dcbor_decode_strict(enc)), enc)

        @settings(max_examples=200, deadline=None, database=None)
        @given(st.dictionaries(st.one_of(st.integers(-10 ** 6, 10 ** 6), st.text(max_size=6)),
                               st.integers(-2 ** 63, 2 ** 63), min_size=2, max_size=8))
        def test_map_keys_bytewise_sorted(self, d):
            enc = S.dcbor(d)
            keys = [S.dcbor(k) for k in cbor2.loads(enc).keys()]
            self.assertEqual(keys, sorted(keys))
            self.assertEqual(enc, S.dcbor(dict(reversed(list(d.items())))))
except ImportError:  # pragma: no cover
    pass


class Wire(Base):
    """Fixed wire format: COSE_Sign1 tag 18, Ed25519 (-19), kid, content type."""

    def test_proposal_shape(self):
        p = self.prop()
        self.assertEqual(set(p["body"]), S.PROPOSAL_KEYS)
        hdr = cbor2.loads(p["protected"])
        self.assertEqual(hdr, {1: -19, 3: S.PROPOSAL_CT, 4: b"agent-1"})
        self.assertEqual(p["body"]["payload_digest"],
                         hashlib.sha256(S.dcbor(PAYLOAD)).digest())
        rest = {k: v for k, v in p["body"].items() if k != "proposal_id"}
        self.assertEqual(p["body"]["proposal_id"],
                         hashlib.sha256(S.dcbor(rest)).hexdigest()[:32])
        self.assertEqual(p["body"]["expires_at"], T0 + 600)

    def test_ratification_shape(self):
        p = self.prop()
        r = self.rat(p)
        self.assertEqual(set(r["body"]), S.RATIFICATION_KEYS)
        self.assertEqual(r["body"]["proposal_digest"],
                         hashlib.sha256(S.to_cose(p)).digest())
        self.assertEqual(cbor2.loads(r["protected"])[3], S.RATIFICATION_CT)

    def test_cose_roundtrip_and_structure(self):
        p = self.prop()
        c = S.to_cose(p)
        tag = cbor2.loads(c)
        self.assertEqual(tag.tag, 18)
        self.assertEqual(tag.value[1], {})
        self.assertEqual(S.from_cose(c), p)
        self.assertEqual(S.to_cose(S.from_cose(c)), c)

    def test_signature_is_cose_sig_structure(self):
        p = self.prop()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.apub))
        pub.verify(bytes.fromhex(p["sig"]),
                   cbor2.dumps(["Signature1", p["protected"], b"",
                                S.dcbor(p["body"])], canonical=True))

    def test_from_cose_rejects_unprotected_headers(self):
        p = self.prop()
        bad = cbor2.dumps(cbor2.CBORTag(18, [p["protected"], {4: b"x"},
                                             S.dcbor(p["body"]), bytes.fromhex(p["sig"])]),
                          canonical=True)
        with self.assertRaises(ValueError):
            S.from_cose(bad)

    def test_from_cose_rejects_nondeterministic(self):
        p = self.prop()
        body = S.dcbor(p["body"])
        # re-encode the body bstr with a non-shortest length head
        good = S.to_cose(p)
        i = good.index(body)
        n = len(body)
        head = bytes([0x59]) + n.to_bytes(2, "big")  # 2-byte length for short body
        self.assertLess(n, 256)
        old_head = bytes([0x58, n])
        self.assertEqual(good[i - 2:i], old_head)
        bad = good[:i - 2] + head + good[i:]
        with self.assertRaises(ValueError):
            S.from_cose(bad)

    def test_from_cose_rejects_untagged(self):
        p = self.prop()
        raw = S.dcbor([p["protected"], {}, S.dcbor(p["body"]), bytes.fromhex(p["sig"])])
        with self.assertRaises(ValueError):
            S.from_cose(raw)


class Gating(Base):
    """Paper 4.6 phase 5 and 4.7 enumerated denial conditions."""

    def test_happy_path(self):
        p = self.prop()
        self.allow(PAYLOAD, p, [self.rat(p)])

    def test_missing_proposal(self):
        self.deny(PAYLOAD, None, [], why="missing proposal")

    def test_missing_ratification(self):
        self.deny(PAYLOAD, self.prop(), [], why="missing ratification")
        self.deny(PAYLOAD, self.prop(), None, why="missing ratification")

    def test_invalid_agent_signature(self):
        p = self.prop()
        r = self.rat(p)
        p2 = copy.deepcopy(p)
        p2["sig"] = ("0" if p["sig"][0] != "0" else "1") + p["sig"][1:]
        # ratification no longer binds to p2 either, but the signature check runs first
        self.deny(PAYLOAD, p2, [r], why="invalid signature (agent_id")

    def test_proposal_signed_by_unauthorized_agent(self):
        rogue, _ = S.new_keypair()
        p = S.make_proposal(rogue, "agent-1", PAYLOAD, ttl=600, now=T0)
        self.deny(PAYLOAD, p, [self.rat(p)], why="invalid signature")
        p = S.make_proposal(rogue, "agent-x", PAYLOAD, ttl=600, now=T0)
        self.deny(PAYLOAD, p, [self.rat(p)], why="not authorized")

    def test_invalid_overseer_signature(self):
        p = self.prop()
        r = self.rat(p)
        r["sig"] = "11" * 64
        self.deny(PAYLOAD, p, [r], why="invalid signature (overseer_id")

    def test_forged_overseer_identity(self):
        # 4.8: attacker signs with own key, claims an authorized overseer id
        attacker, _ = S.new_keypair()
        p = self.prop()
        self.deny(PAYLOAD, p, [S.ratify(attacker, "ov-1", p, now=T0 + 10)],
                  why="invalid signature")

    def test_agent_cannot_self_ratify(self):
        p = self.prop()
        self.deny(PAYLOAD, p, [S.ratify(self.ak, "agent-1", p, now=T0 + 10)],
                  why="not authorized")

    def test_body_mutation_after_signing(self):
        p = self.prop()
        r = self.rat(p)
        r["body"]["valid_until"] += 1000
        self.deny(PAYLOAD, p, [r], why="invalid signature")

    def test_kid_mismatch(self):
        p = self.prop()
        r = self.rat(p)
        r2 = copy.deepcopy(r)
        r2["protected"] = S.dcbor({1: -19, 3: S.RATIFICATION_CT, 4: b"ov-2"})
        self.deny(PAYLOAD, p, [r2], why="kid does not match")

    def test_wrong_content_type(self):
        p = self.prop()
        # a proposal presented as a ratification
        self.deny(PAYLOAD, p, [p], why="wrong content type")

    def test_wrong_alg(self):
        p = self.prop()
        p2 = copy.deepcopy(p)
        p2["protected"] = S.dcbor({1: -8, 3: S.PROPOSAL_CT, 4: b"agent-1"})
        self.deny(PAYLOAD, p2, [self.rat(p)], why="unsupported algorithm")

    def test_rejected_verdict(self):
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p, verdict="REJECTED")], why="rejected")

    def test_rejection_vetoes_quorum(self):
        p = self.prop()
        rs = [self.rat(p), self.rat(p, self.o2, "ov-2"),
              self.rat(p, self.o3, "ov-3", verdict="REJECTED")]
        self.deny(PAYLOAD, p, rs, why="rejected")

    def test_unknown_verdict(self):
        p = self.prop()
        for v in ("approved", "APPROVED ", "YES", ""):
            self.deny(PAYLOAD, p, [self.rat(p, verdict=v)], why="unknown verdict")

    def test_insufficient_quorum(self):
        self.policy["quorum"] = 2
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p)], why="insufficient quorum")
        self.allow(PAYLOAD, p, [self.rat(p), self.rat(p, self.o2, "ov-2")])

    def test_duplicate_overseer_does_not_reach_quorum(self):
        self.policy["quorum"] = 2
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p), self.rat(p, now=T0 + 11)],
                  why="duplicate ratification")
        self.deny(PAYLOAD, p, [self.rat(p), self.rat(p)], why="duplicate")

    def test_expired_proposal(self):
        p = self.prop(ttl=100)
        r = self.rat(p, ttl=10_000)
        self.deny(PAYLOAD, p, [r], now=T0 + 100, why="proposal expired")
        self.allow(PAYLOAD, p, [r], now=T0 + 99)

    def test_expired_ratification(self):
        p = self.prop(ttl=10_000)
        r = self.rat(p, ttl=50)  # reviewed T0+10, valid until T0+60
        self.deny(PAYLOAD, p, [r], now=T0 + 60, why="ratification expired")
        self.allow(PAYLOAD, p, [r], now=T0 + 59)

    def test_expired_ratification_poisons_set(self):
        # D4: an expired APPROVED ratification denies, even if others suffice
        p = self.prop(ttl=10_000)
        rs = [self.rat(p, ttl=5000), self.rat(p, self.o2, "ov-2", ttl=5)]
        self.deny(PAYLOAD, p, rs, now=T0 + 100, why="ratification expired")

    def test_future_dated_proposal(self):
        p = self.prop(now=T0 + 1000)
        r = self.rat(p, now=T0 + 1000)
        self.deny(PAYLOAD, p, [r], now=T0 + 1000 - MAX_FUTURE_SKEW - 1, why="future-dated")  # amended: S1 skew

    def test_future_dated_ratification(self):
        p = self.prop()
        r = self.rat(p, now=T0 + 20 + MAX_FUTURE_SKEW + 1)  # amended: S1 skew
        self.deny(PAYLOAD, p, [r], now=T0 + 20, why="ratification is future-dated")

    def test_ratification_predating_proposal(self):
        p = self.prop(now=T0)
        r = self.rat(p, now=T0 - 1, ttl=1000)
        self.deny(PAYLOAD, p, [r], now=T0 + 20, why="predates proposal")

    def test_ratification_after_proposal_expiry(self):
        p = self.prop(ttl=100)
        r = self.rat(p, now=T0 + 100)
        self.deny(PAYLOAD, p, [r], now=T0 + 100, why="after proposal expiry")

    def test_zero_ttl_never_valid(self):
        p = self.prop(ttl=0)
        self.deny(PAYLOAD, p, [self.rat(p, now=T0)], now=T0, why="interval empty")

    def test_payload_substitution(self):
        # 4.9: every execution-relevant field
        for k in PAYLOAD:
            p = self.prop(nonce="n-" + k)
            t = copy.deepcopy(PAYLOAD)
            t[k] = "ATTACKER"
            self.deny(t, p, [self.rat(p)], why="payload digest mismatch")
        p = self.prop(nonce="extra")
        t = dict(PAYLOAD, memo="added")
        self.deny(t, p, [self.rat(p)], why="payload digest mismatch")

    def test_unencodable_runtime_payload(self):
        p = self.prop()
        self.deny(dict(PAYLOAD, amount=5000.0), p, [self.rat(p)], why="not canonically")

    def test_ratification_bound_to_other_proposal(self):
        # I2: a ratification cannot be detached and applied to another proposal
        p1 = self.prop(nonce="a")
        p2 = self.prop(nonce="b")
        self.deny(PAYLOAD, p2, [self.rat(p1)], why="not bound to this proposal")

    def test_policy_id_mismatch(self):
        p = self.prop(policy_id="p2")
        self.deny(PAYLOAD, p, [self.rat(p)], why="policy_id does not match")

    def test_tampered_proposal_id(self):
        p = self.prop()
        p["body"]["proposal_id"] = "0" * 32
        p = S._sign(self.ak, S.PROPOSAL_CT, "agent-1", p["body"])  # validly re-signed
        self.deny(PAYLOAD, p, [self.rat(p)], why="proposal_id is not derived")

    def test_extra_body_field_rejected(self):
        p = self.prop()
        body = dict(p["body"], approved=True)
        p = S._sign(self.ak, S.PROPOSAL_CT, "agent-1", body)
        self.deny(PAYLOAD, p, [self.rat(p)], why="unexpected or missing fields")

    def test_wrong_version(self):
        p = self.prop()
        body = dict(p["body"], v=2)
        body["proposal_id"] = S._compute_proposal_id(body)
        p = S._sign(self.ak, S.PROPOSAL_CT, "agent-1", body)
        self.deny(PAYLOAD, p, [self.rat(p)], why="version")

    def test_garbage_inputs_never_raise(self):
        p = self.prop()
        r = self.rat(p)
        junk = [None, 1, "x", b"x", [], {}, {"protected": 1, "body": 2, "sig": 3},
                {"protected": b"\xff", "body": {}, "sig": "00" * 64}]
        for j in junk:
            self.deny(PAYLOAD, j, [r])
            self.deny(PAYLOAD, p, [j])
            self.deny(PAYLOAD, p, j)
        self.deny(PAYLOAD, p, [r], now="soon", why="invalid evaluation time")
        self.deny(PAYLOAD, p, [r], now=float("nan"))

    def test_no_application_state_fallback(self):
        # 4.8: an "approved = true" flag is not authorization
        p = self.prop()
        self.deny(PAYLOAD, p, [{"approved": True}])

    def test_inputs_snapshotted(self):
        # mutation of caller dicts after a decision cannot change the logged outcome
        p = self.prop()
        r = self.rat(p)
        self.allow(PAYLOAD, p, [r])
        self.assertTrue(self.store.verify_chain())


class Policy(Base):
    """4.5.3 / 4.7: invalid or unrecognized policy -> deny (D8-D11)."""

    def check_bad(self, mutate):
        pol = copy.deepcopy(self.policy)
        mutate(pol)
        g = S.Gate(pol, S.Store())
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p)], why="invalid policy", gate=g)
        self.assertFalse(S.verify_record_offline(p, [self.rat(p)], pol))

    def test_quorum_zero(self):
        self.check_bad(lambda p: p.update(quorum=0))

    def test_quorum_bool(self):
        self.check_bad(lambda p: p.update(quorum=True))

    def test_quorum_unsatisfiable(self):
        self.check_bad(lambda p: p.update(quorum=4))

    def test_no_overseers(self):
        self.check_bad(lambda p: p.update(authorized_overseers={}))

    def test_no_agents(self):
        self.check_bad(lambda p: p.update(authorized_agents={}))

    def test_bad_key(self):
        self.check_bad(lambda p: p["authorized_overseers"].update({"ov-1": "zz"}))

    def test_shared_overseer_key(self):
        self.check_bad(lambda p: p["authorized_overseers"].update({"ov-2": self.opub1}))

    def test_role_overlap(self):
        self.check_bad(lambda p: p["authorized_overseers"].update({"ov-3": self.apub}))

    def test_unknown_constraint_refused(self):
        self.check_bad(lambda p: p.update(permitted_action_types=["wire_transfer"]))

    def test_missing_policy_id(self):
        self.check_bad(lambda p: p.pop("policy_id"))

    def test_not_a_dict(self):
        g = S.Gate(None, S.Store())
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p)], why="invalid policy", gate=g)

    def test_overseer_removed_from_policy(self):
        p = self.prop()
        r = self.rat(p)
        del self.policy["authorized_overseers"]["ov-1"]
        self.deny(PAYLOAD, p, [r], why="not authorized")


class Replay(Base):
    """4.10: proposal consumed at most once; nonce unique per policy domain;
    transaction identifier maps to one successful execution."""

    def test_same_evidence_twice(self):
        p = self.prop()
        r = self.rat(p)
        self.allow(PAYLOAD, p, [r])
        self.deny(PAYLOAD, p, [r], why="replay")

    def test_fresh_ratification_does_not_reopen(self):
        p = self.prop()
        self.allow(PAYLOAD, p, [self.rat(p)])
        self.deny(PAYLOAD, p, [self.rat(p, now=T0 + 15)], why="replay")

    def test_nonce_reuse_new_proposal(self):
        p = self.prop(nonce="same")
        self.allow(PAYLOAD, p, [self.rat(p)])
        p2 = self.prop(nonce="same", now=T0 + 1, payload=dict(PAYLOAD, transaction_id="tx-2"))
        self.deny(dict(PAYLOAD, transaction_id="tx-2"), p2, [self.rat(p2, now=T0 + 11)],
                  why="nonce")

    def test_transaction_id_reuse(self):
        p = self.prop(nonce="a")
        self.allow(PAYLOAD, p, [self.rat(p)])
        p2 = self.prop(nonce="b")
        self.deny(PAYLOAD, p2, [self.rat(p2)], why="transaction_id")

    def test_denial_does_not_consume(self):
        self.policy["quorum"] = 2
        p = self.prop()
        self.deny(PAYLOAD, p, [self.rat(p)])
        self.allow(PAYLOAD, p, [self.rat(p), self.rat(p, self.o2, "ov-2")])

    def test_shared_store_across_gates(self):
        p = self.prop()
        r = self.rat(p)
        g2 = S.Gate(self.policy, self.store)
        self.allow(PAYLOAD, p, [r])
        self.deny(PAYLOAD, p, [r], gate=g2, why="replay")

    def test_deleting_consumed_row_does_not_reenable(self):
        p = self.prop()
        r = self.rat(p)
        self.allow(PAYLOAD, p, [r])
        self.store.db.execute("DELETE FROM consumed")
        self.deny(PAYLOAD, p, [r], why="replay")

    def test_persistent_store(self):
        import os
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s.db")
        p = self.prop()
        r = self.rat(p)
        g = S.Gate(self.policy, S.Store(path))
        self.assertTrue(g.authorize(PAYLOAD, p, [r], now=T0 + 20)[0])
        g2 = S.Gate(self.policy, S.Store(path))
        self.assertFalse(g2.authorize(PAYLOAD, p, [r], now=T0 + 20)[0])
        os.remove(path)
        os.rmdir(d)


class Log(Base):
    """R2 / T1: tamper-evident append-only decision history."""

    def fill(self):
        p = self.prop()
        r = self.rat(p)
        self.allow(PAYLOAD, p, [r])
        self.deny(PAYLOAD, p, [r])
        self.deny(PAYLOAD, None, [])
        self.assertTrue(self.store.verify_chain())

    def test_every_decision_logged(self):
        self.fill()
        rows = self.store.db.execute("select record from log order by seq").fetchall()
        self.assertEqual([r[0].split()[0] for r in rows], ["ALLOW", "DENY", "DENY"])

    def test_modify(self):
        self.fill()
        self.store.db.execute("update log set record = replace(record,'DENY','ALLOW') where seq=2")
        self.assertFalse(self.store.verify_chain())

    def test_delete_middle(self):
        self.fill()
        self.store.db.execute("delete from log where seq=2")
        self.assertFalse(self.store.verify_chain())

    def test_truncate_tail_is_not_detected_by_chain_alone(self):
        # documented limitation (D17): tail truncation needs an external anchor
        self.fill()
        self.store.db.execute("delete from log where seq=3")
        self.assertTrue(self.store.verify_chain())

    def test_rehash_without_relink(self):
        self.fill()
        rec = self.store.db.execute("select record, prev from log where seq=2").fetchone()
        new = rec[0].replace("DENY", "ALLOW", 1)
        h = S._link_hash(2, rec[1], new)
        self.store.db.execute("update log set record=?, hash=? where seq=2", (new, h))
        self.assertFalse(self.store.verify_chain())  # seq 3 prev no longer matches

    def test_broken_chain_blocks_allow(self):
        self.fill()
        self.store.db.execute("update log set record='DENY x' where seq=2")
        p = self.prop(nonce="fresh", payload=dict(PAYLOAD, transaction_id="tx-9"))
        self.deny(dict(PAYLOAD, transaction_id="tx-9"), p, [self.rat(p)],
                  why="integrity check failed")


class Offline(Base):
    """4.12: verification from artifacts + policy only."""

    def test_valid(self):
        p = self.prop()
        r = [self.rat(p)]
        self.assertTrue(S.verify_record_offline(p, r, self.policy))

    def test_survives_cose_transport(self):
        p = self.prop()
        r = [self.rat(p)]
        p2 = S.from_cose(S.to_cose(p))
        r2 = [S.from_cose(S.to_cose(x)) for x in r]
        self.assertTrue(S.verify_record_offline(p2, r2, self.policy))

    def test_independent_of_wallclock_and_store(self):
        p = self.prop(now=1000, ttl=60)
        r = [self.rat(p, now=1010, ttl=60)]
        self.assertTrue(S.verify_record_offline(p, r, self.policy))
        self.assertTrue(S.verify_record_offline(p, r, self.policy, at=1030))
        self.assertFalse(S.verify_record_offline(p, r, self.policy, at=1060))
        # amended in round 2 (D5, SEMANTICS.md S2): the window [1010, 1060) is accepted from
        # 1010 - MAX_FUTURE_SKEW, exactly as the gate would accept it
        self.assertTrue(S.verify_record_offline(p, r, self.policy, at=1010 - MAX_FUTURE_SKEW))
        self.assertFalse(S.verify_record_offline(p, r, self.policy, at=1010 - MAX_FUTURE_SKEW - 1))

    def test_rejection_not_an_authorization(self):
        p = self.prop()
        self.assertFalse(S.verify_record_offline(p, [self.rat(p, verdict="REJECTED")],
                                                 self.policy))

    def test_quorum_and_binding(self):
        self.policy["quorum"] = 2
        p = self.prop()
        self.assertFalse(S.verify_record_offline(p, [self.rat(p)], self.policy))
        other = self.prop(nonce="zz")
        self.assertFalse(S.verify_record_offline(
            p, [self.rat(p), self.rat(other, self.o2, "ov-2")], self.policy))
        self.assertTrue(S.verify_record_offline(
            p, [self.rat(p), self.rat(p, self.o2, "ov-2")], self.policy))

    def test_every_byte_of_signature_matters(self):
        p = self.prop()
        r = self.rat(p)
        for i in range(0, 128, 16):
            r2 = copy.deepcopy(r)
            c = r2["sig"][i]
            r2["sig"] = r2["sig"][:i] + ("0" if c != "0" else "1") + r2["sig"][i + 1:]
            self.assertFalse(S.verify_record_offline(p, [r2], self.policy))

    def test_uppercase_hex_sig_rejected(self):
        p = self.prop()
        r = self.rat(p)
        r["sig"] = r["sig"].upper()
        if r["sig"] != r["sig"].lower():
            self.assertFalse(S.verify_record_offline(p, [r], self.policy))

    def test_disjoint_validity_windows(self):
        self.policy["quorum"] = 2
        p = self.prop(ttl=1000)
        rs = [self.rat(p, now=T0 + 10, ttl=10), self.rat(p, self.o2, "ov-2", now=T0 + 50, ttl=10)]
        self.assertFalse(S.verify_record_offline(p, rs, self.policy))

    def test_never_raises(self):
        for args in [(None, None, None), (1, 2, 3), ({}, [{}], {})]:
            self.assertFalse(S.verify_record_offline(*args))


if __name__ == "__main__":
    unittest.main()
