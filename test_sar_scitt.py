"""Tests for sar_scitt: Transparency Service, Receipts and Receipt-gated execution (profile
spec/sar-profile.md Sections 15-18; requirement ids in the docstrings).

    python3 -m unittest -v test_sar_scitt      (SAR_DEEP=1 / SAR_SEEDS=a,b for the differential)
"""
import hashlib
import os
import random
import sys
import threading
import unittest

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sar_cose as S
import sar_scitt as X
import test_sar_properties as T

NOW = 1_800_000_000
TAU = S.MAX_CLOCK_SKEW
PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00",
           "transaction_id": "tx-1"}
K = {n: S.new_keypair() for n in ("agent", "ov1", "ov2", "ov3", "evil")}
TS_KEY, EVIL_TS_KEY = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
DEEP = os.environ.get("SAR_DEEP") == "1"
EXTRA_SEEDS = T.EXTRA_SEEDS


def policy(quorum=1, overseers=("ov1", "ov2", "ov3")):
    return {"policy_id": "p1", "quorum": quorum, "authorized_agents": {"agent": K["agent"][1]},
            "authorized_overseers": {o: K[o][1] for o in overseers}}


def statements(nonce="n1", ttl=3600, issued=NOW, rats=(("ov1", "APPROVED", 10, 3600),), payload=PAYLOAD):
    p = S.make_proposal(K["agent"][0], "agent", payload, ttl=ttl, nonce=nonce, now=issued)
    rs = [S.ratify(K[o][0], o, p, verdict=v, ttl=t, now=issued + off) for o, v, off, t in rats]
    return p, rs


def flip(b, i=-1):
    b = bytearray(b)
    b[i] ^= 1
    return bytes(b)


class Env:
    """One TS, one trusted log, one receipt-gated gate on a fresh store."""

    def __init__(self, pol=None, max_age=X.MAX_RECEIPT_AGE):
        self.policy = pol or policy()
        self.ts = X.TransparencyService("log-1", TS_KEY, lambda: self.policy)
        self.trusted = {"log-1": self.ts.public_key}
        self.store = S.Store()
        self.gate = X.ReceiptGate(self.policy, self.store, self.trusted, max_receipt_age=max_age)

    def register(self, p, rs, t, kind="authorization", pid="p1"):
        return self.ts.register(X.make_request(kind, pid, p, rs), now=t)

    def run(self, p, rs, receipt, now, payload=PAYLOAD):
        return self.gate.authorize_bytes(S.dcbor(payload), p, rs, receipt, now=now)


def receipt_with(entries, index, reg, key=TS_KEY, log_id="log-1", size=None, index_in_proof=None, path=None,
                 protected=None, payload=None, sig=None):
    """Hand-built receipt for negative tests."""
    size = len(entries) if size is None else size
    t = X._Tree(entries)
    root = t.mth(0, len(entries))
    prot = protected or S.dcbor({1: -19, 4: log_id.encode(), 395: 1, 15: {1: log_id, 6: reg}})
    proof = S.dcbor([size, index if index_in_proof is None else index_in_proof,
                     t.path(index, 0, len(entries)) if path is None else path])
    s = key.sign(S.dcbor(["Signature1", prot, b"", root])) if sig is None else sig
    return S.dcbor(cbor2.CBORTag(18, [prot, {396: {-1: [proof]}}, payload, s]))


class EndToEnd(unittest.TestCase):
    def test_proposal_ratification_registration_receipt_gate_execution_of_exact_bytes(self):
        """SAR-REQ-120, 125, 130, 132, 133, 137, 071: the whole path, and the executor receives exactly
        the registered-and-ratified payload bytes."""
        env = Env()
        p, rs = statements()
        reg = env.register(p, rs, NOW + 15)
        self.assertTrue(reg.ok, reg.reason)
        executed = []
        allowed, reason, exact = env.run(p, rs, reg.receipt, NOW + 20)
        self.assertTrue(allowed, reason)
        executed.append(exact)
        self.assertEqual(executed, [S.dcbor(PAYLOAD)])
        self.assertIsInstance(exact, bytes)
        tar = X.make_tar(p, rs, "p1", reg.receipt)
        p2, rs2, pref, rec2 = X.parse_tar(tar)
        self.assertTrue(X.verify_tar_offline(p2, rs2, rec2, env.policy, env.trusted))
        self.assertTrue(X.verify_tar_offline(p2, rs2, rec2, env.policy, env.trusted, at=X.receipt_registered_at(rec2)))
        self.assertEqual(pref, "p1")

    def test_receipt_from_a_larger_log_and_refreshed_receipt(self):
        """SAR-REQ-126, 127: entry in the middle of a log; a receipt re-issued at a later tree size verifies too."""
        env = Env()
        for i in range(5):
            q, qs = statements(nonce=f"other{i}")
            self.assertTrue(env.register(q, qs, NOW + 11).ok)
        p, rs = statements()
        reg = env.register(p, rs, NOW + 15)
        for i in range(6):
            q, qs = statements(nonce=f"later{i}")
            self.assertTrue(env.register(q, qs, NOW + 16).ok)
        later = env.ts.get_receipt(reg.index)
        self.assertNotEqual(later, reg.receipt)
        self.assertTrue(env.run(p, rs, later, NOW + 20)[0])
        self.assertFalse(env.run(p, rs, reg.receipt, NOW + 21)[0], "replay with the older receipt")

    def test_receipt_gate_without_receipt_denies_and_logs(self):
        """SAR-REQ-132, 090."""
        env = Env()
        p, rs = statements()
        env.register(p, rs, NOW + 15)
        n = env.store._tip()[0]
        allowed, reason, _ = env.run(p, rs, None, NOW + 20)
        self.assertEqual((allowed, reason), (False, "receipt_missing"))
        self.assertEqual(env.store._tip()[0], n + 1)
        self.assertTrue(S.Gate(env.policy, S.Store()).authorize_bytes(S.dcbor(PAYLOAD), p, rs, now=NOW + 20)[0],
                        "the plain gate would have allowed: the receipt is what made the difference")


class ReceiptAdversarial(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.p, self.rs = statements()
        self.reg = self.env.register(self.p, self.rs, NOW + 15)
        self.assertTrue(self.reg.ok)

    def deny(self, receipt, reason=None, p=None, rs=None, now=NOW + 20, payload=PAYLOAD):
        allowed, why, _ = self.env.run(p or self.p, rs or self.rs, receipt, now, payload=payload)
        self.assertFalse(allowed)
        if reason:
            self.assertEqual(why, reason)
        return why

    def test_forged_receipt_signed_by_another_key(self):
        """SAR-REQ-131: a receipt that names the trusted log but is signed by an attacker's key."""
        forged = receipt_with(self.env.ts.entries, self.reg.index, NOW + 15, key=EVIL_TS_KEY)
        self.deny(forged, "receipt_bad_signature")

    def test_receipt_from_an_untrusted_log(self):
        """SAR-REQ-131: a correctly signed receipt from a log the gate does not trust."""
        rogue = X.TransparencyService("log-2", EVIL_TS_KEY, policy())
        r = rogue.register(X.make_request("authorization", "p1", self.p, self.rs), now=NOW + 15)
        self.assertTrue(r.ok)
        self.deny(r.receipt, "receipt_untrusted_log")

    def test_tampered_inclusion_proof(self):
        """SAR-REQ-127, 133."""
        for i in range(5):
            q, qs = statements(nonce=f"o{i}")
            self.env.register(q, qs, NOW + 16)
        rec = self.env.ts.get_receipt(self.reg.index)
        path = X.parse_receipt(rec)["path"]
        bad = receipt_with(self.env.ts.entries, self.reg.index, NOW + 15, path=[flip(path[0])] + path[1:])
        self.deny(bad, "receipt_bad_signature")
        self.assertTrue(self.env.run(self.p, self.rs, rec, NOW + 20)[0])

    def test_structurally_invalid_proofs_that_reproduce_the_signed_root(self):
        """SAR-REQ-127: with one entry the root is the leaf hash, so [1, 1, []] and [2, 0, []] reproduce
        the signed root; only RFC 9162 2.1.3.2's index bound and final-level check reject them."""
        e = self.env.ts.entries
        self.deny(receipt_with(e, 0, NOW + 15, index_in_proof=1, size=1), "receipt_inclusion_failed")
        self.deny(receipt_with(e, 0, NOW + 15, size=2), "receipt_inclusion_failed")
        self.assertFalse(X.verify_inclusion(e[0], 1, 1, [], X.merkle_root(e)))
        self.assertFalse(X.verify_inclusion(e[0], 0, 2, [], X.merkle_root(e)))

    def test_receipt_for_a_different_statement_set(self):
        """SAR-REQ-125, 133: registered {r1}; presented {r1, r2} (also a valid quorum-1 set)."""
        r2 = S.ratify(K["ov2"][0], "ov2", self.p, ttl=3600, now=NOW + 12)
        self.deny(self.reg.receipt, "receipt_bad_signature", rs=self.rs + [r2])
        p2, rs2 = statements(nonce="n2")
        self.deny(self.reg.receipt, "receipt_bad_signature", p=p2, rs=rs2)

    def test_receipt_reused_for_a_different_payload(self):
        """SAR-REQ-137, 070."""
        self.assertEqual(self.deny(self.reg.receipt, payload=dict(PAYLOAD, amount=5001)), "payload_mismatch")

    def test_replay_with_a_valid_receipt(self):
        """SAR-REQ-137, 080."""
        self.assertTrue(self.env.run(self.p, self.rs, self.reg.receipt, NOW + 20)[0])
        self.deny(self.reg.receipt, "replay", now=NOW + 21)

    def test_receipt_header_variants(self):
        """SAR-REQ-130."""
        e = self.env.ts.entries
        for prot in (S.dcbor({1: -8, 4: b"log-1", 395: 1, 15: {1: "log-1", 6: NOW + 15}}),
                     S.dcbor({1: -19, 4: b"log-1", 395: 2, 15: {1: "log-1", 6: NOW + 15}}),
                     S.dcbor({1: -19, 4: b"log-2", 395: 1, 15: {1: "log-1", 6: NOW + 15}}),
                     S.dcbor({1: -19, 3: "x", 4: b"log-1", 395: 1, 15: {1: "log-1", 6: NOW + 15}})):
            self.deny(receipt_with(e, 0, NOW + 15, protected=prot), "receipt_malformed")
        self.deny(receipt_with(e, 0, NOW + 15, payload=X.merkle_root(e)), "receipt_malformed")
        self.deny(receipt_with(e, 0, NOW + 15, sig=b"\0" * 63), "receipt_malformed")
        self.deny(b"\xa0", "receipt_malformed")

    def test_rejection_receipt_never_authorizes(self):
        """SAR-REQ-124, 136: a rejection entry over a set whose bytes contain only approvals is crafted
        by a TS that registers kind 'rejection'; its receipt must not authorize."""
        env = Env()
        p, rs = statements()
        rj = S.ratify(K["ov2"][0], "ov2", p, verdict="REJECTED", ttl=3600, now=NOW + 12)
        r = env.register(p, [rj], NOW + 15, kind="rejection")
        self.assertTrue(r.ok, r.reason)
        entry = X.registration_entry("rejection", "log-1", "p1", p["body"]["proposal_id"],
                                     X.set_digest(S.to_cose(p), [S.to_cose(x) for x in rs]), NOW + 15)
        env.ts.entries.append(entry)  # a TS registering the approval set as a rejection
        rec = env.ts.get_receipt(len(env.ts.entries) - 1)
        allowed, why, _ = env.run(p, rs, rec, NOW + 20)
        self.assertEqual((allowed, why), (False, "receipt_bad_signature"))

    def test_faulty_ts_registered_an_invalid_set(self):
        """SAR-REQ-137: the gate re-evaluates the statements; a valid receipt over a set with a bad
        signature is denied for the statement fault."""
        bad = T._break_sig(self.rs[0])
        entry = X.registration_entry("authorization", "log-1", "p1", self.p["body"]["proposal_id"],
                                     X.set_digest(S.to_cose(self.p), [S.to_cose(bad)]), NOW + 15)
        self.env.ts.entries.append(entry)
        rec = self.env.ts.get_receipt(len(self.env.ts.entries) - 1)
        self.assertEqual(self.deny(rec, p=self.p, rs=[bad]), "bad_ratification")

    def test_offline_tar_verification_rejects_forged_receipts(self):
        """SAR-REQ-139."""
        env = self.env
        self.assertTrue(X.verify_tar_offline(self.p, self.rs, self.reg.receipt, env.policy, env.trusted))
        forged = receipt_with(env.ts.entries, 0, NOW + 15, key=EVIL_TS_KEY)
        self.assertFalse(X.verify_tar_offline(self.p, self.rs, forged, env.policy, env.trusted))
        self.assertFalse(X.verify_tar_offline(self.p, self.rs, None, env.policy, env.trusted))
        self.assertFalse(X.verify_tar_offline(self.p, self.rs, self.reg.receipt, env.policy, {}))


class TrustedTime(unittest.TestCase):
    """Profile 18.1: the TS registration time as a hypothesis for trusted time (SAR-REQ-134, 135, 138)."""

    def setUp(self):
        self.env = Env()
        self.p, self.rs = statements()          # common interval [NOW+10, NOW+3600)

    def receipt_at(self, reg, p=None, rs=None):
        p, rs = p or self.p, rs or self.rs
        e = X.registration_entry("authorization", "log-1", "p1", p["body"]["proposal_id"],
                                 X.set_digest(S.to_cose(p), [S.to_cose(r) for r in rs]), reg)
        return receipt_with([e], 0, reg)

    def check(self, reg, now, expect, p=None, rs=None):
        allowed, why, _ = self.env.run(p or self.p, rs or self.rs, self.receipt_at(reg, p, rs), now)
        self.assertEqual((allowed, why), expect)

    def test_registration_before_validity(self):
        self.check(NOW + 10 - TAU - 1, NOW + 20, (False, "receipt_registration_outside_validity"))
        self.check(NOW + 10 - TAU, NOW + 20, (True, "ok"))

    def test_registration_at_or_after_expiry(self):
        p, rs = statements(ttl=60, rats=(("ov1", "APPROVED", 10, 60),))
        self.check(NOW + 60, NOW + 59, (False, "receipt_registration_outside_validity"), p, rs)

    def test_ts_clock_ahead_of_the_gate(self):
        self.check(NOW + 20 + TAU + 1, NOW + 20, (False, "receipt_from_future"))
        self.check(NOW + 20 + TAU, NOW + 20, (True, "ok"))

    def test_stale_receipt(self):
        self.check(NOW + 15, NOW + 15 + X.MAX_RECEIPT_AGE, (False, "receipt_stale"))
        self.check(NOW + 15, NOW + 15 + X.MAX_RECEIPT_AGE - 1, (True, "ok"))

    def test_ts_clock_behind_backdated_within_validity_is_stale(self):
        self.check(NOW + 12, NOW + 400, (False, "receipt_stale"))

    def test_lying_ts_cannot_extend_execution_beyond_expiry(self):
        """A receipt 'registered' one second before expiry and presented after it: the gate's own clock
        denies. If the gate used registered_at as 'now' (forbidden by SAR-REQ-138), it would allow:
        offline verification at registered_at succeeds."""
        p, rs = statements(ttl=60, rats=(("ov1", "APPROVED", 10, 60),))
        rec = self.receipt_at(NOW + 59, p, rs)
        allowed, why, _ = self.env.run(p, rs, rec, NOW + 100)
        self.assertEqual((allowed, why), (False, "proposal_expired"))
        self.assertTrue(S.verify_record_offline(p, rs, self.env.policy, at=X.receipt_registered_at(rec)))
        self.assertTrue(X.verify_tar_offline(p, rs, rec, self.env.policy, self.env.trusted))

    def test_ts_refuses_registration_outside_validity_by_its_own_clock(self):
        """SAR-REQ-120: S2 at the registration instant, both directions."""
        p, rs = statements(ttl=60, rats=(("ov1", "APPROVED", 10, 60),))
        self.assertTrue(self.env.register(p, rs, NOW + 60).reason.startswith("time_invalid"))
        self.assertTrue(self.env.register(p, rs, NOW + 10 - TAU - 1).reason.startswith("time_invalid"))
        self.assertTrue(self.env.register(p, rs, NOW + 10 - TAU).ok)


class Registration(unittest.TestCase):
    def test_policy_failing_at_the_ts_issues_no_receipt(self):
        """SAR-REQ-120."""
        env = Env(policy(quorum=2))
        p, rs = statements()
        r = env.register(p, rs, NOW + 15)
        self.assertEqual((r.ok, r.reason, r.receipt), (False, "quorum_not_met", None))
        self.assertEqual(env.ts.entries, [])
        evil = S.ratify(K["evil"][0], "evil", p, ttl=3600, now=NOW + 10)
        self.assertEqual(Env().register(p, [evil], NOW + 15).reason, "unauthorized_signer:overseer")
        self.assertEqual(Env().register(p, rs, NOW + 15, pid="p2").reason,
                         "binding_mismatch:request names another policy")
        bad_policy = dict(policy(), quorum=0)
        self.assertEqual(Env(bad_policy).register(p, rs, NOW + 15).reason, "policy_invalid")

    def test_registration_of_a_rejection_and_registered_veto(self):
        """SAR-REQ-123, 124: the rejection is registered; afterwards an authorization that omits it is refused."""
        env = Env()
        p, rs = statements()
        rj = S.ratify(K["ov2"][0], "ov2", p, verdict="REJECTED", ttl=3600, now=NOW + 12)
        r = env.register(p, [rj], NOW + 15, kind="rejection")
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(S.strict_loads(r.entry)["kind"], "rejection")
        self.assertFalse(env.run(p, rs, r.receipt, NOW + 20)[0])
        a = env.register(p, rs, NOW + 16)
        self.assertEqual((a.ok, a.reason), (False, "registration_conflict:a rejection is registered"))

    def test_authorization_request_containing_a_rejection_is_refused(self):
        """SAR-REQ-124 (S6)."""
        p, rs = statements(rats=(("ov1", "APPROVED", 10, 3600), ("ov2", "REJECTED", 12, 3600)))
        self.assertEqual(Env().register(p, rs, NOW + 15).reason, "rejected")

    def test_rejection_request_needs_a_rejected_ratification(self):
        """SAR-REQ-124."""
        p, rs = statements()
        r = Env().register(p, rs, NOW + 15, kind="rejection")
        self.assertFalse(r.ok)
        self.assertTrue(r.reason.startswith("invalid_statement"))

    def test_second_authorization_registration_is_refused(self):
        """SAR-REQ-122."""
        env = Env()
        p, rs = statements()
        self.assertTrue(env.register(p, rs, NOW + 15).ok)
        r2 = S.ratify(K["ov2"][0], "ov2", p, ttl=3600, now=NOW + 12)
        r = env.register(p, rs + [r2], NOW + 16)
        self.assertEqual((r.ok, r.reason), (False, "registration_conflict:already registered"))

    def test_concurrent_registrations_register_exactly_once(self):
        """SAR-REQ-122: 16 threads register the same authorization at once."""
        for _ in range(3):
            env = Env()
            p, rs = statements()
            req = X.make_request("authorization", "p1", p, rs)
            barrier, results = threading.Barrier(16), []

            def worker():
                barrier.wait()
                results.append(env.ts.register(req, now=NOW + 15).ok)
            threads = [threading.Thread(target=worker) for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(sum(results), 1)
            self.assertEqual(len(env.ts.entries), 1)

    def test_malformed_requests_are_refused(self):
        p, rs = statements()
        ts = Env().ts
        good = cbor2.loads(X.make_request("authorization", "p1", p, rs))
        for bad in (dict(good, v=2), dict(good, kind="maybe"), dict(good, ratifications=[]),
                    dict(good, extra=1), {k: v for k, v in good.items() if k != "proposal"}):
            self.assertFalse(ts.register(S.dcbor(bad), now=NOW + 15).ok)
        self.assertFalse(ts.register(b"\xff", now=NOW + 15).ok)
        self.assertFalse(ts.register(S.dcbor(dict(good, proposal=b"\x00")), now=NOW + 15).ok)


class MerkleLog(unittest.TestCase):
    @staticmethod
    def ref_mth(d):
        """Direct transcription of RFC 9162 2.1.1, independent of sar_scitt's cached tree."""
        if not d:
            return hashlib.sha256(b"").digest()
        if len(d) == 1:
            return hashlib.sha256(b"\x00" + d[0]).digest()
        k = 1 << (len(d) - 1).bit_length() - 1
        return hashlib.sha256(b"\x01" + MerkleLog.ref_mth(d[:k]) + MerkleLog.ref_mth(d[k:])).digest()

    def test_roots_and_inclusion_proofs_for_every_index_and_size(self):
        """SAR-REQ-126, 127."""
        leaves = [bytes([i]) * (i + 1) for i in range(33)]
        for n in range(0, 34):
            root = X.merkle_root(leaves[:n])
            self.assertEqual(root, self.ref_mth(leaves[:n]))
            for m in range(n):
                path = X.inclusion_proof(leaves, m, n)
                self.assertTrue(X.verify_inclusion(leaves[m], m, n, path, root))
                self.assertFalse(X.verify_inclusion(leaves[m] + b"x", m, n, path, root))
                if path:
                    self.assertFalse(X.verify_inclusion(leaves[m], m, n, [flip(path[0])] + path[1:], root))
                self.assertFalse(X.verify_inclusion(leaves[m], n, n, path, root))

    def test_consistency_proofs_between_all_tree_sizes(self):
        """SAR-REQ-128: consistency between every pair 0 < m <= n <= 24, and detection of a forked log."""
        leaves = [b"e%d" % i for i in range(24)]
        roots = [X.merkle_root(leaves[:n]) for n in range(25)]
        for n in range(1, 25):
            for m in range(1, n + 1):
                proof = X.consistency_proof(leaves, m, n)
                self.assertTrue(X.verify_consistency(m, n, roots[m], roots[n], proof), (m, n))
                if m < n:
                    self.assertFalse(X.verify_consistency(m, n, roots[m], flip(roots[n]), proof), (m, n))
                    self.assertFalse(X.verify_consistency(m, n, flip(roots[m]), roots[n], proof), (m, n))
        forked = leaves[:10] + [b"forged"] + leaves[11:]
        self.assertFalse(X.verify_consistency(12, 20, roots[12], X.merkle_root(forked[:20]),
                                              X.consistency_proof(forked, 12, 20)))
        self.assertFalse(X.verify_consistency(0, 3, roots[0], roots[3], []))

    def test_signed_checkpoints_and_log_consistency_of_a_running_ts(self):
        """SAR-REQ-128: a monitor retains checkpoints and checks consistency as the log grows."""
        env = Env()
        retained = []
        for i in range(12):
            p, rs = statements(nonce=f"c{i}")
            self.assertTrue(env.register(p, rs, NOW + 15).ok)
            cp = env.ts.checkpoint()
            self.assertTrue(X.verify_checkpoint(cp, env.ts.public_key))
            self.assertFalse(X.verify_checkpoint(dict(cp, size=cp["size"] + 1), env.ts.public_key))
            for old in retained:
                proof = env.ts.consistency(old["size"])
                self.assertTrue(X.verify_consistency(old["size"], cp["size"], bytes.fromhex(old["root"]),
                                                     bytes.fromhex(cp["root"]), proof))
            retained.append(cp)
        # a TS that rewrites an old entry can no longer prove consistency with retained checkpoints
        env.ts.entries[3] = b"rewritten"
        env.ts._tree.cache.clear()
        new = env.ts.checkpoint()
        old = retained[5]
        self.assertFalse(X.verify_consistency(old["size"], new["size"], bytes.fromhex(old["root"]),
                                              bytes.fromhex(new["root"]), env.ts.consistency(old["size"])))


class Differential(unittest.TestCase):
    def test_registration_and_receipt_gate_agree_with_the_model_at_every_bound(self):
        """SAR-REQ-120, 133, 137: for random scenarios (generators of test_sar_properties) and every
        interval bound t, the TS registers at t iff the reference model allows at t, and the receipt
        gate at t with that receipt allows iff the model does."""
        n = 10000 if DEEP else 1000
        for seed in [31337] + EXTRA_SEEDS:
            rng = random.Random(seed)
            instants = registered = 0
            for i in range(n):
                sc = T.random_scenario(rng)
                prop, rats, _ = T.build_artifacts(sc, f"d{i}")
                pol = T._policy(sc["quorum"])
                for t in T.boundary_instants(sc):
                    model = T.model_allows(dict(sc, payload_ok=True), now=t)
                    ts = X.TransparencyService("log-1", TS_KEY, pol)
                    try:
                        req = X.make_request("authorization", "p1", prop, rats)
                    except Exception:  # noqa: BLE001 - an empty ratification set cannot form a request
                        self.assertFalse(model)
                        continue
                    reg = ts.register(req, now=t)
                    self.assertEqual(reg.ok, model, f"seed {seed} scenario {i} t={t - T.NOW}: {reg.reason} {sc}")
                    instants += 1
                    if reg.ok:
                        registered += 1
                        gate = X.ReceiptGate(pol, S.Store(), {"log-1": ts.public_key})
                        allowed, why = gate.authorize(T.PAYLOAD, prop, rats, reg.receipt, now=t)
                        self.assertTrue(allowed, why)
            self.assertGreater(registered, n // 20)
            print(f"\n    scitt differential seed={seed}: {n} scenarios, {instants} instants ({registered} registered), "
                  f"0 disagreements with the model", end=" ")


class SweepGaps(unittest.TestCase):
    """Tests added for live survivors of the first automated mutation sweep over sar_scitt.py
    (tools/mutation_sweep.py --module sar_scitt.py; see tools/EQUIVALENT_MUTANTS.md)."""

    def test_every_index_of_every_log_size_verifies_through_the_receipt_path(self):
        """SAR-REQ-127, 133: the gate's own audit-path walk, for every leaf of logs of size 1..17."""
        env = Env()
        sets = []
        for i in range(17):
            p, rs = statements(nonce=f"all{i}")
            self.assertTrue(env.register(p, rs, NOW + 15).ok)
            sets.append((p, rs))
            n = len(env.ts.entries)
            for j in range(n):
                failure, info = X.verify_receipt(env.ts.get_receipt(j, n), *sets[j], "p1", env.trusted)
                self.assertIsNone(failure, (j, n))
                self.assertEqual((info["leaf_index"], info["tree_size"]), (j, n))
                if j != n - 1:
                    self.assertIsNotNone(X.verify_receipt(env.ts.get_receipt(j, n), *sets[n - 1], "p1", env.trusted)[0])

    def test_receipt_with_trailing_or_missing_path_elements_is_rejected(self):
        """SAR-REQ-127: an audit path with an extra element after the root level, or one element short."""
        env = Env()
        sets = []
        for i in range(5):
            p, rs = statements(nonce=f"tr{i}")
            env.register(p, rs, NOW + 15)
            sets.append((p, rs))
        e = env.ts.entries
        good = X._Tree(e).path(2, 0, 5)
        for path in (good + [b"\x11" * 32], good[:-1]):
            rec = receipt_with(e, 2, NOW + 15, path=path)
            self.assertIsNotNone(X.verify_receipt(rec, *sets[2], "p1", env.trusted)[0])
        root = X.merkle_root(e)
        self.assertFalse(X.verify_inclusion(e[2], 2, 5, good + [b"\x11" * 32], root))
        self.assertTrue(X.verify_inclusion(e[2], 2, 5, good, root))

    def test_receipt_structure_variants_are_rejected(self):
        """SAR-REQ-130: COSE structure, CWT claims, vdp, proof shape."""
        env = Env()
        p, rs = statements()
        reg = env.register(p, rs, NOW + 15)
        prot, unprot, payload, sig = cbor2.loads(reg.receipt).value
        proof = unprot[396][-1][0]
        ok_prot = S.dcbor({1: -19, 4: b"log-1", 395: 1, 15: {1: "log-1", 6: NOW + 15}})
        variants = [
            S.dcbor([prot, unprot, payload, sig]),                                   # untagged
            S.dcbor(cbor2.CBORTag(17, [prot, unprot, payload, sig])),                # wrong tag
            S.dcbor(cbor2.CBORTag(18, [prot, unprot, payload])),                     # 3 elements
            S.dcbor(cbor2.CBORTag(18, [{1: -19}, unprot, payload, sig])),            # protected not bstr
            S.dcbor(cbor2.CBORTag(18, [prot, unprot, payload, "sig"])),              # signature not bstr
            S.dcbor(cbor2.CBORTag(18, [S.dcbor({1: -19, 4: b"log-1", 395: 1, 15: {1: "log-1", 6: NOW + 15, 4: 1}}),
                                       unprot, payload, sig])),                      # extra CWT claim
            S.dcbor(cbor2.CBORTag(18, [S.dcbor({1: -19, 4: b"log-1", 395: 1, 15: {1: "log-1"}}), unprot, payload,
                                       sig])),                                       # no iat
            S.dcbor(cbor2.CBORTag(18, [S.dcbor({1: -19, 4: b"log-1", 395: 1, 15: {1: "log-1", 6: -5}}), unprot,
                                       payload, sig])),                              # negative iat
            S.dcbor(cbor2.CBORTag(18, [S.dcbor({1: -19, 4: b"", 395: 1, 15: {1: "", 6: NOW}}), unprot, payload,
                                       sig])),                                       # empty iss
            S.dcbor(cbor2.CBORTag(18, [S.dcbor({1: -19, 4: b"log-1", 395: 1, 15: [1, 2]}), unprot, payload, sig])),
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [proof]}, 4: b"x"}, payload, sig])),  # extra label
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: [proof]}, payload, sig])),     # vdp not a map
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [proof], -2: [proof]}}, payload, sig])),
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [proof, proof]}}, payload, sig])),   # two proofs
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: proof}}, payload, sig])),  # not a list
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [S.dcbor([1, 0])]}}, payload, sig])),        # 2 elements
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [S.dcbor(["1", 0, []])]}}, payload, sig])),  # size text
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [S.dcbor([1, -1, []])]}}, payload, sig])),   # index < 0
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [S.dcbor([2, 0, [b"x" * 31]])]}}, payload, sig])),
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [S.dcbor([2, 0, b"x" * 32])]}}, payload, sig])),
            S.dcbor(cbor2.CBORTag(18, [ok_prot, {396: {-1: [12]}}, payload, sig])),  # proof not bstr
        ]
        for i, v in enumerate(variants):
            with self.subTest(i=i):
                self.assertRaises(X.ReceiptError, X.parse_receipt, v)
                self.assertEqual(X.verify_receipt(v, p, rs, "p1", env.trusted)[0], "receipt_malformed")
        self.assertEqual(X.parse_receipt(reg.receipt)["registered_at"], NOW + 15)
        self.assertEqual(X.receipt_registered_at(reg.receipt), NOW + 15)

    def test_ts_refuses_each_proposal_fault(self):
        """SAR-REQ-120 at the TS, with the right class: attacker-chosen proposal_id, unauthorized
        agent, proposal bound to another policy, and a ratified proposal with a bad agent signature."""
        env = Env()
        p, _ = statements()
        body = dict(p["body"], proposal_id="0" * 32)
        forged = S.sign_statement(K["agent"][0], "agent", S.CT_PROPOSAL, body)
        r = env.register(forged, [S.ratify(K["ov1"][0], "ov1", forged, ttl=3600, now=NOW + 10)], NOW + 15)
        self.assertEqual((r.ok, r.reason), (False, "invalid_statement:proposal"))
        extra = S.sign_statement(K["agent"][0], "agent", S.CT_PROPOSAL, dict(p["body"], extra=1))
        r = env.register(extra, [S.ratify(K["ov1"][0], "ov1", extra, ttl=3600, now=NOW + 10)], NOW + 15)
        self.assertEqual(r.reason, "invalid_statement:proposal")
        q = S.make_proposal(K["evil"][0], "evil", PAYLOAD, ttl=3600, nonce="e", now=NOW)
        r = env.register(q, [S.ratify(K["ov1"][0], "ov1", q, ttl=3600, now=NOW + 10)], NOW + 15)
        self.assertEqual((r.ok, r.reason), (False, "unauthorized_signer:agent"))
        p2 = S.make_proposal(K["agent"][0], "agent", PAYLOAD, ttl=3600, nonce="n2", policy_id="p2", now=NOW)
        rb = {"v": 1, "proposal_digest": S.statement_digest(p2), "proposal_id": p2["body"]["proposal_id"],
              "overseer_id": "ov1", "verdict": "APPROVED", "reviewed_at": NOW + 10, "valid_until": NOW + 3600,
              "policy_id": "p1"}
        r = env.register(p2, [S.sign_statement(K["ov1"][0], "ov1", S.CT_RATIFICATION, rb)], NOW + 15)
        self.assertEqual((r.ok, r.reason), (False, "binding_mismatch:proposal policy"))
        bad = T._break_sig(p)
        r = env.register(bad, [S.ratify(K["ov1"][0], "ov1", bad, ttl=3600, now=NOW + 10)], NOW + 15)
        self.assertEqual((r.ok, r.reason), (False, "invalid_statement:proposal signature"))
        right_digest_wrong_id = {"v": 1, "proposal_digest": S.statement_digest(p), "proposal_id": "f" * 32,
                                 "overseer_id": "ov1", "verdict": "APPROVED", "reviewed_at": NOW + 10,
                                 "valid_until": NOW + 3600, "policy_id": "p1"}
        r = env.register(p, [S.sign_statement(K["ov1"][0], "ov1", S.CT_RATIFICATION, right_digest_wrong_id)], NOW + 15)
        self.assertEqual((r.ok, r.reason), (False, "binding_mismatch:ratification"))
        self.assertEqual(env.ts.entries, [])

    def test_ts_time_boundaries(self):
        """SAR-REQ-120, 124: touching but disjoint intervals are refused even within the tolerance; a
        rejection issued at the proposal's expiry is refused (review window applies to rejections)."""
        env = Env(policy(quorum=2))
        p, _ = statements(ttl=3600)
        ra = S.ratify(K["ov1"][0], "ov1", p, ttl=10, now=NOW)
        rb = S.ratify(K["ov2"][0], "ov2", p, ttl=60, now=NOW + 10)
        r = env.register(p, [ra, rb], NOW + 9)
        self.assertEqual((r.ok, r.reason[:12]), (False, "time_invalid"))
        q, _ = statements(ttl=60, nonce="q")
        rj = S.ratify(K["ov2"][0], "ov2", q, verdict="REJECTED", ttl=60, now=NOW + 60)
        r = env.register(q, [rj], NOW + 61, kind="rejection")
        self.assertEqual((r.ok, r.reason), (False, "time_invalid:review window"))

    def test_registration_results_and_log_accessors(self):
        env = Env(dict(policy(), quorum=0))
        p, rs = statements()
        ok, reason, receipt = env.register(p, rs, NOW + 15)
        self.assertEqual((ok, reason, receipt), (False, "policy_invalid", None))
        env = Env()
        ok, reason, receipt = env.register(p, rs, NOW + 15, pid="other")
        self.assertEqual((ok, receipt), (False, None))
        ok, reason, receipt = env.register(p, rs, NOW + 15)
        self.assertTrue(ok)
        self.assertEqual(env.ts.root(), X.merkle_root(env.ts.entries))
        self.assertIs(env.gate.store, env.store)
        self.assertRaises(ValueError, X.inclusion_proof, env.ts.entries, 1, 1)
        self.assertRaises(ValueError, X.inclusion_proof, env.ts.entries, 0, 2)
        self.assertRaises(ValueError, X.consistency_proof, env.ts.entries, 0, 1)
        self.assertRaises(ValueError, X.consistency_proof, env.ts.entries, 1, 2)

    def test_consistency_verifier_edge_cases(self):
        """SAR-REQ-128: old size 0 or larger than new, equal sizes with a non-empty proof, empty proof,
        and a proof with a trailing extra element."""
        leaves = [b"c%d" % i for i in range(9)]
        r = [X.merkle_root(leaves[:n]) for n in range(10)]
        proof = X.consistency_proof(leaves, 3, 9)
        self.assertTrue(X.verify_consistency(3, 9, r[3], r[9], proof))
        self.assertFalse(X.verify_consistency(0, 3, r[0], r[3], [r[3]]))
        self.assertFalse(X.verify_consistency(9, 3, r[9], r[3], proof))
        self.assertFalse(X.verify_consistency(4, 4, r[4], r[4], [r[4]]))
        self.assertTrue(X.verify_consistency(4, 4, r[4], r[4], []))
        self.assertFalse(X.verify_consistency(3, 9, r[3], r[9], []))
        self.assertFalse(X.verify_consistency(3, 9, r[3], r[9], proof + [r[1]]))
        self.assertTrue(X.verify_consistency(4, 9, r[4], r[9], tuple(X.consistency_proof(leaves, 4, 9))))

    def test_gate_revocation_wall_clock_data_item_interface_and_unloggable_denials(self):
        """SAR-REQ-043 through the receipt gate; now=None uses the wall clock; the data-item interface
        also requires a receipt; a receipt denial that cannot be logged is still a denial (S12); the
        denial record names the proposal."""
        import time as _time
        env = Env()
        t0 = int(_time.time())
        p, rs = statements(issued=t0 - 20, nonce="wall")
        reg = env.register(p, rs, t0 - 5)
        self.assertEqual(env.gate.authorize(PAYLOAD, p, rs, None), (False, "receipt_missing"))
        rec = env.store.db.execute("select record from log order by seq desc limit 1").fetchone()[0]
        self.assertIn(p["body"]["proposal_id"], rec)
        env.store._insert = lambda r: (_ for _ in ()).throw(RuntimeError("log down"))
        self.assertEqual(env.gate.authorize_bytes(S.dcbor(PAYLOAD), p, rs, None)[:2], (False, "deny_unlogged"))
        self.assertEqual(env.gate.authorize(PAYLOAD, p, rs, None), (False, "deny_unlogged"))
        del env.store._insert
        self.assertTrue(env.gate.authorize(PAYLOAD, p, rs, reg.receipt)[0])
        p2, rs2 = statements(issued=t0 - 20, nonce="wall2")
        reg2 = env.register(p2, rs2, t0 - 5)
        self.assertTrue(env.gate.authorize_bytes(S.dcbor(PAYLOAD), p2, rs2, reg2.receipt)[0] is False)  # replay txn
        p3, rs3 = statements(issued=t0 - 20, nonce="wall3", payload=dict(PAYLOAD, transaction_id="tx-3"))
        reg3 = env.register(p3, rs3, t0 - 5)
        env.gate.policy = policy(overseers=("ov2", "ov3"))
        self.assertEqual(env.gate.authorize_bytes(S.dcbor(dict(PAYLOAD, transaction_id="tx-3")), p3, rs3,
                                                  reg3.receipt)[:2], (False, "overseer_not_authorized"))

    def test_offline_tar_rejects_invalid_statements_and_garbage(self):
        """SAR-REQ-139: a valid receipt does not make invalid statements verify offline."""
        env = Env()
        p, rs = statements()
        bad = T._break_sig(rs[0])
        entry = X.registration_entry("authorization", "log-1", "p1", p["body"]["proposal_id"],
                                     X.set_digest(S.to_cose(p), [S.to_cose(bad)]), NOW + 15)
        env.ts.entries.append(entry)
        rec = env.ts.get_receipt(0)
        self.assertFalse(X.verify_tar_offline(p, [bad], rec, env.policy, env.trusted))
        self.assertFalse(X.verify_tar_offline(None, rs, rec, env.policy, env.trusted))
        self.assertFalse(X.verify_tar_offline(p, rs, rec, None, env.trusted))

    def test_tar_encoding(self):
        p, rs = statements()
        good = X.make_tar(p, rs, "p1", b"r")
        self.assertEqual(X.parse_tar(good)[2:], ("p1", b"r"))
        no_receipt = S.dcbor({"proposal": S.to_cose(p), "ratifications": [S.to_cose(r) for r in rs], "policy_ref": "p1"})
        self.assertIsNone(X.parse_tar(no_receipt)[3])
        for bad in (S.dcbor({"proposal": S.to_cose(p), "ratifications": [], "policy_ref": "p1", "x": 1}),
                    S.dcbor({"proposal": S.to_cose(p), "policy_ref": "p1"}), S.dcbor([1, 2])):
            self.assertRaises(ValueError, X.parse_tar, bad)

    def test_reference_matches_the_normative_vectors(self):
        """The registration entry, root and Receipt bytes of vector reg-001 and the Merkle roots and
        proofs of merkle-001 (generated by spec/gen_vectors.py without importing this code)."""
        import json
        import pathlib
        vdir = pathlib.Path(__file__).resolve().parent / "spec" / "test-vectors"
        v = json.loads((vdir / "reg-001.json").read_text())
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["inputs"]["keys"]["ts-1"]["seed"]))
        ts = X.TransparencyService("log-1", key, v["inputs"]["policy"])
        st, want = v["inputs"]["steps"][0], v["expected"]["steps"][0]
        ok, reason, receipt = ts.register(bytes.fromhex(st["request_cbor"]), now=st["ts_time"])
        self.assertTrue(ok, reason)
        self.assertEqual((ts.entries[0].hex(), receipt.hex(), ts.root().hex()),
                         (want["entry_cbor"], want["receipt_cose"], want["root"]))
        m = json.loads((vdir / "merkle-001.json").read_text())
        leaves = [bytes.fromhex(x) for x in m["inputs"]["leaves"]]
        for n, root in m["expected"]["roots"].items():
            self.assertEqual(X.merkle_root(leaves[:int(n)]).hex(), root)


if __name__ == "__main__":
    unittest.main()
