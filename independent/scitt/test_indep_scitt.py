"""Tests for sar_indep_scitt, derived from spec/sar-profile.md Sections 15-18
(and RFC 9162 Section 2.1). Requirement ids are given in each test name or
docstring. Run:  PYTHONDONTWRITEBYTECODE=1 python -m unittest -v test_indep_scitt
"""
from __future__ import annotations

import hashlib
import os
import sys
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import cbor2  # noqa: E402  (decoding only, to inspect what we built)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import sar_indep as core  # noqa: E402
import sar_indep_scitt as S  # noqa: E402

T0 = 1760000000
TAU = 30


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pub_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw).hex()


class Fixture:
    """Keys, a policy and helpers to build statements, requests and Receipts."""

    def __init__(self, quorum=1):
        self.agent = Ed25519PrivateKey.generate()
        self.ov = {f"ov-{i}": Ed25519PrivateKey.generate() for i in (1, 2, 3)}
        self.ts_key = Ed25519PrivateKey.generate()
        self.other_ts_key = Ed25519PrivateKey.generate()
        self.policy = {
            "policy_id": "p1", "quorum": quorum,
            "authorized_agents": {"agent-1": pub_hex(self.agent)},
            "authorized_overseers": {k: pub_hex(v) for k, v in self.ov.items()},
        }
        self.trusted = {"log-1": pub_hex(self.ts_key)}
        self.payload = {"action": "transfer", "amount": 5, "transaction_id": "tx-1"}

    def proposal(self, payload=None, nonce="n1", now=T0, ttl=3600, policy_id="p1"):
        return core.make_proposal(self.agent, "agent-1", self.payload if payload is None else payload,
                                  ttl=ttl, nonce=nonce, policy_id=policy_id, now=now)

    def rat(self, p, ov="ov-1", verdict="APPROVED", now=T0 + 10, ttl=3600):
        return core.ratify(self.ov[ov], ov, p, verdict=verdict, ttl=ttl, now=now)

    def ts(self, log_id="log-1", policy=None):
        return S.TransparencyService(log_id, self.ts_key, self.policy if policy is None else policy)

    def request(self, kind, p, rats, policy_id="p1"):
        return S.make_registration_request(kind, policy_id, p, rats)

    def forged_receipt(self, p, rats, *, kind="authorization", policy_id="p1", log_id="log-1",
                       reg_at=T0 + 15, key=None, prefix_entries=0):
        """A Receipt for an arbitrary entry, as a faulty or lying TS could
        issue it (the TS registration logic is bypassed)."""
        entry = S.registration_entry(kind, log_id, policy_id, p["body"]["proposal_id"],
                                     S.set_digest(core.to_cose(p), [core.to_cose(r) for r in rats]),
                                     reg_at)
        leaves = [b"filler-%d" % i for i in range(prefix_entries)] + [entry]
        idx, size = len(leaves) - 1, len(leaves)
        return S.build_receipt(key or self.ts_key, log_id, reg_at, size, idx,
                               S.inclusion_proof(leaves, idx, size), S.merkle_root(leaves))


def cls_of(reason: str) -> str:
    return reason.split(":", 1)[0]


# ---------------------------------------------------------------------------
class MerkleTree(unittest.TestCase):
    """SAR-REQ-126, 127, 128 (RFC 9162 Section 2.1)."""
    LEAVES = [b"leaf-%d" % i for i in range(17)]

    def test_empty_tree_root_is_hash_of_empty_string(self):
        self.assertEqual(S.merkle_root([]), H(b""))

    def test_leaf_and_node_domain_separation(self):
        a, b, c = b"a", b"b", b"c"
        la, lb, lc = H(b"\x00" + a), H(b"\x00" + b), H(b"\x00" + c)
        self.assertEqual(S.merkle_root([a]), la)
        self.assertEqual(S.merkle_root([a, b]), H(b"\x01" + la + lb))
        # split at the largest power of two smaller than n: [a, b] | [c]
        self.assertEqual(S.merkle_root([a, b, c]), H(b"\x01" + H(b"\x01" + la + lb) + lc))

    def test_inclusion_all_positions(self):
        for n in range(1, len(self.LEAVES) + 1):
            root = S.merkle_root(self.LEAVES[:n])
            for i in range(n):
                path = S.inclusion_proof(self.LEAVES, i, n)
                self.assertTrue(S.verify_inclusion(self.LEAVES[i], i, n, path, root), (i, n))
                self.assertFalse(S.verify_inclusion(self.LEAVES[i] + b"!", i, n, path, root))
                if n > 1:
                    self.assertFalse(S.verify_inclusion(self.LEAVES[i], (i + 1) % n, n, path, root))
                    bad = list(path)
                    bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
                    self.assertFalse(S.verify_inclusion(self.LEAVES[i], i, n, bad, root))
                    self.assertFalse(S.verify_inclusion(self.LEAVES[i], i, n, path[:-1], root))
                self.assertFalse(S.verify_inclusion(self.LEAVES[i], i, n, path + [H(b"x")], root))

    def test_inclusion_fails_when_index_not_below_size(self):
        """SAR-REQ-127: the RFC 9162 verifier fails if leaf_index >= tree_size."""
        root = S.merkle_root(self.LEAVES[:1])
        self.assertFalse(S.verify_inclusion(self.LEAVES[0], 1, 1, [], root))
        self.assertFalse(S.verify_inclusion(self.LEAVES[0], 0, 0, [], root))
        with self.assertRaises(ValueError):
            S.inclusion_proof(self.LEAVES, 3, 3)

    def test_inclusion_rejects_malformed_path_elements(self):
        root = S.merkle_root(self.LEAVES[:2])
        self.assertFalse(S.verify_inclusion(self.LEAVES[0], 0, 2, [b"short"], root))
        self.assertFalse(S.verify_inclusion(self.LEAVES[0], 0, 2, "notalist", root))

    def test_consistency_all_pairs(self):
        roots = {n: S.merkle_root(self.LEAVES[:n]) for n in range(len(self.LEAVES) + 1)}
        for n in range(1, len(self.LEAVES) + 1):
            for m in range(1, n + 1):
                proof = S.consistency_proof(self.LEAVES, m, n)
                self.assertTrue(S.verify_consistency(m, n, roots[m], roots[n], proof), (m, n))
                if m < n:
                    self.assertFalse(S.verify_consistency(m, n, roots[m], H(b"x"), proof))
                    self.assertFalse(S.verify_consistency(m, n, H(b"x"), roots[n], proof))
                    if proof:
                        self.assertFalse(S.verify_consistency(m, n, roots[m], roots[n], proof[:-1]))
                else:
                    self.assertEqual(proof, [])

    def test_consistency_degenerate_inputs(self):
        r = S.merkle_root(self.LEAVES[:4])
        self.assertFalse(S.verify_consistency(0, 4, H(b""), r, []))
        self.assertFalse(S.verify_consistency(5, 4, r, r, []))
        self.assertFalse(S.verify_consistency(4, 4, r, r, [r]))
        self.assertFalse(S.verify_consistency(2, 4, S.merkle_root(self.LEAVES[:2]), r, []))


# ---------------------------------------------------------------------------
class Registration(unittest.TestCase):
    """Section 15-17 at the TS."""

    def setUp(self):
        self.f = Fixture()
        self.p = self.f.proposal()
        self.r1 = self.f.rat(self.p)

    def test_valid_authorization_registered_entry_and_receipt_shape(self):
        """SAR-REQ-120, 125, 126, 130."""
        ts = self.f.ts()
        ok, reason, receipt = ts.register(self.f.request("authorization", self.p, [self.r1]), T0 + 15)
        self.assertTrue(ok, reason)
        self.assertEqual(len(ts.entries), 1)
        entry = cbor2.loads(ts.entries[0])
        self.assertEqual(set(entry), {"v", "kind", "log_id", "policy_id", "proposal_id",
                                      "set_digest", "registered_at"})
        p_bytes, r_bytes = core.to_cose(self.p), core.to_cose(self.r1)
        self.assertEqual(entry["set_digest"], H(core.dcbor([H(p_bytes), [H(r_bytes)]])))
        self.assertEqual((entry["kind"], entry["log_id"], entry["policy_id"], entry["registered_at"]),
                         ("authorization", "log-1", "p1", T0 + 15))
        self.assertEqual(entry["proposal_id"], self.p["body"]["proposal_id"])
        self.assertEqual(core.dcbor(entry), ts.entries[0])  # deterministic CBOR
        # Receipt: tag 18, exact protected header, vdp with one proof, detached payload
        obj = cbor2.loads(receipt)
        self.assertEqual(obj.tag, 18)
        prot, unprot, payload, sig = obj.value
        self.assertEqual(cbor2.loads(prot), {1: -19, 4: b"log-1", 395: 1, 15: {1: "log-1", 6: T0 + 15}})
        self.assertEqual(list(unprot), [396])
        self.assertEqual(cbor2.loads(unprot[396][-1][0]), [1, 0, []])
        self.assertIsNone(payload)
        root = S.merkle_root(ts.entries)
        self.ts_pub().verify(sig, core.dcbor(["Signature1", prot, b"", root]))
        self.assertEqual(root, ts.root())

    def ts_pub(self):
        return self.f.ts_key.public_key()

    def test_set_digest_is_order_independent_and_set_sensitive(self):
        """SAR-REQ-125: R is sorted, and a different set gives a different leaf."""
        f = Fixture(quorum=2)
        p = f.proposal()
        a, b = core.to_cose(f.rat(p, "ov-1")), core.to_cose(f.rat(p, "ov-2"))
        pb = core.to_cose(p)
        self.assertEqual(S.set_digest(pb, [a, b]), S.set_digest(pb, [b, a]))
        self.assertNotEqual(S.set_digest(pb, [a]), S.set_digest(pb, [a, b]))

    def test_log_grows_append_only_with_consistent_checkpoints(self):
        """SAR-REQ-126, 128."""
        ts = self.f.ts()
        cps, roots = [], []
        for i in range(5):
            p = self.f.proposal(nonce=f"n{i}")
            ok, reason, _ = ts.register(self.f.request("authorization", p, [self.f.rat(p)]), T0 + 15 + i)
            self.assertTrue(ok, reason)
            cps.append(ts.checkpoint())
            roots.append(ts.root())
        before = list(ts.entries)
        for m in range(1, 6):
            log_id, size, root = S.verify_checkpoint(cps[m - 1], self.f.trusted)
            self.assertEqual((log_id, size, root), ("log-1", m, roots[m - 1]))
            self.assertTrue(S.verify_consistency(m, 5, root, roots[-1], ts.consistency_proof(m, 5)))
            self.assertTrue(S.verify_inclusion(ts.entries[m - 1], m - 1, 5, ts.inclusion_proof(m - 1, 5),
                                               roots[-1]))
        self.assertEqual(ts.entries, before)
        with self.assertRaises(Exception):
            S.verify_checkpoint(cps[0], {"log-1": pub_hex(self.f.other_ts_key)})

    def test_registration_time_bounds(self):
        """SAR-REQ-120 with SAR-REQ-050 at t_reg: lo - tau <= t_reg < hi."""
        lo, hi = T0 + 10, T0 + 3600   # lo = reviewed_at, hi = expires_at
        for t, want in ((lo - TAU - 1, False), (lo - TAU, True), (hi - 1, True), (hi, False)):
            ok, reason, receipt = self.f.ts().register(
                self.f.request("authorization", self.p, [self.r1]), t)
            self.assertEqual(ok, want, (t, reason))
            if not ok:
                self.assertEqual(cls_of(reason), "time_invalid")
                self.assertIsNone(receipt)

    def test_review_window_checked_at_ts(self):
        """SAR-REQ-051 at registration."""
        late = self.f.rat(self.p, now=T0 + 3600)
        ok, reason, _ = self.f.ts().register(self.f.request("authorization", self.p, [late]), T0 + 15)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "time_invalid")

    def test_refusal_classes(self):
        """SAR-REQ-120, 095: refusals carry a Section 13.1 class."""
        f = self.f
        outsider = Ed25519PrivateKey.generate()
        bad_rat = core.ratify(outsider, "ov-9", self.p, now=T0 + 10)
        dup = [self.r1, f.rat(self.p, now=T0 + 11)]
        other = f.proposal(nonce="other")
        unbound = f.rat(other)
        forged = dict(self.r1, sig=core.ratify(f.ov["ov-2"], "ov-1", self.p, now=T0 + 10)["sig"])
        cases = [
            ("unauthorized_signer", f.request("authorization", self.p, [bad_rat])),
            ("duplicate_ratification", f.request("authorization", self.p, dup)),
            ("binding_mismatch", f.request("authorization", self.p, [unbound])),
            ("binding_mismatch", f.request("authorization", self.p, [self.r1], policy_id="p2")),
            ("invalid_statement", f.request("authorization", self.p, [forged])),
            ("rejected", f.request("authorization", self.p,
                                   [self.r1, f.rat(self.p, "ov-2", "REJECTED")])),
            ("missing_evidence", core.dcbor({"v": 1, "kind": "authorization", "policy_id": "p1",
                                             "proposal": core.to_cose(self.p), "ratifications": []})),
            ("missing_evidence", core.dcbor({"v": 1, "kind": "authorization", "policy_id": "p1",
                                             "ratifications": [core.to_cose(self.r1)]})),
            ("invalid_statement", core.dcbor({"v": 1, "kind": "authorization", "policy_id": "p1",
                                              "proposal": core.to_cose(self.p),
                                              "ratifications": [core.to_cose(self.r1)], "x": 1})),
            ("invalid_statement", core.dcbor({"v": 1, "kind": "approval", "policy_id": "p1",
                                              "proposal": core.to_cose(self.p),
                                              "ratifications": [core.to_cose(self.r1)]})),
            ("invalid_statement", b"\xbf\xff"),                    # indefinite-length map
            ("invalid_statement", f.request("authorization", self.p, [self.r1]) + b"\x00"),
            ("invalid_statement", core.dcbor({"v": 1, "kind": "authorization", "policy_id": "p1",
                                              "proposal": b"\x00", "ratifications": [core.to_cose(self.r1)]})),
        ]
        for want, req in cases:
            ts = f.ts()
            ok, reason, receipt = ts.register(req, T0 + 15)
            self.assertFalse(ok, (want, reason))
            self.assertEqual(cls_of(reason), want, reason)
            self.assertTrue(reason.startswith(want + ": "))
            self.assertIsNone(receipt)
            self.assertEqual(ts.entries, [])

    def test_quorum_at_ts(self):
        f = Fixture(quorum=2)
        p = f.proposal()
        ok, reason, _ = f.ts().register(f.request("authorization", p, [f.rat(p)]), T0 + 15)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "quorum_not_met")
        ok, reason, _ = f.ts().register(
            f.request("authorization", p, [f.rat(p, "ov-1"), f.rat(p, "ov-2")]), T0 + 15)
        self.assertTrue(ok, reason)

    def test_invalid_policy_refuses_everything(self):
        """SAR-REQ-040..042 at the TS."""
        for mutate in (lambda q: q.update(quorum=0), lambda q: q.update(policy_version=1),
                       lambda q: q["authorized_overseers"].update({"agent-1": q["authorized_agents"]["agent-1"]})):
            pol = {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.f.policy.items()}
            mutate(pol)
            ok, reason, _ = self.f.ts(policy=pol).register(
                self.f.request("authorization", self.p, [self.r1]), T0 + 15)
            self.assertFalse(ok)
            self.assertEqual(cls_of(reason), "policy_invalid")

    def test_policy_in_force_is_evaluated_per_request(self):
        ts = self.f.ts()
        del ts.policy["authorized_overseers"]["ov-1"]
        ok, reason, _ = ts.register(self.f.request("authorization", self.p, [self.r1]), T0 + 15)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "unauthorized_signer")

    def test_at_most_one_authorization_per_proposal(self):
        """SAR-REQ-122."""
        ts = self.f.ts()
        self.assertTrue(ts.register(self.f.request("authorization", self.p, [self.r1]), T0 + 15)[0])
        other_set = [self.r1, self.f.rat(self.p, "ov-2")]
        ok, reason, _ = ts.register(self.f.request("authorization", self.p, other_set), T0 + 16)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "registration_conflict")
        self.assertEqual(len(ts.entries), 1)

    def test_concurrent_registrations_exactly_one_succeeds(self):
        """SAR-REQ-122: concurrent requests are serialized."""
        ts = self.f.ts()
        req = self.f.request("authorization", self.p, [self.r1])
        results, barrier = [], threading.Barrier(8)

        def worker():
            barrier.wait()
            results.append(ts.register(req, T0 + 15)[0])
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), [False] * 7 + [True])
        self.assertEqual(len(ts.entries), 1)

    def test_registered_veto(self):
        """SAR-REQ-123, 124."""
        ts = self.f.ts()
        rej = self.f.rat(self.p, "ov-2", "REJECTED", now=T0 + 12)
        ok, reason, receipt = ts.register(self.f.request("rejection", self.p, [rej]), T0 + 15)
        self.assertTrue(ok, reason)
        self.assertEqual(cbor2.loads(ts.entries[0])["kind"], "rejection")
        ok, reason, _ = ts.register(self.f.request("authorization", self.p, [self.r1]), T0 + 16)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "registration_conflict")
        # A rejection Receipt never authorizes execution (SAR-REQ-136).
        gate = S.ReceiptGate(self.f.policy, core.Store(), self.f.trusted)
        allowed, reason = gate.authorize(self.f.payload, self.p, [rej], receipt, T0 + 20)
        self.assertFalse(allowed)
        self.assertEqual(cls_of(reason), "rejected")

    def test_rejection_ignores_quorum_and_time_but_needs_valid_statements(self):
        """SAR-REQ-124."""
        f = Fixture(quorum=3)
        p = f.proposal(ttl=60)
        rej = f.rat(p, "ov-2", "REJECTED", ttl=60)
        ok, reason, _ = f.ts().register(f.request("rejection", p, [rej]), T0 + 100000)
        self.assertTrue(ok, reason)
        # mixed set with an approval: still a valid rejection
        ok, reason, _ = f.ts().register(f.request("rejection", p, [f.rat(p, "ov-1", ttl=60), rej]),
                                        T0 + 15)
        self.assertTrue(ok, reason)
        # no REJECTED ratification
        ok, reason, _ = f.ts().register(f.request("rejection", p, [f.rat(p, "ov-1")]), T0 + 15)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "invalid_statement")
        # REJECTED by an outsider
        outsider = Ed25519PrivateKey.generate()
        bad = core.ratify(outsider, "ov-9", p, verdict="REJECTED", now=T0 + 10)
        ok, reason, _ = f.ts().register(f.request("rejection", p, [bad]), T0 + 15)
        self.assertFalse(ok)
        self.assertEqual(cls_of(reason), "unauthorized_signer")

    def test_ts_consumes_no_replay_keys(self):
        """SAR-REQ-121: registration is not execution; the gate still allows once."""
        ts = self.f.ts()
        ok, _, receipt = ts.register(self.f.request("authorization", self.p, [self.r1]), T0 + 15)
        self.assertTrue(ok)
        gate = S.ReceiptGate(self.f.policy, core.Store(), self.f.trusted)
        self.assertEqual(gate.authorize(self.f.payload, self.p, [self.r1], receipt, T0 + 20), (True, "ALLOW"))


# ---------------------------------------------------------------------------
class ReceiptGated(unittest.TestCase):
    """Section 18."""

    def setUp(self):
        self.f = Fixture()
        self.p = self.f.proposal()
        self.r1 = self.f.rat(self.p)
        self.ts = self.f.ts()
        ok, reason, self.receipt = self.ts.register(
            self.f.request("authorization", self.p, [self.r1]), T0 + 15)
        assert ok, reason
        self.store = core.Store()
        self.gate = S.ReceiptGate(self.f.policy, self.store, self.f.trusted, max_receipt_age=300)

    def log_count(self):
        return self.store.db.execute("SELECT COUNT(*) FROM log").fetchone()[0]

    def auth(self, receipt="default", payload=None, p=None, rats=None, now=T0 + 20, gate=None):
        g = gate or self.gate
        return g.authorize(self.f.payload if payload is None else payload,
                           self.p if p is None else p, [self.r1] if rats is None else rats,
                           self.receipt if receipt == "default" else receipt, now)

    def assertDeny(self, result, cls):
        allowed, reason = result
        self.assertFalse(allowed, reason)
        self.assertEqual(cls_of(reason), cls, reason)
        self.assertTrue(reason.startswith(cls + ": "))
        self.assertIn(cls, S.DENY_CLASSES)

    def test_allow_records_one_decision(self):
        n = self.log_count()
        self.assertEqual(self.auth(), (True, "ALLOW"))
        self.assertEqual(self.log_count(), n + 1)

    def test_statements_as_cose_octets_also_accepted(self):
        self.assertEqual(self.auth(p=core.to_cose(self.p), rats=[core.to_cose(self.r1)]), (True, "ALLOW"))

    def test_missing_or_malformed_receipt(self):
        """SAR-REQ-132, 130."""
        for bad in (None, b"", b"\xa0", self.receipt + b"\x00", self.receipt[:-1]):
            n = self.log_count()
            self.assertDeny(self.auth(receipt=bad), "receipt_invalid")
            self.assertEqual(self.log_count(), n + 1)

    def test_receipt_header_variants_rejected(self):
        """SAR-REQ-130: exact header, one proof, detached payload."""
        obj = cbor2.loads(self.receipt)
        prot, unprot, _, sig = obj.value
        hdr = cbor2.loads(prot)
        proof = unprot[396][-1][0]

        def rebuild(h=None, u=None, payload=None, s=None):
            return core.dcbor(core.Tag(18, [core.dcbor(h) if h is not None else prot,
                                            u if u is not None else unprot, payload,
                                            s if s is not None else sig]))
        variants = [
            rebuild(h={**hdr, 1: -8}),
            rebuild(h={**hdr, 3: "application/cose"}),
            rebuild(h={**hdr, 395: 2}),
            rebuild(h={k: v for k, v in hdr.items() if k != 15}),
            rebuild(h={**hdr, 15: {1: "log-1", 6: T0 + 15, 2: "x"}}),
            rebuild(h={**hdr, 4: b"log-2"}),
            rebuild(u={396: {-1: [proof, proof]}}),
            rebuild(u={396: {-1: [proof]}, 4: b"x"}),
            rebuild(u={}),
            rebuild(payload=self.ts.root()),
            rebuild(s=sig[:63]),
            core.dcbor(core.Tag(17, obj.value)),
        ]
        for v in variants:
            self.assertDeny(self.auth(receipt=v), "receipt_invalid")
        self.assertEqual(self.auth(), (True, "ALLOW"))   # denials consumed nothing

    def test_untrusted_log_and_wrong_key(self):
        """SAR-REQ-131."""
        r_other_key = self.f.forged_receipt(self.p, [self.r1], key=self.f.other_ts_key)
        self.assertDeny(self.auth(receipt=r_other_key), "receipt_invalid")
        r_log2 = self.f.forged_receipt(self.p, [self.r1], log_id="log-2", key=self.f.other_ts_key)
        self.assertDeny(self.auth(receipt=r_log2), "receipt_invalid")
        gate = S.ReceiptGate(self.f.policy, self.store, {"log-1": "zz" * 32})
        self.assertDeny(self.auth(gate=gate), "receipt_invalid")

    def test_receipt_binds_set_proposal_policy_kind(self):
        """SAR-REQ-133, 136."""
        f = self.f
        r2 = f.rat(self.p, "ov-2")
        # Receipt for {r1} presented with {r1, r2}
        self.assertDeny(self.auth(rats=[self.r1, r2]), "receipt_invalid")
        # Receipt for another proposal
        p2 = f.proposal(nonce="n2")
        self.assertDeny(self.auth(p=p2, rats=[f.rat(p2)]), "receipt_invalid")
        # another policy id, another kind
        for kw in ({"policy_id": "p0"}, {"kind": "rejection"}):
            self.assertDeny(self.auth(receipt=f.forged_receipt(self.p, [self.r1], **kw)), "receipt_invalid")
        # the honest one, at a non-zero index of a larger log, is fine
        self.assertEqual(self.auth(receipt=f.forged_receipt(self.p, [self.r1], prefix_entries=6)),
                         (True, "ALLOW"))

    def test_inclusion_tampering(self):
        """SAR-REQ-127."""
        rec = self.f.forged_receipt(self.p, [self.r1], prefix_entries=6)
        obj = cbor2.loads(rec)
        prot, unprot, _, sig = obj.value
        size, idx, path = cbor2.loads(unprot[396][-1][0])

        def with_proof(s, i, pth):
            return core.dcbor(core.Tag(18, [prot, {396: {-1: [core.dcbor([s, i, pth])]}}, None, sig]))
        bad_path = [bytes([path[0][0] ^ 1]) + path[0][1:]] + path[1:]
        for v in (with_proof(size, idx, bad_path), with_proof(size, size, path),
                  with_proof(size, idx - 1, path), with_proof(5, idx, path), with_proof(size, idx, path[:-1])):
            self.assertDeny(self.auth(receipt=v), "receipt_invalid")
        self.assertEqual(self.auth(receipt=with_proof(size, idx, path)), (True, "ALLOW"))

    def test_registration_time_within_validity(self):
        """SAR-REQ-134: lo - tau <= registered_at < hi."""
        f = Fixture()
        p = f.proposal(ttl=60)              # hi = T0 + 60
        r = f.rat(p, now=T0 + 10, ttl=600)  # lo = T0 + 10
        for reg_at, now, want in ((T0 + 10 - TAU - 1, T0 + 20, False), (T0 + 10 - TAU, T0 + 20, True),
                                  (T0 + 59, T0 + 59, True), (T0 + 60, T0 + 59, False)):
            gate = S.ReceiptGate(f.policy, core.Store(), f.trusted)
            res = gate.authorize(f.payload, p, [r], f.forged_receipt(p, [r], reg_at=reg_at), now)
            if want:
                self.assertEqual(res, (True, "ALLOW"), reg_at)
            else:
                self.assertDeny(res, "receipt_invalid")

    def test_receipt_freshness_under_gate_clock(self):
        """SAR-REQ-135: registered_at <= t + tau and t < registered_at + max_receipt_age."""
        reg = T0 + 15
        for now, want in ((reg + 299, True), (reg + 300, False), (reg - TAU, True), (reg - TAU - 1, False)):
            gate = S.ReceiptGate(self.f.policy, core.Store(), self.f.trusted, max_receipt_age=300)
            res = self.auth(now=now, gate=gate)
            if want:
                self.assertEqual(res, (True, "ALLOW"), now)
            else:
                self.assertIn(cls_of(res[1]), ("receipt_invalid", "time_invalid"))
                self.assertFalse(res[0])
        # TS clock ahead by 31 s with the statements valid: receipt_invalid
        res = self.auth(receipt=self.f.forged_receipt(self.p, [self.r1], reg_at=T0 + 20 + 31))
        self.assertDeny(res, "receipt_invalid")

    def test_registered_at_is_not_the_evaluation_instant(self):
        """SAR-REQ-138: statements expired at the gate's t, Receipt fresh."""
        f = Fixture()
        p = f.proposal(ttl=60)
        r = f.rat(p, now=T0 + 10, ttl=600)
        rec = f.forged_receipt(p, [r], reg_at=T0 + 59)
        gate = S.ReceiptGate(f.policy, core.Store(), f.trusted)
        self.assertDeny(gate.authorize(f.payload, p, [r], rec, T0 + 100), "time_invalid")

    def test_receipt_does_not_replace_core_checks(self):
        """SAR-REQ-137: payload, replay, statement faults, revocation."""
        self.assertDeny(self.auth(payload={"action": "other"}), "payload_mismatch")
        self.assertEqual(self.auth(), (True, "ALLOW"))
        self.assertDeny(self.auth(now=T0 + 21), "replay")
        # a faulty TS registered a set with a bad signature
        f = self.f
        p2 = f.proposal(nonce="n2")
        good = f.rat(p2)
        bad = dict(good, sig=("00" * 64))
        self.assertDeny(self.gate.authorize(f.payload, p2, [bad],
                                            f.forged_receipt(p2, [bad]), T0 + 20), "invalid_statement")
        # revocation: overseer removed after registration
        p3 = f.proposal(nonce="n3")
        r3 = f.rat(p3)
        rec3 = f.forged_receipt(p3, [r3])
        pol = {k: (dict(v) if isinstance(v, dict) else v) for k, v in f.policy.items()}
        del pol["authorized_overseers"]["ov-1"]
        gate = S.ReceiptGate(pol, core.Store(), f.trusted)
        self.assertDeny(gate.authorize(f.payload, p3, [r3], rec3, T0 + 20), "unauthorized_signer")

    def test_denial_consumes_nothing(self):
        """SAR-REQ-084 with Receipts."""
        self.assertDeny(self.auth(receipt=None), "receipt_invalid")
        self.assertDeny(self.auth(receipt=self.f.forged_receipt(self.p, [self.r1], key=self.f.other_ts_key)),
                        "receipt_invalid")
        self.assertEqual(self.auth(), (True, "ALLOW"))

    def test_missing_evidence_and_bad_instant(self):
        self.assertDeny(self.gate.authorize(self.f.payload, None, [self.r1], self.receipt, T0 + 20),
                        "missing_evidence")
        self.assertDeny(self.gate.authorize(self.f.payload, self.p, [], self.receipt, T0 + 20),
                        "missing_evidence")
        self.assertDeny(self.auth(now=T0 + 20.5), "time_invalid")
        self.assertDeny(self.auth(now=True), "time_invalid")

    def test_invalid_policy_denies(self):
        pol = dict(self.f.policy, quorum=5)
        gate = S.ReceiptGate(pol, self.store, self.f.trusted)
        self.assertDeny(self.auth(gate=gate), "policy_invalid")

    def test_store_failure_denies(self):
        """SAR-REQ-091: an ALLOW that cannot be recorded is a DENY."""
        store = core.Store()
        gate = S.ReceiptGate(self.f.policy, store, self.f.trusted)
        store.db.close()
        allowed, reason = self.auth(gate=gate)
        self.assertFalse(allowed)
        self.assertEqual(cls_of(reason), "store_failure")


# ---------------------------------------------------------------------------
class OfflineTAR(unittest.TestCase):
    """SAR-REQ-139."""

    def setUp(self):
        self.f = Fixture()
        self.p = self.f.proposal()
        self.r1 = self.f.rat(self.p)
        ok, _, self.receipt = self.f.ts().register(
            self.f.request("authorization", self.p, [self.r1]), T0 + 15)
        assert ok

    def test_valid_record_verifies_without_clock(self):
        self.assertTrue(S.verify_tar_offline(self.p, [self.r1], self.receipt, self.f.policy, self.f.trusted))
        # freshness is not part of offline verification: an old record still verifies
        self.assertTrue(S.verify_tar_offline(core.to_cose(self.p), [core.to_cose(self.r1)], self.receipt,
                                             self.f.policy, self.f.trusted))

    def test_registered_at_is_an_instant_of_validity(self):
        reg_at = S.parse_receipt(self.receipt)["registered_at"]
        self.assertTrue(core.verify_record_offline(self.p, [self.r1], self.f.policy, at=reg_at))

    def test_failures(self):
        f = self.f
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1], None, f.policy, f.trusted))
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1], self.receipt, f.policy, {}))
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1], self.receipt[:-1] + bytes([self.receipt[-1] ^ 1]),
                                              f.policy, f.trusted))
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1, f.rat(self.p, "ov-2")], self.receipt,
                                              f.policy, f.trusted))
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1], self.receipt, dict(f.policy, quorum=0),
                                              f.trusted))
        rej = f.rat(self.p, "ov-2", "REJECTED")
        self.assertFalse(S.verify_tar_offline(self.p, [rej], f.forged_receipt(self.p, [rej], kind="rejection"),
                                              f.policy, f.trusted))
        late = f.forged_receipt(self.p, [self.r1], reg_at=T0 + 3600)
        self.assertFalse(S.verify_tar_offline(self.p, [self.r1], late, f.policy, f.trusted))

    def test_gate_allow_implies_offline_success(self):
        gate = S.ReceiptGate(self.f.policy, core.Store(), self.f.trusted)
        for now in range(T0 - 20, T0 + 400, 7):
            g = S.ReceiptGate(self.f.policy, core.Store(), self.f.trusted)
            allowed, _ = g.authorize(self.f.payload, self.p, [self.r1], self.receipt, now)
            if allowed:
                self.assertTrue(S.verify_tar_offline(self.p, [self.r1], self.receipt,
                                                     self.f.policy, self.f.trusted))
                self.assertTrue(core.verify_record_offline(self.p, [self.r1], self.f.policy, at=now))
        del gate


if __name__ == "__main__":
    unittest.main()
