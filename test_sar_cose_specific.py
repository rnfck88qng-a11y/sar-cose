"""COSE/CBOR-specific tests for sar_cose (SARWP v1.1 section 6.4, "not yet covered" list).

    python3 -m unittest -v test_sar_cose_specific
"""
import unittest

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import sar_cose as S

PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00"}


def _raw_priv(k):
    return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def _cose_with_payload_bytes(priv, kid, ctype, payload_bytes, alg=S.ALG_ED25519, unprotected=None):
    """Build a correctly *signed* COSE_Sign1 over arbitrary payload bytes (to test parsers)."""
    protected = S.dcbor({S.HDR_ALG: alg, S.HDR_CT: ctype, S.HDR_KID: kid.encode()})
    sig = priv.sign(S.dcbor(["Signature1", protected, b"", payload_bytes]))
    return S.dcbor(cbor2.CBORTag(18, [protected, unprotected or {}, payload_bytes, sig]))


class DeterministicCBORVectors(unittest.TestCase):
    """RFC 8949 Appendix A examples, plus the section 4.2.1 key-ordering example."""
    VECTORS = [
        (0, "00"), (1, "01"), (10, "0a"), (23, "17"), (24, "1818"), (25, "1819"), (100, "1864"),
        (1000, "1903e8"), (1000000, "1a000f4240"), (1000000000000, "1b000000e8d4a51000"),
        (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"),
        (False, "f4"), (True, "f5"), (None, "f6"),
        (b"", "40"), (bytes.fromhex("01020304"), "4401020304"),
        ("", "60"), ("a", "6161"), ("IETF", "6449455446"),
        ([], "80"), ([1, 2, 3], "83010203"), ({}, "a0"), ({1: 2, 3: 4}, "a201020304"),
        ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    ]

    def test_appendix_a_vectors(self):
        for value, hexstr in self.VECTORS:
            with self.subTest(value=value):
                self.assertEqual(S.dcbor(value).hex(), hexstr)

    def test_core_deterministic_key_order(self):
        # RFC 8949 4.2.1: 10, 100, -1, "z", "aa", ..., false
        enc = S.dcbor({False: 0, "aa": 0, "z": 0, -1: 0, 100: 0, 10: 0})
        self.assertEqual(enc.hex(), "a6" + "0a00" + "186400" + "2000" + "617a00" + "62616100" + "f400")

    def test_floats_rejected(self):
        with self.assertRaises(TypeError):
            S.dcbor({"amount": 1.5})


class CoseStructureTests(unittest.TestCase):
    def setUp(self):
        self.ak, self.apub = S.new_keypair()
        self.ok, self.opub = S.new_keypair()
        self.ok2, self.opub2 = S.new_keypair()
        self.policy = {"policy_id": "p1", "quorum": 1, "authorized_agents": {"agent-1": self.apub},
                       "authorized_overseers": {"ov-1": self.opub, "ov-2": self.opub2}}
        self.gate = S.Gate(self.policy, S.Store())

    def _good(self, nonce="n1"):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD, nonce=nonce)
        return p, [S.ratify(self.ok, "ov-1", p)]

    def test_statements_are_tagged_cose_sign1_with_ed25519_alg_minus19(self):
        p, r = self._good()
        for stmt, ct, kid in ((p, S.CT_PROPOSAL, b"agent-1"), (r[0], S.CT_RATIFICATION, b"ov-1")):
            obj = cbor2.loads(S.to_cose(stmt))
            self.assertIsInstance(obj, cbor2.CBORTag)
            self.assertEqual(obj.tag, 18)
            protected, unprotected, payload, sig = obj.value
            self.assertEqual(cbor2.loads(protected), {1: -19, 3: ct, 4: kid})
            self.assertEqual(unprotected, {})
            self.assertEqual(len(sig), 64)
            self.assertEqual(cbor2.loads(payload), stmt["body"])

    def test_roundtrip_through_bytes_is_accepted_by_gate(self):
        p, r = self._good()
        p2 = S.from_cose(S.to_cose(p))
        r2 = [S.from_cose(S.to_cose(x)) for x in r]
        self.assertTrue(self.gate.authorize(PAYLOAD, p2, r2)[0])

    def test_payload_digest_is_sha256_of_deterministic_cbor(self):
        p, _ = self._good()
        import hashlib
        self.assertEqual(p["body"]["payload_digest"], hashlib.sha256(S.dcbor(PAYLOAD)).digest())
        reordered = dict(reversed(list(PAYLOAD.items())))  # same map, different insertion order
        self.assertEqual(S.payload_digest(reordered), S.payload_digest(PAYLOAD))

    def test_deprecated_polymorphic_alg_rejected(self):
        p, r = self._good()
        legacy = S.sign_statement(self.ok, "ov-1", S.CT_RATIFICATION, r[0]["body"], alg=S.ALG_EDDSA)
        self.assertTrue(S.verify_statement(legacy, self.opub, S.CT_RATIFICATION, "ov-1",
                                           allowed_algs=(S.ALG_EDDSA,)))  # signature itself is valid
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [legacy])[0])     # but policy requires -19

    def test_protected_header_tampering_rejected(self):
        p, r = self._good()
        r[0]["protected"] = S.dcbor({1: -19, 3: S.CT_RATIFICATION, 4: b"ov-2"})
        self.assertFalse(self.gate.authorize(PAYLOAD, p, r)[0])

    def test_kid_must_match_signer_identity(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        body = S.ratify(self.ok2, "ov-2", p)["body"]
        wrong_kid = S.sign_statement(self.ok2, "ov-1", S.CT_RATIFICATION, body)  # valid sig by ov-2, kid says ov-1
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [wrong_kid])[0])

    def test_content_type_confusion_rejected(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        body = S.ratify(self.ok, "ov-1", p)["body"]
        as_proposal_type = S.sign_statement(self.ok, "ov-1", S.CT_PROPOSAL, body)  # right key, wrong role
        self.assertFalse(self.gate.authorize(PAYLOAD, p, [as_proposal_type])[0])

    def test_unprotected_header_parameters_rejected(self):
        data = _cose_with_payload_bytes(self.ak, "agent-1", S.CT_PROPOSAL, S.dcbor({"v": 1}),
                                        unprotected={4: b"agent-1"})
        with self.assertRaises(ValueError):
            S.from_cose(data)

    def test_non_deterministic_payloads_rejected(self):
        cases = {
            "unsorted map keys": bytes.fromhex("a2") + S.dcbor("v") + S.dcbor(1) + S.dcbor("a") + S.dcbor(2),
            "non-preferred integer": bytes.fromhex("a1") + S.dcbor("v") + bytes.fromhex("1801"),
            "duplicate map key": bytes.fromhex("a2") + S.dcbor("v") + S.dcbor(1) + S.dcbor("v") + S.dcbor(2),
            "indefinite-length map": bytes.fromhex("bf") + S.dcbor("v") + S.dcbor(1) + bytes.fromhex("ff"),
        }
        for name, payload_bytes in cases.items():
            with self.subTest(case=name):
                data = _cose_with_payload_bytes(self.ak, "agent-1", S.CT_PROPOSAL, payload_bytes)
                with self.assertRaises(ValueError):
                    S.from_cose(data)

    def test_non_deterministic_protected_header_rejected(self):
        p, _ = self._good()
        hdr = bytes.fromhex("a3") + S.dcbor(4) + S.dcbor(b"agent-1") + S.dcbor(1) + S.dcbor(-19) \
            + S.dcbor(3) + S.dcbor(S.CT_PROPOSAL)  # same header, keys out of order
        stmt = dict(p, protected=hdr, sig=self.ak.sign(S.dcbor(["Signature1", hdr, b"", S.dcbor(p["body"])])).hex())
        self.assertFalse(S.verify_statement(stmt, self.apub, S.CT_PROPOSAL, "agent-1"))


class CrossImplementationTests(unittest.TestCase):
    """Artifacts produced by sar_cose verified by code that does not use sar_cose's encoder or
    verifier, and vice versa."""

    def setUp(self):
        self.ak, self.apub = S.new_keypair()

    def test_independent_verifier_cbor2_plus_cryptography(self):
        p = S.make_proposal(self.ak, "agent-1", PAYLOAD)
        tag = cbor2.loads(S.to_cose(p))                         # decode with cbor2, not sar_cose
        protected, _unprot, payload, sig = tag.value
        self.assertEqual(cbor2.loads(protected)[1], -19)
        to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.apub)).verify(sig, to_be_signed)  # raises if invalid

    def test_pycose_verifies_sar_cose_output(self):
        from pycose.keys import OKPKey
        from pycose.keys.curves import Ed25519
        from pycose.messages import Sign1Message
        # pycose 1.1.0 does not implement alg -19, so this interop check uses polymorphic EdDSA (-8)
        body = S.make_proposal(self.ak, "agent-1", PAYLOAD)["body"]
        stmt = S.sign_statement(self.ak, "agent-1", S.CT_PROPOSAL, body, alg=S.ALG_EDDSA)
        msg = Sign1Message.decode(S.to_cose(stmt))
        msg.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.apub))
        self.assertTrue(msg.verify_signature())

    def test_sar_cose_verifies_pycose_output(self):
        from pycose.algorithms import EdDSA
        from pycose.headers import KID, Algorithm, ContentType
        from pycose.keys import OKPKey
        from pycose.keys.curves import Ed25519
        from pycose.messages import Sign1Message
        body = S.make_proposal(self.ak, "agent-1", PAYLOAD)["body"]
        msg = Sign1Message(phdr={Algorithm: EdDSA, ContentType: S.CT_PROPOSAL, KID: b"agent-1"},
                           payload=S.dcbor(body))
        msg.key = OKPKey(crv=Ed25519, d=_raw_priv(self.ak), x=bytes.fromhex(self.apub))
        stmt = S.from_cose(msg.encode())
        self.assertEqual(stmt["body"], body)
        self.assertTrue(S.verify_statement(stmt, self.apub, S.CT_PROPOSAL, "agent-1", allowed_algs=(S.ALG_EDDSA,)))
        self.assertFalse(S.verify_statement(stmt, self.apub, S.CT_PROPOSAL, "agent-1"))  # -8 not allowed by default


if __name__ == "__main__":
    unittest.main()
