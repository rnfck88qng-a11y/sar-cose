"""Generate the SAR profile test vectors (spec/test-vectors/*.json) deterministically.

    python3 spec/gen_vectors.py            # (re)write spec/test-vectors/
    python3 spec/gen_vectors.py --check    # regenerate in memory and fail if any file differs

This script deliberately imports NEITHER implementation (sar_cose, sar_indep). It has its own
deterministic CBOR encoder and builds COSE_Sign1 structures by hand, so that the vectors are
derived from the profile text and not from either implementation. Expected outcomes are
written by hand from the profile's rules, one fault per vector (SAR-REQ-095).

Keys are Ed25519 keys whose 32-byte secret seeds are the published test keys of RFC 8032,
Section 7.1 (TEST 1, TEST 2, TEST 3, TEST 1024, TEST SHA(abc)); the script checks that the
derived public keys equal the published ones. Two further keys use seeds SHA-256 of a fixed
ASCII label. Ed25519 signatures are deterministic (RFC 8032), and all times, nonces and payloads
are fixed, so the vectors are byte-stable across runs.
"""
import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = pathlib.Path(__file__).resolve().parent / "test-vectors"
TAU = 30
T0 = 1760000000  # 2025-10-09T08:53:20Z, an arbitrary fixed instant

# ------------------------------------------------------------------ keys (RFC 8032 section 7.1)
RFC8032 = {
    "TEST 1": ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
               "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    "TEST 2": ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
               "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    "TEST 3": ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
               "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
    "TEST 1024": ("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                  "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
    "TEST SHA(abc)": ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                      "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
}


def _key(seed_hex):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return k, pub


KEYS = {}
for role, src in [("agent-1", "TEST 1"), ("ov-1", "TEST 2"), ("ov-2", "TEST 3"), ("ov-3", "TEST 1024"),
                  ("ts-1", "TEST SHA(abc)")]:
    seed, published = RFC8032[src]
    k, pub = _key(seed)
    assert pub == published, f"RFC 8032 {src}: derived public key differs from the published one"
    KEYS[role] = {"seed": seed, "public": pub, "source": f"RFC 8032 section 7.1 {src}"}
for role, label in [("outsider", "SAR test vector key: outsider"), ("agent-2", "SAR test vector key: agent-2"),
                    ("ts-2", "SAR test vector key: ts-2")]:
    seed = hashlib.sha256(label.encode()).hexdigest()
    KEYS[role] = {"seed": seed, "public": _key(seed)[1], "source": f"seed = SHA-256(ASCII {label!r})"}


def priv(role):
    return _key(KEYS[role]["seed"])[0]


# ------------------------------------------------------------------ own deterministic CBOR
class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class Raw:
    """Pre-encoded CBOR bytes, inserted verbatim (used to build NON-deterministic encodings)."""

    def __init__(self, b):
        self.b = b


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("too large")


def enc(v):
    if isinstance(v, Raw):
        return v.b
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        assert len({k for k, _ in items}) == len(items)
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return head(6, v.tag) + enc(v.value)
    if isinstance(v, float):
        import struct
        return b"\xfb" + struct.pack(">d", v)  # only for negative vectors
    raise TypeError(type(v))


def H(b):
    return hashlib.sha256(b).digest()


CT_P, CT_R = "application/sar-proposal+cbor", "application/sar-ratification+cbor"


def protected(ct, kid, alg=-19, extra=None, drop=None):
    m = {1: alg, 3: ct, 4: kid.encode()}
    if extra:
        m.update(extra)
    if drop:
        del m[drop]
    return enc(m)


def cose(prot, body_bytes, signer, unprotected=None, sig_mutate=None, tag=18, arr_len=4, payload_override="_"):
    sig = priv(signer).sign(enc(["Signature1", prot, b"", body_bytes]))
    if sig_mutate:
        sig = sig_mutate(sig)
    payload = body_bytes if payload_override == "_" else payload_override
    arr = [prot, unprotected if unprotected is not None else {}, payload, sig][:arr_len]
    return enc(Tag(tag, arr)) if tag is not None else enc(arr)


def proposal_id(body):
    return H(enc({k: v for k, v in body.items() if k != "proposal_id"})).hex()[:32]


PAYLOAD = {"action_type": "wire_transfer", "amount": 5000, "currency": "EUR", "destination_account": "DE00",
           "transaction_id": "tx-0001"}


def proposal(payload=PAYLOAD, agent="agent-1", signer=None, issued=T0, ttl=60, nonce="n-0001", policy_id="p1",
             body_edit=None, pid=None, payload_bytes=None, **cose_kw):
    pb = payload_bytes if payload_bytes is not None else enc(payload)
    body = {"v": 1, "agent_id": agent, "payload_digest": H(pb), "issued_at": issued, "expires_at": issued + ttl,
            "nonce": nonce, "policy_id": policy_id}
    body["proposal_id"] = proposal_id(body)
    if body_edit:
        body_edit(body)
    if pid is not None:
        body["proposal_id"] = pid
    raw_body = cose_kw.pop("raw_body", None)
    prot = cose_kw.pop("prot", None) or protected(CT_P, cose_kw.pop("kid", agent))
    data = cose(prot, raw_body if raw_body is not None else enc(body), signer or KEYS_SIGNER.get(agent, agent),
                **cose_kw)
    return {"body": body, "cose": data, "payload": pb}


KEYS_SIGNER = {"agent-1": "agent-1", "agent-2": "agent-2"}


def ratification(prop, overseer="ov-1", signer=None, verdict="APPROVED", reviewed=T0 + 10, ttl=60, policy_id="p1",
                 body_edit=None, digest=None, pid=None, **cose_kw):
    body = {"v": 1, "proposal_digest": digest if digest is not None else H(prop["cose"]),
            "proposal_id": pid if pid is not None else prop["body"]["proposal_id"], "overseer_id": overseer,
            "verdict": verdict, "reviewed_at": reviewed, "valid_until": reviewed + ttl, "policy_id": policy_id}
    if body_edit:
        body_edit(body)
    raw_body = cose_kw.pop("raw_body", None)
    prot = cose_kw.pop("prot", None) or protected(CT_R, cose_kw.pop("kid", overseer))
    return cose(prot, raw_body if raw_body is not None else enc(body), signer or overseer, **cose_kw)


def policy(quorum=1, agents=("agent-1",), overseers=("ov-1", "ov-2"), pid="p1", **extra):
    p = {"policy_id": pid, "quorum": quorum,
         "authorized_agents": {a: KEYS[a]["public"] for a in agents},
         "authorized_overseers": {o: KEYS[o]["public"] for o in overseers}}
    p.update(extra)
    return p


# ------------------------------------------------------------------ vector assembly
VECTORS = []
OFFLINE_FALSE = {"policy_invalid", "missing_evidence", "invalid_statement", "unauthorized_signer", "binding_mismatch",
                 "duplicate_ratification", "rejected", "quorum_not_met"}


def step(prop, rats, now, payload_bytes=None, **kw):
    s = {"payload_cbor": (payload_bytes if payload_bytes is not None else prop["payload"]).hex() if prop else
         enc(PAYLOAD).hex(),
         "proposal_cose": prop["cose"].hex() if prop else None,
         "ratifications_cose": [r.hex() for r in rats], "now": now}
    s.update(kw)
    return s


def outcome(decision, cls=None, sub=None, logged=True):
    """cls is the required deny class, or a list of classes when a fault necessarily implies a
    second one (the evaluation order is not normative, SAR-REQ-095)."""
    return {"decision": decision, "deny_class": cls, "deny_subclass": sub, "log_records_added": 1 if logged else None}


def add(vid, desc, reqs, pol, steps, outcomes, offline=None, offline_policy=None, cddl_invalid=(), interfaces=(),
        offline_at=None):
    """offline: expected verify_record_offline(step0 statements, policy) without `at`; default
    derived from rule S11/S13: a record is offline-valid unless its first outcome is a denial
    in a class that offline verification also checks. offline_at: list of (t, expected)."""
    first = outcomes[0]
    fc = first["deny_class"]
    fc = fc[0] if isinstance(fc, list) else fc
    first = dict(first, deny_class=fc)
    if offline is None:
        offline = first["decision"] == "ALLOW" or first["deny_class"] not in OFFLINE_FALSE and \
            first["deny_class"] != "time_invalid"
    if offline_at is None:
        # S13: ignoring replay and payload, gate allows at t iff offline(at=t)
        offline_at = [(steps[0]["now"], offline and first["deny_class"] not in ("time_invalid",))]
    v = {"id": vid, "description": desc, "requirements": sorted(set(reqs)), "kind": "decision", "tau": TAU,
         "interfaces": list(interfaces), "cddl_invalid": list(cddl_invalid),
         "inputs": {"keys": {k: KEYS[k] for k in sorted(KEYS)}, "policy": pol, "steps": steps},
         "expected": {"steps": outcomes,
                      "offline": {"policy": offline_policy if offline_policy is not None else pol, "result": offline,
                                  "at": [{"t": t, "result": r} for t, r in offline_at]}}}
    VECTORS.append(v)


def enc_vector(vid, desc, value_json, expected_hex, reqs=("SAR-REQ-010",)):
    VECTORS.append({"id": vid, "description": desc, "requirements": list(reqs), "kind": "encoding",
                    "inputs": {"value": value_json}, "expected": {"cbor": expected_hex}})


def dec_vector(vid, desc, hexdata, reqs):
    VECTORS.append({"id": vid, "description": desc, "requirements": list(reqs), "kind": "decoding",
                    "inputs": {"cbor": hexdata}, "expected": {"result": "reject"}})


def J(v):
    """Typed JSON form of a CBOR value (see README in test-vectors)."""
    if v is True or v is False:
        return {"bool": v}
    if v is None:
        return {"null": True}
    if isinstance(v, int):
        return {"int": str(v)}
    if isinstance(v, bytes):
        return {"bytes": v.hex()}
    if isinstance(v, str):
        return {"text": v}
    if isinstance(v, list):
        return {"array": [J(x) for x in v]}
    if isinstance(v, dict):
        return {"map": [[J(k), J(x)] for k, x in v.items()]}
    if isinstance(v, Tag):
        return {"tag": v.tag, "value": J(v.value)}
    raise TypeError(type(v))


ALLOW = outcome("ALLOW")
BASE_REQS = ["SAR-REQ-090", "SAR-REQ-095", "SAR-REQ-100", "SAR-REQ-102"]


def D(cls, sub=None, logged=True):
    return outcome("DENY", cls, sub, logged)


def build():
    VECTORS.clear()
    # ---------------- encoding (RFC 8949 Appendix A subset; integers, strings, arrays, maps, tags)
    appa = [(0, "00"), (1, "01"), (10, "0a"), (23, "17"), (24, "1818"), (25, "1819"), (100, "1864"), (1000, "1903e8"),
            (1000000, "1a000f4240"), (1000000000000, "1b000000e8d4a51000"),
            (18446744073709551615, "1bffffffffffffffff"), (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"),
            (b"", "40"), (bytes.fromhex("01020304"), "4401020304"), ("", "60"), ("a", "6161"), ("IETF", "6449455446"),
            ("\"\\", "62225c"), ("ü", "62c3bc"), ("水", "63e6b0b4"), ([], "80"), ([1, 2, 3], "83010203"),
            ([1, [2, 3], [4, 5]], "8301820203820405"),
            (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
            ({}, "a0"), ({1: 2, 3: 4}, "a201020304"), ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
            (["a", {"b": "c"}], "826161a161626163"), (False, "f4"), (True, "f5"), (None, "f6"),
            (Tag(1, 1363896240), "c11a514b67b0")]
    for i, (val, hx) in enumerate(appa, 1):
        assert enc(val).hex() == hx, (val, enc(val).hex(), hx)
        enc_vector(f"enc-{i:03d}", f"RFC 8949 Appendix A: {hx}", J(val), hx)
    v = {"a": 1, 1000: 2}
    assert enc(v).hex() == "a21903e8026161" + "01"
    enc_vector("enc-100", "Map keys sorted bytewise by their encodings (1000 = 0x1903e8 before \"a\" = 0x6161), "
               "not length-first", J(v), enc(v).hex())
    v = {"b": 1, "a": 2, 10: 3, -1: 4}
    enc_vector("enc-101", "Mixed integer and text keys in bytewise order", J(v), enc(v).hex())
    # ---------------- decoding: must reject
    for vid, desc, hx, reqs in [
            ("dec-001", "integer 23 with a one-byte argument (not preferred)", "1817", ["SAR-REQ-011"]),
            ("dec-002", "integer 1 with a two-byte argument", "190001", ["SAR-REQ-011"]),
            ("dec-003", "text \"a\" with a one-byte length argument", "780161", ["SAR-REQ-011"]),
            ("dec-004", "indefinite-length byte string", "5f4101ff", ["SAR-REQ-011"]),
            ("dec-005", "indefinite-length array", "9f01ff", ["SAR-REQ-011"]),
            ("dec-006", "indefinite-length map", "bf616101ff", ["SAR-REQ-011"]),
            ("dec-007", "map keys not in bytewise order {\"b\":1,\"a\":1}", "a2616201616101", ["SAR-REQ-011"]),
            ("dec-008", "duplicate map key {\"a\":1,\"a\":2}", "a2616101616102", ["SAR-REQ-011"]),
            ("dec-009", "trailing byte after a complete item", "0000", ["SAR-REQ-011"]),
            ("dec-010", "half-precision float 1.0", "f93c00", ["SAR-REQ-012"]),
            ("dec-011", "double-precision float 1.1", "fb3ff199999999999a", ["SAR-REQ-012"]),
            ("dec-012", "single-precision float 100000.0", "fa47c35000", ["SAR-REQ-012"])]:
        dec_vector(vid, desc, hx, reqs)

    P1 = policy()
    P2 = policy(quorum=2)
    p = proposal()
    r1 = ratification(p)
    r2 = ratification(p, overseer="ov-2", reviewed=T0 + 12)
    now = T0 + 20

    def ratfault(**kw):
        """S4 pattern: a valid approval by ov-1 that alone meets quorum 1, plus a faulty
        ratification by ov-2; the request must be denied because of the faulty one."""
        kw.setdefault("overseer", "ov-2")
        kw.setdefault("reviewed", T0 + 12)
        return [r1, ratification(p, **kw)]
    WIRE = ["SAR-REQ-001", "SAR-REQ-002", "SAR-REQ-003", "SAR-REQ-004", "SAR-REQ-005", "SAR-REQ-006", "SAR-REQ-007",
            "SAR-REQ-008", "SAR-REQ-020", "SAR-REQ-022", "SAR-REQ-030", "SAR-REQ-031", "SAR-REQ-032", "SAR-REQ-033",
            "SAR-REQ-040", "SAR-REQ-044", "SAR-REQ-045", "SAR-REQ-050", "SAR-REQ-061", "SAR-REQ-070", "SAR-REQ-080",
            "SAR-REQ-101"]

    # ---------------- positive
    add("gate-001", "Valid proposal and one approval, quorum 1: ALLOW", BASE_REQS + WIRE, P1,
        [step(p, [r1], now)], [ALLOW])
    add("gate-002", "Valid proposal and two approvals, quorum 2: ALLOW", BASE_REQS + WIRE, P2,
        [step(p, [r1, r2], now)], [ALLOW])
    pb = proposal(nonce=b"\x6e\x31")
    add("gate-003", "Nonce as a byte string: ALLOW", BASE_REQS + ["SAR-REQ-020"], P1,
        [step(pb, [ratification(pb)], now)], [ALLOW])
    pe = proposal(nonce="é" * 256)
    add("gate-004", "Nonce of 256 code points (512 octets): ALLOW (length counted in code points)",
        BASE_REQS + ["SAR-REQ-020", "SAR-REQ-023"], P1, [step(pe, [ratification(pe)], now)], [ALLOW])
    long_id = "a" * 256
    KEYS_SIGNER[long_id] = "agent-1"
    Pl = policy()
    Pl["authorized_agents"] = {long_id: KEYS["agent-1"]["public"]}
    pl = proposal(agent=long_id)
    add("gate-005", "Agent identifier of 256 code points: ALLOW", BASE_REQS + ["SAR-REQ-023"], Pl,
        [step(pl, [ratification(pl)], now)], [ALLOW])
    Pl2 = policy()
    Pl2["authorized_agents"] = {"a" * 257: KEYS["agent-1"]["public"]}
    add("gate-006", "Policy with an agent identifier of 257 code points: policy invalid", BASE_REQS +
        ["SAR-REQ-023", "SAR-REQ-040"], Pl2, [step(p, [r1], now)], [D("policy_invalid")])

    # ---------------- COSE structure (Section 5)
    def flip_last(sig):
        return sig[:-1] + bytes([sig[-1] ^ 1])
    cases = [
        ("gate-010", "Proposal as an untagged COSE_Sign1 array", ["SAR-REQ-001"], dict(tag=None), ["proposal"]),
        ("gate-011", "Proposal with CBOR tag 17 instead of 18", ["SAR-REQ-001"], dict(tag=17), ["proposal"]),
        ("gate-012", "Proposal COSE array with three elements", ["SAR-REQ-001"], dict(arr_len=3), ["proposal"]),
        ("gate-013", "Proposal with a non-empty unprotected header {4: kid}", ["SAR-REQ-006"],
         dict(unprotected={4: b"agent-1"}), ["proposal"]),
        ("gate-014", "Proposal protected header with an extra label 5", ["SAR-REQ-002"],
         dict(prot=protected(CT_P, "agent-1", extra={5: b""})), ["proposal"]),
        ("gate-015", "Proposal protected header without kid", ["SAR-REQ-002"],
         dict(prot=protected(CT_P, "agent-1", drop=4)), ["proposal"]),
        ("gate-016", "Proposal signed correctly but with alg -8 (polymorphic EdDSA)", ["SAR-REQ-003"],
         dict(prot=protected(CT_P, "agent-1", alg=-8)), ["proposal"]),
        ("gate-017", "Proposal body signed with the ratification content type", ["SAR-REQ-004"],
         dict(prot=protected(CT_R, "agent-1")), ["proposal"]),
        ("gate-018", "Proposal kid differs from agent_id", ["SAR-REQ-005"], dict(kid="agent-2"), []),
        ("gate-019", "Proposal payload nil (detached)", ["SAR-REQ-007"], dict(payload_override=None), ["proposal"]),
        ("gate-020", "Proposal signature with one bit flipped", ["SAR-REQ-008"], dict(sig_mutate=flip_last), []),
        ("gate-021", "Proposal signature truncated to 63 bytes", ["SAR-REQ-008"],
         dict(sig_mutate=lambda s: s[:63]), ["proposal"]),
        ("gate-022", "Protected header with alg -19 in a non-preferred two-byte encoding (signed)", ["SAR-REQ-002",
                                                                                                    "SAR-REQ-011"],
         dict(prot=b"\xa3\x01\x38\x12" + enc(3) + enc(CT_P) + enc(4) + enc(b"agent-1")), []),
    ]
    for vid, desc, reqs, kw, inv in cases:
        pp = proposal(**kw)
        rr = ratification(pp)
        add(vid, desc + ": DENY invalid_statement", BASE_REQS + reqs, P1, [step(pp, [rr], now)],
            [D("invalid_statement")], cddl_invalid=inv)
    # body not deterministically encoded (keys unsorted), validly signed
    body = proposal()["body"]
    unsorted = head(5, len(body)) + b"".join(enc(k) + enc(x) for k, x in sorted(body.items(), reverse=True))
    pp = proposal(raw_body=unsorted)
    add("gate-023", "Proposal body with map keys out of order, validly signed: DENY invalid_statement",
        BASE_REQS + ["SAR-REQ-007", "SAR-REQ-011"], P1, [step(pp, [ratification(pp)], now)],
        [D("invalid_statement")])
    pf = proposal(body_edit=lambda b: b.__setitem__("expires_at", float(T0 + 60)))
    add("gate-024", "Proposal body with expires_at as a float, validly signed: DENY invalid_statement",
        BASE_REQS + ["SAR-REQ-012", "SAR-REQ-020"], P1, [step(pf, [ratification(pf)], now)],
        [D("invalid_statement")], cddl_invalid=["proposal"])
    add("gate-025", "ov-2's ratification signature with one bit flipped, next to a valid approval meeting quorum 1: "
        "DENY invalid_statement", BASE_REQS + ["SAR-REQ-008", "SAR-REQ-052"], P1,
        [step(p, ratfault(sig_mutate=flip_last), now)], [D("invalid_statement")])

    # ---------------- body shape (Section 7)
    shape = [
        ("gate-030", "Proposal with an extra member action_type (proposal_id recomputed, validly signed)",
         ["SAR-REQ-020"], dict(body_edit=lambda b: (b.__setitem__("action_type", "wire_transfer"),
                                                   b.__setitem__("proposal_id", proposal_id(b)))), ["proposal"]),
        ("gate-031", "Proposal without nonce", ["SAR-REQ-020"],
         dict(body_edit=lambda b: (b.pop("nonce"), b.__setitem__("proposal_id", proposal_id(b)))), ["proposal"]),
        ("gate-032", "Proposal with v = 2", ["SAR-REQ-020"],
         dict(body_edit=lambda b: (b.__setitem__("v", 2), b.__setitem__("proposal_id", proposal_id(b)))),
         ["proposal"]),
        ("gate-033", "Proposal with a 31-byte payload_digest (implies payload_mismatch)", ["SAR-REQ-020"],
         dict(body_edit=lambda b: (b.__setitem__("payload_digest", b["payload_digest"][:31]),
                                   b.__setitem__("proposal_id", proposal_id(b)))), ["proposal"]),
        ("gate-034", "Proposal with an empty nonce", ["SAR-REQ-020"], dict(nonce=""), ["proposal"]),
        ("gate-035", "Proposal with issued_at = -1", ["SAR-REQ-020"],
         dict(body_edit=lambda b: (b.__setitem__("issued_at", -1), b.__setitem__("proposal_id", proposal_id(b)))),
         ["proposal"]),
        ("gate-036", "Proposal with issued_at == expires_at (ttl 0)", ["SAR-REQ-021"], dict(ttl=0), []),
        ("gate-041", "Proposal with an arbitrary proposal_id (validly signed)", ["SAR-REQ-032"],
         dict(pid="0" * 32), []),
        ("gate-042", "Proposal with a nonce of 257 code points", ["SAR-REQ-020"], dict(nonce="x" * 257), []),
    ]
    also = {"gate-033": "payload_mismatch", "gate-036": "time_invalid"}
    for vid, desc, reqs, kw, inv in shape:
        pp = proposal(**kw)
        cls = ["invalid_statement", also[vid]] if vid in also else "invalid_statement"
        add(vid, desc + ": DENY invalid_statement", BASE_REQS + reqs, P1,
            [step(pp, [ratification(pp, reviewed=T0)], now if "ttl" not in kw else T0)],
            [D(cls)], cddl_invalid=inv)
    rshape = [
        ("gate-037", "Ratification with reviewed_at == valid_until (ttl 0)", ["SAR-REQ-021"], dict(ttl=0), []),
        ("gate-038", "Ratification with an extra member reviewer_context", ["SAR-REQ-022"],
         dict(body_edit=lambda b: b.__setitem__("reviewer_context", {})), ["ratification:0"]),
        ("gate-039", "Ratification with verdict \"approved\" (lower case)", ["SAR-REQ-024"],
         dict(verdict="approved"), ["ratification:0"]),
        ("gate-040", "Ratification with verdict 1 (integer)", ["SAR-REQ-022", "SAR-REQ-024"], dict(verdict=1),
         ["ratification:0"]),
    ]
    for vid, desc, reqs, kw, inv in rshape:
        add(vid, desc + " by ov-2, next to a valid approval by ov-1 that meets quorum 1: DENY invalid_statement",
            BASE_REQS + reqs + ["SAR-REQ-052"], P1, [step(p, ratfault(**kw), now)], [D("invalid_statement")],
            cddl_invalid=[i.replace(":0", ":1") for i in inv])

    # ---------------- binding and digests (Section 8)
    decoy = proposal(nonce="n-decoy")
    add("gate-050", "ov-2's approval of another proposal presented with this one (next to ov-1's valid approval): "
        "DENY binding_mismatch", BASE_REQS + ["SAR-REQ-031", "SAR-REQ-033", "SAR-REQ-052"], P1,
        [step(p, [r1, ratification(decoy, overseer="ov-2", reviewed=T0 + 12)], now)], [D("binding_mismatch")])
    add("gate-051", "Ratification with the right proposal_digest but another proposal_id: DENY binding_mismatch",
        BASE_REQS + ["SAR-REQ-033", "SAR-REQ-052"], P1, [step(p, ratfault(pid=decoy["body"]["proposal_id"]), now)],
        [D("binding_mismatch")])
    add("gate-052", "Ratification with the right proposal_id but the digest of another proposal: DENY "
        "binding_mismatch", BASE_REQS + ["SAR-REQ-031", "SAR-REQ-052"], P1,
        [step(p, ratfault(digest=H(decoy["cose"])), now)], [D("binding_mismatch")])
    p2 = proposal(policy_id="p2")
    add("gate-053", "Proposal bound to policy p2 presented under p1: DENY binding_mismatch",
        BASE_REQS + ["SAR-REQ-044"], P1, [step(p2, [ratification(p2, policy_id="p1")], now)],
        [D("binding_mismatch")])
    add("gate-054", "ov-2's ratification bound to policy p2: DENY binding_mismatch",
        BASE_REQS + ["SAR-REQ-044", "SAR-REQ-052"], P1, [step(p, ratfault(policy_id="p2"), now)],
        [D("binding_mismatch")])
    pP = proposal(policy_id="P1")
    add("gate-055", "Proposal policy_id \"P1\" under policy \"p1\" (no case folding): DENY binding_mismatch",
        BASE_REQS + ["SAR-REQ-034", "SAR-REQ-044"], P1, [step(pP, [ratification(pP, policy_id="P1")], now)],
        [D("binding_mismatch")])
    other = dict(PAYLOAD, amount=5001)
    add("gate-056", "Runtime payload differs (amount 5001): DENY payload_mismatch",
        BASE_REQS + ["SAR-REQ-030", "SAR-REQ-070"], P1, [step(p, [r1], now, payload_bytes=enc(other))],
        [D("payload_mismatch")])
    flipped = H(enc(PAYLOAD))[:31] + bytes([H(enc(PAYLOAD))[31] ^ 1])
    pd = proposal(body_edit=lambda b: (b.__setitem__("payload_digest", flipped),
                                       b.__setitem__("proposal_id", proposal_id(b))))
    add("gate-057", "Proposal digest equal to the payload digest in the first 31 bytes only: DENY payload_mismatch",
        BASE_REQS + ["SAR-REQ-030", "SAR-REQ-034"], P1,
        [step(pd, [ratification(pd)], now, payload_bytes=enc(PAYLOAD))], [D("payload_mismatch")])
    items = sorted(((enc(k), enc(x)) for k, x in PAYLOAD.items()), reverse=True)
    unsorted_payload = head(5, len(items)) + b"".join(k + x for k, x in items)
    add("gate-058", "Payload octets with map keys out of order (decode to the approved value): DENY "
        "payload_mismatch", BASE_REQS + ["SAR-REQ-011", "SAR-REQ-071"], P1,
        [step(p, [r1], now, payload_bytes=unsorted_payload)], [D("payload_mismatch")], interfaces=["payload_bytes"])
    add("gate-059", "Payload octets with a trailing byte: DENY payload_mismatch", BASE_REQS + ["SAR-REQ-011",
                                                                                              "SAR-REQ-071"], P1,
        [step(p, [r1], now, payload_bytes=enc(PAYLOAD) + b"\x00")], [D("payload_mismatch")],
        interfaces=["payload_bytes"])
    fl = enc({"amount": 1.5})
    pfl = proposal(payload_bytes=fl)
    add("gate-059b", "Payload containing a float, proposal digest over those octets: DENY payload_mismatch",
        BASE_REQS + ["SAR-REQ-012", "SAR-REQ-071"], P1, [step(pfl, [ratification(pfl)], now, payload_bytes=fl)],
        [D("payload_mismatch")], interfaces=["payload_bytes"])

    # ---------------- policy (Section 9)
    pol_cases = [
        ("gate-060", "quorum 0", ["SAR-REQ-040"], policy(quorum=0)),
        ("gate-061", "quorum 3 with two overseers", ["SAR-REQ-040"], policy(quorum=3)),
        ("gate-062", "overseer key in upper-case hex", ["SAR-REQ-040"],
         dict(policy(), authorized_overseers={"ov-1": KEYS["ov-1"]["public"].upper(), "ov-2": KEYS["ov-2"]["public"]})),
        ("gate-063", "unknown member policy_version (future member, MUST-reject in v1)", ["SAR-REQ-042"],
         policy(policy_version=2)),
        ("gate-064", "unknown member permitted_action_types", ["SAR-REQ-042"],
         policy(permitted_action_types=["wire_transfer"])),
        ("gate-065", "one key registered for two overseers", ["SAR-REQ-041"],
         dict(policy(), authorized_overseers={"ov-1": KEYS["ov-1"]["public"], "ov-2": KEYS["ov-1"]["public"]})),
        ("gate-066", "identifier both agent and overseer", ["SAR-REQ-041"],
         dict(policy(), authorized_overseers={"ov-1": KEYS["ov-1"]["public"], "agent-1": KEYS["ov-2"]["public"]})),
        ("gate-067", "agent key also registered for an overseer", ["SAR-REQ-041"],
         dict(policy(), authorized_overseers={"ov-1": KEYS["ov-1"]["public"], "ov-2": KEYS["agent-1"]["public"]})),
        ("gate-068", "no authorized agents", ["SAR-REQ-040"], dict(policy(), authorized_agents={})),
    ]
    for vid, desc, reqs, pol in pol_cases:
        inv = ["policy"] if vid in ("gate-063", "gate-064", "gate-068") else []
        add(vid, f"Policy with {desc}: every request DENY policy_invalid", BASE_REQS + reqs, pol,
            [step(p, [r1], now)], [D("policy_invalid")], cddl_invalid=inv)
    KEYS_SIGNER["agent-x"] = "outsider"
    px = proposal(agent="agent-x", signer="outsider")
    add("gate-070", "Proposal by an agent not in the policy: DENY unauthorized_signer", BASE_REQS + ["SAR-REQ-045"],
        P1, [step(px, [ratification(px)], now)], [D("unauthorized_signer")])
    add("gate-071", "Ratification by an overseer not in the policy: DENY unauthorized_signer",
        BASE_REQS + ["SAR-REQ-045", "SAR-REQ-052"], P1,
        [step(p, ratfault(overseer="ov-x", signer="outsider"), now)], [D("unauthorized_signer")])
    pw = proposal(signer="outsider")
    add("gate-072", "Proposal for agent-1 signed with another key: DENY invalid_statement",
        BASE_REQS + ["SAR-REQ-008", "SAR-REQ-045"], P1, [step(pw, [ratification(pw)], now)],
        [D("invalid_statement")])
    Prev = policy(overseers=("ov-1",))
    rov2 = ratification(p, overseer="ov-2")
    add("gate-073", "Revocation: ov-2 removed from the policy after ratifying: DENY unauthorized_signer; offline "
        "verification under the earlier policy succeeds", BASE_REQS + ["SAR-REQ-043"], Prev,
        [step(p, [rov2], now)], [D("unauthorized_signer")], offline=True, offline_policy=P1,
        offline_at=[(now, True)])
    Prot = dict(policy(), authorized_overseers={"ov-1": KEYS["ov-3"]["public"], "ov-2": KEYS["ov-2"]["public"]})
    add("gate-074", "Revocation by key replacement: ov-1's key replaced after ratifying: DENY invalid_statement; "
        "offline under the earlier policy succeeds", BASE_REQS + ["SAR-REQ-043"], Prot, [step(p, [r1], now)],
        [D("invalid_statement")], offline=True, offline_policy=P1, offline_at=[(now, True)])

    # ---------------- time (Section 10). proposal [T0, T0+60), ratification [T0+10, T0+70): lo=T0+10, hi=T0+60
    TR = ["SAR-REQ-050", "SAR-REQ-101", "SAR-REQ-102"]
    for vid, t, ok, desc in [("gate-080", T0 + 10 - TAU, True, "t = lo - tau"),
                             ("gate-081", T0 + 10 - TAU - 1, False, "t = lo - tau - 1"),
                             ("gate-082", T0 + 59, True, "t = hi - 1"),
                             ("gate-083", T0 + 60, False, "t = hi (proposal expiry is exact)")]:
        add(vid, f"Evaluation at {desc}: " + ("ALLOW" if ok else "DENY time_invalid"), BASE_REQS + TR, P1,
            [step(p, [r1], t)], [ALLOW if ok else D("time_invalid")], offline=True,
            offline_at=[(t, ok)])
    rs = ratification(p, ttl=20)  # [T0+10, T0+30)
    add("gate-084", "Ratification expiring at T0+30, evaluated at T0+29: ALLOW", BASE_REQS + TR, P1,
        [step(p, [rs], T0 + 29)], [ALLOW], offline=True, offline_at=[(T0 + 29, True)])
    add("gate-085", "Ratification expiring at T0+30, evaluated at T0+30: DENY time_invalid", BASE_REQS + TR +
        ["SAR-REQ-052"], P1, [step(p, [rs], T0 + 30)], [D("time_invalid")], offline=True,
        offline_at=[(T0 + 30, False)])
    add("gate-086", "Ratification issued one second before the proposal: DENY time_invalid",
        BASE_REQS + ["SAR-REQ-051", "SAR-REQ-052"], P1, [step(p, [ratification(p, reviewed=T0 - 1)], T0 + 5)],
        [D("time_invalid")], offline=False)
    add("gate-087", "Ratification issued at the proposal's expires_at: DENY time_invalid",
        BASE_REQS + ["SAR-REQ-051"], P1, [step(p, [ratification(p, reviewed=T0 + 60)], T0 + 59)],
        [D("time_invalid")], offline=False)
    rexp = ratification(p, overseer="ov-2", reviewed=T0, ttl=5)
    add("gate-088", "Quorum 1 met by ov-1, but ov-2's approval in the set has expired: DENY time_invalid (S4)",
        BASE_REQS + ["SAR-REQ-052"], P1, [step(p, [r1, rexp], T0 + 12)], [D("time_invalid")], offline=False)
    ra = ratification(p, reviewed=T0, ttl=5)
    rb = ratification(p, overseer="ov-2", reviewed=T0 + 30, ttl=60)
    add("gate-089", "Two approvals never jointly valid ([T0,T0+5) and [T0+30,T0+90)), evaluated at T0+4 within "
        "the tolerance of the second: DENY time_invalid", BASE_REQS + ["SAR-REQ-053"], P2,
        [step(p, [ra, rb], T0 + 4)], [D("time_invalid")], offline=False)
    rc = ratification(p, reviewed=T0, ttl=10)
    rd = ratification(p, overseer="ov-2", reviewed=T0 + 10, ttl=60)
    add("gate-090", "Touching but disjoint intervals [T0,T0+10) and [T0+10,T0+70): DENY time_invalid",
        BASE_REQS + ["SAR-REQ-053"], P2, [step(p, [rc, rd], T0 + 9)], [D("time_invalid")], offline=False)
    pfut = proposal(issued=T0 + 100, nonce="n-future")
    rfut = ratification(pfut, reviewed=T0 + 100)
    add("gate-091", "Proposal and ratification dated T0+100, evaluated at T0+69 (31 s early): DENY time_invalid",
        BASE_REQS + TR, P1, [step(pfut, [rfut], T0 + 69)], [D("time_invalid")], offline=True,
        offline_at=[(T0 + 69, False)])
    add("gate-092", "Proposal and ratification dated T0+100, evaluated at T0+70 (30 s early): ALLOW",
        BASE_REQS + TR, P1, [step(pfut, [rfut], T0 + 70)], [ALLOW], offline=True, offline_at=[(T0 + 70, True)])

    # ---------------- quorum, duplicates, rejection (Section 11)
    add("gate-100", "Quorum 2 with one approval: DENY quorum_not_met", BASE_REQS + ["SAR-REQ-061"], P2,
        [step(p, [r1], now)], [D("quorum_not_met")])
    add("gate-101", "The same approval presented twice, quorum 1: DENY duplicate_ratification",
        BASE_REQS + ["SAR-REQ-060"], P1, [step(p, [r1, r1], now)], [D("duplicate_ratification")])
    add("gate-102", "Two different approvals by ov-1, quorum 2: DENY duplicate_ratification",
        BASE_REQS + ["SAR-REQ-060"], P2, [step(p, [r1, ratification(p, reviewed=T0 + 11)], now)],
        [D("duplicate_ratification")])
    rrej = ratification(p, overseer="ov-2", verdict="REJECTED", reviewed=T0 + 12)
    add("gate-103", "Quorum 1 met by ov-1 but ov-2 rejected: DENY rejected", BASE_REQS + ["SAR-REQ-062"], P1,
        [step(p, [r1, rrej], now)], [D("rejected")])
    add("gate-104", "Only a rejection: DENY rejected", BASE_REQS + ["SAR-REQ-062"], P1, [step(p, [rrej], now)],
        [D("rejected")])
    add("gate-105", "Empty ratification set: DENY missing_evidence", BASE_REQS + ["SAR-REQ-063"], P1,
        [step(p, [], now)], [D("missing_evidence")])
    add("gate-106", "No proposal: DENY missing_evidence", BASE_REQS + ["SAR-REQ-063"], P1,
        [step(None, [r1], now)], [D("missing_evidence")])

    # ---------------- replay sequences (Section 11)
    REPLAY = BASE_REQS + ["SAR-REQ-080", "SAR-REQ-084"]
    add("seq-110", "Same authorization presented twice at the same instant: ALLOW then DENY replay",
        REPLAY + ["SAR-REQ-080"], P1, [step(p, [r1], now), step(p, [r1], now)], [ALLOW, D("replay")])
    add("seq-111", "Replay 1 s and 39 s later: ALLOW, DENY replay, DENY replay", REPLAY + ["SAR-REQ-083"], P1,
        [step(p, [r1], now), step(p, [r1], now + 1), step(p, [r1], now + 39)], [ALLOW, D("replay"), D("replay")])

    def pr(nonce, payload=PAYLOAD, agent="agent-1"):
        q = proposal(nonce=nonce, payload=payload, agent=agent)
        return q, ratification(q)
    a1, ar1 = pr("n-7", dict(PAYLOAD, transaction_id="tx-a"))
    a2, ar2 = pr("n-7", dict(PAYLOAD, transaction_id="tx-b"))
    add("seq-112", "A new proposal reusing a consumed nonce: ALLOW then DENY replay", REPLAY + ["SAR-REQ-081"], P1,
        [step(a1, [ar1], now), step(a2, [ar2], now)], [ALLOW, D("replay")])
    b1, br1 = pr("N-8", dict(PAYLOAD, transaction_id="tx-c"))
    b2, br2 = pr("n-8", dict(PAYLOAD, transaction_id="tx-d"))
    add("seq-113", "Nonces \"N-8\" and \"n-8\" are different: ALLOW, ALLOW", REPLAY + ["SAR-REQ-081", "SAR-REQ-034"],
        P1, [step(b1, [br1], now), step(b2, [br2], now)], [ALLOW, ALLOW])
    c1, cr1 = pr("n9", dict(PAYLOAD, transaction_id="tx-e"))
    c2, cr2 = pr(b"n9", dict(PAYLOAD, transaction_id="tx-f"))
    add("seq-114", "Nonce text \"n9\" and bytes h'6e39' are different: ALLOW, ALLOW", REPLAY + ["SAR-REQ-081"], P1,
        [step(c1, [cr1], now), step(c2, [cr2], now)], [ALLOW, ALLOW])
    d1, dr1 = pr("n-10", dict(PAYLOAD, transaction_id=5))
    d2, dr2 = pr("n-11", dict(PAYLOAD, transaction_id=5, amount=1))
    add("seq-115", "Integer transaction_id 5 reused by a new proposal: ALLOW then DENY replay",
        REPLAY + ["SAR-REQ-082"], P1, [step(d1, [dr1], now), step(d2, [dr2], now)], [ALLOW, D("replay")])
    e1, er1 = pr("n-12", dict(PAYLOAD, transaction_id=6))
    e2, er2 = pr("n-13", dict(PAYLOAD, transaction_id="6"))
    add("seq-116", "transaction_id 6 and \"6\" are different: ALLOW, ALLOW", REPLAY + ["SAR-REQ-082"], P1,
        [step(e1, [er1], now), step(e2, [er2], now)], [ALLOW, ALLOW])
    nested = {"action_type": "wire_transfer", "meta": {"transaction_id": "nested-1"}}
    f1, fr1 = pr("n-14", nested)
    f2, fr2 = pr("n-15", dict(nested, amount=1))
    add("seq-117", "A nested transaction_id is not consumed: ALLOW, ALLOW", REPLAY + ["SAR-REQ-082"], P1,
        [step(f1, [fr1], now), step(f2, [fr2], now)], [ALLOW, ALLOW])
    add("seq-118", "Denied for missing quorum, then presented with a full quorum: DENY quorum_not_met, ALLOW",
        REPLAY + ["SAR-REQ-084", "SAR-REQ-061"], P2, [step(p, [r1], now), step(p, [r1, r2], now)],
        [D("quorum_not_met"), ALLOW])
    add("seq-119", "Replay after a restart of the gate on a persistent store: ALLOW, DENY replay",
        REPLAY + ["SAR-REQ-085"], P1, [step(p, [r1], now), step(p, [r1], now, restart_before=True)],
        [ALLOW, D("replay")])
    Pa2 = policy(agents=("agent-1", "agent-2"))
    g1, gr1 = pr("n-shared", dict(PAYLOAD, transaction_id="tx-g"))
    g2, gr2 = pr("n-shared", dict(PAYLOAD, transaction_id="tx-h"), agent="agent-2")
    add("seq-120", "Nonce consumed by agent-1 reused by agent-2: ALLOW then DENY replay (nonce scope is the "
        "policy)", REPLAY + ["SAR-REQ-081"], Pa2, [step(g1, [gr1], now), step(g2, [gr2], now)], [ALLOW, D("replay")])

    # ---------------- logging (Section 13)
    add("gate-130", "Valid request but the decision log fails: DENY store_failure (never ALLOW)",
        BASE_REQS + ["SAR-REQ-091"], P1, [step(p, [r1], now, log_fails=True)], [D("store_failure", logged=False)],
        offline=True, offline_at=[(now, True)])
    add("gate-131", "Invalid request (bad ratification signature) and the log fails: DENY store_failure",
        BASE_REQS + ["SAR-REQ-091"], P1,
        [step(p, [ratification(p, sig_mutate=flip_last)], now, log_fails=True)], [D("store_failure", logged=False)],
        offline=False)
    add("seq-132", "A request that could not be recorded consumed nothing: DENY store_failure, then ALLOW",
        BASE_REQS + ["SAR-REQ-091", "SAR-REQ-084"], P1,
        [step(p, [r1], now, log_fails=True), step(p, [r1], now)], [D("store_failure", logged=False), ALLOW],
        offline=True, offline_at=[(now, True)])
    build_scitt()
    return VECTORS


# ------------------------------------------------------------------ SCITT (profile Sections 15-18)
# Own RFC 9162 Merkle tree and RFC 9942-style Receipt construction (no implementation imported).
MAX_AGE = 300
LOG1, LOG2 = "log-1", "log-2"
LOG_KEYS = {LOG1: "ts-1", LOG2: "ts-2"}


def mth(d):
    n = len(d)
    if n == 0:
        return H(b"")
    if n == 1:
        return H(b"\x00" + d[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return H(b"\x01" + mth(d[:k]) + mth(d[k:]))


def _k(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mpath(m, d):
    n = len(d)
    if n <= 1:
        return []
    k = _k(n)
    return mpath(m, d[:k]) + [mth(d[k:])] if m < k else mpath(m - k, d[k:]) + [mth(d[:k])]


def subproof(m, d, b):
    n = len(d)
    if m == n:
        return [] if b else [mth(d)]
    k = _k(n)
    if m <= k:
        return subproof(m, d[:k], b) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def verify_inclusion(leaf_data, index, size, path, root):
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, H(b"\x00" + leaf_data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = H(b"\x01" + p + r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = H(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def set_digest(prop_cose, rats_cose):
    return H(enc([H(prop_cose), sorted(H(r) for r in rats_cose)]))


def entry(kind, prop, rats_cose, t_reg, log_id=LOG1, policy_id="p1"):
    return enc({"v": 1, "kind": kind, "log_id": log_id, "policy_id": policy_id,
                "proposal_id": prop["body"]["proposal_id"], "set_digest": set_digest(prop["cose"], rats_cose),
                "registered_at": t_reg})


def receipt(entries, index, t_reg, log_id=LOG1, signer=None, size=None, alg=-19, extra_hdr=None, kid=None,
            attach_root=False, path_mutate=None, size_in_proof=None, sig_mutate=None, index_in_proof=None):
    size = len(entries) if size is None else size
    root = mth(entries[:size])
    path = mpath(index, entries[:size])
    if path_mutate:
        path = path_mutate(path)
    hdr = {1: alg, 4: (kid or log_id).encode(), 395: 1, 15: {1: log_id, 6: t_reg}}
    if extra_hdr:
        hdr.update(extra_hdr)
    prot = enc(hdr)
    proof = enc([size if size_in_proof is None else size_in_proof, index if index_in_proof is None else index_in_proof,
                 path])
    sig = priv(signer or LOG_KEYS[log_id]).sign(enc(["Signature1", prot, b"", root]))
    if sig_mutate:
        sig = sig_mutate(sig)
    return enc(Tag(18, [prot, {396: {-1: [proof]}}, root if attach_root else None, sig]))


def filler(i):
    return enc({"v": 1, "kind": "authorization", "log_id": LOG1, "policy_id": "p1", "proposal_id": f"{i:032x}",
                "set_digest": H(b"filler %d" % i), "registered_at": T0 - 1000 + i})


OFFLINE_TAR = {"sc-001": True, "sc-002": True, "sc-004": False, "sc-005": False, "sc-008": False, "sc-011": False,
               "sc-011b": True, "sc-012": False, "sc-013": True, "sc-017": False, "sc-023": False, "sc-026": True}


def add_scitt(vid, desc, reqs, pol, steps, outcomes, cddl_invalid=()):
    """OFFLINE_TAR: expected SAR-REQ-139 offline verification of step 0 (statements + Receipt) under
    the policy and trusted logs; it uses no clock, so a stale Receipt (sc-013) and a lying TS within
    the validity window (sc-026) verify offline."""
    exp = {"steps": outcomes}
    if vid in OFFLINE_TAR:
        exp["offline_tar"] = OFFLINE_TAR[vid]
        reqs = list(reqs) + ["SAR-REQ-139"]
    VECTORS.append({"id": vid, "description": desc, "requirements": sorted(set(reqs)), "kind": "scitt", "tau": TAU,
                    "max_receipt_age": MAX_AGE, "cddl_invalid": list(cddl_invalid),
                    "inputs": {"keys": {k: KEYS[k] for k in sorted(KEYS)}, "policy": pol,
                               "trusted_logs": {LOG1: KEYS["ts-1"]["public"]}, "steps": steps},
                    "expected": exp})


def sstep(prop, rats, rec, now, payload_bytes=None):
    s = step(prop, rats, now, payload_bytes=payload_bytes)
    s["receipt_cose"] = rec.hex() if rec is not None else None
    return s


def build_scitt():
    P1 = policy()
    SC = ["SAR-REQ-095", "SAR-REQ-130", "SAR-REQ-131", "SAR-REQ-132", "SAR-REQ-133", "SAR-REQ-137", "SAR-REQ-138"]
    p = proposal(ttl=3600, nonce="n-scitt")
    r1 = ratification(p, ttl=3600)
    r2 = ratification(p, overseer="ov-2", reviewed=T0 + 12, ttl=3600)
    t_reg, now = T0 + 15, T0 + 20
    e = entry("authorization", p, [r1], t_reg)
    log7 = [filler(i) for i in range(4)] + [e] + [filler(i) for i in range(4, 6)]
    assert verify_inclusion(e, 4, 7, mpath(4, log7), mth(log7))
    rec1 = receipt([e], 0, t_reg)
    rec7 = receipt(log7, 4, t_reg)
    ok = outcome("ALLOW")
    add_scitt("sc-001", "Receipt-gated execution, log of one entry: ALLOW", SC + ["SAR-REQ-125", "SAR-REQ-126",
                                                                                 "SAR-REQ-127"], P1,
              [sstep(p, [r1], rec1, now)], [ok])
    add_scitt("sc-002", "Receipt-gated execution, entry at index 4 of a log of 7: ALLOW",
              SC + ["SAR-REQ-125", "SAR-REQ-126", "SAR-REQ-127"], P1, [sstep(p, [r1], rec7, now)], [ok])
    RI = lambda: outcome("DENY", "receipt_invalid")  # noqa: E731
    add_scitt("sc-003", "No Receipt presented to a gate that requires one: DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], None, now)], [RI()])
    add_scitt("sc-004", "Receipt naming the trusted log-1 but signed with another key: DENY receipt_invalid",
              SC + ["SAR-REQ-131"], P1, [sstep(p, [r1], receipt(log7, 4, t_reg, signer="ts-2"), now)], [RI()])
    e2 = entry("authorization", p, [r1], t_reg, log_id=LOG2)
    add_scitt("sc-005", "Receipt from an untrusted log (log-2, correctly signed by its own key): DENY "
              "receipt_invalid", SC + ["SAR-REQ-131"], P1, [sstep(p, [r1], receipt([e2], 0, t_reg, log_id=LOG2), now)],
              [RI()])
    add_scitt("sc-006", "Inclusion path with one byte changed: DENY receipt_invalid", SC + ["SAR-REQ-127"], P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, path_mutate=lambda pa: [pa[0][:-1] + bytes([pa[0][-1] ^ 1])] +
                                      pa[1:]), now)], [RI()])
    add_scitt("sc-007", "Inclusion proof with leaf_index = tree_size: DENY receipt_invalid", SC + ["SAR-REQ-127"],
              P1, [sstep(p, [r1], receipt([e], 0, t_reg, size_in_proof=0), now)], [RI()])
    bad_size = receipt(log7, 4, t_reg, size_in_proof=8)
    # For a log of one entry the root is the leaf hash, so proofs [1, 1, []] and [2, 0, []] reproduce the
    # signed root; only the structural checks of RFC 9162 2.1.3.2 reject them.
    add_scitt("sc-007b", "Log of one entry, proof [tree_size 1, leaf_index 1, []] (reproduces the signed root): "
              "DENY receipt_invalid", SC + ["SAR-REQ-127"], P1,
              [sstep(p, [r1], receipt([e], 0, t_reg, path_mutate=lambda pa: pa, size_in_proof=1, index_in_proof=1),
                     now)], [RI()])
    add_scitt("sc-007c", "Log of one entry, proof [tree_size 2, leaf_index 0, []] (reproduces the signed root): "
              "DENY receipt_invalid", SC + ["SAR-REQ-127"], P1,
              [sstep(p, [r1], receipt([e], 0, t_reg, size_in_proof=2), now)], [RI()])
    add_scitt("sc-008", "Receipt registered for {r1} presented with {r1, r2}: DENY receipt_invalid (another set)",
              SC, P1, [sstep(p, [r1, r2], rec7, now)], [RI()])
    q = proposal(ttl=3600, nonce="n-scitt-other")
    add_scitt("sc-009", "Receipt for one proposal presented with another, validly ratified: DENY receipt_invalid",
              SC, P1, [sstep(q, [ratification(q, ttl=3600)], rec7, now)], [RI()])
    add_scitt("sc-010", "Valid Receipt reused with a different payload: DENY payload_mismatch",
              SC + ["SAR-REQ-070"], P1,
              [sstep(p, [r1], rec7, now, payload_bytes=enc(dict(PAYLOAD, amount=5001)))],
              [outcome("DENY", "payload_mismatch")])
    for vid, tr, good, desc in [("sc-011", T0 + 10 - TAU - 1, False, "lo - tau - 1 (TS clock behind)"),
                                ("sc-011b", T0 + 10 - TAU, True, "lo - tau")]:
        ee = entry("authorization", p, [r1], tr)
        add_scitt(vid, f"Registration time {desc}: " + ("ALLOW" if good else "DENY receipt_invalid"),
                  SC + ["SAR-REQ-134"], P1, [sstep(p, [r1], receipt([ee], 0, tr), now)], [ok if good else RI()])
    ps = proposal(ttl=60, nonce="n-short")
    rs = ratification(ps)  # [T0+10, T0+70); common [T0+10, T0+60)
    es = entry("authorization", ps, [rs], T0 + 60)
    add_scitt("sc-012", "Registration time at hi (statements already expired at registration): DENY receipt_invalid",
              SC + ["SAR-REQ-134"], P1, [sstep(ps, [rs], receipt([es], 0, T0 + 60), T0 + 59)], [RI()])
    for vid, n_, good in [("sc-013", t_reg + MAX_AGE, False), ("sc-014", t_reg + MAX_AGE - 1, True)]:
        add_scitt(vid, f"Presented {n_ - t_reg} s after registration (max_receipt_age {MAX_AGE}): " +
                  ("ALLOW" if good else "DENY receipt_invalid (stale)"), SC + ["SAR-REQ-135"], P1,
                  [sstep(p, [r1], rec1, n_)], [ok if good else RI()])
    for vid, tr, good in [("sc-015", now + TAU + 1, False), ("sc-016", now + TAU, True)]:
        ee = entry("authorization", p, [r1], tr)
        add_scitt(vid, f"TS clock ahead: registered_at = now + {tr - now}: " +
                  ("ALLOW" if good else "DENY receipt_invalid"), SC + ["SAR-REQ-135"], P1,
                  [sstep(p, [r1], receipt([ee], 0, tr), now)], [ok if good else RI()])
    rrej = ratification(p, overseer="ov-2", verdict="REJECTED", reviewed=T0 + 12, ttl=3600)
    ej = entry("rejection", p, [r1], t_reg)
    add_scitt("sc-017", "Receipt for a rejection entry over the same statements presented as authorization: DENY "
              "receipt_invalid", SC + ["SAR-REQ-136"], P1, [sstep(p, [r1], receipt([ej], 0, t_reg), now)], [RI()])
    add_scitt("sc-018", "Valid Receipt presented twice: ALLOW then DENY replay", SC + ["SAR-REQ-080"], P1,
              [sstep(p, [r1], rec7, now), sstep(p, [r1], rec7, now + 1)], [ok, outcome("DENY", "replay")])
    add_scitt("sc-019", "Receipt with alg -8: DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, alg=-8), now)], [RI()], cddl_invalid=["receipt"])
    add_scitt("sc-019b", "Receipt protected header with an extra label 3: DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, extra_hdr={3: "application/cose"}), now)], [RI()],
              cddl_invalid=["receipt"])
    add_scitt("sc-020", "Receipt with the root attached as payload (not detached): DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, attach_root=True), now)], [RI()], cddl_invalid=["receipt"])
    add_scitt("sc-021", "Receipt signature with one bit flipped: DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, sig_mutate=lambda s: s[:-1] + bytes([s[-1] ^ 1])), now)],
              [RI()])
    es2 = entry("authorization", ps, [rs], T0 + 15)
    add_scitt("sc-022", "Fresh, valid Receipt but the statements expire at the gate's instant: DENY time_invalid",
              SC + ["SAR-REQ-050", "SAR-REQ-138"], P1, [sstep(ps, [rs], receipt([es2], 0, T0 + 15), T0 + 60)],
              [outcome("DENY", "time_invalid")])
    rbad = ratification(p, sig_mutate=lambda s: s[:-1] + bytes([s[-1] ^ 1]), ttl=3600)
    eb = entry("authorization", p, [rbad], t_reg)
    add_scitt("sc-023", "A faulty TS registered a set whose ratification signature is invalid; the Receipt itself is "
              "valid: DENY invalid_statement", SC, P1, [sstep(p, [rbad], receipt([eb], 0, t_reg), now)],
              [outcome("DENY", "invalid_statement")])
    # ISS-108: tree size is not signed. For leaf 4, the audit path of a 7-leaf tree also verifies as a
    # proof in an 8-leaf tree (same root), so that change is NOT detected -- by design of RFC 9942/9162,
    # and harmless because the signed root still commits to the entry. Changing it to 5 is detected.
    assert verify_inclusion(e, 4, 8, mpath(4, log7), mth(log7))
    assert not verify_inclusion(e, 4, 5, mpath(4, log7), mth(log7))
    add_scitt("sc-024", "Inclusion proof with tree_size changed from 7 to 8: still verifies (tree size is not "
              "signed, ISS-108; the signed root commits to the entry): ALLOW", SC + ["SAR-REQ-127"], P1,
              [sstep(p, [r1], bad_size, now)], [ok])
    add_scitt("sc-024b", "Inclusion proof with tree_size changed from 7 to 5: DENY receipt_invalid",
              SC + ["SAR-REQ-127"], P1, [sstep(p, [r1], receipt(log7, 4, t_reg, size_in_proof=5), now)], [RI()])
    e25 = entry("authorization", p, [r1], T0 + 12)
    add_scitt("sc-025", "TS clock behind: registered_at backdated within validity, presented 388 s later (stale): "
              "DENY receipt_invalid", SC + ["SAR-REQ-135"], P1, [sstep(p, [r1], receipt([e25], 0, T0 + 12), T0 + 400)],
              [RI()])
    e26 = entry("authorization", ps, [rs], T0 + 59)
    add_scitt("sc-026", "Lying TS: statements expired at T0+60, registration time claimed T0+59, presented at "
              "T0+100 (fresh by the Receipt): DENY time_invalid (gate's own clock)", SC + ["SAR-REQ-138"], P1,
              [sstep(ps, [rs], receipt([e26], 0, T0 + 59), T0 + 100)], [outcome("DENY", "time_invalid")])
    add_scitt("sc-027", "Receipt kid \"log-2\" with iss \"log-1\": DENY receipt_invalid", SC, P1,
              [sstep(p, [r1], receipt(log7, 4, t_reg, kid=LOG2), now)], [RI()])
    e28 = entry("authorization", p, [r1], t_reg, policy_id="p0")
    add_scitt("sc-028", "Receipt for the same statements registered under policy id p0: DENY receipt_invalid",
              SC, P1, [sstep(p, [r1], receipt([e28], 0, t_reg), now)], [RI()])

    # ---- registration (TS behaviour); expected entries and receipts are byte-exact
    def req(kind, prop, rats, pid="p1"):
        return enc({"v": 1, "kind": kind, "policy_id": pid, "proposal": prop["cose"], "ratifications": rats}).hex()

    def reg_vec(vid, desc, reqs, pol, rsteps):
        """rsteps: list of (request_hex, ts_time, expected) where expected is ("ok", kind, prop, rats) or
        ("refuse", class)."""
        log, steps, outs = [], [], []
        for rq, tt, ex in rsteps:
            steps.append({"request_cbor": rq, "ts_time": tt})
            if ex[0] == "ok":
                _, kind, prop, rats = ex
                en = entry(kind, prop, rats, tt)
                log.append(en)
                rec = receipt(log, len(log) - 1, tt)
                assert verify_inclusion(en, len(log) - 1, len(log), mpath(len(log) - 1, log), mth(log))
                outs.append({"registered": True, "entry_cbor": en.hex(), "leaf_index": len(log) - 1,
                             "tree_size": len(log), "root": mth(log).hex(), "receipt_cose": rec.hex()})
            else:
                outs.append({"registered": False, "refusal_class": ex[1]})
        VECTORS.append({"id": vid, "description": desc, "requirements": sorted(set(reqs)), "kind": "registration",
                        "tau": TAU, "inputs": {"keys": {k: KEYS[k] for k in sorted(KEYS)}, "policy": pol,
                                               "log_id": LOG1, "ts_key": "ts-1", "steps": steps},
                        "expected": {"steps": outs}})
    RG = ["SAR-REQ-095", "SAR-REQ-120", "SAR-REQ-125", "SAR-REQ-126", "SAR-REQ-130"]
    reg_vec("reg-001", "Valid authorization registered; entry, root and Receipt are byte-exact", RG + ["SAR-REQ-121"],
            P1, [(req("authorization", p, [r1]), t_reg, ("ok", "authorization", p, [r1]))])
    reg_vec("reg-002", "Ratification by an overseer not in the policy: refused unauthorized_signer", RG, P1,
            [(req("authorization", p, [ratification(p, overseer="ov-x", signer="outsider", ttl=3600)]), t_reg,
              ("refuse", "unauthorized_signer"))])
    reg_vec("reg-003", "Quorum 2, one approval: refused quorum_not_met", RG, policy(quorum=2),
            [(req("authorization", p, [r1]), t_reg, ("refuse", "quorum_not_met"))])
    reg_vec("reg-004", "TS clock at hi (statements expired): refused time_invalid", RG, P1,
            [(req("authorization", ps, [rs]), T0 + 60, ("refuse", "time_invalid"))])
    reg_vec("reg-005", "TS clock at lo - tau - 1: refused time_invalid", RG, P1,
            [(req("authorization", p, [r1]), T0 + 10 - TAU - 1, ("refuse", "time_invalid"))])
    reg_vec("reg-006", "Rejection registered as a rejection entry", RG + ["SAR-REQ-124"], P1,
            [(req("rejection", p, [rrej]), t_reg, ("ok", "rejection", p, [rrej]))])
    reg_vec("reg-007", "Rejection registered, then an authorization for the same proposal refused "
            "(registered veto)", RG + ["SAR-REQ-123", "SAR-REQ-124"], P1,
            [(req("rejection", p, [rrej]), t_reg, ("ok", "rejection", p, [rrej])),
             (req("authorization", p, [r1]), t_reg + 1, ("refuse", "registration_conflict"))])
    reg_vec("reg-008", "Second authorization registration for the same proposal refused", RG + ["SAR-REQ-122"], P1,
            [(req("authorization", p, [r1]), t_reg, ("ok", "authorization", p, [r1])),
             (req("authorization", p, [r1, r2]), t_reg + 1, ("refuse", "registration_conflict"))])
    reg_vec("reg-009", "Authorization request containing a rejection: refused rejected", RG + ["SAR-REQ-124"], P1,
            [(req("authorization", p, [r1, rrej]), t_reg, ("refuse", "rejected"))])
    reg_vec("reg-010", "Rejection request without any REJECTED ratification: refused", RG + ["SAR-REQ-124"], P1,
            [(req("rejection", p, [r1]), t_reg, ("refuse", "invalid_statement"))])
    reg_vec("reg-011", "Invalid policy at the TS: refused policy_invalid", RG, policy(quorum=0),
            [(req("authorization", p, [r1]), t_reg, ("refuse", "policy_invalid"))])
    reg_vec("reg-012", "Request naming another policy id: refused binding_mismatch", RG, P1,
            [(req("authorization", p, [r1], pid="p2"), t_reg, ("refuse", "binding_mismatch"))])
    reg_vec("reg-013", "Ratification with a bad signature: refused invalid_statement", RG, P1,
            [(req("authorization", p, [rbad]), t_reg, ("refuse", "invalid_statement"))])

    # ---- Merkle tree (RFC 9162): roots, inclusion and consistency proofs over 13 leaves
    leaves = [enc(["leaf", i]) for i in range(13)]
    roots = {n: mth(leaves[:n]).hex() for n in range(0, 14)}
    incl = [{"index": m, "size": n, "path": [x.hex() for x in mpath(m, leaves[:n])]}
            for n in (1, 2, 3, 5, 7, 8, 13) for m in range(n)]
    cons = [{"m": m, "n": n, "proof": [x.hex() for x in subproof(m, leaves[:n], True)]}
            for n in (2, 3, 5, 7, 8, 13) for m in range(1, n + 1)]
    VECTORS.append({"id": "merkle-001", "description": "RFC 9162 Merkle Tree Hash, inclusion and consistency proofs "
                    "for 13 leaves (computed by the generator's own implementation of RFC 9162 sections 2.1.1, "
                    "2.1.3.1 and 2.1.4.1)", "requirements": ["SAR-REQ-126", "SAR-REQ-127", "SAR-REQ-128"],
                    "kind": "merkle", "inputs": {"leaves": [x.hex() for x in leaves]},
                    "expected": {"roots": {str(k): v for k, v in roots.items()}, "inclusion": incl,
                                 "consistency": cons}})


def files():
    out = {}
    for v in build():
        out[f"{v['id']}.json"] = json.dumps(v, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    index = {"profile": "SAR profile version 1", "tau": TAU, "t0": T0,
             "vectors": [{"id": v["id"], "kind": v["kind"], "requirements": v["requirements"],
                          "description": v["description"]} for v in VECTORS]}
    out["index.json"] = json.dumps(index, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    return out


def main():
    fs = files()
    if "--check" in sys.argv:
        bad = [n for n, t in fs.items() if not (OUT / n).exists() or (OUT / n).read_text() != t]
        extra = [p.name for p in OUT.glob("*.json") if p.name not in fs]
        print(f"vectors: {len(fs) - 1}; differing: {bad}; unexpected files: {extra}")
        sys.exit(1 if bad or extra else 0)
    OUT.mkdir(exist_ok=True)
    for p in OUT.glob("*.json"):
        p.unlink()
    for n, t in fs.items():
        (OUT / n).write_text(t)
    print(f"wrote {len(fs) - 1} vectors to {OUT}")


if __name__ == "__main__":
    main()
