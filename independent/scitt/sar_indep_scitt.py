"""Independent implementation of SAR profile Sections 15-18: Transparency
Service registration, RFC 9162 Merkle log, COSE Receipts (RFC 9942 as
constrained by SAR-REQ-130) and Receipt-gated execution.

Written from spec/sar-profile.md, spec/sar-profile.cddl, spec/README.md,
spec/ISSUES.md and the published test vectors only. The core rules
(Sections 5-13: deterministic CBOR, COSE statements, policy, temporal rules,
quorum, replay store) come from ../sar_indep.py, which this module imports and
does not modify. The Merkle tree, the registration logic and the Receipt
construction and verification are written here. Interpretation choices are
recorded in DECISIONS.md (referenced below as SD<n>).
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import sar_indep as core  # noqa: E402  (core profile rules, Sections 5-13)
from sar_indep import Tag, dcbor, dcbor_decode_strict  # noqa: E402

__all__ = [
    "merkle_root", "inclusion_proof", "verify_inclusion", "consistency_proof",
    "verify_consistency", "leaf_hash", "TransparencyService", "ReceiptGate",
    "verify_tar_offline", "verify_receipt", "parse_receipt", "verify_checkpoint",
    "registration_entry", "set_digest", "make_registration_request", "TAU",
    "DENY_CLASSES",
]

# The clock tolerance must be the same at the TS, the gate and the offline
# verifier (Section 10); the core fixes it, so it is taken from there (SD1).
TAU = core.MAX_FUTURE_SKEW
ALG_ED25519 = -19
VDS_RFC9162_SHA256 = 1
HDR_ALG, HDR_KID, HDR_CWT, HDR_VDS, HDR_VDP = 1, 4, 15, 395, 396
CWT_ISS, CWT_IAT = 1, 6
VDP_INCLUSION = -1
KINDS = ("authorization", "rejection")
REQUEST_KEYS = frozenset({"v", "kind", "policy_id", "proposal", "ratifications"})

DENY_CLASSES = (
    "policy_invalid", "missing_evidence", "invalid_statement",
    "unauthorized_signer", "binding_mismatch", "duplicate_ratification",
    "rejected", "quorum_not_met", "time_invalid", "payload_mismatch", "replay",
    "store_failure", "receipt_invalid", "registration_conflict",
)

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# RFC 9162 Section 2.1 Merkle tree (SAR-REQ-126, 127, 128)
# ---------------------------------------------------------------------------
def leaf_hash(d: bytes) -> bytes:
    return _h(b"\x00" + bytes(d))


def _node(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _mth(hashes: list[bytes]) -> bytes:
    n = len(hashes)
    if n == 0:
        return _h(b"")
    if n == 1:
        return hashes[0]
    k = _split(n)
    return _node(_mth(hashes[:k]), _mth(hashes[k:]))


def merkle_root(leaves: list[bytes]) -> bytes:
    """MTH(D_n) of RFC 9162 Section 2.1.1 over the leaf data `leaves`."""
    return _mth([leaf_hash(d) for d in leaves])


def _path(m: int, hashes: list[bytes]) -> list[bytes]:
    n = len(hashes)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, hashes[:k]) + [_mth(hashes[k:])]
    return _path(m - k, hashes[k:]) + [_mth(hashes[:k])]


def inclusion_proof(leaves: list[bytes], index: int, size: int) -> list[bytes]:
    """PATH(index, D[size]) of RFC 9162 Section 2.1.3.1."""
    if not (type(index) is int and type(size) is int and 0 <= index < size <= len(leaves)):
        raise ValueError("inclusion proof needs 0 <= index < size <= len(leaves)")
    return _path(index, [leaf_hash(d) for d in leaves[:size]])


def _root_from_path(lh: bytes, index: int, size: int, path) -> bytes | None:
    """RFC 9162 Section 2.1.3.2 steps 1-5; returns the computed root or None."""
    if type(index) is not int or type(size) is not int or index < 0 or size < 1:
        return None
    if index >= size:
        return None
    if not isinstance(path, (list, tuple)):
        return None
    fn, sn, r = index, size - 1, lh
    for p in path:
        if not isinstance(p, (bytes, bytearray)) or len(p) != 32:
            return None
        p = bytes(p)
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return r


def verify_inclusion(leaf_data: bytes, index: int, size: int, path, root: bytes) -> bool:
    try:
        r = _root_from_path(leaf_hash(leaf_data), index, size, path)
        return r is not None and isinstance(root, (bytes, bytearray)) and r == bytes(root)
    except Exception:  # noqa: BLE001
        return False


def _subproof(m: int, hashes: list[bytes], b: bool) -> list[bytes]:
    n = len(hashes)
    if m == n:
        return [] if b else [_mth(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, hashes[:k], b) + [_mth(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [_mth(hashes[:k])]


def consistency_proof(leaves: list[bytes], m: int, n: int) -> list[bytes]:
    """PROOF(m, D[n]) of RFC 9162 Section 2.1.4.1 (0 < m <= n; empty for m == n)."""
    if not (type(m) is int and type(n) is int and 0 < m <= n <= len(leaves)):
        raise ValueError("consistency proof needs 0 < m <= n <= len(leaves)")
    return _subproof(m, [leaf_hash(d) for d in leaves[:n]], True)


def verify_consistency(m: int, n: int, root_m: bytes, root_n: bytes, proof) -> bool:
    """RFC 9162 Section 2.1.4.2. m == n requires an empty proof and equal
    roots; m == 0 is not defined by RFC 9162 and is rejected (SD10)."""
    try:
        if type(m) is not int or type(n) is not int or not 0 < m <= n:
            return False
        if not isinstance(proof, (list, tuple)):
            return False
        for c in proof:
            if not isinstance(c, (bytes, bytearray)) or len(c) != 32:
                return False
        proof = [bytes(c) for c in proof]
        root_m, root_n = bytes(root_m), bytes(root_n)
        if m == n:
            return len(proof) == 0 and root_m == root_n
        if not proof:
            return False
        if m & (m - 1) == 0:          # m is an exact power of two
            proof = [root_m] + proof
        fn, sn = m - 1, n - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = proof[0]
        for c in proof[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr = _node(c, fr)
                sr = _node(c, sr)
                if not fn & 1:
                    while not (fn & 1) and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                sr = _node(sr, c)
            fn >>= 1
            sn >>= 1
        return fr == root_m and sr == root_n and sn == 0
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Reasons: every denial / refusal starts with a Section 13.1 class
# ---------------------------------------------------------------------------
class Refusal(Exception):
    def __init__(self, cls: str, detail: str):
        assert cls in DENY_CLASSES, cls
        super().__init__(f"{cls}: {detail}")
        self.cls, self.detail = cls, detail


# Map the core's (sar_indep) denial messages to Section 13.1 classes by the
# message PREFIX (the core's messages start with fixed text; later parts may
# contain signer identifiers, which must not influence the class) (SD2).
_CORE_CLASS_TABLE = (
    ("invalid policy", "policy_invalid"),
    ("missing proposal", "missing_evidence"),
    ("missing ratification", "missing_evidence"),
    ("agent_id not authorized by policy", "unauthorized_signer"),
    ("overseer_id not authorized by policy", "unauthorized_signer"),
    ("proposal policy_id does not match", "binding_mismatch"),
    ("ratification policy_id does not match", "binding_mismatch"),
    ("ratification is not bound", "binding_mismatch"),
    ("ratification proposal_id mismatch", "binding_mismatch"),
    ("duplicate ratification", "duplicate_ratification"),
    ("rejected by overseer", "rejected"),
    ("insufficient quorum", "quorum_not_met"),
    ("ratification predates proposal", "time_invalid"),
    ("ratification issued after proposal expiry", "time_invalid"),
    ("no instant at which", "time_invalid"),
    ("proposal is future-dated", "time_invalid"),
    ("ratification is future-dated", "time_invalid"),
    ("proposal expired", "time_invalid"),
    ("ratification expired", "time_invalid"),
    ("invalid evaluation time", "time_invalid"),
    ("authorization not valid at the given instant", "time_invalid"),
    ("missing runtime payload", "payload_mismatch"),
    ("runtime payload not canonically", "payload_mismatch"),
    ("payload digest mismatch", "payload_mismatch"),
    ("replay", "replay"),
    ("decision log integrity", "store_failure"),
    # statement structure, headers, signatures, bodies, empty intervals,
    # proposal_id derivation, verdict values:
    ("malformed", "invalid_statement"),
    ("protected header", "invalid_statement"),
    ("unsupported algorithm", "invalid_statement"),
    ("wrong content type", "invalid_statement"),
    ("body has unexpected or missing fields", "invalid_statement"),
    ("unsupported statement version", "invalid_statement"),
    ("kid does not match", "invalid_statement"),
    ("invalid signature", "invalid_statement"),
    ("proposal_id is not derived", "invalid_statement"),
    ("proposal validity interval empty", "invalid_statement"),
    ("ratification validity interval empty", "invalid_statement"),
    ("unknown verdict", "invalid_statement"),
    ("ratification set too large", "invalid_statement"),
)


def _classify_core(msg: str) -> str:
    for prefix, cls in _CORE_CLASS_TABLE:
        if msg.startswith(prefix):
            return cls
    return "invalid_statement"    # SD2: unrecognised evaluation failure


def _core_refusal(e: Exception) -> Refusal:
    msg = str(e)
    return Refusal(_classify_core(msg), msg)


# ---------------------------------------------------------------------------
# Statements given as sar_indep dicts or as COSE_Sign1 octets
# ---------------------------------------------------------------------------
def _as_stmt(x):
    """Return a sar_indep statement dict; COSE octets are parsed strictly."""
    if isinstance(x, (bytes, bytearray)):
        try:
            return core.from_cose(bytes(x))
        except Exception as e:  # noqa: BLE001
            raise Refusal("invalid_statement", f"malformed statement: {e}") from None
    return x


def _cose_of(stmt) -> bytes:
    try:
        return core.to_cose(stmt)
    except Exception as e:  # noqa: BLE001
        raise Refusal("invalid_statement", f"malformed statement: {e}") from None


def set_digest(proposal_bytes: bytes, ratification_bytes: list[bytes]) -> bytes:
    """H(dcbor([H(proposal_bytes), sorted [H(r) for r]])) (SAR-REQ-125)."""
    rs = sorted(_h(bytes(r)) for r in ratification_bytes)
    return _h(dcbor([_h(bytes(proposal_bytes)), rs]))


def registration_entry(kind: str, log_id: str, policy_id: str, proposal_id: str,
                       sdigest: bytes, registered_at: int) -> bytes:
    """dcbor of the registration-entry map (SAR-REQ-125); the log leaf data."""
    return dcbor({"v": 1, "kind": kind, "log_id": log_id, "policy_id": policy_id,
                  "proposal_id": proposal_id, "set_digest": sdigest,
                  "registered_at": registered_at})


def make_registration_request(kind: str, policy_id: str, proposal, ratifications) -> bytes:
    """Client helper: build a registration-request (Section 15.1)."""
    p = proposal if isinstance(proposal, (bytes, bytearray)) else core.to_cose(proposal)
    rs = [r if isinstance(r, (bytes, bytearray)) else core.to_cose(r) for r in ratifications]
    return dcbor({"v": 1, "kind": kind, "policy_id": policy_id,
                  "proposal": bytes(p), "ratifications": [bytes(r) for r in rs]})


def _is_uint(x) -> bool:
    return type(x) is int and 0 <= x < 2 ** 64


def _is_id(x) -> bool:
    return isinstance(x, str) and 1 <= len(x) <= 256


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    return dcbor(["Signature1", protected, b"", payload])


# ---------------------------------------------------------------------------
# Receipt (Section 17)
# ---------------------------------------------------------------------------
def build_receipt(signing_key: Ed25519PrivateKey, log_id: str, registered_at: int,
                  tree_size: int, leaf_index: int, path: list[bytes], root: bytes) -> bytes:
    protected = dcbor({HDR_ALG: ALG_ED25519, HDR_KID: log_id.encode("utf-8"),
                       HDR_VDS: VDS_RFC9162_SHA256,
                       HDR_CWT: {CWT_ISS: log_id, CWT_IAT: registered_at}})
    proof = dcbor([tree_size, leaf_index, list(path)])
    unprotected = {HDR_VDP: {VDP_INCLUSION: [proof]}}
    sig = signing_key.sign(_sig_structure(protected, root))
    return dcbor(Tag(18, [protected, unprotected, None, sig]))


def parse_receipt(receipt_bytes) -> dict:
    """Strictly parse a Receipt (SAR-REQ-130). Raises Refusal(receipt_invalid)."""
    def bad(why):
        return Refusal("receipt_invalid", f"malformed Receipt: {why}")

    if receipt_bytes is None:
        raise Refusal("receipt_invalid", "no Receipt presented")
    if not isinstance(receipt_bytes, (bytes, bytearray)):
        raise bad("not an octet string")
    try:
        obj = dcbor_decode_strict(bytes(receipt_bytes))
    except Exception as e:  # noqa: BLE001
        raise bad(f"not deterministic CBOR ({e})") from None
    if getattr(obj, "tag", None) != 18 or not hasattr(obj, "value"):
        raise bad("not a tag-18 COSE_Sign1")
    arr = obj.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise bad("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, sig = arr
    if not isinstance(protected, bytes):
        raise bad("protected header is not a byte string")
    try:
        hdr = dcbor_decode_strict(protected)
    except Exception as e:  # noqa: BLE001
        raise bad(f"protected header not deterministic CBOR ({e})") from None
    if not isinstance(hdr, Mapping) or set(hdr.keys()) != {HDR_ALG, HDR_KID, HDR_VDS, HDR_CWT} \
            or any(type(k) is not int for k in hdr):
        raise bad("protected header must have exactly labels 1, 4, 15, 395")
    if type(hdr[HDR_ALG]) is not int or hdr[HDR_ALG] != ALG_ED25519:
        raise bad("algorithm is not -19 (Ed25519)")
    if type(hdr[HDR_VDS]) is not int or hdr[HDR_VDS] != VDS_RFC9162_SHA256:
        raise bad("vds is not 1 (RFC9162_SHA256)")
    kid, cwt = hdr[HDR_KID], hdr[HDR_CWT]
    if not isinstance(kid, bytes):
        raise bad("kid is not a byte string")
    if not isinstance(cwt, Mapping) or set(cwt.keys()) != {CWT_ISS, CWT_IAT} \
            or any(type(k) is not int for k in cwt):
        raise bad("CWT claims must have exactly iss (1) and iat (6)")
    log_id, reg_at = cwt[CWT_ISS], cwt[CWT_IAT]
    if not _is_id(log_id):
        raise bad("iss is not an identifier")
    if not _is_uint(reg_at):
        raise bad("iat is not an unsigned integer")
    if kid != log_id.encode("utf-8"):
        raise bad("kid is not the UTF-8 of iss")
    if not isinstance(unprotected, Mapping) or set(unprotected.keys()) != {HDR_VDP} \
            or type(next(iter(unprotected))) is not int:
        raise bad("unprotected header must be exactly {396: ...}")
    vdp = unprotected[HDR_VDP]
    if not isinstance(vdp, Mapping) or set(vdp.keys()) != {VDP_INCLUSION} \
            or type(next(iter(vdp))) is not int:
        raise bad("vdp must be exactly {-1: [proof]}")
    proofs = vdp[VDP_INCLUSION]
    if not isinstance(proofs, list) or len(proofs) != 1 or not isinstance(proofs[0], bytes):
        raise bad("exactly one inclusion proof (a byte string) is required")
    try:
        pr = dcbor_decode_strict(proofs[0])
    except Exception as e:  # noqa: BLE001
        raise bad(f"inclusion proof not deterministic CBOR ({e})") from None
    if not isinstance(pr, list) or len(pr) != 3:
        raise bad("inclusion proof must be [tree_size, leaf_index, path]")
    tree_size, leaf_index, path = pr
    if not (_is_uint(tree_size) and _is_uint(leaf_index)):
        raise bad("tree_size and leaf_index must be unsigned integers")
    if not isinstance(path, list) or any(not isinstance(p, bytes) or len(p) != 32 for p in path):
        raise bad("inclusion path must be a list of 32-byte strings")
    if payload is not None:
        raise bad("payload must be nil (detached)")
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise bad("signature must be 64 bytes")
    return {"protected": protected, "log_id": log_id, "registered_at": reg_at,
            "tree_size": tree_size, "leaf_index": leaf_index, "path": path, "sig": sig}


def _trusted_key(trusted_logs, log_id) -> Ed25519PublicKey:
    if not isinstance(trusted_logs, Mapping) or log_id not in trusted_logs:
        raise Refusal("receipt_invalid", f"log {log_id!r} is not trusted")
    hexkey = trusted_logs[log_id]
    if not isinstance(hexkey, str) or not _HEX64.match(hexkey):
        raise Refusal("receipt_invalid", f"trusted key for {log_id!r} is malformed")
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))
    except Exception:  # noqa: BLE001
        raise Refusal("receipt_invalid", f"trusted key for {log_id!r} is not a valid point") from None


def verify_receipt(receipt_bytes, *, kind: str, policy_id: str, proposal_id: str,
                   sdigest: bytes, trusted_logs, lo: int, hi: int) -> dict:
    """SAR-REQ-130..134 (no clock): structure, trusted log and key,
    reconstruction of the entry, inclusion, signature over the root, and
    registration time within validity. Returns the parsed Receipt or raises
    Refusal(receipt_invalid)."""
    rc = parse_receipt(receipt_bytes)
    pub = _trusted_key(trusted_logs, rc["log_id"])
    leaf = registration_entry(kind, rc["log_id"], policy_id, proposal_id, sdigest,
                              rc["registered_at"])
    root = _root_from_path(leaf_hash(leaf), rc["leaf_index"], rc["tree_size"], rc["path"])
    if root is None:
        raise Refusal("receipt_invalid", "inclusion proof does not verify")
    try:
        pub.verify(rc["sig"], _sig_structure(rc["protected"], root))
    except InvalidSignature:
        raise Refusal("receipt_invalid",
                      "Receipt signature does not verify over the reconstructed root "
                      "(wrong key, or a Receipt for another entry)") from None
    if not (lo - TAU <= rc["registered_at"] < hi):
        raise Refusal("receipt_invalid", "registration time outside the statements' validity")
    return rc


def _window(proposal_stmt, rat_stmts) -> tuple[int, int]:
    pb = proposal_stmt["body"]
    lo, hi = pb["issued_at"], pb["expires_at"]
    for r in rat_stmts:
        rb = r["body"]
        lo, hi = max(lo, rb["reviewed_at"]), min(hi, rb["valid_until"])
    return lo, hi


# ---------------------------------------------------------------------------
# Signed checkpoints (SAR-REQ-128, SHOULD; header format is SD9)
# ---------------------------------------------------------------------------
CHECKPOINT_CT = "application/sar-ts-checkpoint+cbor"


def verify_checkpoint(cp_bytes, trusted_logs) -> tuple[str, int, bytes]:
    obj = dcbor_decode_strict(bytes(cp_bytes))
    if getattr(obj, "tag", None) != 18 or not isinstance(obj.value, list) or len(obj.value) != 4:
        raise ValueError("checkpoint is not a COSE_Sign1")
    protected, unprotected, payload, sig = obj.value
    hdr = dcbor_decode_strict(protected)
    if set(hdr.keys()) != {1, 3, 4} or hdr[1] != ALG_ED25519 or type(hdr[1]) is not int \
            or hdr[3] != CHECKPOINT_CT or unprotected != {}:
        raise ValueError("bad checkpoint header")
    body = dcbor_decode_strict(payload)
    if not (isinstance(body, list) and len(body) == 4 and body[0] == "sar-ts-checkpoint"
            and _is_id(body[1]) and _is_uint(body[2]) and isinstance(body[3], bytes)
            and len(body[3]) == 32 and hdr[4] == body[1].encode("utf-8")):
        raise ValueError("bad checkpoint payload")
    pub = _trusted_key(trusted_logs, body[1])
    pub.verify(sig, _sig_structure(protected, payload))
    return body[1], body[2], body[3]


# ---------------------------------------------------------------------------
# Transparency Service (Sections 15-17)
# ---------------------------------------------------------------------------
class TransparencyService:
    """In-process TS with an append-only RFC 9162 log. `entries` holds the leaf
    data (dcbor registration entries) in log order."""

    def __init__(self, log_id: str, signing_key: Ed25519PrivateKey, policy: dict):
        if not _is_id(log_id):
            raise ValueError("log_id must be an identifier (1..256 code points)")
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("signing_key must be an Ed25519PrivateKey")
        self.log_id = log_id
        self._key = signing_key
        self.policy = policy           # evaluated on every request (SAR-REQ-043 analogue)
        self.entries: list[bytes] = []
        self._leaf_hashes: list[bytes] = []
        self._authorized: set[tuple[str, str]] = set()
        self._vetoed: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    # -- log views ---------------------------------------------------------
    def root(self, size: int | None = None) -> bytes:
        size = len(self.entries) if size is None else size
        return _mth(self._leaf_hashes[:size])

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.entries) if size is None else size
        return inclusion_proof(self.entries, index, size)

    def consistency_proof(self, m: int, n: int | None = None) -> list[bytes]:
        n = len(self.entries) if n is None else n
        return consistency_proof(self.entries, m, n)

    def checkpoint(self, size: int | None = None) -> bytes:
        """Signed checkpoint over ["sar-ts-checkpoint", log_id, size, root]."""
        size = len(self.entries) if size is None else size
        if not 0 <= size <= len(self.entries):
            raise ValueError("size out of range")
        protected = dcbor({1: ALG_ED25519, 3: CHECKPOINT_CT, 4: self.log_id.encode("utf-8")})
        payload = dcbor(["sar-ts-checkpoint", self.log_id, size, self.root(size)])
        sig = self._key.sign(_sig_structure(protected, payload))
        return dcbor(Tag(18, [protected, {}, payload, sig]))

    # -- registration --------------------------------------------------------
    def register(self, request_bytes: bytes, now: int):
        """Evaluate the Registration Policy at t_reg = now and, if it is
        satisfied, append an entry and return (True, reason, receipt). Otherwise
        (False, "<class>: <detail>", None); nothing is appended."""
        with self._lock:     # serializes registrations (SAR-REQ-122)
            try:
                return self._register(request_bytes, now)
            except Refusal as r:
                return False, str(r), None
            except Exception as e:  # noqa: BLE001
                return False, f"invalid_statement: internal error while evaluating request ({type(e).__name__})", None

    def _register(self, request_bytes, t_reg):
        if not _is_uint(t_reg):
            raise Refusal("time_invalid", "TS clock reading is not an unsigned integer")
        # Policy first: an invalid policy refuses everything (SAR-REQ-040).
        try:
            pol = core.validate_policy(self.policy)
        except core.Deny as e:
            raise Refusal("policy_invalid", str(e)) from None
        pid = pol["policy_id"]

        # Request shape (Section 15.1, CDDL registration-request).
        if not isinstance(request_bytes, (bytes, bytearray)):
            raise Refusal("invalid_statement", "registration request is not an octet string")
        try:
            req = dcbor_decode_strict(bytes(request_bytes))
        except Exception as e:  # noqa: BLE001
            raise Refusal("invalid_statement",
                          f"registration request is not deterministic CBOR ({e})") from None
        if not isinstance(req, Mapping):
            raise Refusal("invalid_statement", "registration request is not a map")
        if "proposal" not in req or req.get("proposal") is None:
            raise Refusal("missing_evidence", "registration request has no proposal")
        if "ratifications" in req and req["ratifications"] == []:
            raise Refusal("missing_evidence", "registration request has no ratification")
        if set(req.keys()) != REQUEST_KEYS:
            raise Refusal("invalid_statement", "registration request has unexpected or missing members")
        if type(req["v"]) is not int or req["v"] != 1:
            raise Refusal("invalid_statement", "registration request version is not 1")
        kind = req["kind"]
        if not isinstance(kind, str) or kind not in KINDS:
            raise Refusal("invalid_statement", "registration kind is not authorization/rejection")
        if not _is_id(req["policy_id"]):
            raise Refusal("invalid_statement", "registration policy_id is not an identifier")
        if req["policy_id"] != pid:
            raise Refusal("binding_mismatch",
                          f"request names policy {req['policy_id']!r}, the TS evaluates {pid!r}")
        p_bytes, r_list = req["proposal"], req["ratifications"]
        if not isinstance(p_bytes, bytes):
            raise Refusal("invalid_statement", "proposal is not a byte string")
        if not isinstance(r_list, list) or any(not isinstance(r, bytes) for r in r_list):
            raise Refusal("invalid_statement", "ratifications is not a list of byte strings")
        proposal = _as_stmt(p_bytes)
        rats = [_as_stmt(r) for r in r_list]

        # Registration Policy evaluation (SAR-REQ-120, 124), by the core.
        if kind == "authorization":
            try:
                info = core._evaluate(proposal, rats, self.policy, mode="offline", now=t_reg)
            except core.Deny as e:
                raise _core_refusal(e) from None
        else:
            # The core evaluates every per-statement rule, S3 and duplicates
            # before it looks at verdicts, and only then quorum and the common
            # interval. Reaching "rejected" therefore means: all statements
            # valid and at least one REJECTED. Reaching quorum, the common
            # interval or success means: no REJECTED ratification (SD5).
            no_rejection = Refusal("invalid_statement",
                                   "rejection request contains no valid REJECTED ratification")
            try:
                core._evaluate(proposal, rats, self.policy, mode="offline", now=None)
            except core.Deny as e:
                msg = str(e)
                cls = _classify_core(msg)
                if cls == "quorum_not_met" or msg.startswith("no instant at which"):
                    raise no_rejection from None
                if cls != "rejected":
                    raise _core_refusal(e) from None
            else:
                raise no_rejection
        proposal_id = proposal["body"]["proposal_id"]
        pair = (pid, proposal_id)

        if kind == "authorization":
            if pair in self._vetoed:
                raise Refusal("registration_conflict",
                              "a rejection is registered for this proposal (registered veto)")
            if pair in self._authorized:
                raise Refusal("registration_conflict",
                              "an authorization is already registered for this proposal")

        # The exact octets are what the entry commits to (they round-trip).
        p_cose = _cose_of(proposal)
        r_coses = [_cose_of(r) for r in rats]
        if p_cose != p_bytes or r_coses != list(r_list):
            raise Refusal("invalid_statement", "statement octets are not canonical")
        entry = registration_entry(kind, self.log_id, pid, proposal_id,
                                   set_digest(p_cose, r_coses), t_reg)
        # Build everything before mutating, so a failure appends nothing.
        lh = leaf_hash(entry)
        hashes = self._leaf_hashes + [lh]
        index, size = len(hashes) - 1, len(hashes)
        path = _path(index, hashes)
        root = _mth(hashes)
        receipt = build_receipt(self._key, self.log_id, t_reg, size, index, path, root)
        self.entries.append(entry)
        self._leaf_hashes.append(lh)
        (self._authorized if kind == "authorization" else self._vetoed).add(pair)
        return True, f"registered: kind={kind} leaf_index={index} tree_size={size}", receipt


# ---------------------------------------------------------------------------
# Receipt-gated Execution Gate (Section 18)
# ---------------------------------------------------------------------------
class ReceiptGate:
    """Execution Gate that requires a Receipt (SAR-REQ-132). The core checks
    (Sections 5-13) are those of sar_indep and are always performed in full
    (SAR-REQ-137); the Receipt is an additional precondition."""

    def __init__(self, policy: dict, store, trusted_logs: dict, max_receipt_age: int = 300):
        self.policy = policy
        self.store = store
        self.trusted_logs = trusted_logs
        self.max_receipt_age = max_receipt_age

    def authorize(self, runtime_payload, proposal, ratifications, receipt_bytes, now):
        """Returns (allowed, reason). Starts from DENY and never raises. On
        DENY the reason is "<class>: <detail>". `now` is the gate's own clock
        (SAR-REQ-138); `registered_at` is never used in its place."""
        claimed = {}
        try:
            try:
                p0 = core.from_cose(bytes(proposal)) if isinstance(proposal, (bytes, bytearray)) else proposal
                claimed["proposal_id"] = str(p0["body"]["proposal_id"])[:64]
            except Exception:  # noqa: BLE001
                pass
            claimed["at"] = now if type(now) is int else None
            reason = "store_failure: decision not reached"
            try:
                allowed, reason = self._decide(runtime_payload, proposal, ratifications,
                                               receipt_bytes, now)
                if allowed:
                    return True, "ALLOW"
            except Refusal as r:
                reason = str(r)
            except Exception as e:  # noqa: BLE001
                reason = f"invalid_statement: internal verification failure ({type(e).__name__})"
        except Exception as e:  # noqa: BLE001  (belt and braces: start from DENY)
            reason = f"store_failure: internal error ({type(e).__name__})"
        try:
            self.store.log_deny(dict(claimed, reason=reason))
        except Exception:  # noqa: BLE001
            reason += " (decision could not be recorded)"
        return False, reason

    def _decide(self, runtime_payload, proposal, ratifications, receipt_bytes, now):
        if proposal is None:
            raise Refusal("missing_evidence", "no proposal")
        if ratifications is None or (isinstance(ratifications, (list, tuple)) and len(ratifications) == 0):
            raise Refusal("missing_evidence", "no ratification")
        if type(now) is not int or not 0 <= now < 2 ** 64:
            raise Refusal("time_invalid", "evaluation instant is not an integer number of seconds")
        if not isinstance(ratifications, (list, tuple)):
            raise Refusal("invalid_statement", "ratifications must be a list")
        proposal = _as_stmt(proposal)
        rats = [_as_stmt(r) for r in ratifications]

        # 1. Every check of Sections 5-13 except replay consumption, at the
        #    gate's own instant (SAR-REQ-137, 138), against the policy in force.
        policy = self.policy
        try:
            info = core._evaluate(proposal, rats, policy, mode="gate", now=now,
                                  runtime_payload=runtime_payload, have_payload=True)
        except core.Deny as e:
            raise _core_refusal(e) from None

        # 2. The Receipt (SAR-REQ-130..136): reconstruct the authorization entry
        #    from the presented statements and the gate's own policy_id.
        p_cose = _cose_of(proposal)
        r_coses = [_cose_of(r) for r in rats]
        lo, hi = _window(proposal, rats)
        rc = verify_receipt(receipt_bytes, kind="authorization", policy_id=info["policy_id"],
                            proposal_id=info["proposal_id"],
                            sdigest=set_digest(p_cose, r_coses),
                            trusted_logs=self.trusted_logs, lo=lo, hi=hi)
        reg_at = rc["registered_at"]
        mra = self.max_receipt_age
        if type(mra) is not int or mra < 0:
            raise Refusal("receipt_invalid", "max_receipt_age is not configured correctly")
        if reg_at > now + TAU:
            raise Refusal("receipt_invalid", "Receipt is dated more than tau after the gate's clock")
        if not now < reg_at + mra:
            raise Refusal("receipt_invalid", "Receipt is stale (older than max_receipt_age)")

        # 3. Consume the replay keys and record ALLOW in one atomic step.
        keys = core._replay_keys(info, runtime_payload)
        rec = {"at": now, "proposal_id": info["proposal_id"], "agent_id": info["agent_id"],
               "policy_id": info["policy_id"], "approvals": info["approvals"],
               "receipt": {"log_id": rc["log_id"], "registered_at": reg_at,
                           "tree_size": rc["tree_size"], "leaf_index": rc["leaf_index"]}}
        try:
            self.store.consume_and_log_allow(keys, rec)
        except core.Deny as e:
            msg = str(e)
            if msg.startswith("replay"):
                raise Refusal("replay", msg.split(": ", 1)[-1]) from None
            raise Refusal("store_failure", msg) from None
        except Exception as e:  # noqa: BLE001
            raise Refusal("store_failure", f"ALLOW could not be recorded ({type(e).__name__})") from None
        return True, "ALLOW"


# ---------------------------------------------------------------------------
# Offline verification of a Transparent Authorization Record (SAR-REQ-139)
# ---------------------------------------------------------------------------
def verify_tar_offline(proposal, ratifications, receipt_bytes, policy, trusted_logs) -> bool:
    """SAR-REQ-100 plus SAR-REQ-130..134, using no clock and no store. Does not
    check freshness (SAR-REQ-135 needs the gate's clock). Never raises."""
    try:
        if proposal is None or not isinstance(ratifications, (list, tuple)) or not ratifications:
            return False
        p = _as_stmt(proposal)
        rats = [_as_stmt(r) for r in ratifications]
        try:
            info = core._evaluate(p, rats, policy, mode="offline", now=None)
        except core.Deny:
            return False
        lo, hi = _window(p, rats)
        verify_receipt(receipt_bytes, kind="authorization", policy_id=info["policy_id"],
                       proposal_id=info["proposal_id"],
                       sdigest=set_digest(_cose_of(p), [_cose_of(r) for r in rats]),
                       trusted_logs=trusted_logs, lo=lo, hi=hi)
        return True
    except Exception:  # noqa: BLE001
        return False
