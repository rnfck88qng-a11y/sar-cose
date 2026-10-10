"""sar_scitt.py - SCITT Transparency Service and Receipt-gated execution for SAR (profile spec/sar-profile.md,
Sections 15-18; SARWP v1.3).

Implements, on top of sar_cose:
  - an append-only Merkle log with RFC 9162 section 2.1 hashing, inclusion proofs (2.1.3) and
    consistency proofs (2.1.4), and signed checkpoints;
  - TransparencyService.register(): evaluates the Registration Policy at the registration instant
    before adding an entry (SAR-REQ-120..125) and issues a Receipt (RFC 9942 structure with the
    constraints of SAR-REQ-130: vds 395 = RFC9162_SHA256, vdp 396 with one inclusion proof, CWT
    claims 15 with iss = log id and iat = registration time, detached payload = Merkle root);
  - ReceiptGate: executes only with a valid Receipt from a trusted log that covers exactly the
    presented proposal and ratification set, registered within the statements' validity and fresh
    under the gate's own clock (SAR-REQ-131..138), and then applies every check of sar_cose.Gate
    (statements, policy, S2 at its own instant, payload digest, replay consumption);
  - verify_tar_offline(): offline verification of a Transparent Authorization Record with a
    Receipt (SAR-REQ-139).

Deviations from RFC 9943 / RFC 9942 / SCRAPI are listed in profile Section 15.4. The log is kept in
memory (not persisted); there is no HTTP API. Mutants for test-the-tests (env SAR_MUTANT) are listed
in MUTANTS; each disables one guard.
"""
import os
import threading
import time
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import sar_cose as S

MUT = os.environ.get("SAR_MUTANT", "")
MUTANTS = [
    "skip_receipt_required", "skip_receipt_header_check", "skip_trusted_log", "skip_receipt_sig",
    "skip_inclusion", "inclusion_skip_index_bound", "inclusion_skip_final_size", "set_digest_proposal_only",
    "entry_kind_any", "skip_registration_window", "skip_receipt_future", "skip_receipt_age",
    "receipt_time_as_now", "merkle_leaf_no_prefix", "consistency_skip_roots",
    "ts_skip_policy", "ts_skip_time", "ts_skip_uniqueness", "ts_skip_veto", "ts_allow_rejected",
    "ts_unlocked", "ts_rejection_without_reject", "offline_skip_receipt",
]

HDR_ALG, HDR_KID, HDR_CWT, HDR_VDS, HDR_VDP = 1, 4, 15, 395, 396
CWT_ISS, CWT_IAT = 1, 6
VDS_RFC9162_SHA256 = 1
VDP_INCLUSION = -1
MAX_RECEIPT_AGE = 300       # seconds; deployment parameter (SAR-REQ-135)
KINDS = ("authorization", "rejection")
REQUEST_KEYS = frozenset({"v", "kind", "policy_id", "proposal", "ratifications"})
H = S.H


class ReceiptError(ValueError):
    pass


# ---------------------------------------------------------------- RFC 9162 Merkle tree (SAR-REQ-126..128)

def leaf_hash(d):
    return H(bytes(d)) if MUT == "merkle_leaf_no_prefix" else H(b"\x00" + bytes(d))


def node_hash(left, right):
    return H(b"\x01" + left + right)


def _split(n):
    """Largest power of two smaller than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class _Tree:
    """Merkle Tree Hash over a list of leaf data, caching complete (power-of-two) subtrees, which
    never change in an append-only log."""

    def __init__(self, leaves):
        self.leaves = leaves
        self.cache = {}

    def mth(self, lo, hi):
        n = hi - lo
        if n == 0:
            return H(b"")
        if n == 1:
            return leaf_hash(self.leaves[lo])
        full = n & (n - 1) == 0
        if full and (lo, hi) in self.cache:
            return self.cache[(lo, hi)]
        k = _split(n)
        r = node_hash(self.mth(lo, lo + k), self.mth(lo + k, hi))
        if full:
            self.cache[(lo, hi)] = r
        return r

    def path(self, m, lo, hi):
        n = hi - lo
        if n <= 1:
            return []
        k = _split(n)
        if m < k:
            return self.path(m, lo, lo + k) + [self.mth(lo + k, hi)]
        return self.path(m - k, lo + k, hi) + [self.mth(lo, lo + k)]

    def subproof(self, m, lo, hi, b):
        n = hi - lo
        if m == n:
            return [] if b else [self.mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return self.subproof(m, lo, lo + k, b) + [self.mth(lo + k, hi)]
        return self.subproof(m - k, lo + k, hi, False) + [self.mth(lo, lo + k)]


def merkle_root(leaves):
    return _Tree(list(leaves)).mth(0, len(leaves))


def inclusion_proof(leaves, index, size):
    if not 0 <= index < size <= len(leaves):
        raise ValueError("index out of range")
    return _Tree(list(leaves)).path(index, 0, size)


def verify_inclusion(leaf_data, index, size, path, root):
    """RFC 9162 section 2.1.3.2."""
    if MUT != "inclusion_skip_index_bound" and index >= size:
        return False
    fn, sn, r = index, size - 1, leaf_hash(leaf_data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if MUT == "inclusion_skip_final_size":
        return r == root
    return sn == 0 and r == root


def consistency_proof(leaves, m, n):
    if not 0 < m <= n <= len(leaves):
        raise ValueError("sizes out of range")
    return _Tree(list(leaves)).subproof(m, 0, n, True)


def verify_consistency(m, n, root_m, root_n, proof):
    """RFC 9162 section 2.1.4.2 (0 < m <= n)."""
    if not 0 < m <= n:
        return False
    if m == n:
        return not proof and root_m == root_n
    if not proof:
        return False
    proof = list(proof)
    if m & (m - 1) == 0:
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
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    if MUT == "consistency_skip_roots":
        return sn == 0
    return sn == 0 and fr == root_m and sr == root_n


# ---------------------------------------------------------------- entries and Receipts

def set_digest(proposal_bytes, ratification_bytes):
    """SAR-REQ-125: H(dcbor([H(proposal), sorted H(ratification)...]))."""
    rats = [] if MUT == "set_digest_proposal_only" else sorted(H(bytes(r)) for r in ratification_bytes)
    return H(S.dcbor([H(bytes(proposal_bytes)), rats]))


def registration_entry(kind, log_id, policy_id, proposal_id, sdigest, registered_at):
    return S.dcbor({"v": 1, "kind": kind, "log_id": log_id, "policy_id": policy_id, "proposal_id": proposal_id,
                    "set_digest": sdigest, "registered_at": registered_at})


def _pub_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def make_receipt(key, log_id, registered_at, size, index, path, root):
    protected = S.dcbor({HDR_ALG: S.ALG_ED25519, HDR_KID: log_id.encode(), HDR_VDS: VDS_RFC9162_SHA256,
                         HDR_CWT: {CWT_ISS: log_id, CWT_IAT: registered_at}})
    proof = S.dcbor([size, index, list(path)])
    sig = key.sign(S.dcbor(["Signature1", protected, b"", root]))
    return S.dcbor(cbor2.CBORTag(S.COSE_SIGN1_TAG, [protected, {HDR_VDP: {VDP_INCLUSION: [proof]}}, None, sig]))


def parse_receipt(data):
    """Strict structure check of SAR-REQ-130. Returns a dict; raises ReceiptError."""
    try:
        obj = S.strict_loads(bytes(data))
    except Exception as e:  # noqa: BLE001
        raise ReceiptError("receipt is not deterministic CBOR") from e
    if not (isinstance(obj, cbor2.CBORTag) and obj.tag == S.COSE_SIGN1_TAG and isinstance(obj.value, (list, tuple))
            and len(obj.value) == 4):
        raise ReceiptError("receipt is not a tagged COSE_Sign1")
    protected, unprotected, payload, sig = obj.value
    if not (isinstance(protected, bytes) and isinstance(sig, bytes)):
        raise ReceiptError("malformed receipt")
    hdr = S.strict_loads(protected)
    check = MUT != "skip_receipt_header_check"
    if check:
        if not (isinstance(hdr, Mapping) and set(hdr) == {HDR_ALG, HDR_KID, HDR_VDS, HDR_CWT}):
            raise ReceiptError("receipt protected header must be exactly alg, kid, vds, CWT claims")
        if hdr[HDR_ALG] != S.ALG_ED25519 or hdr[HDR_VDS] != VDS_RFC9162_SHA256:
            raise ReceiptError("receipt algorithm or verifiable data structure not supported")
        if payload is not None:
            raise ReceiptError("receipt payload must be detached")
        if len(sig) != 64:
            raise ReceiptError("receipt signature must be 64 bytes")
    cwt = hdr[HDR_CWT]
    if not (isinstance(cwt, Mapping) and set(cwt) == {CWT_ISS, CWT_IAT} and S._ident(cwt[CWT_ISS])
            and S._uint(cwt[CWT_IAT])):
        raise ReceiptError("receipt CWT claims must be exactly iss and iat")
    log_id, reg = cwt[CWT_ISS], cwt[CWT_IAT]
    if check and hdr[HDR_KID] != log_id.encode():
        raise ReceiptError("receipt kid differs from iss")
    if not (isinstance(unprotected, Mapping) and set(unprotected) == {HDR_VDP} and isinstance(unprotected[HDR_VDP], Mapping)
            and set(unprotected[HDR_VDP]) == {VDP_INCLUSION}):
        raise ReceiptError("receipt unprotected header must be exactly vdp with an inclusion proof")
    proofs = unprotected[HDR_VDP][VDP_INCLUSION]
    if not (isinstance(proofs, (list, tuple)) and len(proofs) == 1 and isinstance(proofs[0], bytes)):
        raise ReceiptError("exactly one inclusion proof is required")
    p = S.strict_loads(proofs[0])
    if not (isinstance(p, (list, tuple)) and len(p) == 3 and S._uint(p[0]) and S._uint(p[1])
            and isinstance(p[2], (list, tuple)) and all(isinstance(x, bytes) and len(x) == 32 for x in p[2])):
        raise ReceiptError("malformed inclusion proof")
    return {"protected": protected, "sig": sig, "log_id": log_id, "registered_at": reg, "tree_size": p[0],
            "leaf_index": p[1], "path": list(p[2])}


def _cose_bytes(stmt):
    return S.to_cose(stmt)


def receipt_entry_for(proposal, ratifications, policy_id, log_id, registered_at, kind="authorization"):
    pb = proposal["body"]
    return registration_entry(kind, log_id, policy_id, pb["proposal_id"],
                              set_digest(_cose_bytes(proposal), [_cose_bytes(r) for r in ratifications]),
                              registered_at)


def verify_receipt(receipt, proposal, ratifications, policy_id, trusted_logs):
    """Structure, trust, inclusion and signature (SAR-REQ-130, 131, 133). Returns (None, info) on
    success or (reason, None)."""
    if receipt is None:
        return "receipt_missing", None
    try:
        info = parse_receipt(receipt)
    except Exception:  # noqa: BLE001
        return "receipt_malformed", None
    pub = trusted_logs.get(info["log_id"]) if isinstance(trusted_logs, Mapping) else None
    if pub is None:
        if MUT != "skip_trusted_log":
            return "receipt_untrusted_log", None
        pub = next(iter(trusted_logs.values()))
    kinds = KINDS if MUT == "entry_kind_any" else ("authorization",)
    failure = "receipt_inclusion_failed"
    for kind in kinds:
        leaf = receipt_entry_for(proposal, ratifications, policy_id, info["log_id"], info["registered_at"], kind)
        root = _root_from_proof(leaf, info)
        if root is None:
            continue
        if MUT == "skip_receipt_sig":
            return None, info
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
                info["sig"], S.dcbor(["Signature1", info["protected"], b"", root]))
            return None, info
        except (InvalidSignature, ValueError):
            failure = "receipt_bad_signature"
    return failure, None


def _root_from_proof(leaf, info):
    """Root implied by the inclusion proof (RFC 9162 2.1.3.2 walk), or None if the proof is
    structurally invalid (leaf_index >= tree_size, or the path does not end at the root level).
    As in RFC 9942, the root is the detached payload, so it is authenticated by the Receipt
    signature over it; there is no separate root to compare with."""
    size, index, path = info["tree_size"], info["leaf_index"], info["path"]
    strict = MUT != "skip_inclusion"
    if strict and MUT != "inclusion_skip_index_bound" and index >= size:
        return None
    fn, sn, r = index, size - 1, leaf_hash(leaf)
    for p in path:
        if sn == 0:
            if strict:
                return None
            break
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if strict and MUT != "inclusion_skip_final_size" and sn != 0:
        return None
    return r


def _validity(proposal, ratifications):
    """(lo, hi) of the common nominal interval, or None if any body is not well-formed (then the
    statement checks deny later)."""
    try:
        pb = proposal["body"]
        if not S.proposal_shape_ok(pb) or not all(S.ratification_shape_ok(r["body"]) for r in ratifications):
            return None
        lo = max([pb["issued_at"]] + [r["body"]["reviewed_at"] for r in ratifications])
        hi = min([pb["expires_at"]] + [r["body"]["valid_until"] for r in ratifications])
        return lo, hi
    except Exception:  # noqa: BLE001
        return None


def check_registration_time(info, proposal, ratifications):
    """SAR-REQ-134: lo - tau <= registered_at < hi."""
    v = _validity(proposal, ratifications)
    if v is None or MUT == "skip_registration_window":
        return None
    lo, hi = v
    return None if S.accepts_at(lo, hi, info["registered_at"]) else "receipt_registration_outside_validity"


# ---------------------------------------------------------------- Transparency Service

class Registration:
    def __init__(self, ok, reason, receipt=None, entry=None, index=None):
        self.ok, self.reason, self.receipt, self.entry, self.index = ok, reason, receipt, entry, index

    def __iter__(self):  # (ok, reason, receipt)
        return iter((self.ok, self.reason, self.receipt))


class TransparencyService:
    """In-memory SCITT Transparency Service for SAR registrations. `policy` is a policy dict, or a
    callable returning the policy in force (re-read on every registration)."""

    def __init__(self, log_id, signing_key=None, policy=None, max_entries=None):
        self.log_id = log_id
        self._key = signing_key or Ed25519PrivateKey.generate()
        self.public_key = _pub_hex(self._key)
        self._policy = policy
        self.entries = []
        self._tree = _Tree(self.entries)
        self._authorized, self._rejected = set(), set()
        self._lock = threading.Lock()

    @property
    def policy(self):
        return self._policy() if callable(self._policy) else self._policy

    # -- evaluation (SAR-REQ-120, 124)
    def _evaluate(self, kind, proposal, ratifications, policy, t):
        """Return None or 'class:detail'. Same checks as the gate (sar_cose.Gate) without payload
        and replay, with S2 at the registration instant t."""
        if not S.policy_valid(policy):
            return "policy_invalid"
        pb = proposal["body"]
        if not S.proposal_shape_ok(pb) or pb["proposal_id"] != S.expected_proposal_id(pb):
            return "invalid_statement:proposal"
        if pb["policy_id"] != policy["policy_id"]:
            return "binding_mismatch:proposal policy"
        apub = policy["authorized_agents"].get(pb["agent_id"])
        if apub is None:
            return "unauthorized_signer:agent"
        if not S.verify_statement(proposal, apub, S.CT_PROPOSAL, pb["agent_id"]):
            return "invalid_statement:proposal signature"
        pdig = S.statement_digest(proposal)
        seen, approvals, rejections = set(), 0, 0
        lo, hi = pb["issued_at"], pb["expires_at"]
        for r in ratifications:
            rb = r["body"]
            if not S.ratification_shape_ok(rb):
                return "invalid_statement:ratification"
            opub = policy["authorized_overseers"].get(rb["overseer_id"])
            if opub is None:
                return "unauthorized_signer:overseer"
            if not S.verify_statement(r, opub, S.CT_RATIFICATION, rb["overseer_id"]):
                return "invalid_statement:ratification signature"
            if rb["proposal_digest"] != pdig or rb["proposal_id"] != pb["proposal_id"]:
                return "binding_mismatch:ratification"
            if rb["policy_id"] != policy["policy_id"]:
                return "binding_mismatch:ratification policy"
            if rb["overseer_id"] in seen:
                return "duplicate_ratification"
            seen.add(rb["overseer_id"])
            if not pb["issued_at"] <= rb["reviewed_at"] < pb["expires_at"]:
                return "time_invalid:review window"
            if rb["verdict"] not in S.VERDICTS:
                return "invalid_statement:verdict"
            if rb["verdict"] == "REJECTED":
                rejections += 1
            else:
                approvals += 1
            lo, hi = max(lo, rb["reviewed_at"]), min(hi, rb["valid_until"])
        if kind == "rejection":
            if rejections == 0 and MUT != "ts_rejection_without_reject":
                return "invalid_statement:rejection request without a REJECTED ratification"
            return None
        if rejections and MUT != "ts_allow_rejected":
            return "rejected"
        if approvals < policy["quorum"]:
            return "quorum_not_met"
        if MUT != "ts_skip_time" and not (lo < hi and S.accepts_at(lo, hi, t)):
            return "time_invalid:registration instant outside the common validity interval"
        return None

    def register(self, request, now=None):
        """Register a registration-request (deterministic CBOR bytes, profile 15.1). Returns a
        Registration (iterable as (ok, reason, receipt))."""
        t = int(time.time()) if now is None else now
        lock = threading.Lock() if MUT == "ts_unlocked" else self._lock
        with lock:
            try:
                req = S.strict_loads(bytes(request))
                if not (isinstance(req, Mapping) and set(req) == REQUEST_KEYS and type(req["v"]) is int and req["v"] == 1
                        and req["kind"] in KINDS and isinstance(req["proposal"], bytes)
                        and isinstance(req["ratifications"], (list, tuple)) and req["ratifications"]
                        and all(isinstance(x, bytes) for x in req["ratifications"])):
                    return Registration(False, "invalid_statement:malformed registration request")
                proposal = S.from_cose(req["proposal"])
                rats = [S.from_cose(x) for x in req["ratifications"]]
            except Exception:  # noqa: BLE001
                return Registration(False, "invalid_statement:statement not parseable")
            policy = self.policy
            if not S.policy_valid(policy):
                return Registration(False, "policy_invalid")
            if req["policy_id"] != policy["policy_id"]:
                return Registration(False, "binding_mismatch:request names another policy")
            kind = req["kind"]
            if MUT != "ts_skip_policy":
                try:
                    failure = self._evaluate(kind, proposal, rats, policy, t)
                except Exception as e:  # noqa: BLE001
                    failure = f"invalid_statement:{type(e).__name__}"
                if failure:
                    return Registration(False, failure)
            key = (policy["policy_id"], proposal["body"]["proposal_id"])
            if kind == "authorization":
                if key in self._authorized and MUT != "ts_skip_uniqueness":
                    return Registration(False, "registration_conflict:already registered")
                if key in self._rejected and MUT != "ts_skip_veto":
                    return Registration(False, "registration_conflict:a rejection is registered")
            if MUT == "ts_unlocked":
                time.sleep(0.001)  # widen the race window for the concurrency test
            entry = registration_entry(kind, self.log_id, policy["policy_id"], proposal["body"]["proposal_id"],
                                       set_digest(req["proposal"], req["ratifications"]), t)
            self.entries.append(entry)
            (self._authorized if kind == "authorization" else self._rejected).add(key)
            index = len(self.entries) - 1
            return Registration(True, "registered", self.get_receipt(index), entry, index)

    # -- log access
    def root(self, size=None):
        size = len(self.entries) if size is None else size
        return self._tree.mth(0, size)

    def get_receipt(self, index, size=None):
        """Receipt for entry `index` relative to tree size `size` (default: current size)."""
        size = len(self.entries) if size is None else size
        reg = S.strict_loads(self.entries[index])["registered_at"]
        return make_receipt(self._key, self.log_id, reg, size, index, self._tree.path(index, 0, size),
                            self._tree.mth(0, size))

    def checkpoint(self, size=None):
        size = len(self.entries) if size is None else size
        root = self.root(size)
        return {"log_id": self.log_id, "size": size, "root": root.hex(),
                "sig": self._key.sign(S.dcbor(["sar-ts-checkpoint", self.log_id, size, root])).hex()}

    def consistency(self, m, n=None):
        n = len(self.entries) if n is None else n
        return self._tree.subproof(m, 0, n, True)


def verify_checkpoint(cp, pub_hex):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(cp["sig"]), S.dcbor(["sar-ts-checkpoint", cp["log_id"], cp["size"], bytes.fromhex(cp["root"])]))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def make_request(kind, policy_id, proposal, ratifications):
    return S.dcbor({"v": 1, "kind": kind, "policy_id": policy_id, "proposal": S.to_cose(proposal),
                    "ratifications": [S.to_cose(r) for r in ratifications]})


# ---------------------------------------------------------------- Receipt-gated execution

class ReceiptGate:
    """Execution Gate that requires a Receipt (SAR-REQ-132..138). It wraps a sar_cose.Gate: a request
    is allowed only if the Receipt is valid AND the inner gate allows it at the gate's own instant.
    Receipt denials are recorded in the same decision log. Trust assumptions as in paper 3.8; in
    addition the trusted log keys are configuration of the gate (SAR-REQ-131)."""

    def __init__(self, policy, store, trusted_logs, max_receipt_age=MAX_RECEIPT_AGE):
        self._gate = S.Gate(policy, store)
        self.trusted_logs = dict(trusted_logs)
        self.max_receipt_age = max_receipt_age

    @property
    def policy(self):
        return self._gate.policy

    @policy.setter
    def policy(self, p):
        self._gate.policy = p

    @property
    def store(self):
        return self._gate.store

    def check_receipt(self, proposal, ratifications, receipt, now):
        """None if the Receipt is acceptable at instant `now`, else a receipt_* reason."""
        if receipt is None and MUT == "skip_receipt_required":
            return None
        failure, info = verify_receipt(receipt, proposal, ratifications, self.policy["policy_id"], self.trusted_logs)
        if failure:
            return failure
        failure = check_registration_time(info, proposal, ratifications)
        if failure:
            return failure
        reg = info["registered_at"]
        if MUT != "skip_receipt_future" and reg > now + S.MAX_CLOCK_SKEW:
            return "receipt_from_future"
        if MUT != "skip_receipt_age" and not now < reg + self.max_receipt_age:
            return "receipt_stale"
        return None

    def _pid(self, proposal):
        try:
            return proposal["body"]["proposal_id"]
        except Exception:  # noqa: BLE001
            return None

    def _instant(self, proposal, ratifications, receipt, now):
        if MUT == "receipt_time_as_now" and receipt is not None:
            try:
                return parse_receipt(receipt)["registered_at"]
            except Exception:  # noqa: BLE001
                return now
        return now

    def authorize_bytes(self, payload_bytes, proposal, ratifications, receipt, now=None):
        """Like sar_cose.Gate.authorize_bytes, plus the Receipt; returns (allowed, reason, bytes|None)."""
        if now is None:
            now = int(time.time())
        try:
            failure = self.check_receipt(proposal, ratifications, receipt, now)
        except Exception as e:  # noqa: BLE001 - fail closed
            failure = f"receipt_malformed:{type(e).__name__}"
        if failure:
            try:
                return (*self._gate._deny(failure, self._pid(proposal)), None)
            except Exception:  # noqa: BLE001
                return False, "deny_unlogged", None
        return self._gate.authorize_bytes(payload_bytes, proposal, ratifications,
                                          self._instant(proposal, ratifications, receipt, now))

    def authorize(self, runtime_payload, proposal, ratifications, receipt, now=None):
        if now is None:
            now = int(time.time())
        try:
            failure = self.check_receipt(proposal, ratifications, receipt, now)
        except Exception as e:  # noqa: BLE001
            failure = f"receipt_malformed:{type(e).__name__}"
        if failure:
            try:
                return self._gate._deny(failure, self._pid(proposal))
            except Exception:  # noqa: BLE001
                return False, "deny_unlogged"
        return self._gate.authorize(runtime_payload, proposal, ratifications,
                                    self._instant(proposal, ratifications, receipt, now))


# ---------------------------------------------------------------- Transparent Authorization Record

def make_tar(proposal, ratifications, policy_id, receipt):
    return S.dcbor({"proposal": S.to_cose(proposal), "ratifications": [S.to_cose(r) for r in ratifications],
                    "policy_ref": policy_id, "receipt": receipt})


def parse_tar(data):
    obj = S.strict_loads(bytes(data))
    if not (isinstance(obj, Mapping) and set(obj) <= {"proposal", "ratifications", "policy_ref", "receipt"}
            and {"proposal", "ratifications", "policy_ref"} <= set(obj)):
        raise ValueError("malformed Transparent Authorization Record")
    return (S.from_cose(obj["proposal"]), [S.from_cose(x) for x in obj["ratifications"]], obj["policy_ref"],
            obj.get("receipt"))


def verify_tar_offline(proposal, ratifications, receipt, policy, trusted_logs, at=None):
    """SAR-REQ-139: S11 plus Receipt structure, trust, inclusion and registration within validity,
    with no clock. `at` (optional) is checked with the S2 rule as in sar_cose."""
    try:
        if not S.verify_record_offline(proposal, ratifications, policy, at=at):
            return False
        if MUT == "offline_skip_receipt":
            return True
        failure, info = verify_receipt(receipt, proposal, ratifications, policy["policy_id"], trusted_logs)
        if failure:
            return False
        return check_registration_time(info, proposal, ratifications) is None
    except Exception:  # noqa: BLE001
        return False


def receipt_registered_at(receipt):
    return parse_receipt(receipt)["registered_at"]
