"""sar_cose.py - minimal SAR reference implementation (SARWP v1.1, section 6).

Proposal and Ratification Statements are COSE_Sign1 objects (RFC 9052) whose payloads are
deterministically encoded CBOR (RFC 8949 section 4.2.1), signed with Ed25519 using the
fully-specified algorithm identifier -19 (RFC 9864). The Execution Gate evaluates the
Registration Policy, verifies both statement types, compares the runtime payload digest with
the ratified one, and consumes the nonce atomically with recording the decision in a
hash-chained SQLite log whose head is published as a signed checkpoint.

Not implemented (still [Specified]): registration with an external SCITT Transparency
Service, Receipts and inclusion proofs, consistency monitoring.

Implements the interface expected by harness/test_sar_conformance.py:
new_keypair, make_proposal, ratify, Store, Gate, verify_record_offline.

Mutants for test-the-tests (env SAR_MUTANT) are listed in MUTANTS below; each disables one guard.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MUT = os.environ.get("SAR_MUTANT", "")
MUTANTS = [
    "skip_digest", "skip_replay", "skip_expiry", "skip_rat_expiry", "skip_sig", "allow_rejected",
    "chain_noop", "dedup_overseer", "skip_policy_bind", "skip_future_check", "offline_skip_quorum",
    "skip_head_check", "skip_alg_check", "skip_ctype_check", "skip_kid_check",
    "accept_nondeterministic", "skip_binding", "offline_skip_binding", "deferred_tx",
]

ALG_ED25519 = -19          # RFC 9864 fully-specified Ed25519
ALG_EDDSA = -8             # polymorphic EdDSA, deprecated by RFC 9864; interop/testing only
HDR_ALG, HDR_CT, HDR_KID = 1, 3, 4
COSE_SIGN1_TAG = 18
CT_PROPOSAL = "application/sar-proposal+cbor"
CT_RATIFICATION = "application/sar-ratification+cbor"
MAX_CLOCK_SKEW = 30        # seconds a statement may be dated in the future
VERDICTS = ("APPROVED", "REJECTED")


class NonDeterministicCBOR(ValueError):
    pass


# ---------------------------------------------------------------- deterministic CBOR (RFC 8949 4.2.1)

def _head(major, n):
    if n < 0:
        raise ValueError("negative length")
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * size)):
            return bytes([(major << 5) | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large for CBOR head")


def dcbor(o):
    """Core deterministic encoding: preferred (shortest) heads, definite lengths, map keys sorted
    by the bytewise order of their encodings, no duplicate keys. Floats are not supported."""
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if o is None:
        return b"\xf6"
    if isinstance(o, int):
        return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, (bytes, bytearray)):
        return _head(2, len(o)) + bytes(o)
    if isinstance(o, str):
        b = o.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(o, (list, tuple)):
        return _head(4, len(o)) + b"".join(dcbor(x) for x in o)
    if isinstance(o, Mapping):  # cbor2>=6 decodes nested maps as frozendict
        items = sorted((dcbor(k), dcbor(v)) for k, v in o.items())
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(o, cbor2.CBORTag):
        return _head(6, o.tag) + dcbor(o.value)
    raise TypeError(f"type not allowed in SAR CBOR: {type(o).__name__}")


def strict_loads(b):
    """Decode CBOR and reject anything that is not in deterministic form (non-preferred
    integers, unsorted or duplicate map keys, indefinite lengths, floats, trailing bytes)."""
    obj = cbor2.loads(b)
    if MUT == "accept_nondeterministic":
        return obj
    try:
        canonical = dcbor(obj)
    except (TypeError, ValueError) as e:
        raise NonDeterministicCBOR(str(e)) from e
    if canonical != bytes(b):
        raise NonDeterministicCBOR("encoding is not deterministic CBOR")
    return obj


def H(b):
    return hashlib.sha256(b).digest()


def payload_digest(payload):
    return H(dcbor(payload))


# ---------------------------------------------------------------- keys and COSE_Sign1

def new_keypair():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, pub.hex()


def _sig_structure(protected, payload):
    return dcbor(["Signature1", protected, b"", payload])


def sign_statement(priv, kid, content_type, body, alg=ALG_ED25519):
    """Return a statement {"protected", "body", "sig"}; to_cose() gives the COSE_Sign1 bytes."""
    protected = dcbor({HDR_ALG: alg, HDR_CT: content_type, HDR_KID: kid.encode()})
    sig = priv.sign(_sig_structure(protected, dcbor(body)))
    return {"protected": protected, "body": body, "sig": sig.hex()}


def to_cose(stmt):
    return dcbor(cbor2.CBORTag(COSE_SIGN1_TAG, [stmt["protected"], {}, dcbor(stmt["body"]),
                                                 bytes.fromhex(stmt["sig"])]))


def from_cose(data):
    """Parse tagged COSE_Sign1 bytes into a statement. Rejects non-deterministic encodings and
    any unprotected header parameters. Signature is NOT verified here (see verify_statement)."""
    obj = strict_loads(data)
    if not (isinstance(obj, cbor2.CBORTag) and obj.tag == COSE_SIGN1_TAG):
        raise ValueError("not a tagged COSE_Sign1")
    arr = obj.value
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4):
        raise ValueError("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, sig = arr
    if not isinstance(protected, bytes) or not isinstance(payload, bytes) or not isinstance(sig, bytes):
        raise ValueError("malformed COSE_Sign1")
    if not isinstance(unprotected, Mapping) or len(unprotected) != 0:
        raise ValueError("unprotected header parameters are not allowed")
    body = strict_loads(payload)
    if not isinstance(body, Mapping):
        raise ValueError("payload must be a map")
    return {"protected": protected, "body": dict(body), "sig": sig.hex()}


def verify_statement(stmt, pub_hex, content_type, kid, allowed_algs=(ALG_ED25519,)):
    """True iff the protected header is deterministic, names an allowed algorithm, the expected
    content type and kid, and the Ed25519 signature over the Sig_structure is valid."""
    try:
        hdr = strict_loads(stmt["protected"])
        if not isinstance(hdr, Mapping) or set(hdr) != {HDR_ALG, HDR_CT, HDR_KID}:
            return False
        if MUT != "skip_alg_check" and hdr[HDR_ALG] not in allowed_algs:
            return False
        if MUT != "skip_ctype_check" and hdr[HDR_CT] != content_type:
            return False
        if MUT != "skip_kid_check" and hdr[HDR_KID] != kid.encode():
            return False
        if MUT == "skip_sig":
            return True
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(stmt["sig"]), _sig_structure(stmt["protected"], dcbor(stmt["body"])))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError, cbor2.CBORDecodeError):
        return False


def statement_digest(stmt):
    """Digest of the exact COSE_Sign1 bytes; a ratification binds to this value."""
    return H(to_cose(stmt))


# ---------------------------------------------------------------- protocol objects

def make_proposal(agent_priv, agent_id, payload, ttl=60, nonce="n1", policy_id="p1", now=None):
    now = int(time.time() if now is None else now)
    body = {"v": 1, "agent_id": agent_id, "payload_digest": payload_digest(payload),
            "issued_at": now, "expires_at": now + ttl, "nonce": nonce, "policy_id": policy_id}
    body["proposal_id"] = H(dcbor(body)).hex()[:32]
    return sign_statement(agent_priv, agent_id, CT_PROPOSAL, body)


def ratify(overseer_priv, overseer_id, proposal, verdict="APPROVED", ttl=60, now=None):
    now = int(time.time() if now is None else now)
    pb = proposal["body"]
    body = {"v": 1, "proposal_digest": statement_digest(proposal), "proposal_id": pb["proposal_id"],
            "overseer_id": overseer_id, "verdict": verdict, "reviewed_at": now,
            "valid_until": now + ttl, "policy_id": pb["policy_id"]}
    return sign_statement(overseer_priv, overseer_id, CT_RATIFICATION, body)


def policy_valid(policy):
    try:
        overseers = policy["authorized_overseers"]
        return (isinstance(policy["policy_id"], str) and policy["policy_id"]
                and isinstance(policy["quorum"], int) and not isinstance(policy["quorum"], bool)
                and 1 <= policy["quorum"] <= len(overseers)
                and bool(policy["authorized_agents"]))
    except (KeyError, TypeError):
        return False


# ---------------------------------------------------------------- authorization store

def _canon_json(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


class Store:
    """SQLite hash-chained decision log plus consumed-nonce table. After every commit the store
    signs a checkpoint (size, head hash); in a deployment the checkpoint is published outside
    the store (e.g. registered with a transparency service), which is what makes truncation
    detectable. Here the last published checkpoint is held by the Store object."""

    GENESIS = "0" * 64

    def __init__(self, path=":memory:"):
        # Autocommit mode with explicit BEGIN IMMEDIATE: a writer takes the database write lock
        # *before* reading the chain tip, so concurrent gates sharing one database file cannot
        # fork the hash chain (found by test_concurrent_presentations_allow_exactly_once).
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        with self._write():
            self.db.execute("create table if not exists log(seq integer primary key, record text, prev text, hash text)")
            self.db.execute("create table if not exists consumed(k text primary key)")
        self._key = Ed25519PrivateKey.generate()
        self.checkpoint_key = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.published = None
        self._publish()

    @contextlib.contextmanager
    def _write(self):
        self.db.execute("BEGIN" if MUT == "deferred_tx" else "BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def close(self):
        self.db.close()

    def __del__(self):
        try:
            self.db.close()
        except Exception:
            pass

    def _tip(self):
        row = self.db.execute("select count(*), (select hash from log order by seq desc limit 1) from log").fetchone()
        return row[0], (row[1] or self.GENESIS)

    def _insert(self, rec):
        _, prev = self._tip()
        r = _canon_json(rec)
        self.db.execute("insert into log(record,prev,hash) values(?,?,?)",
                        (r, prev, hashlib.sha256((prev + r).encode()).hexdigest()))

    def _publish(self):
        size, head = self._tip()
        msg = dcbor(["sar-checkpoint", size, head])
        self.published = {"size": size, "head": head, "sig": self._key.sign(msg).hex()}

    def append(self, rec):
        with self._write():
            self._insert(rec)
        self._publish()

    def consume(self, key):
        """Standalone consume (kept for interface compatibility)."""
        try:
            with self._write():
                self.db.execute("insert into consumed(k) values(?)", (key,))
            return True
        except sqlite3.IntegrityError:
            return False

    def consume_and_record(self, key, rec):
        """Atomically consume an authorization and record ALLOW; False if already consumed."""
        try:
            with self._write():
                if MUT != "skip_replay":
                    self.db.execute("insert into consumed(k) values(?)", (key,))
                self._insert(rec)
        except sqlite3.IntegrityError:
            return False
        self._publish()
        return True

    def _walk(self):
        """Return (size, head) if every record links to its predecessor, else None."""
        prev, n = self.GENESIS, 0
        for _seq, record, p, h in self.db.execute("select seq,record,prev,hash from log order by seq"):
            if p != prev or hashlib.sha256((p + record).encode()).hexdigest() != h:
                return None
            prev, n = h, n + 1
        return n, prev

    def verify_links(self):
        """Hash-chain linkage only (no checkpoint): detects modification, not truncation."""
        return MUT == "chain_noop" or self._walk() is not None

    def verify_chain(self, checkpoint=None):
        if MUT == "chain_noop":
            return True
        walked = self._walk()
        if walked is None:
            return False
        n, prev = walked
        if MUT == "skip_head_check":
            return True
        cp = checkpoint or self.published
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.checkpoint_key)).verify(
                bytes.fromhex(cp["sig"]), dcbor(["sar-checkpoint", cp["size"], cp["head"]]))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False
        return cp["size"] == n and cp["head"] == prev


# ---------------------------------------------------------------- execution gate

class Gate:
    def __init__(self, policy, store):
        self.policy, self.store = policy, store

    def _deny(self, reason, proposal_id=None):
        self.store.append({"decision": "DENY", "reason": reason, "proposal_id": proposal_id})
        return False, reason

    def authorize(self, runtime_payload, proposal, ratifications, now=None):
        try:
            return self._authorize(runtime_payload, proposal, ratifications, now)
        except Exception as e:  # fail closed on anything unexpected (malformed input etc.)
            return self._deny(f"malformed:{type(e).__name__}")

    def _authorize(self, runtime_payload, proposal, ratifications, now):
        now = int(time.time() if now is None else now)
        pol = self.policy
        if not policy_valid(pol):
            return self._deny("policy_invalid")
        if not proposal:
            return self._deny("missing_proposal")
        if not ratifications:
            return self._deny("missing_ratification")
        pb = proposal["body"]
        pid = pb.get("proposal_id")
        if MUT != "skip_policy_bind" and pb["policy_id"] != pol["policy_id"]:
            return self._deny("policy_mismatch", pid)
        agent_pub = pol["authorized_agents"].get(pb["agent_id"])
        if agent_pub is None:
            return self._deny("agent_not_authorized", pid)
        if not verify_statement(proposal, agent_pub, CT_PROPOSAL, pb["agent_id"]):
            return self._deny("bad_proposal", pid)
        if MUT != "skip_expiry" and now > pb["expires_at"]:
            return self._deny("proposal_expired", pid)
        if MUT != "skip_future_check" and pb["issued_at"] > now + MAX_CLOCK_SKEW:
            return self._deny("proposal_from_future", pid)
        pdig = statement_digest(proposal)
        approvals = []
        for r in ratifications:
            rb = r["body"]
            opub = pol["authorized_overseers"].get(rb["overseer_id"])
            if opub is None:
                return self._deny("overseer_not_authorized", pid)
            if not verify_statement(r, opub, CT_RATIFICATION, rb["overseer_id"]):
                return self._deny("bad_ratification", pid)
            if MUT != "skip_binding" and (rb["proposal_digest"] != pdig or rb["proposal_id"] != pid):
                return self._deny("ratification_not_bound", pid)
            if MUT != "skip_policy_bind" and rb["policy_id"] != pol["policy_id"]:
                return self._deny("policy_mismatch", pid)
            if MUT != "skip_future_check" and (rb["reviewed_at"] > now + MAX_CLOCK_SKEW
                                               or rb["reviewed_at"] < pb["issued_at"]):
                return self._deny("ratification_time_invalid", pid)
            if rb["verdict"] not in VERDICTS:
                return self._deny("unknown_verdict", pid)
            if rb["verdict"] == "REJECTED" and MUT != "allow_rejected":
                return self._deny("rejected", pid)
            if rb["verdict"] == "APPROVED" and (MUT == "skip_rat_expiry" or now <= rb["valid_until"]):
                approvals.append(rb["overseer_id"])
        count = len(approvals) if MUT == "dedup_overseer" else len(set(approvals))
        if count < pol["quorum"] and MUT != "allow_rejected":
            return self._deny("quorum_not_met", pid)
        if MUT != "skip_digest" and payload_digest(runtime_payload) != pb["payload_digest"]:
            return self._deny("payload_mismatch", pid)
        key = f'{pol["policy_id"]}|{pb["agent_id"]}|{pb["nonce"]}'
        if not self.store.consume_and_record(key, {"decision": "ALLOW", "proposal_id": pid}):
            return self._deny("replay", pid)
        return True, "ok"


# ---------------------------------------------------------------- offline verification

def verify_record_offline(proposal, ratifications, policy):
    """Stateless check that the artifacts constitute a valid authorization under `policy`:
    authentic proposal, every ratification authentic and bound to it, no rejection, and a
    quorum of distinct approving overseers who reviewed within the proposal's validity window.
    Needs only the artifacts and trust anchors (no store, no runtime)."""
    try:
        pb = proposal["body"]
        if pb["policy_id"] != policy["policy_id"]:
            return False
        ap = policy["authorized_agents"].get(pb["agent_id"])
        if ap is None or not verify_statement(proposal, ap, CT_PROPOSAL, pb["agent_id"]):
            return False
        pdig = statement_digest(proposal)
        approvers = set()
        for r in ratifications:
            rb = r["body"]
            op = policy["authorized_overseers"].get(rb["overseer_id"])
            if op is None or not verify_statement(r, op, CT_RATIFICATION, rb["overseer_id"]):
                return False
            if MUT != "offline_skip_binding" and rb["proposal_digest"] != pdig:
                return False
            if rb["policy_id"] != policy["policy_id"]:
                return False
            if rb["verdict"] != "APPROVED":
                return False
            if not (pb["issued_at"] <= rb["reviewed_at"] <= min(pb["expires_at"], rb["valid_until"])):
                return False
            approvers.add(rb["overseer_id"])
        if MUT == "offline_skip_quorum":
            return True
        return len(approvers) >= policy["quorum"]
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
