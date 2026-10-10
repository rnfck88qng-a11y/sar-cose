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
    "skip_policy_shape", "skip_role_separation", "skip_shape_check", "skip_proposal_id_check",
    "inclusive_expiry", "replay_proposal_id_only", "skip_common_window",
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
        sig = stmt["sig"]
        if not (isinstance(sig, str) and len(sig) == 128 and sig == sig.lower()):
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


PROPOSAL_KEYS = frozenset({"v", "agent_id", "payload_digest", "issued_at", "expires_at", "nonce", "policy_id",
                           "proposal_id"})
RATIFICATION_KEYS = frozenset({"v", "proposal_digest", "proposal_id", "overseer_id", "verdict", "reviewed_at",
                               "valid_until", "policy_id"})
POLICY_KEYS = frozenset({"policy_id", "quorum", "authorized_agents", "authorized_overseers"})
MAX_ID_LEN = 256


def _uint(x):
    return type(x) is int and 0 <= x < 2**64


def _ident(x):
    return isinstance(x, str) and 0 < len(x) <= MAX_ID_LEN


def _pub_hex(x):
    if not (isinstance(x, str) and len(x) == 64 and x == x.lower()):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(x))
        return True
    except ValueError:
        return False


def expected_proposal_id(pb):
    return H(dcbor({k: v for k, v in pb.items() if k != "proposal_id"})).hex()[:32]


def proposal_shape_ok(pb):
    """Rule S9: exact field set and types for a v1 Proposal Statement body."""
    if MUT == "skip_shape_check":
        return isinstance(pb, Mapping)
    return (isinstance(pb, Mapping) and set(pb) == PROPOSAL_KEYS and type(pb["v"]) is int and pb["v"] == 1
            and _ident(pb["agent_id"]) and _ident(pb["policy_id"])
            and isinstance(pb["payload_digest"], bytes) and len(pb["payload_digest"]) == 32
            and _uint(pb["issued_at"]) and _uint(pb["expires_at"]) and pb["issued_at"] < pb["expires_at"]
            and isinstance(pb["nonce"], (str, bytes)) and 0 < len(pb["nonce"]) <= MAX_ID_LEN
            and isinstance(pb["proposal_id"], str))


def ratification_shape_ok(rb):
    """Rule S9: exact field set and types for a v1 Ratification Statement body."""
    if MUT == "skip_shape_check":
        return isinstance(rb, Mapping)
    return (isinstance(rb, Mapping) and set(rb) == RATIFICATION_KEYS and type(rb["v"]) is int and rb["v"] == 1
            and isinstance(rb["proposal_digest"], bytes) and len(rb["proposal_digest"]) == 32
            and isinstance(rb["proposal_id"], str) and _ident(rb["overseer_id"]) and _ident(rb["policy_id"])
            and isinstance(rb["verdict"], str)
            and _uint(rb["reviewed_at"]) and _uint(rb["valid_until"]) and rb["reviewed_at"] < rb["valid_until"])


def policy_valid(policy):
    """Rule S8: exact field set; non-empty agents and overseers with well-formed ids and Ed25519
    keys; 1 <= quorum <= number of overseers; separation of roles (no key shared by two
    overseers, no identity or key that is both agent and overseer)."""
    try:
        if not isinstance(policy, Mapping):
            return False
        if MUT != "skip_policy_shape" and set(policy) != POLICY_KEYS:
            return False
        agents, overseers, q = policy["authorized_agents"], policy["authorized_overseers"], policy["quorum"]
        if not (_ident(policy["policy_id"]) and isinstance(agents, Mapping) and isinstance(overseers, Mapping)
                and agents and overseers):
            return False
        if not (type(q) is int and 1 <= q <= len(overseers)):
            return False
        if not all(_ident(k) and _pub_hex(v) for k, v in list(agents.items()) + list(overseers.items())):
            return False
        if MUT != "skip_role_separation":
            okeys = list(overseers.values())
            if len(set(okeys)) != len(okeys):
                return False
            if set(agents) & set(overseers) or set(agents.values()) & set(okeys):
                return False
        return True
    except (KeyError, TypeError, AttributeError):
        return False


def _canon_json(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


class Store:
    """SQLite hash-chained decision log plus consumed-nonce table. After every commit the store
    signs a checkpoint (size, head hash) with its checkpoint key. Truncation or rewriting is
    detectable against any checkpoint retained *outside* the database (see checkpoint() and
    verify_chain(checkpoint, checkpoint_key)); the most recent checkpoint is also kept on the
    Store object as `published`. Pass a persistent `signing_key` so that checkpoints remain
    verifiable after the store is reopened."""

    GENESIS = "0" * 64

    def __init__(self, path=":memory:", signing_key=None):
        # Autocommit mode with explicit BEGIN IMMEDIATE: a writer takes the database write lock
        # *before* reading the chain tip, so concurrent gates sharing one database file cannot
        # fork the hash chain (found by test_concurrent_presentations_allow_exactly_once).
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        with self._write():
            self.db.execute("create table if not exists log(seq integer primary key, record text, prev text, hash text)")
            self.db.execute("create table if not exists consumed(k text primary key)")
        self._key = signing_key or Ed25519PrivateKey.generate()
        self.checkpoint_key = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
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

    def consume_and_record(self, keys, rec):
        """Atomically consume every replay key of an authorization and record ALLOW. Returns False
        (and changes nothing) if any key was already consumed."""
        try:
            with self._write():
                if MUT != "skip_replay":
                    for key in keys:
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

    def checkpoint(self):
        """The latest signed checkpoint, for retention outside the store."""
        return dict(self.published)

    def verify_chain(self, checkpoint=None, checkpoint_key=None):
        """True iff every record links to its predecessor and the chain matches the given signed
        checkpoint (default: the store's own latest one) exactly in size and head. Pass a
        checkpoint retained outside the database to detect truncation or rewriting by anyone
        with write access to the database file."""
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
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(checkpoint_key or self.checkpoint_key)).verify(
                bytes.fromhex(cp["sig"]), dcbor(["sar-checkpoint", cp["size"], cp["head"]]))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False
        return cp["size"] == n and cp["head"] == prev


# ---------------------------------------------------------------- execution gate

class Gate:
    """Execution Gate. Implements rules S1-S12 (SEMANTICS.md): it starts from DENY and allows only
    if every check passes; every decision, including every denial, is recorded in the store."""

    def __init__(self, policy, store):
        self.policy, self.store = policy, store

    def _deny(self, reason, proposal_id=None):
        self.store.append({"decision": "DENY", "reason": reason, "proposal_id": proposal_id})
        return False, reason

    def authorize(self, runtime_payload, proposal, ratifications, now=None):
        try:
            return self._authorize(runtime_payload, proposal, ratifications, now)
        except Exception as e:  # fail closed on anything unexpected (malformed input etc.)
            try:
                return self._deny(f"malformed:{type(e).__name__}")
            except Exception:  # even if the denial cannot be logged, never allow (S12)
                return False, "deny_unlogged"

    def _authorize(self, runtime_payload, proposal, ratifications, now):
        if now is None:
            now = int(time.time())
        if type(now) is not int:
            return self._deny("invalid_clock")
        pol = self.policy
        if not policy_valid(pol):
            return self._deny("policy_invalid")
        if not proposal:
            return self._deny("missing_proposal")
        if not ratifications or not isinstance(ratifications, (list, tuple)):
            return self._deny("missing_ratification")
        pb = proposal["body"]
        if not proposal_shape_ok(pb):
            return self._deny("malformed_proposal")
        pid = pb["proposal_id"]
        if MUT != "skip_proposal_id_check" and pid != expected_proposal_id(pb):
            return self._deny("proposal_id_mismatch", pid)
        if MUT != "skip_policy_bind" and pb["policy_id"] != pol["policy_id"]:
            return self._deny("policy_mismatch", pid)
        agent_pub = pol["authorized_agents"].get(pb["agent_id"])
        if agent_pub is None:
            return self._deny("agent_not_authorized", pid)
        if not verify_statement(proposal, agent_pub, CT_PROPOSAL, pb["agent_id"]):
            return self._deny("bad_proposal", pid)
        if MUT != "skip_expiry" and not (now < pb["expires_at"] or (MUT == "inclusive_expiry" and now == pb["expires_at"])):
            return self._deny("proposal_expired", pid)
        if MUT != "skip_future_check" and pb["issued_at"] > now + MAX_CLOCK_SKEW:
            return self._deny("proposal_from_future", pid)
        pdig = statement_digest(proposal)
        approvers = set()
        start, end = pb["issued_at"], pb["expires_at"]
        for r in ratifications:
            rb = r["body"]
            if not ratification_shape_ok(rb):
                return self._deny("malformed_ratification", pid)
            opub = pol["authorized_overseers"].get(rb["overseer_id"])
            if opub is None:
                return self._deny("overseer_not_authorized", pid)
            if not verify_statement(r, opub, CT_RATIFICATION, rb["overseer_id"]):
                return self._deny("bad_ratification", pid)
            if MUT != "skip_binding" and (rb["proposal_digest"] != pdig or rb["proposal_id"] != pid):
                return self._deny("ratification_not_bound", pid)
            if MUT != "skip_policy_bind" and rb["policy_id"] != pol["policy_id"]:
                return self._deny("policy_mismatch", pid)
            if MUT != "dedup_overseer" and rb["overseer_id"] in approvers:
                return self._deny("duplicate_ratification", pid)
            if MUT != "skip_future_check" and (rb["reviewed_at"] > now + MAX_CLOCK_SKEW
                                               or rb["reviewed_at"] < pb["issued_at"]
                                               or rb["reviewed_at"] >= pb["expires_at"]):
                return self._deny("ratification_time_invalid", pid)
            if rb["verdict"] not in VERDICTS:
                return self._deny("unknown_verdict", pid)
            if rb["verdict"] == "REJECTED":
                if MUT == "allow_rejected":
                    continue
                return self._deny("rejected", pid)
            if MUT != "skip_rat_expiry" and now >= rb["valid_until"]:
                return self._deny("ratification_expired", pid)
            start, end = max(start, rb["reviewed_at"]), min(end, rb["valid_until"])
            approvers.add(rb["overseer_id"])
        count = len(approvers) + (len(ratifications) - len(approvers) if MUT == "dedup_overseer" else 0)
        if count < pol["quorum"]:
            return self._deny("quorum_not_met", pid)
        if MUT != "skip_common_window" and not start < end:  # S13: every ALLOW is offline-verifiable
            return self._deny("no_common_validity", pid)
        if MUT != "skip_digest" and payload_digest(runtime_payload) != pb["payload_digest"]:
            return self._deny("payload_mismatch", pid)
        keys = [f'pid|{pol["policy_id"]}|{pid}']
        if MUT != "replay_proposal_id_only":
            keys.append(f'nonce|{pol["policy_id"]}|{dcbor(pb["nonce"]).hex()}')
            if isinstance(runtime_payload, Mapping) and "transaction_id" in runtime_payload:
                keys.append(f'txn|{pol["policy_id"]}|{dcbor(runtime_payload["transaction_id"]).hex()}')
        if not self.store.consume_and_record(keys, {"decision": "ALLOW", "proposal_id": pid}):
            return self._deny("replay", pid)
        return True, "ok"


# ---------------------------------------------------------------- offline verification

def verify_record_offline(proposal, ratifications, policy, at=None):
    """Stateless check (rule S11) that the artifacts constitute a valid authorization under
    `policy`, using only the artifacts and the policy's trust anchors (no store, no clock):
    authentic, well-formed, policy-bound proposal; every ratification authentic, bound to it,
    distinct, APPROVED and issued within the proposal's validity window; a quorum of distinct
    approvers; and a non-empty interval in which the proposal and all ratifications were valid
    together (which must contain `at`, if given)."""
    try:
        if not policy_valid(policy):
            return False
        pb = proposal["body"]
        if not proposal_shape_ok(pb) or pb["proposal_id"] != expected_proposal_id(pb):
            return False
        if pb["policy_id"] != policy["policy_id"]:
            return False
        ap = policy["authorized_agents"].get(pb["agent_id"])
        if ap is None or not verify_statement(proposal, ap, CT_PROPOSAL, pb["agent_id"]):
            return False
        pdig = statement_digest(proposal)
        approvers = set()
        start, end = pb["issued_at"], pb["expires_at"]
        for r in ratifications:
            rb = r["body"]
            if not ratification_shape_ok(rb):
                return False
            op = policy["authorized_overseers"].get(rb["overseer_id"])
            if op is None or not verify_statement(r, op, CT_RATIFICATION, rb["overseer_id"]):
                return False
            if MUT != "offline_skip_binding" and (rb["proposal_digest"] != pdig or rb["proposal_id"] != pb["proposal_id"]):
                return False
            if rb["policy_id"] != policy["policy_id"] or rb["verdict"] != "APPROVED":
                return False
            if rb["overseer_id"] in approvers:
                return False
            if not (pb["issued_at"] <= rb["reviewed_at"] < pb["expires_at"]):
                return False
            start, end = max(start, rb["reviewed_at"]), min(end, rb["valid_until"])
            approvers.add(rb["overseer_id"])
        if MUT == "offline_skip_quorum":
            return True
        if len(approvers) < policy["quorum"] or not start < end:
            return False
        return at is None or start <= at < end
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
