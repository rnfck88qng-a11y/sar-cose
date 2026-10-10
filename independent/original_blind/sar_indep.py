"""Independent SAR (Sovereign Acceptance Runtime) implementation.

Written blind from SARWP working paper v1.1, sections 3 and 4.4-4.15, plus a
fixed wire-format / interface description. It deliberately shares no code with
any other SAR implementation. Every point where the paper is silent or
ambiguous is recorded in DECISIONS.md (referenced below as D<n>).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from collections.abc import Mapping

import cbor2  # used for DECODING only; encoding is our own (dcbor below)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "dcbor", "dcbor_decode_strict", "new_keypair", "make_proposal", "ratify",
    "to_cose", "from_cose", "Store", "Gate", "verify_record_offline",
    "payload_digest", "PROPOSAL_CT", "RATIFICATION_CT",
]

ALG_ED25519 = -19                      # RFC 9864 fully-specified Ed25519
PROPOSAL_CT = "application/sar-proposal+cbor"
RATIFICATION_CT = "application/sar-ratification+cbor"
VERDICTS = ("APPROVED", "REJECTED")    # D7: anything else is malformed
VERSION = 1
MAX_FUTURE_SKEW = 0                    # D1: no tolerance for future-dated statements

PROPOSAL_KEYS = frozenset(
    {"v", "agent_id", "payload_digest", "issued_at", "expires_at", "nonce",
     "policy_id", "proposal_id"})
RATIFICATION_KEYS = frozenset(
    {"v", "proposal_digest", "proposal_id", "overseer_id", "verdict",
     "reviewed_at", "valid_until", "policy_id"})
POLICY_KEYS = frozenset(
    {"policy_id", "quorum", "authorized_agents", "authorized_overseers"})

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"\A[0-9a-f]{128}\Z")
_HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")


# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 section 4.2.1, core deterministic encoding)
# ---------------------------------------------------------------------------
class Tag:
    """A CBOR tag for encoding (cbor2.CBORTag is also accepted)."""

    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class CBORError(ValueError):
    pass


def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise CBORError("negative length/argument")
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24]) + n.to_bytes(1, "big")
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise CBORError("integer out of CBOR range")


def _enc(obj, depth: int) -> bytes:
    if depth > 64:
        raise CBORError("nesting too deep")
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if obj is None:
        return b"\xf6"
    if type(obj) is int:
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, float):
        raise CBORError("floats are not permitted")
    if isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        return _head(2, len(b)) + b
    if isinstance(obj, str):
        b = obj.encode("utf-8")  # raises on lone surrogates
        return _head(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(_enc(x, depth + 1) for x in obj)
    if isinstance(obj, Mapping):
        items = []
        for k, v in obj.items():
            items.append((_enc(k, depth + 1), _enc(v, depth + 1)))
        items.sort(key=lambda kv: kv[0])  # bytewise lexicographic order
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CBORError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(obj, Tag) or isinstance(obj, cbor2.CBORTag):
        if type(obj.tag) is not int or obj.tag < 0:
            raise CBORError("bad tag number")
        return _head(6, obj.tag) + _enc(obj.value, depth + 1)
    raise CBORError(f"type not encodable: {type(obj).__name__}")


def dcbor(obj) -> bytes:
    """Deterministically encode obj (ints, bytes, text, arrays, maps, bools,
    null, tags). Floats and other types raise CBORError."""
    return _enc(obj, 0)


def dcbor_decode_strict(data: bytes):
    """Decode CBOR and require that it is exactly the deterministic encoding
    of the decoded value (rejects non-shortest heads, indefinite lengths,
    unsorted or duplicate map keys, floats, unknown simple values, trailing
    bytes)."""
    if not isinstance(data, (bytes, bytearray)):
        raise CBORError("expected bytes")
    data = bytes(data)
    try:
        obj = cbor2.loads(data)
    except Exception as e:  # noqa: BLE001
        raise CBORError(f"undecodable CBOR: {e}") from None
    if dcbor(obj) != data:
        raise CBORError("non-deterministic CBOR encoding")
    return obj


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def payload_digest(payload) -> bytes:
    """d_P = SHA-256(dcbor(P)) (paper 4.4)."""
    return _sha256(dcbor(payload))


# ---------------------------------------------------------------------------
# Keys and statements
# ---------------------------------------------------------------------------
def new_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub.hex()


def _protected(content_type: str, kid: str) -> bytes:
    return dcbor({1: ALG_ED25519, 3: content_type, 4: kid.encode("utf-8")})


def _sig_structure(protected: bytes, body_bytes: bytes) -> bytes:
    return dcbor(["Signature1", protected, b"", body_bytes])


def _sign(priv: Ed25519PrivateKey, content_type: str, kid: str, body: dict) -> dict:
    protected = _protected(content_type, kid)
    sig = priv.sign(_sig_structure(protected, dcbor(body)))
    return {"protected": protected, "body": body, "sig": sig.hex()}


def _compute_proposal_id(body: Mapping) -> str:
    rest = {k: v for k, v in body.items() if k != "proposal_id"}
    return hashlib.sha256(dcbor(rest)).hexdigest()[:32]


def make_proposal(agent_priv, agent_id, payload, ttl=60, nonce="n1",
                  policy_id="p1", now=None):
    issued = int(time.time() if now is None else now)
    body = {
        "v": VERSION,
        "agent_id": agent_id,
        "payload_digest": payload_digest(payload),
        "issued_at": issued,
        "expires_at": issued + int(ttl),
        "nonce": nonce,
        "policy_id": policy_id,
    }
    body["proposal_id"] = _compute_proposal_id(body)
    return _sign(agent_priv, PROPOSAL_CT, agent_id, body)


def ratify(overseer_priv, overseer_id, proposal, verdict="APPROVED", ttl=60,
           now=None):
    reviewed = int(time.time() if now is None else now)
    body = {
        "v": VERSION,
        "proposal_digest": _sha256(to_cose(proposal)),
        "proposal_id": proposal["body"]["proposal_id"],
        "overseer_id": overseer_id,
        "verdict": verdict,
        "reviewed_at": reviewed,
        "valid_until": reviewed + int(ttl),
        "policy_id": proposal["body"]["policy_id"],
    }
    return _sign(overseer_priv, RATIFICATION_CT, overseer_id, body)


def to_cose(stmt) -> bytes:
    """COSE_Sign1 = tag 18 [protected, {}, dcbor(body), signature]."""
    if not isinstance(stmt, Mapping) or set(stmt.keys()) != {"protected", "body", "sig"}:
        raise CBORError("statement must have exactly protected/body/sig")
    protected, body, sig = stmt["protected"], stmt["body"], stmt["sig"]
    if not isinstance(protected, (bytes, bytearray)):
        raise CBORError("protected must be bytes")
    if not isinstance(body, Mapping):
        raise CBORError("body must be a map")
    if not isinstance(sig, str) or not _HEX128.match(sig):
        raise CBORError("sig must be 128 lowercase hex chars")
    return dcbor(Tag(18, [bytes(protected), {}, dcbor(body), bytes.fromhex(sig)]))


def from_cose(data: bytes) -> dict:
    obj = dcbor_decode_strict(data)
    if not isinstance(obj, cbor2.CBORTag) or obj.tag != 18:
        raise CBORError("not a tagged COSE_Sign1")
    arr = obj.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise CBORError("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, sig = arr
    if not isinstance(protected, bytes):
        raise CBORError("protected header must be bstr")
    if not isinstance(unprotected, Mapping) or len(unprotected) != 0:
        raise CBORError("unprotected header parameters are not permitted")
    if not isinstance(payload, bytes):
        raise CBORError("payload must be bstr (detached payload not permitted)")
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise CBORError("signature must be a 64-byte bstr")
    hdr = dcbor_decode_strict(protected)
    if not isinstance(hdr, Mapping):
        raise CBORError("protected header must be a map")
    body = dcbor_decode_strict(payload)
    if not isinstance(body, Mapping):
        raise CBORError("payload must be a map")
    return {"protected": protected, "body": dict(body), "sig": sig.hex()}


# ---------------------------------------------------------------------------
# Verification core
# ---------------------------------------------------------------------------
class Deny(Exception):
    """Internal: a reasoned denial."""


def _is_uint(x) -> bool:
    return type(x) is int and 0 <= x < 2 ** 64


def _is_id(x) -> bool:
    return isinstance(x, str) and 0 < len(x) <= 256


def _load_pub(hexkey) -> tuple[Ed25519PublicKey, bytes]:
    if not isinstance(hexkey, str) or not _HEX64.match(hexkey):
        raise Deny("invalid policy: key is not 64 lowercase hex chars")
    raw = bytes.fromhex(hexkey)
    try:
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except Exception:  # noqa: BLE001
        raise Deny("invalid policy: key is not a valid Ed25519 key") from None


def validate_policy(policy):
    """Return a normalized policy or raise Deny (paper 4.5.3, 4.7; D8-D11)."""
    if not isinstance(policy, Mapping):
        raise Deny("invalid policy: not a map")
    if set(policy.keys()) != POLICY_KEYS:
        raise Deny("invalid policy: unexpected or missing keys "
                   "(unenforceable constraints are refused)")
    pid, quorum = policy["policy_id"], policy["quorum"]
    agents, overseers = policy["authorized_agents"], policy["authorized_overseers"]
    if not _is_id(pid):
        raise Deny("invalid policy: policy_id")
    if type(quorum) is not int or quorum < 1:
        raise Deny("invalid policy: quorum must be an integer >= 1")
    if not isinstance(agents, Mapping) or not agents:
        raise Deny("invalid policy: no authorized agents")
    if not isinstance(overseers, Mapping) or not overseers:
        raise Deny("invalid policy: no authorized overseers")
    if quorum > len(overseers):
        raise Deny("invalid policy: quorum unsatisfiable")
    na, no, raws_a, raws_o = {}, {}, set(), set()
    for ident, k in agents.items():
        if not _is_id(ident):
            raise Deny("invalid policy: agent id")
        na[ident], raw = _load_pub(k)
        raws_a.add(raw)
    for ident, k in overseers.items():
        if not _is_id(ident):
            raise Deny("invalid policy: overseer id")
        no[ident], raw = _load_pub(k)
        if raw in raws_o:
            raise Deny("invalid policy: two overseers share one key")
        raws_o.add(raw)
    if raws_a & raws_o or set(na) & set(no):
        raise Deny("invalid policy: agent and overseer roles overlap")
    return {"policy_id": pid, "quorum": quorum, "agents": na, "overseers": no}


def _verify_statement(stmt, content_type, keys, id_field, keyring):
    """Snapshot, parse strictly, check header and signature.
    Returns (canonical_stmt, cose_bytes)."""
    try:
        cose = to_cose(stmt)
        canon = from_cose(cose)          # independent copy, strictly parsed
    except Deny:
        raise
    except Exception as e:  # noqa: BLE001
        raise Deny(f"malformed statement: {e}") from None
    if canon["protected"] != bytes(stmt["protected"]):
        raise Deny("malformed statement: protected header changed")
    hdr = dcbor_decode_strict(canon["protected"])
    if set(hdr.keys()) != {1, 3, 4}:
        raise Deny("protected header must contain exactly alg, content type, kid")
    if hdr[1] != ALG_ED25519 or type(hdr[1]) is not int:
        raise Deny("unsupported algorithm")
    if hdr[3] != content_type:
        raise Deny("wrong content type")
    body = canon["body"]
    if set(body.keys()) != keys:
        raise Deny("body has unexpected or missing fields")
    if type(body["v"]) is not int or body["v"] != VERSION:
        raise Deny("unsupported statement version")
    signer = body[id_field]
    if not _is_id(signer):
        raise Deny(f"malformed {id_field}")
    if not isinstance(hdr[4], bytes) or hdr[4] != signer.encode("utf-8"):
        raise Deny("kid does not match signer id")
    pub = keyring.get(signer)
    if pub is None:
        raise Deny(f"{id_field} not authorized by policy")
    try:
        pub.verify(bytes.fromhex(canon["sig"]),
                   _sig_structure(canon["protected"], dcbor(body)))
    except InvalidSignature:
        raise Deny(f"invalid signature ({id_field}={signer})") from None
    return canon, cose


def _check_number(now):
    if type(now) is bool or not isinstance(now, (int, float)) or not math.isfinite(now):
        raise Deny("invalid evaluation time")


def _evaluate(proposal, ratifications, policy, *, mode, now=None,
              runtime_payload=None, have_payload=False):
    """Shared verification for the gate (mode='gate') and the offline
    verifier (mode='offline'). Returns info dict on success, raises Deny."""
    pol = validate_policy(policy)
    if proposal is None:
        raise Deny("missing proposal")
    if ratifications is None or not isinstance(ratifications, (list, tuple)):
        raise Deny("missing ratification set")
    if len(ratifications) == 0:
        raise Deny("missing ratification")
    if len(ratifications) > 1024:
        raise Deny("ratification set too large")

    # --- proposal ---
    p, p_cose = _verify_statement(proposal, PROPOSAL_CT, PROPOSAL_KEYS,
                                  "agent_id", pol["agents"])
    pb = p["body"]
    if not (isinstance(pb["payload_digest"], bytes) and len(pb["payload_digest"]) == 32):
        raise Deny("malformed payload_digest")
    if not (_is_uint(pb["issued_at"]) and _is_uint(pb["expires_at"])):
        raise Deny("malformed proposal validity interval")
    nonce = pb["nonce"]
    if not (isinstance(nonce, (str, bytes)) and 0 < len(nonce) <= 256):
        raise Deny("malformed nonce")
    if pb["policy_id"] != pol["policy_id"]:
        raise Deny("proposal policy_id does not match gate policy")
    if not (isinstance(pb["proposal_id"], str) and _HEX32.match(pb["proposal_id"])
            and pb["proposal_id"] == _compute_proposal_id(pb)):
        raise Deny("proposal_id is not derived from proposal content")
    if pb["issued_at"] >= pb["expires_at"]:
        raise Deny("proposal validity interval empty")
    p_digest = _sha256(p_cose)

    # --- ratifications ---
    seen, approvals, rejected, rbodies = set(), [], [], []
    window_lo, window_hi = pb["issued_at"], pb["expires_at"]
    for r in ratifications:
        rc, _ = _verify_statement(r, RATIFICATION_CT, RATIFICATION_KEYS,
                                  "overseer_id", pol["overseers"])
        rb = rc["body"]
        rbodies.append(rb)
        if not (isinstance(rb["proposal_digest"], bytes)
                and rb["proposal_digest"] == p_digest):
            raise Deny("ratification is not bound to this proposal")
        if rb["proposal_id"] != pb["proposal_id"]:
            raise Deny("ratification proposal_id mismatch")
        if rb["policy_id"] != pol["policy_id"]:
            raise Deny("ratification policy_id does not match gate policy")
        if not isinstance(rb["verdict"], str) or rb["verdict"] not in VERDICTS:
            raise Deny("unknown verdict")
        if not (_is_uint(rb["reviewed_at"]) and _is_uint(rb["valid_until"])):
            raise Deny("malformed ratification validity interval")
        if rb["reviewed_at"] >= rb["valid_until"]:
            raise Deny("ratification validity interval empty")
        if rb["reviewed_at"] < pb["issued_at"]:
            raise Deny("ratification predates proposal")
        if rb["reviewed_at"] >= pb["expires_at"]:
            raise Deny("ratification issued after proposal expiry")
        ov = rb["overseer_id"]
        if ov in seen:
            raise Deny("duplicate ratification from one overseer")
        seen.add(ov)
        window_lo = max(window_lo, rb["reviewed_at"])
        window_hi = min(window_hi, rb["valid_until"])
        (approvals if rb["verdict"] == "APPROVED" else rejected).append(ov)

    if rejected:
        raise Deny("rejected by overseer " + ",".join(sorted(rejected)))
    if len(approvals) < pol["quorum"]:
        raise Deny(f"insufficient quorum ({len(approvals)}/{pol['quorum']})")
    if window_lo >= window_hi:
        raise Deny("no instant at which proposal and all ratifications were valid")

    if mode == "gate":
        _check_number(now)
        if pb["issued_at"] > now + MAX_FUTURE_SKEW:
            raise Deny("proposal is future-dated")
        if now >= pb["expires_at"]:
            raise Deny("proposal expired")
        for rb in rbodies:
            if rb["reviewed_at"] > now + MAX_FUTURE_SKEW:
                raise Deny("ratification is future-dated")
            if now >= rb["valid_until"]:
                raise Deny("ratification expired")
        if not have_payload:
            raise Deny("missing runtime payload")
        try:
            d_rt = payload_digest(runtime_payload)
        except Exception as e:  # noqa: BLE001
            raise Deny(f"runtime payload not canonically encodable: {e}") from None
        if d_rt != pb["payload_digest"]:
            raise Deny("payload digest mismatch")
    elif now is not None:  # offline verifier with explicit evaluation instant
        _check_number(now)
        if not (window_lo <= now < window_hi):
            raise Deny("authorization not valid at the given instant")

    return {"policy_id": pol["policy_id"], "proposal_id": pb["proposal_id"],
            "nonce": nonce, "agent_id": pb["agent_id"],
            "proposal_digest": p_digest.hex(), "approvals": sorted(approvals)}


def verify_record_offline(proposal, ratifications, policy, at=None) -> bool:
    """Stateless verification (paper 4.12) that the artifacts constitute a
    valid authorization under `policy`. Does not need the runtime or the store.
    Without `at`, validity intervals are checked for internal consistency
    (a common validity window exists); with `at`, also that `at` is inside it.
    Never raises."""
    try:
        _evaluate(proposal, ratifications, policy, mode="offline", now=at)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Store: append-only hash-chained decision log + consumed authorizations
# ---------------------------------------------------------------------------
GENESIS = "0" * 64


def _link_hash(seq: int, prev: str, record: str) -> str:
    return hashlib.sha256(dcbor([seq, prev, record])).hexdigest()


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.lock = threading.RLock()
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS log (seq INTEGER PRIMARY KEY, "
            "record TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS consumed (key TEXT PRIMARY KEY, "
            "log_seq INTEGER NOT NULL)")

    def close(self):
        try:
            self.db.close()
        except Exception:  # noqa: BLE001
            pass

    def __del__(self):
        self.close()

    # -- chain -----------------------------------------------------------
    def _rows(self):
        return self.db.execute(
            "SELECT seq, record, prev, hash FROM log ORDER BY seq").fetchall()

    def verify_chain(self) -> bool:
        try:
            with self.lock:
                prev, expect = GENESIS, 1
                for seq, record, p, h in self._rows():
                    if seq != expect or p != prev or not isinstance(record, str):
                        return False
                    if _link_hash(seq, p, record) != h:
                        return False
                    prev, expect = h, expect + 1
                return True
        except Exception:  # noqa: BLE001
            return False

    def _append(self, record: str) -> int:
        row = self.db.execute(
            "SELECT seq, hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
        self.db.execute("INSERT INTO log (seq, record, prev, hash) VALUES (?,?,?,?)",
                        (seq, record, prev, _link_hash(seq, prev, record)))
        return seq

    def _consumed_in_log(self, keys) -> bool:
        """Replay keys are also recorded inside the chained ALLOW records, so
        deleting rows from `consumed` alone cannot re-enable a replay."""
        keys = set(keys)
        for (record,) in self.db.execute("SELECT record FROM log"):
            if not record.startswith("ALLOW "):
                continue
            try:
                data = json.loads(record[6:])
            except Exception:  # noqa: BLE001
                return True  # unparsable ALLOW record: fail closed
            if keys & set(data.get("consumed", [])):
                return True
        return False

    # -- decisions -------------------------------------------------------
    def log_deny(self, info: dict) -> None:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self._append("DENY " + json.dumps(info, sort_keys=True))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def consume_and_log_allow(self, keys, info: dict) -> None:
        """Atomically: check chain integrity, check replay keys, mark them
        consumed, append the ALLOW record. Raises Deny on any failure."""
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if not self.verify_chain():
                    raise Deny("decision log integrity check failed")
                for k in keys:
                    if self.db.execute("SELECT 1 FROM consumed WHERE key=?",
                                       (k,)).fetchone():
                        raise Deny("replay: authorization already consumed (" +
                                   k.split("|", 1)[0] + ")")
                if self._consumed_in_log(keys):
                    raise Deny("replay: authorization already consumed (log)")
                rec = dict(info, consumed=sorted(keys))
                seq = self._append("ALLOW " + json.dumps(rec, sort_keys=True))
                for k in keys:
                    self.db.execute("INSERT INTO consumed (key, log_seq) VALUES (?,?)",
                                    (k, seq))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------
def _replay_keys(info: dict, runtime_payload) -> list[str]:
    pid = info["policy_id"]
    n = info["nonce"]
    n_repr = ("t:" + n) if isinstance(n, str) else ("b:" + n.hex())
    keys = [
        f"proposal_id|{pid}|{info['proposal_id']}",
        f"proposal_digest|{info['proposal_digest']}",
        f"nonce|{pid}|{n_repr}",
    ]
    if isinstance(runtime_payload, Mapping) and "transaction_id" in runtime_payload:
        tx = dcbor(runtime_payload["transaction_id"]).hex()
        keys.append(f"transaction_id|{pid}|{tx}")
    return keys


class Gate:
    _NO_PAYLOAD = object()

    def __init__(self, policy, store):
        self.policy = policy
        self.store = store

    def authorize(self, runtime_payload, proposal, ratifications, now=None):
        """Fail-closed execution gate (paper 4.6 phase 5, 4.7). Returns
        (allowed, reason). Never raises. Starts in DENY."""
        claimed = {}
        try:
            try:
                claimed = {"proposal_id": str(proposal["body"]["proposal_id"])[:64]}
            except Exception:  # noqa: BLE001
                pass
            t = time.time() if now is None else now
            claimed["at"] = t if isinstance(t, (int, float)) and not isinstance(t, bool) \
                and math.isfinite(t) else None
            info = _evaluate(proposal, ratifications, self.policy, mode="gate",
                             now=t, runtime_payload=runtime_payload,
                             have_payload=True)
            keys = _replay_keys(info, runtime_payload)
            rec = {"at": t, "proposal_id": info["proposal_id"],
                   "agent_id": info["agent_id"], "policy_id": info["policy_id"],
                   "approvals": info["approvals"]}
            self.store.consume_and_log_allow(keys, rec)
            return True, "ALLOW"
        except Deny as e:
            reason = str(e)
        except Exception as e:  # noqa: BLE001
            reason = f"internal verification failure: {type(e).__name__}"
        try:
            self.store.log_deny(dict(claimed, reason=reason))
        except Exception:  # noqa: BLE001
            reason += " (decision could not be logged)"
        return False, "DENY: " + reason
