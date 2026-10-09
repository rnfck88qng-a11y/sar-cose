"""sar_stub.py - ILLUSTRATIVE harness implementation. NOT the paper's reference implementation.

Purpose: prove that test_sar_conformance.py can discriminate (passes on a correct gate,
fails on mutated gates). It uses Ed25519 + canonical JSON + sqlite hash chain.
It deliberately does NOT use COSE_Sign1 / CBOR / SCITT. Passing these tests with this stub
is NOT evidence for any "[Proven]" claim in SARWP v1.0. See ../05_build_and_run_tests.md.

Mutants (env SAR_MUTANT): skip_digest, skip_replay, skip_expiry, skip_rat_expiry, skip_sig, allow_rejected, chain_noop
"""
import hashlib
import json
import os
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MUT = os.environ.get("SAR_MUTANT", "")


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def H(b):
    return hashlib.sha256(b).hexdigest()


def new_keypair():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, pub.hex()


def _sign(k, obj):
    return k.sign(canon(obj)).hex()


def _verify(pub_hex, obj, sig_hex):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), canon(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


def make_proposal(agent_priv, agent_id, payload, ttl=60, nonce="n1", policy_id="p1", now=None):
    now = int(time.time() if now is None else now)
    body = {"agent_id": agent_id, "payload_digest": H(canon(payload)), "issued_at": now,
            "expires_at": now + ttl, "nonce": nonce, "policy_id": policy_id}
    body["proposal_id"] = H(canon(body))[:16]
    return {"body": body, "sig": _sign(agent_priv, body)}


def ratify(overseer_priv, overseer_id, proposal, verdict="APPROVED", ttl=60, now=None):
    now = int(time.time() if now is None else now)
    body = {"proposal_digest": H(canon(proposal["body"])), "overseer_id": overseer_id,
            "verdict": verdict, "reviewed_at": now, "valid_until": now + ttl,
            "policy_id": proposal["body"]["policy_id"]}
    return {"body": body, "sig": _sign(overseer_priv, body)}


class Store:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("create table log(seq integer primary key, record text, prev text, hash text)")
        self.db.execute("create table consumed(k text primary key)")

    def append(self, rec):
        row = self.db.execute("select hash from log order by seq desc limit 1").fetchone()
        prev = row[0] if row else "0" * 64
        r = canon(rec).decode()
        self.db.execute("insert into log(record,prev,hash) values(?,?,?)", (r, prev, H((prev + r).encode())))
        self.db.commit()

    def consume(self, key):
        try:
            self.db.execute("insert into consumed(k) values(?)", (key,))
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_chain(self):
        if MUT == "chain_noop":
            return True
        prev = "0" * 64
        for _seq, record, p, h in self.db.execute("select seq,record,prev,hash from log order by seq"):
            if p != prev or H((p + record).encode()) != h:
                return False
            prev = h
        return True


def policy_valid(policy):
    try:
        return (policy["quorum"] >= 1 and policy["authorized_agents"] and policy["authorized_overseers"]
                and policy["policy_id"])
    except (KeyError, TypeError):
        return False


class Gate:
    def __init__(self, policy, store):
        self.policy, self.store = policy, store

    def _deny(self, reason, runtime_payload=None):
        self.store.append({"decision": "DENY", "reason": reason})
        return False, reason

    def authorize(self, runtime_payload, proposal, ratifications, now=None):
        now = int(time.time() if now is None else now)
        if not policy_valid(self.policy):
            return self._deny("policy_invalid")
        if not proposal:
            return self._deny("missing_proposal")
        if not ratifications:
            return self._deny("missing_ratification")
        pb = proposal["body"]
        agent_pub = self.policy["authorized_agents"].get(pb["agent_id"])
        if agent_pub is None:
            return self._deny("agent_not_authorized")
        if MUT != "skip_sig" and not _verify(agent_pub, pb, proposal["sig"]):
            return self._deny("bad_agent_sig")
        if MUT != "skip_expiry" and now > pb["expires_at"]:
            return self._deny("expired")
        pdig = H(canon(pb))
        approvals = 0
        for r in ratifications:
            rb = r["body"]
            opub = self.policy["authorized_overseers"].get(rb["overseer_id"])
            if opub is None:
                return self._deny("overseer_not_authorized")
            if MUT != "skip_sig" and not _verify(opub, rb, r["sig"]):
                return self._deny("bad_ratification_sig")
            if rb["proposal_digest"] != pdig:
                return self._deny("ratification_not_bound")
            if rb["verdict"] == "REJECTED" and MUT != "allow_rejected":
                return self._deny("rejected")
            if rb["verdict"] == "APPROVED" and (MUT == "skip_rat_expiry" or now <= rb["valid_until"]):
                approvals += 1
        if approvals < self.policy["quorum"] and MUT != "allow_rejected":
            return self._deny("quorum_not_met")
        if MUT != "skip_digest" and H(canon(runtime_payload)) != pb["payload_digest"]:
            return self._deny("payload_mismatch")
        if MUT != "skip_replay" and not self.store.consume(pb["nonce"]):
            return self._deny("replay")
        self.store.append({"decision": "ALLOW", "proposal_id": pb["proposal_id"]})
        return True, "ok"


def verify_record_offline(proposal, ratifications, policy):
    """Stateless: needs only artifacts + trust anchors (no store, no runtime)."""
    pb = proposal["body"]
    ap = policy["authorized_agents"].get(pb["agent_id"])
    if ap is None or not _verify(ap, pb, proposal["sig"]):
        return False
    pdig = H(canon(pb))
    for r in ratifications:
        rb = r["body"]
        op = policy["authorized_overseers"].get(rb["overseer_id"])
        if op is None or not _verify(op, rb, r["sig"]) or rb["proposal_digest"] != pdig:
            return False
    return True
