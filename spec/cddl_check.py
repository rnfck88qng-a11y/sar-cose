"""Minimal CDDL (RFC 8610) checker for the subset used in spec/sar-profile.cddl.

No full CDDL tool (the Ruby `cddl` gem, `cddlc`, or a Rust/JS implementation) was installed in the
environment where this profile was written, so this script implements the subset of CDDL the
profile uses and nothing more:

  rules `name = type`; comments `;`; choices `/`; literals (integers, negative integers, text);
  ranges `a..b`; control operators `.size` and `.cbor`; tags `#6.n(type)`; maps `{ ... }` with
  bare-word keys `key: type` and computed keys `type => type`; arrays `[ ... ]` with optional
  member labels; occurrence indicators `?`, `+`, `*`; groups in parentheses; the prelude types
  uint, nint, int, tstr, text, bstr, bytes, bool, nil, null, any.

Maps are closed: a member not matched by any entry fails. It is NOT a conforming CDDL
implementation (no generics, sockets, unwrapping, cuts, or most control operators).

    python3 spec/cddl_check.py                 # parse the CDDL and validate every test vector
    python3 spec/cddl_check.py --parse-only

Validation of vectors: every statement, body and policy that occurs in a vector must satisfy its
rule, except the artifacts a vector lists in "cddl_invalid", which must NOT satisfy it.
"""
import json
import pathlib
import re
import sys

import cbor2

HERE = pathlib.Path(__file__).resolve().parent
CDDL = HERE / "sar-profile.cddl"
VECTORS = HERE / "test-vectors"

TOKEN = re.compile(r'''\s*(?:
    (?P<str>"[^"]*") |
    (?P<tag>\#6\.\d+) |
    (?P<num>-?\d+) |
    (?P<ctl>\.(?:size|cbor)) |
    (?P<range>\.\.\.?) |
    (?P<arrow>=>) |
    (?P<name>[A-Za-z_][A-Za-z0-9_\-]*) |
    (?P<punct>[{}\[\]()=:,/?+*])
)''', re.X)


def tokenize(text):
    text = "\n".join(line.split(";", 1)[0] for line in text.splitlines())
    pos, out = 0, []
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise SyntaxError(f"cannot tokenize at {text[pos:pos + 30]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else (None, None)

    def take(self, val=None):
        tok = self.peek()
        if val is not None and tok[1] != val:
            raise SyntaxError(f"expected {val!r}, got {tok}")
        self.i += 1
        return tok

    def rules(self):
        rules = {}
        while self.peek()[0] is not None:
            kind, name = self.take()
            if kind != "name":
                raise SyntaxError(f"rule name expected, got {name!r}")
            self.take("=")
            start = self.i
            try:
                rules[name] = self.type_()
                if self.peek()[0] is not None and self.peek(1)[1] != "=":
                    raise SyntaxError("trailing tokens")
            except SyntaxError:
                if self.t[start][1] != "(":
                    raise
                self.i = start  # a group rule: name = ( entries )
                self.take("(")
                rules[name] = ("group", self.group(")"))
                self.take(")")
        return rules

    def type_(self):
        alts = [self.type1()]
        while self.peek()[1] == "/":
            self.take("/")
            alts.append(self.type1())
        return alts[0] if len(alts) == 1 else ("choice", alts)

    def type1(self):
        t = self.type2()
        if self.peek()[0] == "range":
            self.take()
            t = ("range", t, self.type2())
        while self.peek()[0] == "ctl":
            op = self.take()[1]
            t = (op[1:], t, self.type2())
        return t

    def type2(self):
        kind, val = self.peek()
        if kind == "num":
            self.take()
            return ("lit", int(val))
        if kind == "str":
            self.take()
            return ("lit", val[1:-1])
        if kind == "name":
            self.take()
            return ("ref", val)
        if kind == "tag":
            self.take()
            self.take("(")
            inner = self.type_()
            self.take(")")
            return ("tag", int(val[3:]), inner)
        if val == "{":
            self.take("{")
            g = self.group("}")
            self.take("}")
            return ("map", g)
        if val == "[":
            self.take("[")
            g = self.group("]")
            self.take("]")
            return ("array", g)
        if val == "(":
            self.take("(")
            t = self.type_()
            self.take(")")
            return t
        raise SyntaxError(f"unexpected token {val!r}")

    def group(self, close):
        entries = []
        while self.peek()[1] != close:
            occ = None
            if self.peek()[1] in ("?", "+", "*"):
                occ = self.take()[1]
            key = None
            if self.peek()[0] == "name" and self.peek(1)[1] == ":":
                key = ("bare", self.take()[1])
                self.take(":")
                val = self.type_()
            else:
                t = self.type_()
                if self.peek()[0] == "arrow":
                    self.take()
                    key, val = ("type", t), self.type_()
                else:
                    val = t
            entries.append((occ, key, val))
            if self.peek()[1] == ",":
                self.take(",")
        return entries


PRELUDE = {"uint", "nint", "int", "tstr", "text", "bstr", "bytes", "bool", "nil", "null", "any"}


def parse(path=CDDL):
    rules = Parser(tokenize(pathlib.Path(path).read_text())).rules()
    for name, body in rules.items():  # every reference must resolve
        for ref in _refs(body):
            if ref not in rules and ref not in PRELUDE:
                raise SyntaxError(f"rule {name}: undefined name {ref}")
    return rules


def _refs(t):
    if isinstance(t, tuple):
        if t[0] == "ref":
            yield t[1]
        for x in t[1:]:
            yield from _refs(x)
    elif isinstance(t, list):
        for x in t:
            yield from _refs(x)


class Validator:
    def __init__(self, rules):
        self.r = rules

    def ok(self, v, t):
        k = t[0]
        if k == "lit":
            return type(v) is type(t[1]) and v == t[1] and not isinstance(v, bool)
        if k == "ref":
            n = t[1]
            if n in self.r:
                return self.ok(v, self.r[n])
            return {"uint": lambda: type(v) is int and v >= 0, "nint": lambda: type(v) is int and v < 0,
                    "int": lambda: type(v) is int, "tstr": lambda: isinstance(v, str),
                    "text": lambda: isinstance(v, str), "bstr": lambda: isinstance(v, bytes),
                    "bytes": lambda: isinstance(v, bytes), "bool": lambda: isinstance(v, bool),
                    "nil": lambda: v is None, "null": lambda: v is None, "any": lambda: True}[n]()
        if k == "choice":
            return any(self.ok(v, a) for a in t[1])
        if k == "range":
            lo, hi = t[1][1], t[2][1]
            return type(v) is int and lo <= v <= hi
        if k == "size":
            if not self.ok(v, t[1]):
                return False
            n = len(v) if isinstance(v, bytes) else len(v.encode()) if isinstance(v, str) else None
            spec = t[2]
            if n is None:  # uint .size n: fits in n bytes
                return type(v) is int and 0 <= v < 256 ** spec[1]
            return (spec[1][1] <= n <= spec[2][1]) if spec[0] == "range" else n == spec[1]
        if k == "cbor":
            if not self.ok(v, t[1]):
                return False
            try:
                return self.ok(cbor2.loads(v), t[2])
            except Exception:  # noqa: BLE001
                return False
        if k == "tag":
            return isinstance(v, cbor2.CBORTag) and v.tag == t[1] and self.ok(v.value, t[2])
        if k == "map":
            return isinstance(v, dict) and self.map_ok(v, t[1])
        if k == "array":
            return isinstance(v, (list, tuple)) and self.arr_ok(list(v), t[1])
        raise ValueError(f"unsupported type node {k}")

    def map_ok(self, v, entries):
        remaining = dict(v)
        for occ, key, val in entries:
            if key and key[0] == "bare":
                if key[1] in remaining:
                    if not self.ok(remaining.pop(key[1]), val):
                        return False
                elif occ != "?":
                    return False
            else:
                kt = key[1] if key else ("ref", "any")
                matched = [kk for kk in list(remaining) if self.ok(kk, kt)]
                if occ is None and len(matched) != 1 or occ == "+" and not matched or occ == "?" and len(matched) > 1:
                    return False
                for kk in matched:
                    if not self.ok(remaining.pop(kk), val):
                        return False
        return not remaining

    def arr_ok(self, items, entries):
        i = 0
        for occ, _key, val in entries:
            if occ in ("+", "*"):
                n = 0
                while i < len(items) and self.ok(items[i], val):
                    i, n = i + 1, n + 1
                if occ == "+" and n == 0:
                    return False
            elif occ == "?":
                if i < len(items) and self.ok(items[i], val):
                    i += 1
            else:
                if i >= len(items) or not self.ok(items[i], val):
                    return False
                i += 1
        return i == len(items)

    def check(self, value, rule):
        return self.ok(value, ("ref", rule))


def artifacts(vec):
    """Yield (label, rule, value) for every artifact in a vector."""
    inp = vec.get("inputs", {})
    if "policy" in inp:
        yield "policy", "registration-policy", inp["policy"]
    for si, step in enumerate(inp.get("steps", [])):
        if "policy" in step:
            yield f"step{si}.policy", "registration-policy", step["policy"]
        if step.get("receipt_cose"):
            try:
                yield f"step{si}.receipt", "sar-receipt", cbor2.loads(bytes.fromhex(step["receipt_cose"]))
            except Exception:  # noqa: BLE001
                yield f"step{si}.receipt", "sar-receipt", None
        if step.get("request_cbor"):
            yield f"step{si}.request", "registration-request", cbor2.loads(bytes.fromhex(step["request_cbor"]))
        for label, h in [("proposal", step.get("proposal_cose"))] + \
                [(f"ratification:{j}", x) for j, x in enumerate(step.get("ratifications_cose") or [])]:
            if h is None:
                continue
            try:
                obj = cbor2.loads(bytes.fromhex(h))
            except Exception:  # noqa: BLE001
                obj = None
            yield f"step{si}.{label}", "sar-statement", obj
            if isinstance(obj, cbor2.CBORTag) and isinstance(obj.value, list) and len(obj.value) == 4:
                try:
                    hdr = cbor2.loads(obj.value[0])
                    body = cbor2.loads(obj.value[2])
                except Exception:  # noqa: BLE001
                    continue
                rule = "ratification-body" if hdr.get(3) == "application/sar-ratification+cbor" else "proposal-body"
                yield f"step{si}.{label}.body", rule, body


def expected_artifacts(vec):
    for si, out in enumerate(vec.get("expected", {}).get("steps", [])):
        if isinstance(out, dict) and out.get("entry_cbor"):
            yield f"expected{si}.entry", "registration-entry", cbor2.loads(bytes.fromhex(out["entry_cbor"]))
            yield f"expected{si}.receipt", "sar-receipt", cbor2.loads(bytes.fromhex(out["receipt_cose"]))


def main():
    rules = parse()
    print(f"{CDDL.name}: parsed {len(rules)} rules; all references resolve")
    if "--parse-only" in sys.argv:
        return 0
    v = Validator(rules)
    bad, checked = [], 0
    for path in sorted(VECTORS.glob("*.json")):
        vec = json.loads(path.read_text())
        expect_invalid = set(vec.get("cddl_invalid", []))
        seen_invalid = set()
        for label, rule, value in list(artifacts(vec)) + list(expected_artifacts(vec)):
            checked += 1
            okv = value is not None and v.check(value, rule)
            short = label.split(".", 1)[1] if label.startswith("step") else label
            if not okv:
                seen_invalid.add(short)
            if not okv and short not in expect_invalid and short.split(".")[0] not in expect_invalid:
                bad.append(f"{vec['id']}: {label} does not satisfy {rule}")
        for want in expect_invalid:
            if not any(s == want or s.startswith(want + ".") for s in seen_invalid):
                bad.append(f"{vec['id']}: {want} was expected to violate the CDDL but satisfies it")
    for b in bad:
        print("FAIL", b)
    print(f"artifacts checked: {checked}; CDDL mismatches: {len(bad)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
