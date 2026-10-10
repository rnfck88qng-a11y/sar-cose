"""Render a template by filling {{placeholders}} from results/paper_claims.json.

    python3 tools/render_claims.py TEMPLATE OUTPUT [--claims results/paper_claims.json]

Placeholder syntax: {{dotted.key}} or {{dotted.key|fmt}} where fmt is one of
  n     integer with thousands separator "," (default for ints): 12345 -> 12,345
  raw   str(value) unchanged
  pct   one decimal and no % sign: 96.94 -> 96.9
  f1/f2/f3  fixed decimals
  us    microseconds, one decimal; ms  value given in microseconds rendered in ms with 2 decimals
  words small integer as an English word (zero..twenty), otherwise as n
A key that does not exist, or a placeholder left in the output, is an error (exit 1): nothing in a
rendered document can be typed by hand where a placeholder stands.
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PH = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*(?:\|\s*([a-z0-9]+)\s*)?\}\}")
WORDS = "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen " \
        "seventeen eighteen nineteen twenty".split()


def lookup(claims, key):
    cur = claims
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise KeyError(key)
    return cur


def fmt(value, how):
    if how is None:
        how = "n" if isinstance(value, int) and not isinstance(value, bool) else "raw"
    if how == "raw":
        return str(value)
    if how == "n":
        return f"{int(value):,}"
    if how == "words":
        return WORDS[value] if isinstance(value, int) and 0 <= value < len(WORDS) else f"{int(value):,}"
    if how == "pct":
        return f"{float(value):.1f}"
    if how in ("f1", "f2", "f3"):
        return f"{float(value):.{how[1]}f}"
    if how == "us":
        return f"{float(value):.1f}"
    if how == "ms":
        return f"{float(value) / 1000:.2f}"
    raise ValueError(f"unknown format {how}")


def render(text, claims):
    errors = []

    def sub(m):
        try:
            return fmt(lookup(claims, m.group(1)), m.group(2))
        except (KeyError, ValueError) as e:
            errors.append(f"{m.group(0)}: {e}")
            return m.group(0)

    out = PH.sub(sub, text)
    return out, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("output")
    ap.add_argument("--claims", default=str(ROOT / "results" / "paper_claims.json"))
    a = ap.parse_args()
    text = pathlib.Path(a.template).read_text()
    claims = json.loads(pathlib.Path(a.claims).read_text()) if pathlib.Path(a.claims).exists() else {}
    out, errors = render(text, claims)
    left = PH.findall(out)
    if errors or left:
        for e in errors:
            print("unresolved:", e, file=sys.stderr)
        sys.exit(1)
    pathlib.Path(a.output).write_text(out)
    print(f"rendered {a.output} ({len(PH.findall(text))} placeholders filled)")


if __name__ == "__main__":
    main()
