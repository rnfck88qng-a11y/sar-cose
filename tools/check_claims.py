"""Check that rendered documents agree with results/paper_claims.json.

    python3 tools/check_claims.py FILE [FILE ...] [--claims results/paper_claims.json]

Targets: the rendered paper and README.md. RESULTS.md is raw output (per-seed subtotals) and is not a target.
With no FILE the check fails rather than passing vacuously.

Fails (exit 1) if
  1. any {{placeholder}} is left unresolved, or
  2. a number that appears in a counting context ("N tests", "N of M mutants", "N vectors",
     "N requirements", "N scenarios", "N instants", "N decision pairs", "N disagreements",
     "N survivors", "N MUST", "N registered", "N killed", ...) is neither a value in the claims
     file nor in the short, justified whitelist below.

Text after the heading "Revision Notes (v1.1 → v1.2)" (the quoted history of earlier versions) and
the reference list are not checked, because they describe earlier versions or other documents.
This is a contradiction check, not a proof that every number is a placeholder; the template is the
place where every empirical number is written as a placeholder.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTEXT = re.compile(
    r"(?<![\w.\-§])(?<!RFC )(?<!BCP )(?<!Section )(?<!Sections )(\d{1,3}(?:,\d{3})+|\d+)(?![.\d])"
    r"(?:\s+of\s+(\d{1,3}(?:,\d{3})+|\d+))?\s+"
    r"(?:[A-Za-z\-]+\s+){0,3}?"
    r"(tests?|mutants?|vectors?|requirements?|scenarios?|instants?|decision pairs|disagreements?|survivors?|"
    r"MUSTs?|registered|killed|decisions|artifacts|rules|entries)\b")
# Numbers that legitimately appear in counting contexts but are configuration or history, not results.
WHITELIST = {
    118: "disagreements in the original, unpreserved v1.2 comparison run (history)",
    1000: "Hypothesis examples per property in the deep run (test configuration)",
    16: "threads in the concurrency tests (test configuration)",
    8: "processes in the concurrency tests; 8-byte digest mutant (configuration)",
    13: "leaves of the Merkle test vector (configuration)",
    2000: "operations per benchmark run (configuration)",
    6000: "decisions in the reproduced v1.2 comparison (also a claim value)",
    20: "external audit mutants (also a claim value)",
    7: "survivors of the v1.2 first-round suite among the audit mutants (history)",
}


def leaves(x, out):
    if isinstance(x, dict):
        for v in x.values():
            leaves(v, out)
    elif isinstance(x, list):
        for v in x:
            leaves(v, out)
    elif isinstance(x, bool):
        pass
    elif isinstance(x, int) or isinstance(x, float) and x.is_integer():
        out.add(int(x))  # non-integral floats (timings, loads) never justify an integer count
    return out


def checked_text(text):
    for marker in ("## Revision Notes (v1.1 → v1.2)",):
        if marker in text:
            text = text.split(marker, 1)[0]
    if "\n## References" in text:
        head, tail = text.split("\n## References", 1)
        rest = tail.split("\n---", 1)
        text = head + ("\n" + rest[1] if len(rest) > 1 else "")
    return text


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    cpath = ROOT / "results" / "paper_claims.json"
    if "--claims" in sys.argv:
        cpath = pathlib.Path(sys.argv[sys.argv.index("--claims") + 1])
        args = [a for a in args if a != str(cpath)]
    if not args:
        sys.exit("check_claims: no files given (nothing checked). Intended targets: the rendered paper "
                 "(SARWP_working_paper_v1.3.md) and README.md; RESULTS.md is raw run output with per-seed "
                 "subtotals and is not a target.")
    claims = json.loads(cpath.read_text())
    # counts only: timings, loads and metadata cannot justify a count
    counts = {k: v for k, v in claims.items() if k not in ("bench", "meta", "_sources", "errors")}
    for sect in counts.values():
        if isinstance(sect, dict):
            for k in ("duration_min", "load_1min"):
                sect.pop(k, None)
    allowed = leaves(counts, set()) | set(WHITELIST) | {0}
    bad = []
    checked = 0
    for f in args:
        text = pathlib.Path(f).read_text()
        for m in re.finditer(r"\{\{[^}]*\}\}", text):
            bad.append(f"{f}: unresolved placeholder {m.group(0)}")
        body = checked_text(text)
        for m in CONTEXT.finditer(body):
            for g in (m.group(1), m.group(2)):
                if g is None:
                    continue
                checked += 1
                n = int(g.replace(",", ""))
                if n not in allowed:
                    line = body[:m.start()].count("\n") + 1
                    bad.append(f"{f}:{line}: '{m.group(0)}' — {n} is not a value in {cpath.name}")
    for b in bad:
        print("FAIL", b)
    print(f"numbers in counting contexts checked: {checked}; problems: {len(bad)}")
    print("claims check:", "FAIL" if bad else "PASS")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
