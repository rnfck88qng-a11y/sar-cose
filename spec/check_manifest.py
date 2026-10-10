"""Generate and check the conformance manifest (spec/conformance_manifest.csv and .json).

    python3 spec/check_manifest.py            # regenerate both files, then check
    python3 spec/check_manifest.py --check    # check only; also fails if the files on disk are stale

Sources (nothing in the manifest is typed by hand):
  - requirements, levels and sections: parsed from spec/sar-profile.md ("**SAR-REQ-nnn** (LEVEL)");
  - test vectors per requirement: the "requirements" lists of spec/test-vectors/*.json;
  - CDDL rule and implementation tests: spec/req_map.json;
  - status per implementation: spec/vector_results.json (written by spec/run_vectors.py), or the
    "declared" entry of req_map.json for requirements without vectors (SHOULD/MAY).

Fails (exit 1) if: a MUST/MUST NOT has no vector; a vector cites an unknown requirement; a
requirement is missing from req_map.json or req_map.json names an unknown one; a referenced test
does not exist; a referenced CDDL rule is not defined in spec/sar-profile.cddl; any status is
"fail"; or, with --check, the files on disk differ from the regenerated ones.
"""
import ast
import csv
import io
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import cddl_check  # noqa: E402

IMPLS = ["sar_cose", "sar_indep", "sar_scitt"]
REQ = re.compile(r"^\*\*(SAR-REQ-\d{3})\*\* \((MUST NOT|MUST|SHOULD NOT|SHOULD|MAY)\)")
HEAD = re.compile(r"^(#{2,3}) (\d+(?:\.\d+)?)\.? ")


def requirements():
    reqs, section = {}, None
    for line in (HERE / "sar-profile.md").read_text().splitlines():
        h = HEAD.match(line)
        if h:
            section = h.group(2)
        m = REQ.match(line)
        if m:
            if m.group(1) in reqs:
                raise SystemExit(f"duplicate requirement id {m.group(1)}")
            text = line[m.end():].strip()
            reqs[m.group(1)] = {"level": m.group(2), "section": section, "text": text[:160]}
    return reqs


def test_names():
    names = set()
    files = list(ROOT.glob("test_sar_*.py")) + [ROOT / "harness" / "test_sar_conformance.py"]
    for f in files:
        tree = ast.parse(f.read_text())
        for c in tree.body:
            if isinstance(c, ast.ClassDef):
                for fn in c.body:
                    if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test"):
                        names.add(f"{f.stem}.{c.name}.{fn.name}")
    return names


def build():
    reqs = requirements()
    rmap = {k: v for k, v in json.loads((HERE / "req_map.json").read_text()).items() if not k.startswith("_")}
    vectors = [json.loads(p.read_text()) for p in sorted((HERE / "test-vectors").glob("*.json")) if p.name != "index.json"]
    results = json.loads((HERE / "vector_results.json").read_text())["results"] \
        if (HERE / "vector_results.json").exists() else {}
    rules = cddl_check.parse()
    tests = test_names()
    errors = []
    by_req = {r: [] for r in reqs}
    for v in vectors:
        for r in v["requirements"]:
            if r not in reqs:
                errors.append(f"vector {v['id']} cites unknown requirement {r}")
            else:
                by_req[r].append(v["id"])
    for r in rmap:
        if r not in reqs:
            errors.append(f"req_map.json names unknown requirement {r}")
    rows = []
    for r, info in reqs.items():
        m = rmap.get(r)
        if m is None:
            errors.append(f"{r} missing from req_map.json")
            m = {"cddl": "", "tests": []}
        for t in m["tests"]:
            if t not in tests:
                errors.append(f"{r}: referenced test does not exist: {t}")
        if m.get("cddl") and m["cddl"] not in rules:
            errors.append(f"{r}: CDDL rule {m['cddl']} not defined")
        vids = sorted(by_req[r])
        if info["level"].startswith("MUST") and not vids:
            errors.append(f"{r} ({info['level']}) has no test vector")
        status = {}
        for impl in IMPLS:
            res = results.get(impl)
            if impl in m.get("declared", {}):
                status[impl] = m["declared"][impl]
            elif res is None:
                status[impl] = "not-run"
            else:
                st = [res[v]["status"] for v in vids if v in res]
                if not vids:
                    status[impl] = "no-vectors"
                elif any(s == "fail" for s in st):
                    status[impl] = "fail"
                elif st and all(s == "n/a" for s in st):
                    status[impl] = "not-implemented"
                elif any(s == "pass" for s in st):
                    status[impl] = "pass" + (" (some vectors n/a)" if "n/a" in st else "")
                else:
                    status[impl] = "not-run"
            if status[impl] == "fail" or status[impl].startswith("fail "):
                errors.append(f"{r}: status fail for {impl}")
        rows.append({"requirement": r, "section": info["section"], "level": info["level"], "cddl_rule": m.get("cddl", ""),
                     "test_vectors": vids, "tests": m["tests"], **{f"status_{i}": status[i] for i in IMPLS},
                     "text": info["text"]})
    musts = [x for x in rows if x["level"].startswith("MUST")]
    summary = {"requirements": len(rows), "must": len(musts),
               "must_with_vectors": sum(1 for x in musts if x["test_vectors"]),
               "should": sum(1 for x in rows if x["level"].startswith("SHOULD")),
               "may": sum(1 for x in rows if x["level"] == "MAY"),
               "vectors": len(vectors),
               "status": {i: {} for i in IMPLS}}
    for i in IMPLS:
        for x in rows:
            key = x[f"status_{i}"].split(" ")[0]
            summary["status"][i][key] = summary["status"][i].get(key, 0) + 1
    return rows, summary, errors


def render(rows, summary):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    cols = ["requirement", "section", "level", "cddl_rule", "test_vectors", "tests"] + [f"status_{i}" for i in IMPLS]
    w.writerow(cols)
    for x in rows:
        w.writerow([";".join(x[c]) if isinstance(x[c], list) else x[c] for c in cols])
    js = json.dumps({"summary": summary, "requirements": rows}, indent=1, sort_keys=True) + "\n"
    return buf.getvalue(), js


def main():
    rows, summary, errors = build()
    csv_text, json_text = render(rows, summary)
    if "--check" in sys.argv:
        for name, text in (("conformance_manifest.csv", csv_text), ("conformance_manifest.json", json_text)):
            p = HERE / name
            if not p.exists() or p.read_text() != text:
                errors.append(f"{name} is stale: run spec/check_manifest.py to regenerate")
    else:
        (HERE / "conformance_manifest.csv").write_text(csv_text)
        (HERE / "conformance_manifest.json").write_text(json_text)
    print(f"requirements: {summary['requirements']} (MUST {summary['must']}, SHOULD {summary['should']}, "
          f"MAY {summary['may']}); MUSTs with at least one vector: {summary['must_with_vectors']}/{summary['must']}; "
          f"vectors: {summary['vectors']}")
    for i in IMPLS:
        print(f"  {i}: " + ", ".join(f"{k} {v}" for k, v in sorted(summary["status"][i].items())))
    for e in errors:
        print("FAIL", e)
    print("manifest check:", "FAIL" if errors else "PASS")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
