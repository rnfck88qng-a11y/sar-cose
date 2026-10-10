"""Derive results/paper_claims.json from the archived runs in results/ (never from hand-typed numbers).

    python3 tools/make_claims.py [--allow-missing]

Inputs: results/runs/<name>.json/.log written by tools/archive_run.py (names: tests, hand_mutants,
audit_mutants, concurrency, stub_gaps, blind_diff, vectors, manifest, cddl, vectors_regen,
vectors_vs_mutants, deep, sweep_sar_cose, sweep_sar_scitt, bench_1..bench_5), results/sweep_*.json,
spec/conformance_manifest.json, spec/vector_results.json, spec/test-vectors/, spec/ISSUES.md, and
the v1.2 figures from RESULTS.md at commit f9d968c (git show). Every value records where it came from
in claims["_sources"]. Fails (exit 1) if a required run is missing or failed, unless --allow-missing.
"""
import json
import pathlib
import re
import statistics
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNS = ROOT / "results" / "runs"
V12 = "f9d968c"
REQUIRED = ["tests", "hand_mutants", "audit_mutants", "concurrency", "blind_diff", "vectors", "manifest", "cddl",
            "vectors_regen", "vectors_vs_mutants", "deep", "sweep_sar_cose", "sweep_sar_scitt"] + \
           [f"bench_{i}" for i in range(1, 6)]
ERR = []


def run(name):
    j, lg = RUNS / f"{name}.json", RUNS / f"{name}.log"
    if not j.exists():
        ERR.append(f"missing run {name}")
        return None, ""
    rec = json.loads(j.read_text())
    if not rec["passed"]:
        ERR.append(f"run {name} did not pass (exit {rec['exit_code']})")
    return rec, lg.read_text() if lg.exists() else ""


def ints(pattern, text, cast=int):
    return [tuple(cast(x) for x in m.groups()) for m in re.finditer(pattern, text)]


def stats(log):
    """Statistics printed by the randomized tests (default or deep run)."""
    out = {}
    eq = ints(r"gate/offline equivalence seed=\d+: (\d+) scenarios, (\d+) instants \((\d+) allowed\)", log)
    out["equiv"] = {"seeds": len(eq), "scenarios": sum(x[0] for x in eq), "instants": sum(x[1] for x in eq),
                    "allowed": sum(x[2] for x in eq)}
    dif = ints(r"differential seed=\d+: (\d+) allowed \(replay-relevant\), (\d+) denied", log)
    out["random"] = {"seeds": len(dif), "scenarios": sum(a + b for a, b in dif), "allowed": sum(a for a, _ in dif),
                     "denied": sum(b for _, b in dif)}
    sf = re.findall(r"single-fault seed=\d+: ([^\n]*?allowed)\s*(?:\n|$)", log)
    total = free = 0
    types = set()
    for line in sf:
        for name, a, n in re.findall(r"(\w+)=(\d+)/(\d+) allowed", line):
            total += int(n)
            if name == "none":
                free += int(a)
                if int(a) != int(n):
                    ERR.append("a fault-free scenario was denied")
            else:
                types.add(name)
                if int(a):
                    ERR.append(f"fault {name} allowed")
    out["fault"] = {"seeds": len(sf), "scenarios": total, "fault_free_allowed": free, "fault_types": len(types)}
    both = ints(r"both implementations, seed=\d+: (\d+) scenarios, (\d+) instants each", log)
    out["equiv_both"] = {"seeds": len(both), "scenarios": sum(x[0] for x in both),
                         "instants_each": sum(x[1] for x in both)}
    cr = ints(r"cross (?:random|fault)/seed\d+: (\d+) decision pairs, (\d+) allowed, (\d+) disagreements", log)
    out["cross"] = {"runs": len(cr), "pairs": sum(x[0] for x in cr), "allowed": sum(x[1] for x in cr),
                    "disagreements": sum(x[2] for x in cr)}
    sc = ints(r"scitt differential seed=\d+: (\d+) scenarios, (\d+) instants \((\d+) registered\), (\d+) disagreements",
              log)
    out["scitt_diff"] = {"seeds": len(sc), "scenarios": sum(x[0] for x in sc), "instants": sum(x[1] for x in sc),
                         "registered": sum(x[2] for x in sc), "disagreements": sum(x[3] for x in sc)}
    out["replay_relevant"] = out["random"]["allowed"] + out["fault"]["fault_free_allowed"]
    for k in ("equiv", "random", "equiv_both", "cross", "scitt_diff"):
        if out[k].get("disagreements"):
            ERR.append(f"{k}: disagreements")
    return out


def by_module(log):
    first = log.split("== second implementation", 1)[0]
    names = set(re.findall(r"^test\w* \(((test_sar_\w+)\.\w+\.\w+)\)", first, re.M))
    mods = {}
    for _full, mod in names:
        mods[mod] = mods.get(mod, 0) + 1
    return mods


def bench(names):
    rows, loads = {}, []
    for n in names:
        rec, log = run(n)
        if rec is None:
            continue
        loads.append(rec["load_avg_before"][0])
        for name, med, p99 in re.findall(r"^(\S.{0,40}?)\s{2,}([\d.]+)\s+([\d.]+)\s*$", log, re.M):
            key = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
            rows.setdefault(key, {"name": name.strip(), "medians_us": []})["medians_us"].append(float(med))
    for r in rows.values():
        r["min_us"], r["max_us"] = min(r["medians_us"]), max(r["medians_us"])
        r["min_ms"], r["max_ms"] = round(r["min_us"] / 1000, 2), round(r["max_us"] / 1000, 2)
        r["median_of_medians_us"] = statistics.median(r["medians_us"])
        a, b = f"{r['min_us'] / 1000:.2f}", f"{r['max_us'] / 1000:.2f}"
        r["range_ms"] = a if a == b else f"{a}–{b}"
        a, b = f"{r['min_us']:.1f}", f"{r['max_us']:.1f}"
        r["range_us"] = a if a == b else f"{a}–{b}"
    return {"runs": len(loads), "load_1min_min": min(loads) if loads else None,
            "load_1min_max": max(loads) if loads else None, "rows": rows}


def v12():
    try:
        txt = subprocess.run(["git", "-C", str(ROOT), "show", f"{V12}:RESULTS.md"], capture_output=True, text=True,
                             check=True).stdout
    except subprocess.CalledProcessError:
        ERR.append("cannot read v1.2 RESULTS.md")
        return {}
    sw = re.search(r"mutants: (\d+)\s+killed: (\d+)\s+survived: (\d+)\s+score: ([\d.]+)%", txt)
    return {"tests": int(re.search(r"^Ran (\d+) tests", txt, re.M).group(1)),
            "hand_mutants": int(re.search(r"mutants killed: \d+/(\d+)", txt).group(1)),
            "audit_mutants": int(re.search(r"audit mutants killed: \d+/(\d+)", txt).group(1)),
            "sweep_total": int(sw.group(1)), "sweep_killed": int(sw.group(2)), "sweep_survived": int(sw.group(3)),
            "sweep_score": float(sw.group(4)),
            "blind_disagreements": int(re.search(r"^disagreements: (\d+)", txt, re.M).group(1)),
            "source": f"git show {V12}:RESULTS.md"}


def main():
    c, src = {}, {}
    rec, log = run("tests")
    if rec:
        blocks = rec["unittest"]
        c["tests"] = {"reference_suite": blocks[0]["ran"], "all_ok": all(b["ok"] for b in blocks),
                      "by_module": by_module(log), "blocks": [b["ran"] for b in blocks]}
        names = ["reference_suite", "indep_harness", "indep_own", "blind_harness", "blind_own", "indep_scitt_own"]
        for n, b in zip(names, blocks):
            c["tests"][n] = b["ran"]
        bm = c["tests"]["by_module"]
        c["tests"]["reference_core"] = sum(v for k, v in bm.items() if k != "test_sar_scitt")
        c["tests"]["scitt"] = bm.get("test_sar_scitt", 0)
        if sum(bm.values()) != blocks[0]["ran"]:
            ERR.append(f"per-module test counts {sum(bm.values())} do not add up to {blocks[0]['ran']}")
        c["tests"]["total_all_suites"] = sum(b["ran"] for b in blocks)
        c["default"] = stats(log)
        c["meta"] = {"commit": rec["git_commit"], "commit_short": (rec["git_commit"] or "")[:7],
                     "date": rec["started_utc"][:10], "python": rec["environment"]["python"],
                     "cpu": rec["environment"]["cpu"], "os": rec["environment"]["os"],
                     "cores": rec["environment"]["logical_cpus"], "libs": rec["environment"]["libs"]}
        src["tests"] = "results/runs/tests.json"
    rec, log = run("deep")
    if rec:
        c["deep"] = stats(log)
        c["deep"]["seeds_extra"] = rec["seeds"]["SAR_SEEDS"]
        sd = rec["seeds"]["SAR_SEEDS"].split(",")
        c["deep"]["seeds_extra_text"] = ", ".join(sd[:-1]) + " and " + sd[-1] if len(sd) > 1 else sd[0]
        c["deep"]["tests"] = rec["unittest"][0]["ran"] if rec["unittest"] else None
        c["deep"]["duration_min"] = round(rec["duration_s"] / 60, 1)
        c["deep"]["load_1min"] = rec["load_avg_before"][0]
    rec, log = run("hand_mutants")
    if rec:
        k, t = map(int, re.search(r"mutants killed: (\d+)/(\d+)", log).groups())
        import importlib
        sys.path.insert(0, str(ROOT))
        core, scitt = importlib.import_module("sar_cose").MUTANTS, importlib.import_module("sar_scitt").MUTANTS
        killed = set(re.findall(r"PASS mutant (\S+) killed", log))
        c["mutants"] = {"hand": {"total": t, "killed": k, "core_total": len(core),
                                 "core_killed": len(killed & set(core)), "scitt_total": len(scitt),
                                 "scitt_killed": len(killed & set(scitt))}}
    rec, log = run("audit_mutants")
    if rec:
        k, t = map(int, re.search(r"audit mutants killed: (\d+)/(\d+)", log).groups())
        c.setdefault("mutants", {})["audit"] = {"total": t, "killed": k}
    rec, log = run("vectors_vs_mutants")
    if rec:
        d, t = map(int, re.search(r"detected by the vectors: (\d+)/(\d+)", log).groups())
        nd = re.findall(r"NOT-DETECTED (\S+)", log)
        c.setdefault("mutants", {})["vectors_detect"] = {"detected": d, "total": t, "not_detected": nd,
                                                          "not_detected_count": len(nd)}
    c["sweep"] = {}
    for mod in ("sar_cose", "sar_scitt", "sar_scitt_first"):
        p = ROOT / "results" / f"sweep_{mod}.json"
        if p.exists():
            d = json.loads(p.read_text())
            c["sweep"][mod] = {k: d[k] for k in ("total", "killed", "survived", "equivalent", "live", "score_percent")}
            c["sweep"][mod]["arguments"] = len({m["argument"] for m in d["mutants"] if m.get("argument")})
        elif mod != "sar_scitt_first":
            ERR.append(f"missing results/sweep_{mod}.json")
    for mod in ("sar_cose", "sar_scitt"):
        run(f"sweep_{mod}")
    rec, log = run("vectors")
    vr = json.loads((ROOT / "spec" / "vector_results.json").read_text())
    kinds = {}
    for p in (ROOT / "spec" / "test-vectors").glob("*.json"):
        if p.name != "index.json":
            v = json.loads(p.read_text())
            kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
    sc = [json.loads(p.read_text()) for p in (ROOT / "spec" / "test-vectors").glob("sc-*.json")]
    impl = {n: {("na" if k == "n/a" else k): v for k, v in cnt.items()} for n, cnt in vr["counts"].items()}
    c["vectors"] = {"total": vr["vectors"], "by_kind": kinds, "impl": impl,
                    "core": kinds.get("encoding", 0) + kinds.get("decoding", 0) + kinds.get("decision", 0),
                    "scitt_all": kinds.get("scitt", 0) + kinds.get("registration", 0) + kinds.get("merkle", 0)}
    man = json.loads((ROOT / "spec" / "conformance_manifest.json").read_text())["summary"]
    c["spec"] = dict(man)
    c["spec"]["issues"] = len(re.findall(r"^### ISS-\d+", (ROOT / "spec" / "ISSUES.md").read_text(), re.M))
    c["spec"]["issues_step2"] = len(re.findall(r"^### ISS-0\d\d", (ROOT / "spec" / "ISSUES.md").read_text(), re.M))
    c["spec"]["issues_blind_scitt"] = len(re.findall(r"^### ISS-1(?:1[1-9]|20)", (ROOT / "spec" / "ISSUES.md").read_text(), re.M))
    run("manifest")
    rec, log = run("cddl")
    if rec:
        r, a, m = map(int, re.search(r"parsed (\d+) rules.*?artifacts checked: (\d+); CDDL mismatches: (\d+)", log,
                                      re.S).groups())
        c["cddl"] = {"rules": r, "artifacts": a, "mismatches": m}
    run("vectors_regen")
    sc_deny = sum(1 for v in sc if any(s["decision"] == "DENY" for s in v["expected"]["steps"]))
    c["scitt"] = {"sc_vectors": len(sc), "sc_deny_vectors": sc_deny, "sc_allow_only_vectors": len(sc) - sc_deny,
                  "registration_vectors": kinds.get("registration", 0), "merkle_vectors": kinds.get("merkle", 0),
                  "implementations": 2 if "sar_indep_scitt" in vr["counts"] else 1}
    rec, log = run("concurrency")
    if rec:
        t = re.search(r"threads, fixed code: (\d+)/(\d+)", log).groups()
        p = re.search(r"processes, fixed code: (\d+)/(\d+)", log).groups()
        m = re.search(r"deferred_tx mutant: killed (\d+)/(\d+)", log).groups()
        c["concurrency"] = {"threads_ok": int(t[0]), "threads_runs": int(t[1]), "processes_ok": int(p[0]),
                            "processes_runs": int(p[1]), "deferred_killed": int(m[0]), "deferred_runs": int(m[1])}
    rec, log = run("blind_diff")
    if rec:
        c["blind_diff"] = {"decisions": int(re.search(r"decisions compared: (\d+)", log).group(1)),
                           "disagreements": int(re.search(r"^disagreements: (\d+)", log, re.M).group(1))}
    c["bench"] = bench([f"bench_{i}" for i in range(1, 6)])
    c["history"] = {"v1_2": v12()}
    c["status"] = {"scitt": "implemented and empirically verified (reference sar_scitt.py; second implementation "
                            "independent/scitt written blind from the profile)" if c["scitt"]["implementations"] == 2
                   else "implemented in the reference implementation only"}
    c["errors"] = list(ERR)
    c["_sources"] = {"runs": sorted(p.name for p in RUNS.glob("*.json")), **src}
    out = ROOT / "results" / "paper_claims.json"
    out.write_text(json.dumps(c, indent=1, sort_keys=True) + "\n")
    print(f"wrote {out.relative_to(ROOT)}; problems: {len(ERR)}")
    for e in ERR:
        print("  ", e)
    sys.exit(1 if ERR and "--allow-missing" not in sys.argv else 0)


if __name__ == "__main__":
    main()
