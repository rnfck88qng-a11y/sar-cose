"""Automated mutation sweep (complements the hand-written SAR_MUTANT guards).

Every mutation site found mechanically in the AST of one module (default sar_cose.py; also
sar_scitt.py) is mutated in turn and the full test suite is run against the mutant. A mutant that
leaves the suite green has *survived*: either the tests miss a behaviour (a **live** survivor), or
the mutation is decision-equivalent. Each survivor is classified mechanically: it is `equivalent`
only if it matches an entry of tools/equivalent_mutants.json (module, kind, mutation text and the
exact source line), whose `argument` id points to a written argument in
tools/EQUIVALENT_MUTANTS.md; every other survivor is `live`.

    python3 tools/mutation_sweep.py [--module sar_cose.py] [--jobs 8] [--json out.json] [--fail-on-live]

Mutation operators:
  cmp   swap comparison operators (< <= > >= == != in / not in, is / is not)
  bool  and <-> or
  not   remove a `not`
  if    negate an `if` / `while` condition
  const int c -> c+1 / c-1 (c != 0 -> 0), True <-> False
  ret   `return True` <-> `return False`
  del   delete one statement inside a function body (replaced by `pass`)
Code that only exists for testing (MUT checks, __del__, close, the MUTANTS list) is skipped.
"""
import argparse
import ast
import concurrent.futures as cf
import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE = ["test_sar_conformance", "test_sar_gaps", "test_sar_cose_specific", "test_sar_properties", "test_sar_hardening",
         "test_sar_cross"]
SUITES = {"sar_cose.py": SUITE + ["test_sar_scitt"], "sar_scitt.py": ["test_sar_scitt"]}
EQUIV = ROOT / "tools" / "equivalent_mutants.json"
CMP_SWAP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq,
            ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
SKIP_FUNCS = {"__del__", "close"}


def _mentions_mut(node):
    return any(isinstance(n, ast.Name) and n.id == "MUT" for n in ast.walk(node))


def _is_mut_hook(st):
    """`if MUT == "...":` blocks exist only to implement the hand-written mutants; mutating them
    tests the test hooks, not the implementation."""
    return isinstance(st, ast.If) and isinstance(st.test, ast.Compare) and _mentions_mut(st.test) \
        and all(not isinstance(n, ast.Compare) or _mentions_mut(n) for n in ast.walk(st.test))


class Sites(ast.NodeVisitor):
    """Collect (index, kind, lineno, description) for every mutation site."""

    def __init__(self):
        self.sites, self.func = [], None

    def add(self, node, kind, desc, extra=None):
        self.sites.append((len(self.sites), kind, getattr(node, "lineno", 0), desc))

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Name) and t.id == "MUTANTS" for t in node.targets):
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name in SKIP_FUNCS:
            return
        prev, self.func = self.func, node.name
        for st in node.body:
            if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)) and not _is_mut_hook(st):
                self.add(st, "del", f"delete statement in {node.name}")
        self.generic_visit(node)
        self.func = prev

    def visit_Compare(self, node):
        if self.func and not _mentions_mut(node):
            for i, op in enumerate(node.ops):
                if type(op) in CMP_SWAP:
                    self.add(node, "cmp", f"{type(op).__name__}->{CMP_SWAP[type(op)].__name__} (op {i}) in {self.func}", i)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        if self.func and not _mentions_mut(node):
            self.add(node, "bool", f"{type(node.op).__name__} swap in {self.func}")
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if self.func and isinstance(node.op, ast.Not) and not _mentions_mut(node):
            self.add(node, "not", f"remove not in {self.func}")
        self.generic_visit(node)

    def visit_If(self, node):
        if _is_mut_hook(node):
            for st in node.orelse:  # skip the hook body, keep any else branch
                self.visit(st)
            return
        if self.func and not _mentions_mut(node.test):
            self.add(node, "if", f"negate if in {self.func}")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if self.func and isinstance(node.value, bool):
            self.add(node, "const", f"{node.value}->{not node.value} in {self.func}")
        elif self.func and isinstance(node.value, int):
            self.add(node, "const", f"{node.value}->{node.value + 1 if node.value == 0 else 0} in {self.func}")
        self.generic_visit(node)

    def visit_Return(self, node):
        if self.func and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
            self.add(node, "ret", f"return {node.value.value}->{not node.value.value} in {self.func}")
        self.generic_visit(node)


class Mutate(Sites):
    """Re-walk in the same order; apply the mutation whose index == target."""

    def __init__(self, target):
        super().__init__()
        self.target, self.applied = target, None

    def add(self, node, kind, desc, extra=None):
        idx = len(self.sites)
        super().add(node, kind, desc)
        if idx != self.target:
            return
        self.applied = desc
        if kind == "cmp":
            node.ops[extra] = CMP_SWAP[type(node.ops[extra])]()
        elif kind == "bool":
            node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        elif kind == "not":
            node.__class__, node.op = ast.Call, None  # marker; replaced below
        elif kind == "if":
            node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        elif kind == "const":
            node.value = (not node.value) if isinstance(node.value, bool) else (node.value + 1 if node.value == 0 else 0)
        elif kind == "ret":
            node.value.value = not node.value.value
        elif kind == "del":
            self.deleted = node


class _ApplyStructural(ast.NodeTransformer):
    def __init__(self, deleted):
        self.deleted = deleted

    def generic_visit(self, node):
        super().generic_visit(node)
        for field, value in ast.iter_fields(node):
            if isinstance(value, list) and self.deleted in value:
                setattr(node, field, [ast.Pass() if v is self.deleted else v for v in value])
        return node

    def visit_Call(self, node):
        if getattr(node, "op", 1) is None and hasattr(node, "operand"):  # 'not' removal marker
            return self.visit(node.operand)
        return self.generic_visit(node)


def make_mutant(tree, idx):
    t = copy.deepcopy(tree)
    m = Mutate(idx)
    m.deleted = None
    m.visit(t)
    t = _ApplyStructural(m.deleted).visit(t)
    ast.fix_missing_locations(t)
    return ast.unparse(t), m.applied


def run_suite(src_text, python, module="sar_cose.py", suite=SUITE, timeout=600):
    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, module).write_text(src_text)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", SAR_IMPL="sar_cose", SAR_MUTANT="",
                   PYTHONPATH=os.pathsep.join([d, str(ROOT), str(ROOT / "harness")]))
        try:
            r = subprocess.run([python, "-m", "unittest", *suite], cwd=d, env=env, capture_output=True,
                               text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "killed(timeout)"
        shutil.rmtree(pathlib.Path(d, ".hypothesis"), ignore_errors=True)
        return "survived" if r.returncode == 0 else "killed"


def load_equivalences():
    if not EQUIV.exists():
        return []
    return json.loads(EQUIV.read_text())["equivalent"]


def classify(results, module, src_lines, equivs):
    """killed / equivalent (with argument id) / live, by exact match on module, kind, mutation
    text and the stripped source line of the mutated node."""
    for r in results:
        r["source_line"] = src_lines[r["line"] - 1].strip() if 0 < r["line"] <= len(src_lines) else ""
        if r["result"].startswith("killed"):
            r["classification"], r["argument"] = "killed", None
            continue
        match = [e for e in equivs if e["module"] == module and e["kind"] == r["kind"]
                 and e["mutation"] == r["mutation"] and e["source_line"] == r["source_line"]]
        r["classification"] = "equivalent" if match else "live"
        r["argument"] = match[0]["argument"] if match else None
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default="sar_cose.py")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--json")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--fail-on-live", action="store_true")
    ap.add_argument("--limit", type=int, help="only the first N sites (smoke test)")
    args = ap.parse_args()
    module = args.module
    suite = SUITES.get(module, SUITE)
    suite = [t for t in suite if (ROOT / f"{t}.py").exists() or (ROOT / "harness" / f"{t}.py").exists()]
    src_text = (ROOT / module).read_text()
    tree = ast.parse(src_text)
    s = Sites()
    s.visit(copy.deepcopy(tree))
    sites = s.sites[: args.limit] if args.limit else s.sites
    baseline = run_suite(ast.unparse(tree), args.python, module, suite)
    if baseline != "survived":
        sys.exit(f"baseline suite fails on the unmutated (unparsed) source: {baseline}")
    results = []
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        futs = {}
        for idx, kind, line, desc in sites:
            text, applied = make_mutant(tree, idx)
            futs[ex.submit(run_suite, text, args.python, module, suite)] = (idx, kind, line, applied or desc)
        for f in cf.as_completed(futs):
            idx, kind, line, desc = futs[f]
            results.append({"id": idx, "kind": kind, "line": line, "mutation": desc, "result": f.result()})
    results.sort(key=lambda r: r["id"])
    classify(results, module, src_text.splitlines(), load_equivalences())
    killed = sum(r["classification"] == "killed" for r in results)
    equiv = [r for r in results if r["classification"] == "equivalent"]
    live = [r for r in results if r["classification"] == "live"]
    print(f"module: {module}  suite: {' '.join(suite)}")
    print(f"mutants: {len(results)}  killed: {killed}  survived: {len(results) - killed}  "
          f"score: {100 * killed / max(1, len(results)):.1f}%")
    print(f"survivors classified: equivalent: {len(equiv)}  live: {len(live)}")
    for r in results:
        if r["classification"] != "killed":
            tag = r["argument"] if r["classification"] == "equivalent" else "LIVE"
            print(f"  SURVIVED  {tag:6s} line {r['line']:4d}  [{r['kind']}] {r['mutation']}  | {r['source_line'][:80]}")
    if args.json:
        summary = {"module": module, "suite": suite, "total": len(results), "killed": killed,
                   "survived": len(results) - killed, "equivalent": len(equiv), "live": len(live),
                   "score_percent": round(100 * killed / max(1, len(results)), 1),
                   "module_sha256": __import__("hashlib").sha256(src_text.encode()).hexdigest(),
                   "mutants": results}
        pathlib.Path(args.json).write_text(json.dumps(summary, indent=1) + "\n")
    if args.fail_on_live and live:
        sys.exit(1)


if __name__ == "__main__":
    main()
