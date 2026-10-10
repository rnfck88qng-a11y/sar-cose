"""Automated mutation sweep for sar_cose.py (complements the hand-written SAR_MUTANT guards).

Every mutation site found mechanically in the AST is mutated in turn and the full test suite
is run against the mutant. A mutant that leaves the suite green has *survived*: either the
tests miss a behaviour, or the mutation is semantically equivalent (must be argued case by case).

    python3 tools/mutation_sweep.py [--jobs 8] [--json out.json]

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
SRC = ROOT / "sar_cose.py"
SUITE = ["test_sar_conformance", "test_sar_gaps", "test_sar_cose_specific", "test_sar_properties", "test_sar_hardening", "test_sar_cross"]
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


def run_suite(src_text, python, timeout=300):
    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, "sar_cose.py").write_text(src_text)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", SAR_IMPL="sar_cose", SAR_MUTANT="",
                   PYTHONPATH=os.pathsep.join([d, str(ROOT), str(ROOT / "harness")]))
        try:
            r = subprocess.run([python, "-m", "unittest", *SUITE], cwd=d, env=env, capture_output=True,
                               text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "killed(timeout)"
        shutil.rmtree(pathlib.Path(d, ".hypothesis"), ignore_errors=True)
        return "survived" if r.returncode == 0 else "killed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--json")
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    tree = ast.parse(SRC.read_text())
    s = Sites()
    s.visit(copy.deepcopy(tree))
    sites = s.sites
    baseline = run_suite(ast.unparse(tree), args.python)
    if baseline != "survived":
        sys.exit(f"baseline suite fails on the unmutated (unparsed) source: {baseline}")
    results = []
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        futs = {}
        for idx, kind, line, desc in sites:
            text, applied = make_mutant(tree, idx)
            futs[ex.submit(run_suite, text, args.python)] = (idx, kind, line, applied or desc)
        for f in cf.as_completed(futs):
            idx, kind, line, desc = futs[f]
            results.append({"id": idx, "kind": kind, "line": line, "mutation": desc, "result": f.result()})
    results.sort(key=lambda r: r["id"])
    killed = sum(r["result"].startswith("killed") for r in results)
    print(f"mutants: {len(results)}  killed: {killed}  survived: {len(results) - killed}  "
          f"score: {100 * killed / max(1, len(results)):.1f}%")
    for r in results:
        if r["result"] == "survived":
            print(f"  SURVIVED  line {r['line']:4d}  [{r['kind']}] {r['mutation']}")
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
