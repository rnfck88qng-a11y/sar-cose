"""Render README.md from README.template.md with results/paper_claims.json and check it.

    python3 tools/render_docs.py [--paper PATH_TO_TEMPLATE OUTPUT]

With --paper, the paper template is rendered too (the paper lives outside this repository).
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable


def run(*a):
    r = subprocess.run([PY, "-B", *a], cwd=ROOT)
    if r.returncode:
        sys.exit(r.returncode)


def main():
    run("tools/render_claims.py", "README.template.md", "README.md")
    targets = ["README.md"]
    if "--paper" in sys.argv:
        i = sys.argv.index("--paper")
        tpl, out = sys.argv[i + 1], sys.argv[i + 2]
        run("tools/render_claims.py", tpl, out)
        targets.append(out)
    run("tools/check_claims.py", *targets)


if __name__ == "__main__":
    main()
