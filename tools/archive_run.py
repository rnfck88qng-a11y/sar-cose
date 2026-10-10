"""Run one command and archive it as a machine-readable record in results/runs/.

    python3 tools/archive_run.py NAME [--env K=V ...] [--expect-fail] -- COMMAND [ARGS...]

Writes results/runs/NAME.json and results/runs/NAME.log (the combined stdout/stderr). The JSON
records the command, the environment overrides (including SAR_SEEDS / SAR_DEEP), the git commit
and whether the working tree was dirty, sha256 of the implementation modules, the Python and
library versions, OS, CPU, the 1/5/15-minute load averages before and after, wall-clock duration,
the exit code, pass/fail, and every unittest summary block found in the output ("Ran N tests" +
OK/FAILED). Home-directory paths are replaced by "~" in both files. Re-running a NAME overwrites
its record (git history keeps earlier ones). Exit code is that of the command.
"""
import argparse
import datetime
import hashlib
import importlib.metadata as md
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNS = ROOT / "results" / "runs"
HOME = os.path.expanduser("~")
MODULES = ["sar_cose.py", "sar_scitt.py", "independent/sar_indep.py", "independent/original_blind/sar_indep.py"]
LIBS = ["cbor2", "cryptography", "pycose", "hypothesis", "coverage"]


def sanitize(s):
    return s.replace(HOME, "~")


def git(*args):
    try:
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def cpu_brand():
    try:
        return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip() \
            or platform.processor()
    except FileNotFoundError:
        return platform.processor()


def environment(python):
    """Versions of the interpreter that runs the command (not necessarily this one)."""
    code = ("import json,platform,importlib.metadata as m\n"
            "v={}\n"
            f"for n in {LIBS!r}:\n"
            "    try: v[n]=m.version(n)\n"
            "    except Exception: v[n]=None\n"
            "print(json.dumps({'python':platform.python_version(),'implementation':platform.python_implementation(),'libs':v}))")
    try:
        info = json.loads(subprocess.run([python, "-c", code], capture_output=True, text=True, check=True).stdout)
    except Exception:  # noqa: BLE001
        info = {"python": None, "libs": {}}
    info.update({"os": f"{platform.system()} {platform.release()}", "machine": platform.machine(), "cpu": cpu_brand(),
                 "logical_cpus": os.cpu_count()})
    return info


def unittest_blocks(text):
    blocks = []
    for m in re.finditer(r"^Ran (\d+) tests? in ([\d.]+)s\s*\n\s*\n?(OK.*|FAILED.*)$", text, re.M):
        blocks.append({"ran": int(m.group(1)), "seconds": float(m.group(2)), "result": m.group(3).strip(),
                       "ok": m.group(3).startswith("OK")})
    return blocks


def main():
    argv = sys.argv[1:]
    if "--" not in argv:
        sys.exit("usage: archive_run.py NAME [--env K=V ...] [--expect-fail] -- COMMAND ...")
    i = argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--expect-fail", action="store_true", help="the command is expected to exit non-zero")
    ap.add_argument("--python", default=os.environ.get("PYTHON", sys.executable))
    args = ap.parse_args(argv[:i])
    cmd = argv[i + 1:]
    overrides = dict(kv.split("=", 1) for kv in args.env)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", **overrides)
    RUNS.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc)
    load_before = os.getloadavg()
    t0 = time.monotonic()
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    duration = time.monotonic() - t0
    load_after = os.getloadavg()
    out = sanitize(p.stdout)
    status = git("status", "--porcelain")
    rec = {
        "name": args.name,
        "command": [sanitize(c) for c in cmd],
        "env_overrides": {k: sanitize(v) for k, v in overrides.items()},
        "seeds": {"SAR_SEEDS": env.get("SAR_SEEDS", ""), "SAR_DEEP": env.get("SAR_DEEP", ""),
                  "note": "fixed default seeds are hard-coded in the test modules; SAR_SEEDS adds seeds"},
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": round(duration, 2),
        "load_avg_before": [round(x, 2) for x in load_before],
        "load_avg_after": [round(x, 2) for x in load_after],
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(status) if status is not None else None,
        "module_sha256": {m: hashlib.sha256((ROOT / m).read_bytes()).hexdigest()
                          for m in MODULES if (ROOT / m).exists()},
        "environment": environment(args.python),
        "exit_code": p.returncode,
        "expect_fail": args.expect_fail,
        "passed": (p.returncode != 0) if args.expect_fail else (p.returncode == 0),
        "unittest": unittest_blocks(out),
        "log": f"results/runs/{args.name}.log",
    }
    (RUNS / f"{args.name}.log").write_text(out)
    (RUNS / f"{args.name}.json").write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n")
    sys.stdout.write(out)
    print(f"[archived results/runs/{args.name}.json: exit={p.returncode} passed={rec['passed']} "
          f"duration={rec['duration_s']}s load={rec['load_avg_before']}]")
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
