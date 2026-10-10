# Archived runs

Every run that the paper or `RESULTS.md` cites is archived here as a machine-readable record, so that figures can be traced to the run that produced them.

- `runs/<name>.json` — one record per run, written by `tools/archive_run.py`: the command, environment overrides (`SAR_SEEDS`, `SAR_DEEP`, …), start time (UTC), duration, the 1/5/15-minute load average before and after, the git commit and whether the working tree was dirty, sha256 of each implementation module, Python and library versions, OS, CPU and core count, exit code, pass/fail, and every unittest summary (`Ran N tests` + `OK`/`FAILED`) found in the output.
- `runs/<name>.log` — the complete output of that run (home-directory paths replaced by `~`).
- `sweep_<module>.json` — the classified automated mutation sweep (`tools/mutation_sweep.py --json`): every mutant with its result and, for survivors, `equivalent` plus the argument id in `tools/EQUIVALENT_MUTANTS.md`, or `live`.
- `paper_claims.json` — every number and status that the paper v1.3, `README.md` and `RESULTS.md` state, derived by `tools/make_claims.py` from the records above (never typed by hand). `tools/render_claims.py` fills the `{{placeholders}}` of the templates from it and `tools/check_claims.py` fails if a placeholder is unresolved or a rendered number contradicts it.

Producers: `make_results.sh` (default runs), `tools/run_slow.sh` (deep run, mutation sweeps, repeated benchmarks). A record whose `git_dirty` is true was produced from uncommitted code; the final records of a release must have `git_dirty: false`.
