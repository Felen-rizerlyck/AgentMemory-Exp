# fix-retest-2026-11-10

Reproduction artifacts for `docs/RUNTIME_MEMORY_FIX_AND_RETEST_PLAN_2026-11-10.md`.

- Commit under test: `2b933ce` (parent `f00b1de`)
- All commands were run from the repository root unless noted.

## Layout

| Path | Content |
|---|---|
| `BASELINE.md` | commit, Python, working tree, fixed areas |
| `SUMMARY.md` | R1–R7 verdict, metrics, limitations |
| `results.json` | machine-readable R1–R7 results and probe summary |
| `step0/unittest.log` | R1: 92 tests, exit 0 |
| `probe-01` … `probe-10/` | R2–R4: 10 × `python sim/concurrency.py` (append / postflight / partial / crash) |
| `probes/summary.json` | per-probe aggregate |
| `simple/` | R5: T0–T8 simple functional archive |
| `step6/` | R6: CLI check/report/brief/state on a temporary root |
| `step7/` | R7: `git diff --check` / `git status --short` snapshots |

## Reproduce

```powershell
cd runtime_memory
python -m unittest discover -s tests

for ($i = 1; $i -le 10; $i++) {
  python sim/concurrency.py --run-id "fix-retest-probe-$i" --out "sim/runs/fix-retest-2026-11-10/probe-$i" --force
}

python runtime_memory/sim/simple_guide_2026-11-10.py   # from repo root; R5
```

All concurrency probes were run with temporary data directories; no real tools,
network or LLM were used.
