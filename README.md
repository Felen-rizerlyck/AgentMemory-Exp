# Agent Memory Prototypes

This repository contains two separate memory prototypes for security agents:

- **Case memory** in [`demo/`](demo/README.md): recalls previously reviewed attack patterns and their evidence.
- **Runtime memory** in [`runtime_memory/`](runtime_memory/README.md): records tool and service failures, applies retry windows, and gates later calls.

They have separate code, data, and lifecycles. Runtime failures are not attack cases, and case-memory records do not control tool availability.

## Project layout

| Path | Role | Status |
|---|---|---|
| `demo/` | Standalone case-memory application: ingest, retrieve, audit, review, and controlled memory updates | Main case-memory implementation |
| `runtime_memory/` | Operational/tool memory library, CLI, policy, simulation, and local HTTP tool harness | Main runtime-memory implementation |
| `src/`, root `scripts/`, root `tests/`, `data/` | Earlier root-level case-memory prototype and its reproducibility assets | Legacy reference; retained for comparison, not the default development target |
| `eval/`, `dataset/` | Evaluation data, generators, fixtures, and reports | Research/evaluation assets |
| `docs/` | Architecture, review, implementation plans, and test guides | Shared project documentation |
| `skills/` | Agent-facing case-memory skill and references | Operational guidance |
| `history/` | Archived implementations and notes | Historical reference |

The root-level `src/` prototype is still present because old evaluations and
data refer to it. New case-memory work should start in `demo/`; runtime/tool
health work belongs in `runtime_memory/`.

## Quick start

### Case memory

```powershell
cd demo
python src/manage_memory.py catalog validate
python src/manage_memory.py audit
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
python -m unittest discover -s tests
```

See [`demo/README.md`](demo/README.md) for workflows, commands, and data rules.

### Runtime memory

```powershell
cd runtime_memory
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py brief
python src/run_runtime_demo.py --shadow
```

The local tool layer exercises the real preflight → HTTP call → postflight
path against a controllable service, without an external account or network:

```powershell
python runtime_memory/tool_layer/run_demo.py
```

It is a local HTTP harness, not an MCP server. See
[`runtime_memory/README.md`](runtime_memory/README.md) and
[`runtime_memory/README_CN.md`](runtime_memory/README_CN.md).

## Research and validation

- [`GUIDE.md`](GUIDE.md): root prototype design and historical operating guide.
- [`docs/`](docs/): architecture notes, reviews, and directly executable test plans.
- [`eval/usability_ablation/`](eval/usability_ablation/): memory/retrieval ablation work and reports.
- [`dataset/`](dataset/): source batches and synthetic dataset generators.

Results in evaluation documents are tied to their stated datasets, model
versions, and protocols; they should not be treated as production guarantees.

## Data boundaries

- `demo/data/` belongs to case memory; use its own audit, snapshot, and retention commands.
- `runtime_memory/data/` belongs to runtime memory; local test tools should use a temporary or dedicated `--root`.
- Do not copy runtime issue/event data into the case-memory store.
- Some scenario data and local research assets are intentionally ignored by Git; see `.gitignore` before assuming a dataset is included.
