# Attack Memory Demo

An isolated, movable demonstration of a small attack-memory workflow. It uses only the Python standard library and does not modify files outside this directory.

## Layout

```text
demo/
├── data/
│   ├── attack_patterns.json       # reusable attack-pattern catalog
│   ├── raw_logs.csv               # cumulative observations; CASE-008 and synthetic fixture
│   ├── event_pattern_links.csv    # reviewed event → incident → pattern-step links
│   └── validation_batches/        # isolated synthetic validation input
├── src/
│   ├── attack_memory/             # storage, retrieval, ingestion, memory management
│   ├── run_demo.py                # candidate retrieval CLI
│   ├── lookup_case_logs.py        # fetch stored observations after candidate retrieval
│   ├── ingest_logs.py             # append normalized log CSV rows
│   └── manage_memory.py           # validate/add patterns and append reviewed links
└── skills/attack-memory/          # Agent workflow and schema instructions
```

The three identifiers have separate meanings: `event_id` identifies one alert, `incident_id` identifies one suspected real-world activity, and `case_id` identifies a reusable attack pattern. Original observations are not the pattern itself. The `case_id` values already present in the CASE-008 sample are curated demo labels; newly ingested events are left unlabeled until review. After retrieval, use `lookup_case_logs.py` to fetch historical rows by the selected case and optionally narrow them to an incident.

`data/validation_batches/CASE-008_similar_synthetic.csv` is a synthetic positive fixture, separate from the original observed batch. Its eight rows are also included in the cumulative `raw_logs.csv`; their event links use status `fixture` and do not increase CASE-008's real observation count.

All command paths supplied by the user are relative to this `demo/` directory, independent of the shell's current directory. The code locates the demo root from its own file path, so the folder can be moved as a unit.

## Quick start

Run from this directory:

```powershell
python src/run_demo.py
python src/run_demo.py --input data/raw_logs.csv --json
python src/run_demo.py --input data/validation_batches/CASE-008_similar_synthetic.csv
python src/lookup_case_logs.py --case-id CASE-008 --incident-id INC-CASE008-001
python src/manage_memory.py validate
```

The retriever builds an action-to-pattern reverse index in memory from JSON steps, aligns observed action detections to each ordered pattern, and ranks by evidence tier before match count and auxiliary keyword/probe signals. It never assigns a final incident verdict or automatically labels new logs. Known `incident_id` groups are analyzed separately; unassigned rows are only batch-scoped candidates.

## Append new logs

Prepare a CSV with at least `timestamp,source,log_id,content`; an optional `event_id` is preserved. Then run:

```powershell
python src/ingest_logs.py --input data/incoming_batch.csv
```

The script appends observations to `data/raw_logs.csv`, assigns event and batch IDs where missing, and rejects duplicate event IDs. It leaves case labels blank. A confirmed link fills the CSV's analysis-only `case_id` and `incident_id` columns while preserving original timestamp, source, log ID, and content; the relation file retains step-level rationale and decision history.

## Add a reviewed pattern or link evidence

An input pattern must follow the schema in `skills/attack-memory/references/memory-schema.md` and include executable `action_regex` values for each step:

```powershell
python src/manage_memory.py add-pattern --input data/new_pattern.json
python src/manage_memory.py link-events --event-ids EVT-123 --incident-id INC-123 --case-id CASE-008 --step-id S1 --status confirmed --basis "Shared request URI and X-BEResource evidence"
```

Links are appended so the analysis history is auditable. The latest link for a given event/case/step is the current status; prior decisions remain in the CSV.

## Limits of this demo

- Rule-based retrieval is explainable but only as complete as the pattern rules.
- Sequence ordering is checked from timestamps when all matched steps have parseable timestamps; missing timestamps make order unassessable.
- Simple source expectations are evidence cues, not proof that a different source is unrelated.
- Retrieval tiers and lexical points are deterministic ranking signals, not calibrated confidence.
- Incident clustering is not automatic here. An Agent or analyst must review correlation evidence and record confirmed links.
- CSV is a convenient demo store, not a concurrent database. Large-scale ingestion, retention, access control, and privacy policy are outside this prototype.
