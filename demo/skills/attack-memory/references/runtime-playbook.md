# Runtime Playbook

Run commands from `demo/`. Supplied file paths are relative to the demo root.

## Retrieve and interpret

```powershell
python src/run_demo.py --input data/raw_logs.csv
python src/run_demo.py --input data/raw_logs.csv --json
```

The CLI partitions rows by known `incident_id`. Rows without one are grouped by `batch_id` and explicitly described as a batch-level candidate, not a proven incident. Use `--incident-id` to select one known incident from a cumulative CSV. Once a candidate case is selected, fetch historical evidence separately with `python src/lookup_case_logs.py --case-id CASE-008` (optionally add `--incident-id ...`).

For each case candidate, inspect:

- `matched_steps / total_steps`: distinct pattern steps supported by at least one log whose source fits the step's expected sources;
- `evidence`: event IDs and sources supporting each matched step;
- `source_mismatches`: action-shaped rows from sources not listed for that step; review rather than discard automatically;
- `order_ok` and `order_assessable`: whether the earliest evidence timestamps follow pattern order, and whether there was enough parseable time data to check;
- `keyword_score`, `keyword_details`, and MITRE overlap: auxiliary lexical signals;
- `tier` and `shape`: deterministic evidence classes and alignment shape, not probabilities.

Candidate tiers are deterministic presentation hints: all steps matched in assessable, consistent time order with at least one non-generic step = `strong`; at least two non-generic steps = `medium`; some action evidence or source-mismatched action evidence = `weak`; lexical-only = `keyword_only`. The Agent/analyst still makes the incident and case decision.

## New observations

Input CSV requires `timestamp`, `source`, `log_id`, and `content`; `event_id`, `batch_id`, and `incident_id` are optional. Ingest appends, assigns IDs if absent, and leaves `case_id` blank:

```powershell
python src/ingest_logs.py --input data/incoming_batch.csv
```

Do not treat the pattern match as the incident grouping result. Review cross-alert linkage separately, then append a relation:

```powershell
python src/manage_memory.py link-events --event-ids EVT-123 --incident-id INC-123 --case-id CASE-008 --step-id S1 --status candidate --basis "Same host and URI; request identifier absent"
```

`candidate`, `confirmed`, `rejected`, and `fixture` are allowed statuses. `fixture` is reserved for synthetic validation data and must not be presented as a real observation. Link rows are append-only; later decisions supersede earlier ones operationally while preserving the history.

Confirmed and rejected decisions also update the CSV's `case_id`/`incident_id` analysis columns. The raw `content`, timestamp, source, and log ID remain unchanged. The relation table retains the rationale and decision history.

## No-candidate handling

No candidate means the current rules did not find a supported pattern. It does not establish that the activity is benign or novel. Review extracted behavior, sensor coverage, truncation, encoding, and whether a current pattern needs a carefully evidenced variant before adding a new pattern.
