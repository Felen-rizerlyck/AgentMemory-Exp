---
name: attack-memory-demo
description: Use the local rule-based attack-pattern catalog to retrieve candidate attack chains, explain evidence, append raw alerts, and record reviewed event-to-pattern links.
---

# Attack Memory Demo Skill

Use this skill when analyzing logs with the isolated `demo/` attack memory.

## Operating rules

1. Treat `event_id`, `incident_id`, and `case_id` as different concepts. Do not infer that two alerts are one incident merely because both match the same pattern.
2. Preserve original log content. Add new observations with `src/ingest_logs.py`; do not overwrite the raw CSV. Confirmed case/incident labels may change in dedicated CSV columns, but never rewrite the original content.
3. Run deterministic retrieval with `src/run_demo.py`. Report action evidence, alignment shape, source fit, time ordering, and auxiliary lexical hits separately. Known incident IDs are isolated; an unassigned batch is only a candidate scope.
4. Treat evidence tiers and keyword points as ordering signals, never as probabilities or verdicts.
5. Decide whether alerts form one incident from correlation evidence (session/request identifiers, host/process relationships, shared entities, temporal proximity, and payload/path similarity). Shared host or a single generic action alone is weak evidence.
6. For each candidate pattern, state what supports it, what conflicts with it, what remains unobserved, and which sources were available. Missing evidence is unknown unless collection coverage establishes otherwise.
7. A source mismatch is a reason to review an observation, not automatic proof of another incident.
8. Do not add a pattern just because retrieval returned no candidate. First establish a coherent, sufficiently evidenced behavior pattern and check whether an existing pattern can be extended.
9. After human/Agent review, append event links with a concise evidence basis. Add or modify pattern JSON only through the schema and management command.

## Routine workflow

1. Receive a batch and preserve it as CSV with `timestamp`, `source`, `log_id`, and `content`.
2. Append it using `python src/ingest_logs.py --input <demo-relative-path>`.
3. Retrieve candidates using `python src/run_demo.py --input data/raw_logs.csv --json` (or point to a separate batch CSV before ingestion).
4. Inspect each candidate's action-step evidence, sequence order, source fit, keyword/probe details, and MITRE overlap.
5. Correlate alerts into incident hypotheses independently from pattern retrieval. Keep uncertain links as `candidate`.
6. Present the conclusion with evidence and uncertainty. Do not auto-label from the top score.
7. Once a pattern is selected, fetch historical examples with `python src/lookup_case_logs.py --case-id CASE-...` and keep separate incidents distinct.
8. Record reviewed event-to-incident/case-step relations using `python src/manage_memory.py link-events ...`. Confirmed links fill only the CSV analysis-label columns; original log content is preserved.
9. If a genuinely new reusable pattern is established, prepare a schema-compliant JSON file, validate/add it, and rerun retrieval manually.

## References

- [Runtime playbook](references/runtime-playbook.md)
- [Memory schema](references/memory-schema.md)
- [Write and review rules](references/case-write-spec.md)
