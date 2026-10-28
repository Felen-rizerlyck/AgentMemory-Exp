---
name: attack-memory
description: Use the local rule-based attack-pattern catalog to retrieve candidate attack chains, explain evidence, append raw alerts, record reviewed event-to-pattern links, audit the memory store, and evolve patterns through gated proposals.
---

# Attack Memory Demo Skill

Use this skill when analyzing logs with the isolated `demo/` attack memory.

## Operating rules

1. Treat `event_id`, `incident_id`, and `case_id` as different concepts. Do not infer that two alerts are one incident merely because both match the same pattern.
2. Preserve original log content. Add new observations with `src/ingest_logs.py`; do not overwrite the raw CSV. Confirmed case/incident labels may change in dedicated CSV columns, but never rewrite the original content.
3. Run deterministic retrieval with `src/run_demo.py`. Report `matched_steps` (aligned) separately from `detected_steps`, list every event in `evidence`, and read `unaligned_detections` before concluding that something is missing. `unobserved_required_steps` and `unobserved_optional_steps` mean zero detection, not "not aligned".
4. Treat evidence tiers and keyword points as ordering signals, never as probabilities or verdicts. MITRE IDs are metadata, not a retrieval signal.
5. Decide whether alerts form one incident from correlation evidence (session/request identifiers, host/process relationships, shared entities, temporal proximity, and payload/path similarity). Shared host or a single generic action alone is weak evidence. Retrieval scopes unlabeled rows per host for this reason.
6. For each candidate pattern, state what supports it, what conflicts with it, what remains unobserved, and which sources were available. Quote `pattern_scope.variant_note`, `negative_and_unknown_evidence.not_observed`, and `provenance` rather than generalizing past them.
7. A source mismatch is a reason to review an observation, not automatic proof of another incident.
8. Do not add a pattern just because retrieval returned no candidate. First establish a coherent, sufficiently evidenced behavior pattern and check whether an existing pattern can be extended.
9. After human/Agent review, append event links with a concise evidence basis. The CLI verifies that the event content matches the chosen step; never `--force` a link to make the narrative fit.
10. Add or modify pattern JSON only through the schema, `catalog validate`, and `catalog add`. A new case needs at least two supporting incidents (`--supporting-incident-ids`); `--force` is only for a reviewed singleton. Set `family_id` to an existing family; do not create a family per case. A schema move (for example a step into a family) is recorded in `pattern_migrations.json` via `catalog migrations`, not as a pattern proposal. An `action_id` keeps one authoritative regex across the catalog; variants need a new ID. Every model-added case gets an admission record and `review_status: "unreviewed"`; in deployment, a human clears it with `catalog review-case`.
11. Run `python src/manage_memory.py audit` after linking. A failed audit means the store contains a claim its evidence does not support; fix it before presenting conclusions. Counts and maturity are derived from confirmed links, so there is no counter to resynchronise.
12. Grow an existing pattern through `evolve propose` and `evolve accept`, never by hand-editing the catalog. Completion and widening may be accepted automatically from maturity `repeated`; demotion and narrowing need an explicit accept. A stage only some incidents reach must be `required: false`.
13. Start from `python src/manage_memory.py audit --verbose --case-id <CASE>`: `matched` vs `linked` exposes ambiguous matchers, and `unexplained in <incident>` lists confirmed events no step explains. Those are the only legitimate inputs to a completion proposal.
14. Before recalling a stored log, read `tier` and `weak_kind` and apply the recall policy below. A weak result is a step-level hint, never a case-level precedent.
15. A variant that shares one step, or belongs to the same attack family with different tooling, is a `related` association, not a new case: `review associate --case-id CASE-... --basis ...` (optionally `--step-id`). Related incidents count as proposal support but never as confirmed observations.
16. A technique that belongs to no existing case is staged as a candidate, not created as a case: `catalog stage --signature ... --family-id ... --incident-id ... --event-ids ...`. One incident is `provisional`; a second incident with the same signature is `promotable`. Promotion needs an authored pattern (`catalog add --from-candidate`), and a provisional candidate needs `--force` after review. `catalog candidates --by-group` groups by deterministic `signature_key`; `catalog merge` merges only same-family/same-key duplicates (aliases become `merged`), and `catalog split` reverses a non-promoted merge. A merged incident in a promoted cluster is `pending_case_links`, not a new case.
17. Group by `family_id` before adding a case or a candidate: `catalog families` shows the current families, their cases and family steps. A family is a taxonomy, not a case; reuse an existing one unless the behavior genuinely starts a new class. Family steps are broad behaviors linked only as `related`, shown by `run_demo` as family evidence; they never change a case's tier.

## Recall policy (retrieval → lookup)

The model retrieves a candidate, then decides which stored logs to recall. That second step is where false positives enter, so gate it on evidence quality:

| result | recall | use |
|---|---|---|
| `strong` / `medium` | the case and its other incidents | positive precedent; cite the steps |
| `weak` · `prefix` | the matched step's events plus the chain | hypothesis to falsify (the attack may be early) |
| `weak` · `tail` | only the matched step's events | "what this step looks like", not the chain |
| `weak` · `generic_only` | nothing (or that step as background) | shared detector only, no case precedent |
| `weak` · `mismatch_only` | nothing | sensor-expectation question |
| `keyword_only` | nothing | not a candidate |

- Always pass `--exclude-incident` for the incident under judgement; recalling its own reviewed rows is answer leakage.
- Present recalled rows as step examples, never as "this is the same case". State the matched step, whether it is generic, which required steps are missing, and how many source mismatches there are.
- Use `run_demo.py --min-tier medium` for triage and `lookup_case_logs.py --step-id S4` for targeted recall.

## Routine workflow

1. Receive a batch and preserve it as CSV with `timestamp`, `source`, `log_id`, and `content`.
2. Append it using `python src/ingest_logs.py --input <demo-relative-path>`. A supplied `incident_id` is withheld unless the batch is already reviewed and you pass `--allow-incident-id`.
3. Retrieve candidates using `python src/run_demo.py --input data/raw_logs.csv --json` (or point to a separate batch CSV before ingestion).
4. Inspect each candidate's evidence, extra/out-of-order detections, sequence order, source fit, keyword details, and the pattern's caveats and provenance.
5. Correlate alerts into incident hypotheses independently from pattern retrieval. Keep uncertain links as `candidate`.
6. Present the conclusion with evidence and uncertainty. Do not auto-label from the top score, and do not report a scope whose only reviewed links are `fixture` as a real observation.
7. Once a pattern is selected, fetch historical examples with `python src/lookup_case_logs.py --case-id CASE-...` (fixtures hidden by default) and keep separate incidents distinct.
8. Record reviewed event-to-incident/case-step relations using `python src/manage_memory.py review link ...`. Confirmed links fill only the CSV analysis-label columns; original log content is preserved.
9. For a weak or family variant, record `review associate` (related) instead of a new case; related incidents are the support set for a later proposal.
10. Run `python src/manage_memory.py audit`, then rerun retrieval manually to confirm the review changed nothing unexpectedly.
11. If later incidents reveal an extra stage for an existing case, run `audit --verbose --case-id`, write a proposal with the supporting events, and let the gate decide. Accept it (or `--auto` for completion), then link those events to the new step and audit again.
12. If a genuinely new reusable pattern is established **by at least two incidents**, prepare a schema-compliant JSON file, add it with `catalog add --supporting-incident-ids`, and rerun retrieval manually.
13. If the technique is novel but not yet repeated, stage it with `catalog stage` (set `--family-id`); `catalog candidates` shows what is provisional versus promotable. Promote a promotable candidate with `catalog add --from-candidate`, then link its incidents and audit.
14. Run `catalog families` before adding a case or candidate: it shows which family already covers the behavior. A family is a classification, not a new case. Family-level evidence in `run_demo` is context, not part of the case's strong/medium judgement.

## References

- [Runtime playbook](references/runtime-playbook.md)
- [Memory schema](references/memory-schema.md)
- [Write and review rules](references/case-write-spec.md)
