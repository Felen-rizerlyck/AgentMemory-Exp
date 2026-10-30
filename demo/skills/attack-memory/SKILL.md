---
name: attack-memory
description: Use the local rule-based attack-pattern catalog to retrieve candidate attack chains, explain evidence, append raw alerts, record reviewed event-to-pattern links, record negative-memory corrections, audit the memory store, and evolve patterns through gated proposals with snapshots and rollback.
---

# Attack Memory Demo Skill

Use this skill when analyzing logs with the isolated `demo/` attack memory. The store is a
deterministic, auditable memory — not a vector index. Every claim must be traceable to evidence, every
write must be reviewable, and every accepted change must be reversible.

## Operating rules

1. Treat `event_id`, `incident_id`, and `case_id` as different concepts. Do not infer that two alerts
   are one incident merely because both match the same pattern.
2. Preserve original log content. Add observations with `src/ingest_logs.py`; do not overwrite the raw
   CSV. Confirmed/rejected case labels may change in dedicated CSV columns, never in the content.
3. Run deterministic retrieval with `src/run_demo.py`. Report `matched_steps` (aligned) separately from
   `detected_steps`, list the events in `evidence`, and read `unaligned_detections` before concluding
   that something is missing. `unobserved_required_steps` / `unobserved_optional_steps` mean zero
   detection, not "not aligned". `evidence_confidence` is an evidence ratio, not a probability; do not
   present it as a score.
4. Treat evidence tiers and keyword points as ordering signals, never as probabilities or verdicts.
   MITRE IDs are metadata, not a retrieval signal.
5. Decide whether alerts form one incident from correlation evidence (session/request identifiers,
   host/process relationships, shared entities, temporal proximity, payload/path similarity). A shared
   host or one generic action alone is weak evidence; `run_demo` scopes unlabeled rows per host for
   this reason. A batch/host scope is a candidate scope, not proof of an incident.
6. For each candidate pattern, state what supports it, what conflicts with it, what remains
   unobserved, and which sources were available. Quote `pattern_scope.variant_note`,
   `negative_and_unknown_evidence.not_observed`, and `provenance` rather than generalizing past them.
7. A source mismatch is a reason to review an observation, not automatic proof of another incident.
8. Do not add a pattern just because retrieval returned no candidate. No candidate means the rules did
   not find a supported pattern; it does not establish that the activity is benign or novel.
9. Record reviewed relations with `review link` (a step is verified against its `action_regex`),
   `review associate` (a variant, written as `related`, no case label), or `review stage` (a chain
   annotation independent of any case). `--force` is only for a reviewed exception: it needs a
   non-empty `--basis` and writes an entry to `data/link_exceptions.json`; `audit` waives exactly that
   row and reports the visible forced count. Never force a link to make a narrative fit.
10. Add or modify pattern JSON only through the schema, `catalog validate`, and the write path.
    A new case needs required-step union coverage across at least two independent incidents and at
    least one support incident at `strong`/`medium` tier; `--force` is only for a reviewed singleton
    and records `single_sample` plus per-incident `support_coverage` in the admission. `catalog add`
    writes the pattern and its `v001` snapshot in one transaction. Every added case gets an
    `unreviewed` admission and marker; in deployment a human clears it with `catalog review-case`.
11. `action_id` has exactly one authoritative regex across the catalog; a variant needs its own
    `action_id`. A schema move (for example moving a step into a family) is a reviewed migration in
    `pattern_migrations.json`, not a proposal.
12. Grow an existing pattern only through `evolve propose` → `evolve accept`. `add_step` defaults to
    `required: false`; a stage only some incidents reach must stay optional. The gate requires
    supporting events from confirmed-or-related incidents, at least two independent incidents, no
    foreign-case match, no shadow top-1 change, no drop in `strong`/required coverage, and no
    regression on held-out (non-support) confirmed incidents. `--auto` is limited to completion-class
    operations the gate marked eligible; demotion, narrowing and `reorder_steps` need an explicit
    accept. Accepting snapshots the old and new versions; then link the supporting events and audit.
13. Remember the negative. When a match is rejected, record *why* with
    `catalog correction add --incident-id ... --case-id ... --reason-code ... --basis "..."`.
    A correction is an append-only boundary ("this is not that, because ..."), not a replacement for
    the rejected link. Before recalling a candidate as a precedent, read its `prior_rejections`;
    a prior rejection is a tested boundary, not a precedent.
14. Run `python src/manage_memory.py audit` after any batch of links or accepted proposal. It checks
    links, force exceptions, versions, proposals, candidates, families, migrations, admissions,
    chains, lifecycle, retention, corrections, and the transaction journal. A failed audit means the
    store contains a claim its evidence does not support; fix it before presenting conclusions.
    Counts and maturity are derived from confirmed links, so there is no counter to resynchronise.
15. Keep state and docs in sync: `catalog state` prints the generated numbers block;
    `catalog state --check README.md` fails when the README block no longer matches the store. Use
    `audit --json` when a machine must consume the report; `run_demo --json` and `lookup_case_logs --json`
    carry a top-level `schema_version`, while the `audit`/`state` report shape is fixed by the invariant
    tests.
16. Repair only derived state: `catalog repair` is dry-run by default and rebuilds labels from links,
    backfills missing snapshot baselines, and removes orphan admissions. `--apply` commits one
    journaled transaction and records it in `repair_log.json`. Repair never deletes raw logs, links,
    cases, candidates or proposals. Never hand-edit the store to fix a crash; inspect the journal and
    use repair.
17. A technique that belongs to no existing case is staged, not created: `catalog stage` records it
    under a signature. One incident is `provisional`; a second with the same signature is
    `promotable`. Promotion needs an authored pattern (`catalog add --from-candidate`). A candidate
    without discriminative terms is `ungrouped` (visible in `catalog candidates --by-group`); merging
    ungrouped candidates needs `--allow-ungrouped`, because a content hash is not evidence of a shared
    technique. A merged incident in a promoted cluster is `pending_case_links`, not a new case.
18. Group by `family_id` before adding a case or candidate (`catalog families`). A family is a
    taxonomy, not a case; family steps are broad behaviors linked only as `related`, shown by
    `run_demo` as context and never changing a case's tier.
19. Incident chains are first-class: `catalog chain --incident-id ... --summarize` shows ordered
    stages, including `unclassified` events; `review stage` names behavior outside every case.
    Summaries are suggestions and never create a case or stage automatically.
20. Case lifecycle is explicit: `catalog merge-case` (same family; source retired with
    `merged_into=target`, links not rewritten), `split-case`, `retire`, `reactivate`. Every lifecycle
    write is one journaled transaction; a case merge commits patterns, candidates and lifecycle
    together, so a reader never sees half a merge. Retired cases keep their history but are skipped by
    retrieval. `lookup_case_logs --case-id <merged source>` follows the alias and counts the source's
    evidence under the target (`alias_of` / `resolved_case_id` in JSON); `run_demo` scores active
    patterns only.
21. Use snapshots, not hand edits, to go back: `evolve rollback --case-id CASE --to N --basis "..."`.
    `catalog snapshot --all` backfills missing version numbers from the current catalog as *baselines*
    (not historical replays); the audit only requires existence, version and case ID to agree.

## Recall policy (retrieval → lookup)

The model retrieves a candidate, then decides which stored logs to recall. That second step is where
false positives enter, so gate it on evidence quality:

| result | recall | use |
|---|---|---|
| `strong` / `medium` | the case and its other incidents | positive precedent; cite the steps |
| `weak` · `prefix` | the matched step's events plus the chain | hypothesis to falsify (the attack may be early) |
| `weak` · `tail` | only the matched step's events | "what this step looks like", not the chain |
| `weak` · `generic_only` | nothing (or that step as background) | shared detector only, no case precedent |
| `weak` · `mismatch_only` | nothing | sensor-expectation question |
| `keyword_only` | nothing | not a candidate |

- Always pass `--exclude-incident` for the incident under judgement; recalling its own reviewed rows
  is answer leakage.
- Present recalled rows as step examples, never as "this is the same case". State the matched step,
  whether it is generic, which required steps are missing, and how many source mismatches there are.
- Use `run_demo.py --min-tier medium` for triage and `lookup_case_logs.py --case-id CASE-... --step-id S4`
  for targeted recall. Fixtures are hidden by default and must never be reported as real observations.
- Use `run_demo.py --json` / `lookup_case_logs.py --json` when another agent or script consumes the
  result; both include `schema_version: 1`. `run_demo` candidates carry `historical_precision`,
  `evidence_confidence` and `prior_rejections`; `lookup` carries `alias_of` / `resolved_case_id`.

## Routine workflow

1. Receive a batch and preserve it as CSV with `timestamp`, `source`, `log_id`, `content`.
2. Append it with `python src/ingest_logs.py --input <demo-relative-path>`. A supplied `incident_id`
   is withheld unless the batch is already reviewed and you pass `--allow-incident-id`.
3. Retrieve candidates with `python src/run_demo.py --input data/raw_logs.csv --json` (or point at a
   separate batch CSV before ingestion).
4. Inspect each candidate's evidence, extra/out-of-order detections, sequence order, source fit,
   `evidence_confidence`, `prior_rejections`, and the pattern's caveats and provenance.
5. Correlate alerts into incident hypotheses independently from pattern retrieval; keep uncertain
   relations as `candidate`.
6. Present the conclusion with evidence and uncertainty. Do not auto-label from the top score, and do
   not report a scope whose only reviewed links are `fixture` as a real observation.
7. Once a pattern is selected, fetch historical examples with
   `python src/lookup_case_logs.py --case-id CASE-...` (fixtures hidden; alias-following enabled).
8. Record reviewed relations with `review link` (confirmed) or `review associate` (related). If the
   step genuinely does not match but the exception is reviewed, pass `--force` with a basis.
9. When a reviewed match is rejected, record the boundary with `catalog correction add` so the same
   false positive is not re-promoted later.
10. Run `audit`, then `catalog state --check README.md` after any write that changes counts.
11. If later incidents reveal an extra stage, run `audit --verbose --case-id`, write a proposal with
    the supporting events, and let the gate decide (held-out included). Accept it (or `--auto` for
    eligible completion), link the events to the new step, and audit again.
12. If a genuinely new reusable pattern is established by at least two incidents, prepare a
    schema-compliant JSON file and add it with `catalog add --supporting-incident-ids`.
13. If the technique is novel but not yet repeated, stage it with `catalog stage`; promote a
    promotable candidate with `catalog add --from-candidate`, then link its incidents and audit.
14. Inspect `catalog chains` after a review batch; annotate new behavior with `review stage` instead of
    forcing it into a case. Use `catalog chain --summarize` only as a suggestion.
15. If two cases are aliases of one behavior, use `catalog merge-case` (same family); split with
    `catalog split-case`; retire an obsolete case instead of deleting history.
16. If the store and the state block disagree, run `catalog state --check README.md`; if derived state
    is inconsistent after an interrupted write, run `catalog repair` (dry run) before `--apply`.

## References

- [Runtime playbook](references/runtime-playbook.md)
- [Memory schema](references/memory-schema.md)
- [Write and review rules](references/case-write-spec.md)
