# Pattern Write and Review Rules

## When to add or revise

- Add a new pattern only when the observed behavior is sufficiently distinct from current patterns and
  supported by evidence.
- Extend a pattern when new observations are a credible variant of the same behavior. Keep the original
  evidence and document the new variant and its source.
- If evidence is incomplete or only a generic probe is present, retain it as unclassified/candidate
  evidence instead of forcing a new pattern.

## Required discipline

1. Preserve the source logs and event IDs. Ingest appends; it never rewrites `content`.
2. State which events support each pattern step; record the event-to-step links separately.
3. Separate observed facts from inferred attack stage, attribution, and expected next steps.
4. Use `expected_sources` as an evidence hint. Add alternatives when observed evidence supports them;
   `["any"]` is allowed, but do not make a single sensor an absolute requirement without collection
   justification.
5. Include meaningful `action_regex` anchors and check that generic commands do not become a pattern's
   defining action. A regex must not match the empty string.
6. Keep MITRE mappings as references with supporting evidence; they are metadata, not a merge
   criterion and not a score.
7. Record unobserved behavior as unknown unless sensor coverage supports a negative conclusion.
8. Set `pattern_scope.variant_note` to identify unvalidated generalizations, especially when derived
   from one incident.
9. Validate before adding. The CLI refuses duplicate case IDs, malformed steps, any redefinition of an
   existing `action_id` with a different regex, a pattern whose steps are all optional, and a new case
   that fails the support gate (see below).
10. Set `family_id` from `data/families.json`. Reuse an existing family; a new family is a reviewed
    taxonomy change, not a per-case label. Family `steps` are broad behaviors linked only as
    `related`; they are not case required steps. `catalog validate` and `audit` require the registry
    and catalog to agree.
11. Every added case writes an admission (`case_admissions.json`) and carries `review_status:
    "unreviewed"` + `admission_id`. Experiment mode may leave it unreviewed; deployment mode must run
    `catalog review-case` before treating the case as trusted.
12. Behavior outside every case belongs on the incident chain: `review stage --incident-id --event-id
    --stage --basis`. It does not create a case and does not alter links; `catalog chain --summarize`
    only suggests labels.
13. Case lifecycle is explicit and recorded in `case_lifecycle.json`: `merge-case` (same-family
    alias; source retired, links not rewritten), `split-case`, `retire`, `reactivate`. Retired cases
    keep history but are skipped by retrieval.

## New-case support gate

`catalog add` (and `catalog add --from-candidate`) is admitted only when:

- the supporting set contains **at least two independent incidents**;
- every required step of the new pattern is covered by the union of the supporting incidents'
  events;
- at least one supporting incident reaches `strong`/`medium` tier on its own.

The admission records the per-incident `support_coverage`, `missing_required`, `has_strong_medium`
and `single_sample`, so a reviewer can see how complete the evidence was. `--force` is the reviewed
exception for a singleton: it waives the coverage rules but still records the partial coverage and
sets `single_sample`. Never use `--force` to skip evidence that is simply missing.

`catalog add` writes the pattern **and** `pattern_versions/<CASE>/v001.json` (plus the admission) in
one journaled transaction. A case without `v001` would fail `audit` and make rollback impossible.

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog add --input data/new_pattern.json \
  --supporting-incident-ids INC-1,INC-2
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
```

## Link rows

Use `event_pattern_links.csv` to record `event_id`, `incident_id`, `case_id`, `step_id`, `action_id`,
`link_status`, `link_basis`, and `decided_at`. Link status is `candidate`, `confirmed`, `related`,
`rejected`, or `fixture`; `fixture` is reserved for synthetic validation data. `related` records a
family/step association without confirming the canonical chain. Corrections append a new decision row
rather than rewriting the observation.

The step must be chosen from the event's own content, not from the pattern's narrative order.
`review link` enforces this by running the step's `action_regex` against the event content and refusing
a mismatch. The only exception is a reviewed `--force` with a non-empty basis: it writes a record to
`data/link_exceptions.json`, which `audit` waives and counts (`forced exceptions=N`). An exception
without a live matching link, or without a basis, is an audit problem. A `rejected` link needs no
exception because it is already exempt from the regex replay.

Labels follow the latest decision:

- `confirmed` sets `case_id` and `incident_id` on the raw row;
- `rejected` clears them only when it names the same case and incident, or withdraws an incident label
  that ingestion supplied without a case;
- `candidate`, `related`, and `fixture` never change labels, so a proposal cannot look like a finding.

## Negative memory

A rejected match should leave a durable boundary, not just a rejected link. Record the *why*:

```powershell
python src/manage_memory.py catalog correction add --incident-id INC-... --case-id CASE-005 \
  --reason-code generic_only --event-ids EVT-... \
  --basis "only a shared whoami probe; no case step"
```

Corrections are append-only and never edited in place; a later review appends a new record. Valid
reason codes: `generic_only`, `source_mismatch`, `incomplete_chain`, `wrong_family`,
`insufficient_evidence`, `other`; valid decisions: `reject_match`, `reject_case`. Before recalling a
candidate as a precedent, read its `prior_rejections` from `run_demo` — a prior rejection is a tested
boundary, not a precedent.

## Variant or new case

- Shares one step with a case, or belongs to its family with different tooling: record
  `review associate` (`related`), optionally with `--step-id`. Do not create a case.
- Genuinely distinct behavior: stage it as a candidate (`catalog stage`); one incident is
  `provisional`, a second with the same signature is `promotable`. Create a case only by promoting
  with an authored pattern (`catalog add --from-candidate`); a provisional promotion needs `--force`.
- A candidate without discriminative signature terms is `ungrouped`; it needs a reviewed
  `catalog merge --allow-ungrouped` (or an authored pattern) before it can be grouped/promoted.
  `signature_lexicon.json` extends the deterministic vocabulary; a malformed lexicon falls back to the
  built-in tables.
- Related incidents are support for a future proposal (completion, widening, source), not for the
  confirmed count or `maturity`; candidate incidents are support for a future case.

## Evolving an existing pattern

Do not edit `attack_patterns.json` to complete a pattern. Write a proposal and let the gate evaluate
it:

- the proposal must cite supporting events from confirmed-or-related incidents of the case; at least
  two independent incidents must support the change;
- `add_step` defaults to `required: false`. A stage that only some incidents reach must stay optional;
  marking it required drops existing `strong`/coverage incidents and is rejected;
- the gate checks no foreign-case match, no shadow top-1 change, no drop in `strong`/required coverage,
  and no regression on **held-out** confirmed incidents (the ones the proposal did not cite);
- completion (`add_step`), widening (`extend_step`) and source addition (`add_source`) may be accepted
  with `--auto` when the gate marks them eligible; demotion (`set_required: false`), narrowing and
  `reorder_steps` need an explicit accept.

Every accepted change snapshots the old and new pattern under `data/pattern_versions/` and appends the
decision to `pattern_proposals.json`. Use `evolve rollback --to N` instead of hand-editing backwards.
After accepting, link the supporting events to the new step so the evidence becomes permanent.

## Audit and repair after writing

Run `python src/manage_memory.py audit` after any batch of links or any accepted proposal. It checks
links, force exceptions, version snapshots, proposals, candidates, families, migrations, admissions,
chains, lifecycle, retention, corrections, and the journal; `--json` gives a machine-readable report.
A non-zero exit means the store contains a claim its own evidence does not support.

If a write was interrupted or derived state is inconsistent, run `catalog repair` (dry-run) and read
its plan before `catalog repair --apply`. Repair only rebuilds derived state (labels from links,
missing baseline snapshots, orphan admissions) in one journaled transaction and records it in
`repair_log.json`; it never deletes raw logs, links, cases, candidates or proposals. Do not hand-edit
data files to "fix" an inconsistency.

After any write that changes counts, run `catalog state --check README.md`; a mismatch means the
documented state block is stale and must be regenerated with `catalog state`.

## Scope

This demo has no concurrent-write protection (single-writer assumption), no access control or
authenticated reviewer identity, no automatic decay-based retirement, no scheduler, and no calibrated
confidence model. Tiers and `evidence_confidence` are deterministic evidence signals, not
probabilities. Do not use it as a production incident store without adding those controls around the
CLI.
