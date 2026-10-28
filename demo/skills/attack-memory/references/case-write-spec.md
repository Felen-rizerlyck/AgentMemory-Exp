# Pattern Write and Review Rules

## When to add or revise

- Add a new pattern only when the observed behavior is sufficiently distinct from current patterns and supported by evidence.
- Extend a pattern when new observations are a credible variant of the same behavior. Keep the original evidence and document the new variant and its source.
- If evidence is incomplete or only a generic probe is present, retain it as unclassified/candidate evidence instead of forcing a new pattern.

## Required discipline

1. Preserve the source logs and event IDs.
2. State which events support each pattern step; record the event-to-step links separately.
3. Separate observed facts from inferred attack stage, attribution, and expected next steps.
4. Use `expected_sources` as an evidence hint. Add alternatives when observed evidence supports them; do not make a single sensor an absolute requirement without collection justification.
5. Include meaningful `action_regex` anchors and check that generic commands do not become a pattern's defining action.
6. Keep MITRE mappings as references with supporting evidence; they are metadata, not a merge criterion and not a score.
7. Record unobserved behavior as unknown unless sensor coverage supports a negative conclusion.
8. Set `pattern_scope.variant_note` to identify unvalidated generalizations, especially when derived from one incident.
9. Validate before adding. The management CLI refuses duplicate case IDs, malformed steps, any redefinition of an existing `action_id` with a different regex, a pattern whose steps are all optional, and a new case with fewer than two supporting incidents unless `--force` is explicit.
10. Set `family_id` from `data/families.json`. Reuse an existing family; a new family is a reviewed taxonomy change, not a per-case label. Family `steps` are broad behaviors linked only as `related`; they are not case required steps. `catalog validate` and `audit` require the registry and catalog to agree.
11. Every added case writes an admission (`case_admissions.json`) and carries `review_status: "unreviewed"` + `admission_id`. Experiment mode may leave it unreviewed; deployment mode must run `catalog review-case` before treating the case as trusted.

## Link rows

Use `event_pattern_links.csv` to record `event_id`, `incident_id`, `case_id`, `step_id`, `action_id`, `link_status`, `link_basis`, and `decided_at`. Link status is `candidate`, `confirmed`, `related`, or `rejected`; `fixture` is reserved for synthetic validation data. `related` records a family/step association without confirming the canonical chain. Corrections append a new decision row rather than rewriting the observation.

The step must be chosen from the event's own content, not from the pattern's narrative order. `review link` enforces this by running the step's `action_regex` against the event content and refusing a mismatch; an exception needs `--force` and a basis that explains it. A link row without that check is how step attribution silently drifts.

Labels follow the latest decision:

- `confirmed` sets `case_id` and `incident_id` on the raw row;
- `rejected` clears them only when it names the same case and incident, or withdraws an incident label that ingestion supplied without a case;
- `candidate`, `related`, and `fixture` never change labels, so a proposal cannot look like a finding.

## Variant or new case

- Shares one step with a case, or belongs to its family with different tooling: record `review associate` (`related`), optionally with `--step-id`. Do not create a case.
- Genuinely distinct behavior: stage it as a candidate (`catalog stage`); one incident is `provisional`, a second with the same signature is `promotable`. Create a case only by promoting with an authored pattern (`catalog add --from-candidate`); a provisional promotion needs `--force`.
- Related incidents are support for a future proposal (completion, widening, source), not for the confirmed count or `maturity`; candidate incidents are support for a future case.

## Evolving an existing pattern

Do not edit `attack_patterns.json` to complete a pattern. Write a proposal and let the gate evaluate it:

- completion (`add_step`) and widening (`extend_step`, `add_source`) may be accepted automatically once the case has at least two confirmed or related incidents and the gate sees no regression;
- demotion (`set_required: false`) and narrowing need an explicit human accept;
- a stage that only some incidents reach must be `required: false`; forcing it required will be rejected because it drops existing `strong` incidents.

Every accepted change snapshots the old pattern under `data/pattern_versions/` and appends the decision to `pattern_proposals.json`. Use `evolve rollback` instead of hand-editing backwards. After accepting, link the supporting events to the new step so the evidence becomes permanent.

## Audit after linking

Run `python src/manage_memory.py audit` after any batch of links or any accepted proposal. It re-checks every row against the event content, the catalog, and the confirmed labels, and verifies accepted proposals still have their snapshots. A non-zero exit means the store contains a claim its own evidence does not support. Counts and maturity are derived from confirmed links, not stored.

## Scope

This demo has no concurrent-write protection, retention scheduler, access controls, secrets handling, reviewer identity, calibrated confidence model, or merge/split/retire of whole cases. Do not use it as a production incident store without addressing those requirements.
