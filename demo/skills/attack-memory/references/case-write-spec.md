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
6. Keep MITRE mappings as references with supporting evidence; do not use MITRE overlap as the sole basis for merging patterns.
7. Record unobserved behavior as unknown unless sensor coverage supports a negative conclusion.
8. Set `pattern_scope.variant_note` to identify unvalidated generalizations, especially when derived from one incident.
9. Validate before adding. The management CLI refuses duplicate case IDs and malformed steps.

## Link rows

Use `event_pattern_links.csv` to record `event_id`, `incident_id`, `case_id`, `step_id`, `action_id`, `link_status`, and a concise `link_basis`. Link status is `candidate`, `confirmed`, or `rejected`; `fixture` is reserved for synthetic validation data. Corrections append a new decision row rather than rewriting the observation.

## Scope

This demo has no concurrent-write protection, retention scheduler, access controls, secrets handling, or calibrated confidence model. Do not use it as a production incident store without addressing those requirements.
