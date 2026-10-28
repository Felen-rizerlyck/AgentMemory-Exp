# Runtime Playbook

Run commands from `demo/`. Supplied file paths are relative to the demo root.

## Retrieve and interpret

```powershell
python src/run_demo.py --input data/raw_logs.csv
python src/run_demo.py --input data/raw_logs.csv --json
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
```

`--min-tier` defaults to `weak`, so lexical-only candidates are hidden. Pass `--min-tier keyword_only` to see them, `--min-tier medium` for triage that only accepts chain-level evidence.

The CLI partitions rows by known `incident_id`. Rows without one are grouped by `batch_id` and then split by the `host=` value in the content, because one chain cannot span two hosts. Every unlabeled group is a candidate scope, not a proven incident. Use `--incident-id` to select one known incident from a cumulative CSV.

For each case candidate, inspect:

- `matched_steps / total_steps`: aligned steps, all of them;
- `matched_required_steps / required_steps`: the required skeleton that decides `shape` and `tier`;
- `detected_steps`: steps with at least one detection of any source;
- `evidence`: **every** source-compatible detection for a step, time ordered, with `event_ids`, `sources`, per-detection provenance, `aligned_event_id` (the one used for alignment), and `required`;
- `unaligned_detections`: detections the alignment did not use, with reason `extra_detection_for_S<n>` (same step already aligned) or `out_of_order` (using it would break time order);
- `source_mismatches`: action-shaped rows from sources not listed for that step; review rather than discard automatically;
- `order_ok` / `order_assessable`: time order over the **required** skeleton (what `strong` uses);
- `unobserved_required_steps` / `unobserved_optional_steps`: steps with no detection at all, split by requiredness — never "detected but unaligned";
- `keyword_score`, `keyword_details`: auxiliary lexical signals;
- `pattern_scope.variant_note`, `negative_and_unknown_evidence.not_observed`, `provenance`: the author's caveats and evidence status, surfaced so a single-sample pattern is not over-generalized;
- `version`: the pattern version that produced this result;
- `family_id`: the case's family; family-level steps are printed separately as context and never change `tier`;
- `weak_kind`: for `weak` only — `prefix` (first required step, chain may be early), `tail` (a later specific step while earlier required steps are missing), `generic_only` (only generic steps), `mismatch_only` (no aligned evidence, only source mismatches), `unaligned_only` (defensive fallback);
- `tier` and `shape`: deterministic evidence classes and alignment shape, not probabilities.

MITRE technique IDs are catalog metadata. They are not inferred from the logs and do not rank candidates.

Candidate tiers are deterministic presentation hints over the **required** skeleton: all required steps aligned in assessable, consistent time order with at least one non-generic required step = `strong`; at least two non-generic required steps aligned = `medium`; some action evidence (aligned, extra, or source-mismatched) = `weak`; lexical-only = `keyword_only`. An optional step may be missing without changing shape or tier. The Agent/analyst still makes the incident and case decision.

The scope header also shows review state (`reviewed confirmed=8`). A scope whose only reviewed links are `fixture` is synthetic and must not be reported as a real observation.

## Recall policy (retrieval → lookup)

Retrieving a candidate is not the same as recalling a precedent. Decide what to read from the tier and `weak_kind`:

| result | recall | use |
|---|---|---|
| `strong` / `medium` | the case and its other incidents | positive precedent; cite the steps, and `predict_next` may be used |
| `weak` · `prefix` | the matched step's events plus the chain | hypothesis to falsify; the attack may simply be early |
| `weak` · `tail` | only the matched step's events | "what this step looks like in a real log", not the chain |
| `weak` · `generic_only` | nothing, or the matched step as background | a shared detector, not a case precedent |
| `weak` · `mismatch_only` | nothing | a sensor-expectation question, not behavioral similarity |
| `keyword_only` | nothing | lexical noise; treat the scope as out of catalog |

```powershell
python src/lookup_case_logs.py --case-id CASE-002 --step-id S4
python src/lookup_case_logs.py --case-id CASE-002 --exclude-incident INC-20261021-001
python src/lookup_case_logs.py --case-id CASE-005 --include-related --status related
```

Rules:

- Exclude the incident under judgement (`--exclude-incident`); recalling its own reviewed labels is answer leakage.
- Present recalled rows as **step examples**, not case conclusions. When a weak match is used at all, say which step matched, whether it is generic, which required steps are absent, and how many source mismatches exist.
- Related variants carry no case label; read them with `--include-related`. They are family context, not confirmed precedents.
- Do not let a recalled complete chain "fill in" a partial input. The gap is the finding, not a prompt to complete it.
- A `weak` result must never be written up as "same attack"; at most it is "same single behavior, different technique".
- Family evidence (`ransomware/S9`, `supply-chain/S4`, …) is context, not a case conclusion. It can explain a variant that has no case candidate, but it never raises the case tier.

## New observations

Input CSV requires `timestamp`, `source`, `log_id`, and `content`; `event_id`, `batch_id`, and `incident_id` are optional. Ingest appends, assigns IDs if absent, leaves `case_id` blank, and withholds a supplied `incident_id`:

```powershell
python src/ingest_logs.py --input data/incoming_batch.csv
```

Use `--allow-incident-id` only when the batch has already been correlated by a human, otherwise an input file could claim membership in a known incident without review.

Do not treat the pattern match as the incident grouping result. Review cross-alert linkage separately, then append a relation:

```powershell
python src/manage_memory.py review link --event-ids EVT-123 --incident-id INC-123 --case-id CASE-008 --step-id S1 --status candidate --basis "Same host and URI; request identifier absent"
python src/manage_memory.py review associate --event-ids EVT-9,EVT-10 --incident-id INC-9 --case-id CASE-005 --basis "same ransomware family, different tooling"
```

`candidate`, `confirmed`, `rejected`, `fixture`, and `related` are allowed statuses. `fixture` is reserved for synthetic validation data and must not be presented as a real observation. `related` means the incident belongs to the case's family or shares a step, without confirming the canonical chain: it writes no `case_id` label, but counts as support for a proposal. Link rows are append-only; later decisions supersede earlier ones operationally while preserving the history.

`review link` verifies that the event content matches the step's `action_regex` before writing. If the step genuinely does not match, do not force it — the step choice is probably wrong. `--force` exists only for a reviewed exception and requires the basis to say why.

A variant that shares one step should be recorded with `review associate` (implicit `related`, optionally with `--step-id`), not turned into a new case. A genuinely new case needs at least two supporting incidents: `catalog add --supporting-incident-ids INC-1,INC-2`, or `--force` for a reviewed singleton.

Confirmed and rejected decisions also update the CSV's `case_id`/`incident_id` analysis columns. `confirmed` sets them; `rejected` clears them only when it names the same case and incident, or withdraws an incident label that ingestion supplied without a case. `candidate`, `related`, and `fixture` leave labels untouched. The raw `content`, timestamp, source, log ID, extra columns, and line endings remain unchanged.

## Audit

```powershell
python src/manage_memory.py audit
python src/manage_memory.py audit --verbose --case-id CASE-005
```

The audit re-reads every link row and checks that the event exists, the case/step exist, the recorded `action_id` matches the step, the event content still matches the step regex, and confirmed labels agree with the link. It also checks that every accepted proposal still has its version snapshot. Exit code 1 means drift; fix the link or the label before trusting the store.

`--verbose` adds per-step `matched` / `linked` / `ambiguity` and any confirmed event no step explains. Counts and maturity are derived from confirmed links at read time, so there is no stored counter to resynchronise.

## Evolve a pattern

Pattern changes go through a proposal, never a hand edit:

```powershell
python src/manage_memory.py audit --verbose --case-id CASE-008
python src/manage_memory.py evolve propose --input data/proposals/CASE-008_add_S7.json
python src/manage_memory.py evolve list --status ready
python src/manage_memory.py evolve accept PROP-... --basis "two incidents continued into S7"
python src/manage_memory.py evolve rollback --case-id CASE-008 --to 1 --basis "false matches increased"
```

`metrics` is the input to a proposal: `matched` vs `linked` per step shows ambiguity, and `unexplained in <incident>` lists confirmed events that no step explains — those are the candidate new stages.

A proposal is evidence plus a patch: `case_id`, `base_version`, `operation`, `rationale`, `supporting_event_ids`, and the operation-specific fields. The gate checks version freshness, that the supporting events belong to incidents already confirmed for the case, that at least two incidents support the change, that the regex matches them and no other case's events, and that a shadow re-run over every stored incident keeps top-1, `strong` count, and required coverage from dropping. Failing proposals stay `candidate` and cannot be accepted.

Use `required: false` when a stage is only present in some incidents. Marking a step required when older incidents lack it will be rejected, because their `strong` would drop.

`--auto` accepts completion-class changes (`add_step`, widening `extend_step`, `add_source`) without a second review, but only from maturity `repeated`; `set_required` and any narrowing need an explicit human `accept`. Nothing triggers by itself. After accepting, link the supporting events to the new step and run `audit`.

## No-candidate handling

No candidate means the current rules did not find a supported pattern. It does not establish that the activity is benign or novel. Review extracted behavior, sensor coverage, truncation, encoding, and whether a current pattern needs a carefully evidenced variant before adding a new pattern.
