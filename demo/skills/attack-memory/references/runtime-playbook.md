# Runtime Playbook

Run commands from `demo/`. Supplied file paths are relative to the demo root. Every write is
journaled; after a batch of writes, the two gates are `audit` and `catalog state --check README.md`.

## Trust gates at a glance

| Command | Question it answers | On failure |
|---|---|---|
| `catalog validate` | Are the catalog, registry, ledgers and snapshots structurally consistent? | exit 1; fix the named object |
| `audit` | Do all claims (links, exceptions, versions, proposals, corrections, journal) agree with primary data? | exit 1; fix or `catalog repair` |
| `catalog state --check README.md` | Does the documented state match the store? | regenerate the block with `catalog state` |
| `catalog repair` | Is there derived state that can be safely rebuilt? | dry-run shows the plan; `--apply` writes it |

## Retrieve and interpret

```powershell
python src/run_demo.py --input data/raw_logs.csv
python src/run_demo.py --input data/raw_logs.csv --json
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
python src/run_demo.py --input data/raw_logs.csv --incident-id INC-CASE-005-001
```

`--min-tier` defaults to `weak`, so lexical-only candidates are hidden. Pass
`--min-tier keyword_only` to see them, `--min-tier medium` for triage that only accepts
chain-level evidence.

The CLI partitions rows by known `incident_id`. Rows without one are grouped by `batch_id` and then
split by the `host=` value in the content, because one chain cannot span two hosts. Every unlabeled
group is a candidate scope, not a proven incident. Use `--incident-id` to select one known incident
from a cumulative CSV.

For each case candidate, inspect:

- `matched_steps / total_steps`: aligned steps, all of them;
- `matched_required_steps / required_steps`: the required skeleton that decides `shape` and `tier`;
- `detected_steps`: steps with at least one detection of any source;
- `evidence`: **every** source-compatible detection for a step, time ordered, with `event_ids`,
  `sources`, per-detection provenance, `aligned_event_id` (the one used for alignment), and
  `required`;
- `unaligned_detections`: detections the alignment did not use, with reason
  `extra_detection_for_S<n>` (same step already aligned) or `out_of_order`;
- `source_mismatches`: action-shaped rows from sources not listed for that step; review rather than
  discard automatically;
- `order_ok` / `order_assessable`: time order over the **required** skeleton (what `strong` uses);
- `unobserved_required_steps` / `unobserved_optional_steps`: steps with no detection at all, split by
  requiredness — never "detected but unaligned";
- `keyword_score`, `keyword_details`: auxiliary lexical signals;
- `evidence_confidence`, `historical_precision`: a deterministic evidence ratio
  (`matched_required / required_steps × historical linked/matched step precision`) and the case's
  historical step precision. Neither is a probability, and neither changes `tier`;
- `prior_rejections`: reviewed corrections for this case (and scope incident), with reason and basis.
  A prior rejection is a tested boundary, not a precedent;
- `pattern_scope.variant_note`, `negative_and_unknown_evidence.not_observed`, `provenance`: the
  author's caveats and evidence status, surfaced so a single-sample pattern is not over-generalized;
- `version`: the pattern version that produced this result;
- `family_id`: the case's family; family-level steps are printed separately as context and never
  change `tier`;
- `weak_kind`: for `weak` only — `prefix` (first required step, chain may be early), `tail` (a later
  specific step while earlier required steps are missing), `generic_only` (only generic steps),
  `mismatch_only` (no aligned evidence, only source mismatches), `unaligned_only` (defensive
  fallback);
- `tier` and `shape`: deterministic evidence classes and alignment shape, not probabilities.

MITRE technique IDs are catalog metadata. They are not inferred from the logs and do not rank
candidates.

Candidate tiers are deterministic presentation hints over the **required** skeleton: all required
steps aligned in assessable, consistent time order with at least one non-generic required step =
`strong`; at least two non-generic required steps aligned = `medium`; some action evidence (aligned,
extra, or source-mismatched) = `weak`; lexical-only = `keyword_only`. An optional step may be missing
without changing shape or tier. The Agent/analyst still makes the incident and case decision.

The scope header also shows review state (`reviewed confirmed=8`). A scope whose only reviewed links
are `fixture` is synthetic and must not be reported as a real observation.

`--json` has a stable contract: top-level `schema_version: 1`, `evidence_confidence_note`, `input`,
`log_count`, `min_tier`, `scopes[]`; each candidate additionally carries `historical_precision`,
`evidence_confidence`, `prior_rejections`.

## Recall policy (retrieval → lookup)

Retrieving a candidate is not the same as recalling a precedent. Decide what to read from the tier
and `weak_kind`:

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
python src/lookup_case_logs.py --case-id CASE-002 --exclude-incident INC-CASE-002-001
python src/lookup_case_logs.py --case-id CASE-005 --include-related --status related
python src/lookup_case_logs.py --case-id CASE-005 --json
```

Rules:

- Exclude the incident under judgement (`--exclude-incident`); recalling its own reviewed labels is
  answer leakage.
- Present recalled rows as **step examples**, not case conclusions. When a weak match is used at all,
  say which step matched, whether it is generic, which required steps are absent, and how many source
  mismatches exist.
- Related variants carry no case label; read them with `--include-related`. They are family context,
  not confirmed precedents.
- Do not let a recalled complete chain "fill in" a partial input. The gap is the finding, not a prompt
  to complete it.
- A `weak` result must never be written up as "same attack"; at most it is "same single behavior,
  different technique".
- Family evidence (`ransomware/S9`, `supply-chain/S4`, …) is context, not a case conclusion. It can
  explain a variant that has no case candidate, but it never raises the case tier.
- A merged (`retired`) source is followed by `lookup_case_logs` and shown as `alias_of`; `--json` adds
  `alias_of` and `resolved_case_id`. `run_demo` scores active patterns only.

## New observations

Input CSV requires `timestamp`, `source`, `log_id`, and `content`; `event_id`, `batch_id`, and
`incident_id` are optional. Ingest appends, assigns IDs if absent, leaves `case_id` blank, and
withholds a supplied `incident_id`:

```powershell
python src/ingest_logs.py --input data/incoming_batch.csv
```

Use `--allow-incident-id` only when the batch has already been correlated by a human, otherwise an
input file could claim membership in a known incident without review.

Do not treat the pattern match as the incident grouping result. Review cross-alert linkage separately,
then append a relation:

```powershell
python src/manage_memory.py review link --event-ids EVT-123 --incident-id INC-123 --case-id CASE-008 \
  --step-id S1 --status candidate --basis "Same host and URI; request identifier absent"
python src/manage_memory.py review associate --event-ids EVT-9,EVT-10 --incident-id INC-9 \
  --case-id CASE-005 --basis "same ransomware family, different tooling"
```

`candidate`, `confirmed`, `rejected`, `fixture`, and `related` are allowed statuses. `fixture` is
reserved for synthetic validation data and must not be presented as a real observation. `related`
means the incident belongs to the case's family or shares a step, without confirming the canonical
chain: it writes no `case_id` label, but counts as support for a proposal. Link rows are append-only;
later decisions supersede earlier ones operationally while preserving the history.

`review link` verifies that the event content matches the step's `action_regex` before writing. If the
step genuinely does not match, the step choice is probably wrong; do not force it. `--force` exists
only for a reviewed exception, requires a non-empty `--basis`, and records the row in
`data/link_exceptions.json`. `audit` waives exactly that row and reports `forced exceptions=N`; an
exception without a live link or a basis fails the audit.

Confirmed and rejected decisions also update the CSV's `case_id`/`incident_id` analysis columns.
`confirmed` sets them; `rejected` clears them only when it names the same case and incident, or
withdraws an incident label that ingestion supplied without a case. `candidate`, `related`, and
`fixture` leave labels untouched. The raw `content`, timestamp, source, log ID, extra columns, and
line endings remain unchanged.

## Negative memory

When a reviewed match is rejected, record the boundary:

```powershell
python src/manage_memory.py catalog correction add --incident-id INC-123 --case-id CASE-005 \
  --reason-code generic_only --event-ids EVT-123 --basis "only a shared whoami probe; no case step"
python src/manage_memory.py catalog corrections --case-id CASE-005
```

Reason codes: `generic_only`, `source_mismatch`, `incomplete_chain`, `wrong_family`,
`insufficient_evidence`, `other`. Decisions: `reject_match` (this evidence is not this case) or
`reject_case` (the incident is not this case at all). The ledger is append-only; duplicate exact
rejections are rejected. `audit` re-checks that every correction still points at a real case,
incident and event, and `run_demo` surfaces matching records as `prior_rejections`.

## Audit

```powershell
python src/manage_memory.py audit
python src/manage_memory.py audit --verbose --case-id CASE-005
python src/manage_memory.py audit --json
```

The audit re-reads every link row and checks that the event exists, the case/step exist, the recorded
`action_id` matches the step, the event content still matches the step regex (unless a reviewed force
exception waives it), and confirmed labels agree with the link. It checks force exceptions, version
snapshots, accepted proposals, candidate state, families, migrations, admissions, chains, lifecycle,
retention archives, corrections, and the write journal. `--json` emits
`{ok, problems, warnings, checks, counts, forced_exceptions}`. Exit code 1 means drift; fix the link,
the label or the derived state before trusting the store. An `unfinished transaction` problem is the
crash window: inspect it, then run `catalog repair --dry-run` and `--apply`.

`--verbose` adds per-step `matched` / `linked` / `ambiguity` and any confirmed event no step explains.
Counts and maturity are derived from confirmed links at read time, so there is no stored counter to
resynchronise.

## State, repair and snapshots

```powershell
python src/manage_memory.py catalog state
python src/manage_memory.py catalog state --json
python src/manage_memory.py catalog state --check README.md
python src/manage_memory.py catalog repair                 # dry run: prints the safe plan
python src/manage_memory.py catalog repair --apply
python src/manage_memory.py catalog snapshot --all
python src/manage_memory.py catalog snapshot --case-id CASE-009
```

`catalog state` is the single source of documented numbers; the README block between
`<!-- STATE:START -->` and `<!-- STATE:END -->` must match it byte for byte. `catalog repair` only
rebuilds derived state (labels from the latest reviewed link, missing snapshot baselines, orphan
admissions), is idempotent, and records applied fixes in `repair_log.json`. It never deletes raw logs,
links, cases, candidates or proposals. `catalog snapshot` writes missing `vNNN` files from the current
catalog as **baselines**, not historical replays; normal versions are written by `catalog add`,
proposal accepts and migrations.

## Evolve a pattern

Pattern changes go through a proposal, never a hand edit:

```powershell
python src/manage_memory.py audit --verbose --case-id CASE-008
python src/manage_memory.py evolve propose --input data/proposals/CASE-008_add_S7.json
python src/manage_memory.py evolve list --status ready
python src/manage_memory.py evolve accept PROP-... --basis "two incidents continued into S7"
python src/manage_memory.py evolve rollback --case-id CASE-008 --to 1 --basis "false matches increased"
```

`metrics` is the input to a proposal: `matched` vs `linked` per step shows ambiguity, and
`unexplained in <incident>` lists confirmed events that no step explains — those are the candidate new
stages.

A proposal is evidence plus a patch: `case_id`, `base_version`, `operation`, `rationale`,
`supporting_event_ids`, and the operation-specific fields (`step`, `step_id`, `action_regex`,
`add_sources`, `required`, or `order`). The gate checks version freshness; that the supporting events
belong to incidents already confirmed or related for the case; that at least two incidents support the
change; that the regex matches them and no other case's events; that a shadow re-run over every
stored incident keeps top-1, `strong` count, and required coverage from dropping; and that the
**held-out** confirmed incidents (not cited by the proposal) do not lose `strong` or coverage. Metrics
recorded on the proposal include `foreign_matches`, `top1_changes`, `coverage_before/after`,
`strong_before/after`, `narrowing`, and `heldout_*`. Failing proposals stay `candidate` and cannot be
accepted.

`add_step` defaults to `required: false`. A stage only some incidents reach must stay optional;
marking it required drops existing `strong`/coverage incidents and is rejected. `--auto` accepts
completion-class changes (`add_step`, widening `extend_step`, `add_source`) only when the gate marked
them `auto_eligible`; `set_required`, narrowing and `reorder_steps` need an explicit human accept.
Nothing triggers by itself. After accepting, link the supporting events to the new step and audit;
`evolve rollback` is the way back.

## Candidates

```powershell
python src/manage_memory.py catalog stage --signature "F1::Spring4Shell" --family-id web-exploit \
  --incident-id SIM-INC-1002 --event-ids SIM-1002-1 --source-batch SIM-B-1002
python src/manage_memory.py catalog candidates --by-group
python src/manage_memory.py catalog candidates --status promotable
python src/manage_memory.py catalog merge --primary CAND-0002 --alias CAND-0058 --basis "same signature_key"
python src/manage_memory.py catalog split --primary CAND-0002 --alias CAND-0058 --basis "wrong merge"
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
```

A candidate is one behavioural signature with one or more incidents. `catalog stage` validates that
the events exist and belong to the named incident. One incident is `provisional`; a second with the
same `signature_key` is `promotable`. `catalog merge` requires the same family and key unless
`--allow-ungrouped` is explicit: candidates without discriminative terms land in the visible
`ungrouped` bucket and have no explainable equivalence class. The primary absorbs the alias incidents
and records `aliases`/`merged_from`; a merged alias keeps its own row for reversibility, and
`catalog split` reverses a non-promoted merge. Promotion needs an authored pattern
(`catalog add --from-candidate`); a provisional candidate needs `--force` after review. Incidents
added to an already promoted cluster become `pending_case_links`, not a second case.

## Case lifecycle, aliases and JSON contracts

```powershell
python src/manage_memory.py catalog merge-case --source CASE-009 --target CASE-001 --basis "alias duplicate"
python src/manage_memory.py catalog split-case --case-id CASE-009 --basis "not a duplicate"
python src/manage_memory.py catalog retire --case-id CASE-009 --basis "obsolete"
python src/manage_memory.py catalog reactivate --case-id CASE-009 --basis "restored"
python src/manage_memory.py catalog review-case --case-id CASE-009 --basis "reviewed by analyst" --reviewer analyst
```

A merge is a conservative alias: source becomes `retired` with `merged_into=target`; links and steps
are not rewritten, and the target must be active and in the same family. `merge-case`/`split-case`
commit patterns, candidates and the lifecycle ledger in one journaled transaction, like every other
mutating command. Retired cases keep their history but are skipped by retrieval and shown as
`retired=N` in `catalog families`.
`lookup_case_logs --case-id <source>` follows `merged_into` and returns source ∪ target observations
with `alias_of` / `resolved_case_id`; its JSON also carries `schema_version: 1`. `run_demo` scores
active patterns only and does not fold a merged source's evidence into the target score.
`review-case` removes only the `unreviewed` marker; the admission record stays for traceability.

## No-candidate handling

No candidate means the current rules did not find a supported pattern. It does not establish that the
activity is benign or novel. Review extracted behavior, sensor coverage, truncation, encoding, and
whether a current pattern needs a carefully evidenced variant before adding a new pattern.
