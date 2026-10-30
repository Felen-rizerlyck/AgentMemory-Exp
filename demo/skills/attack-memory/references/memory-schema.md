# Memory Schema

The store is plain CSV/JSON. This file describes every object, how it is validated, and which
invariant the audit enforces for it.

| File | Format | Written by |
|---|---|---|
| `data/attack_patterns.json` | JSON catalog | `catalog add`, `evolve accept`, `catalog rollback`, lifecycle commands |
| `data/raw_logs.csv` | CSV rows | `ingest_logs.py`, derived label updates from `review link` |
| `data/event_pattern_links.csv` | CSV append-only | `review link`, `review associate` |
| `data/incident_chains.json` | JSON | `catalog chains --rebuild`, `review stage` |
| `data/pattern_versions/<CASE>/vNNN.json` | immutable JSON | `catalog add`, proposal accept, migrations, `catalog snapshot` |
| `data/families.json` | JSON registry | reviewed taxonomy edits |
| `data/pattern_migrations.json` | append-only ledger | reviewed schema migrations |
| `data/case_lifecycle.json` | append-only ledger | `merge-case`, `split-case`, `retire`, `reactivate` |
| `data/case_candidates.json` | JSON | `catalog stage/merge/split`, promotion |
| `data/case_admissions.json` | append-only ledger | `catalog add`, `review-case` |
| `data/pattern_proposals.json` | append-only ledger | `evolve propose/accept/reject` |
| `data/corrections.json` | append-only ledger | `catalog correction add` |
| `data/link_exceptions.json` | append-only ledger | `review link --force` (created on first force) |
| `data/signature_lexicon.json` | JSON vocabulary | reviewed edits; built-in fallback |
| `data/ops_journal.jsonl` | append-only journal | every `storage.commit()` |
| `data/repair_log.json` | append-only ledger | `catalog repair --apply` (created on first apply) |
| `data/retention_tombstones.json` | JSON | `catalog retention --apply` |
| `data/archive/<month>/` | gzip segments | `catalog retention --apply` |

## Pattern catalog

The catalog is `data/attack_patterns.json` with a top-level `schema_version` and an `attack_patterns`
array. Each pattern includes:

| Field | Meaning |
|---|---|
| `case_id` | Stable ID for a reusable attack behavior pattern (`CASE-NNN`). |
| `name`, `summary`, `pattern_scope` | Human-readable identity, scope, and variant caveats. |
| `mitre` | ATT&CK technique IDs (`T1190`, `T1059.004`). Displayed as metadata; not inferred from logs and not a ranking signal. |
| `steps` | Ordered behavior steps. Each step needs `step_id`, unique ascending `order`, `action_id`, executable `action_regex`, and `expected_sources` (use `["any"]` to accept every source). |
| `steps[].required` | `true` (default for existing patterns) or `false`. Shape and `strong` use the required skeleton only, so an optional later stage does not break shorter incidents. New steps added through `add_step` default to `false`. |
| `version`, `supersedes`, `updated_at` | Written by the evolution flow. Missing `version` means 1. Never edit these by hand. |
| `review_status`, `admission_id`, `reviewed_at`, `reviewed_by` | Review provenance for an auto-added case. `review_status`/`reviewed_at`/`reviewed_by` are administrative and are excluded from snapshots. |
| `provenance` | `created_at`, `source`, `updated_at`, `admission_id`, and pattern-level evidence status. Do not embed incident IDs or alert content. |
| `retrieval.keywords` | Case-insensitive terms, each contributing auxiliary ranking points. |
| `retrieval.pattern_probes` | Regex probes for structural lexical recall; not the primary action definition. |
| `negative_and_unknown_evidence` | Evidence limits and explicitly unobserved behavior; surfaced in CLI output. |

Raw alert rows live in `data/raw_logs.csv`. Reviewed relations live in
`data/event_pattern_links.csv`. A pattern is not an incident; one incident can support one or more
patterns, and one pattern can describe many incidents. The action-to-pattern reverse index is built
in memory from `steps`; do not persist a duplicate index in the pattern JSON.

`case_id` on a raw CSV row is an analysis label, not an original log field. Ingestion leaves it empty.
A confirmed decision fills it; a rejected decision can clear it. The relation CSV preserves rationale
and history.

## One authoritative action definition

`action_id` is a detector name, not a free-form tag. Across the whole catalog an `action_id` must have
exactly one `action_regex` and one `generic` flag; `catalog add` and `catalog validate` reject a
conflicting redefinition, so a pattern can never match rows its own regex does not match. To describe
a variant, use a new `action_id`. Within a single pattern each `action_id` may appear only once.

## Validation rules

`validate_pattern` rejects a catalog that would silently break recall:

- missing or non-string `case_id`, `name`, `summary`;
- `mitre` that is not a list of technique IDs;
- `retrieval.keywords` / `pattern_probes` that are not lists of non-empty strings;
- a probe that matches the empty string, and therefore every log;
- empty `steps`, duplicate `step_id`, duplicate `action_id`, or non-ascending `order`;
- an `action_regex` shorter than three characters or one that matches the empty string (`""`, `".*"`, `"\\s*"`);
- `expected_sources` that is a string instead of a list, empty, or holds a non-string;
- `generic` or `required` that is not a boolean, or a pattern whose steps are all optional;
- `family_id` that is present but not a non-empty string;
- `version` / `supersedes` that is not a positive integer.

## Adding a pattern

A new case is admitted only with **support evidence**, not with an authored narrative.
`pattern_support_report` computes, per supporting incident:

- which required steps the incident's events match (union across incidents is the coverage);
- the incident's tier (`strong`/`medium`/`weak`/…);
- per-incident coverage ratio and missing steps.

The gate rejects the add unless every required step is covered by the union of the supporting
incidents and at least one supporting incident reaches `strong`/`medium` on its own. `--force` is the
reviewed exception for a singleton: it waives the coverage rules but records `single_sample` and the
per-incident `support_coverage` in the admission, so a reviewer sees "1/3 required steps, single
sample" instead of a bare "added".

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog add --input data/new_pattern.json --supporting-incident-ids INC-1,INC-2
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
```

`catalog add` runs the schema checks plus the whole-catalog action-library check, allocates `v001`,
builds the admission record, and commits `attack_patterns.json` + `case_admissions.json` +
`pattern_versions/<CASE>/v001.json` in one journaled transaction. `catalog add --from-candidate` uses
all events owned by the candidate's incidents as support (staged event IDs are only a lower bound)
and marks the candidate `promoted` in the same transaction.

## Version snapshots

- `catalog add` and `catalog add --from-candidate` write `v001` at creation.
- `evolve accept` snapshots the old and the new version before updating the catalog.
- Reviewed migrations write the `vNNN` snapshot the migration record names.
- `catalog snapshot --all` / `--case-id` backfill missing version numbers from the **current catalog**
  as baselines. They do not invent history; the journal records the backfill basis.
- `audit_versions` requires a snapshot for every version `1..current`, with matching `version` and
  `case_id`. It does not judge whether a baseline is "true" history.
- `evolve rollback --to N` restores a snapshot's content; the restored pattern keeps being a normal
  catalog entry, and the audit re-checks its version files.

Snapshot payloads exclude `review_status`, `reviewed_at` and `reviewed_by`; the promise is
"same behavioral content", not "same review marker".

## Variant association

A unit that shares one step with a case, or belongs to the same attack family with different tooling,
is not a new case. Record it with a `related` link:

```powershell
python src/manage_memory.py review associate --event-ids EVT-1,EVT-2 --incident-id INC-9 \
  --case-id CASE-005 --basis "same ransomware family, different tooling"
```

`related` writes no `case_id` label and does not change `maturity` or the confirmed incident set. It
does count as support for a pattern-evolution proposal, which is how a family of variants enriches an
existing case without fragmenting it. Rejecting a match is a different act: record the boundary in
`corrections.json` (below), not by deleting history.

## Families

Every pattern carries a `family_id`; `data/families.json` lists the families, their `case_ids`, and
optional family-level `steps`:

```json
{
  "schema_version": 1,
  "families": [
    {
      "family_id": "ransomware",
      "name": "勒索与数据破坏",
      "case_ids": ["CASE-005"],
      "steps": [
        {
          "step_id": "S9",
          "action_id": "fa_recovery_or_encrypt_variant",
          "label": "恢复能力破坏/批量加密变体",
          "action_regex": "(?i)vssadmin|bcdedit|gpg|openssl\\s+enc",
          "expected_sources": ["hids"],
          "generic": true
        }
      ]
    }
  ]
}
```

The registry and the catalog must agree: a case has exactly one family, every `family_id` exists, and
every `case_ids` entry exists. `catalog validate` and `audit` enforce this. A family step is a broad
behavior that does not belong in a case's required chain: it is linked only with `related`, never
`confirmed`, is audited against the family regex when a historical link still names that step, and is
surfaced by `run_demo` as family-level evidence without changing the case tier. Family step
`action_id`s must not redefine another family step's regex.

## Migrations

Schema moves that are not pattern deltas are recorded in `data/pattern_migrations.json`, not
`pattern_proposals.json`:

```json
{
  "migration_id": "MIG-CASE-005-v3",
  "case_id": "CASE-005",
  "from_version": 2,
  "to_version": 3,
  "kind": "move_step_to_family",
  "step_id": "S9",
  "family_id": "ransomware",
  "basis": "reviewed schema migration",
  "decided_at": "...",
  "snapshot": "pattern_versions/CASE-005/v003.json"
}
```

`catalog migrations` lists them. `catalog validate` and `audit` check that the snapshot exists, the
versions are consecutive, the step is no longer in the case, and the family step exists. A migration
does not run the proposal gate; it is an explicit reviewed change with its own ledger.

## Case lifecycle

`data/case_lifecycle.json` records case-level lifecycle events:

```json
{"event_id": "LIF-0001", "action": "merge", "case_id": "CASE-009", "target": "CASE-001",
 "basis": "alias duplicate", "reviewer": "analyst", "candidate_ids": ["CAND-0001"]}
```

Actions are `merge`, `split`, `retire`, `reactivate`. A merge is a conservative alias merge: the
source gets `status: "retired"` and `merged_into: target`; steps and existing links are not rewritten.
The target must be active and in the same family. `split` reverses the latest merge. `retire` and
`reactivate` are independent. All lifecycle writes are committed through `storage.commit()`;
`merge-case`/`split-case` stage the catalog, candidate store and lifecycle ledger together as one
transaction. Retired cases keep their history but are skipped by `retrieve`, and `catalog families`
reports `retired=N`. `catalog validate` / `audit` check the latest lifecycle event against the case's
`status` / `merged_into`.

Alias semantics: `lookup_case_logs --case-id <source>` follows `merged_into` recursively, displays
`alias_of` / `resolved_case_id`, and returns observations from source and target labels; the source's
confirmed links are counted under the target only for this read path. `run_demo` scores active
patterns only, so a merged source's historical evidence is not folded into the target score.

## Admissions

A model- or analyst-added case gets an admission record in `data/case_admissions.json`:

```json
{
  "admission_id": "ADM-CASE-009",
  "case_id": "CASE-009",
  "source": "candidate:CAND-0001",
  "basis": "experimental auto-add; awaiting review",
  "status": "unreviewed",
  "created_at": "...",
  "reviewed_at": null,
  "reviewed_by": null,
  "review_basis": "",
  "single_sample": false,
  "support_coverage": {
    "required_steps": ["S1", "S2", "S3"],
    "covered_required": ["S1", "S2", "S3"],
    "missing_required": [],
    "has_strong_medium": true,
    "per_incident": {
      "INC-...": {"covered_required": ["S1"], "required_total": 3, "coverage": 0.333, "tier": "weak"}
    }
  }
}
```

The pattern carries `review_status: "unreviewed"` and `admission_id`. `catalog review-case` flips the
ledger record to `reviewed` and removes only the marker; the `admission_id` stays. `catalog validate`
and `audit` require the ledger and marker to agree, so a marker cannot drift away from its record.
`run_demo` and `lookup` display `UNREVIEWED`.

## Incident chains

`data/incident_chains.json` records every known incident as ordered events, independent of a case:

```json
{
  "incident_id": "SIM-INC-1083",
  "case_id": "CASE-005",
  "events": [
    {"event_id": "SIM-1083-1", "timestamp": "...", "source": "hids",
     "stage": "S9", "stage_kind": "family_step", "label": "...", "stage_order": 9,
     "stage_basis": ""},
    {"event_id": "SIM-1083-2", "timestamp": "...", "source": "dns",
     "stage": "exfiltration", "stage_kind": "annotated", "label": "DNS tunneling",
     "stage_order": 4, "stage_basis": "three DNS events at a two-minute cadence",
     "reviewed_at": "..."}
  ],
  "updated_at": "..."
}
```

Stage kinds are `case_step`, `family_step`, `annotated`, `unclassified`. `catalog chains --rebuild`
derives the chain from raw logs and links but preserves `annotated` events. `review stage` writes an
annotation without touching a case or link. `catalog chain --summarize` groups consecutive
`unclassified` events and suggests labels; it never writes a case automatically. `audit` checks
event existence, stage kind, annotation basis, and case-step references.

## Candidates

A technique that belongs to no existing case is recorded in `data/case_candidates.json`, not in the
catalog:

```json
{
  "schema_version": 1,
  "candidates": [
    {
      "candidate_id": "CAND-0001",
      "signature": "F1::Spring4Shell",
      "signature_key": "cb7586b1291ed571",
      "signature_source": "terms",
      "signature_terms": ["CVE-2022-22965", "spring", "spring4shell", "tomcat"],
      "label": "Spring4Shell CVE-2022-22965",
      "family_id": "web-exploit",
      "status": "promoted",
      "incidents": [
        {"incident_id": "SIM-INC-1002", "event_ids": ["SIM-1002-1"], "source_batch": "SIM-B-1002", "first_seen": "..."}
      ],
      "aliases": ["CAND-0066"],
      "merged_from": ["CAND-0066"],
      "pending_case_links": ["SIM-INC-1073"],
      "created_at": "...",
      "updated_at": "...",
      "promoted_case_id": "CASE-009"
    }
  ]
}
```

`signature` is the legacy exact staging label. `signature_key` / `signature_terms` are deterministic
features from `signatures.py`: CVE, product, primary action and all technique terms. `signature_source`
is `terms` or `fallback`.

- Candidates with discriminative terms group by their deterministic `signature_key`
  (`catalog candidates --by-group`).
- Candidates without terms are **ungrouped** (`signature_key` may be absent or a legacy content hash;
  grouping puts them in one visible `ungrouped` bucket). An ungrouped candidate has no explainable
  equivalence class, so `catalog merge` needs an explicit `--allow-ungrouped` after review; `audit`
  warns about ungrouped candidates instead of failing.
- The product/action vocabulary can be extended through `data/signature_lexicon.json` (products,
  actions). A malformed file falls back to the built-in tables so the demo always runs.

Status is `provisional` for one incident, `promotable` for two or more, `promoted` once a case exists,
`merged` for an alias absorbed by a primary, and `rejected` if the hypothesis is discarded. A merge
adds the alias incidents to the primary and records `aliases` / `merged_from`; the alias keeps its own
incidents and `merged_into` for reversibility. If the primary is already promoted, its status stays
`promoted` and the new incidents go to `pending_case_links` instead of creating a second case. `audit`
checks the alias back-reference, the incident subset, promoted case existence, and status/incident
counts. `audit` also rejects stale tests: staging validates that event IDs exist and belong to the
named incident (via raw labels or latest reviewed links).

Promotion still needs an authored, schema-valid pattern:

```powershell
python src/manage_memory.py catalog candidates --status promotable
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
```

A provisional candidate needs `--force` after review. The primary's incident IDs (including merged
aliases) become the support set, so the same evidence checks as
`catalog add --supporting-incident-ids` still apply.

## Pattern proposals

An accepted change never edits history in place:

- the previous pattern is snapshotted to `data/pattern_versions/<CASE>/vNNN.json`;
- the new version is written to the catalog and snapshotted too;
- `data/pattern_proposals.json` keeps every proposal with its evidence, gate metrics and decision.

A proposal names `case_id`, `base_version`, `operation` (`add_step`, `extend_step`, `add_source`,
`set_required`, `reorder_steps`), a `rationale`, and `supporting_event_ids`. The supporting events are
the evidence: they must exist, belong to incidents **confirmed or related** to the case, and be
matched by the proposed step. Two independent incidents are the minimum.

The gate records, and the audit can re-derive, these metrics:

| Metric | Meaning |
|---|---|
| `support_incidents`, `support_events` | The proposal's own evidence. |
| `confirmed_incidents`, `related_incidents`, `maturity` | Derived context, not gates. |
| `foreign_matches` | Rows the proposed step would also match that belong to another case (raw label or latest reviewed link). Must be 0. |
| `top1_changes` | Shadow re-run: incidents whose retrieval top-1 changes for a reason other than the intended support. Must be empty. |
| `coverage_before/after`, `strong_before/after` | Required coverage and `strong` count over confirmed incidents. Must not drop. |
| `heldout_incidents`, `heldout_coverage_before/after`, `heldout_strong_before/after` | The same checks over confirmed incidents **not** in the support set (keep-better). Must not drop. |
| `narrowing` | Events matched by the old regex but not the new one; any narrowing needs explicit review. |

`add_step` defaults to `required: false`; an explicitly `required: true` completion step will usually
be rejected because required coverage and `strong` drop for incidents that lack it. `--auto` is
accepted only for `add_step`, widening `extend_step` and `add_source` when the gate's
`auto_eligible` is true. `set_required`, narrowing and `reorder_steps` always need an explicit accept.
`reorder_steps` requires an `order` list containing every step exactly once, uses confirmed incidents,
and is never auto-accepted. `evolve rollback` restores a snapshot by version; it is the supported way
to undo a pattern change.

## Link exceptions

A forced link is a reviewed exception. `review link --force` requires a non-empty `--basis` and writes
one record per mismatching event to `data/link_exceptions.json`:

```json
{
  "schema_version": 1,
  "exceptions": [
    {
      "event_id": "EVT-...",
      "incident_id": "INC-...",
      "case_id": "CASE-008",
      "step_id": "S1",
      "decided_at": "2026-10-30T03:07:08Z",
      "basis": "reviewed: source log truncated the payload",
      "reviewer": "analyst"
    }
  ]
}
```

The key is `(event_id, incident_id, case_id, step_id)`; `decided_at` and `reviewer` are recorded but
not part of the identity. `audit_links` waives a regex mismatch only when a matching exception with a
non-empty basis exists, and `audit` reports `forced exceptions=N` so exceptions stay visible.
`audit_link_exceptions` fails on an exception without a matching live link, a missing basis, a
duplicate key, or an exception whose link is `rejected` (a rejected link is already exempt from the
replay, so it must not have an exception). A forced link is never auto-created; the CLI refuses
`--force` without a basis.

## Corrections (negative memory)

`data/corrections.json` records reviewed rejections — the boundaries the memory has already tested:

```json
{
  "schema_version": 1,
  "corrections": [
    {
      "correction_id": "COR-0001",
      "incident_id": "INC-...",
      "case_id": "CASE-005",
      "decision": "reject_match",
      "reason_code": "generic_only",
      "event_ids": ["EVT-..."],
      "basis": "only a shared whoami probe; no case step",
      "reviewer": "analyst",
      "decided_at": "2026-10-30T...Z",
      "created_at": "2026-10-30T...Z"
    }
  ]
}
```

- `decision` is `reject_match` (this evidence is not this case) or `reject_case` (the incident is not
  this case at all).
- `reason_code` is one of `generic_only`, `source_mismatch`, `incomplete_chain`, `wrong_family`,
  `insufficient_evidence`, `other`.
- `basis` is required; `event_ids` are optional but validated (existing, and belonging to the named
  incident when the raw row carries an incident label).
- The ledger is append-only: a later review appends a new record; exact duplicate rejections are
  rejected with a pointer to the existing `correction_id`.
- `audit_corrections` re-checks case/incident/event existence, allowed codes, basis, reviewer,
  timestamps and duplicate records.
- `run_demo` attaches matching records to a candidate as `prior_rejections` (and prints them); a
  correction is a boundary, not a precedent.

## Journal and repair

`data/ops_journal.jsonl` is the write history. `storage.commit()` is the only multi-file writer:

1. render every target and stage temp files (nothing replaced yet);
2. append a `pending` record: `{txn_id, status:"pending", kind, summary, basis, at, files:[{path, sha256}]}`;
3. replace each target;
4. append a `done` record `{txn_id, status:"done", at, files:[...]}`.

If a replace fails, a `failed` record lists the files already applied and the error. `audit_journal`
reports any `pending` transaction without a matching `done` as a problem ("unfinished transaction"),
including which files were applied per the recorded hashes; `audit` treats that as a store problem and
`catalog repair` is the recovery path.

`data/repair_log.json` is append-only and records each applied fix:

```json
{"repair_id": "REP-...-001", "kind": "label", "target": "EVT-...",
 "before": {"case_id": "", "incident_id": ""}, "after": {"case_id": "CASE-008", "incident_id": "INC-..."},
 "basis": "label is a derived cache of the latest reviewed link", "at": "..."}
```

Repair only touches derived state: labels are re-derived from the latest reviewed link, missing
snapshot baselines are written from the current catalog, and orphan admissions (case no longer exists)
are removed. It never deletes raw logs, links, patterns, candidates or proposals. It is idempotent:
a second run finds nothing to repair.

## State block

`state.py` is the single source of documented numbers. `catalog state` renders:

```text
<!-- STATE:START -->
cases                9 (CASE-001..CASE-009)
journal              2 transaction(s), 0 unfinished
audit                clean
<!-- STATE:END -->
```

`catalog state --check <file>` re-renders the block and compares it byte for byte with the block
between the markers; any difference is a failure (`exit 1`). Change the store, or regenerate the block
with `catalog state` — never hand-edit it. `catalog state --json` exposes the same numbers under
`counts` plus the rendered `lines`.

## JSON contracts

`run_demo --json` and `lookup_case_logs --json` carry a top-level `schema_version: 1`; breaking a field
contract requires a version bump. The other machine-readable commands (`audit`, `catalog state`,
`catalog retention`, `catalog repair`) do not carry `schema_version` yet; their shapes are pinned by the
invariant tests, so a breaking change must update tests and docs together.

- `run_demo --json`: `{schema_version, evidence_confidence_note, input, log_count, min_tier, scopes}`.
  Each scope has `scope_type`, `scope_id`, `log_count`, `hosts`, `reviewed_links`,
  `hidden_below_min_tier`, `family_matches`, `candidates`. Each candidate adds
  `historical_precision`, `evidence_confidence` and `prior_rejections` to the match fields.
- `lookup_case_logs --json`: `{schema_version, case_id, incident_id, step_id, excluded_incident,
  alias_of, resolved_case_id, pattern_version, maturity, family_id, review_status, status, count,
  fixture_rows_hidden, derived_real_observations, observations}`.
- `audit --json`: `{ok, problems, warnings, checks, counts, forced_exceptions}`.
- `catalog state --json`: `{counts, lines}`.
- `catalog retention --json`: `{report}` (+ `apply` when `--apply`).
- `catalog repair --json`: `{ok, dry_run, applied, lines, actions, labels, snapshots, admissions, change_count, repair_log}` (+ `txn_id` when applied).

## Observation counts

There is no stored observation counter. The confirmed incident count, fixture count and maturity are
derived from `event_pattern_links.csv` at read time: distinct confirmed incidents, fixtures ignored,
`related` excluded from the confirmed count. `audit` therefore only checks that the claims and files
agree.

Maturity is derived the same way: 1 confirmed incident is `single_sample`, 2 is `repeated`, 3 or more
is `validated`. Evolution proposals are only auto-eligible from `repeated` upward in practice; the
gate also requires at least two confirmed-or-related support incidents.
