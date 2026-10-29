# Memory Schema

The catalog is `data/attack_patterns.json` with a top-level `schema_version` and an `attack_patterns` array. Each pattern includes:

| Field | Meaning |
|---|---|
| `case_id` | Stable ID for a reusable attack behavior pattern (`CASE-NNN`). |
| `name`, `summary`, `pattern_scope` | Human-readable identity, scope, and variant caveats. |
| `mitre` | ATT&CK technique IDs (`T1190`, `T1059.004`). Displayed as metadata; not inferred from logs and not a ranking signal. |
| `steps` | Ordered behavior steps. Each step needs `step_id`, unique ascending `order`, `action_id`, executable `action_regex`, and `expected_sources` (use `["any"]` to accept every source). |
| `steps[].required` | `true` (default) or `false`. Shape and `strong` use the required skeleton only, so an optional later stage does not break shorter incidents. |
| `version`, `supersedes`, `updated_at` | Written by the evolution flow. Missing `version` means 1. Never edit these by hand. |
| `retrieval.keywords` | Case-insensitive terms, each contributing auxiliary ranking points. |
| `retrieval.pattern_probes` | Regex probes for structural lexical recall; not the primary action definition. |
| `negative_and_unknown_evidence` | Evidence limits and explicitly unobserved behavior; surfaced in CLI output. |
| `provenance` | Pattern-level evidence status and optional aggregate real-observation count; do not embed case IDs for individual incidents or concrete alert content. |

Raw alert rows live in `data/raw_logs.csv`. Event-to-incident/pattern-step rationale and decision history live in `data/event_pattern_links.csv`. A pattern is not an incident; one incident can support one or more patterns, and one pattern can describe many incidents. The action-to-pattern reverse index is built in memory from `steps`; do not persist a duplicate index in the pattern JSON.

`case_id` on a raw CSV row is an analysis label, not an original log field. Ingestion leaves it empty. A confirmed decision fills it; rejected decisions can clear it. The relation CSV preserves rationale and history.

## One authoritative action definition

`action_id` is a detector name, not a free-form tag. Across the whole catalog an `action_id` must have exactly one `action_regex` and one `generic` flag; `catalog add` and `catalog validate` reject a conflicting redefinition, so a pattern can never match rows its own regex does not match. To describe a variant, use a new `action_id`. Within a single pattern each `action_id` may appear only once.

## Validation rules

`validate_pattern` rejects a catalog that would silently break recall:

- missing or non-string `case_id`, `name`, `summary`;
- `mitre` that is not a list of technique IDs;
- `retrieval.keywords` / `pattern_probes` that are not lists of non-empty strings;
- a probe that matches the empty string, and therefore every log;
- empty `steps`, duplicate `step_id`, duplicate `action_id`, or non-ascending `order`;
- an `action_regex` shorter than three characters or one that matches the empty string (`""`, `".*"`, `"\\s*"`);
- `expected_sources` that is a string instead of a list, empty, or holds a non-string;
- `generic` that is not a boolean;
- `required` that is not a boolean, or a pattern whose steps are all optional;
- `family_id` that is present but not a non-empty string;
- `version` / `supersedes` that is not a positive integer.

## Adding a pattern

Copy one pattern object to a separate JSON file, assign a new ID, set `family_id` to an existing family, and provide evidence-backed steps and regexes. Do not invent expected sources or claim optionality from one sample. A new case needs **at least two supporting incidents** whose events match the pattern's steps:

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog add --input data/new_pattern.json --supporting-incident-ids INC-1,INC-2
```

`catalog add` runs the same checks plus the whole-catalog action-library check, then atomically replaces the catalog. `--force` exists only for a reviewed singleton. `catalog validate` and `audit` also check that the new `family_id` exists in `data/families.json` and that the case is listed under it.

## Variant association

A unit that shares one step with a case, or belongs to the same attack family with different
tooling, is not a new case. Record it with a `related` link:

```powershell
python src/manage_memory.py review associate --event-ids EVT-1,EVT-2 --incident-id INC-9 \
  --case-id CASE-005 --basis "same ransomware family, different tooling"
```

`related` writes no `case_id` label and does not change `maturity` or the confirmed incident set. It does count as support for a pattern-evolution proposal, which is how a family of variants enriches an existing case without fragmenting it.

## Families

Every pattern carries a `family_id`; `data/families.json` lists the families, their `case_ids`, and optional family-level `steps`:

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

The registry and the catalog must agree: a case has exactly one family, every `family_id` exists, and every `case_ids` entry exists. `catalog validate` and `audit` enforce this. A family step is a broad behavior that does not belong in a case's required chain: it is linked only with `related`, never `confirmed`, is audited against the family regex when a historical link still names that step, and is surfaced by `run_demo` as family-level evidence without changing the case tier. Family step `action_id`s must not redefine another family step's regex.

## Migrations

Schema moves that are not pattern deltas are recorded in `data/pattern_migrations.json`, not `pattern_proposals.json`:

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

`catalog migrations` lists them. `catalog validate` and `audit` check that the snapshot exists, the versions are consecutive, the step is no longer in the case, and the family step exists. A migration does not run the proposal gate; it is an explicit reviewed change with its own ledger.

## Case lifecycle

`data/case_lifecycle.json` records case-level lifecycle events:

```json
{"event_id": "LIF-0001", "action": "merge", "case_id": "CASE-009", "target": "CASE-001",
 "basis": "alias duplicate", "reviewer": "analyst", "candidate_ids": ["CAND-0001"]}
```

Actions are `merge`, `split`, `retire`, `reactivate`. A merge is a conservative alias merge: the
source gets `status: "retired"` and `merged_into: target`; steps and existing links are not rewritten.
The target must be active and in the same family. `split` reverses the latest merge. `retire` and
`reactivate` are independent. Retired cases keep their history but are skipped by `retrieve`, and
`catalog families` reports `retired=N`. `catalog validate` / `audit` check the latest lifecycle event
against the case's `status` / `merged_into`.

## Admissions

A model- or analyst-added case gets an admission record in `data/case_admissions.json`:

```json
{
  "admission_id": "ADM-CASE-009",
  "case_id": "CASE-009",
  "source": "candidate:CAND-0001",
  "status": "unreviewed",
  "created_at": "...",
  "reviewed_at": null,
  "reviewed_by": null,
  "review_basis": ""
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

A technique that belongs to no existing case is recorded in `data/case_candidates.json`, not in the catalog:

```json
{
  "schema_version": 1,
  "candidates": [
    {
      "candidate_id": "CAND-0001",
      "signature": "F1::Spring4Shell",
      "signature_key": "cb7586b1291ed571",
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

`signature` is the legacy exact staging label. `signature_key` / `signature_terms` are the deterministic features from `signatures.py`: CVE, product, primary action and all technique terms. The key is family-scoped and is used for grouping (`catalog candidates --by-group`); `catalog merge` performs an explicit same-family/same-key merge, and `catalog split` reverses a non-promoted merge.

Status is `provisional` for one incident, `promotable` for two or more, `promoted` once a case exists, `merged` for an alias absorbed by a primary, and `rejected` if the hypothesis is discarded. A merge adds the alias incidents to the primary and records `aliases` / `merged_from`; the alias keeps its own incidents and `merged_into` for reversibility. If the primary is already promoted, its status stays `promoted` and the new incidents go to `pending_case_links` instead of creating a second case. `audit` checks the alias back-reference, the incident subset, promoted case existence, and status/incident counts.

Promotion still needs an authored, schema-valid pattern:

```powershell
python src/manage_memory.py catalog candidates --status promotable
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
```

A provisional candidate needs `--force` after review. The primary's incident IDs (including merged aliases) become the support set, so the same evidence checks as `catalog add --supporting-incident-ids` still apply.

## Pattern versions and proposals

An accepted change never edits history in place:

- the previous pattern is snapshotted to `data/pattern_versions/<CASE>/vNNN.json`;
- the new version is written to the catalog and snapshotted too;
- `data/pattern_proposals.json` keeps every proposal with its evidence, gate metrics and decision.

A proposal names `case_id`, `base_version`, `operation` (`add_step`, `extend_step`, `add_source`, `set_required`, `reorder_steps`), a `rationale`, and `supporting_event_ids`. The supporting events are the evidence: they must exist, belong to incidents **confirmed or related** to the case, and be matched by the proposed step. Two independent incidents are the minimum. `--auto` is limited to completion-class operations; `set_required` always needs an explicit accept. `reorder_steps` requires an `order` list containing every step exactly once; it uses confirmed incidents, keeps `strong`/coverage from dropping, and is never auto-accepted.

## Observation counts

There is no stored observation counter. The confirmed incident count, fixture count and maturity are derived from `event_pattern_links.csv` at read time: distinct confirmed incidents, fixtures ignored, `related` excluded from the confirmed count. `audit` therefore only checks links, labels and accepted-proposal snapshots.

Maturity is derived the same way: 1 confirmed incident is `single_sample`, 2 is `repeated`, 3 or more is `validated`. Evolution proposals are only auto-eligible from `repeated` upward.
