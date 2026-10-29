# Attack Memory Demo

A local, file-based memory for attack-pattern review. It stores raw observations, reviewed
event-to-case links, reusable cases, family-level behaviors, staged candidates, pattern versions,
schema migrations, and new-case admissions. Retrieval is rule-based and explainable; nothing runs
in the background.

The demo is deliberately small enough to inspect by hand. It is not a production service: CSV is
the store, there is no reviewer login, and the deployment review gate described below is a policy
you add around the CLI, not something this prototype enforces.

## Quick start

```powershell
cd demo

# 1. Inspect the catalog, family registry, candidates and trust state
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog families
python src/manage_memory.py catalog candidates --by-group
python src/manage_memory.py catalog admissions
python src/manage_memory.py audit

# 2. Retrieve against the stored corpus
python src/run_demo.py --input data/raw_logs.csv --min-tier weak

# 3. Tests
python -m unittest discover -s tests
```

Python 3.11+ is enough; the demo uses only the standard library. All commands are run from
`demo/` (paths inside the CLI are relative to the demo root).

## Mental model

| Object | File | Meaning |
|---|---|---|
| observation | `data/raw_logs.csv` | One sensor row. `case_id`/`incident_id` are analysis labels, not original fields. |
| link | `data/event_pattern_links.csv` | Reviewed event → incident → case/step relation. Append-only; latest decision wins. |
| incident chain | `data/incident_chains.json` | Ordered events per incident with independent stages (`case_step`, `family_step`, `annotated`, `unclassified`). |
| case | `data/attack_patterns.json` | A reusable, ordered attack chain with executable step regexes. |
| family | `data/families.json` | A taxonomy above cases, plus broad family-level steps. |
| candidate | `data/case_candidates.json` | A technique that is not a case yet; 1 incident = `provisional`, 2+ = `promotable`. |
| proposal | `data/pattern_proposals.json` | A candidate delta for an existing case, evaluated by the deterministic gate. |
| version | `data/pattern_versions/<CASE>/vNNN.json` | Immutable snapshot of every accepted or migrated version. |
| migration | `data/pattern_migrations.json` | A reviewed schema move (for example a step from a case into a family). |
| admission | `data/case_admissions.json` | A new-case record and its review status (`unreviewed` / `reviewed`). |
| lifecycle | `data/case_lifecycle.json` | merge/split/retire/reactivate events for cases. |

The pipeline is:

```
raw_logs.csv
  -> retrieval (tier + weak_kind)
  -> reviewed links (confirmed / related / candidate / rejected / fixture)
  -> incident chain (ordered stages, including unclassified behavior)
  -> existing case, family step, annotated stage, or staged candidate
  -> authored pattern (catalog add / add --from-candidate)
  -> versioned case (proposals or reviewed migrations)
  -> audit
```

`event_id` identifies one observation; `incident_id` groups correlated observations; `case_id`
identifies the reusable pattern. Do not conflate them. A case can have many incidents; an incident
can have many events.

## Directory structure

```text
demo/
├── data/
│   ├── attack_patterns.json       # current case catalog; 9 cases, 32 case steps
│   ├── families.json              # 5 families + family-level steps (ransomware/S9, supply-chain/S4)
│   ├── case_candidates.json       # 88 records: 81 active + 7 merged aliases
│   ├── case_admissions.json       # new-case admissions; currently CASE-009 is unreviewed
│   ├── case_lifecycle.json        # merge/split/retire/reactivate ledger (currently empty)
│   ├── pattern_proposals.json     # 2 accepted add_step proposals (CASE-005/007 v1 -> v2)
│   ├── pattern_migrations.json    # 2 reviewed v2 -> v3 moves (S9/S4 into families)
│   ├── pattern_versions/          # immutable snapshots v001..v003 for CASE-005/007
│   ├── raw_logs.csv               # 565 active observations (16 archived)
│   ├── event_pattern_links.csv    # 265 reviewed links
│   ├── incident_chains.json       # 59 incident chains with independent stages
│   ├── archive/2026-10/           # monthly gzip: raw/links/chains/candidates + run manifests
│   ├── retention_tombstones.json  # 1 run; incident summaries + referenced-event tombstones
│   ├── promoted/
│   │   └── CASE-009.json          # authored pattern used to promote CAND-0001
│   ├── proposals/
│   │   └── README.md              # proposal input format
│   └── validation_batches/        # isolated synthetic validation input
├── src/
│   ├── attack_memory/
│   │   ├── storage.py             # CSV/JSON IO, schema validation, link helpers
│   │   ├── retrieval.py           # LCS alignment, tier, weak_kind, evidence
│   │   ├── ingest.py              # append normalized batches; withhold incident labels
│   │   ├── catalog.py             # catalog load/add, versions, maturity, admissions, review-case
│   │   ├── links.py               # link append/audit, family-step links, derived counts
│   │   ├── evolution.py           # proposals, deterministic gate, accept/reject/rollback
│   │   ├── diagnostics.py         # audit aggregation, step statistics, unexplained events
│   │   ├── candidates.py          # candidate store, provisional/promotable, promotion
│   │   ├── families.py            # family registry, family steps, family evidence
│   │   ├── chains.py              # incident chains, stage annotations, summaries
│   │   ├── migrations.py          # reviewed migration ledger
│   │   ├── lifecycle.py           # case merge/split/retire ledger
│   │   ├── retention.py           # incident-level retention classifier/report
│   │   ├── admissions.py          # new-case admission ledger + review marker
│   │   ├── signatures.py          # deterministic candidate signature features (step 1)
│   │   └── manage.py              # the 4-verb CLI
│   ├── run_demo.py                # retrieval CLI; prints case + family evidence
│   ├── lookup_case_logs.py        # stored observations by case/step/status
│   ├── ingest_logs.py             # append a batch CSV
│   └── manage_memory.py           # entry point -> attack_memory.manage.main
├── skills/attack-memory/
│   ├── SKILL.md                   # runtime rules for an agent
│   └── references/
│       ├── runtime-playbook.md    # retrieval/link/audit commands
│       ├── memory-schema.md       # JSON/CSV schemas
│       └── case-write-spec.md     # when and how to write a case
├── tests/
│   └── test_memory.py             # 87 stdlib unittest tests
└── README.md
```

## Command surface

The management CLI has four top-level verbs:

```text
catalog   validate / add / stage / merge / split / merge-case / split-case / retire / reactivate / lifecycle / retention / candidates / chains / chain / families / migrations / admissions / review-case
review    link / associate / stage
evolve    propose / list / accept / reject / rollback
audit     [--verbose] [--case-id CASE]
```

### Catalog

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog add --input data/new_pattern.json --supporting-incident-ids INC-1,INC-2
python src/manage_memory.py catalog add --from-candidate CAND-0001 --input data/promoted/CASE-009.json --force
python src/manage_memory.py catalog stage --signature "F1::Spring4Shell" --family-id web-exploit --incident-id INC-9 --event-ids EVT-1,EVT-2
python src/manage_memory.py catalog candidates --by-group
python src/manage_memory.py catalog chains --rebuild
python src/manage_memory.py catalog chain --incident-id SIM-INC-1083 --summarize
python src/manage_memory.py review stage --incident-id SIM-INC-1083 --event-id SIM-1083-2 --stage exfiltration --label "DNS tunneling" --basis "reviewed cadence"
python src/manage_memory.py catalog merge --primary CAND-0002 --alias CAND-0058 --basis "same signature_key"
python src/manage_memory.py catalog split --primary CAND-0002 --alias CAND-0058 --basis "wrong merge"
python src/manage_memory.py catalog lifecycle
python src/manage_memory.py catalog retention --as-of 2026-10-29
python src/manage_memory.py catalog retire --case-id CASE-009 --basis "obsolete"
python src/manage_memory.py catalog reactivate --case-id CASE-009 --basis "restored"
python src/manage_memory.py catalog merge-case --source CASE-009 --target CASE-001 --basis "alias duplicate"
python src/manage_memory.py catalog split-case --case-id CASE-009 --basis "not a duplicate"
python src/manage_memory.py catalog families
python src/manage_memory.py catalog migrations
python src/manage_memory.py catalog admissions
python src/manage_memory.py catalog review-case --case-id CASE-009 --basis "reviewed by analyst" --reviewer analyst
```

- `catalog add` requires **two supporting incidents** whose events match the pattern, unless
  `--force` is used for a reviewed singleton. It records a new admission automatically.
- `catalog add --from-candidate` uses the candidate's incidents as support and marks the candidate
  `promoted`. A one-incident candidate needs `--force`.
- `catalog stage` adds/merges one incident under a candidate signature. The same signature with a
  second incident becomes `promotable`.
- `catalog chains` / `catalog chain` show the incident-chain layer; `catalog chains --rebuild`
  rebuilds from raw logs and links while preserving annotated stages.
- `review stage` annotates an event's stage independently of any case or link.
- `catalog candidates --by-group` groups by deterministic `signature_key`; it does not merge or
  change status. `catalog merge` performs an explicit same-family/same-key merge; `catalog split`
  reverses a non-promoted merge.
- `catalog merge-case` is a conservative alias merge: the source becomes `retired` with
  `merged_into=target`; steps and existing links are not rewritten. `split-case` restores it.
  `retire` / `reactivate` are independent lifecycle actions. All are recorded in
  `case_lifecycle.json` and shown by `catalog lifecycle`.
- `catalog retention` is a read-only incident-level report; it does not delete or archive data.
- `catalog review-case` removes the `unreviewed` marker after human review. Only the marker is
  removed; `admission_id` stays for audit.

### Review

```powershell
python src/manage_memory.py review link --event-ids EVT-1,EVT-2 --incident-id INC-1 --case-id CASE-008 --step-id S1 --status confirmed --basis "shared URI and header"
python src/manage_memory.py review associate --event-ids EVT-9,EVT-10 --incident-id INC-9 --case-id CASE-005 --basis "same ransomware family, different tooling"
```

`review link` checks that the event content matches the step regex. `--force` is only for a reviewed
exception and needs a basis. `review associate` writes `related`, does not set `case_id` labels, and
counts as proposal support. A family step can be linked only as `related`; `confirmed` is rejected.

### Evolve

```powershell
python src/manage_memory.py evolve propose --input data/proposals/CASE-008_add_S7.json
python src/manage_memory.py evolve list
python src/manage_memory.py evolve accept PROP-... --auto --basis "two incidents continued into S7"
python src/manage_memory.py evolve reject PROP-... --basis "evidence insufficient"
python src/manage_memory.py evolve rollback --case-id CASE-008 --to 2 --basis "false matches increased"
```

Proposals are deterministic: base version must be current, supporting events must exist, at least two
independent incidents must support the change, the step regex must not match another labelled case,
and shadow evaluation must not reduce `strong` count or required coverage. `--auto` is limited to
`add_step` / widening `extend_step` / `add_source`; demotion and narrowing need explicit accept.

### Audit

```powershell
python src/manage_memory.py audit
python src/manage_memory.py audit --verbose --case-id CASE-005
```

The audit checks link content/action/step consistency, confirmed labels, accepted-proposal snapshots,
family ↔ catalog agreement, migration snapshots/steps, admission markers, and candidate state. It
exits 1 on any inconsistency.

### Retrieval and lookup

```powershell
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
python src/lookup_case_logs.py --case-id CASE-005 --status related
python src/lookup_case_logs.py --case-id CASE-002 --step-id S4 --exclude-incident INC-CASE-002-001
python src/lookup_case_logs.py --case-id CASE-005 --include-related --status related
```

`run_demo` prints each candidate's tier, `weak_kind`, matched/missing steps, source fit, evidence,
family, and — separately — family-level evidence. Family evidence is context, not part of the case
tier. Use `--exclude-incident` when recalling examples for an incident under judgement; otherwise
you leak its own reviewed labels.

## Review and trust model

### Experiment mode (this demo)

The model is allowed to write `attack_patterns.json` through the CLI. It does **not** get a separate
approval step here. Every new case still leaves an audit trail:

1. `catalog add` / `catalog add --from-candidate` writes the case;
2. `case_admissions.json` gets an `unreviewed` record with source and basis;
3. the pattern gets `review_status: "unreviewed"` and `admission_id`;
4. `run_demo` shows `UNREVIEWED` next to the case; `lookup` shows `[UNREVIEWED]`;
5. `audit` verifies the ledger and marker agree.

The marker is **not** removed automatically. In the experiment nobody reviews it, so it stays; that
is intentional visibility, not a failure.

### Deployment mode (recommended gate)

Before a deployment trusts a model-added case, add a policy around the same fields:

- treat `review_status == "unreviewed"` as untrusted for recall or reporting;
- require a human to run
  `python src/manage_memory.py catalog review-case --case-id CASE-... --basis "..." --reviewer NAME`;
- after review, the marker is removed and the ledger record becomes `reviewed`; the
  `admission_id` remains for traceability;
- keep `audit` in CI so an unreviewed marker cannot drift away from its ledger record.

This repository ships the mechanism, not an enforced gate. A deployment can enforce it by rejecting
`unreviewed` cases in its own retrieval/reporting layer until `review-case` has been run.

### Current trust state

- CASE-001..CASE-008 are seed/reviewed cases and carry no marker.
- CASE-009 (promoted from CAND-0001) is **unreviewed**; `ADM-CASE-009` is in the admission ledger.
- No case is auto-approved by `audit`.

## Families and family-level steps

Each pattern has a `family_id`; `families.json` groups cases and may carry broad `steps`:

- `web-exploit` (CASE-001/002/004/008/009)
- `host-persistence` (CASE-003)
- `ransomware` (CASE-005; family step S9)
- `domain-identity` (CASE-006)
- `supply-chain` (CASE-007; family step S4)

CASE-005/S9 and CASE-007/S4 were first added as optional case steps in v2, then moved into their
families in v3. The case now has only its specific required chain (3/3 strong); the broad behavior is
family context. Historical `related + step` links that still name S9/S4 are audited against the
family step. Family steps are never `confirmed`.

`data/pattern_migrations.json` records the move:

```
MIG-CASE-005-v3  CASE-005  v2->3  move_step_to_family  S9 -> ransomware
MIG-CASE-007-v3  CASE-007  v2->3  move_step_to_family  S4 -> supply-chain
```

`catalog validate` / `audit` check the v003 snapshot, consecutive versions, the step being absent
from the case, and the family step existing.

## Case lifecycle (Phase 3c)

`data/case_lifecycle.json` is an append-only ledger for case-level lifecycle events:

- `merge`: conservative alias merge. Source becomes `retired`, `merged_into=target`; steps and
  existing links are **not** rewritten. Target must be active and in the same family.
- `split`: reverses the latest merge; source becomes active again.
- `retire` / `reactivate`: retire a case without merging, or bring it back.
- Candidate primaries that pointed at the source are moved to the target on merge and restored on
  split.

Retired cases stay in the catalog and keep their history, but `retrieve` skips them and
`catalog families` shows `retired=N`. Current ledger is empty: no production case has been merged or
retired. The operations are covered by synthetic lifecycle tests.

```powershell
python src/manage_memory.py catalog lifecycle
python src/manage_memory.py catalog merge-case --source CASE-009 --target CASE-001 --basis "alias duplicate"
python src/manage_memory.py catalog split-case --case-id CASE-009 --basis "not a duplicate"
python src/manage_memory.py catalog retire --case-id CASE-009 --basis "obsolete"
python src/manage_memory.py catalog reactivate --case-id CASE-009 --basis "restored"
```

Automatic decay/retirement (`last_confirmed_at`, unobserved duration) is still deferred; this phase
implements explicit, auditable operations.

## Incident chains (Phase 3)

`data/incident_chains.json` is the first-class chain layer. Each incident has ordered events with
one of four stage kinds:

- `case_step`: covered by a case step;
- `family_step`: covered by a broad family step (for example ransomware/S9);
- `annotated`: named by a human/agent independently of any case;
- `unclassified`: behavior not covered by a case, family step, or annotation.

Build or inspect:

```powershell
python src/manage_memory.py catalog chains --rebuild
python src/manage_memory.py catalog chain --incident-id SIM-INC-1083 --summarize
python src/manage_memory.py review stage --incident-id SIM-INC-1083 --event-id SIM-1083-2 \
  --stage exfiltration --label "DNS tunneling" --order 4 \
  --basis "three DNS events at a two-minute cadence"
```

`catalog chain --summarize` groups consecutive `unclassified` events into segments and suggests
action labels from event content. It is a suggestion, not an automatic case edit.

Current state: 59 chains, 56 unclassified events. `SIM-INC-1083` has its three DNS events annotated
as `exfiltration`; a rebuild preserves that annotation instead of overwriting it with `unclassified`.
`audit` checks chain events, stage kinds, annotation basis, and case-step references.

`reorder_steps` is implemented as an evolution operation (explicit accept, no `--auto`): it lists
every step exactly once, rewrites `order`, and the gate requires at least two confirmed incidents
and no drop in `strong` count or required coverage. Case-level `merge`/`split`/`retire` remain
deferred (Phase 3c); they need the chain layer to stabilize first.

## Candidates and signature clusters

A novel technique is staged, not turned into a case:

- one incident → `provisional`;
- a second incident under the same signature → `promotable`;
- promotion needs an authored pattern; a singleton needs `--force`;
- after promotion the candidate is `promoted` and points at the case.

Step 1 was deterministic grouping: CVE, product, primary action and all technique terms produce a
family-scoped `signature_key`. `catalog candidates --by-group` showed the groups without changing
status.

Step 2 merges the duplicate groups:

- `catalog merge --primary CAND-0002 --alias CAND-0058 --basis "same signature_key"`;
- `catalog split --primary CAND-0002 --alias CAND-0058 --basis "wrong merge"`;
- merge requires the same family and `signature_key`; split is allowed only for non-promoted clusters;
- the primary absorbs the alias incidents, keeps `aliases` / `merged_from`, and becomes
  `promotable` once it has two incidents;
- a merged alias stays in the file as `status=merged`, `merged_into=primary`, so the merge is
  auditable and reversible.

Current result:

```
91 candidate records
84 active candidates: 77 provisional, 6 promotable, 1 promoted
7 merged aliases
0 remaining duplicate groups
```

The six promotable clusters are:

| primary | alias | technique |
|---|---|---|
| CAND-0002 | CAND-0058 | Spring Cloud Gateway SpEL |
| CAND-0003 | CAND-0057 | Confluence OGNL |
| CAND-0008 | CAND-0056 | Solr Velocity |
| CAND-0014 | CAND-0059 | Node.js vm escape |
| CAND-0018 | CAND-0070 | Django SQL injection |
| CAND-0033 | CAND-0063 | GitLab ExifTool |

Spring4Shell is special: `CAND-0001` was already promoted to CASE-009, so merging `CAND-0066`
keeps the primary `promoted` and records the new incident as `pending_case_links=["SIM-INC-1073"]`.
It does **not** create CASE-010; a human should decide whether to link that incident to CASE-009 or
reject it.

Same-product but different techniques (for example OFBiz XML-RPC vs OFBiz Groovy) stay separate;
product-only PHP variants are not merged.

## Retention

`catalog retention` classifies incidents, not individual rows. With no `--apply` it is read-only:

| class | protection | TTL |
|---|---|---|
| `anchor` | confirmed link to a case | keep |
| `fixture` | synthetic validation | keep |
| `candidate` | `promotable` / `promoted` / `merged` | 150 days for provisional |
| `variant` | none (unless open proposal/annotation) | 180 days |
| `unclassified` | none | 90 days |

The clock is the latest event timestamp, not last recall. No per-log access timestamp is written.
The TTLs are early-experiment defaults and will be revisited at deployment.

Before apply (as of 2026-10-29):

```
149 incidents, 571 grouped events / 581 raw events
classes: anchor=16, candidate=90, variant=42, fixture=1
expired: 3 incidents / 16 events
protected: 31
unassigned: 10 events (SIM-B-1035 and SIM-B-1076)
```

The apply was run with the experimental TTLs:

```
3 incidents / 16 events / 3 candidates archived
CAND-0010, CAND-0036, CAND-0068
archive: data/archive/2026-10/ (monthly gzip)
```

After apply:

```
146 incidents, 555 grouped events / 565 raw events
expired: 0
candidate records: 88 (81 active + 7 merged)
bytes: active=312909 archive=2397 data=374957
files: active=4 archive=5 data=25
```

`--apply` writes monthly gzip segments (`raw_logs.csv.gz`, `event_pattern_links.csv.gz`,
`incident_chains.json.gz`, `case_candidates.json.gz`) plus a per-run manifest. It then writes one
run to `retention_tombstones.json`: an incident-level summary with `content_hash_root`, and
per-event tombstones only for events still referenced by active links/chains/candidates/proposals.
This keeps tombstones bounded instead of one record per archived event.

Hard caps are optional:

```powershell
python src/manage_memory.py catalog retention --apply \
  --max-active-bytes 500000000 --archive-max-days 365
```

- `--max-active-bytes` archives the oldest eligible non-anchor incidents until the active files are
  under the cap;
- `--archive-max-days` deletes a whole archive group only when **all** runs in it are older than the
  limit.

The 10 unassigned events are still a real gap; the report lists them.

## Current demo state

```
cases                9 (CASE-001..CASE-009)
case steps           32 (0 optional case steps)
families             5
candidates           88 records: 81 active (74 provisional, 6 promotable, 1 promoted) + 7 merged
admissions           1 (CASE-009 unreviewed)
links                265
raw events           565 (16 archived)
proposals            2 accepted (v1 -> v2)
migrations           2 reviewed (v2 -> v3)
chains               59 (56 unclassified events; 3 annotated in SIM-INC-1083)
lifecycle            0 events (no production merge/retire applied)
retention            146 incidents / 555 grouped of 565 events; 1 archive run; 0 expired
tests                100
audit                clean
```

The seed data is the original 45-row demo plus dataset units 1001-1140. Unclassified units still
carry only their `SIM-B-<unit>` batch scope; CAND-0001's rows now carry `CASE-009` /
`SIM-INC-1002`. CASE-005/007 are v3; CASE-009 is v1 and unreviewed.

## Reset and reproducibility

- Backups live next to `demo/` as `demo_backup_<timestamp>/`. Use the newest backup for a state that
  matches the current schema. Older backups predate families/admissions/migrations; restoring one
  without also restoring the newer ledgers will make `catalog validate` fail.
- `data/promoted/CASE-009.json` is the authored pattern used for the promotion demo.
- `eval/apply_ingest_1001_1140.py` refuses to run twice (it checks for `SIM-` events).
- `eval/migrate_family_steps.py` is the reviewed v3 migration step; it writes v003 snapshots.
- `eval/stage_candidates_1001_1140.py` stages the 91 unclassified units; it is idempotent.
- `eval/backfill_candidate_signatures.py` adds signature features and writes
  `eval/ingest_applied_1001_1140/signature_groups.json`; it never changes candidate status.
- `eval/merge_signature_groups.py` merges duplicate groups; it is idempotent and writes
  `eval/ingest_applied_1001_1140/merge_groups.json`.

## Limits

- CSV is a convenient demo store, not a concurrent database. No retention, access control, or
  privacy policy.
- Rule-based retrieval is explainable only as complete as the step regexes.
- Sequence order is checked from timestamps; missing timestamps make it unassessable.
- Tiers and keyword scores are deterministic signals, not calibrated confidence.
- Incident clustering is not automatic; an agent/analyst must review correlation evidence.
- Model-added cases are not automatically trusted in deployment; the demo only makes the marker and
  ledger visible.
- Family evidence is context, not a second tier.
- Candidate signature step 1 (deterministic grouping) and step 2 (explicit same-key merge/split) are
  implemented; semantic/fuzzy clustering and automatic merge suggestions are not.
- A merged incident in a promoted cluster is only a `pending_case_link`; it is not automatically
  linked to the promoted case.
- `reorder_steps` is implemented; case-level alias `merge-case`/`split-case` and
  `retire`/`reactivate` are implemented; automatic decay-based retirement is deferred.
- Retention archive/tombstone apply is implemented; the TTLs are early-experiment defaults, and 10 unassigned events still need review.
- Chain summaries are suggestions; they never create a case or a stage automatically.
- Migrations are recorded in their own ledger; they are not re-evaluated by the proposal gate.
- `decided_at`/`reviewed_at` exist, but there is no authenticated reviewer identity.

## Further reading

- [Skill rules](skills/attack-memory/SKILL.md)
- [Runtime playbook](skills/attack-memory/references/runtime-playbook.md)
- [Memory schema](skills/attack-memory/references/memory-schema.md)
- [Case write spec](skills/attack-memory/references/case-write-spec.md)
- [Optimization plan](../MEMORY_OPTIMIZATION_PLAN.md)
- [Applied dataset report](../eval/INGEST_APPLIED_1001_1140.md)
