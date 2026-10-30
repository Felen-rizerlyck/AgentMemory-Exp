# Attack Memory Demo

A local, file-based memory for attack-pattern review. It stores raw observations, reviewed
event-to-case links, reusable cases, family-level behaviors, staged candidates, pattern versions,
new-case admissions, negative-memory corrections, and the journal of every write. Retrieval is
rule-based and explainable; consolidation is explicit, never a background daemon.

The demo is deliberately small enough to inspect by hand: the whole catalog fits on one screen and
every derived number can be re-derived from primary data. It is not a production service — no
reviewer login, no concurrency control, no enforced policy — but it ships the mechanism for one.

## Why it is not another "RAG + top-k" demo

| Typical vector-memory demo | This demo |
|---|---|
| Retrieval returns a ranked answer. | Retrieval returns a chain of required steps, the events behind each step, source fit, and explicitly unobserved steps. |
| Memory is "what matched". | Memory also records **what was rejected, and why** (`corrections`, `link_exceptions`, rejected links). |
| A write is an upsert. | A write is a gated, versioned, journaled transaction; a new case cannot enter the catalog on partial evidence. |
| History is the latest value. | History is append-only links plus immutable `vNNN` snapshots; rollback is a first-class command. |
| "It works" means the demo output looks right. | "It works" means `audit` is clean **and** the generated state block in this README matches the store. |

## Design principles

The project's 2026 self-iteration survey identifies these principles as separating systems that
improve from systems that drift; each is wired to a mechanism here, not a slogan.

| # | Principle | What the demo actually does | Mechanism / command |
|---|---|---|---|
| 1 | **Gate the write path, not only the read path.** | A new case must cover every required step across its supporting incidents, and at least one supporting incident must reach `strong`/`medium` on its own; `--force` is a reviewed exception, not a shortcut. | `catalog add`, `pattern_support_report`, `audit` |
| 2 | **The model proposes; the harness decides.** | A proposal is recorded with deterministic gate metrics and blockers. Only an explicit accept writes a new version; `--auto` is limited to completion-class operations that the gate marked eligible. | `evolve propose` / `evolve accept` |
| 3 | **Validate held-out, not just support.** | A proposal may not lower `strong` count or required coverage on confirmed incidents outside its own support set — a keep-better check against the population it was not built from. | `evaluate_proposal`, `heldout_*` metrics |
| 4 | **Remember the negative.** | Rejections are first-class: a corrections ledger stores case, incident, reason code, evidence events, basis and reviewer; retrieval surfaces prior rejections next to a candidate. | `catalog correction add`, `catalog corrections`, `run_demo --json` |
| 5 | **Keep provenance on every claim.** | Every link, proposal, admission and correction carries basis, timestamp and reviewer; patterns carry version and provenance; every write lands in a transaction journal. | schemas in `skills/attack-memory/references/`, `ops_journal.jsonl` |
| 6 | **Prefer small, append-only edits.** | Pattern changes are five small delta operations; links and ledgers are append-only; no command rewrites reviewed history in place. | `evolve propose` operations, `event_pattern_links.csv` |
| 7 | **Make every state change reversible and repairable.** | Each accepted version has an immutable snapshot; old versions can be restored; derived state (labels, snapshots, orphan admissions) can be rebuilt idempotently from authoritative sources. | `catalog snapshot`, `evolve rollback`, `catalog repair`, two-phase `storage.commit` |
| 8 | **Run three loops, not one hot path.** | Capture small observations during work, gate experience after the task, consolidate idle state on demand — each loop has its own commands and its own gate. | see [The three loops](#the-three-loops) |

Survey mapping (`docs/agent-memory-skill-self-iteration-survey-2026-10.md`): 1 → §1/§7.2 write-path
filtering; 2 → §2.4 "propose, harness decides"; 3 → §5.3 held-out keep-better (RSEA); 4/5 → §3.1
NOOP and provenance; 6 → §5.2 small edits; 7 → §2.4/§7.2 commit-and-rollback; 8 → §2.1/§7.1 clocks
and rings.

## Memory layers

Five kinds of memory are kept separate so each has an appropriate gate.

| Layer | Question it answers | Files | Write operator | Gate |
|---|---|---|---|---|
| **Episodic** | What happened? | `raw_logs.csv`, `event_pattern_links.csv`, `incident_chains.json` | `ingest_logs.py`, `review link/associate/stage` | step regex match, append-only links, `audit` |
| **Semantic** | What reusable behavior is real? | `attack_patterns.json`, `pattern_versions/`, `families.json`, `pattern_migrations.json` | `catalog add`, `evolve accept`, reviewed migrations | support coverage + `strong`/`medium` + held-out + explicit accept |
| **Procedural** | How should an agent work? | `skills/attack-memory/**`, CLI entry points | humans and agents edit skill text (progressive disclosure: description -> `SKILL.md` -> references) | review only; the runtime does not enforce it |
| **Negative** | What is it *not*, and why? | `corrections.json`, `link_exceptions.json`, rejected links, `unclassified` chain stages | `catalog correction add`, `review link --status rejected`, `review link --force` | non-empty basis + `audit` |
| **Ledger / meta** | What did the memory do to itself? | `pattern_proposals.json`, `case_admissions.json`, `case_lifecycle.json`, `retention_tombstones.json`, `ops_journal.jsonl`, `repair_log.json` | every mutating command, in one transaction | `audit` + generated state block |

### Data flow

```
                 CAPTURE                                GATE                              CONSOLIDATE
  raw CSV --ingest--> raw_logs.csv      catalog add  --+                    audit / state --check
                        |                evolve propose -+-> deterministic  ->  repair (dry-run/--apply)
          review link/  |                    |           |   gate            snapshot --all
          associate/    v                    v           v      |            retention [--apply]
          stage ---> event_pattern_links.csv   pattern_proposals.json      corrections review
                        |                (accept)          |                 chains --rebuild
                        v                                  v
              incident_chains.json                    attack_patterns.json
              case_candidates.json                    pattern_versions/<CASE>/vNNN.json
                        +-------- every transaction ---------> ops_journal.jsonl
```

Three identifiers, never conflated: an **event** is one sensor row (`event_id`), an **incident** is a
correlated set of events (`incident_id`), and a **case** is a reusable ordered pattern (`case_id`).
One case can be supported by many incidents; one incident can contain many events. A link records a
reviewed `event -> (incident, case, step)` relation; the latest decision wins, history is kept.

## The three loops

| Loop | Typical trigger | Commands | What becomes durable |
|---|---|---|---|
| **Capture** (during work) | a new batch, a reviewed step, a novel technique | `ingest_logs.py`, `review link/associate/stage`, `catalog stage` | links, chains, candidates. No case is created; everything stays auditable as `candidate`/`related`/`unclassified`. |
| **Gate** (after the task) | evidence is complete enough to promote or extend | `catalog add`, `catalog add --from-candidate`, `evolve propose/accept`, `catalog review-case`, `catalog merge-case/split-case/retire/reactivate` | patterns, immutable version snapshots, admissions, lifecycle records. |
| **Consolidate** (idle) | scheduled review, store growth, drift suspicion | `audit`, `catalog state --check`, `catalog snapshot --all`, `catalog repair --apply`, `catalog retention --apply`, `catalog corrections` | backfilled snapshots, archive segments/tombstones, repair log, matching state block. |

Nothing triggers itself: consolidation is an explicit decision whose outputs are reports and ledgers
first, destructive actions opt-in.

## Directory and modules

```text
demo/
├── data/                        # plain CSV/JSON store, no database
│   ├── raw_logs.csv             # episodic rows; case_id/incident_id are analysis labels
│   ├── event_pattern_links.csv  # append-only reviewed relations
│   ├── incident_chains.json     # ordered stages, including unclassified behavior
│   ├── attack_patterns.json     # semantic catalog (9 cases)
│   ├── pattern_versions/        # immutable vNNN snapshots
│   ├── families.json  pattern_migrations.json  case_lifecycle.json
│   ├── case_candidates.json  case_admissions.json  pattern_proposals.json
│   ├── corrections.json  link_exceptions.json      # negative memory (exceptions on first --force)
│   ├── ops_journal.jsonl  repair_log.json          # write ledger; repair_log on first --apply
│   ├── signature_lexicon.json                      # candidate signature vocabulary
│   └── retention_tombstones.json  archive/2026-10/ # archive runs / gzip segments
├── src/attack_memory/           # library: business rules live here, not in the CLI
├── src/manage_memory.py  run_demo.py  lookup_case_logs.py  ingest_logs.py
├── scripts/verify_demo.py       # one-command read-only verification matrix
├── skills/attack-memory/        # runtime rules for an agent (SKILL.md + references)
└── tests/                       # stdlib unittest suite
```

| Module | Responsibility |
|---|---|
| `attack_memory/storage.py` | **Single IO/transaction layer.** Paths, strict CSV/JSON reads, schema checks, shared helpers (`source_fits`, `owner_of_event`, `resolve_case`, timestamps), and the journaled two-phase `commit()`. |
| `attack_memory/retrieval.py` | Rule-based, source-aware matching: action index, temporal alignment, `tier`/`shape`/`weak_kind`, evidence and caveats. |
| `attack_memory/catalog.py` | Catalog loading and validation, the new-case support gate, v001 creation, snapshot/version audits, case lifecycle operations. |
| `attack_memory/links.py` | Append reviewed links, force-exception ledger, derived label updates, and link audit (including exception waiver). |
| `attack_memory/evolution.py` | Proposals: deterministic gate (support, foreign matches, shadow top-1, held-out keep-better), accept/reject/rollback, version snapshots. |
| `attack_memory/audit.py` | **Single audit entry point.** One report over every invariant; `audit` and `catalog validate` both read it. |
| `attack_memory/state.py` | **Single numeric source.** Counts for the README state block, rendering and `--check` drift detection. |
| `attack_memory/corrections.py` | Negative-memory ledger: add/list/query rejections, audit validity, one-line summaries. |
| `attack_memory/candidates.py` | Staged techniques and their state transitions; explicit same-signature merge/split, no automatic merge. |
| `attack_memory/signatures.py` | Deterministic signature features; `signature_source`; the visible `ungrouped` bucket; external lexicon fallback. |
| `attack_memory/admissions.py` | New-case admission records, review marker, `support_coverage`/`single_sample`, orphan repair helper. |
| `attack_memory/families.py` | Family registry, family-level steps and evidence, catalog/registry agreement checks. |
| `attack_memory/chains.py` | Incident chains: build, summarize, stage annotation, audit. |
| `attack_memory/migrations.py` | Append-only ledger for reviewed schema moves such as moving a step into a family. |
| `attack_memory/lifecycle.py` | Case merge/split/retire/reactivate events. |
| `attack_memory/retention.py` | Incident-level retention report, archive/tombstone apply, hard caps, archive audit. |
| `attack_memory/repair.py` | Idempotent repair of derived state: labels from links, missing snapshots, orphan admissions. |
| `attack_memory/diagnostics.py` | Per-step `matched`/`linked`/`ambiguity` statistics, unexplained events, `audit --verbose` lines. |
| `attack_memory/manage.py` | CLI surface only: one argparse entry per verb, one handler per command; no business rules. |

## Quick start

```powershell
cd demo

python src/manage_memory.py catalog validate     # structural validation
python src/manage_memory.py audit                # full trust check
python src/manage_memory.py catalog state        # current counts / state block
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
python -m unittest discover -s tests             # full suite
python scripts/verify_demo.py                    # one-command read-only matrix
```

Python 3.11+; standard library only. Run from `demo/`; supplied paths are relative to it. `run_demo`
retrieves, `lookup_case_logs.py` recalls stored observations after a candidate is selected.

## Command reference

The management CLI has four top-level verbs: `catalog`, `review`, `evolve`, `audit`.

### Inspect (read-only)

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py catalog families
python src/manage_memory.py catalog candidates --by-group
python src/manage_memory.py catalog admissions
python src/manage_memory.py catalog chains
python src/manage_memory.py catalog chain --incident-id SIM-INC-1083 --summarize
python src/manage_memory.py catalog retention --as-of 2026-10-30
```

Read-only except `catalog chains --rebuild` (rewrites `incident_chains.json`, preserves annotations)
and `catalog retention --apply` (archives expired incidents; see Retention below).

### Catalog writes (gated)

```powershell
python src/manage_memory.py catalog stage --signature "F1::Spring4Shell" --family-id web-exploit \
  --incident-id SIM-INC-1002 --event-ids SIM-1002-1
python src/manage_memory.py catalog add --from-candidate CAND-0002 --input data/new_pattern.json
python src/manage_memory.py catalog add --input data/new_pattern.json --supporting-incident-ids INC-1,INC-2
python src/manage_memory.py catalog merge --primary CAND-0002 --alias CAND-0058 --basis "same signature_key"
python src/manage_memory.py catalog split --primary CAND-0002 --alias CAND-0058 --basis "wrong merge"
python src/manage_memory.py catalog merge-case --source CASE-009 --target CASE-001 --basis "alias duplicate"
python src/manage_memory.py catalog split-case --case-id CASE-009 --basis "not a duplicate"
python src/manage_memory.py catalog retire --case-id CASE-009 --basis "obsolete"
python src/manage_memory.py catalog reactivate --case-id CASE-009 --basis "restored"
python src/manage_memory.py catalog review-case --case-id CASE-009 --basis "reviewed by analyst" --reviewer analyst
```

`catalog stage` records evidence for a technique that is not a case yet; it does not create a case.
Promotion and direct creation run the same support gate: required-step union coverage across
independent incidents, at least one `strong`/`medium` support incident, no conflicting action
definition. `--force` is only for a reviewed singleton and records the partial observation in the
admission record. Candidate merges need the same family and (unless `--allow-ungrouped` is explicit)
a shared `signature_key`; a case merge is a conservative alias merge (source retired with
`merged_into=target`, links and steps not rewritten) committed as one journaled transaction over
patterns, candidates and lifecycle. `review-case` clears only the `unreviewed` marker; the admission
record stays.

### Reviewed links

```powershell
python src/manage_memory.py review link --event-ids EVT-1,EVT-2 --incident-id INC-1 \
  --case-id CASE-008 --step-id S1 --status confirmed --basis "shared URI and header"
python src/manage_memory.py review associate --event-ids EVT-9 --incident-id INC-9 \
  --case-id CASE-005 --basis "same ransomware family, different tooling"
python src/manage_memory.py review stage --incident-id SIM-INC-1083 --event-id SIM-1083-2 \
  --stage exfiltration --label "DNS tunneling" --basis "three DNS events at a 2-minute cadence"
```

`review link` replays the step `action_regex` against the event content and refuses a mismatch;
`--force` with a non-empty `--basis` records a reviewed exception in `link_exceptions.json` instead
of hiding it. Only `confirmed`/`rejected` update the CSV analysis labels. `review associate` writes
`related` (family/step context, no case label); a family step can only be `related`.

### Evolve a pattern

```powershell
python src/manage_memory.py evolve propose --input data/proposals/my_proposal.json
python src/manage_memory.py evolve list --status ready
python src/manage_memory.py evolve accept PROP-... --basis "two incidents continued into S7"
python src/manage_memory.py evolve reject PROP-... --basis "evidence insufficient"
python src/manage_memory.py evolve rollback --case-id CASE-008 --to 2 --basis "false matches increased"
```

Operations: `add_step`, `extend_step`, `add_source`, `set_required`, `reorder_steps`. `add_step`
defaults to `required: false`; a completion stage that only some incidents reach must be optional,
otherwise the gate rejects it for dropping existing `strong` incidents. `--auto` is accepted only for
completion-class operations the gate marked eligible (`add_step`, widening `extend_step`,
`add_source`); demotion, narrowing and reordering need an explicit accept.

### Trust and maintenance

```powershell
python src/manage_memory.py audit
python src/manage_memory.py audit --verbose --case-id CASE-005
python src/manage_memory.py catalog state
python src/manage_memory.py catalog state --check README.md
python src/manage_memory.py catalog repair                 # dry run; --apply to write
python src/manage_memory.py catalog snapshot --all         # backfill missing vNNN baselines
python src/manage_memory.py catalog retention              # report; --apply to archive
python src/manage_memory.py catalog corrections
python src/manage_memory.py catalog correction add --incident-id SIM-INC-1026 --case-id CASE-005 \
  --reason-code generic_only --basis "only a shared whoami probe; no case step"
```

`audit --json` emits `{ok, problems, warnings, checks, counts, forced_exceptions}`; exit code is 1 on
any problem. `catalog repair` is dry-run by default and only rebuilds derived state. `catalog snapshot`
writes baselines for missing versions (never a historical replay). `catalog retention --apply` is the
only command that archives data; it writes gzip segments, a manifest, and bounded tombstones.

### Retrieval and recall

```powershell
python src/run_demo.py --input data/raw_logs.csv --min-tier medium
python src/run_demo.py --input data/raw_logs.csv --incident-id INC-CASE-005-001 --json
python src/lookup_case_logs.py --case-id CASE-002 --step-id S4
python src/lookup_case_logs.py --case-id CASE-002 --exclude-incident INC-CASE-002-001
python src/lookup_case_logs.py --case-id CASE-005 --include-related --status related
```

`run_demo` partitions the batch by known `incident_id`; unlabeled rows become batch/host candidate
scopes, not proven incidents. It prints each candidate's tier, `weak_kind`, required coverage,
evidence, family context, `evidence_confidence` (an evidence ratio, not a probability), and any
`prior_rejections` from the corrections ledger. `lookup_case_logs` follows a merged-case alias
(`alias_of` / `resolved_case_id`) and hides fixtures by default. Use `--exclude-incident` when
recalling examples for an incident under judgement; otherwise its own labels leak into the recall.

## Trust model

### Experiment mode vs deployment mode

This repository ships the mechanism, not an enforced review policy.

**Experiment mode (this demo).** The model may write the catalog through the CLI. Every new case
still leaves an audit trail:

1. `catalog add` / `catalog add --from-candidate` writes the case and a `v001` snapshot in one transaction;
2. `case_admissions.json` gets an `unreviewed` record with source, basis, `support_coverage` and
   `single_sample`;
3. the pattern carries `review_status: "unreviewed"` plus `admission_id`; `run_demo` prints
   `UNREVIEWED`, `lookup` shows `[UNREVIEWED]`, and `audit` requires marker and ledger to agree.

The marker is **not** removed automatically. In the experiment nobody reviews it, so it stays — that
is intentional visibility, not a failure.

**Deployment mode (recommended policy).** Around the same fields, a deployment should:

- treat `review_status == "unreviewed"` as untrusted for recall, reporting and alerting;
- require a human to run `catalog review-case --case-id CASE-... --basis "..." --reviewer NAME`;
- keep `audit` and `catalog state --check README.md` in CI so neither the marker nor the documented
  state can drift;
- restrict `--force`, `--auto`, `retention --apply` and `repair --apply` to named operators (the
  recorded `reviewer` is a string, not an authenticated identity).

### The write gate

| Operation | Must pass | Auto-accept |
|---|---|---|
| `catalog add` | ≥2 independent incidents; required-step union covered; ≥1 support incident `strong`/`medium`; action definitions consistent. `--force` waives coverage for a reviewed singleton and records `single_sample`. | never |
| `add_step` | supporting events exist in confirmed-or-related incidents (≥2 incidents); regex matches them; no foreign-case match; no shadow `top-1` change; no `strong`/required-coverage drop; held-out incidents do not regress. Step defaults to optional. | eligible completion changes only |
| `extend_step` | same checks; widening may auto-accept, any narrowing (events the old regex matched no longer match) needs explicit accept. | widening only |
| `add_source` | added source matches the supporting events; same foreign/shadow/held-out checks as `add_step`. | eligible completion changes only |
| `set_required: false` | rejected if the step is observed in every confirmed incident (demotion would only weaken the chain). | never |
| `reorder_steps` | lists every step exactly once; ≥2 confirmed incidents; no `strong`/coverage drop; never auto. | never |
| `review link --status confirmed` | event content matches the step regex (or a reviewed `--force` exception with basis); labels not already owned by another case. | n/a |
| `catalog review-case` | admission exists and is `unreviewed`; basis required. | n/a |

### Held-out keep-better

A proposal is scored on every stored incident before and after the change. The **support** incidents
are the ones it cites; the **held-out** incidents are the remaining confirmed incidents of that case.
The gate rejects a proposal that raises support performance while lowering held-out `strong` count or
coverage, and records `heldout_*` metrics on the proposal for after-the-fact review. This stops a
pattern from becoming an overfit to its latest evidence.

### `--force` is an exception ledger, not a bypass

`review link --force` is only for a reviewed mismatch (truncated logs, imperfect regex). It requires
a non-empty `--basis` and writes an exception keyed by `(event_id, incident_id, case_id, step_id)` to
`link_exceptions.json`. `audit` waives exactly that row, reports `forced exceptions=N` when present,
and fails on an exception with no matching live link, a missing basis, a duplicate key, or a link that
became `rejected`. Exceptions are visible and counted; they are never silently ignored.

### The journal: crash-detectable writes

Every mutating command stages all file effects first, appends a `pending` record with each target's
SHA-256 to `ops_journal.jsonl`, replaces the files, then appends `done`. Rendering problems leave the
store untouched. `catalog merge-case` / `split-case` follow the same pattern: patterns, candidates and
the lifecycle ledger are staged together and committed as one transaction, so a reader never observes
half of an alias merge. A crash between `pending` and `done` is detected by `audit` (unfinished
transaction) and can be repaired by `catalog repair`; `audit` and `state` report the unfinished count.
Partial multi-file writes become a recoverable incident, not silent corruption.

### Snapshots and rollback

Every case has an immutable snapshot for each version from `v001` onward, written at creation and
when a proposal is accepted. `evolve rollback --to N` restores a snapshot's content and keeps the
history; `catalog snapshot --all` backfills a missing baseline from the current catalog and records
that basis in the journal. Seed cases' `v001` files are such baselines, not reconstructed history:
the audit checks existence, version and case ID, not authorship.

### Documentation drift is a test failure

The block in [Current state](#current-state) is generated by `catalog state` and may not be edited
by hand. `catalog state --check README.md` renders the block from the store and compares it byte for
byte; CI treats a difference as a failure. Numbers that matter live in the block, not in prose.

### Honest incompleteness

`audit` clean means the store's claims agree with each other; it does not mean the world is fully
explained. The demo keeps incompleteness visible: 56 chain events are `unclassified`; 21 active
candidates are `ungrouped` (no explainable signature terms) and need a reviewed merge before
grouping/promotion (`audit` warns, does not fail); detection evidence marks steps `unobserved`
(unknown, not absent); fixture rows are labelled; thin correlation is reported as a candidate scope.

## Negative memory (`corrections`)

A `rejected` link says a relation was rejected; a **correction** says *why*: which case and incident
were ruled out, under which reason code, with which evidence, on whose basis. Recording tested
boundaries is what stops the same false positive from being re-promoted next month.

| Field | Meaning |
|---|---|
| `correction_id` | Stable `COR-NNNN` id. |
| `incident_id`, `case_id` | The rejected association. Both must exist; evidence events must belong to the incident. |
| `decision` | `reject_match` (this evidence is not this case) or `reject_case` (this incident is not this case at all). |
| `reason_code` | `generic_only`, `source_mismatch`, `incomplete_chain`, `wrong_family`, `insufficient_evidence`, `other`. |
| `event_ids` | Evidence events behind the rejection (optional, validated when present). |
| `basis` | Required prose: what was insufficient or misleading. |
| `reviewer`, `decided_at` | Accountability fields. |

Corrections are append-only; a later review appends a new record. `catalog corrections` lists them,
`catalog correction add` records one, `run_demo` attaches matching prior rejections to candidates,
and `audit` re-checks that every correction still points at a real case, incident and event.

## Current state

<!-- STATE:START -->
```text
cases                9 (CASE-001..CASE-009)
case steps           32 (0 optional)
families             5
candidates           88 records: 81 active (74 provisional, 6 promotable, 1 promoted) + 7 merged
admissions           1 (1 unreviewed)
links                265 (candidate=0, confirmed=70, rejected=0, fixture=8, related=187)
raw events           565 active (+16 archived)
proposals            2 (2 accepted)
migrations           2
chains               59 (56 unclassified events)
lifecycle            0 event(s)
retention            1 archive run(s), 16 archived event(s)
corrections          0
journal              2 transaction(s), 0 unfinished
tests                266
audit                clean
```
<!-- STATE:END -->

Regenerate with `python src/manage_memory.py catalog state`; verify with
`python src/manage_memory.py catalog state --check README.md`. Do not edit the block by hand.

## Performance and verification

Measured on Windows 11, Python 3.12.4, standard library only; best-of-runs in-process `retrieve()`;
"before" = `demo_backup_20261030-105300`, reproducible with `tests/test_perf.py`.

| Workload | Before | After | Delta |
|---|---|---|---|
| Real corpus: 565 logs, 9 patterns, 32 actions, 146 scopes, `retrieve()` for all scopes | 118.5 ms | 45.6 ms | 2.60× |
| Synthetic: 5,000 rows / 100 patterns / 300 actions, `retrieve()` | 1.161 s | 0.194 s | 5.99× |
| Synthetic: 5,000 rows / 100 patterns, `extract_log_actions()` | 1.022 s | 0.131 s | 7.82× |
| Synthetic: 20,000 rows / 100 patterns (regression guard) | — | 0.75 s | threshold 8.0 s |
| `run_demo --json`, in-process | 165.6 ms | 129.3 ms | 1.28× (the new path adds ~30 ms historical-precision work) |

Indexing is the main change: `retrieve()` builds the action reverse index and the lower-cased corpus
once per batch instead of once per pattern, and `extract_log_actions` caches per unique content and
prefilters on a mandatory literal. Benchmark: `$env:RUN_PERF='1'; python -m unittest discover -s
tests -p "test_perf.py" -v` (skipped by default; loose thresholds are regression guards, not host
benchmarks). `run_demo` end-to-end subprocess is ~0.46 s, dominated by process startup. Full suite:
`Ran 266 tests in ~16 s, OK (4 skipped)`. `scripts/verify_demo.py` runs the read-only matrix —
compileall, the suite, `catalog validate`, `audit`, `catalog state --check README.md`,
retrieval/lookup samples in text and JSON, `audit --json`, `catalog repair --dry-run`,
`catalog corrections`, and a data-mutation guard.

## Limits and boundaries

- **Single-writer store.** The journal detects interrupted transactions but does not lock or isolate
  concurrent writers.
- **No auth, no privacy policy.** `reviewer` is a string, not an identity; no access control or retention policy beyond the experimental TTLs.
- **Rule-based retrieval is only as complete as the regexes.** Tiers and keyword scores are
  deterministic ordering signals, not calibrated confidence; `evidence_confidence` is an evidence
  ratio, also not a probability.
- **Incident correlation is not automated.** Unlabeled rows are grouped by batch and host as
  *candidate* scopes; a shared host or one generic action is weak evidence.
- **Merged aliases are only partially joined.** `lookup_case_logs` follows `merged_into` and counts
  the alias's evidence under the target; `run_demo` scores active patterns only.
- **21 active candidates are ungrouped.** They have no explainable signature terms; audit warns and
  they need a reviewed merge (or an authored pattern) before grouping/promotion.
- **Automatic decay retirement is not implemented.** Retention TTLs are experimental; `--apply` is an
  operator decision; 10 raw events remain unassigned.
- **Family evidence is context, not a second tier.** Family steps never change a case's `tier` and are
  never `confirmed`.
- **Skills are instructions, not enforcement.** Deployment review policy must be built around the CLI.
- **Seed snapshots are baselines and chain summaries are suggestions.** Backfilled `vNNN` files
  reproduce current content as a baseline; `catalog chain --summarize` never creates a case or stage.

## Further reading

- [中文说明：运行流程 / data 目录 / 指令手册](README_CN.md)
- [Project overview and briefing](../docs/DEMO_OVERVIEW.md)
- [Improvement backlog and fix plans](../docs/DEMO_IMPROVEMENT_BACKLOG.md)
- [Self-iteration survey (2026-10)](../docs/agent-memory-skill-self-iteration-survey-2026-10.md)
- [Skill rules](skills/attack-memory/SKILL.md)
- [Runtime playbook](skills/attack-memory/references/runtime-playbook.md)
- [Memory schema](skills/attack-memory/references/memory-schema.md)
- [Case write spec](skills/attack-memory/references/case-write-spec.md)
- [Optimization plan](../MEMORY_OPTIMIZATION_PLAN.md)
- [Applied dataset report](../eval/INGEST_APPLIED_1001_1140.md)
