# Memory Schema

The catalog is `data/attack_patterns.json` with a top-level `schema_version` and an `attack_patterns` array. Each pattern includes:

| Field | Meaning |
|---|---|
| `case_id` | Stable ID for a reusable attack behavior pattern (`CASE-NNN`). |
| `name`, `summary`, `pattern_scope` | Human-readable identity, scope, and variant caveats. |
| `mitre` | ATT&CK technique references; useful metadata and an auxiliary retrieval signal, not a verdict. |
| `steps` | Ordered behavior steps. Each step needs `step_id`, unique ascending `order`, `action_id`, executable `action_regex`, and `expected_sources`. |
| `retrieval.keywords` | Case-insensitive terms, each contributing auxiliary ranking points. |
| `retrieval.pattern_probes` | Regex probes for structural lexical recall; not the primary action definition. |
| `negative_and_unknown_evidence` | Evidence limits and explicitly unobserved behavior. |
| `provenance` | Pattern-level evidence status and optional aggregate real-observation count; do not embed case IDs for individual incidents or concrete alert content. |

Raw alert rows live in `data/raw_logs.csv`. Event-to-incident/pattern-step rationale and decision history live in `data/event_pattern_links.csv`. A pattern is not an incident; one incident can support one or more patterns, and one pattern can describe many incidents. The action-to-pattern reverse index is built in memory from `steps`; do not persist a duplicate index in the pattern JSON.

`case_id` on a raw CSV row is an analysis label, not an original log field. Ingestion leaves it empty. A confirmed decision fills it; rejected decisions can clear that label. The relation CSV preserves rationale and history.

## Adding a pattern

Copy one pattern object to a separate JSON file, assign a new ID, and provide evidence-backed steps and regexes. Do not invent expected sources or claim optionality from one sample. Validate with:

```powershell
python src/manage_memory.py validate
python src/manage_memory.py add-pattern --input data/new_pattern.json
```

`add-pattern` checks required fields, unique IDs and step IDs, ascending step order, and compilable regexes before atomically replacing the catalog.
