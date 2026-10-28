# Evolution proposals

Drop one JSON file here, then run from `demo/`:

```powershell
python src/manage_memory.py propose --input data/proposals/<file>.json
python src/manage_memory.py proposals
python src/manage_memory.py accept PROP-... --basis "..."
```

A proposal is evidence plus a patch. It never edits the catalog by itself; `propose` only
records it, and `accept` is a separate command.

```json
{
  "case_id": "CASE-008",
  "base_version": 1,
  "operation": "add_step",
  "rationale": "two incidents continue past S6 into a scheduled task",
  "author": "human",
  "supporting_event_ids": ["EVT-1", "EVT-2"],
  "step": {
    "step_id": "S7",
    "order": 7,
    "action_id": "exchange_scheduled_task",
    "label": "计划任务持久化",
    "action_regex": "(?i)schtasks(?:\\.exe)?\\s+/create",
    "expected_sources": ["hids"],
    "generic": false,
    "required": false
  }
}
```

Operations:

| operation | extra fields | auto-accept |
|---|---|---|
| `add_step` | `step` | yes, if gate passes and maturity ≥ repeated |
| `extend_step` | `step_id`, `action_regex` | yes only when the new regex is a strict widening |
| `add_source` | `step_id`, `add_sources` | yes, if gate passes |
| `set_required` | `step_id`, `required` | never (needs an explicit human accept) |

`supporting_event_ids` must belong to incidents already confirmed for the case, and at least
two independent incidents are required. The gate also re-runs retrieval over every stored
incident and refuses a change that flips another incident's top-1, drops the case's `strong`
count, or lowers its required coverage. A proposal that fails stays `candidate` and cannot be
accepted; that is expected for a case with only one confirmed incident.
