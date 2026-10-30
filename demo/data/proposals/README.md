# Evolution proposals

Drop one JSON file here, then run from `demo/`:

```powershell
python src/manage_memory.py evolve propose --input data/proposals/<file>.json
python src/manage_memory.py evolve list
python src/manage_memory.py evolve accept PROP-... --basis "..."
```

A proposal is evidence plus a patch. It never edits the catalog by itself; `evolve propose` only
records it, and `evolve accept` is a separate, reviewed command.

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

`required` defaults to `false` for `add_step`: a completion stage that only some incidents reach is
optional by design. Write `"required": true` only when every confirmed incident must contain it.

Operations:

| operation | extra fields | auto-accept |
|---|---|---|
| `add_step` | `step` | yes, when the gate passes and the case has at least two supporting incidents |
| `extend_step` | `step_id`, `action_regex` | yes only when the new regex is a strict widening |
| `add_source` | `step_id`, `add_sources` | yes, when the gate passes (including foreign/shadow checks) |
| `set_required` | `step_id`, `required` | never (needs an explicit human accept) |
| `reorder_steps` | `order` (every step ID exactly once) | never |

`supporting_event_ids` must belong to incidents already confirmed or related for the case, and at
least two independent incidents are required. The deterministic gate re-runs retrieval over every
stored incident and refuses a change that flips another incident's top-1, matches another case's
event (including `related`/`fixture` ownership), drops the case's `strong` count, lowers required
coverage, or regresses held-out confirmed incidents. A proposal that fails stays `candidate` and
cannot be accepted; that is expected for a case with only one confirmed incident.
