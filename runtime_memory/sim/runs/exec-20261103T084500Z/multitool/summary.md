# T4 multi-tool / alternative workload

seeds per config: 30; 3 needed tools; alternatives succeed with p=0.7.

| config | task success | calls | failures | blocked | mean false blocks | mean TTS |
|---|---|---|---|---|---|---|
| baseline | 0.233 | 44.1 | 27.667 | 0 | 0 | 565.714 |
| shadow | 0.233 | 44.1 | 27.667 | 26.633 | 1.467 | 565.714 |
| enforce_obedient | 1.0 | 4.233 | 2.5 | 6.867 | 0 | 162 |
| enforce_naive | 0.233 | 13 | 3.533 | 35 | 0 | 900 |

## Cross-tool checks

```json
{
  "checks": {
    "unrelated_tool_allowed": true,
    "same_scope_blocked": true,
    "call_level_args_isolated": true,
    "workaround_in_alternatives": true,
    "same_component_other_tool_allowed": true
  },
  "all_pass": true
}
```

## Comparisons

```json
{
  "obedient_not_below_baseline": true,
  "naive_worse_than_obedient": true
}
```
