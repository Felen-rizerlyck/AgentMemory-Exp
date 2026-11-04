# Scale probe (synthetic JSONL events)

| events | preflight no run_id | preflight with run_id | report | check |
|---|---|---|---|---|
| 1000 | 0.77 ms | 15.82 ms | 10.5 ms | 30.35 ms |
| 5000 | 0.9 ms | 44.68 ms | 37.99 ms | 39.46 ms |
| 20000 | 0.75 ms | 162.01 ms | 155.98 ms | 161.09 ms |

`preflight with run_id` includes the per-run budget scan over all events; `preflight no run_id` skips it.
