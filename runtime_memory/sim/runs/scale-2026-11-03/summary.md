# Scale probe (synthetic JSONL events)

| events | preflight no run_id | preflight with run_id | report | check |
|---|---|---|---|---|
| 1000 | 0.97 ms | 15.54 ms | 10.13 ms | 11.07 ms |
| 5000 | 0.82 ms | 46.91 ms | 37.96 ms | 38.93 ms |
| 20000 | 0.9 ms | 155.88 ms | 150.21 ms | 145.99 ms |

`preflight with run_id` includes the per-run budget scan over all events; `preflight no run_id` skips it.
