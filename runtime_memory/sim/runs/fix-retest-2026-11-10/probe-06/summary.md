# T6 concurrency / crash / partial write

| test | status | observed |
|---|---|---|
| concurrent_append | **PASS** | `{"expected_lines": 200, "actual_lines": 200, "bad_lines": 0, "errors": []}` |
| concurrent_postflight | **PASS** | `{"expected_issue_records": 1, "expected_aggregated_failures": 2, "issue_records": 1, "issue_counts": [2], "events": 2, "errors": []}` |
| partial_write_event_without_issue | **PASS** | `{"check_problems": ["event OP-partial: failure has no matching issue (fp/None)"], "detected": true, "note": "plan T6: not detecting event-without-issue is a gap"}` |
| terminate_between_event_and_issue | **PASS** | `{"marker_seen": true, "check_problems": ["event OP-crash: failure has no matching issue (fp/)"], "corrupt_event_lines": 0, "event_count": 1, "issue_count": 0, "orphan_event_detected": true}` |

Notes:
- `concurrent_append`: 2 processes x 100 valid JSON lines.
- `concurrent_postflight`: 2 processes record the same failure.
- `partial_write_event_without_issue`: check() visibility.
- `terminate_between_event_and_issue`: simulated crash after the event append, before the issue update.
