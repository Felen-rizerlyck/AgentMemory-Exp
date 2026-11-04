# T6 concurrency / crash / partial write

| test | status | observed |
|---|---|---|
| concurrent_append | **FAIL** | `{"expected_lines": 200, "actual_lines": 165, "bad_lines": 0, "errors": [{"type": "PermissionError", "message": "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-conc-append-n87fgl2d\\\\events\\\\2026-11.jsonl.lock'"}]}` |
| concurrent_postflight | **FAIL** | `{"expected_issue_count": 2, "issue_records": 2, "issue_counts": [1, 1], "events": 2, "errors": []}` |
| partial_write_event_without_issue | **GAP** | `{"check_problems": [], "detected": false, "note": "plan T6: not detecting event-without-issue is a gap"}` |
| terminate_between_event_and_issue | **PASS** | `{"marker_seen": true, "check_problems": [], "corrupt_event_lines": 0, "event_count": 1, "issue_count": 0}` |

Notes:
- `concurrent_append`: 2 processes x 100 valid JSON lines.
- `concurrent_postflight`: 2 processes record the same failure.
- `partial_write_event_without_issue`: check() visibility.
- `terminate_between_event_and_issue`: simulated crash after the event append, before the issue update.
