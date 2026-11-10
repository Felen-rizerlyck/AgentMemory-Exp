# Error Classification and Recovery

Choose the narrowest error class supported by evidence. Classify from the
exception type and protocol status, not from words in an error message alone.
If caller input is invalid, do not label the tool endpoint unavailable.

## Built-in classes

| `error_class` | Typical evidence | Default retry policy | Caller action |
|---|---|---|---|
| `unreachable` | Connection refused/reset/DNS failure; adapter-mapped service unavailable (for example HTTP 503) | Retryable, scope key, fixed 15 min; max interval 30 min; TTL 24 h | Wait for the retry window; make one probe when allowed |
| `timeout` | Client timeout/deadline exceeded | Retryable, call key, exponential 30 s to 5 min; TTL 1 h | Check whether the operation is safe to retry; wait for probe decision |
| `rate_limit` | HTTP 429 or equivalent explicit quota signal | Retryable, scope key, exponential 1 min to 5 min; honor `Retry-After` | Respect server retry guidance; avoid parallel retries |
| `auth` | HTTP 401/403 or confirmed invalid credentials | Non-retryable, scope key; TTL 24 h | Stop and request credential/authorization correction; don't loop retries |
| `permission` | Local/OS access denied or tool permission rejection | Non-retryable, scope key; TTL 24 h | Check authorization/sandbox policy; do not mislabel as network failure |
| `schema` | Response parse/schema validation error | Non-retryable, call key; TTL 24 h | Inspect response contract/parser; don't retry unchanged input |
| `invalid_args` | Tool rejects arguments (for example HTTP 400) or argument validation fails | Non-retryable, call key; TTL 1 h | Correct the arguments; do not block the whole service |
| `not_found` | Requested resource/tool/record is confirmed absent (for example HTTP 404) | Non-retryable, call key; TTL 1 h | Verify identifier/path/query; do not retry unchanged request |
| `internal` | Confirmed tool-side internal error | Retryable, scope key, fixed 1 min; max 10 min; one retry after initial failure; TTL 1 h | Retry only when preflight allows it |
| `unknown` | Insufficient evidence to classify | Cautious retryable fallback, scope key, fixed 1 min; max 10 min; one retry after initial failure; TTL 1 h | Preserve redacted evidence and avoid confident claims about root cause |

Defaults live in `runtime_memory/data/policy.json` and may be overridden by a
deployment policy. Treat them as prototype starting values, not universal
production settings.

## Important adapter mapping details

- The core exception classifier recognizes common Python exceptions and
  selected HTTP status attributes/context. Many HTTP clients wrap network
  errors differently; the gateway should unwrap/map them explicitly.
- HTTP 401/403 → `auth`; 429 → `rate_limit`; 404 → `not_found`; caller-side
  4xx such as 400 → `invalid_args`. Map 5xx to `internal` or `unreachable`
  only when the service contract gives enough evidence.
- The local HTTP test gateway explicitly maps 503 to `unreachable`, 429 to
  `rate_limit`, 401 to `auth`, and 403 to `permission`. That is adapter logic,
  not a guarantee that every client adapter will classify statuses the same way.
- Pass a server-provided retry delay using `retry_after_s` when available.
  The store keeps the issue expiry from preceding a later retry time.
- For permission/auth/schema/argument errors, fix the cause or ask an operator
  to review. Do not repeatedly call the same operation to manufacture more
  evidence.

## Evidence and issue strength

- Repeated failures with the same `run_id` are not independent evidence.
- A retryable issue reaches `open` after failures in distinct runs. Without a
  `run_id`, the system cannot establish cross-run independence from repeated
  calls alone.
- Retryable issues block only until the recorded retry time; after the normal
  attempt budget is exhausted, the system still allows slower probes according
  to the retry interval. A probe decision authorizes one call, not a retry loop.
- An expired issue becomes stale and may allow a probe when
  `probe_after_expiry` is enabled. A successful call resolves the matching
  issue; otherwise follow the next decision or ask an operator.
- Non-retryable issues remain blocked until corrected/resolved or their expiry
  path allows a probe. Don't use `resolve`, `ignore`, or override to hide a
  model/tool error without a verified basis.
