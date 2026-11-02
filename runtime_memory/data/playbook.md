# Runtime Memory Playbook

This file is for curated, human-reviewed handling notes.

Rules:

- Do not auto-generate an entry from a single failure.
- Record the symptom, the environment, the workaround, and the expiry condition.
- Link back to the issue id(s) that justify the note.

## Example (not active)

- Symptom: `hunt.query` returns ECONNREFUSED for `10.7.194.120:22196`.
- Environment: `lab-a`.
- Workaround: use a local pcap; probe once after 30 minutes.
- Basis: ISS-... (3 failures, reviewed on 2026-11-02).
- Expires when: the endpoint is restored or the network policy changes.
