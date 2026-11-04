#!/usr/bin/env python3
"""T7 retention / gc / stale-data simulation.

Generates 90 days of events (100/day) plus a mix of resolved/open issues, then
runs gc in dry-run and apply mode and records what was deleted.

Run from ``runtime_memory/``::

    python sim/retention.py --days 90 --run-id exec-<UTC>-retention
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.models import Issue  # noqa: E402
from runtime_memory.store import Store, atomic_write_json  # noqa: E402
from runtime_memory.timeutil import iso  # noqa: E402


def make_event(day_index: int, item: int, now: dt.datetime) -> dict[str, Any]:
    stamp = now - dt.timedelta(days=day_index)
    return {
        "event_id": f"OP-{day_index:03d}-{item:03d}",
        "ts": iso(stamp),
        "component": "mcp" if item % 2 == 0 else "parser",
        "tool": "hunt.query" if item % 2 == 0 else "pcap.parse",
        "action": "search" if item % 2 == 0 else "parse",
        "target": "http://x/hunt",
        "outcome": "fail" if item % 5 == 0 else "ok",
        "fingerprint": "fp",
        "run_id": f"retention-{day_index // 10}",
        "schema_version": 1,
    }


def make_issue(issue_id: str, status: str, resolved_at: dt.datetime | None,
               now: dt.datetime) -> Issue:
    return Issue(
        issue_id=issue_id,
        fingerprint=f"fp-{issue_id}",
        key_level="scope", scope="global", environment_id="lab-a",
        component="mcp", tool="hunt.query", action="search",
        target="http://x/hunt", error_class="unreachable",
        status=status, first_seen=iso(now - dt.timedelta(days=120)),
        last_seen=iso(now - dt.timedelta(days=100)),
        count=2, attempts=2,
        retry_policy={"retryable": True, "max_attempts": 3},
        next_retry_at=iso(now - dt.timedelta(days=100)),
        expires_at=iso(now + dt.timedelta(days=30)),
        resolved_at=iso(resolved_at) if resolved_at else None,
        resolved_basis="retention test" if resolved_at else "",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="T7 retention/gc simulation")
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--per-day", type=int, default=100)
    parser.add_argument("--run-id", default="retention-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    now = dt.datetime.now(dt.timezone.utc)
    folder = tempfile.mkdtemp(prefix="rtmem-retention-")
    store = Store(folder)
    store.ensure()
    monthly: dict[str, list[str]] = {}
    for day in range(args.days):
        for item in range(args.per_day):
            record = make_event(day, item, now)
            month = record["ts"][:7]
            monthly.setdefault(month, []).append(
                json.dumps(record, ensure_ascii=False))
    for month, lines in monthly.items():
        path = store.events_dir / f"{month}.jsonl"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    old_resolved = make_issue("ISS-old-resolved", "resolved",
                              now - dt.timedelta(days=100), now)
    old_open = make_issue("ISS-old-open", "open", None, now)
    recent_resolved = make_issue("ISS-recent-resolved", "resolved",
                                 now - dt.timedelta(days=10), now)
    recent_open = make_issue("ISS-recent-open", "open", None, now)
    for issue in (old_resolved, old_open, recent_resolved, recent_open):
        store.upsert_issue(issue)

    def snapshot() -> dict[str, Any]:
        files = sorted(store.events_dir.glob("*.jsonl"))
        return {
            "event_files": len(files),
            "event_bytes": sum(path.stat().st_size for path in files),
            "event_lines": sum(len(path.read_text(encoding="utf-8").splitlines())
                               for path in files),
            "issues": len(store.load_issues()["issues"]),
            "issue_ids": [item["issue_id"] for item in store.load_issues()["issues"]],
            "issues_json_bytes": store.issues_path.stat().st_size,
        }

    before = snapshot()
    dry = store.gc(events_days=30, issues_days=90, dry_run=True)
    after_dry = snapshot()
    apply_result = store.gc(events_days=30, issues_days=90, dry_run=False)
    after_apply = snapshot()
    problems = store.check()

    result = {
        "schema_version": 1,
        "days": args.days,
        "per_day": args.per_day,
        "before": before,
        "dry_run": dry,
        "after_dry_run": after_dry,
        "apply": apply_result,
        "after_apply": after_apply,
        "dry_run_deleted_nothing": before == after_dry,
        "open_issues_kept": all(item in after_apply["issue_ids"]
                                for item in ("ISS-old-open", "ISS-recent-open")),
        "old_resolved_deleted": "ISS-old-resolved" not in after_apply["issue_ids"],
        "recent_resolved_kept": "ISS-recent-resolved" in after_apply["issue_ids"],
        "check_problems": problems,
    }
    atomic_write_json(out / "metrics.json", result)
    lines = [
        "# T7 retention / gc",
        "",
        f"days={args.days}, per_day={args.per_day}",
        "",
        "| phase | event files | event lines | event bytes | issues | issues.json |",
        "|---|---|---|---|---|---|",
    ]
    for label, snap in (("before", before), ("after dry-run", after_dry),
                        ("after apply", after_apply)):
        lines.append(f"| {label} | {snap['event_files']} | {snap['event_lines']} | "
                     f"{snap['event_bytes']} | {snap['issues']} | "
                     f"{snap['issues_json_bytes']} |")
    lines += ["", f"dry_run: `{json.dumps(dry)}`",
              f"apply: `{json.dumps(apply_result)}`",
              f"dry_run_deleted_nothing: {result['dry_run_deleted_nothing']}",
              f"open_issues_kept: {result['open_issues_kept']}",
              f"old_resolved_deleted: {result['old_resolved_deleted']}",
              f"recent_resolved_kept: {result['recent_resolved_kept']}",
              f"check: {problems or 'clean'}"]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    shutil.rmtree(folder, ignore_errors=True)
    print("\n".join(lines))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
