"""File store for runtime memory: JSONL traces + atomic issue snapshots."""
from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from .models import (ACTIONS, KEY_LEVELS, OUTCOMES, STATUSES, Issue,
                     OperationEvent)
from .policy import Policy, default_policy
from .timeutil import parse_iso, utcnow

RUNTIME_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = RUNTIME_ROOT / "data"
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


_LOCK_STATE = threading.local()


def _acquire_os_lock(handle, timeout: float) -> None:
    started = time.monotonic()
    while True:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() - started > timeout:
                raise TimeoutError("could not acquire writer lock")
            time.sleep(0.05)


def _release_os_lock(handle) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def file_lock(lock_path: Path, timeout: float = 30.0) -> Iterator[None]:
    """Reentrant, cross-process lock on a persistent lock file.

    The lock file is kept on disk: unlinking a lock file is racy on Windows and
    was the source of ``PermissionError`` / lost JSONL lines.  OS-level locks
    (``msvcrt`` on Windows, ``fcntl`` on POSIX) are released automatically if
    the process dies.
    """
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    key = str(lock_path.resolve())
    held = getattr(_LOCK_STATE, "held", None)
    if held is None:
        held = {}
        _LOCK_STATE.held = held
    if key in held:
        held[key] += 1
        try:
            yield
        finally:
            held[key] -= 1
            if held[key] == 0:
                del held[key]
        return

    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        _acquire_os_lock(handle, timeout)
        held[key] = 1
        try:
            yield
        finally:
            del held[key]
            _release_os_lock(handle)
    finally:
        handle.close()


def append_jsonl(path: Path, record: dict[str, Any],
                 lock_path: Path | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with file_lock(lock_path or path.with_name(path.name + ".lock")):
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path.name} line {number}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"{path.name} line {number}: record must be an object")
            records.append(record)
    return records


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n",
                                     dir=path.parent, suffix=".tmp",
                                     delete=False) as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


class Store:
    def __init__(self, root: Path | str = DEFAULT_DATA_DIR):
        self.root = Path(root).resolve()
        self.events_dir = self.root / "events"
        self.policy_path = self.root / "policy.json"
        self.issues_path = self.root / "issues.json"
        self.decisions_path = self.root / "decisions.jsonl"
        self.overrides_path = self.root / "overrides.jsonl"
        self.playbook_path = self.root / "playbook.md"
        self.write_lock_path = self.root / ".writer.lock"

    def writer_lock(self):
        return file_lock(self.write_lock_path)

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.writer_lock():
            self.events_dir.mkdir(parents=True, exist_ok=True)
            if not self.policy_path.exists():
                atomic_write_json(self.policy_path, default_policy())
            if not self.issues_path.exists():
                atomic_write_json(self.issues_path, {"schema_version": 1, "issues": []})
            for path in (self.decisions_path, self.overrides_path):
                if not path.exists():
                    path.touch()
            if not self.playbook_path.exists():
                self.playbook_path.write_text(
                    "# Runtime Memory Playbook\n\n"
                    "Curated, human-reviewed handling notes live here. "
                    "Do not auto-generate entries from a single failure.\n",
                    encoding="utf-8",
                )

    # -- policy ---------------------------------------------------------
    def load_policy(self) -> Policy:
        self.ensure()
        return Policy.load(self.policy_path)

    # -- events ---------------------------------------------------------
    def event_path(self, event: OperationEvent) -> Path:
        month = (event.ts or "")[:7]
        if not _MONTH_RE.match(month):
            month = utcnow().strftime("%Y-%m")
        return self.events_dir / f"{month}.jsonl"

    def append_event(self, event: OperationEvent) -> None:
        append_jsonl(self.event_path(event), event.to_dict(),
                     lock_path=self.write_lock_path)

    def read_events(self, since=None) -> list[dict[str, Any]]:
        with self.writer_lock():
            records: list[dict[str, Any]] = []
            for path in sorted(self.events_dir.glob("*.jsonl")):
                for record in read_jsonl(path):
                    if since is not None:
                        stamp = parse_iso(record.get("ts"))
                        if stamp is None or stamp < since:
                            continue
                    records.append(record)
            records.sort(key=lambda item: str(item.get("ts", "")))
            return records

    # -- decisions / overrides -----------------------------------------
    def append_decision(self, record: dict[str, Any]) -> None:
        append_jsonl(self.decisions_path, record, lock_path=self.write_lock_path)

    def read_decisions(self, since=None) -> list[dict[str, Any]]:
        with self.writer_lock():
            records = read_jsonl(self.decisions_path)
            if since is not None:
                filtered = []
                for record in records:
                    stamp = parse_iso(record.get("ts"))
                    if stamp is not None and stamp >= since:
                        filtered.append(record)
                records = filtered
            return records

    def append_override(self, record: dict[str, Any]) -> None:
        append_jsonl(self.overrides_path, record, lock_path=self.write_lock_path)

    def read_overrides(self) -> list[dict[str, Any]]:
        with self.writer_lock():
            return read_jsonl(self.overrides_path)

    # -- issues ---------------------------------------------------------
    def load_issues(self) -> dict[str, Any]:
        with self.writer_lock():
            if not self.issues_path.exists():
                return {"schema_version": 1, "issues": []}
            data = json.loads(self.issues_path.read_text(encoding="utf-8-sig"))
            if not isinstance(data, dict) or not isinstance(data.get("issues"), list):
                raise ValueError("issues.json must contain an issues list")
            return data

    def save_issues(self, data: dict[str, Any]) -> None:
        data.setdefault("schema_version", 1)
        with self.writer_lock():
            atomic_write_json(self.issues_path, data)

    def list_issues(self, status: str | None = None,
                    include_resolved: bool = True) -> list[dict[str, Any]]:
        issues = self.load_issues()["issues"]
        if status:
            issues = [item for item in issues if item.get("status") == status]
        elif not include_resolved:
            issues = [item for item in issues
                      if item.get("status") not in ("resolved",)]
        return issues

    def find_issues(self, fingerprints: list[str] | set[str],
                    statuses: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        wanted = set(fingerprints)
        issues = self.load_issues()["issues"]
        result = [item for item in issues if item.get("fingerprint") in wanted]
        if statuses is not None:
            result = [item for item in result if item.get("status") in statuses]
        return result

    def find_issue(self, fingerprint: str, error_class: str,
                   include_resolved: bool = True,
                   scope: str | None = None,
                   scope_id: str | None = None) -> dict[str, Any] | None:
        matches = [
            item for item in self.load_issues()["issues"]
            if item.get("fingerprint") == fingerprint
            and item.get("error_class") == error_class
            and (include_resolved or item.get("status") != "resolved")
            and (scope is None or item.get("scope") == scope)
            and (scope_id is None or item.get("scope_id", "") == scope_id)
        ]
        if not matches:
            return None
        # Prefer a live issue if a duplicate ever exists; a resolved record is
        # history, not the thing a new failure should update.
        live = [item for item in matches if item.get("status") != "resolved"]
        return (live or matches)[0]

    def get_issue(self, issue_id: str) -> dict[str, Any] | None:
        for item in self.load_issues()["issues"]:
            if item.get("issue_id") == issue_id:
                return item
        return None

    @staticmethod
    def _issue_key(item: dict[str, Any]) -> tuple:
        return (item.get("fingerprint"), item.get("error_class"),
                item.get("scope", "global"), item.get("scope_id", ""))

    @staticmethod
    def _merge_issues(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        """Merge two issues that raced to be created with the same key."""
        merged = dict(existing)
        merged["count"] = int(existing.get("count", 0)) + int(incoming.get("count", 0))
        merged["attempts"] = int(existing.get("attempts", 0)) + int(incoming.get("attempts", 0))
        merged["first_seen"] = min(str(existing.get("first_seen", "")),
                                   str(incoming.get("first_seen", "")))
        merged["last_seen"] = max(str(existing.get("last_seen", "")),
                                  str(incoming.get("last_seen", "")))
        merged["confidence"] = max(float(existing.get("confidence", 0) or 0),
                                   float(incoming.get("confidence", 0) or 0))
        merged["source_event_ids"] = list(dict.fromkeys(
            list(existing.get("source_event_ids") or [])
            + list(incoming.get("source_event_ids") or [])))[-20:]
        if existing.get("status") not in ("resolved", "mitigated") and incoming.get("status") in (
                "open", "probing", "stale"):
            merged["status"] = incoming["status"]
        if existing.get("status") in ("resolved", "mitigated") and incoming.get("status") not in (
                "resolved", "mitigated"):
            merged["status"] = incoming["status"]
            merged["resolution"] = ""
            merged["resolved_at"] = None
            merged["resolved_basis"] = ""
        for field_name in ("next_retry_at", "expires_at"):
            values = [str(value) for value in (existing.get(field_name),
                                               incoming.get(field_name)) if value]
            if values:
                merged[field_name] = max(values)
        merged["workaround"] = existing.get("workaround") or incoming.get("workaround", "")
        return merged

    def upsert_issue(self, issue: Issue | dict[str, Any]) -> dict[str, Any]:
        record = issue.to_dict() if isinstance(issue, Issue) else dict(issue)
        with self.writer_lock():
            data = self.load_issues()
            items = data["issues"]
            for index, item in enumerate(items):
                if item.get("issue_id") == record.get("issue_id"):
                    items[index] = record
                    self.save_issues(data)
                    return record
            key = self._issue_key(record)
            for index, item in enumerate(items):
                if self._issue_key(item) == key:
                    merged = self._merge_issues(item, record)
                    items[index] = merged
                    self.save_issues(data)
                    return merged
            items.append(record)
            self.save_issues(data)
            return record

    def delete_issues(self, issue_ids: set[str]) -> int:
        with self.writer_lock():
            data = self.load_issues()
            before = len(data["issues"])
            data["issues"] = [item for item in data["issues"]
                              if item.get("issue_id") not in issue_ids]
            if len(data["issues"]) != before:
                self.save_issues(data)
            return before - len(data["issues"])

    # -- checks / stats -------------------------------------------------
    def check(self) -> list[str]:
        problems: list[str] = []
        try:
            problems.extend(self.load_policy().validate())
        except (ValueError, json.JSONDecodeError) as error:
            problems.append(f"policy: {error}")
        try:
            issues = self.load_issues()["issues"]
        except (ValueError, json.JSONDecodeError) as error:
            return problems + [f"issues: {error}"]
        seen_ids: set[str] = set()
        for item in issues:
            issue_id = item.get("issue_id")
            if not issue_id or issue_id in seen_ids:
                problems.append(f"issue: duplicate or missing issue_id {issue_id!r}")
                continue
            seen_ids.add(issue_id)
            if item.get("status") not in STATUSES:
                problems.append(f"{issue_id}: unsupported status {item.get('status')!r}")
            if item.get("key_level") not in KEY_LEVELS:
                problems.append(f"{issue_id}: unsupported key_level {item.get('key_level')!r}")
            if not item.get("fingerprint"):
                problems.append(f"{issue_id}: empty fingerprint")
            if not isinstance(item.get("count"), int) or item.get("count", 0) < 1:
                problems.append(f"{issue_id}: count must be a positive integer")
            if not isinstance(item.get("attempts"), int) or item.get("attempts", 0) < 0:
                problems.append(f"{issue_id}: attempts must be a non-negative integer")
            for field_name in ("next_retry_at", "expires_at"):
                value = item.get(field_name)
                if value and parse_iso(value) is None:
                    problems.append(f"{issue_id}: {field_name} is not ISO 8601")
        try:
            decisions = self.read_decisions()
            events = self.read_events()
        except ValueError as error:
            return problems + [f"journal: {error}"]
        for record in decisions:
            if record.get("decision", record.get("action")) not in ACTIONS:
                problems.append(f"decision {record.get('decision_id')}: bad action")
        for record in events:
            if record.get("outcome") not in OUTCOMES:
                problems.append(f"event {record.get('event_id')}: bad outcome")
        return problems

    def state(self, policy: Policy | None = None) -> dict[str, Any]:
        issues = self.load_issues()["issues"]
        counts = {status: 0 for status in STATUSES}
        for item in issues:
            status = item.get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
        events = self.read_events()
        decisions = self.read_decisions()
        return {
            "root": str(self.root),
            "enforce": (policy or self.load_policy()).enforce,
            "events": len(events),
            "decisions": len(decisions),
            "overrides": len(self.read_overrides()),
            "issues": len(issues),
            "issues_by_status": counts,
            "last_event_at": events[-1].get("ts") if events else None,
        }

    def gc(self, *, events_days: int = 30, issues_days: int = 90,
           dry_run: bool = True) -> dict[str, int]:
        now = utcnow()
        event_cutoff = now.timestamp() - events_days * 86400
        issue_cutoff = now.timestamp() - issues_days * 86400
        deleted_files = 0
        deleted_events = 0
        for path in sorted(self.events_dir.glob("*.jsonl")):
            records = read_jsonl(path)
            stamps = [parse_iso(item.get("ts")) for item in records]
            valid = [stamp for stamp in stamps if stamp is not None]
            if valid and all(stamp.timestamp() < event_cutoff for stamp in valid):
                deleted_files += 1
                deleted_events += len(records)
                if not dry_run:
                    path.unlink(missing_ok=True)
        data = self.load_issues()
        keep = []
        deleted_issues = 0
        for item in data["issues"]:
            resolved_at = parse_iso(item.get("resolved_at"))
            if item.get("status") == "resolved" and resolved_at is not None \
                    and resolved_at.timestamp() < issue_cutoff:
                deleted_issues += 1
                continue
            keep.append(item)
        if not dry_run and deleted_issues:
            data["issues"] = keep
            self.save_issues(data)
        return {"event_files": deleted_files, "events": deleted_events,
                "issues": deleted_issues, "dry_run": int(dry_run)}
