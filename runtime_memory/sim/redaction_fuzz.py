#!/usr/bin/env python3
"""T8 redaction fuzz for runtime-memory.

Generates 1000 messages containing tokens, passwords, cookies, API keys and
private keys, checks ``redact()``, then stores a sample through ``postflight``
and scans the JSONL/JSON files for leaked secrets.  JSON-formatted secrets and
URL userinfo are included because real tool errors often use JSON.

Run from ``runtime_memory/``::

    python sim/redaction_fuzz.py --messages 1000 --run-id exec-<UTC>-redaction
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.redact import redact  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402

PATTERNS = (
    "authorization", "password", "token", "api_key", "cookie",
    "private_key", "json_password", "json_token", "json_authorization",
    "normal",
)


def make_secret(rng: random.Random, tag: str, index: int) -> str:
    return f"SEC-{tag}-{index:04d}-{rng.randrange(10**8):08d}"


def make_message(rng: random.Random, index: int) -> tuple[str, list[str], str]:
    template = PATTERNS[index % len(PATTERNS)]
    secret = make_secret(rng, template.upper(), index)
    if template == "authorization":
        return f"Authorization: Bearer {secret}", [secret], template
    if template == "password":
        return f"login failed password={secret}", [secret], template
    if template == "token":
        return f"request token={secret}", [secret], template
    if template == "api_key":
        return f"api_key={secret}", [secret], template
    if template == "cookie":
        return f"Cookie: session={secret}", [secret], template
    if template == "private_key":
        return (f"-----BEGIN RSA PRIVATE KEY-----\n{secret}\n"
                f"-----END RSA PRIVATE KEY-----"), [secret], template
    if template == "json_password":
        return json.dumps({"password": secret, "ok": False}), [secret], template
    if template == "json_token":
        return json.dumps({"token": secret, "error": "expired"}), [secret], template
    if template == "json_authorization":
        return json.dumps({"Authorization": f"Bearer {secret}"}), [secret], template
    return f"normal informational message {index}", [], template


def main() -> int:
    parser = argparse.ArgumentParser(description="T8 redaction fuzz")
    parser.add_argument("--messages", type=int, default=1000)
    parser.add_argument("--run-id", default="redaction-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    rng = random.Random(20261103)
    redaction_leaks: list[dict[str, Any]] = []
    by_pattern: dict[str, dict[str, int]] = {}
    messages = []
    for index in range(args.messages):
        text, secrets, pattern = make_message(rng, index)
        redacted = redact(text)
        stats = by_pattern.setdefault(pattern, {"checked": 0, "leaks": 0})
        stats["checked"] += 1
        for secret in secrets:
            if secret in redacted:
                stats["leaks"] += 1
                redaction_leaks.append({"pattern": pattern, "index": index,
                                        "secret": secret,
                                        "redacted": redacted[:120]})
        if index < 40:
            messages.append((text, secrets))

    folder = tempfile.mkdtemp(prefix="rtmem-redaction-")
    runtime = RuntimeMemory(folder, policy=Policy(default_policy()))
    stored_secrets: list[str] = []
    for index, (text, secrets) in enumerate(messages):
        request = OperationRequest(
            component="mcp", tool="hunt.query", action="search",
            target="http://10.0.0.1/hunt", args={"q": "x"},
            scope="global", environment_id="lab-a", run_id="redaction")
        runtime.postflight(request, "fail", error_class="unknown", message=text)
        stored_secrets.extend(secrets)

    # URL userinfo is not part of message redaction, but it is persisted in
    # issue.target; include it so the report shows that separate gap.
    target_secret = "SEC-TARGET-0001-99999999"
    runtime.postflight(OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target=f"https://user:{target_secret}@10.0.0.1/hunt",
        args={"q": "x"}, scope="global", environment_id="lab-a",
        run_id="redaction-target"), "fail", error_class="unreachable")

    file_texts: dict[str, str] = {}
    for path in Path(folder).rglob("*"):
        if path.is_file() and path.suffix in (".json", ".jsonl", ".md"):
            try:
                file_texts[str(path.relative_to(folder))] = path.read_text(
                    encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
    stored_leaks: list[dict[str, Any]] = []
    for relative, text in file_texts.items():
        for secret in set(stored_secrets):
            if secret in text:
                stored_leaks.append({"file": relative, "secret": secret,
                                     "pattern": "stored_message"})
        if target_secret in text:
            stored_leaks.append({"file": relative, "secret": target_secret,
                                 "pattern": "target_userinfo"})

    plan_patterns = [name for name in by_pattern
                     if not name.startswith("json_")]
    plan_leaks = sum(by_pattern[name]["leaks"] for name in plan_patterns)
    json_leaks = sum(by_pattern[name]["leaks"] for name in by_pattern
                     if name.startswith("json_"))
    storage_plan_leaks = [item for item in stored_leaks
                          if item["pattern"] != "target_userinfo"]
    target_leaks = [item for item in stored_leaks
                    if item["pattern"] == "target_userinfo"]
    result = {
        "schema_version": 1,
        "messages": args.messages,
        "stored_messages": len(messages),
        "by_pattern": by_pattern,
        "plan_pattern_leaks": plan_leaks,
        "json_pattern_leaks": json_leaks,
        "redaction_leak_samples": redaction_leaks[:10],
        "stored_leaks": stored_leaks[:20],
        "storage_message_leaks": len(storage_plan_leaks),
        "target_userinfo_leaks": len(target_leaks),
        "normal_text_preserved": redact("normal informational message") ==
                                 "normal informational message",
    }
    atomic_write_json(out / "metrics.json", result)
    lines = [
        "# T8 redaction fuzz",
        "",
        f"messages: {args.messages}; stored through postflight: {len(messages)}",
        "",
        "| pattern | checked | leaks |", "|---|---|---|",
    ]
    for pattern, stats in sorted(by_pattern.items()):
        lines.append(f"| {pattern} | {stats['checked']} | {stats['leaks']} |")
    lines += [
        "",
        f"plan-pattern leaks: {plan_leaks}",
        f"JSON-pattern leaks: {json_leaks}",
        f"stored message leaks: {len(storage_plan_leaks)}",
        f"target userinfo leaks: {len(target_leaks)}",
        f"normal text preserved: {result['normal_text_preserved']}",
        "",
        "Note: the plan lists header/password/token/cookie/private-key "
        "patterns; JSON-formatted secrets and URL userinfo are included as "
        "realistic additional variants.",
    ]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    shutil.rmtree(folder, ignore_errors=True)
    print("\n".join(lines))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
