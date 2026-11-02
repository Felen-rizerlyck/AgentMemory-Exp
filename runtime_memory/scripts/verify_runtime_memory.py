#!/usr/bin/env python3
"""Read-only verification matrix for the runtime-memory prototype.

Run from runtime_memory/:

    python scripts/verify_runtime_memory.py

The demo commands use temporary data directories, so this script does not
mutate the checked-in data/ store.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(label: str, command: list[str]) -> bool:
    print(f"\n== {label} ==")
    result = subprocess.run(command, cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = (result.stdout or "").strip()
    if output:
        print(output)
    if result.returncode != 0:
        print(f"FAILED: {label} (exit {result.returncode})")
        return False
    print(f"OK: {label}")
    return True


def main() -> int:
    checks = [
        ("compile", [sys.executable, "-m", "compileall", "-q", "src"]),
        ("tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
        ("check", [sys.executable, "src/manage_runtime_memory.py", "check"]),
        ("shadow demo", [sys.executable, "src/run_runtime_demo.py", "--shadow"]),
        ("enforce demo", [sys.executable, "src/run_runtime_demo.py", "--enforce"]),
    ]
    results = [run(label, command) for label, command in checks]
    print("\nRuntime memory verification:", "PASS" if all(results) else "FAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
