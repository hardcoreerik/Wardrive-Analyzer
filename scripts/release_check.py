"""
release_check.py — pre-release gate for Wardrive Analyzer.

Checks:
  - requirements.txt and requirements-dev.txt exist
  - no .db files in repo root
  - no __pycache__ directories tracked by git
  - no token/secret files present
  - all .py files compile cleanly
  - pytest passes

Run with:
    python scripts/release_check.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PASS = "\u2713"
FAIL = "\u2717"

errors: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    status = PASS if ok else FAIL
    print(f"  [{status}] {label}" + (f": {detail}" if detail else ""))
    if not ok:
        errors.append(f"{label}{': ' + detail if detail else ''}")


print("=== Wardrive Analyzer release check ===\n")

# 1. requirements files
check("requirements.txt exists", (ROOT / "requirements.txt").is_file())
check("requirements-dev.txt exists", (ROOT / "requirements-dev.txt").is_file())

# 2. No .db files in root
root_dbs = list(ROOT.glob("*.db"))
check("no .db files in repo root", len(root_dbs) == 0, str(root_dbs) if root_dbs else "")

# 3. No committed __pycache__
pycache_dirs = [p for p in ROOT.rglob("__pycache__") if ".venv" not in str(p) and "build" not in str(p)]
check("no __pycache__ in source tree (outside venv/build)", len(pycache_dirs) == 0,
      f"{len(pycache_dirs)} found" if pycache_dirs else "")

# 4. No token/credential files
sensitive_patterns = ["*.token", "*.secret", "*.env", ".env"]
found_sensitive: list[Path] = []
for pat in sensitive_patterns:
    found_sensitive.extend(p for p in ROOT.glob(pat) if ".venv" not in str(p))
check("no credential files in root", len(found_sensitive) == 0, str(found_sensitive) if found_sensitive else "")

# 5. Syntax check all .py files
py_files = [p for p in ROOT.rglob("*.py") if ".venv" not in str(p) and "build" not in str(p)]
syntax_errors: list[str] = []
for f in py_files:
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(f)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        syntax_errors.append(f"{f.relative_to(ROOT)}: {result.stderr.strip()}")
check(f"syntax clean ({len(py_files)} .py files)", len(syntax_errors) == 0,
      "; ".join(syntax_errors) if syntax_errors else "")

# 6. pytest
print("\nRunning pytest ...\n")
pytest_result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--timeout=30", "-q"],
    cwd=str(ROOT),
)
check("pytest passes", pytest_result.returncode == 0)

# Summary
print("\n" + "=" * 40)
if errors:
    print(f"FAIL — {len(errors)} issue(s):")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("PASS — release check complete.")
