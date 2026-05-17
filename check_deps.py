"""
Startup dependency validator for Wardrive Analyzer.

Run this before launch to get actionable install guidance if anything is missing.
Called automatically by run_step3d_scene.py before the GUI starts.
"""
from __future__ import annotations

import importlib
import sys
from typing import List, Tuple


# (module, pip_package, required)
_DEPS: List[Tuple[str, str, bool]] = [
    ("PySide6", "PySide6>=6.6.0", True),
    ("dpkt", "dpkt>=1.9.8", False),
    ("openpyxl", "openpyxl>=3.1.0", False),
    ("keyring", "keyring>=24.0.0", False),
]


def check_dependencies() -> Tuple[List[str], List[str]]:
    """
    Returns (missing_required, missing_optional).
    Each entry is a pip install string for the package.
    """
    missing_required: List[str] = []
    missing_optional: List[str] = []
    for module, pip_pkg, required in _DEPS:
        try:
            importlib.import_module(module)
        except ImportError:
            if required:
                missing_required.append(pip_pkg)
            else:
                missing_optional.append(pip_pkg)
    return missing_required, missing_optional


def validate_or_exit() -> None:
    """
    Call from run_step3d_scene.py before starting the GUI.
    Prints actionable messages and exits if required deps are missing.
    Optional deps print warnings only.
    """
    missing_required, missing_optional = check_dependencies()

    if missing_optional:
        print("[WARN] Optional dependencies missing — some features will be disabled:", file=sys.stderr)
        for pkg in missing_optional:
            print(f"       pip install {pkg}", file=sys.stderr)

    if missing_required:
        print("[ERROR] Required dependencies are missing. The application cannot start.", file=sys.stderr)
        print("        Install them with:", file=sys.stderr)
        for pkg in missing_required:
            print(f"        pip install {pkg}", file=sys.stderr)
        print("", file=sys.stderr)
        print("        Or install all at once:", file=sys.stderr)
        print("        pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    req, opt = check_dependencies()
    if not req and not opt:
        print("All dependencies satisfied.")
    else:
        validate_or_exit()
