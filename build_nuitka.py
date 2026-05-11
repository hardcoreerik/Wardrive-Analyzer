"""
Nuitka build script for Wardrive Analyzer.
Produces a faster, smaller EXE than PyInstaller.

Usage:
    python build_nuitka.py

Requirements:
    pip install nuitka ordered-set zstandard

Nuitka compiles Python to C and links it, removing the interpreter overhead.
Typical result: ~40 MB (vs ~120 MB PyInstaller), 2-3x faster cold start.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

DATA_FILES = [
    ("oui.csv", "."),
    ("style_scene.qss", "."),
    ("assets", "assets"),
]

# Build --include-data-files and --include-data-dir arguments
data_args = []
for src, dst in DATA_FILES:
    src_abs = os.path.join(ROOT, src)
    if os.path.isdir(src_abs):
        data_args += [f"--include-data-dir={src_abs}={dst}"]
    elif os.path.isfile(src_abs):
        data_args += [f"--include-data-files={src_abs}={dst}/{os.path.basename(src)}"]

cmd = [
    sys.executable, "-m", "nuitka",
    "--standalone",
    "--onefile",
    "--enable-plugin=pyside6",
    "--windows-console-mode=disable",
    "--windows-icon-from-ico=assets/icon.ico" if os.path.exists(os.path.join(ROOT, "assets", "icon.ico")) else "",
    f"--output-filename=WardriveAnalyzer",
    f"--output-dir={os.path.join(ROOT, 'dist_nuitka')}",
    "--assume-yes-for-downloads",
    "--show-progress",
    *data_args,
    os.path.join(ROOT, "run_step3d_scene.py"),
]

# Remove empty args (e.g. missing icon)
cmd = [c for c in cmd if c]

print("=" * 60)
print("Wardrive Analyzer — Nuitka build")
print("=" * 60)
print("Command:")
print(" ".join(cmd))
print()

result = subprocess.run(cmd, cwd=ROOT)
sys.exit(result.returncode)
