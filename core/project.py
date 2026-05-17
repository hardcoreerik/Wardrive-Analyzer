"""Run folder creation, manifest management, and project index HTML."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import List, Tuple

from .constants import NO_DATA, CORE_REVISION
from .helpers import now_str


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def create_run_dir(project_dir: str) -> Tuple[str, str]:
    """
    Create a new run directory under <project_dir>/runs/.
    Returns (run_dir, run_id).  Format: run_###_YYYYMMDD_HHMMSS
    """
    os.makedirs(project_dir, exist_ok=True)
    runs_root = os.path.join(project_dir, "runs")
    os.makedirs(runs_root, exist_ok=True)

    existing = [d for d in os.listdir(runs_root) if d.startswith("run_")]
    nums = []
    for d in existing:
        m = re.match(r"run_(\d+)", d)
        if m:
            try:
                nums.append(int(m.group(1)))
            except Exception:
                pass
    n = (max(nums) + 1) if nums else 1
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{n:03d}_{ts}"
    run_dir = os.path.join(runs_root, run_id)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir, run_id


def update_manifest(project_dir: str, run_id: str, artifacts: dict) -> None:
    path = os.path.join(project_dir, "project.json")
    data = _read_json(path)
    data.setdefault("schema_version", 2)
    data["revision"] = CORE_REVISION
    data.setdefault("runs", [])

    entry = {
        "run_id": run_id,
        "created": now_str(),
        "artifacts": {
            k: os.path.basename(v) if v and v != NO_DATA else v
            for k, v in artifacts.items()
            if isinstance(v, str)
        },
    }
    data["runs"].append(entry)
    try:
        _write_json(path, data)
    except Exception:
        pass


def update_project_index(project_dir: str) -> str:
    manifest_path = os.path.join(project_dir, "project.json")
    data = _read_json(manifest_path)
    runs = list(reversed(data.get("runs", [])))

    rows_html = ""
    for r in runs:
        run_id = r.get("run_id", "")
        created = r.get("created", "")
        arts = r.get("artifacts", {})
        out_rel = f"runs/{run_id}"

        def _link(label: str, key: str, default: str) -> str:
            fname = arts.get(key, default)
            if not fname or fname == NO_DATA:
                return f"{label}: N/A"
            href = f"{out_rel}/{fname}".replace("\\", "/")
            return f'<a href="{href}">{label}</a>'

        links = " | ".join([
            _link("Summary", "summary", "summary.html"),
            _link("Map", "map", "map.html"),
            _link("Master CSV", "csv", "wardrive_master.csv"),
            _link("PCAP", "pcap_summary_html", "pcap_summary.html"),
        ])
        rows_html += f"<tr><td>{run_id}</td><td>{created}</td><td>{links}</td></tr>\n"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>Wardrive Project Index</title>
<style>
  body{{background:black;color:limegreen;font-family:Consolas,monospace;padding:20px}}
  h1{{color:#00ffcc;text-shadow:0 0 6px #00ffcc}}
  table{{border-collapse:collapse;width:100%;margin-top:12px}}
  th,td{{border:1px solid limegreen;padding:8px;vertical-align:top}}
  a{{color:cyan;text-decoration:none}} a:hover{{text-decoration:underline}}
  .muted{{color:#A0FFA0}}
</style></head><body>
<h1>WARDRIVE PROJECT — Run History</h1>
<p class="muted">Each run is isolated in <code>runs/</code> — no overwrites.</p>
<table><tr><th>Run</th><th>Created</th><th>Artifacts</th></tr>
{rows_html}
</table></body></html>
"""
    index_path = os.path.join(project_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    return index_path
