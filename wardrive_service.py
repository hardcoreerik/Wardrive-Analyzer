from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from core.analyze import analyze
from project_vault import (
    discover_project_runs,
    ensure_project_vault,
    evidence_summary,
    gather_project_inputs_for_analysis,
    list_import_history,
    list_project_evidence_detailed,
    scan_sd_folder,
)


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return str(value)


def result(status: str, **payload: Any) -> dict[str, Any]:
    body = {"status": status}
    body.update({k: _jsonable(v) for k, v in payload.items()})
    return body


def project_summary(project_dir: str, import_limit: int = 10) -> dict[str, Any]:
    db_path = ensure_project_vault(project_dir)
    logs, pcaps = gather_project_inputs_for_analysis(project_dir)
    runs = discover_project_runs(project_dir)
    latest_run = runs[0] if runs else None
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        db_path=db_path,
        evidence=evidence_summary(project_dir),
        analysis_inputs={"logs": len(logs), "pcaps": len(pcaps)},
        imports=list_import_history(project_dir, limit=import_limit),
        runs_count=len(runs),
        latest_run=latest_run,
    )


def evidence_list(project_dir: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    rows = list_project_evidence_detailed(project_dir)
    total = len(rows)
    offset = max(0, int(offset))
    limit = max(0, int(limit))
    page = rows[offset: offset + limit] if limit else rows[offset:]
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        total=total,
        offset=offset,
        limit=limit,
        evidence=page,
    )


def runs_list(project_dir: str, limit: int = 20) -> dict[str, Any]:
    runs = discover_project_runs(project_dir)
    limit = max(0, int(limit))
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        total=len(runs),
        runs=runs[:limit] if limit else runs,
    )


def latest_run(project_dir: str) -> dict[str, Any]:
    runs = discover_project_runs(project_dir)
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        latest_run=runs[0] if runs else None,
    )


def scan_folder(folder: str, limit: int = 250, include_hidden: bool = False) -> dict[str, Any]:
    candidates = scan_sd_folder(folder, include_hidden=include_hidden)
    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    recommended = 0
    for cand in candidates:
        by_kind[cand.kind] = by_kind.get(cand.kind, 0) + 1
        by_source[cand.source_app] = by_source.get(cand.source_app, 0) + 1
        if cand.recommended:
            recommended += 1
    limit = max(0, int(limit))
    return result(
        "ok",
        folder=os.path.abspath(folder),
        total=len(candidates),
        recommended=recommended,
        by_kind=by_kind,
        by_source=by_source,
        candidates=candidates[:limit] if limit else candidates,
    )


def analyze_project(
    project_dir: str,
    status_cb: Optional[Callable[[str], None]] = None,
    status_tail_limit: int = 80,
) -> dict[str, Any]:
    logs, pcaps = gather_project_inputs_for_analysis(project_dir)
    events: list[str] = []

    def capture_event(message: str) -> None:
        if len(events) >= status_tail_limit:
            events.pop(0)
        events.append(str(message))
        if status_cb:
            status_cb(str(message))

    if not logs and not pcaps:
        return result(
            "error",
            project_dir=os.path.abspath(project_dir),
            error="No attached logs or PCAPs found for this project.",
        )

    outputs = analyze(logs, pcaps, project_dir, status_cb=capture_event)
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        inputs={"logs": len(logs), "pcaps": len(pcaps)},
        outputs=outputs,
        status_tail=events,
    )


def dumps_json(data: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(_jsonable(data), indent=2 if pretty else None, sort_keys=False)
