from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any

from core import analyze
from error_logger import install_global_error_hooks, write_error_report


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return str(value)


def _emit_event(message: str) -> None:
    print(json.dumps({"event": str(message)}, ensure_ascii=False), file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        print(json.dumps({"status": "error", "error": "Missing request JSON path."}), flush=True)
        return 2

    request_path = argv[0]
    install_global_error_hooks(os.getcwd())

    try:
        with open(request_path, "r", encoding="utf-8") as f:
            request = json.load(f)
        wardrive_files = list(request.get("wardrive_files") or [])
        pcap_files = list(request.get("pcap_files") or [])
        project_dir = str(request.get("project_dir") or "")

        _emit_event("Analyzer subprocess online.")
        results = analyze(wardrive_files, pcap_files, project_dir, status_cb=_emit_event)
        print(json.dumps({"status": "ok", "results": _jsonable(results)}, ensure_ascii=False), flush=True)
        return 0
    except Exception as exc:
        report = write_error_report(
            "analysis_subprocess_failure",
            exc,
            context={"request_path": request_path},
            traceback_text=traceback.format_exc(),
        )
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "report": report,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
