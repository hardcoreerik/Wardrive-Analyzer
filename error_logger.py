from __future__ import annotations

import json
import os
import platform
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

_CONTROL_RE = __import__("re").compile(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]")
_MAX_TEXT = 12000


def safe_text(value: Any, limit: int = _MAX_TEXT) -> str:
    text = str(value) if value is not None else ""
    text = _CONTROL_RE.sub("", text).replace("\ufffd", "?")
    if len(text) > limit:
        return text[:limit] + "\n... [truncated]"
    return text


def error_reports_dir(base_dir: Optional[str] = None) -> Path:
    root = Path(base_dir or os.getcwd())
    path = root / "error_reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _tail_file(path: Path, limit: int = 20000) -> str:
    try:
        if not path.exists() or path.stat().st_size <= 0:
            return ""
        with path.open("rb") as f:
            if path.stat().st_size > limit:
                f.seek(-limit, os.SEEK_END)
            data = f.read()
        return safe_text(data.decode("utf-8", errors="replace"), limit=limit)
    except Exception as exc:
        return f"(failed to read {path.name}: {exc})"


def write_error_report(
    title: str,
    exc: BaseException | None = None,
    *,
    context: Optional[dict[str, Any]] = None,
    traceback_text: str = "",
    base_dir: Optional[str] = None,
) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_title = "".join(ch if ch.isalnum() else "_" for ch in title.lower()).strip("_")[:60] or "error"
    path = error_reports_dir(base_dir) / f"{stamp}_{safe_title}.json"

    if exc is not None and not traceback_text:
        traceback_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    payload = {
        "title": safe_text(title, 500),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "cwd": os.getcwd(),
        "executable": sys.executable,
        "python": sys.version,
        "platform": platform.platform(),
        "thread": threading.current_thread().name,
        "exception_type": type(exc).__name__ if exc else "",
        "exception": safe_text(exc, 2000) if exc else "",
        "traceback": safe_text(traceback_text),
        "context": {str(k): safe_text(v, 3000) for k, v in (context or {}).items()},
        "wardrive_run_log_tail": _tail_file(Path(os.getcwd()) / "wardrive_run.log"),
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def install_global_error_hooks(base_dir: Optional[str] = None) -> None:
    def excepthook(exc_type, exc, tb):
        report = write_error_report(
            "unhandled_exception",
            exc,
            traceback_text="".join(traceback.format_exception(exc_type, exc, tb)),
            base_dir=base_dir,
        )
        print(f"Unhandled exception report: {report}", file=sys.stderr)
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = excepthook

    if hasattr(threading, "excepthook"):
        def thread_hook(args):
            report = write_error_report(
                "thread_exception",
                args.exc_value,
                traceback_text="".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)),
                context={"thread_name": args.thread.name if args.thread else ""},
                base_dir=base_dir,
            )
            print(f"Thread exception report: {report}", file=sys.stderr)
            if getattr(threading, "__excepthook__", None):
                threading.__excepthook__(args)

        threading.excepthook = thread_hook
