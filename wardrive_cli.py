from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import Any, Callable

import wardrive_service as svc
from error_logger import write_error_report


Action = Callable[[argparse.Namespace], dict[str, Any]]


def _print(data: dict[str, Any], pretty: bool = True) -> None:
    print(svc.dumps_json(data, pretty=pretty))


def _cmd_project_summary(args: argparse.Namespace) -> dict[str, Any]:
    return svc.project_summary(args.project, import_limit=args.import_limit)


def _cmd_evidence_list(args: argparse.Namespace) -> dict[str, Any]:
    return svc.evidence_list(args.project, limit=args.limit, offset=args.offset)


def _cmd_runs_list(args: argparse.Namespace) -> dict[str, Any]:
    return svc.runs_list(args.project, limit=args.limit)


def _cmd_latest_run(args: argparse.Namespace) -> dict[str, Any]:
    return svc.latest_run(args.project)


def _cmd_summarize_latest_run(args: argparse.Namespace) -> dict[str, Any]:
    return svc.summarize_latest_run(args.project, top_limit=args.top)


def _cmd_strongest_unknown_aps(args: argparse.Namespace) -> dict[str, Any]:
    return svc.strongest_unknown_aps(args.project, limit=args.limit)


def _cmd_compare_latest_runs(args: argparse.Namespace) -> dict[str, Any]:
    return svc.compare_latest_runs(args.project)


def _cmd_suspicious_handshakes(args: argparse.Namespace) -> dict[str, Any]:
    return svc.suspicious_handshakes(args.project, limit=args.limit)


def _cmd_evidence_health(args: argparse.Namespace) -> dict[str, Any]:
    return svc.evidence_health(args.project)


def _cmd_integration_plan(args: argparse.Namespace) -> dict[str, Any]:
    return svc.integration_plan()


def _cmd_scan_folder(args: argparse.Namespace) -> dict[str, Any]:
    return svc.scan_folder(args.folder, limit=args.limit, include_hidden=args.include_hidden)


def _cmd_analyze_project(args: argparse.Namespace) -> dict[str, Any]:
    def event(message: str) -> None:
        if args.events:
            print(json.dumps({"event": message}, ensure_ascii=False), file=sys.stderr, flush=True)

    return svc.analyze_project(args.project, status_cb=event if args.events else None)


def _dispatch_action(action: str, params: dict[str, Any]) -> dict[str, Any]:
    if action == "project_summary":
        return svc.project_summary(str(params["project"]), import_limit=int(params.get("import_limit", 10)))
    if action == "evidence_list":
        return svc.evidence_list(str(params["project"]), limit=int(params.get("limit", 100)), offset=int(params.get("offset", 0)))
    if action == "runs_list":
        return svc.runs_list(str(params["project"]), limit=int(params.get("limit", 20)))
    if action == "latest_run":
        return svc.latest_run(str(params["project"]))
    if action == "summarize_latest_run":
        return svc.summarize_latest_run(str(params["project"]), top_limit=int(params.get("top", 10)))
    if action == "strongest_unknown_aps":
        return svc.strongest_unknown_aps(str(params["project"]), limit=int(params.get("limit", 25)))
    if action == "compare_latest_runs":
        return svc.compare_latest_runs(str(params["project"]))
    if action == "suspicious_handshakes":
        return svc.suspicious_handshakes(str(params["project"]), limit=int(params.get("limit", 25)))
    if action == "evidence_health":
        return svc.evidence_health(str(params["project"]))
    if action == "integration_plan":
        return svc.integration_plan()
    if action == "scan_folder":
        return svc.scan_folder(str(params["folder"]), limit=int(params.get("limit", 250)), include_hidden=bool(params.get("include_hidden", False)))
    if action == "analyze_project":
        return svc.analyze_project(str(params["project"]))
    return svc.result("error", error=f"Unknown action: {action}")


def _cmd_serve_stdio(args: argparse.Namespace) -> dict[str, Any]:
    print(json.dumps({"status": "ready", "protocol": "wardrive-jsonl-v1"}), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            request_id = request.get("id")
            action = str(request.get("action", ""))
            params = request.get("params") or {}
            response = _dispatch_action(action, params)
            response["id"] = request_id
        except Exception as exc:
            report = write_error_report("cli_stdio_action_error", exc, traceback_text=traceback.format_exc())
            response = svc.result("error", error=f"{type(exc).__name__}: {exc}", report=report)
        print(json.dumps(response, ensure_ascii=False), flush=True)
    return svc.result("ok", message="stdio bridge stopped")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wardrive_cli.py",
        description="Local JSON command bridge for Wardrive Analyzer.",
    )
    parser.add_argument("--compact", action="store_true", help="Print compact JSON.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("project-summary", help="Summarize a project vault.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--import-limit", type=int, default=10)
    p.set_defaults(func=_cmd_project_summary)

    p = sub.add_parser("evidence-list", help="List project evidence rows.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.set_defaults(func=_cmd_evidence_list)

    p = sub.add_parser("runs-list", help="List discovered analysis runs.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=_cmd_runs_list)

    p = sub.add_parser("latest-run", help="Return the latest discovered run.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.set_defaults(func=_cmd_latest_run)

    p = sub.add_parser("summarize-latest-run", help="Summarize risk, auth, and changes for the latest run.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--top", type=int, default=10, help="Number of top-risk APs to return.")
    p.set_defaults(func=_cmd_summarize_latest_run)

    p = sub.add_parser("strongest-unknown-aps", help="Find strongest hidden, unknown, or incomplete AP records.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=_cmd_strongest_unknown_aps)

    p = sub.add_parser("compare-latest-runs", help="Compare the two newest wardrive master CSVs.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.set_defaults(func=_cmd_compare_latest_runs)

    p = sub.add_parser("suspicious-handshakes", help="Flag APs with handshake or EAPOL evidence.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=_cmd_suspicious_handshakes)

    p = sub.add_parser("evidence-health", help="Report duplicate evidence, missing sources, and empty PCAP summaries.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.set_defaults(func=_cmd_evidence_health)

    p = sub.add_parser("integration-plan", help="List planned import, map, WiGLE, and agent bridge surfaces.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=_cmd_integration_plan)

    p = sub.add_parser("scan-folder", help="Scan an SD/evidence folder without ingesting.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("folder")
    p.add_argument("--limit", type=int, default=250)
    p.add_argument("--include-hidden", action="store_true")
    p.set_defaults(func=_cmd_scan_folder)

    p = sub.add_parser("analyze-project", help="Analyze all attached project evidence and generate a new run.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("project")
    p.add_argument("--events", action="store_true", help="Stream progress events as JSON lines to stderr.")
    p.set_defaults(func=_cmd_analyze_project)

    p = sub.add_parser("serve-stdio", help="Run a local JSONL stdio bridge for agents.")
    p.add_argument("--compact", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=_cmd_serve_stdio)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        data = args.func(args)
        if args.command != "serve-stdio":
            _print(data, pretty=not args.compact)
        return 0 if data.get("status") == "ok" else 1
    except Exception as exc:
        report = write_error_report("cli_command_error", exc, traceback_text=traceback.format_exc())
        _print(svc.result("error", error=f"{type(exc).__name__}: {exc}", report=report), pretty=not args.compact)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
