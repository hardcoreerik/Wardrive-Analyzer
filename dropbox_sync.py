from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


def _norm_folder(path: str) -> str:
    text = (path or "/WardriveAnalyzerSync").strip()
    if not text.startswith("/"):
        text = "/" + text
    return text.rstrip("/") or "/WardriveAnalyzerSync"


def _zip_project(project_dir: str) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    base_name = f"wardrive_project_{ts}.zip"
    out_path = os.path.join(tempfile.gettempdir(), base_name)
    # Some SD-card captures come in with pre-1980 timestamps (no RTC).
    # strict_timestamps=False clamps invalid DOS dates instead of raising.
    with zipfile.ZipFile(
        out_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        strict_timestamps=False,
    ) as zf:
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in {".venv", "__pycache__", ".git"}]
            for file_name in files:
                if file_name in {"wardrive_run.log"}:
                    continue
                full = os.path.join(root, file_name)
                rel = os.path.relpath(full, project_dir)
                zf.write(full, arcname=rel)
    return out_path


def _upload_file(local_path: str, token: str, remote_path: str) -> None:
    with open(local_path, "rb") as f:
        data = f.read()
    req = urllib.request.Request(
        "https://content.dropboxapi.com/2/files/upload",
        data=data,
        method="POST",
    )
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header(
        "Dropbox-API-Arg",
        json.dumps(
            {
                "path": remote_path,
                "mode": "overwrite",
                "autorename": False,
                "mute": False,
                "strict_conflict": False,
            }
        ),
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"Dropbox upload failed: HTTP {resp.status}")


def sync_project_to_dropbox(project_dir: str, access_token: str, remote_folder: str = "/WardriveAnalyzerSync") -> dict:
    if not os.path.isdir(project_dir):
        raise ValueError("Project folder does not exist.")
    token = (access_token or "").strip()
    if not token:
        raise ValueError("Dropbox access token is required.")
    folder = _norm_folder(remote_folder)
    zip_path = _zip_project(project_dir)
    file_name = os.path.basename(zip_path)
    versioned_remote = f"{folder}/{file_name}"
    latest_remote = f"{folder}/latest_project.zip"
    try:
        _upload_file(zip_path, token, versioned_remote)
        _upload_file(zip_path, token, latest_remote)
        return {
            "zip_path": zip_path,
            "remote_folder": folder,
            "remote_file": versioned_remote,
            "remote_latest": latest_remote,
        }
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Dropbox API error: {e.code} {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Dropbox network error: {e}") from e
