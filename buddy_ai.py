from __future__ import annotations

import json
import os
import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import wardrive_service as svc


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4.1-mini"

PATH_KEY_PARTS = ("path", "dir", "file", "output", "pcap")
SECRET_KEY_PARTS = ("token", "key", "secret", "credential", "password")


def redact_token(token: str) -> str:
    """Return a safe display string for a token — never the token value.

    Always call this before logging or displaying any API key or credential.
    Returns a string of the form ``sk-...xxxx`` (last-4 hint) or ``[empty]``.
    """
    if not token or not token.strip():
        return "[empty]"
    stripped = token.strip()
    if len(stripped) <= 8:
        return "[redacted]"
    return f"{stripped[:3]}...{stripped[-4:]}"


@dataclass
class BuddyAIConfig:
    enabled: bool = False
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    sanitize_only: bool = True


class BuddyAIError(RuntimeError):
    pass


def project_token_name(project_dir: str) -> str:
    digest = hashlib.sha256(os.path.abspath(project_dir).encode("utf-8", errors="ignore")).hexdigest()[:24]
    return f"buddy_ai:{digest}"


def save_token_to_keyring(project_dir: str, token: str) -> bool:
    try:
        import keyring  # type: ignore
    except Exception:
        return False
    try:
        keyring.set_password("Wardrive Analyzer", project_token_name(project_dir), token)
        return True
    except Exception:
        return False


def load_token_from_keyring(project_dir: str) -> str:
    try:
        import keyring  # type: ignore
    except Exception:
        return ""
    try:
        return keyring.get_password("Wardrive Analyzer", project_token_name(project_dir)) or ""
    except Exception:
        return ""


def _looks_like_path(value: str) -> bool:
    return (":\\" in value) or value.startswith("\\\\") or "/" in value or "\\" in value


def _redact_path(value: str) -> str:
    if not value:
        return ""
    name = os.path.basename(value.rstrip("\\/"))
    return f"[redacted path: {name or 'item'}]"


def _scrub(value: Any, key: str = "") -> Any:
    key_l = key.lower()
    if any(part in key_l for part in SECRET_KEY_PARTS):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(k): _scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, key) for v in value[:50]]
    if isinstance(value, tuple):
        return [_scrub(v, key) for v in list(value)[:50]]
    if isinstance(value, str):
        if any(part in key_l for part in PATH_KEY_PARTS) or _looks_like_path(value):
            return _redact_path(value)
        return value[:600]
    return value


def build_buddy_context(project_dir: str, action: str) -> dict[str, Any]:
    """Build compact context for the buddy without raw evidence payloads."""
    if not project_dir:
        return {"status": "error", "error": "No project selected."}

    action = action.strip().lower()
    builders = {
        "summarize_latest_run": lambda: svc.summarize_latest_run(project_dir, top_limit=8),
        "evidence_health": lambda: svc.evidence_health(project_dir),
        "strongest_unknown_aps": lambda: svc.strongest_unknown_aps(project_dir, limit=12),
        "compare_latest_runs": lambda: svc.compare_latest_runs(project_dir),
        "suspicious_handshakes": lambda: svc.suspicious_handshakes(project_dir, limit=12),
        "next_step": lambda: svc.project_summary(project_dir, import_limit=5),
    }
    builder = builders.get(action, builders["next_step"])
    data = builder()
    return _scrub(data)


def local_buddy_summary(action: str, context: dict[str, Any]) -> str:
    if context.get("status") == "error":
        return f"I could not read that yet: {context.get('error', 'unknown problem')}"

    action = action.strip().lower()
    if action == "summarize_latest_run":
        summary = context.get("summary") or {}
        total = summary.get("total_aps", 0)
        risky = (summary.get("risk_tiers") or {}).get("high", 0) + (summary.get("risk_tiers") or {}).get("critical", 0)
        repeated = summary.get("repeated_aps", 0)
        return f"Latest run: {total} APs, {risky} high-or-critical risks, {repeated} repeated sightings. Open the summary when you want the pretty version."
    if action == "evidence_health":
        dupes = len(context.get("duplicate_warnings") or [])
        missing = len(context.get("missing_source_files") or [])
        pcap_warnings = len(context.get("pcap_health_warnings") or [])
        return f"Evidence health: {dupes} duplicate warnings, {missing} missing source files, {pcap_warnings} PCAP warnings."
    if action == "strongest_unknown_aps":
        total = context.get("total_unknown", 0)
        aps = context.get("aps") or []
        first = aps[0] if aps else {}
        strongest = first.get("best_rssi", "n/a")
        return f"Unknown AP sweep found {total}. Strongest visible unknown RSSI is {strongest}. That one deserves a look."
    if action == "compare_latest_runs":
        comp = context.get("comparison") or {}
        return f"Run delta: {comp.get('added_count', 0)} new, {comp.get('missing_count', 0)} missing, {comp.get('changed_count', 0)} changed."
    if action == "suspicious_handshakes":
        return f"Handshake sweep flagged {context.get('total_flagged', 0)} BSSIDs. Sort by confidence before you celebrate."
    runs = context.get("runs_count", 0)
    evidence = context.get("evidence") or {}
    return f"Next step readout: {evidence.get('total', 0)} evidence rows and {runs} runs. If evidence exists, analyze; if runs exist, review reports."


class BuddyAIClient:
    def __init__(self, config: BuddyAIConfig):
        self.config = config

    def ask(self, action: str, context: dict[str, Any]) -> str:
        if not self.config.enabled:
            return local_buddy_summary(action, context)
        if not self.config.api_key.strip():
            return local_buddy_summary(action, context)

        base = (self.config.base_url or DEFAULT_BASE_URL).rstrip("/")
        url = f"{base}/chat/completions"
        payload = {
            "model": self.config.model or DEFAULT_MODEL,
            "temperature": 0.35,
            "max_tokens": 260,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are the Wardrive Analyzer buddy: concise, sardonic, helpful, and privacy-aware. "
                        "Give practical next-step guidance from sanitized wardriving analysis summaries. "
                        "Do not ask for raw PCAPs, secrets, API tokens, or full file paths. Keep the reply under 90 words."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps({"action": action, "context": context}, ensure_ascii=True),
                },
            ],
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key.strip()}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            # Read detail but sanitize before surfacing — never echo back auth headers
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise BuddyAIError(f"AI provider rejected the request: HTTP {exc.code} {detail}") from exc
        except Exception as exc:
            # Stringify without repr to avoid echoing request object (which may hold headers)
            raise BuddyAIError(f"AI provider request failed: {type(exc).__name__}: {exc}") from exc

        try:
            text = body["choices"][0]["message"]["content"]
        except Exception as exc:
            raise BuddyAIError("AI provider returned an unexpected response shape.") from exc
        return str(text).strip() or local_buddy_summary(action, context)
