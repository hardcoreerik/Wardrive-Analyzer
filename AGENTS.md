# AGENTS.md

This repository uses a shared agent collaboration protocol so Codex and Claude Code can work through GitHub without losing local context or overwriting each other.

Before starting work, read and follow:

- [docs/agent-collaboration.md](docs/agent-collaboration.md)

## Project Context

Wardrive Analyzer is a local-first PySide6 desktop application for ingesting, parsing, and reporting on authorized WiFi wardrive evidence.

- Primary entrypoint: `run_step3d_scene.py`
- Main GUI surface: `gui_step3d_scene.py`
- Project vault and ingest logic: `project_vault.py`
- Core parser/report pipeline: `core/`
- Local evidence and generated reports live under `Projects/` and must not be committed.

## Codex Defaults

- Treat `master` as the stable integration branch.
- Use `codex/<short-task-name>` branches for Codex-owned changes.
- Check open pull requests and recent remote branches before editing.
- Commit and push meaningful work so Claude can see it.
- Leave concise handoff notes in pull request descriptions.
- Do not overwrite uncommitted user changes or another agent's branch work.
- Preserve the local-first desktop architecture unless the user explicitly asks for a web service.

## User Operating Profile

Use the distilled operating preferences from `F:\Ai\ABOUT_ME` as standard repo practice:

- Keep responses and handoffs brief, direct, and technical.
- Favor working, verified local behavior over abstract architecture.
- Ask one clarifying question when a risky assumption cannot be verified from the repo.
- Use markdown, code fences for commands, and concrete file paths.
- Do not use emojis, decorative language, or exclamation marks in repo docs.
- Treat security, RF, location, and evidence workflows as authorized lab or owned-data work only.
- Do not commit private notes, personal context files, tokens, local settings, or raw evidence.

## Codex Commit Voice

Use the repository's public commit-log voice from [docs/agent-collaboration.md](docs/agent-collaboration.md): clinical, self-aware, slightly eerie, and technically accurate.

- Prefix commits and pull requests with `Codex:`.
- Keep the technical meaning clear underneath the style.
- Make the tone deadpan, not chaotic.
- Do not imply real-world harm, unauthorized access, credential theft, malware, or actual threats.
- Do not rewrite existing commit history unless the user explicitly asks.

Examples:

- `Codex: record the observer state before the next ingest cycle`
- `Codex: preserve project-vault intent for the second operator`
- `Codex: reduce drift between desktop behavior and remote memory`
- `Codex: make the handoff visible before the evidence moves`

## Local Safety

- Run `git status -sb` and `git diff --stat` before staging.
- Stage only files that belong to the current task.
- Keep `Projects/`, `wardrive_run.log`, virtual environments, build output, and generated artifacts out of commits.
- Verify desktop changes with syntax checks and, when requested, a visible PySide6 launch.
- Prefer focused verification over broad churn.
