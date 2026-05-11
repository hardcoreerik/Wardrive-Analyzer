# CLAUDE.md

This repository is set up for tandem work between Claude Code and Codex.

Before starting work, read and follow:

- [docs/agent-collaboration.md](docs/agent-collaboration.md)

## Project Context

Wardrive Analyzer is a Windows-first, local-first PySide6 desktop application. It ingests authorized wardrive evidence from SD cards or project folders, parses logs and PCAPs, and writes reports into local project vaults.

Important paths:

- `run_step3d_scene.py` starts the app.
- `gui_step3d_scene.py` owns the main desktop interface.
- `project_vault.py` owns SD discovery, classification, ingest, and project evidence lookup.
- `core/parser_logs.py` and `core/parser_pcap.py` parse evidence.
- `core/analyze.py` orchestrates report generation.
- `Projects/` contains local evidence and generated outputs. Do not commit it.

## Claude Defaults

- Treat `master` as the stable integration branch.
- Use `claude/<short-task-name>` branches for Claude-owned changes.
- Check open pull requests and recent remote branches before editing.
- Commit and push meaningful work so Codex can see it.
- Leave concise handoff notes in pull request descriptions.
- Do not overwrite uncommitted user changes or another agent's branch work.
- Preserve the desktop-native PySide6 direction unless the user explicitly changes architecture.

## User Operating Profile

Integrate the durable preferences from `F:\Ai\ABOUT_ME` without copying private personal notes into commits:

- Be brief, direct, and technical.
- Favor working local behavior and visible verification.
- Ask one clarifying question when the repo cannot answer a risky ambiguity.
- Use markdown and fenced command blocks.
- Avoid emojis, decorative prose, and exclamation marks.
- Treat security, RF, location, and evidence workflows as authorized lab or owned-data work.
- Keep tokens, private context, local settings, and raw evidence out of Git.

## Local Safety

- Review `git status -sb` and `git diff --stat` before staging.
- Stage only task-owned files.
- Do not commit `.claude/settings.local.json`, local logs, virtual environments, build output, or `Projects/`.
- If another agent has active edits in a file, work around them or leave a pull request note.
- Verify code with the smallest useful check. For desktop-facing changes, prefer syntax checks plus a visible app launch when practical.
