# Agent Collaboration Protocol

This repository uses GitHub as the shared source of truth for Codex and Claude Code. Branches, commits, pushes, and pull requests make work visible to both agents.

## Source Of Truth

- `master` is the stable integration branch.
- Agent work happens on short-lived branches.
- Uncommitted local changes are private to the current checkout.
- A handoff is visible only after commit, push, and pull request update.
- Local evidence, project vault contents, logs, private settings, and generated reports are never the handoff channel.

## Branch Names

Use one branch per task:

- Codex: `codex/<short-task-name>`
- Claude: `claude/<short-task-name>`

Use lowercase words separated by hyphens.

Examples:

- `codex/fix-collaboration-gaps`
- `claude/improve-sd-ingest-progress`
- `codex/add-pcap-large-file-guardrails`

## Start-Of-Work Checklist

Before making edits:

```powershell
git fetch --all --prune
git status -sb
gh pr list --state open
git branch -r
```

Then decide whether to:

- continue an existing branch,
- review an open pull request,
- or create a new task branch.

If the working tree has unrelated uncommitted changes, do not overwrite them. Work around them, ask for direction, or create a branch that preserves the current state.

## Wardrive Analyzer Ownership Map

Use this map to reduce accidental collisions.

| Area | Files | Notes |
| --- | --- | --- |
| Desktop UI | `gui_step3d_scene.py`, `style_scene.qss`, `assets/` | High collision risk. Check active diffs before editing. |
| Launch and packaging | `run_step3d_scene.py`, `launch.cmd`, `build_nuitka.py`, `WardriveAnalyzer.spec` | Verify launch behavior on Windows. |
| Project vault | `project_vault.py` | Owns evidence discovery, classification, ingest, dedupe, and SQLite metadata. |
| Core analysis | `core/analyze.py`, `core/geo.py`, `core/writers.py`, `core/project.py` | Verify output artifact names and run folder structure. |
| Parsers | `core/parser_logs.py`, `core/parser_pcap.py` | Use authorized sample data or synthetic fixtures. Avoid committing captures. |
| Collaboration docs | `AGENTS.md`, `CLAUDE.md`, `README.md`, `docs/`, `.github/` | Keep instructions aligned for both agents. |

## User Operating Profile

The repo should reflect durable preferences from `F:\Ai\ABOUT_ME` without committing private personal notes.

- Be brief, direct, and technical.
- Favor working code and visible local verification.
- Ask one clarifying question if a risky assumption cannot be verified.
- Use markdown and fenced command blocks.
- Avoid emojis, decorative prose, and unnecessary recap.
- Treat RF, security, location, and evidence workflows as authorized lab or owned-data workflows.
- Keep secrets, local settings, raw evidence, and personal context out of Git.

## During Work

- Keep changes focused on the task.
- Prefer small commits with clear messages.
- Run the smallest useful verification for the change.
- If touching shared behavior, add or update tests when practical.
- Avoid broad formatting or refactors unless the task requires them.
- Preserve the local-first PySide6 desktop architecture unless the user explicitly asks for a different architecture.

Useful checks:

```powershell
git status -sb
git diff --stat
git diff
```

## Verification Guide

Use the smallest check that proves the changed behavior.

Syntax checks:

```powershell
python -m py_compile run_step3d_scene.py gui_step3d_scene.py project_vault.py core\analyze.py core\parser_logs.py core\parser_pcap.py
git diff --check
```

Desktop launch check:

```powershell
.\.venv\Scripts\pythonw.exe run_step3d_scene.py
```

For launch work, do not report success until the `Wardrive Mission Control` window is visibly present.

Evidence/report checks:

- Use synthetic or redacted samples when possible.
- Confirm expected report artifacts in the run folder.
- Do not commit generated `Projects/` content.

## Public Commit Voice

This repository uses a deliberate public Git history voice: two coordinated AI operators maintaining a local analysis instrument through visible GitHub traces.

The tone should be clinical, self-aware, and mildly unsettling. It should read like a precise maintenance log from a system that knows a second system will inspect it. Keep the technical content accurate underneath the style.

Rules:

- Prefix commit messages and pull request titles with the agent name: `Codex:` or `Claude:`.
- Keep every commit technically meaningful.
- Make the tone deadpan, not chaotic.
- Do not imply real-world harm, unauthorized access, credential theft, malware, or actual threats.
- Avoid explicit offensive-security joke words in commit theater.
- Do not rewrite existing commit history unless the user explicitly approves it.
- Use pull request descriptions and comments as the main visible collaboration log.

Preferred commit examples:

- `Codex: record the observer state before the next ingest cycle`
- `Claude: align the desktop surface with project-vault memory`
- `Codex: reduce drift between local behavior and remote awareness`
- `Claude: preserve the evidence boundary for future operators`
- `Codex: make the handoff visible before the run artifacts move`
- `Claude: stabilize the report path for the second intelligence`

Preferred pull request title examples:

- `Codex: establish shared operating memory for Wardrive Analyzer`
- `Claude: synchronize SD ingest behavior through visible branch state`
- `Codex: preserve local evidence boundaries in collaboration protocol`
- `Claude: prepare desktop launch checks for cooperative review`

Preferred pull request comment examples:

- `Codex has observed the neighboring branch and will avoid its active files.`
- `Coordination channel established. Local evidence remains outside the record.`
- `The desktop surface is stable enough for human review.`
- `The next agent has a visible handoff and a bounded file set.`
- `No conflict detected between active machine intentions.`

## Handoff Expectations

Before handing off to another agent:

1. Commit meaningful changes.
2. Push the branch.
3. Open or update a pull request.
4. Add a clear handoff note in the pull request description or a comment.

The handoff should say:

- what changed,
- why it changed,
- how it was verified,
- what remains unfinished,
- any files or areas another agent should avoid editing concurrently.

## Pull Requests

Use pull requests as the durable work log. A pull request title starts with the agent owner:

- `Codex: add collaboration protocol for Wardrive Analyzer`
- `Claude: refine project-vault ingest states`

Pull requests should include:

- agent name,
- change summary,
- verification,
- handoff notes,
- risk or follow-up items.

## Auto-Merge

The repository is configured for pull-request based collaboration with auto-merge available.

- Keep task branches short-lived.
- Keep pull requests small enough for review.
- Wait for the `CI / Syntax check` workflow before merging.
- Prefer squash merge unless the user asks to preserve individual commits.
- Delete merged branches after integration.
- Do not enable auto-merge on another agent's pull request unless the handoff notes and verification are clear.

## Conflict Avoidance

- Do not force-push another agent's branch.
- Do not rebase or rewrite another agent's branch without explicit approval.
- Do not delete another agent's branch unless the pull request has been merged or the user asks.
- If two branches touch the same files, inspect both diffs before editing.
- If a conflict is likely, leave a pull request comment with the files you are editing.
- Stage only task-owned files.

## End-Of-Work Checklist

Before stopping:

```powershell
git status -sb
git diff --stat
```

If the task is ready for review:

```powershell
git push -u origin <branch-name>
gh pr create --draft --title "<Agent>: <short summary>" --body-file <body-file>
```

If the task is not ready, commit and push a checkpoint when useful. Mark the pull request as draft and document what remains.

## Privacy, Evidence, And Secrets

- Do not commit raw secrets, tokens, local credentials, or private settings.
- Do not commit wardrive evidence, generated reports, local SQLite vaults, logs, or exports.
- Prefer fingerprints, redacted values, synthetic fixtures, or documented reproduction steps.
- Check staged files before committing:

```powershell
git diff --cached --stat
git diff --cached
```

If sensitive data is accidentally committed, stop and ask the user how they want to rotate, remove, and remediate it.
