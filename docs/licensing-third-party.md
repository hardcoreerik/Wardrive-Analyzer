# Third-Party Licensing Notes

## Serial Studio

- Project reviewed: [Serial Studio](https://github.com/Serial-Studio/Serial-Studio)
- Upstream license: GPL family (strong copyleft)
- Status in Wardrive Analyzer: **not embedded**

## Clean-room policy for this codebase

- No Serial Studio source files are copied into this repository.
- No Serial Studio assets (icons, themes, sprites, UI files) are copied into this repository.
- No derivative imports from Serial Studio are used at runtime.
- New telemetry/map UX in Wardrive Analyzer is implemented in-house using native PySide6/Qt code and local project models.

## Practical guidance

- We can use Serial Studio as **inspiration** for operator UX patterns.
- We do **not** reuse GPL code in this proprietary/commercial pipeline.
- If future integration with third-party tools is needed, keep it as an optional external launch/integration path with clear separation.
