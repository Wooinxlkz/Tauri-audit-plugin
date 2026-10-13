# Changelog

## 0.2.0

- Attack paths: findings that combine into a real attack are chained and explained, with the cheapest link to cut.
- Grade (A to F) and score, plus `--badge` to write an SVG badge.
- `--format html`: self-contained, escaped, light/dark report.
- Baselines for CI: `--write-baseline` and `--baseline` so only new findings count.
- Exit-safe when piped (no BrokenPipe traceback).

## 0.1.0

Initial release.

- Checker: 42 rules across CSP, app config, updater, capabilities, Cargo and custom commands, plus Tauri v1 allowlist basics.
- Output: text, JSON, Markdown, SARIF. Exit codes for CI.
- Skill: triage, safe-fix and verification workflow.
- Slash command: `/tauri-audit`.
