# Contributing

1. Fork, branch, change.
2. `python3 -m unittest discover -s tests -v` must pass on Python 3.8+.
3. New rule: add it to `RULES` in `skills/tauri-audit/scripts/tauri_audit.py`, document it in `skills/tauri-audit/references/rules.md` (heading format `### \`RULE-ID\``; a test enforces it), and trigger it from `tests/fixtures/insecure`. The `secure` fixture must keep reporting zero findings.
4. Keep the checker dependency-free and read-only.
5. Prefer fewer, sharper rules. A rule that cries wolf gets ignored.
