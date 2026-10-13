---
description: Audit a Tauri project's security config (capabilities, CSP, updater, commands)
argument-hint: "[path-to-project] [--apply]"
---

Use the `tauri-audit` skill to audit the Tauri project at `$ARGUMENTS` (default: the current directory).

1. Run the bundled checker from the skill folder and read its full output.
2. Triage the findings as the skill describes: reachability, real usage, false positives.
3. Report in the skill's format, ordered by real risk.
4. Only edit files if `--apply` was passed. Otherwise show diffs and ask.
5. After any edit, re-run the checker and tell me which `tauri dev` checks I should do.
