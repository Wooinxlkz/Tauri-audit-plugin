---
name: tauri-audit
description: Security audit and safe hardening for Tauri apps (v2 and v1). Runs a deterministic checker over tauri.conf.json, capabilities/*.json|toml, the CSP, updater config, Cargo.toml and custom Rust commands, then triages the findings and proposes minimal fixes that don't break the app. Use whenever the user mentions Tauri security, capabilities, permissions, CSP, allowlist, updater signing, scopes, "is my Tauri app secure", reviewing or pasting a tauri.conf.json or capability file, or preparing a Tauri release, even if they never say "audit".
---

# tauri-audit

Two halves. The script finds problems deterministically; you decide which ones matter for this app and how to fix them without breaking it. Never skip the script and "eyeball" the config: it catches things that are easy to miss (wildcard windows, remote IPC, unscoped commands, unused plugin permissions).

## 1. Run the checker

The script is read-only and needs only Python 3.8+ (3.11+ for `.toml` capability files).

```bash
python3 <skill-dir>/scripts/tauri_audit.py <project-dir> --fail-on never
```

- In the Claude Code / Cowork plugin, `<skill-dir>` is `${CLAUDE_PLUGIN_ROOT}/skills/tauri-audit`. Otherwise use the folder this SKILL.md is in.
- `<project-dir>` is the repo root (it finds `tauri.conf.json` anywhere under it, monorepos included). It can also be a single `tauri.conf.json` or one capability file.
- If the user pasted config text or uploaded files, write them to a temp folder as `src-tauri/tauri.conf.json` and `src-tauri/capabilities/<name>.json`, then run the script on that folder.
- Useful flags: `--format json` (to parse it yourself), `--format markdown` or `html` (to hand over a report), `--badge FILE.svg`, `--ignore RULE_ID`, `--no-frontend-scan`, `--baseline FILE` / `--write-baseline FILE` (track only new findings), `--list-rules`.
- The output starts with a **grade** and **attack paths**: chains of findings that combine into a real attack (for example remote IPC + file write, or weak CSP + shell access). Lead your report with the attack paths, since cutting one link in a chain is usually the highest-value fix.
- If Python or the project files are unavailable, say so and fall back to reading `references/rules.md` and reviewing by hand, clearly labelled as a manual review.

## 2. Triage like an engineer

Raw findings are not the answer. For each critical/high finding decide:

1. **Reachable?** A dangerous permission only matters if untrusted content can use it. Ask: does any window load remote URLs, render user/web content (markdown, HTML, iframes), or ship many npm dependencies? Local-only apps with a strict CSP are lower risk than the same permission in an app that shows remote pages.
2. **Needed?** Grep the frontend (`@tauri-apps/plugin-*`, `invoke(`) and Rust (`generate_handler!`) for actual usage before recommending removal. `CAP-UNUSED-PLUGIN` is a hint, not proof: plugins can be used from Rust only.
3. **False positive?** State it plainly when a finding does not apply (for example `localhost` dev URLs, or `'unsafe-inline'` in `style-src`) and why.

Order the report by real risk, not by the script's order. Group repeated findings.

## 3. Fix without breaking anything

The user's top requirement is that nothing breaks. Follow these rules:

- **Propose before changing.** Show a small diff per fix. Edit files only when the user asked you to apply fixes, and touch only the lines involved.
- **Scope, don't delete**, when the feature is used: narrow `$HOME/**` to `$APPDATA/**`, replace `*` windows with explicit labels, replace `https://*` with exact hosts.
- **CSP changes:** keep `ipc:` and `http://ipc.localhost` in `connect-src` (v2 IPC breaks without them). Add every origin the app really needs (APIs, fonts, images) and use `devCsp` only for dev-server needs such as the HMR websocket. Change one directive at a time.
- **Never** invent a pubkey, rename the bundle identifier silently (it moves the app data folder), enable `pattern: isolation` without an isolation app, or remove a permission you have not checked for usage.
- **Verify:** re-run the script after edits and confirm the targeted findings are gone and no new ones appeared. Tell the user to run `tauri dev` (and a release build for CSP/Cargo changes) and click through the features that use the touched permissions. You cannot run the GUI yourself, so say that this last check is theirs.

## 4. Report format

Keep it short and decisive:

```
Tauri audit: <project>   grade <X> (<score>/100)   <N critical, N high, N medium...>

Attack paths
- <path title>: <chain> -> cheapest link to cut: ...

Fix now
1. [CRITICAL] RULE-ID: what is wrong in one line, where (file -> pointer)
   Why it matters here: ...
   Fix: <diff or exact change>   Risk of breaking: low/medium, check <feature>

Worth doing
...
Not a problem here
- RULE-ID: reason
```

End with what you could not check (runtime behavior, dynamically created windows, code paths outside the scanned files).

## Reference

- `references/rules.md`: every rule ID with why it matters and the safest fix. Read the entry for any finding you are about to explain or fix, especially CSP and capability rules.
- The checker is static analysis of config and source text. It does not run the app and does not prove the absence of vulnerabilities; say so when the result is clean.
