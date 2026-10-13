# Rule reference

Every finding carries a stable ID. Each entry says why it matters and the safest fix. Severities shown are defaults; the checker can raise or lower them based on context (for example, `CAP-REMOTE-IPC` becomes critical when the same capability grants fs/shell/http).

Run `python3 scripts/tauri_audit.py --list-rules` for the live list.

## CSP and app config

### `ASSET-PROTOCOL`

**high** | Asset protocol scope is too broad or missing

- Why: The asset protocol serves local files to the webview. A broad scope exposes them to any script.
- Safe fix: Scope to one app directory such as `$APPDATA/media/**`. Disable the protocol if unused (and drop the `protocol-asset` Cargo feature).
- Docs: https://v2.tauri.app/security/scope/

### `CSP-ASSET-MODIFICATION-DISABLED`

**high** | Tauri's automatic CSP hardening is disabled

- Why: Tauri normally appends nonces/hashes to protect your own assets; this switch turns that off.
- Safe fix: Remove it. If you set it because a build step breaks, scope it to specific directives instead.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-DANGEROUS-SCHEME`

**high** | CSP allows a bare scheme in script sources

- Why: `https:`, `http:` or `data:` as a script source allows any host or inline data URLs to supply code.
- Safe fix: List explicit hosts. `data:` is fine in `img-src`, never in `script-src`.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-MISSING`

**high** | No Content Security Policy configured

- Why: With no CSP, any injected script runs unrestricted and can call the IPC.
- Safe fix: Add a policy and test `tauri dev` plus a release build. Always keep `ipc:` and `http://ipc.localhost` in `connect-src`, or every `invoke` fails. Add remote origins one at a time.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-UNSAFE-EVAL`

**high** | CSP allows 'unsafe-eval' for scripts

- Why: Lets `eval`, `new Function` and string timers execute, which turns many XSS bugs into full compromise.
- Safe fix: Remove it and run the app. If a library breaks, replace the library; for WebAssembly use `'wasm-unsafe-eval'`.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-WILDCARD-SOURCE`

**high** | CSP uses a wildcard source

- Why: `*` allows any origin, which defeats the policy for that directive.
- Safe fix: Replace it with the exact origins the app talks to. For `connect-src` list the API hosts.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-HOSTED-SCRIPT-HOST`

**medium** | CSP trusts a public script host

- Why: Public CDNs host many libraries with known script gadgets that bypass allowlists.
- Safe fix: Bundle the dependency into the app and drop the host.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-INSECURE-SOURCE`

**medium** | CSP allows a non-local plaintext source

- Why: Plaintext HTTP/WS can be tampered with on the network.
- Safe fix: Use `https://` or `wss://`. `localhost` and `ipc.localhost` are exempt.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-NO-FALLBACK`

**medium** | CSP has neither default-src nor script-src

- Why: Directives that are not listed are unrestricted, so scripts are not limited.
- Safe fix: Add `default-src 'self'` as the base, then open only what is needed.
- Docs: https://v2.tauri.app/security/csp/

### `CSP-UNSAFE-INLINE`

**medium** | CSP allows 'unsafe-inline' for scripts

- Why: Inline script injection is allowed. Tauri adds nonces/hashes for its own inline code, and browsers ignore `'unsafe-inline'` when a nonce is present.
- Safe fix: Remove it from script sources and test. Leave it in `style-src` if your UI library needs inline styles; that is much lower risk.
- Docs: https://v2.tauri.app/security/csp/

### `GLOBAL-TAURI`

**medium** | withGlobalTauri exposes the IPC API on window

- Why: `window.__TAURI__` gives injected scripts IPC access without needing imports.
- Safe fix: Set `withGlobalTauri: false` and use `@tauri-apps/api` imports. Search the frontend for `__TAURI__` first.
- Docs: https://v2.tauri.app/reference/config/

### `SHELL-OPEN-BROAD`

**medium** | Shell 'open' allows broad targets

- Why: An overly open regex lets the webview open arbitrary files/URLs with the OS handler.
- Safe fix: Remove the setting (the default only allows https, mailto and tel) or use a strict regex.
- Docs: https://v2.tauri.app/plugin/shell/

### `CSP-NO-OBJECT-SRC`

**low** | CSP does not restrict object-src

- Why: Plugins and embeds are not restricted.
- Safe fix: Add `object-src 'none'`.
- Docs: https://v2.tauri.app/security/csp/

### `DEFAULT-IDENTIFIER`

**low** | Placeholder bundle identifier

- Why: Placeholder identifiers collide with other apps' storage and signing identity.
- Safe fix: Set a reverse-domain id you own. Changing it moves the app data directory, so migrate user data.
- Docs: https://v2.tauri.app/reference/config/

### `FREEZE-PROTOTYPE`

**low** | freezePrototype is not enabled

- Why: A frozen `Object.prototype` blocks a class of prototype-pollution attacks.
- Safe fix: Set `freezePrototype: true`. Test: some old libraries mutate built-in prototypes and will fail.
- Docs: https://v2.tauri.app/security/

### `MACOS-PRIVATE-API`

**low** | macOS private API enabled

- Why: Uses non-public macOS APIs, which widens the attack surface and blocks App Store distribution.
- Safe fix: Disable it unless you need macOS window transparency.
- Docs: https://v2.tauri.app/reference/config/

### `REMOTE-WINDOW-URL`

**low** | A window loads remote content

- Why: The window displays third-party content. Risk depends on which capabilities match that window.
- Safe fix: Prefer bundled pages. Make sure no capability with powerful permissions matches this window label.
- Docs: https://v2.tauri.app/security/

### `ISOLATION-PATTERN`

**info** | Isolation pattern is not used

- Why: Isolation runs a sandboxed iframe that can inspect every IPC message before it reaches Rust.
- Safe fix: Optional hardening. Needs an isolation app (`dist-isolation`); do not enable it without building that.
- Docs: https://v2.tauri.app/concept/inter-process-communication/isolation/

## Updater

### `UPDATER-NO-PUBKEY`

**critical** | Updater has no signature public key

- Why: Updates cannot be verified, so anyone who controls the endpoint can ship code to every user.
- Safe fix: Run `tauri signer generate`, store the private key outside the repo, put the public key in `plugins.updater.pubkey`, and sign builds.
- Docs: https://v2.tauri.app/plugin/updater/

### `UPDATER-INSECURE-TRANSPORT`

**high** | Updater allows plaintext HTTP

- Why: Plaintext update checks can be intercepted or downgraded.
- Safe fix: Use HTTPS endpoints and remove `dangerousInsecureTransportProtocol`.
- Docs: https://v2.tauri.app/plugin/updater/

### `UPDATER-NO-ENDPOINTS`

**low** | Updater has no endpoints

- Why: The updater is configured but has nowhere to check.
- Safe fix: Add HTTPS endpoints, or remove the updater config if unused.
- Docs: https://v2.tauri.app/plugin/updater/

## Capabilities and permissions

### `CAP-FS-BROAD`

**high** | Filesystem permission scope is too broad

- Why: Broad file scopes let any script read secrets or write startup files.
- Safe fix: Scope to `$APPDATA/**`/`$APPCONFIG/**`, or let the user pick a file with the dialog plugin (the pick grants a scoped path). Add `deny` entries for sensitive folders.
- Docs: https://v2.tauri.app/plugin/file-system/

### `CAP-REMOTE-IPC`

**high** | Remote origins can call the IPC

- Why: A capability with `remote.urls` lets those web origins call Tauri commands. Compromise of the site becomes compromise of the machine.
- Safe fix: Remove `remote`. If essential, one exact HTTPS origin and a separate capability with minimal permissions.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-SHELL-SCOPE`

**high** | Shell command scope is unsafe

- Why: Interpreters or unvalidated arguments turn a scoped command into arbitrary code execution.
- Safe fix: Expose a fixed binary with fixed args, a sidecar, or move the logic into a Rust command. Use argument validators with tight regexes.
- Docs: https://v2.tauri.app/plugin/shell/

### `CAP-HTTP-BROAD`

**medium** | HTTP/WebSocket scope is too broad

- Why: A webview that can fetch any host can exfiltrate data and reach internal services.
- Safe fix: List exact hostnames; use `https://`.
- Docs: https://v2.tauri.app/security/permissions/

### `CAP-MISSING`

**medium** | Config references a capability that does not exist

- Why: A referenced capability does not exist; the build may fail or the intended permissions are not granted.
- Safe fix: Create the file or fix the identifier.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-OPENER-BROAD`

**medium** | Opener scope is too broad

- Why: Opening arbitrary paths/URLs with the OS handler can launch programs or phishing pages.
- Safe fix: Scope paths to one directory and URLs to exact hosts.
- Docs: https://v2.tauri.app/security/permissions/

### `CAP-WILDCARD-WINDOW`

**medium** | Capability applies to every window/webview

- Why: `*` applies the permissions to every window and webview, including ones created later.
- Safe fix: List labels explicitly (`["main"]`). Check `app.windows[].label` and any `WebviewWindowBuilder` labels first.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-DUPLICATE-ID`

**low** | Duplicate capability identifier

- Why: Two capabilities with the same identifier make behavior ambiguous.
- Safe fix: Rename one.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-UNUSED-PLUGIN`

**low** | Permission granted for a plugin the frontend never imports

- Why: Least privilege: permissions for plugins the frontend never imports are attack surface for nothing. Plugins used only from Rust do not need capability entries.
- Safe fix: Remove after checking JS *and* Rust usage. Re-run `tauri dev` and exercise features that use the plugin.
- Docs: https://v2.tauri.app/security/permissions/

### `CAP-WEBVIEW-CREATE`

**low** | Frontend may create new windows/webviews

- Why: JS can open new windows, which inherit capabilities that match their label.
- Safe fix: Remove it if windows are created from Rust only.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-NO-WINDOW-MATCH`

**info** | Capability matches no configured window

- Why: The capability probably does nothing, or targets a typo.
- Safe fix: Verify labels. Ignore if windows are created dynamically.
- Docs: https://v2.tauri.app/security/capabilities/

### `CAP-ORPHAN`

**info** | Capability file is not enabled

- Why: When `app.security.capabilities` is set, files not listed there are ignored, which hides what is really enabled.
- Safe fix: Add the identifier to the list or delete the file.
- Docs: https://v2.tauri.app/security/capabilities/

## Cargo and Rust

### `CARGO-DEVTOOLS`

**medium** | devtools feature enabled for the tauri crate

- Why: The `devtools` crate feature enables the inspector in release builds, exposing app internals and IPC.
- Safe fix: Remove the feature. Devtools already work in debug builds.
- Docs: https://v2.tauri.app/reference/config/

### `CMD-UNSCOPED`

**low** | Custom commands are callable from every window

- Why: v2 commands registered with `generate_handler!` are available to all windows unless restricted by an app manifest.
- Safe fix: Add an AppManifest in `build.rs` listing commands, then grant `allow-<command>` per capability.
- Docs: https://v2.tauri.app/security/permissions/

### `CMD-RAW-INPUT`

**info** | Custom commands take raw path/command-like input

- Why: Commands taking `path`, `url`, `cmd`, `args` or `sql` strings are common sources of traversal and injection bugs. This is a pointer to review, not a confirmed bug.
- Safe fix: Canonicalize paths against an allowed root, reject `..`, parse URLs, never pass strings to a shell, and use parameterized queries.
- Docs: https://v2.tauri.app/security/

## Tauri v1

### `V1-ALLOWLIST-ALL`

**critical** | allowlist.all enables every API

- Why: Every API is exposed to the frontend.
- Safe fix: Set `all: false` and enable only the specific flags the app uses.
- Docs: https://v2.tauri.app/security/

### `V1-ALLOWLIST-MODULE-ALL`

**high** | allowlist module enables every API in it

- Why: The whole module is exposed, not just the calls you use.
- Safe fix: Enable individual flags. Grep the frontend for the API you actually call.
- Docs: https://v2.tauri.app/security/

### `V1-ALLOWLIST-SCOPE`

**high** | allowlist scope is too broad

- Why: The scope lets scripts reach too many files, hosts or commands.
- Safe fix: Narrow scopes like in the v2 rules for fs/http/shell.
- Docs: https://v2.tauri.app/security/scope/

### `V1-REMOTE-IPC`

**high** | Remote domains can call the IPC

- Why: Remote domains can invoke commands.
- Safe fix: Remove, or limit to one exact domain and a small plugin set.
- Docs: https://v2.tauri.app/security/

### `V1-DETECTED`

**info** | Tauri v1 config detected

- Why: v1 uses a global allowlist instead of per-window capabilities.
- Safe fix: Plan a migration with `tauri migrate`; fix v1 findings meanwhile.
- Docs: https://v2.tauri.app/security/

## Housekeeping

### `PARSE-ERROR`

**medium** | File could not be parsed

- Why: The file was skipped, so nothing in it was checked.
- Safe fix: Fix the syntax. JSON with comments and trailing commas is accepted; JSON5 with unquoted keys is not.
- Docs: https://v2.tauri.app/reference/config/
