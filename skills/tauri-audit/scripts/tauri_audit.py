#!/usr/bin/env python3
"""tauri-audit: deterministic security auditor for Tauri apps.

Zero dependencies. Python 3.8+ (TOML files need 3.11+).
Reads tauri.conf.json / capabilities / Cargo.toml / Rust commands and reports
risky configuration with stable rule IDs.  It never modifies anything.

Usage:
    tauri_audit.py [PATH] [--format text|json|markdown|sarif|html] [--fail-on LEVEL]
                   [--ignore RULE_ID ...] [--no-frontend-scan] [--no-color]
                   [--output FILE] [--badge FILE.svg]
                   [--baseline FILE | --write-baseline FILE]

Exit codes: 0 clean (below --fail-on), 1 findings at/above --fail-on, 2 usage/input error.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore

__version__ = "0.2.0"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower number = worse

DOCS = "https://v2.tauri.app"
REF_SEC = DOCS + "/security/"
REF_CAP = DOCS + "/security/capabilities/"
REF_CSP = DOCS + "/security/csp/"
REF_SCOPE = DOCS + "/security/scope/"
REF_PERM = DOCS + "/security/permissions/"
REF_UPD = DOCS + "/plugin/updater/"
REF_FS = DOCS + "/plugin/file-system/"
REF_SHELL = DOCS + "/plugin/shell/"
REF_ISO = DOCS + "/concept/inter-process-communication/isolation/"
REF_CFG = DOCS + "/reference/config/"

# rule id -> (default severity, title, reference)
RULES: Dict[str, Tuple[str, str, str]] = {
    "PARSE-ERROR": ("medium", "File could not be parsed", REF_CFG),
    "CSP-MISSING": ("high", "No Content Security Policy configured", REF_CSP),
    "CSP-NO-FALLBACK": ("medium", "CSP has neither default-src nor script-src", REF_CSP),
    "CSP-UNSAFE-EVAL": ("high", "CSP allows 'unsafe-eval' for scripts", REF_CSP),
    "CSP-UNSAFE-INLINE": ("medium", "CSP allows 'unsafe-inline' for scripts", REF_CSP),
    "CSP-WILDCARD-SOURCE": ("high", "CSP uses a wildcard source", REF_CSP),
    "CSP-DANGEROUS-SCHEME": ("high", "CSP allows a bare scheme in script sources", REF_CSP),
    "CSP-HOSTED-SCRIPT-HOST": ("medium", "CSP trusts a public script host", REF_CSP),
    "CSP-INSECURE-SOURCE": ("medium", "CSP allows a non-local plaintext source", REF_CSP),
    "CSP-NO-OBJECT-SRC": ("low", "CSP does not restrict object-src", REF_CSP),
    "CSP-ASSET-MODIFICATION-DISABLED": ("high", "Tauri's automatic CSP hardening is disabled", REF_CSP),
    "FREEZE-PROTOTYPE": ("low", "freezePrototype is not enabled", REF_SEC),
    "GLOBAL-TAURI": ("medium", "withGlobalTauri exposes the IPC API on window", REF_CFG),
    "ASSET-PROTOCOL": ("high", "Asset protocol scope is too broad or missing", REF_SCOPE),
    "ISOLATION-PATTERN": ("info", "Isolation pattern is not used", REF_ISO),
    "REMOTE-WINDOW-URL": ("low", "A window loads remote content", REF_SEC),
    "UPDATER-NO-PUBKEY": ("critical", "Updater has no signature public key", REF_UPD),
    "UPDATER-INSECURE-TRANSPORT": ("high", "Updater allows plaintext HTTP", REF_UPD),
    "UPDATER-NO-ENDPOINTS": ("low", "Updater has no endpoints", REF_UPD),
    "MACOS-PRIVATE-API": ("low", "macOS private API enabled", REF_CFG),
    "DEFAULT-IDENTIFIER": ("low", "Placeholder bundle identifier", REF_CFG),
    "SHELL-OPEN-BROAD": ("medium", "Shell 'open' allows broad targets", REF_SHELL),
    "CAP-REMOTE-IPC": ("high", "Remote origins can call the IPC", REF_CAP),
    "CAP-WILDCARD-WINDOW": ("medium", "Capability applies to every window/webview", REF_CAP),
    "CAP-FS-BROAD": ("high", "Filesystem permission scope is too broad", REF_FS),
    "CAP-SHELL-SCOPE": ("high", "Shell command scope is unsafe", REF_SHELL),
    "CAP-OPENER-BROAD": ("medium", "Opener scope is too broad", REF_PERM),
    "CAP-HTTP-BROAD": ("medium", "HTTP/WebSocket scope is too broad", REF_PERM),
    "CAP-WEBVIEW-CREATE": ("low", "Frontend may create new windows/webviews", REF_CAP),
    "CAP-NO-WINDOW-MATCH": ("info", "Capability matches no configured window", REF_CAP),
    "CAP-ORPHAN": ("info", "Capability file is not enabled", REF_CAP),
    "CAP-MISSING": ("medium", "Config references a capability that does not exist", REF_CAP),
    "CAP-DUPLICATE-ID": ("low", "Duplicate capability identifier", REF_CAP),
    "CAP-UNUSED-PLUGIN": ("low", "Permission granted for a plugin the frontend never imports", REF_PERM),
    "CARGO-DEVTOOLS": ("medium", "devtools feature enabled for the tauri crate", REF_CFG),
    "CMD-UNSCOPED": ("low", "Custom commands are callable from every window", REF_PERM),
    "CMD-RAW-INPUT": ("info", "Custom commands take raw path/command-like input", REF_SEC),
    "V1-DETECTED": ("info", "Tauri v1 config detected", REF_SEC),
    "V1-ALLOWLIST-ALL": ("critical", "allowlist.all enables every API", REF_SEC),
    "V1-ALLOWLIST-MODULE-ALL": ("high", "allowlist module enables every API in it", REF_SEC),
    "V1-ALLOWLIST-SCOPE": ("high", "allowlist scope is too broad", REF_SCOPE),
    "V1-REMOTE-IPC": ("high", "Remote domains can call the IPC", REF_SEC),
}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    message: str
    file: str
    pointer: str = ""
    fix: str = ""
    ref: str = ""


# --------------------------------------------------------------------------- parsing

class ParseError(Exception):
    pass


def _strip_comments(text: str) -> str:
    out: List[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: List[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def load_file(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise ParseError(str(e))
    if path.suffix.lower() == ".toml":
        if tomllib is None:
            raise ParseError("TOML files need Python 3.11+ (tomllib)")
        try:
            return tomllib.loads(raw)
        except Exception as e:  # tomllib.TOMLDecodeError
            raise ParseError(str(e))
    try:
        return json.loads(_strip_trailing_commas(_strip_comments(raw)))
    except json.JSONDecodeError as e:
        hint = " (unquoted keys / single quotes in JSON5 are not supported)" if path.suffix == ".json5" else ""
        raise ParseError("%s%s" % (e, hint))


def d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def lst(x: Any) -> list:
    return x if isinstance(x, list) else []


# --------------------------------------------------------------------------- heuristics

LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1", "ipc.localhost", "0.0.0.0"}
HOSTED_SCRIPT_HOSTS = ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com")
INTERPRETER_RE = re.compile(
    r"(^|[\\/])(sh|bash|zsh|fish|dash|ksh|cmd(\.exe)?|powershell(\.exe)?|pwsh|python[0-9.]*|node|deno|bun|perl|ruby|"
    r"osascript|wscript|cscript|mshta|curl|wget)$",
    re.I,
)
WRITE_HINT = re.compile(r"(write|remove|rename|copy|mkdir|create|truncate|delete)", re.I)
SENSITIVE_DIR = re.compile(r"(^|/)\.(ssh|aws|gnupg|kube|docker)(/|$)", re.I)
POWERFUL_PREFIXES = {"fs", "shell", "http", "opener", "process", "sql", "stronghold", "websocket", "updater", "clipboard-manager"}
KNOWN_PLUGINS = {
    "fs", "shell", "dialog", "http", "opener", "clipboard-manager", "global-shortcut", "notification", "os",
    "process", "updater", "store", "sql", "stronghold", "websocket", "autostart", "deep-link", "positioner",
    "window-state", "log", "upload", "nfc", "biometric", "barcode-scanner", "haptics", "geolocation", "cli",
    "localhost", "single-instance",
}
PLUGIN_IMPORT_RE = re.compile(r"@tauri-apps/plugin-([a-z0-9-]+)")


def path_breadth(p: str) -> Optional[str]:
    s = p.strip().replace("\\", "/")
    if s in ("*", "**", "/", "/*", "/**", "**/*", "$HOME", "$HOME/", "$HOME/*", "$HOME/**", "$HOME/**/*",
             "~", "~/**", "$ROOT", "$ROOT/**"):
        return "root"
    if re.match(r"^[A-Za-z]:/?(\*\*?(/\*)?)?$", s):
        return "root"
    if SENSITIVE_DIR.search(s):
        return "sensitive"
    if re.match(r"^\$(DESKTOP|DOCUMENT|DOWNLOAD)(/\*\*?)?$", s):
        return "wide"
    return None


def url_host(u: str) -> str:
    m = re.match(r"^(?:\*|[a-z*]+)://([^/:?#]*)", u.strip(), re.I)
    return m.group(1).lower() if m else ""


def url_breadth(u: str) -> Optional[str]:
    s = u.strip()
    if s in ("*", "**", "*://*", "*://*/*", "https://*", "https://*/*", "https://**", "http://*", "http://**",
             "http://*/*", "https://*:*", "http*://*"):
        return "any"
    host = url_host(s)
    if host in ("*", "**") or re.match(r"^\*\.(com|org|net|io|dev|app|co)$", host):
        return "any"
    if s.lower().startswith("http://") and host not in LOCAL_HOSTS:
        return "insecure"
    if host.startswith("*."):
        return "subdomain"
    return None


def is_local_url(u: str) -> bool:
    return url_host(u) in LOCAL_HOSTS or u.startswith(("tauri://", "/", "./", "index.html")) or "://" not in u


def parse_csp(csp: Any) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if isinstance(csp, dict):
        for k, v in csp.items():
            toks = v.split() if isinstance(v, str) else [str(x) for x in lst(v)]
            out[str(k).lower()] = toks
        return out
    for part in str(csp).split(";"):
        bits = part.strip().split()
        if bits and bits[0].lower() not in out:
            out[bits[0].lower()] = bits[1:]
    return out


# --------------------------------------------------------------------------- project model

CONFIG_NAMES = {"tauri.conf.json", "tauri.conf.json5", "Tauri.toml"}
PLATFORM_CFG_RE = re.compile(r"^(tauri\.(windows|linux|macos|android|ios)\.conf\.json5?|Tauri\.(windows|linux|macos|android|ios)\.toml)$")
IGNORE_DIRS = {"node_modules", "target", "dist", "build", "vendor", "gen", "out", "coverage"}
FRONT_IGNORE = IGNORE_DIRS | {"src-tauri"}
FRONT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}


def find_configs(root: Path) -> List[Path]:
    found: List[Path] = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [x for x in dn if x not in IGNORE_DIRS and not x.startswith(".")]
        if len(Path(dp).relative_to(root).parts) > 6:
            dn[:] = []
        for f in fn:
            if f in CONFIG_NAMES or PLATFORM_CFG_RE.match(f):
                found.append(Path(dp) / f)
    return sorted(found)


class Auditor:
    def __init__(self, root: Path, ignore: set, frontend_scan: bool = True):
        self.root = root if root.is_dir() else root.parent
        self.ignore = ignore
        self.frontend_scan = frontend_scan
        self.findings: List[Finding] = []
        self.projects: List[str] = []

    # -- helpers
    def rel(self, p: Path) -> str:
        try:
            return str(p.resolve().relative_to(self.root.resolve())) or p.name
        except ValueError:
            return str(p)

    def add(self, rule: str, message: str, file: str, pointer: str = "", fix: str = "",
            sev: Optional[str] = None, cap: Optional[str] = None) -> None:
        if rule in self.ignore:
            return
        default, title, ref = RULES[rule]
        severity = sev or default
        if cap and RANK[severity] < RANK[cap]:
            severity = cap
        self.findings.append(Finding(rule, severity, title, message, file, pointer, fix, ref))

    # -- CSP
    def check_csp(self, csp: Any, f: str, ptr: str, dev: bool = False) -> None:
        dirs = parse_csp(csp)
        cap = "low" if dev else None
        tag = " (devCsp: only affects `tauri dev`)" if dev else ""

        def add(rule: str, msg: str, fix: str, sev: Optional[str] = None, name: str = "") -> None:
            self.add(rule, msg + tag, f, ptr + ("/" + name if name and isinstance(csp, dict) else ""), fix, sev, cap)

        if "default-src" not in dirs and "script-src" not in dirs:
            add("CSP-NO-FALLBACK", "Without default-src or script-src, scripts are not restricted by this policy.",
                "Start from: default-src 'self'; connect-src ipc: http://ipc.localhost")
        script_name = "script-src" if "script-src" in dirs else "default-src"
        script = dirs.get(script_name, [])
        low = [t.lower() for t in script]
        if "'unsafe-eval'" in low:
            add("CSP-UNSAFE-EVAL", "%s allows 'unsafe-eval', so eval()/new Function() XSS payloads run." % script_name,
                "Remove 'unsafe-eval'. If WebAssembly is the reason, use 'wasm-unsafe-eval' instead.", name=script_name)
        if "'unsafe-inline'" in low:
            add("CSP-UNSAFE-INLINE",
                "%s allows 'unsafe-inline'. Where a nonce or hash is present browsers ignore it anyway, so it is "
                "either dead weight or a real hole." % script_name,
                "Remove 'unsafe-inline' from script sources; Tauri injects nonces/hashes for its own scripts.",
                name=script_name)
        if "*" in script:
            add("CSP-WILDCARD-SOURCE", "%s contains '*', allowing scripts from any origin." % script_name,
                "List only the exact origins you need, or just 'self'.", name=script_name)
        for t in low:
            if t in ("data:", "http:", "https:"):
                add("CSP-DANGEROUS-SCHEME", "%s allows the bare scheme `%s`." % (script_name, t),
                    "Remove the scheme and list explicit hosts instead.", name=script_name)
            elif t in ("blob:", "filesystem:"):
                add("CSP-DANGEROUS-SCHEME", "%s allows `%s`, which can host attacker-controlled script." % (script_name, t),
                    "Drop it unless a worker/library truly requires it.", sev="medium", name=script_name)
            elif any(h in t for h in HOSTED_SCRIPT_HOSTS):
                add("CSP-HOSTED-SCRIPT-HOST", "%s trusts `%s`, a public host that serves attacker-usable script gadgets." % (script_name, t),
                    "Bundle the library locally and remove the host.", name=script_name)
        for name, toks in dirs.items():
            if name != script_name and "*" in toks:
                sev = "high" if name in ("default-src", "object-src") else "medium" if name in (
                    "connect-src", "frame-src", "child-src", "worker-src") else None
                if sev:
                    add("CSP-WILDCARD-SOURCE", "%s contains '*'." % name, "Restrict it to the origins the app really contacts.",
                        sev=sev, name=name)
            for t in toks:
                tl = t.lower()
                if re.match(r"^(http|ws)://", tl) and url_host(tl) not in LOCAL_HOSTS:
                    add("CSP-INSECURE-SOURCE", "%s allows plaintext source `%s`." % (name, t),
                        "Use https:// / wss:// for remote hosts.", name=name)
        if "object-src" not in dirs and "default-src" not in dirs:
            add("CSP-NO-OBJECT-SRC", "No object-src or default-src, so plugins/embeds are unrestricted.",
                "Add object-src 'none'.")

    # -- Tauri v2 config
    def config_v2(self, cfg: dict, f: str, main: bool) -> None:
        app = d(cfg.get("app"))
        sec = d(app.get("security"))
        plugins = d(cfg.get("plugins"))

        if "csp" in sec and sec["csp"] not in (None, ""):
            self.check_csp(sec["csp"], f, "app.security.csp")
        elif main:
            self.add("CSP-MISSING", "app.security.csp is null/absent, so the webview runs with no CSP.", f, "app.security.csp",
                     "Set a strict policy, e.g. \"default-src 'self'; connect-src ipc: http://ipc.localhost\" "
                     "and add only the origins your app needs. Keep ipc: / http://ipc.localhost or IPC will break.")
        if sec.get("devCsp") not in (None, ""):
            self.check_csp(sec["devCsp"], f, "app.security.devCsp", dev=True)

        dis = sec.get("dangerousDisableAssetCspModification")
        if dis is True or (isinstance(dis, list) and dis):
            self.add("CSP-ASSET-MODIFICATION-DISABLED",
                     "Tauri will not add nonces/hashes to your CSP, weakening the protection it gives by default.",
                     f, "app.security.dangerousDisableAssetCspModification",
                     "Remove it (or set false) unless you can prove a build step conflicts, then scope it to specific directives.")
        if main and sec.get("freezePrototype") is not True:
            self.add("FREEZE-PROTOTYPE", "Object.prototype is not frozen, which leaves prototype-pollution gadgets open.",
                     f, "app.security.freezePrototype", 'Set "freezePrototype": true and test the frontend.')
        pattern = d(sec.get("pattern")).get("use")
        if main and pattern != "isolation":
            self.add("ISOLATION-PATTERN",
                     "Isolation puts a sandboxed layer between frontend and IPC. Worth it if you use fs/shell/http or many npm deps.",
                     f, "app.security.pattern",
                     'Only switch to {"use":"isolation"} after you add an isolation app; it needs frontend work.')
        ap = d(sec.get("assetProtocol"))
        if ap.get("enable") is True:
            scope = ap.get("scope")
            allow = scope if isinstance(scope, list) else lst(d(scope).get("allow"))
            if not allow:
                self.add("ASSET-PROTOCOL", "assetProtocol is enabled with no scope.", f, "app.security.assetProtocol.scope",
                         'Add a minimal scope such as ["$APPDATA/media/**"].', sev="medium")
            else:
                for p in allow:
                    b = path_breadth(str(p))
                    if b in ("root", "sensitive"):
                        self.add("ASSET-PROTOCOL", "assetProtocol scope `%s` exposes files readable by any script in the webview." % p,
                                 f, "app.security.assetProtocol.scope", "Narrow it to a dedicated app directory.")
                    elif b == "wide":
                        self.add("ASSET-PROTOCOL", "assetProtocol scope `%s` is a broad user folder." % p, f,
                                 "app.security.assetProtocol.scope", "Narrow it to a sub-folder.", sev="medium")
        if app.get("withGlobalTauri") is True:
            self.add("GLOBAL-TAURI", "window.__TAURI__ lets any injected script reach the IPC without imports.", f,
                     "app.withGlobalTauri", "Set false and import from @tauri-apps/api instead.")
        if app.get("macOSPrivateApi") is True:
            self.add("MACOS-PRIVATE-API", "Uses private macOS APIs: larger attack surface and rejected by the App Store.",
                     f, "app.macOSPrivateApi", "Disable unless you need transparent windows on macOS.")
        for i, w in enumerate(lst(app.get("windows"))):
            url = d(w).get("url")
            if isinstance(url, str) and re.match(r"^https?://", url, re.I) and not is_local_url(url):
                self.add("REMOTE-WINDOW-URL", "Window `%s` loads %s directly." % (d(w).get("label", "main"), url), f,
                         "app.windows[%d].url" % i, "Prefer bundled content. Never list this origin in a capability's `remote.urls` unless essential.")
        if main and cfg.get("identifier") in ("com.tauri.dev", "com.tauri.app"):
            self.add("DEFAULT-IDENTIFIER", "Placeholder identifier `%s` is shared by every unmodified template." % cfg["identifier"],
                     f, "identifier", "Use a reverse-domain id you own, e.g. com.yourname.app.")
        upd = plugins.get("updater")
        if isinstance(upd, dict):
            self.check_updater(upd, f, "plugins.updater")
        sh = d(plugins.get("shell")).get("open")
        if sh is True or (isinstance(sh, str) and sh in (".*", ".+", "^.*$", "^.+$")):
            self.add("SHELL-OPEN-BROAD", "plugins.shell.open allows any target, including local executables on some platforms.",
                     f, "plugins.shell.open", "Remove it (defaults to https/mailto/tel) or use a strict regex.")

    def check_updater(self, upd: dict, f: str, ptr: str) -> None:
        if not str(upd.get("pubkey", "")).strip():
            self.add("UPDATER-NO-PUBKEY", "Without a public key updates cannot be signature-verified.", f, ptr + ".pubkey",
                     "Generate a keypair with `tauri signer generate` and put the public key here.")
        eps = lst(upd.get("endpoints"))
        if not eps:
            self.add("UPDATER-NO-ENDPOINTS", "No update endpoints configured.", f, ptr + ".endpoints", "Add https:// endpoints.")
        for e in eps:
            if isinstance(e, str) and e.lower().startswith("http://") and url_host(e) not in LOCAL_HOSTS:
                self.add("UPDATER-INSECURE-TRANSPORT", "Endpoint `%s` uses plaintext HTTP." % e, f, ptr + ".endpoints",
                         "Use https://.")
        if upd.get("dangerousInsecureTransportProtocol") is True:
            self.add("UPDATER-INSECURE-TRANSPORT", "dangerousInsecureTransportProtocol is true.", f,
                     ptr + ".dangerousInsecureTransportProtocol", "Remove it and serve updates over HTTPS.")

    # -- Tauri v1 config
    def config_v1(self, cfg: dict, f: str) -> None:
        t = d(cfg.get("tauri"))
        self.add("V1-DETECTED", "This project uses the v1 `tauri` config block. v2 replaces the allowlist with per-window "
                 "capabilities and finer permissions.", f, "tauri", "Plan a migration with `npm run tauri migrate`.")
        al = d(t.get("allowlist"))
        if al.get("all") is True:
            self.add("V1-ALLOWLIST-ALL", "Every Tauri API is exposed to the frontend.", f, "tauri.allowlist.all",
                     "Set false and enable only the specific APIs you call.")
        for mod, val in al.items():
            if mod == "all" or not isinstance(val, dict):
                continue
            if val.get("all") is True:
                self.add("V1-ALLOWLIST-MODULE-ALL", "allowlist.%s.all enables the whole module." % mod, f,
                         "tauri.allowlist.%s.all" % mod, "Enable individual flags instead.")
            scope = val.get("scope")
            items = scope if isinstance(scope, list) else lst(d(scope).get("allow"))
            for it in items:
                if isinstance(it, str):
                    b = path_breadth(it) if mod == "fs" else url_breadth(it) if mod == "http" else None
                    if b in ("root", "any", "sensitive"):
                        self.add("V1-ALLOWLIST-SCOPE", "allowlist.%s.scope allows `%s`." % (mod, it), f,
                                 "tauri.allowlist.%s.scope" % mod, "Narrow the scope.")
                elif isinstance(it, dict) and mod == "shell":
                    cmd = str(it.get("cmd", ""))
                    if INTERPRETER_RE.search(cmd) or it.get("args") is True:
                        self.add("V1-ALLOWLIST-SCOPE", "shell scope entry `%s` allows an interpreter or arbitrary arguments." % it.get("name", cmd),
                                 f, "tauri.allowlist.shell.scope", "Pin exact arguments with validators.")
        proto = d(al.get("protocol"))
        if proto.get("asset") is True:
            for p in lst(proto.get("assetScope")) or []:
                if path_breadth(str(p)) in ("root", "sensitive"):
                    self.add("V1-ALLOWLIST-SCOPE", "protocol.assetScope allows `%s`." % p, f,
                             "tauri.allowlist.protocol.assetScope", "Narrow it.")
            if not lst(proto.get("assetScope")):
                self.add("V1-ALLOWLIST-SCOPE", "Asset protocol enabled without a scope.", f,
                         "tauri.allowlist.protocol.assetScope", "Add a minimal scope.", sev="medium")
        sec = d(t.get("security"))
        if sec.get("csp") in (None, ""):
            self.add("CSP-MISSING", "tauri.security.csp is null/absent.", f, "tauri.security.csp",
                     "Set a strict CSP, e.g. \"default-src 'self'\".")
        else:
            self.check_csp(sec["csp"], f, "tauri.security.csp")
        if sec.get("dangerousDisableAssetCspModification") in (True,) or lst(sec.get("dangerousDisableAssetCspModification")):
            self.add("CSP-ASSET-MODIFICATION-DISABLED", "Automatic CSP hardening is disabled.", f,
                     "tauri.security.dangerousDisableAssetCspModification", "Remove it.")
        if sec.get("freezePrototype") is not True:
            self.add("FREEZE-PROTOTYPE", "Object.prototype is not frozen.", f, "tauri.security.freezePrototype", "Set true.")
        for r in lst(sec.get("dangerousRemoteDomainIpcAccess")):
            if isinstance(r, dict):
                dom = str(r.get("domain", ""))
                self.add("V1-REMOTE-IPC", "Domain `%s` can call IPC commands." % dom, f,
                         "tauri.security.dangerousRemoteDomainIpcAccess", "Remove unless essential; scope windows and plugins tightly.",
                         sev="critical" if dom in ("*", "") or dom.startswith("*") else None)
        upd = d(t.get("updater"))
        if upd.get("active") is True:
            self.check_updater(upd, f, "tauri.updater")
        if t.get("macOSPrivateApi") is True:
            self.add("MACOS-PRIVATE-API", "macOS private API enabled.", f, "tauri.macOSPrivateApi", "Disable unless required.")

    # -- capabilities
    def load_capabilities(self, proj_dir: Path, cfg: dict, cfg_file: str) -> List[Tuple[str, str, dict]]:
        """returns (file, pointer, capability)"""
        caps: List[Tuple[str, str, dict]] = []
        cap_dir = proj_dir / "capabilities"
        files: Dict[str, str] = {}
        if cap_dir.is_dir():
            for p in sorted(cap_dir.iterdir()):
                if p.suffix.lower() in (".json", ".json5", ".toml") and p.is_file():
                    try:
                        data = load_file(p)
                    except ParseError as e:
                        self.add("PARSE-ERROR", str(e), self.rel(p), "", "Fix the syntax; this file was not audited.")
                        continue
                    if isinstance(data, dict):
                        caps.append((self.rel(p), "", data))
                        files[str(data.get("identifier", p.stem))] = self.rel(p)
        enabled = d(d(cfg.get("app")).get("security")).get("capabilities")
        if isinstance(enabled, list):
            known = set(files)
            for i, item in enumerate(enabled):
                if isinstance(item, dict):
                    caps.append((cfg_file, "app.security.capabilities[%d]" % i, item))
                    known.add(str(item.get("identifier", "")))
            for i, item in enumerate(enabled):
                if isinstance(item, str) and item not in known:
                    self.add("CAP-MISSING", "Capability `%s` is listed but no matching file/inline definition was found." % item,
                             cfg_file, "app.security.capabilities[%d]" % i, "Create it or remove the reference.")
            ids = {i for i in enabled if isinstance(i, str)} | {str(i.get("identifier")) for i in enabled if isinstance(i, dict)}
            for ident, fl in files.items():
                if ident not in ids:
                    self.add("CAP-ORPHAN", "Capability `%s` exists but is not in app.security.capabilities, so it is ignored." % ident,
                             fl, "", "Add it to the list or delete the file.")
        seen: Dict[str, str] = {}
        for fl, ptr, c in caps:
            ident = str(c.get("identifier", ""))
            if ident in seen and ident:
                self.add("CAP-DUPLICATE-ID", "Identifier `%s` already defined in %s." % (ident, seen[ident]), fl, ptr, "Make identifiers unique.")
            seen[ident] = fl
        return caps

    def check_capability(self, c: dict, f: str, base: str, labels: List[str]) -> List[str]:
        """returns list of plugin prefixes granted."""
        ident = str(c.get("identifier", "?"))
        perms = lst(c.get("permissions"))
        norm: List[Tuple[str, Any, int]] = []
        for i, p in enumerate(perms):
            pid = p if isinstance(p, str) else str(d(p).get("identifier", ""))
            norm.append((pid, p, i))
        prefixes = {pid.split(":")[0] for pid, _, _ in norm if ":" in pid}
        powerful = sorted(prefixes & POWERFUL_PREFIXES)
        remote_urls = [u for u in lst(d(c.get("remote")).get("urls")) if isinstance(u, str)]
        pre = base + ("/" if base else "")

        if remote_urls:
            sev = "high"
            reasons = []
            if any(url_breadth(u) == "any" for u in remote_urls):
                sev = "critical"
                reasons.append("a pattern matches (nearly) any site")
            if powerful:
                sev = "critical"
                reasons.append("it also grants %s" % ", ".join(powerful))
            self.add("CAP-REMOTE-IPC", "Capability `%s` lets %s call the IPC%s." % (
                ident, ", ".join(remote_urls), (" (" + "; ".join(reasons) + ")") if reasons else ""), f, pre + "remote.urls",
                "Drop `remote` or limit it to one exact origin with the smallest possible permission set.", sev=sev)
            for u in remote_urls:
                if url_breadth(u) == "insecure":
                    self.add("CAP-REMOTE-IPC", "Remote origin `%s` is plaintext HTTP." % u, f, pre + "remote.urls", "Use https://.", sev="critical")

        wins = [w for w in lst(c.get("windows")) if isinstance(w, str)]
        webs = [w for w in lst(c.get("webviews")) if isinstance(w, str)]
        if "*" in wins or "*" in webs:
            self.add("CAP-WILDCARD-WINDOW", "Capability `%s` uses \"*\", so every current and future window/webview gets these permissions." % ident,
                     f, pre + ("windows" if "*" in wins else "webviews"), "List window labels explicitly (e.g. [\"main\"]).",
                     sev="high" if remote_urls else None)
        elif wins and labels and not any(fnmatch.fnmatch(l, w) for w in wins for l in labels):
            self.add("CAP-NO-WINDOW-MATCH", "Capability `%s` targets %s but configured windows are %s. Fine if windows are created at runtime." % (
                ident, wins, labels), f, pre + "windows", "Check the labels for typos.")

        for pid, entry, i in norm:
            ptr = "%spermissions[%d]" % (pre, i)
            self.check_permission(pid, entry, f, ptr)
        return sorted(prefixes)

    def check_permission(self, pid: str, entry: Any, f: str, ptr: str) -> None:
        prefix = pid.split(":")[0]
        write = bool(WRITE_HINT.search(pid))
        if re.match(r"^fs:(allow|scope)-home", pid) or pid in ("fs:write-all", "fs:read-all"):
            wr = "write" in pid or pid == "fs:write-all"
            self.add("CAP-FS-BROAD", "`%s` reaches the whole home directory%s." % (pid, " with write access" if wr else ""), f, ptr,
                     "Use a dedicated scope such as $APPDATA/**, or a dialog-picked path.", sev="critical" if wr else "high")
        elif re.match(r"^fs:(allow|scope)-(desktop|document|download)", pid):
            self.add("CAP-FS-BROAD", "`%s` reaches a broad user folder." % pid, f, ptr, "Narrow to a sub-folder scope.",
                     sev="medium" if "write" in pid else "low")
        if pid == "core:webview:allow-create-webview-window" or pid == "core:window:allow-create":
            self.add("CAP-WEBVIEW-CREATE", "Frontend code can spawn windows that may inherit capabilities by label.", f, ptr,
                     "Remove if the app never creates windows from JS.")
        if not isinstance(entry, dict):
            return
        for key in ("allow",):
            for j, item in enumerate(lst(entry.get(key))):
                if not isinstance(item, dict):
                    continue
                sptr = "%s.%s[%d]" % (ptr, key, j)
                if "path" in item:
                    b = path_breadth(str(item["path"]))
                    if prefix == "opener" and b in ("root", "sensitive"):
                        self.add("CAP-OPENER-BROAD", "`%s` may open any path (%s); opening files can launch programs." % (pid, item["path"]),
                                 f, sptr, "Scope to one app directory.", sev="high")
                    elif prefix == "fs" or prefix not in ("opener",):
                        if b in ("root", "sensitive"):
                            sev = "critical" if (write and b == "root") else "high"
                            self.add("CAP-FS-BROAD", "`%s` scope `%s` is %s." % (pid, item["path"], "the whole disk/home" if b == "root" else "a sensitive directory"),
                                     f, sptr, "Use $APPDATA/**, $APPCONFIG/** or a user-picked path.", sev=sev)
                        elif b == "wide":
                            self.add("CAP-FS-BROAD", "`%s` scope `%s` is a broad user folder." % (pid, item["path"]), f, sptr,
                                     "Narrow to a sub-folder.", sev="medium" if write else "low")
                if "url" in item:
                    b = url_breadth(str(item["url"]))
                    rule = "CAP-OPENER-BROAD" if prefix == "opener" else "CAP-HTTP-BROAD"
                    if b == "any":
                        self.add(rule, "`%s` allows `%s`, effectively any site." % (pid, item["url"]), f, sptr, "List exact hosts.")
                    elif b == "insecure":
                        self.add(rule, "`%s` allows plaintext `%s`." % (pid, item["url"]), f, sptr, "Use https://.", sev="high")
                    elif b == "subdomain" and prefix != "opener":
                        self.add(rule, "`%s` allows wildcard subdomain `%s`; any subdomain takeover becomes reachable." % (pid, item["url"]),
                                 f, sptr, "Prefer exact hostnames.", sev="low")
                if prefix == "shell" and ("cmd" in item or "name" in item or "args" in item):
                    cmd = str(item.get("cmd", item.get("name", "")))
                    nm = item.get("name", cmd)
                    if INTERPRETER_RE.search(cmd) and not item.get("sidecar"):
                        self.add("CAP-SHELL-SCOPE", "Scope `%s` runs `%s`, a shell/interpreter/downloader." % (nm, cmd), f, sptr,
                                 "Expose a fixed binary or a Rust command; never an interpreter.", sev="critical")
                    args = item.get("args")
                    if args is True:
                        self.add("CAP-SHELL-SCOPE", "Scope `%s` accepts any arguments." % nm, f, sptr,
                                 "Replace `true` with a fixed list or validators.")
                    else:
                        for a in lst(args):
                            if isinstance(a, dict) and str(a.get("validator", "")) in (".*", ".+", "^.*$", "^.+$", "\\S+", ".*?"):
                                self.add("CAP-SHELL-SCOPE", "Scope `%s` has an argument validator that matches everything." % nm, f, sptr,
                                         "Use a tight regex such as ^[a-z0-9._-]+$.")

    # -- Cargo / Rust
    def check_cargo(self, proj_dir: Path) -> None:
        cargo = proj_dir / "Cargo.toml"
        if not cargo.is_file():
            return
        feats: List[str] = []
        text = cargo.read_text(encoding="utf-8", errors="ignore")
        if tomllib is not None:
            try:
                dep = d(d(tomllib.loads(text)).get("dependencies")).get("tauri")
                if isinstance(dep, dict):
                    feats = [str(x) for x in lst(dep.get("features"))]
            except Exception:
                pass
        else:
            m = re.search(r"^tauri\s*=\s*\{[^}]*features\s*=\s*\[([^\]]*)\]", text, re.M)
            if m:
                feats = re.findall(r"[\"']([^\"']+)[\"']", m.group(1))
        if "devtools" in feats:
            self.add("CARGO-DEVTOOLS", "The `devtools` feature turns on webview devtools in release builds too.", self.rel(cargo),
                     "dependencies.tauri.features", "Remove the feature, or gate it behind a cargo feature you never ship.")

    def check_commands(self, proj_dir: Path) -> None:
        src = proj_dir / "src"
        if not src.is_dir():
            return
        pat = re.compile(r"#\[(?:tauri::)?command[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)", re.S)
        risky = re.compile(r"\b(path|file|filename|filepath|dir|url|command|cmd|args|sql|script)\s*:\s*(?:&\s*)?(String|str|PathBuf|Path|Vec<String>)")
        total = 0
        risky_by_file: Dict[str, List[str]] = {}
        count = 0
        for p in src.rglob("*.rs"):
            count += 1
            if count > 2000:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in pat.finditer(text):
                total += 1
                if risky.search(m.group(2)):
                    risky_by_file.setdefault(self.rel(p), []).append(m.group(1))
        if total:
            build = proj_dir / "build.rs"
            manifest = build.is_file() and re.search(r"app_manifest|AppManifest", build.read_text(encoding="utf-8", errors="ignore"))
            if not manifest:
                self.add("CMD-UNSCOPED", "%d custom command(s) are callable from every window and webview. v2 lets you restrict them "
                         "with an AppManifest in build.rs." % total, self.rel(build if build.is_file() else src), "",
                         "Add tauri_build::Attributes::new().app_manifest(AppManifest::new().commands(&[...])) and grant them per capability.")
        for fl, names in risky_by_file.items():
            self.add("CMD-RAW-INPUT", "Commands taking path/URL/command-like arguments: %s. Validate or canonicalize inside the command." % (
                ", ".join(names[:8]) + (" ..." if len(names) > 8 else "")), fl, "",
                "Reject '..', resolve against an allowed root, and avoid passing user strings to a shell.")

    # -- frontend usage
    def scan_frontend(self, root: Path) -> Tuple[set, int, bool]:
        used: set = set()
        files = 0
        global_api = False
        for dp, dn, fn in os.walk(root):
            dn[:] = [x for x in dn if x not in FRONT_IGNORE and not x.startswith(".")]
            for name in fn:
                if Path(name).suffix not in FRONT_EXT:
                    continue
                p = Path(dp) / name
                try:
                    if p.stat().st_size > 1_000_000:
                        continue
                    t = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                files += 1
                used.update(PLUGIN_IMPORT_RE.findall(t))
                if "__TAURI__" in t:
                    global_api = True
                if files >= 5000:
                    return used, files, global_api
        return used, files, global_api

    # -- orchestration
    def audit_project(self, cfg_path: Path, siblings: List[Path]) -> None:
        proj_dir = cfg_path.parent
        try:
            cfg = load_file(cfg_path)
        except ParseError as e:
            self.add("PARSE-ERROR", str(e), self.rel(cfg_path), "", "Fix the syntax; this project was not audited.")
            return
        if not isinstance(cfg, dict):
            return
        f = self.rel(cfg_path)
        is_v1 = "tauri" in cfg and "app" not in cfg
        self.projects.append("%s (Tauri %s)" % (f, "v1" if is_v1 else "v2"))
        if is_v1:
            self.config_v1(cfg, f)
            self.check_cargo(proj_dir)
            self.check_commands(proj_dir)
            return
        self.config_v2(cfg, f, main=True)
        for sib in siblings:
            try:
                scfg = load_file(sib)
            except ParseError as e:
                self.add("PARSE-ERROR", str(e), self.rel(sib), "", "Fix the syntax.")
                continue
            if isinstance(scfg, dict):
                self.config_v2(scfg, self.rel(sib), main=False)
        labels = [str(d(w).get("label", "main")) for w in lst(d(cfg.get("app")).get("windows"))] or ["main"]
        caps = self.load_capabilities(proj_dir, cfg, f)
        granted: Dict[str, set] = {}
        for fl, ptr, c in caps:
            for pre in self.check_capability(c, fl, ptr, labels):
                granted.setdefault(fl + "|" + ptr, set()).add(pre)
        self.check_cargo(proj_dir)
        self.check_commands(proj_dir)
        if self.frontend_scan and caps:
            front = proj_dir.parent if proj_dir.name == "src-tauri" else proj_dir
            used, nfiles, global_api = self.scan_frontend(front)
            if nfiles and not global_api:
                for key, prefixes in sorted(granted.items()):
                    unused = sorted(p for p in prefixes if p in KNOWN_PLUGINS and p not in used)
                    if unused:
                        fl, _, ptr = key.partition("|")
                        self.add("CAP-UNUSED-PLUGIN", "Granted but never imported in the frontend: %s. Ignore if used only from Rust." % ", ".join(unused),
                                 fl, ptr, "Remove the permissions you do not need, after confirming no JS or Rust code path uses them.")

    def run(self, target: Path) -> None:
        if target.is_file():
            try:
                data = load_file(target)
            except ParseError as e:
                self.add("PARSE-ERROR", str(e), target.name)
                return
            if isinstance(data, dict) and ("permissions" in data or "identifier" in data) and not (
                    "app" in data or "tauri" in data or "productName" in data):
                self.projects.append("%s (capability file)" % target.name)
                self.check_capability(data, target.name, "", [])
                return
            if isinstance(data, dict):
                self.audit_project(target, [])
                return
            return
        configs = find_configs(target)
        mains = [c for c in configs if c.name in CONFIG_NAMES]
        by_dir: Dict[Path, List[Path]] = {}
        for c in configs:
            if PLATFORM_CFG_RE.match(c.name):
                by_dir.setdefault(c.parent, []).append(c)
        if not mains:
            return
        done = set()
        for m in mains:
            if m.parent in done:
                continue  # json + json5 in the same dir: audit one
            done.add(m.parent)
            self.audit_project(m, by_dir.get(m.parent, []))

    def sorted_findings(self) -> List[Finding]:
        seen = set()
        out = []
        for x in self.findings:
            key = (x.rule, x.file, x.pointer, x.message)
            if key not in seen:
                seen.add(key)
                out.append(x)
        return sorted(out, key=lambda x: (RANK[x.severity], x.file, x.pointer, x.rule))


# --------------------------------------------------------------------------- scoring, attack paths, baseline

WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def score_of(findings: List[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))


def grade_of(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


CSP_WEAK = {"CSP-MISSING", "CSP-NO-FALLBACK", "CSP-UNSAFE-EVAL", "CSP-UNSAFE-INLINE", "CSP-WILDCARD-SOURCE",
            "CSP-DANGEROUS-SCHEME", "CSP-HOSTED-SCRIPT-HOST"}
POWER = {"CAP-SHELL-SCOPE", "CAP-FS-BROAD", "CAP-OPENER-BROAD"}

# id, title, [any-of groups that must ALL be present], story, cheapest way to break the chain
ATTACK_PATHS = [
    ("PATH-REMOTE-TAKEOVER", "A remote site you trust can take over the machine",
     [{"CAP-REMOTE-IPC"}, POWER],
     "A capability lists remote origins AND grants file-write, shell or open permissions. Whoever controls or compromises "
     "one of those origins can invoke them on every user's computer.",
     "Remove `remote.urls` from the capability. It is the cheapest link to cut."),
    ("PATH-XSS-TO-RCE", "One XSS bug becomes code execution or file write",
     [CSP_WEAK, POWER],
     "The CSP does not contain injected script, and powerful permissions are reachable from the webview. "
     "Any XSS (a markdown renderer, a dependency, a remote page) escalates past the webview.",
     "Tighten the CSP first, then narrow the permission scopes."),
    ("PATH-UPDATE-HIJACK", "The update channel can ship code to every install",
     [{"UPDATER-NO-PUBKEY", "UPDATER-INSECURE-TRANSPORT"}],
     "Updates are unsigned or fetched over plaintext HTTP. Anyone who can tamper with the endpoint or the network "
     "path can deliver a malicious build.",
     "Set `plugins.updater.pubkey`, sign releases, and use HTTPS endpoints only."),
    ("PATH-XSS-TO-IPC", "Injected script reaches the IPC without any imports",
     [CSP_WEAK, {"GLOBAL-TAURI"}],
     "`withGlobalTauri` puts the IPC on `window.__TAURI__` and the CSP will not stop injected script from using it.",
     "Set `withGlobalTauri: false` and import from `@tauri-apps/api`."),
    ("PATH-FILE-EXFIL", "Scripts can read local files and send them anywhere",
     [{"ASSET-PROTOCOL"}, CSP_WEAK | {"CAP-HTTP-BROAD"}],
     "The asset protocol exposes local files to the webview and nothing stops script from posting them to any host.",
     "Scope the asset protocol to one app folder and restrict `connect-src`."),
]


def attack_paths(findings: List[Finding]) -> List[dict]:
    solid = [f for f in findings if RANK[f.severity] <= RANK["medium"]]
    out = []
    for pid, title, groups, story, brk in ATTACK_PATHS:
        links, ok = [], True
        for g in groups:
            hit = [f for f in solid if f.rule in g]
            if not hit:
                ok = False
                break
            links.extend(hit)
        if ok:
            seen, uniq = set(), []
            for f in links:
                k = (f.rule, f.file, f.pointer)
                if k not in seen:
                    seen.add(k)
                    uniq.append({"rule": f.rule, "file": f.file, "pointer": f.pointer})
            out.append({"id": pid, "title": title, "severity": "critical", "story": story, "break": brk, "links": uniq})
    return out


def fingerprint(f: Finding) -> str:
    return "|".join((f.rule, f.file, f.pointer, f.message))


def badge_svg(score: int, grade: str) -> str:
    color = {"A": "#2EA98F", "B": "#4FA3C7", "C": "#C9A227", "D": "#D9822B", "F": "#D1453B"}[grade]
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="156" height="24" role="img" aria-label="tauri-audit: %s %d">'
        '<rect width="156" height="24" rx="3" fill="#0A0D12"/>'
        '<rect x="96" width="60" height="24" rx="3" fill="%s"/><rect x="96" width="6" height="24" fill="%s"/>'
        '<g font-family="ui-monospace,Menlo,Consolas,monospace" font-size="12" fill="#E6EDF3" text-anchor="middle">'
        '<text x="48" y="16">tauri-audit</text><text x="126" y="16" font-weight="700" fill="#0A0D12">%s %d</text></g></svg>\n'
    ) % (grade, score, color, color, grade, score)


# --------------------------------------------------------------------------- output

COLORS = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def summary_counts(findings: List[Finding]) -> Dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def render_text(a: Auditor, findings: List[Finding], color: bool, paths: List[dict], suppressed: int = 0) -> str:
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    sc = score_of(findings)
    lines = [c(BOLD, "tauri-audit %s" % __version__) + "  " + str(a.root)]
    for p in a.projects:
        lines.append(c(DIM, "project: " + p))
    lines.append("grade: %s (%d/100)" % (grade_of(sc), sc))
    lines.append("")
    if paths:
        lines.append(c(COLORS["critical"], "ATTACK PATHS (%d)" % len(paths)))
        for ap in paths:
            lines.append("  ! " + c(BOLD, ap["title"]))
            lines.append("    chain: " + " + ".join(sorted({l["rule"] for l in ap["links"]})))
            lines.append("    " + ap["story"])
            lines.append("    break it: " + ap["break"])
            lines.append("")
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines.append("%s  %s  %s" % (c(COLORS[f.severity], f.severity.upper().ljust(8)), c(BOLD, f.rule), f.title))
        lines.append("    %s%s" % (f.file, ("  ->  " + f.pointer) if f.pointer else ""))
        lines.append("    " + f.message)
        if f.fix:
            lines.append("    fix: " + f.fix)
        lines.append(c(DIM, "    " + f.ref))
        lines.append("")
    n = summary_counts(findings)
    lines.append("Summary: " + " | ".join("%d %s" % (n[s], s) for s in SEVERITIES))
    if suppressed:
        lines.append("%d known finding(s) hidden by baseline." % suppressed)
    return "\n".join(lines)


def render_markdown(a: Auditor, findings: List[Finding], paths: List[dict], suppressed: int = 0) -> str:
    n = summary_counts(findings)
    sc = score_of(findings)
    out = ["# tauri-audit report", "", "Target: `%s`" % a.root, ""]
    out.append("**Grade %s (%d/100)** | " % (grade_of(sc), sc) + " | ".join("%d %s" % (n[s], s) for s in SEVERITIES))
    out.append("")
    if suppressed:
        out += ["_%d known finding(s) hidden by baseline._" % suppressed, ""]
    if paths:
        out += ["## Attack paths", ""]
        for ap in paths:
            out += ["### %s" % ap["title"], "", ap["story"], "",
                    "Chain: " + " + ".join("`%s`" % r for r in sorted({l["rule"] for l in ap["links"]})), "",
                    "**Break it:** " + ap["break"], ""]
        out += ["## Findings", ""]
    if not findings:
        out.append("No findings.")
    for f in findings:
        out.append("### [%s] %s: %s" % (f.severity.upper(), f.rule, f.title))
        out.append("")
        out.append("`%s`%s" % (f.file, (" -> `%s`" % f.pointer) if f.pointer else ""))
        out.append("")
        out.append(f.message)
        if f.fix:
            out.append("")
            out.append("**Fix:** " + f.fix)
        out.append("")
        out.append("[docs](%s)" % f.ref)
        out.append("")
    return "\n".join(out)


def render_json(a: Auditor, findings: List[Finding], paths: List[dict], suppressed: int = 0) -> str:
    sc = score_of(findings)
    return json.dumps({
        "tool": "tauri-audit", "version": __version__, "root": str(a.root), "projects": a.projects,
        "score": sc, "grade": grade_of(sc), "summary": summary_counts(findings), "attackPaths": paths,
        "suppressedByBaseline": suppressed, "findings": [asdict(f) for f in findings],
    }, indent=2)


def render_html(a: Auditor, findings: List[Finding], paths: List[dict], suppressed: int = 0) -> str:
    from html import escape as e
    sc = score_of(findings)
    gr = grade_of(sc)
    n = summary_counts(findings)
    chips = "".join('<span class="chip %s">%d %s</span>' % (s, n[s], s) for s in SEVERITIES if n[s])
    parts = []
    if paths:
        parts.append("<h2>Attack paths</h2>")
        for ap in paths:
            parts.append('<section class="card path"><h3>%s</h3><p>%s</p><p class="mono dim">%s</p><p><b>Break it:</b> %s</p></section>' % (
                e(ap["title"]), e(ap["story"]), e(" + ".join(sorted({l["rule"] for l in ap["links"]}))), e(ap["break"])))
    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append("<p>No findings.</p>")
    for f in findings:
        parts.append(
            '<section class="card"><div class="row"><span class="chip %s">%s</span><b class="mono">%s</b><span>%s</span></div>'
            '<p class="mono dim">%s%s</p><p>%s</p>%s<p class="dim"><a href="%s">docs</a></p></section>' % (
                f.severity, e(f.severity), e(f.rule), e(f.title), e(f.file),
                e(" -> " + f.pointer) if f.pointer else "", e(f.message),
                ("<p><b>Fix:</b> %s</p>" % e(f.fix)) if f.fix else "", e(f.ref)))
    css = ("""
:root{--bg:#0A0D12;--fg:#E6EDF3;--dim:#7D8590;--card:#11161D;--line:#1C232C;--acc:#7DD3FC}
@media (prefers-color-scheme:light){:root{--bg:#F6F8FA;--fg:#0A0D12;--dim:#57606A;--card:#fff;--line:#D0D7DE;--acc:#0969DA}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,sans-serif;padding:40px 20px}
main{max-width:860px;margin:0 auto}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}.dim{color:var(--dim)}
h1{font:700 28px ui-monospace,Menlo,Consolas,monospace;margin:0 0 4px}h2{margin:36px 0 12px;font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.head{display:flex;gap:24px;align-items:center;margin:24px 0}.grade{font:700 64px ui-monospace,Menlo,Consolas,monospace;color:var(--acc);line-height:1}
.card{background:var(--card);border:1px solid var(--line);padding:16px 18px;margin:10px 0}.card p{margin:6px 0}.path{border-left:3px solid #D1453B}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.chip{font:600 11px ui-monospace,monospace;text-transform:uppercase;padding:2px 8px;border:1px solid var(--line);margin-right:6px}
.critical{background:#D1453B;color:#fff;border-color:#D1453B}.high{color:#E5534B;border-color:#E5534B}.medium{color:#C9A227;border-color:#C9A227}.low{color:#4FA3C7;border-color:#4FA3C7}.info{color:var(--dim)}
a{color:var(--acc)}""")
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>tauri-audit report</title><style>%s</style></head><body><main><h1>tauri-audit</h1><div class="dim mono">%s &middot; v%s</div>'
            '<div class="head"><div class="grade">%s</div><div><div class="mono">%d / 100</div><div>%s</div></div></div>%s%s</main></body></html>\n'
            ) % (css, e(str(a.root)), __version__, gr, sc, chips,
                 ('<p class="dim">%d known finding(s) hidden by baseline.</p>' % suppressed) if suppressed else "", "".join(parts))


def render_sarif(a: Auditor, findings: List[Finding], paths: List[dict] = (), suppressed: int = 0) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": t}, "helpUri": ref,
              "defaultConfiguration": {"level": level[sev]}} for rid, (sev, t, ref) in sorted(RULES.items())]
    results = [{
        "ruleId": f.rule, "level": level[f.severity],
        "message": {"text": f.message + ((" Fix: " + f.fix) if f.fix else "")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace("\\", "/")}}}],
        "properties": {"severity": f.severity, "pointer": f.pointer},
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "tauri-audit", "version": __version__,
                                      "informationUri": "https://github.com/Wooinxlkz/Tauri-audit-plugin", "rules": rules}},
                  "results": results}],
    }, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tauri_audit", description="Security auditor for Tauri apps (read-only).")
    ap.add_argument("path", nargs="?", default=".", help="project dir, tauri.conf.json, or a capability file (default: .)")
    ap.add_argument("--format", choices=["text", "json", "markdown", "sarif", "html"], default="text")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high", help="exit 1 at/above this severity (default: high)")
    ap.add_argument("--ignore", action="append", default=[], metavar="RULE", help="rule id to skip (repeatable)")
    ap.add_argument("--no-frontend-scan", action="store_true", help="skip the unused-plugin check")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--output", "-o", help="write the report to a file")
    ap.add_argument("--badge", metavar="FILE.svg", help="write a grade badge SVG")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--baseline", metavar="FILE", help="hide findings already recorded in this baseline; only new ones count")
    grp.add_argument("--write-baseline", metavar="FILE", help="record current findings as the baseline and exit 0")
    ap.add_argument("--list-rules", action="store_true", help="print all rule ids and exit")
    ap.add_argument("--version", action="version", version="tauri-audit " + __version__)
    args = ap.parse_args(argv)

    if args.list_rules:
        for rid, (sev, title, _) in sorted(RULES.items()):
            print("%-34s %-9s %s" % (rid, sev, title))
        return 0

    target = Path(args.path)
    if not target.exists():
        print("error: path not found: %s" % target, file=sys.stderr)
        return 2
    ignore = set(args.ignore)
    cfg_file = (target if target.is_dir() else target.parent) / ".tauri-audit.json"
    if cfg_file.is_file():
        try:
            ignore |= {str(x) for x in lst(d(load_file(cfg_file)).get("ignore"))}
        except ParseError as e:
            print("warning: could not read %s: %s" % (cfg_file, e), file=sys.stderr)
    unknown = sorted(r for r in ignore if r not in RULES)
    if unknown:
        print("warning: unknown rule id(s) ignored: %s" % ", ".join(unknown), file=sys.stderr)

    a = Auditor(target, ignore, frontend_scan=not args.no_frontend_scan)
    a.run(target)
    if not a.projects and not a.findings:
        print("error: no Tauri config (tauri.conf.json / Tauri.toml) found under %s" % target, file=sys.stderr)
        return 2
    findings = a.sorted_findings()

    if args.write_baseline:
        Path(args.write_baseline).write_text(json.dumps(
            {"version": 1, "tool": "tauri-audit", "fingerprints": sorted(fingerprint(f) for f in findings)}, indent=2) + "\n",
            encoding="utf-8")
        print("baseline written: %d finding(s) -> %s" % (len(findings), args.write_baseline))
        return 0
    suppressed = 0
    if args.baseline:
        try:
            known = set(d(json.loads(Path(args.baseline).read_text(encoding="utf-8"))).get("fingerprints", []))
        except (OSError, ValueError) as ex:
            print("error: cannot read baseline: %s" % ex, file=sys.stderr)
            return 2
        kept = [f for f in findings if fingerprint(f) not in known]
        suppressed = len(findings) - len(kept)
        findings = kept
    paths = attack_paths(findings)
    if args.badge:
        sc = score_of(findings)
        Path(args.badge).write_text(badge_svg(sc, grade_of(sc)), encoding="utf-8")

    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR") and not args.output
    report = {"text": lambda: render_text(a, findings, color, paths, suppressed),
              "markdown": lambda: render_markdown(a, findings, paths, suppressed),
              "json": lambda: render_json(a, findings, paths, suppressed),
              "sarif": lambda: render_sarif(a, findings, paths, suppressed),
              "html": lambda: render_html(a, findings, paths, suppressed)}[args.format]()
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        try:
            print(report)
        except BrokenPipeError:  # e.g. piped into `head`
            pass

    if args.fail_on != "never" and any(RANK[f.severity] <= RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
