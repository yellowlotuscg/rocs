"""Shared primitives: findings, coverage, the read-only environment and helpers."""
from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlsplit

from .iocs import IOCSet, sha256_file

SEVERITIES = ("high", "medium", "low", "info")

WIN_SERVICES_ARGV = ("powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-CimInstance Win32_Service | Select-Object Name,PathName,State | ConvertTo-Json -Compress")

# Every external command the scanner may run. Each entry is a prefix the full
# argv must start with. All of them only READ state. Anything else is refused.
READ_ONLY_COMMANDS = [
    ("ps",),
    ("crontab", "-l"),
    ("profiles", "list"),
    ("tasklist",),
    ("schtasks", "/query"),
    WIN_SERVICES_ARGV,        # exact argv only (see is_read_only)
    ("adb", "devices"),
    ("adb", "-s"),            # further validated in _adb_ok
]
_ADB_SHELL_OK = [
    ("pm", "list", "packages"),
    ("dumpsys", "device_policy"),
    ("settings", "get", "secure"),
    ("getprop",),
    ("sha256sum",),
]


class CommandRefused(RuntimeError):
    pass


def _adb_ok(argv: list[str]) -> bool:
    # adb -s SERIAL shell <cmd...>
    if len(argv) < 5 or argv[3] != "shell":
        return False
    rest = tuple(argv[4:])
    if any(c in tok for tok in rest for c in ";|&><`$\n"):
        return False
    return any(rest[: len(p)] == p for p in _ADB_SHELL_OK)


def is_read_only(argv: list[str]) -> bool:
    t = tuple(argv)
    for p in READ_ONLY_COMMANDS:
        if t[: len(p)] == p:
            if p == ("adb", "-s"):
                return _adb_ok(argv)
            if p == WIN_SERVICES_ARGV:
                return t == WIN_SERVICES_ARGV
            return True
    return False


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)
    indicator: dict | None = None
    what_to_do: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    platform: str
    findings: list = field(default_factory=list)
    checked: list = field(default_factory=list)       # [{"area":..., "items": n, "note":...}]
    not_checked: list = field(default_factory=list)   # [{"area":..., "reason":...}]

    def add(self, *a, **kw):
        self.findings.append(Finding(*a, **kw))

    def ok(self, area: str, items: int | None = None, note: str = ""):
        self.checked.append({"area": area, "items": items, "note": note})

    def skip(self, area: str, reason: str):
        self.not_checked.append({"area": area, "reason": reason})


def default_runner(argv: list[str], timeout: int = 120) -> tuple[int, str, str]:
    if not is_read_only(argv):
        raise CommandRefused(f"not on the read-only allowlist: {argv[:4]}")
    exe = shutil.which(argv[0])
    if not exe:
        return 127, "", f"{argv[0]} not found"
    p = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, errors="replace")
    return p.returncode, p.stdout, p.stderr


@dataclass
class Env:
    """Where to look. `root` lets tests point the scanner at a fixture tree."""
    root: Path = Path("/")
    home: Path = field(default_factory=Path.home)
    runner: object = default_runner
    proc: Path | None = None   # /proc for Linux; None => root/proc
    run_keys: list | None = None  # tests only: injected Windows Run-key entries

    def p(self, path: str | Path) -> Path:
        path = Path(path)
        if self.root == Path("/"):
            return path
        rel = os.path.splitdrive(str(path))[1].lstrip("/\\")
        return self.root / rel

    def h(self, rel: str) -> Path:
        """Path under the user's home, mapped into root."""
        return self.p(self.home) / rel

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        if not is_read_only(argv):
            raise CommandRefused(f"not on the read-only allowlist: {argv[:4]}")
        return self.runner(argv)


# ----------------------------------------------------------------- helpers

_COMMON_DOTDIRS = r"(?!(?:local|config|cargo|rustup|nvm|pyenv|rbenv|sdkman|deno|bun|volta|asdf|vscode|cursor|npm|dotnet)/)"
_SUSP_UNIX = re.compile(r"(^|[\s\"'=:])(/tmp/|/var/tmp/|/dev/shm/|/Users/Shared/|/private/tmp/)"
                        r"|(^|[\s\"'=:])/\S*?/\." + _COMMON_DOTDIRS + r"[^/\s]+/")
_SUSP_WIN = re.compile(r"(\\Users\\Public\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|%TEMP%|\\ProgramData\\[^\\]+\.exe)", re.I)


class _Susp:
    @staticmethod
    def search(text: str):
        return _SUSP_UNIX.search(text) or _SUSP_WIN.search(text)


SUSPICIOUS_DIRS = _Susp()
_HOST_RE = re.compile(r"(?:https?://|\b)((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)


SYSTEM_PREFIXES = ("/system/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                   "/usr/lib/", "/lib/", "c:\\windows\\system32\\", "c:\\windows\\syswow64\\")


def name_hit_severity(path: str | None) -> tuple[str, str]:
    """Process/file NAME indicators are weak on their own (most are iOS daemon names that
    mimic Apple ones). Grade by where the binary lives."""
    if not path:
        return "medium", "Only the name matched; the program's location could not be read, so confirm it by hand."
    if path.lower().startswith(SYSTEM_PREFIXES):
        return "low", ("The name matches, but the program lives in an operating-system folder, so this is "
                       "most likely a harmless name collision. Confirm it is the vendor's signed binary.")
    return "high", "The name matches and the program is outside the operating-system folders."


def basename_any(p: str) -> str:
    return re.split(r"[\\/]", p.strip().strip('"'))[-1].lower()


def first_path(cmd: str) -> str:
    cmd = (cmd or "").strip()
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    return cmd.split()[0] if cmd else ""


def check_command_line(rep: Report, iocs: IOCSet, area: str, name: str, cmd: str,
                       env: Env | None = None, hashed: set | None = None) -> None:
    """Shared logic for any persistence entry: IOC names, domains, hashes, odd paths."""
    exe = first_path(cmd)
    procs, files = iocs.get("process"), iocs.get("filename")
    for cand in {basename_any(exe), basename_any(name)} - {""}:
        hit = procs.get(cand) or files.get(cand)
        if hit:
            sev, why = name_hit_severity(exe if exe.startswith(("/", "\\")) or ":" in exe[:3] else None)
            rep.add(sev, area, f"{area} entry matches known spyware name: {cand}",
                    f"'{name}' runs '{cmd}'. The name '{cand}' is listed as an indicator for {hit.malware}. {why}",
                    {"entry": name, "command": cmd},
                    {"kind": hit.kind, "value": hit.value, "malware": hit.malware, "source": hit.source},
                    "Do not delete it yet. Preserve evidence and get expert help (see report footer).")
    for host in set(m.lower() for m in _HOST_RE.findall(cmd or "")):
        hit = iocs.match_domain(host)
        if hit:
            rep.add("high", area, f"{area} entry contacts a known spyware domain: {host}",
                    f"'{name}' references {host}, listed for {hit.malware}.",
                    {"entry": name, "command": cmd},
                    {"kind": "domain", "value": hit.value, "malware": hit.malware, "source": hit.source},
                    "Do not delete it yet. Preserve evidence and get expert help.")
    if SUSPICIOUS_DIRS.search(" " + (cmd or "")):
        rep.add("medium", area, f"{area} entry runs from a temporary, shared or hidden folder",
                f"'{name}' runs '{cmd}'. Legitimate software rarely auto-starts from these locations, "
                "but some does. This is a lead to review, not proof of infection.",
                {"entry": name, "command": cmd}, None,
                "Check who installed it and whether you recognise it.")
    if env is not None and exe and iocs.get("sha256"):
        hash_and_match(rep, iocs, area, env.p(exe) if os.path.isabs(exe) else None, name, hashed)


def hash_and_match(rep: Report, iocs: IOCSet, area: str, path: Path | None, label: str,
                   hashed: set | None = None, max_bytes: int = 200 * 1024 * 1024) -> None:
    if path is None:
        return
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return
        key = str(path)
        if hashed is not None:
            if key in hashed:
                return
            hashed.add(key)
        digest = sha256_file(path)
    except (OSError, PermissionError):
        return
    hit = iocs.get("sha256").get(digest)
    if hit:
        rep.add("high", area, f"File hash matches known spyware: {path.name}",
                f"{path} (from {label}) has SHA-256 {digest}, listed for {hit.malware}.",
                {"path": str(path), "sha256": digest},
                {"kind": "sha256", "value": digest, "malware": hit.malware, "source": hit.source},
                "Do not delete it. Preserve evidence and get expert help.")


BROWSER_QUERIES = {
    "chromium": "SELECT url, visit_count FROM urls",
    "firefox": "SELECT url, visit_count FROM moz_places",
    "safari": "SELECT url, visit_count FROM history_items",
}


def read_history(db: Path, kind: str) -> list[tuple[str, int]]:
    """Open a browser history DB strictly read-only (immutable: no locks, no WAL writes)."""
    uri = Path(db).resolve().as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True, timeout=1)
    try:
        return [(r[0] or "", int(r[1] or 0)) for r in con.execute(BROWSER_QUERIES[kind])]
    finally:
        con.close()


def scan_browser_histories(rep: Report, iocs: IOCSet, dbs: list[tuple[str, str, Path]]) -> None:
    """dbs: [(label, kind, path)]"""
    found_any = False
    for label, kind, db in dbs:
        if not db.exists():
            continue
        found_any = True
        try:
            rows = read_history(db, kind)
        except (sqlite3.Error, OSError, PermissionError) as e:
            rep.skip(f"Browser history: {label}", f"could not open {db} read-only ({e}). "
                     "On macOS this usually needs Full Disk Access for the terminal; on Windows "
                     "close the browser and retry.")
            continue
        hits: dict[str, list] = {}
        for url, visits in rows:
            host = urlsplit(url).hostname
            if not host:
                continue
            ioc = iocs.match_domain(host)
            if ioc:
                hits.setdefault(host, [ioc, 0, url])[1] += max(visits, 1)
        for host, (ioc, n, sample) in hits.items():
            rep.add("high", "browser-history", f"{label} visited a known spyware domain: {host}",
                    f"{n} visit(s) to {host}, listed for {ioc.malware}. A visit can mean an "
                    "infection link was opened, or only that the site was looked up; context matters.",
                    {"browser": label, "host": host, "visits": n, "example_url": sample[:200]},
                    {"kind": "domain", "value": ioc.value, "malware": ioc.malware, "source": ioc.source},
                    "Note when you visited it and get expert help before changing anything.")
        rep.ok(f"Browser history: {label}", len(rows))
    if not found_any:
        rep.skip("Browser history", "no supported browser history databases were found for this user")


def hostname_note() -> str:
    try:
        import socket as _s
        return _s.gethostname()
    except Exception:  # noqa: BLE001
        return "unknown"
