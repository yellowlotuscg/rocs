"""Windows: processes, services, scheduled tasks, Run keys, browsers. No admin needed."""
from __future__ import annotations

import csv
import io
import json

from ..common import WIN_SERVICES_ARGV, Report, Env, check_command_line, scan_browser_histories
from ..iocs import IOCSet
from .procs import check_processes

RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def _procs(env: Env, rep: Report, iocs: IOCSet) -> None:
    rc, out, _ = env.run(["tasklist", "/fo", "csv", "/nh"])
    if rc != 0:
        rep.skip("Running processes", "tasklist failed")
        return
    procs = [{"pid": r[1], "name": r[0], "exe": None} for r in csv.reader(io.StringIO(out)) if len(r) >= 2]
    check_processes(rep, iocs, procs)
    rep.skip("Process executable paths/hashes", "tasklist gives names only; full paths of other "
             "users' processes need admin")


def _services(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    rc, out, _ = env.run(list(WIN_SERVICES_ARGV))
    if rc != 0:
        rep.skip("Services", "PowerShell Get-CimInstance failed")
        return
    try:
        rows = json.loads(out or "[]")
    except json.JSONDecodeError:
        rep.skip("Services", "could not parse service list")
        return
    rows = rows if isinstance(rows, list) else [rows]
    for r in rows:
        check_command_line(rep, iocs, "service", r.get("Name", ""), r.get("PathName") or "", env, hashed)
    rep.ok("Windows services", len(rows))


def _tasks(env: Env, rep: Report, iocs: IOCSet) -> None:
    rc, out, _ = env.run(["schtasks", "/query", "/fo", "csv", "/v"])
    if rc != 0:
        rep.skip("Scheduled tasks", "schtasks failed")
        return
    n = 0
    for r in csv.DictReader(io.StringIO(out)):
        name, cmd = r.get("TaskName", ""), r.get("Task To Run", "")
        if not name or name == "TaskName":
            continue
        n += 1
        check_command_line(rep, iocs, "scheduled-task", name, cmd)
    rep.ok("Scheduled tasks (visible to this user)", n)
    rep.skip("Scheduled tasks owned by SYSTEM/other users", "some are hidden from non-admin users")


def _run_keys(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    entries = list(env.run_keys) if env.run_keys is not None else []
    if env.run_keys is None:
        try:
            import winreg  # type: ignore
        except ImportError:
            rep.skip("Registry Run keys", "winreg unavailable (not running on Windows)")
            return
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        for hive, path in RUN_KEYS:
            try:
                with winreg.OpenKey(hives[hive], path, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        entries.append({"key": f"{hive}\\{path}", "name": name, "value": str(val)})
                        i += 1
            except OSError:
                continue
    for e in entries:
        check_command_line(rep, iocs, "run-key", f"{e['key']}\\{e['name']}", e["value"], env, hashed)
    rep.ok("Registry Run/RunOnce keys", len(entries))


def _browsers(env: Env, rep: Report, iocs: IOCSet) -> None:
    dbs = []
    for label, base in (("Chrome", "AppData/Local/Google/Chrome/User Data"),
                        ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
                        ("Brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data")):
        b = env.h(base)
        if b.is_dir():
            dbs += [(f"{label} ({h.parent.name})", "chromium", h) for h in sorted(b.glob("*/History"))]
    ff = env.h("AppData/Roaming/Mozilla/Firefox/Profiles")
    if ff.is_dir():
        dbs += [(f"Firefox ({p.parent.name})", "firefox", p) for p in sorted(ff.glob("*/places.sqlite"))]
    scan_browser_histories(rep, iocs, dbs)


def collect(env: Env, iocs: IOCSet) -> Report:
    rep = Report("windows")
    hashed: set = set()
    _procs(env, rep, iocs)
    _services(env, rep, iocs, hashed)
    _tasks(env, rep, iocs)
    _run_keys(env, rep, iocs, hashed)
    _browsers(env, rep, iocs)
    rep.skip("Drivers, WMI subscriptions, Defender/EDR telemetry, event logs",
             "need admin or forensic tooling")
    return rep
