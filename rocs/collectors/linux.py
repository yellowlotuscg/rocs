"""Linux: processes (/proc), systemd units, cron, XDG autostart, ld.so.preload, browsers."""
from __future__ import annotations

import configparser
import os
from pathlib import Path

from ..common import Report, Env, check_command_line, scan_browser_histories
from ..iocs import IOCSet
from .procs import check_processes


def _procs(env: Env, rep: Report) -> list[dict]:
    proc = env.proc or env.p("/proc")
    out, denied = [], 0
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError as e:
        rep.skip("Running processes", f"cannot list {proc}: {e}")
        return []
    for pid in pids:
        d = Path(proc) / pid
        try:
            name = (d / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        exe = None
        try:
            exe = os.readlink(d / "exe")
        except OSError:
            denied += 1
            ef = d / "exe_path"          # fixture convenience
            if ef.is_file():
                exe = ef.read_text(encoding="utf-8").strip()
        out.append({"pid": int(pid), "name": name, "exe": exe})
    if denied:
        rep.skip("Executable paths/hashes of other users' processes",
                 f"{denied} processes belong to other users or the kernel; without admin their "
                 "executable path cannot be read (names were still checked)")
    return out


def _deleted_exes(rep: Report, procs: list[dict]) -> None:
    for p in procs:
        if p.get("exe") and p["exe"].endswith(" (deleted)"):
            rep.add("medium", "process", f"Process running from a deleted file: {p['name']}",
                    f"PID {p['pid']} runs {p['exe']}. This often happens harmlessly after a software "
                    "update, but malware also deletes its file after starting.",
                    {"pid": p["pid"], "exe": p["exe"]}, None,
                    "If a reboot doesn't clear it, investigate.")


def _systemd(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    dirs = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
            "/run/systemd/system"]
    paths = [env.p(d) for d in dirs] + [env.h(".config/systemd/user"), env.p("/etc/systemd/user")]
    n = 0
    for d in paths:
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if f.suffix not in (".service", ".timer", ".socket") or not f.is_file():
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            n += 1
            for line in text.splitlines():
                line = line.strip()
                if line.split("=", 1)[0] in ("ExecStart", "ExecStartPre", "ExecStartPost"):
                    cmd = line.split("=", 1)[1].lstrip("-@+!:")
                    check_command_line(rep, iocs, "systemd", f.name, cmd, env, hashed)
    rep.ok("systemd units (system + user)", n)


def _cron(env: Env, rep: Report, iocs: IOCSet) -> None:
    n = 0
    tables = [env.p("/etc/crontab"), env.p("/etc/anacrontab")]
    d = env.p("/etc/cron.d")
    if d.is_dir():
        tables += [f for f in sorted(d.iterdir()) if f.is_file()]
    for f in tables:
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for ln in lines:
            if ln.strip() and not ln.lstrip().startswith("#") and "=" not in ln.split()[0]:
                n += 1
                check_command_line(rep, iocs, "cron", f.name, ln)
    # run-parts folders hold scripts, not crontab lines: check each script's name and path once
    for dname in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        dp = env.p(dname)
        if dp.is_dir():
            for f in sorted(dp.iterdir()):
                if f.is_file() and not f.name.startswith("."):
                    n += 1
                    check_command_line(rep, iocs, "cron", f.name, f"{dname}/{f.name}", env)
    rc, out, _ = env.run(["crontab", "-l"])
    if rc == 0:
        for ln in out.splitlines():
            if ln.strip() and not ln.startswith("#"):
                n += 1
                check_command_line(rep, iocs, "cron", "user crontab", ln)
    rep.ok("cron jobs (system + current user)", n)
    spool = env.p("/var/spool/cron")
    if spool.exists() and not os.access(spool, os.R_OK | os.X_OK):
        rep.skip("Other users' crontabs", "/var/spool/cron is readable only by root")


def _autostart(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    n = 0
    for d in (env.h(".config/autostart"), env.p("/etc/xdg/autostart")):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.desktop")):
            cp = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                cp.read(f, encoding="utf-8")
                cmd = cp.get("Desktop Entry", "Exec", fallback="")
            except (configparser.Error, OSError):
                continue
            n += 1
            check_command_line(rep, iocs, "autostart", f.name, cmd, env, hashed)
    rep.ok("XDG autostart entries", n)


def _preload(env: Env, rep: Report) -> None:
    f = env.p("/etc/ld.so.preload")
    if f.is_file():
        content = f.read_text(errors="replace").strip()
        if content:
            rep.add("medium", "persistence", "/etc/ld.so.preload is in use",
                    "Every program on the system loads these libraries. Rootkits use this; a few "
                    "legitimate tools do too.", {"content": content[:500]}, None,
                    "Find out which package installed it.")
    rep.ok("/etc/ld.so.preload")


def _browsers(env: Env, rep: Report, iocs: IOCSet) -> None:
    dbs = []
    for label, base in (("Chrome", ".config/google-chrome"), ("Chromium", ".config/chromium"),
                        ("Brave", ".config/BraveSoftware/Brave-Browser"),
                        ("Edge", ".config/microsoft-edge")):
        b = env.h(base)
        if b.is_dir():
            dbs += [(f"{label} ({h.parent.name})", "chromium", h) for h in sorted(b.glob("*/History"))]
    for root in (env.h(".mozilla/firefox"), env.h("snap/firefox/common/.mozilla/firefox")):
        if root.is_dir():
            dbs += [(f"Firefox ({p.parent.name})", "firefox", p) for p in sorted(root.glob("*/places.sqlite"))]
    scan_browser_histories(rep, iocs, dbs)


def collect(env: Env, iocs: IOCSet) -> Report:
    rep = Report("linux")
    hashed: set = set()
    procs = _procs(env, rep)
    check_processes(rep, iocs, procs, env, hashed)
    _deleted_exes(rep, procs)
    _systemd(env, rep, iocs, hashed)
    _cron(env, rep, iocs)
    _autostart(env, rep, iocs, hashed)
    _preload(env, rep)
    _browsers(env, rep, iocs)
    rep.skip("Kernel modules and rootkits", "a rootkit can hide from any tool running on the same "
             "system; this needs offline forensics")
    rep.skip("Network connections", "not inspected; a one-time snapshot misses intermittent beacons")
    return rep
