"""macOS: processes, LaunchAgents/Daemons, login items, config profiles, browsers."""
from __future__ import annotations

import plistlib
import re

from ..common import Report, Env, check_command_line, scan_browser_histories
from ..iocs import IOCSet
from .procs import check_processes


def _procs(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    rc, out, _ = env.run(["ps", "-axo", "pid=,comm="])
    if rc != 0:
        rep.skip("Running processes", "ps failed")
        return
    procs = []
    for ln in out.splitlines():
        parts = ln.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            procs.append({"pid": int(parts[0]), "name": parts[1].rsplit("/", 1)[-1],
                          "exe": parts[1] if parts[1].startswith("/") else None})
    check_processes(rep, iocs, procs, env, hashed)


def _launchd(env: Env, rep: Report, iocs: IOCSet, hashed: set) -> None:
    dirs = [env.h("Library/LaunchAgents"), env.p("/Library/LaunchAgents"),
            env.p("/Library/LaunchDaemons")]
    n = 0
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.plist")):
            try:
                with open(f, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception as e:  # noqa: BLE001
                rep.skip(f"launchd item {f.name}", f"unreadable plist ({e.__class__.__name__})")
                continue
            n += 1
            args = pl.get("ProgramArguments") or []
            prog = pl.get("Program") or (args[0] if args else "")
            cmd = " ".join(f'"{a}"' if " " in str(a) else str(a) for a in ([prog] + list(args[1:])))
            check_command_line(rep, iocs, "launchd", f"{pl.get('Label', f.stem)} ({f})", cmd, env, hashed)
    rep.ok("LaunchAgents / LaunchDaemons (user + /Library)", n)
    rep.skip("/System/Library launchd items", "Apple-signed and protected by SIP; not inspected")


def _login_items(env: Env, rep: Report, iocs: IOCSet) -> None:
    btm = env.h("Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm")
    if btm.is_file():
        try:
            raw = btm.read_bytes()
            paths = set(re.findall(rb"(/(?:Applications|Users|Library|private|tmp)[\x20-\x7e]{3,200}?\.app)", raw))
            for p in paths:
                check_command_line(rep, iocs, "login-item", p.decode(), p.decode())
            rep.ok("Login items (legacy backgrounditems.btm)", len(paths))
        except OSError as e:
            rep.skip("Login items", f"could not read {btm}: {e}")
    rep.skip("Login items and background items on macOS 13+",
             "stored in a root-only database; review System Settings > General > Login Items, "
             "or run `sudo sfltool dumpbtm` yourself (read-only) and check unfamiliar entries")


def _profiles(env: Env, rep: Report) -> None:
    rc, out, _ = env.run(["profiles", "list"])
    if rc != 0:
        rep.skip("Configuration profiles", "`profiles list` failed")
        return
    ids = re.findall(r"profileIdentifier:\s*(\S+)", out)
    if ids:
        rep.add("low", "config-profile", f"{len(ids)} configuration profile(s) installed",
                "Profiles can install root certificates, VPNs, proxies or device management. That is "
                "normal on a work-managed Mac and suspicious on a personal one you didn't set up.",
                {"profiles": ids}, None,
                "Open System Settings > Privacy & Security > Profiles and confirm you recognise each.")
    rep.ok("Configuration profiles (user-visible)", len(ids))


def _browsers(env: Env, rep: Report, iocs: IOCSet) -> None:
    dbs = [("Safari", "safari", env.h("Library/Safari/History.db"))]
    for label, base in (("Chrome", "Library/Application Support/Google/Chrome"),
                        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
                        ("Edge", "Library/Application Support/Microsoft Edge"),
                        ("Arc", "Library/Application Support/Arc/User Data")):
        b = env.h(base)
        if b.is_dir():
            dbs += [(f"{label} ({h.parent.name})", "chromium", h) for h in sorted(b.glob("*/History"))]
    ff = env.h("Library/Application Support/Firefox/Profiles")
    if ff.is_dir():
        dbs += [(f"Firefox ({p.parent.name})", "firefox", p) for p in sorted(ff.glob("*/places.sqlite"))]
    scan_browser_histories(rep, iocs, dbs)


def collect(env: Env, iocs: IOCSet) -> Report:
    rep = Report("macos")
    hashed: set = set()
    _procs(env, rep, iocs, hashed)
    _launchd(env, rep, iocs, hashed)
    _login_items(env, rep, iocs)
    _profiles(env, rep)
    _browsers(env, rep, iocs)
    rep.skip("Kernel/system extensions, TCC privacy grants, unified logs",
             "need admin or Full Disk Access; for targeted-spyware concerns use MVT or a professional")
    rep.skip("iPhone / iPad", "not scanned here; use MVT on an encrypted iTunes/Finder backup (see README)")
    return rep
