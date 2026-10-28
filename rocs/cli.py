"""Command line entry point.

  rocs update      [--ioc-dir DIR] [--sources sources.json]     (network: downloads indicators)
  rocs verify-iocs [--ioc-dir DIR]                               (offline checksum check)
  rocs scan --out PATH [--json] [--platform auto|linux|macos|windows|android] ...  (offline)
"""
from __future__ import annotations

import argparse
import contextlib
import os
import platform
import socket
import sys
from pathlib import Path

from . import __version__
from .common import Env
from .iocs import load_ioc_dir
from . import report as _report

PKG_DIR = Path(__file__).resolve().parent
EXIT_OK, EXIT_REVIEW, EXIT_FOUND, EXIT_ERROR = 0, 10, 20, 3


def default_ioc_dir() -> Path:
    env = os.environ.get("ROCS_IOC_DIR")
    return Path(env).expanduser() if env else Path.home() / ".rocs" / "iocs"


class NetworkBlocked(RuntimeError):
    pass


@contextlib.contextmanager
def no_network():
    """Belt and braces: make any socket use inside the scan raise immediately."""
    def _blocked(*a, **k):
        raise NetworkBlocked("network access is disabled during scans")
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)
    socket.socket.connect = _blocked          # type: ignore[assignment]
    socket.socket.connect_ex = _blocked       # type: ignore[assignment]
    socket.create_connection = _blocked       # type: ignore[assignment]
    socket.getaddrinfo = _blocked             # type: ignore[assignment]
    try:
        yield
    finally:
        (socket.socket.connect, socket.socket.connect_ex, socket.create_connection,
         socket.getaddrinfo) = saved


def detect_platform() -> str:
    s = platform.system().lower()
    return {"darwin": "macos", "windows": "windows", "linux": "linux"}.get(s, s)


def run_scan(args, env: Env | None = None) -> tuple[int, dict]:
    out = Path(args.out) if args.out != "-" else None
    if out is not None:
        if out.exists() and not args.force:
            print(f"Refusing to overwrite {out} (use --force).", file=sys.stderr)
            return EXIT_ERROR, {}
        if not out.parent.exists():
            print(f"Output folder {out.parent} does not exist.", file=sys.stderr)
            return EXIT_ERROR, {}
    plat = detect_platform() if args.platform == "auto" else args.platform
    if plat == "ios":
        print("iOS is not scanned by rocs. Use MVT on an encrypted backup; see README.", file=sys.stderr)
        return EXIT_ERROR, {}
    with no_network():
        iocs = load_ioc_dir(Path(args.ioc_dir).expanduser())
        env = env or Env()
        if plat == "linux":
            from .collectors import linux as mod
            rep = mod.collect(env, iocs)
        elif plat == "macos":
            from .collectors import macos as mod
            rep = mod.collect(env, iocs)
        elif plat == "windows":
            from .collectors import windows as mod
            rep = mod.collect(env, iocs)
        elif plat == "android":
            from .collectors import android as mod
            rep = mod.collect(env, iocs, args.android_serial, args.android_hash)
        else:
            print(f"Unsupported platform: {plat}", file=sys.stderr)
            return EXIT_ERROR, {}
        ioc_info = {"total": sum(iocs.counts().values()), "by_kind": iocs.counts(),
                    "sources": iocs.sources, "oldest_fetch": iocs.oldest_fetch,
                    "age_days": iocs.age_days()}
        data = _report.build(rep, ioc_info, iocs.problems)
    text = _report.dumps_json(data) if args.json else _report.to_text(data)
    if out is None:
        sys.stdout.write(text)
    else:
        # The only file a scan writes. 'x' mode = never clobber unless --force.
        with open(out, "w" if args.force else "x", encoding="utf-8") as f:
            f.write(text)
        print(f"Report written to {out}", file=sys.stderr)
        print(data["verdict_text"], file=sys.stderr)
    code = {"indicators_found": EXIT_FOUND, "review_needed": EXIT_REVIEW,
            "no_known_indicators": EXIT_OK}.get(data["verdict"], EXIT_ERROR)
    return code, data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rocs", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"rocs {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    u = sub.add_parser("update", help="download indicators (the only networked command)")
    u.add_argument("--ioc-dir", default=str(default_ioc_dir()))
    u.add_argument("--sources", default=str(PKG_DIR.parent / "sources.json"))

    v = sub.add_parser("verify-iocs", help="verify indicator checksums against the manifest (offline)")
    v.add_argument("--ioc-dir", default=str(default_ioc_dir()))

    s = sub.add_parser("scan", help="offline, read-only scan; writes only the report")
    s.add_argument("--out", required=True, help="report path ('-' for stdout). Never overwritten without --force")
    s.add_argument("--json", action="store_true", help="write machine-readable JSON (see CONTRACT.md)")
    s.add_argument("--platform", default="auto", choices=["auto", "linux", "macos", "windows", "android", "ios"])
    s.add_argument("--ioc-dir", default=str(default_ioc_dir()))
    s.add_argument("--android-serial")
    s.add_argument("--android-hash", action="store_true", help="also SHA-256 user APKs on the phone (slow)")
    s.add_argument("--force", action="store_true", help="allow overwriting an existing report file")

    a = ap.parse_args(argv)
    if a.cmd == "update":
        from .update import run_update
        return run_update(Path(a.sources), Path(a.ioc_dir).expanduser())
    if a.cmd == "verify-iocs":
        iocs = load_ioc_dir(Path(a.ioc_dir).expanduser())
        for p in iocs.problems:
            print("PROBLEM:", p)
        print(f"{len(iocs.sources)} bundles verified, {sum(iocs.counts().values())} indicators: {iocs.counts()}")
        print(f"Oldest download: {iocs.oldest_fetch} (age {iocs.age_days()} days)")
        return EXIT_ERROR if iocs.problems else EXIT_OK
    code, _ = run_scan(a)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
