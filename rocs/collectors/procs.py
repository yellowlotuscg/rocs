from __future__ import annotations

from ..common import Report, Env, basename_any, hash_and_match, name_hit_severity
from ..iocs import IOCSet


def check_processes(rep: Report, iocs: IOCSet, procs: list[dict], env: Env | None = None,
                    hashed: set | None = None) -> None:
    """procs: [{"pid":..., "name":..., "exe": optional path}]"""
    names, files = iocs.get("process"), iocs.get("filename")
    for pr in procs:
        cands = {basename_any(pr.get("name") or ""), basename_any(pr.get("exe") or "")} - {""}
        cands |= {c[:-4] for c in cands if c.endswith(".exe")}
        for c in cands:
            hit = names.get(c) or files.get(c)
            if hit:
                sev, why = name_hit_severity(pr.get("exe"))
                rep.add(sev, "process", f"Running process matches a known spyware name: {c}",
                        f"PID {pr.get('pid')} '{pr.get('name')}' ({pr.get('exe') or 'path unknown'}) "
                        f"matches an indicator for {hit.malware}. {why}",
                        {"pid": pr.get("pid"), "name": pr.get("name"), "exe": pr.get("exe")},
                        {"kind": hit.kind, "value": hit.value, "malware": hit.malware, "source": hit.source},
                        "Do not kill or delete it yet. Preserve evidence and get expert help.")
                break
        if env is not None and pr.get("exe") and iocs.get("sha256"):
            hash_and_match(rep, iocs, "process", env.p(pr["exe"]), f"PID {pr.get('pid')}", hashed)
    rep.ok("Running processes", len(procs))
