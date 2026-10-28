"""Build the plain-language and JSON reports."""
from __future__ import annotations

import datetime as _dt
import json
import platform as _pf

from . import __version__, TOOL_NAME
from .common import Report, SEVERITIES

SCHEMA_VERSION = "1.0"

GENERAL_LIMITS = [
    "This tool only finds KNOWN indicators (names, domains, hashes, package ids published by Amnesty Tech, "
    "MVT and Echap). New, custom or unpublished spyware will not match.",
    "Advanced spyware (e.g. Pegasus, Predator) mostly targets phones and often leaves few traces on a "
    "running system; a clean result here does not rule it out.",
    "It runs without admin rights, so anything readable only by root/SYSTEM or protected by the OS "
    "privacy controls was not inspected (listed below).",
    "Something running with higher privileges than this scan can hide from it.",
    "Heuristic findings (medium/low) are leads for a human to review, not proof of infection.",
]

HELP = [
    "Amnesty Tech Security Lab (civil society, journalists, human rights defenders): https://securitylab.amnesty.org/get-help/",
    "Access Now Digital Security Helpline: https://www.accessnow.org/help/",
    "Coalition Against Stalkerware (stalkerware / tech-enabled abuse): https://stopstalkerware.org/",
    "US National Domestic Violence Hotline: 1-800-799-7233 (thehotline.org)",
]

VERDICT_TEXT = {
    "indicators_found": "Known spyware/stalkerware indicators were found. Treat this device as possibly "
                        "compromised. Do not wipe or delete anything yet: preserve evidence and get expert help.",
    "review_needed": "No known indicators matched, but there are items a human should review.",
    "no_known_indicators": "No known indicators matched in the areas that were checked. This is NOT proof "
                           "the device is clean; see 'What I could not check'.",
    "scan_incomplete": "The scan could not run properly (see problems). No conclusion can be drawn.",
}


def build(rep: Report, ioc_info: dict, problems: list[str]) -> dict:
    counts = {s: sum(1 for f in rep.findings if f.severity == s) for s in SEVERITIES}
    if not rep.checked:
        verdict = "scan_incomplete"
    elif counts["high"]:
        verdict = "indicators_found"
    elif counts["medium"] or counts["low"]:
        verdict = "review_needed"
    else:
        verdict = "no_known_indicators"
    if ioc_info.get("total", 0) == 0:
        verdict = "scan_incomplete"
        problems = problems + ["No indicators were loaded, so nothing could be matched."]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    must_tell = [VERDICT_TEXT[verdict]]
    if verdict != "indicators_found":
        must_tell.append("A clean or partial result is not proof the device is clean.")
    if rep.not_checked:
        must_tell.append(f"{len(rep.not_checked)} area(s) could not be checked: "
                         + "; ".join(n["area"] for n in rep.not_checked))
    age = ioc_info.get("age_days")
    if age is None or age > 30:
        must_tell.append(f"Indicator data is {'of unknown age' if age is None else f'{age:.0f} days old'}; "
                         "run `rocs update` for current indicators.")
    if any(f.category.startswith("android") and f.severity == "high" for f in rep.findings):
        must_tell.append("Stalkerware safety: removing it can alert whoever installed it. Plan with a "
                         "domestic-violence advocate or help line before acting.")
    return {
        "tool": TOOL_NAME, "version": __version__, "schema_version": SCHEMA_VERSION,
        "generated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scanner_host": {"os": _pf.system(), "release": _pf.release()},
        "target_platform": rep.platform,
        "mode": {"read_only": True, "network_during_scan": False, "admin": False,
                 "samples_uploaded": False},
        "verdict": verdict, "verdict_text": VERDICT_TEXT[verdict],
        "counts": counts,
        "findings": [f.to_dict() for f in sorted(rep.findings, key=lambda f: order[f.severity])],
        "checked": rep.checked,
        "not_checked": rep.not_checked,
        "problems": problems,
        "indicators": ioc_info,
        "limitations": GENERAL_LIMITS,
        "get_help": HELP,
        "must_tell_human": must_tell,
    }


def to_text(d: dict) -> str:
    L = []
    w = L.append
    w(f"ROCS REPORT ({d['target_platform']})  -  {d['generated_at']}")
    w("=" * 72)
    w("Read-only scan. No network used during the scan. Nothing was changed, deleted or uploaded.")
    w("")
    w(f"RESULT: {d['verdict_text']}")
    c = d["counts"]
    w(f"Findings: {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    w("")
    labels = {"high": "HIGH  - matches a published spyware/stalkerware indicator",
              "medium": "MEDIUM - suspicious, needs a human to review",
              "low": "LOW   - worth a look", "info": "INFO  - for context"}
    for sev in ("high", "medium", "low", "info"):
        fs = [f for f in d["findings"] if f["severity"] == sev]
        if not fs:
            continue
        w(labels[sev])
        w("-" * 72)
        for i, f in enumerate(fs, 1):
            w(f"{i}. {f['title']}")
            w(f"   {f['detail']}")
            if f.get("indicator"):
                ind = f["indicator"]
                w(f"   Indicator: {ind['kind']} '{ind['value']}' ({ind['malware']}; source: {ind['source']})")
            if f.get("what_to_do"):
                w(f"   What to do: {f['what_to_do']}")
        w("")
    w("WHAT I CHECKED")
    w("-" * 72)
    for ck in d["checked"]:
        extra = f" ({ck['items']} items)" if ck.get("items") is not None else ""
        note = f" - {ck['note']}" if ck.get("note") else ""
        w(f"  [x] {ck['area']}{extra}{note}")
    w("")
    w("WHAT I COULD NOT CHECK")
    w("-" * 72)
    for n in d["not_checked"]:
        w(f"  [ ] {n['area']}: {n['reason']}")
    if not d["not_checked"]:
        w("  (nothing specific recorded; the general limits below still apply)")
    w("")
    if d["problems"]:
        w("PROBLEMS")
        w("-" * 72)
        for p in d["problems"]:
            w(f"  ! {p}")
        w("")
    w("LIMITS OF THIS TOOL")
    w("-" * 72)
    for l in d["limitations"]:
        w(f"  - {l}")
    w("")
    ind = d["indicators"]
    fetched = ind.get("oldest_fetch")
    if fetched:
        fetched = _dt.datetime.fromisoformat(fetched).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    w(f"Indicators: {ind.get('total', 0)} from {len(ind.get('sources', []))} source files, "
      f"downloaded {fetched or 'unknown'} (age {ind.get('age_days')} days).")
    w("")
    w("If you think you are being targeted or monitored, get help (from a device the other person can't access):")
    for h in d["get_help"]:
        w(f"  - {h}")
    return "\n".join(L) + "\n"


def dumps_json(d: dict) -> str:
    return json.dumps(d, indent=2, ensure_ascii=False) + "\n"
