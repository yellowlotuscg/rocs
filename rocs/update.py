"""`rocs update`: the ONLY code path that touches the network.

Downloads STIX2 bundles from the vetted sources in sources.json, records URL,
SHA-256, size and fetch time in manifest.json. Nothing is ever uploaded.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .iocs import parse_stix_bundle

UA = f"rocs/{__version__} (indicator update; read-only)"
MAX_BYTES = 50 * 1024 * 1024


def _fetch(url: str, allowed_hosts: list[str]) -> bytes:
    u = urlsplit(url)
    if u.scheme != "https" or u.hostname not in allowed_hosts:
        raise ValueError(f"Refusing non-allowlisted URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (https + allowlist enforced)
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url} larger than {MAX_BYTES} bytes")
    return data


def parse_mvt_index(text: str) -> list[dict]:
    """Minimal parser for mvt-indicators/indicators.yaml (avoids a PyYAML dependency)."""
    entries, cur = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        if re.match(r"^\s{2}-\s*$", line) or re.match(r"^\s{2}-\s+\S", line):
            if cur:
                entries.append(cur)
            cur = {}
            line = line.replace("-", " ", 1)
        if cur is None:
            continue
        m = re.match(r"^\s+(type|name|owner|repo|branch|path):\s*(.+?)\s*$", line)
        if m:
            cur.setdefault(m.group(1), m.group(2).strip("'\""))
    if cur:
        entries.append(cur)
    out = []
    for e in entries:
        if e.get("type") == "github" and all(k in e for k in ("owner", "repo", "branch", "path")):
            out.append({
                "name": e.get("name", e["path"]),
                "owner": e["owner"],
                "url": f"https://raw.githubusercontent.com/{e['owner']}/{e['repo']}/{e['branch']}/{e['path']}",
            })
    return out


def _safe_name(url: str) -> str:
    p = urlsplit(url).path.strip("/").replace("/", "__")
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", p)


def run_update(sources_path: Path, ioc_dir: Path, log=print) -> int:
    cfg = json.loads(sources_path.read_text(encoding="utf-8"))
    hosts = cfg.get("allowed_hosts", ["raw.githubusercontent.com"])
    owners = set(cfg.get("allowed_owners", []))
    ioc_dir.mkdir(parents=True, exist_ok=True)
    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")

    targets, index_records = [], []
    for idx in cfg.get("indexes", []):
        raw = _fetch(idx["url"], hosts)
        index_records.append({"name": idx["name"], "url": idx["url"],
                              "sha256": hashlib.sha256(raw).hexdigest(), "fetched_at": now})
        for e in parse_mvt_index(raw.decode("utf-8")):
            if owners and e["owner"] not in owners:
                log(f"  skip (owner not allowlisted): {e['url']}")
                continue
            targets.append({"name": e["name"], "url": e["url"]})
    targets += [{"name": f["name"], "url": f["url"]} for f in cfg.get("files", [])]

    seen, files, errors = set(), [], []
    for t in targets:
        if t["url"] in seen:
            continue
        seen.add(t["url"])
        try:
            data = _fetch(t["url"], hosts)
            bundle = json.loads(data.decode("utf-8"))
            n = len(parse_stix_bundle(bundle, t["name"]))
        except Exception as e:  # noqa: BLE001
            errors.append({"url": t["url"], "error": str(e)})
            log(f"  FAILED {t['url']}: {e}")
            continue
        fname = _safe_name(t["url"])
        (ioc_dir / fname).write_bytes(data)
        files.append({"name": t["name"], "url": t["url"], "file": fname, "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "fetched_at": now,
                      "indicator_count": n})
        log(f"  ok {n:6d} indicators  {t['url']}")

    manifest = {"tool": "rocs", "version": __version__, "updated_at": now,
                "sources_file": str(sources_path), "indexes": index_records,
                "files": files, "errors": errors}
    (ioc_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log(f"Wrote {len(files)} bundles to {ioc_dir} ({len(errors)} errors). Manifest: {ioc_dir / 'manifest.json'}")
    return 0 if files and not errors else (1 if files else 3)
