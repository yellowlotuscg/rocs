"""Load and normalise STIX2 indicator bundles. No network access in this module."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# STIX object path -> our indicator kind
KIND_MAP = {
    "domain-name:value": "domain",
    "url:value": "domain",          # we keep only the host part
    "process:name": "process",
    "file:name": "filename",
    "file:hashes.sha256": "sha256",
    "file:hashes.'sha-256'": "sha256",
    "app:id": "android_package",
    "app:cert.sha1": "android_cert_sha1",
    "email-addr:value": "email",
}
_PATTERN_RE = re.compile(r"([a-z0-9\-]+:[a-z0-9_\.\-']+)\s*=\s*'((?:[^'\\]|\\.)*)'", re.I)


@dataclass
class IOC:
    kind: str
    value: str
    malware: str
    source: str


@dataclass
class IOCSet:
    by_kind: dict = field(default_factory=dict)   # kind -> {value: IOC}
    sources: list = field(default_factory=list)   # manifest entries
    problems: list = field(default_factory=list)
    oldest_fetch: str | None = None

    def add(self, ioc: IOC) -> None:
        self.by_kind.setdefault(ioc.kind, {}).setdefault(ioc.value, ioc)

    def get(self, kind: str) -> dict:
        return self.by_kind.get(kind, {})

    def counts(self) -> dict:
        return {k: len(v) for k, v in sorted(self.by_kind.items())}

    def match_domain(self, host: str) -> IOC | None:
        host = (host or "").lower().strip(".")
        doms = self.get("domain")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in doms:
                return doms[cand]
        return None

    def age_days(self) -> float | None:
        if not self.oldest_fetch:
            return None
        t = _dt.datetime.fromisoformat(self.oldest_fetch)
        return round((_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() / 86400, 1)


def _normalise(kind: str, value: str) -> str | None:
    value = value.replace("\\'", "'").strip()
    if kind == "domain":
        if "://" in value:
            value = urlsplit(value).hostname or ""
        value = value.lower().strip(".")
        if value.startswith("*."):
            value = value[2:]
        return value or None
    if kind in ("sha256", "android_cert_sha1"):
        return value.lower()
    if kind in ("process", "filename", "android_package", "email"):
        return value.lower() if kind != "android_package" else value
    return value


def parse_stix_bundle(data: dict, source: str) -> list[IOC]:
    objs = data.get("objects", []) if isinstance(data, dict) else []
    names = {o["id"]: o.get("name", "unknown") for o in objs if o.get("type") == "malware"}
    ind_to_mal = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            ind_to_mal[o.get("source_ref")] = names.get(o.get("target_ref"), "unknown")
    out = []
    for o in objs:
        if o.get("type") != "indicator":
            continue
        mal = ind_to_mal.get(o.get("id"), o.get("name") or "unknown")
        for path, val in _PATTERN_RE.findall(o.get("pattern", "")):
            kind = KIND_MAP.get(path.lower())
            if not kind:
                continue
            v = _normalise(kind, val)
            if v:
                out.append(IOC(kind, v, mal, source))
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_ioc_dir(ioc_dir: Path, verify: bool = True) -> IOCSet:
    """Load every bundle listed in manifest.json, verifying SHA-256 checksums."""
    s = IOCSet()
    manifest_path = ioc_dir / "manifest.json"
    if not manifest_path.is_file():
        s.problems.append(f"No indicator manifest at {manifest_path}. Run `rocs update` first.")
        return s
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fetched = []
    for entry in manifest.get("files", []):
        p = ioc_dir / entry["file"]
        if not p.is_file():
            s.problems.append(f"Missing indicator file {entry['file']}")
            continue
        if verify and sha256_file(p) != entry.get("sha256"):
            s.problems.append(f"Checksum mismatch for {entry['file']} (file changed since download); skipped")
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            s.problems.append(f"Could not parse {entry['file']}: {e}")
            continue
        for ioc in parse_stix_bundle(data, entry.get("name") or entry["file"]):
            s.add(ioc)
        s.sources.append({k: entry.get(k) for k in ("name", "url", "sha256", "fetched_at", "indicator_count")})
        if entry.get("fetched_at"):
            fetched.append(entry["fetched_at"])
    s.oldest_fetch = min(fetched) if fetched else None
    return s
