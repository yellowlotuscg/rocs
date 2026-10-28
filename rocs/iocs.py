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
    "url:value": "url",             # full URL; whole-site URLs become domains
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

    def match_url(self, url: str) -> IOC | None:
        """Match a visited URL against URL indicators by host + path prefix, so an
        indicator like https://github.com/<repo> only hits that repo, not all of github.com."""
        urls = self.get("url")
        if not urls:
            return None
        key = url_key(url)
        if not key:
            return None
        host, _, path = key.partition("/")
        segs = [x for x in path.split("/") if x]
        for h in {host, host[4:] if host.startswith("www.") else host}:
            for i in range(len(segs), 0, -1):
                cand = h + "/" + "/".join(segs[:i])
                if cand in urls:
                    return urls[cand]
        return None

    def age_days(self) -> float | None:
        if not self.oldest_fetch:
            return None
        t = _dt.datetime.fromisoformat(self.oldest_fetch)
        return round((_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() / 86400, 1)


# Big shared platforms. A URL indicator on one of these names one page or repo, never the
# whole site, so it is matched by host + path prefix instead of by domain.
SHARED_HOSTS = frozenset("""
github.com githubusercontent.com gitlab.com bitbucket.org sourceforge.net google.com
googleapis.com googleusercontent.com dropbox.com dropboxusercontent.com t.me telegram.me
telegram.org youtube.com youtu.be facebook.com instagram.com twitter.com x.com
mediafire.com mega.nz pastebin.com discord.com discordapp.com amazonaws.com apple.com
icloud.com microsoft.com live.com onedrive.com sharepoint.com yandex.ru bit.ly
""".split())


def is_shared_host(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == h or host.endswith("." + h) for h in SHARED_HOSTS)


def url_key(url: str) -> str | None:
    """'https://WWW.Example.com/a/b/?q' -> 'www.example.com/a/b' (host lowercased, no query)."""
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
        host = (parts.hostname or "").strip(".")
    except ValueError:
        return None
    if not host:
        return None
    return host + "/" + parts.path.strip("/")


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
            if kind == "url":
                key = url_key(val.replace("\\'", "'").strip())
                if not key:
                    continue
                host, _, path = key.partition("/")
                if path and is_shared_host(host):
                    v = key                          # e.g. one GitHub repo, not all of GitHub
                else:
                    kind, v = "domain", host
            else:
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
