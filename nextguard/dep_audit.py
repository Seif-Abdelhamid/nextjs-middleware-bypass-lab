"""Audit `next` versions against the CVE-2025-29927 affected/fixed ranges.

Ranges are taken verbatim from the official advisory GHSA-f82v-jwr5-mffw
(mirrored on NVD as CVE-2025-29927):

    affected, fixed in:
        >=12.0.0  <12.3.5   -> fixed 12.3.5
        >=13.0.0  <13.5.9   -> fixed 13.5.9
        >=14.0.0  <14.2.25  -> fixed 14.2.25
        >=15.0.0  <15.2.3   -> fixed 15.2.3

    affected, no official patch:
        <12.0.0 (the 11.x line and earlier) -- the advisory offers only the
        header-stripping workaround; upgrade to a supported, patched major.

Anything at or above a fixed version within its major (and below the next major)
is not affected by this CVE.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from . import CVE
from .semver import InvalidVersion, Version, in_range, parse

# (low_inclusive, high_exclusive, fixed_version)
FIXED_RANGES = [
    ("12.0.0", "12.3.5", "12.3.5"),
    ("13.0.0", "13.5.9", "13.5.9"),
    ("14.0.0", "14.2.25", "14.2.25"),
    ("15.0.0", "15.2.3", "15.2.3"),
]
# Below this, affected with no backported patch.
UNPATCHED_BELOW = "12.0.0"

VULNERABLE = "vulnerable"
UNPATCHED = "vulnerable_no_patch"
SAFE = "not_affected"
UNKNOWN = "unknown"


@dataclass
class Finding:
    source: str          # file path
    declared: str        # the version/spec as written in the file
    resolved: str | None # concrete version evaluated, if we could pin one
    status: str          # VULNERABLE / UNPATCHED / SAFE / UNKNOWN
    fixed_in: str | None
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


def classify(version: str) -> tuple[str, str | None, str]:
    """Classify a *concrete* next version. Returns (status, fixed_in, detail)."""
    try:
        v: Version = parse(version)
    except InvalidVersion:
        return (UNKNOWN, None, f"could not parse a concrete version from {version!r}")

    for low, high, fixed in FIXED_RANGES:
        if in_range(v, low, high):
            return (VULNERABLE, fixed, f"{version} is in the affected range >={low} <{high}")
    if v < parse(UNPATCHED_BELOW):
        return (UNPATCHED, None,
                f"{version} predates 12.0.0; affected with no backported patch "
                f"(apply the header-stripping workaround and upgrade)")
    return (SAFE, None, f"{version} is not affected by {CVE}")


def _resolve_spec(spec: str) -> str | None:
    """Best-effort pin of a package.json spec to a concrete version.

    We only trust specs that pin an exact version (`14.2.24`, `=14.2.24`,
    `v14.2.24`). Fuzzy ranges (`^14.0.0`, `~14`, `14.x`, `latest`) cannot be
    resolved without a lockfile, so we return None and let the caller mark it
    UNKNOWN (and tell the user to check the lockfile).
    """
    s = spec.strip()
    if re.fullmatch(r"[=vV]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", s):
        return s
    return None


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_package_json(path: str | Path) -> list[Finding]:
    path = Path(path)
    data = _read_json(path)
    findings: list[Finding] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        spec = (data.get(section) or {}).get("next")
        if spec is None:
            continue
        resolved = _resolve_spec(spec)
        if resolved is None:
            findings.append(Finding(str(path), spec, None, UNKNOWN, None,
                                    f"'{section}.next' = {spec!r} is a range, not a pin; "
                                    f"resolve it from the lockfile"))
            continue
        status, fixed, detail = classify(resolved)
        findings.append(Finding(str(path), spec, str(parse(resolved)), status, fixed, detail))
    return findings


def audit_package_lock(path: str | Path) -> list[Finding]:
    """npm v2/v3 lockfile: find every pinned `next` version."""
    path = Path(path)
    data = _read_json(path)
    seen: dict[str, Finding] = {}

    def add(version: str):
        try:
            resolved = str(parse(version))
        except InvalidVersion:
            return
        if resolved in seen:
            return
        status, fixed, detail = classify(resolved)
        seen[resolved] = Finding(str(path), version, resolved, status, fixed, detail)

    # npm v3 "packages": keys like "node_modules/next"
    for pkgkey, meta in (data.get("packages") or {}).items():
        if pkgkey.endswith("node_modules/next") and isinstance(meta, dict) and meta.get("version"):
            add(meta["version"])
    # npm v1/v2 "dependencies": nested { next: { version } }
    def walk(deps: dict):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            if name == "next" and meta.get("version"):
                add(meta["version"])
            walk(meta.get("dependencies") or {})
    walk(data.get("dependencies") or {})
    return list(seen.values())


def audit_yarn_lock(path: str | Path) -> list[Finding]:
    """Classic yarn.lock (v1). Find entries whose key names the `next` package."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    seen: set[str] = set()
    blocks = re.split(r"\n(?=\S)", text)
    for block in blocks:
        head = block.splitlines()[0] if block.strip() else ""
        # A next@... entry header, e.g.  "next@14.2.24", next@^14.0.0:
        if not re.match(r'^"?next@', head):
            continue
        m = re.search(r'^\s*version:?\s+"?([0-9][^"\s]*)"?', block, re.MULTILINE)
        if not m:
            continue
        version = m.group(1)
        try:
            resolved = str(parse(version))
        except InvalidVersion:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        status, fixed, detail = classify(resolved)
        findings.append(Finding(str(path), version, resolved, status, fixed, detail))
    return findings


_DISPATCH = {
    "package.json": audit_package_json,
    "package-lock.json": audit_package_lock,
    "yarn.lock": audit_yarn_lock,
}


def audit_path(path: str | Path) -> list[Finding]:
    """Audit a single file, dispatching on its name."""
    path = Path(path)
    fn = _DISPATCH.get(path.name)
    if fn is None:
        raise ValueError(f"unsupported file: {path.name} (expected one of {sorted(_DISPATCH)})")
    return fn(path)


def audit_tree(root: str | Path) -> list[Finding]:
    """Walk a directory and audit every supported manifest/lockfile, skipping node_modules."""
    root = Path(root)
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        if "node_modules" in p.parts:
            continue
        if p.name in _DISPATCH:
            try:
                findings.extend(audit_path(p))
            except (ValueError, json.JSONDecodeError):
                continue
    return findings


def worst_status(findings: list[Finding]) -> str:
    order = [VULNERABLE, UNPATCHED, UNKNOWN, SAFE]
    for s in order:
        if any(f.status == s for f in findings):
            return s
    return SAFE
