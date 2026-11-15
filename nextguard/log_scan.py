"""Detect CVE-2025-29927 exploitation attempts in web/proxy logs.

The signal is simple and high-fidelity: a *client* request that carries the
internal header `x-middleware-subrequest`. Legitimate external clients never
send it; Next.js uses it only for its own in-process subrequests. The patched
runtime additionally pairs it with a secret `x-middleware-subrequest-id`, so an
external request that has the first header but no valid id is the exploit shape.

Because servers don't log request headers by default, this scanner reads the two
formats you actually get when you *do* capture them:

  * JSON lines (structured access logs / SIEM exports). We search, case-insensitively,
    for any key that looks like the header, nested anywhere.
  * Header dumps: plain `Name: value` lines (e.g. mirrored request headers,
    mod_security audit logs, tcpdump-style captures).

We also flag the classic repeated-token payload shape
(`middleware:middleware:...`, `src/middleware:...`, `pages/_middleware`) as
higher confidence, but the mere presence of the header is already a finding.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

HEADER = "x-middleware-subrequest"
HEADER_ID = "x-middleware-subrequest-id"

# Known middleware "names" that the exploit repeats; used only to raise confidence.
_KNOWN_TOKENS = {"middleware", "src/middleware", "pages/_middleware", "src/pages/_middleware"}


@dataclass
class Detection:
    line_no: int
    raw: str
    header_value: str
    payload_tokens: list
    repeated_known_token: bool
    has_valid_id_pairing: bool
    confidence: str      # "high" | "medium"
    reason: str

    def as_dict(self) -> dict:
        return asdict(self)


def _analyze_value(value: str, has_id: bool) -> Detection | None:
    if value is None:
        return None
    tokens = [t for t in value.split(":") if t != ""]
    lowered = [t.lower() for t in tokens]
    repeated_known = any(
        lowered.count(k) >= 1 and len(lowered) >= 2 and len(set(lowered)) == 1 and lowered[0] == k
        for k in _KNOWN_TOKENS
    )
    # confidence: a repeated known-token payload, or >=5 repeats (the depth trigger),
    # is high; a bare header is still reported at medium.
    depth_trigger = len(tokens) >= 5 and len(set(lowered)) == 1
    if repeated_known or depth_trigger:
        confidence = "high"
        reason = "repeated middleware-name payload matching the CVE-2025-29927 bypass shape"
    else:
        confidence = "medium"
        reason = "external request carries the internal x-middleware-subrequest header"
    return Detection(
        line_no=-1, raw="", header_value=value, payload_tokens=tokens,
        repeated_known_token=repeated_known or depth_trigger,
        has_valid_id_pairing=has_id, confidence=confidence, reason=reason,
    )


def _find_in_obj(obj, header: str):
    """Recursively search a decoded JSON value for a key matching `header`
    (case-insensitive). Returns (value, sibling_has_id) or (None, False)."""
    header = header.lower()
    if isinstance(obj, dict):
        # does this dict directly contain the header?
        lowered = {str(k).lower(): v for k, v in obj.items()}
        if header in lowered:
            has_id = HEADER_ID in lowered and bool(lowered[HEADER_ID])
            val = lowered[header]
            if isinstance(val, str):
                sval = val
            elif isinstance(val, list):
                sval = ":".join(map(str, val))
            else:
                sval = str(val)
            return sval, has_id
        for v in obj.values():
            found, has_id = _find_in_obj(v, header)
            if found is not None:
                return found, has_id
    elif isinstance(obj, list):
        for item in obj:
            found, has_id = _find_in_obj(item, header)
            if found is not None:
                return found, has_id
    return None, False


def scan_line(line: str, line_no: int = -1) -> Detection | None:
    stripped = line.strip()
    if not stripped:
        return None
    # cheap pre-filter
    if HEADER not in stripped.lower():
        return None

    # 1) JSON line?
    if stripped[0] in "{[":
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            obj = None
        if obj is not None:
            value, has_id = _find_in_obj(obj, HEADER)
            if value is not None:
                det = _analyze_value(value, has_id)
                if det:
                    det.line_no, det.raw = line_no, stripped
                    return det
            return None  # header text appeared only in a string field, not as a key

    # 2) Header-dump "Name: value"
    for part in stripped.split("\n"):
        if ":" not in part:
            continue
        name, _, value = part.partition(":")
        if name.strip().lower() == HEADER:
            # look for an id pairing anywhere on the same line/block
            has_id = HEADER_ID in stripped.lower()
            det = _analyze_value(value.strip(), has_id)
            if det:
                det.line_no, det.raw = line_no, stripped
                return det
    return None


def scan_lines(lines) -> list[Detection]:
    out: list[Detection] = []
    for i, line in enumerate(lines, start=1):
        det = scan_line(line, i)
        if det is not None:
            out.append(det)
    return out


def scan_file(path) -> list[Detection]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return scan_lines(fh)
