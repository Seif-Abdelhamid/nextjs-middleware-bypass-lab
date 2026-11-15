"""nextguard — detection and remediation helpers for CVE-2025-29927.

Two independent capabilities:
  * dep_audit  — classify `next` versions in manifests/lockfiles against the
                 CVE-2025-29927 affected/fixed ranges (GHSA-f82v-jwr5-mffw).
  * log_scan   — find `x-middleware-subrequest` exploitation attempts in
                 web/proxy logs.

Nothing here talks to the network or to any live system.
"""

__all__ = ["dep_audit", "log_scan", "semver"]
__version__ = "0.1.0"

CVE = "CVE-2025-29927"
GHSA = "GHSA-f82v-jwr5-mffw"
