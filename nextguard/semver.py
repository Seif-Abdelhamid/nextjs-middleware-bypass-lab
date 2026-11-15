"""A small, dependency-free semantic-version comparator.

Only what we need to evaluate npm-style ranges for the advisory: parse
`major.minor.patch` (with an optional pre-release that sorts *below* the release,
per semver) and compare. Build metadata is ignored. Leading `v`, `=` and
whitespace are stripped so manifest values still parse. Range sigils (`^`,
`~`, `x`) are NOT accepted: they denote constraints, not a version.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_CORE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


class InvalidVersion(ValueError):
    pass


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple = ()

    def _key(self):
        # A release outranks any of its pre-releases: empty prerelease -> highest.
        return (self.major, self.minor, self.patch, 0 if not self.prerelease else -1, self.prerelease)

    def __lt__(self, other: Version) -> bool:
        return self._key() < other._key()

    def __le__(self, other: Version) -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: Version) -> bool:
        return self._key() > other._key()

    def __ge__(self, other: Version) -> bool:
        return self._key() >= other._key()

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{'.'.join(map(str, self.prerelease))}" if self.prerelease else base


def _pre_tuple(pre: str | None) -> tuple:
    if not pre:
        return ()
    # Numeric identifiers compare as ints and below equal-length alphanumerics.
    out = []
    for ident in pre.split("."):
        out.append((0, int(ident)) if ident.isdigit() else (1, ident))
    return tuple(out)


def parse(raw: str) -> Version:
    if raw is None:
        raise InvalidVersion("version is None")
    s = raw.strip().lstrip("v= ").strip()
    m = _CORE.match(s)
    if not m:
        raise InvalidVersion(f"not a concrete semver: {raw!r}")
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)), _pre_tuple(m.group(4)))


def in_range(v: Version, low: str | None, high: str | None,
             include_low: bool = True, include_high: bool = False) -> bool:
    """True if `v` is within [low, high) by default (npm's usual `>=low <high`)."""
    if low is not None:
        lo = parse(low)
        if (v < lo) or (v == lo and not include_low):
            return False
    if high is not None:
        hi = parse(high)
        if (v > hi) or (v == hi and not include_high):
            return False
    return True
