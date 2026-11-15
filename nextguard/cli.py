"""Command-line interface for nextguard.

    nextguard deps  <path ...>     audit manifests/lockfiles (or a directory tree)
    nextguard logs  <file ...>     scan web/proxy logs for exploitation attempts

Exit codes: 0 = clean, 1 = findings, 2 = usage error. Designed for CI gates.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import CVE, GHSA, __version__, dep_audit, log_scan


def _print(obj, as_json: bool):
    if as_json:
        print(json.dumps(obj, indent=2))


def cmd_deps(args) -> int:
    findings = []
    for target in args.paths:
        p = Path(target)
        if p.is_dir():
            findings.extend(dep_audit.audit_tree(p))
        else:
            findings.extend(dep_audit.audit_path(p))

    payload = {"cve": CVE, "ghsa": GHSA, "findings": [f.as_dict() for f in findings]}
    if args.json:
        _print(payload, True)
    else:
        if not findings:
            print("no `next` dependency found in the given paths")
        for f in findings:
            flag = {"vulnerable": "VULNERABLE", "vulnerable_no_patch": "VULNERABLE(no patch)",
                    "not_affected": "ok", "unknown": "UNKNOWN"}[f.status]
            fix = f" -> upgrade to {f.fixed_in}" if f.fixed_in else ""
            print(f"[{flag}] {f.source}: next {f.declared} ({f.resolved or '?'}) {f.detail}{fix}")

    worst = dep_audit.worst_status(findings)
    bad = worst in (dep_audit.VULNERABLE, dep_audit.UNPATCHED)
    if not args.json:
        print(f"\nworst status: {worst}")
    return 1 if (bad or (args.strict and worst == dep_audit.UNKNOWN)) else 0


def cmd_logs(args) -> int:
    all_dets = []
    for target in args.files:
        dets = log_scan.scan_file(target)
        for d in dets:
            row = d.as_dict()
            row["source"] = str(target)
            all_dets.append(row)

    # Internal subrequests carrying a valid id pairing are expected; optionally hide them.
    shown = [d for d in all_dets if not (args.ignore_paired and d["has_valid_id_pairing"])]

    if args.json:
        _print({"cve": CVE, "ghsa": GHSA, "detections": shown}, True)
    else:
        if not shown:
            print("no exploitation attempts detected")
        for d in shown:
            tag = "PAIRED-ID(likely internal)" if d["has_valid_id_pairing"] else d["confidence"].upper()
            print(f"[{tag}] {d['source']}:{d['line_no']} value={d['header_value']!r} -- {d['reason']}")
        print(f"\n{len(shown)} detection(s)")

    # Only unpaired detections should fail a gate.
    actionable = [d for d in shown if not d["has_valid_id_pairing"]]
    return 1 if actionable else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nextguard",
                                description=f"Detection/remediation helpers for {CVE} ({GHSA}).")
    p.add_argument("--version", action="version", version=f"nextguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("deps", help="audit next versions in manifests/lockfiles")
    d.add_argument("paths", nargs="+")
    d.add_argument("--json", action="store_true")
    d.add_argument("--strict", action="store_true", help="also fail on UNKNOWN (unresolved ranges)")
    d.set_defaults(func=cmd_deps)

    lp = sub.add_parser("logs", help="scan web/proxy logs for exploitation attempts")
    lp.add_argument("files", nargs="+")
    lp.add_argument("--json", action="store_true")
    lp.add_argument("--ignore-paired", action="store_true",
                   help="hide detections that carry a valid x-middleware-subrequest-id pairing")
    lp.set_defaults(func=cmd_logs)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
