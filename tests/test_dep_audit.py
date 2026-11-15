import json

import pytest

from nextguard import dep_audit as da


@pytest.mark.parametrize("version,status,fixed", [
    ("14.2.24", da.VULNERABLE, "14.2.25"),
    ("14.2.25", da.SAFE, None),
    ("14.0.0", da.VULNERABLE, "14.2.25"),
    ("13.5.8", da.VULNERABLE, "13.5.9"),
    ("13.5.9", da.SAFE, None),
    ("12.3.4", da.VULNERABLE, "12.3.5"),
    ("12.3.5", da.SAFE, None),
    ("15.2.2", da.VULNERABLE, "15.2.3"),
    ("15.2.3", da.SAFE, None),
    ("16.1.0", da.SAFE, None),
    ("11.1.0", da.UNPATCHED, None),
    ("not-a-version", da.UNKNOWN, None),
])
def test_classify(version, status, fixed):
    s, f, _ = da.classify(version)
    assert s == status
    assert f == fixed


def test_package_json_pinned(tmp_path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"dependencies": {"next": "14.2.24", "react": "18.3.1"}}))
    findings = da.audit_package_json(p)
    assert len(findings) == 1
    assert findings[0].status == da.VULNERABLE
    assert findings[0].fixed_in == "14.2.25"


def test_package_json_range_is_unknown(tmp_path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"dependencies": {"next": "^14.0.0"}}))
    findings = da.audit_package_json(p)
    assert findings[0].status == da.UNKNOWN


def test_package_lock_v3(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/next": {"version": "14.2.24"},
            "node_modules/react": {"version": "18.3.1"},
        },
    }))
    findings = da.audit_package_lock(p)
    assert len(findings) == 1
    assert findings[0].resolved == "14.2.24"
    assert findings[0].status == da.VULNERABLE


def test_package_lock_v1_nested(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"next": {"version": "13.5.9"}},
    }))
    findings = da.audit_package_lock(p)
    assert findings[0].status == da.SAFE


def test_yarn_lock(tmp_path):
    p = tmp_path / "yarn.lock"
    p.write_text(
        'next@^14.0.0:\n'
        '  version "14.2.24"\n'
        '  resolved "https://registry.yarnpkg.com/next/-/next-14.2.24.tgz"\n'
        '\n'
        'react@^18.0.0:\n'
        '  version "18.3.1"\n'
    )
    findings = da.audit_yarn_lock(p)
    assert len(findings) == 1
    assert findings[0].resolved == "14.2.24"
    assert findings[0].status == da.VULNERABLE


def test_real_vulnerable_app_manifest():
    # The lab's own vulnerable app must be flagged.
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    findings = da.audit_package_json(root / "labs" / "vulnerable-app" / "package.json")
    assert any(f.status == da.VULNERABLE and f.fixed_in == "14.2.25" for f in findings)


def test_worst_status():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    findings = da.audit_tree(root / "labs")
    # tree contains both vulnerable (14.2.24) and patched (14.2.25) manifests
    assert da.worst_status(findings) == da.VULNERABLE
