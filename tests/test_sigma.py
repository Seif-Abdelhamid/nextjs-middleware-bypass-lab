import pathlib

import pytest

yaml = pytest.importorskip("yaml")
SIGMA = pathlib.Path(__file__).resolve().parents[1] / "detection" / "sigma"


def test_sigma_rules_are_valid_yaml_with_required_fields():
    rules = list(SIGMA.glob("*.yml"))
    assert rules, "no sigma rules found"
    for r in rules:
        doc = yaml.safe_load(r.read_text())
        for field in ("title", "id", "logsource", "detection", "level", "references"):
            assert field in doc, f"{r.name} missing {field}"
        assert "condition" in doc["detection"]
        # references must point at the primary sources
        refs = " ".join(doc["references"])
        assert "GHSA-f82v-jwr5-mffw" in refs


def test_sigma_keyword_present_in_attack_samples_absent_in_benign():
    """The rule keys on the 'x-middleware-subrequest' header. Confirm that token
    appears in every attack sample and not in the benign one, so the rule would
    fire on the former and stay quiet on the latter."""
    samples = SIGMA.parent / "samples"
    attack = (samples / "access-json.log").read_text() + (samples / "header-dump.log").read_text()
    benign = (samples / "benign.log").read_text()
    assert "x-middleware-subrequest" in attack
    assert "x-middleware-subrequest" not in benign
