import pytest

from nextguard import semver


def test_ordering():
    assert semver.parse("14.2.24") < semver.parse("14.2.25")
    assert semver.parse("13.5.9") > semver.parse("13.5.8")
    assert semver.parse("15.0.0") > semver.parse("14.99.99")


def test_prerelease_sorts_below_release():
    assert semver.parse("15.0.0-canary.1") < semver.parse("15.0.0")
    assert semver.parse("15.0.0-canary.1") < semver.parse("15.0.0-canary.2")


def test_strips_prefixes():
    assert semver.parse("v14.2.24") == semver.parse("=14.2.24") == semver.parse("14.2.24")


@pytest.mark.parametrize("bad", ["", "latest", "14", "14.2", "^14.0.0", None])
def test_invalid(bad):
    with pytest.raises(semver.InvalidVersion):
        semver.parse(bad)


def test_in_range_half_open():
    v = semver.parse("14.2.24")
    assert semver.in_range(v, "14.0.0", "14.2.25")       # >=14.0.0 <14.2.25
    assert not semver.in_range(semver.parse("14.2.25"), "14.0.0", "14.2.25")
    assert semver.in_range(semver.parse("14.0.0"), "14.0.0", "14.2.25")  # low inclusive
