import pytest

from winflux.units import format_units, to_units


def test_to_units():
    assert to_units("1") == 10**8
    assert to_units("0.00000001") == 1
    assert to_units("12.5") == 1_250_000_000
    assert to_units("100000000") == 10**16


@pytest.mark.parametrize("bad", ["", "-1", "1.123456789", "1,5", "abc", "1e3", " ", ".5", None, 1.5])
def test_to_units_rejects(bad):
    with pytest.raises(ValueError):
        to_units(bad)


def test_format_roundtrip():
    for s in ("0.00000001", "1.00000000", "12.50000000"):
        assert format_units(to_units(s)) == s
