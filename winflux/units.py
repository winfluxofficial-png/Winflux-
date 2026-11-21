"""Conversion between decimal text (e.g. "12.5") and integer units.

1 WFLX = 10**8 units. The whole protocol uses integers; decimal text only
exists at the edge (CLI, API, interface).
"""
import re

DECIMALS = 8


def to_units(text: str, decimals: int = DECIMALS) -> int:
    if not isinstance(text, str):
        raise ValueError("value must be text")
    s = text.strip()
    if not re.fullmatch(r"\d+(\.\d{1,%d})?" % decimals, s):
        raise ValueError(f"invalid value: {text!r}")
    whole, _, frac = s.partition(".")
    return int(whole) * 10**decimals + int(frac.ljust(decimals, "0"))


def format_units(units: int, decimals: int = DECIMALS) -> str:
    if units < 0:
        raise ValueError("negative units")
    whole, frac = divmod(units, 10**decimals)
    return f"{whole}.{frac:0{decimals}d}"
