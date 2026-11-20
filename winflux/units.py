"""Conversão entre texto decimal (ex.: "12.5") e unidades inteiras.

1 WFLX = 10**8 unidades. Todo o protocolo usa inteiros; o texto decimal só
existe na borda (CLI, API, interface).
"""
import re

DECIMALS = 8


def to_units(text: str, decimals: int = DECIMALS) -> int:
    if not isinstance(text, str):
        raise ValueError("valor deve ser texto")
    s = text.strip()
    if not re.fullmatch(r"\d+(\.\d{1,%d})?" % decimals, s):
        raise ValueError(f"valor inválido: {text!r}")
    whole, _, frac = s.partition(".")
    return int(whole) * 10**decimals + int(frac.ljust(decimals, "0"))


def format_units(units: int, decimals: int = DECIMALS) -> str:
    if units < 0:
        raise ValueError("unidades negativas")
    whole, frac = divmod(units, 10**decimals)
    return f"{whole}.{frac:0{decimals}d}"
