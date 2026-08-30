"""Weight-unit normalization for InnoVint FloatUnit values.

Kept in Python rather than a generated column so the conversion table is
unit-testable and, more importantly, so an unrecognized or non-weight unit
fails LOUDLY at ingest instead of silently producing a null in the database.

Canonical unit is the US short ton -- InnoVint is US winery software and
every observed weigh-tag receipt is in `tons`. That assumption is recorded
here rather than left implicit.
"""

from __future__ import annotations

# To US short tons.
_TO_SHORT_TONS: dict[str, float] = {
    "tons": 1.0,
    "ton": 1.0,
    "tonne": 1.10231,
    "tonnes": 1.10231,  # metric ton
    "kg": 0.00110231,
    "kilograms": 0.00110231,
    "lbs": 0.0005,
}

# Present in FloatUnit's enum but meaningless as a fruit intake weight.
_VOLUME_UNITS = {
    "gal",
    "gallons",
    "gallon",
    "hl",
    "hL",
    "liters",
    "litres",
    "L",
    "pg",
    "PG",
}


class UnrecognizedWeightUnit(ValueError):
    pass


def to_short_tons(value: float, unit: str) -> float:
    if unit in _VOLUME_UNITS:
        raise UnrecognizedWeightUnit(
            f"volume unit {unit!r} on a fruit intake weight -- refusing to "
            f"coerce; this is a source data error, not a conversion gap"
        )
    try:
        return value * _TO_SHORT_TONS[unit]
    except KeyError:
        raise UnrecognizedWeightUnit(
            f"no short-ton conversion for unit {unit!r}; add it to "
            f"_TO_SHORT_TONS deliberately rather than defaulting"
        ) from None
