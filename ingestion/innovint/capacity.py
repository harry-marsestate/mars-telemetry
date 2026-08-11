"""capacity_suspect heuristic for vessels_sync.

Two independent signals, combined:

1. An exact-match check against placeholder values directly observed
   during the InnoVint data inventory (TD-07 and TD-08 both report
   exactly 500,000 gal, dwarfing every real volume in the account -- the
   largest genuine vessel seen was in the low hundreds of gallons).

2. A statistical outlier check relative to the rest of the vessels
   fetched in the same run, so the heuristic isn't pinned to today's one
   known bad value and can catch a *different* placeholder InnoVint
   introduces later without a code change. The baseline for this check
   deliberately excludes anything already caught by (1) -- otherwise a
   pair of 500,000-gal placeholders sitting in the top percentile of a
   ~90-vessel sample would drag the outlier threshold up to the point of
   no longer catching anything, including themselves.

Real commercial tanks can legitimately span an order of magnitude (a
50-gal keg next to a 2,000-gal fermenter), so the outlier multiple is
deliberately generous -- this is meant to catch "obviously not a real
number," not "large."
"""

from __future__ import annotations

import statistics

KNOWN_PLACEHOLDER_VALUES: frozenset[float] = frozenset({500_000.0})

OUTLIER_MULTIPLE = 10
MIN_SAMPLE_FOR_OUTLIER_CHECK = 5


def outlier_threshold(capacities: list[float]) -> float | None:
    """99th-percentile-based threshold, computed once per run from every
    non-null, non-placeholder capacity fetched. None if the clean sample
    is too small to be statistically meaningful (falls back to the
    exact-match check alone).
    """
    baseline = [c for c in capacities if c not in KNOWN_PLACEHOLDER_VALUES]
    if len(baseline) < MIN_SAMPLE_FOR_OUTLIER_CHECK:
        return None
    p99 = statistics.quantiles(baseline, n=100)[98]
    return OUTLIER_MULTIPLE * p99 if p99 > 0 else None


def compute_capacity_suspect(capacity_gal: float | None, threshold: float | None) -> bool:
    if capacity_gal is None:
        return False
    if capacity_gal in KNOWN_PLACEHOLDER_VALUES:
        return True
    return threshold is not None and capacity_gal > threshold
