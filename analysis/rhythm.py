"""Timing and size rules: what survives encryption.

periodicities(flow)  -> list of (period_s, score): dominant periods in the flow's payload
                        packet times, from the autocorrelation of a binned count series.
bursts(flow)         -> generation-like structure: runs of alternating request/response
                        exchanges with stable sizes; returns the burst interval (decode
                        period), bytes per burst each way, and their spread.
"""

from __future__ import annotations

import statistics as st
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .flows import Flow


def _binned(times: List[float], t0: float, t1: float, dt: float) -> List[int]:
    n = int((t1 - t0) / dt) + 1
    c = [0] * n
    for t in times:
        i = int((t - t0) / dt)
        if 0 <= i < n:
            c[i] += 1
    return c


def periodicities(f: Flow, dt: float = 0.1, min_period: float = 0.3, max_period: float = 120.0,
                  top: int = 4) -> List[Tuple[float, float]]:
    """Dominant periods of payload-packet arrivals (both directions), by autocorrelation of
    the per-bin count series. Score is the normalised autocorrelation at that lag (1 = exact
    repetition). Needs at least ~3 periods of capture to show a period."""
    times = sorted(t for t, _ in f.series_ab + f.series_ba)
    if len(times) < 6:
        return []
    t0, t1 = times[0], times[-1]
    if t1 - t0 < 3 * min_period:
        return []
    c = _binned(times, t0, t1, dt)
    n = len(c)
    mean = sum(c) / n
    var = sum((x - mean) ** 2 for x in c)
    if var == 0:
        return []
    lo, hi = int(min_period / dt), min(int(max_period / dt), n // 3)
    scores = []
    for lag in range(lo, hi + 1):
        s = sum((c[i] - mean) * (c[i + lag] - mean) for i in range(n - lag)) / var
        scores.append((lag * dt, s))
    # local maxima only; a periodic series also peaks at every multiple of its period, so
    # keep the smallest period of each harmonic family (a multiple is dropped when a
    # divisor scored at least 80% as well), then report strongest first
    peaks = [(p, s) for i, (p, s) in enumerate(scores)
             if 0 < i < len(scores) - 1 and s >= scores[i - 1][1] and s >= scores[i + 1][1] and s > 0.2]
    peaks.sort()
    kept: List[Tuple[float, float]] = []
    for p, s in peaks:
        if any(abs(p / q - round(p / q)) < 0.06 and round(p / q) >= 2 and sq >= 0.8 * s for q, sq in kept):
            continue
        kept.append((p, s))
    kept.sort(key=lambda x: -x[1])
    out = [(round(p, 2), round(s, 2)) for p, s in kept[:top]]
    return out


@dataclass
class Bursts:
    n: int                       # exchanges found
    period_s: float              # median gap between exchange starts (decode period if generation)
    period_cv: float             # spread of that gap (median abs. deviation / median)
    req_bytes: float             # median bytes per exchange, a->b
    resp_bytes: float            # median bytes per exchange, b->a
    req_cv: float
    resp_cv: float
    t_start: float
    t_end: float
    direction: str               # which side sends first: "ab" or "ba"

    def looks_like_generation(self) -> bool:
        """Stable exchange sizes at a stable rate, for at least ten exchanges, with a
        return leg: the shape predicted for decode (STUDY.md predictions 7, 10, 13)."""
        return (self.n >= 10 and self.period_cv < 0.35 and self.req_cv < 0.5
                and self.resp_cv < 0.5 and self.resp_bytes > 0 and 0.01 <= self.period_s <= 60)


def _group(ev, gap):
    groups = [[ev[0]]]
    for e in ev[1:]:
        if e[0] - groups[-1][-1][0] > gap:
            groups.append([e])
        else:
            groups[-1].append(e)
    return groups


def _measure(groups, gap) -> Optional[Bursts]:
    if len(groups) < 3:
        return None
    starts = [g[0][0] for g in groups]
    periods = [b - a for a, b in zip(starts, starts[1:])]
    req = [sum(n for _, n, d in g if d == "ab") for g in groups]
    resp = [sum(n for _, n, d in g if d == "ba") for g in groups]
    first_dir = st.mode(g[0][2] for g in groups)
    if first_dir == "ba":
        req, resp = resp, req

    def cv(xs):
        # robust spread: median absolute deviation over the median, so a handful of
        # exchanges from another phase (a load, a hello) do not swamp the decode rhythm
        m = st.median(xs)
        return (st.median(abs(x - m) for x in xs) / m) if m else 0.0

    return Bursts(len(groups), st.median(periods), cv(periods), st.median(req), st.median(resp),
                  cv(req), cv(resp), starts[0], groups[-1][-1][0], first_dir)


def bursts(f: Flow, gap: Optional[float] = None) -> Optional[Bursts]:
    """Group payload packets into exchanges separated by quiet gaps, then measure them.
    Without `gap`, every jump in the sorted inter-packet gaps (ratio > 3) is tried as the
    split threshold and the grouping with the most regular exchanges wins (lowest period
    spread among groupings with at least 10 exchanges, else the one with most exchanges).
    A flow that holds a load phase and then decode is thus measured at the decode scale."""
    ev = sorted([(t, n, "ab") for t, n in f.series_ab] + [(t, n, "ba") for t, n in f.series_ba])
    if len(ev) < 20:
        return None
    if gap is not None:
        return _measure(_group(ev, gap), gap)
    gaps = sorted(set(ev[i + 1][0] - ev[i][0] for i in range(len(ev) - 1)))
    cands = [(gaps[i] + gaps[i + 1]) / 2 for i in range(len(gaps) - 1)
             if gaps[i] > 0 and gaps[i + 1] / gaps[i] > 3 and gaps[i + 1] > 1e-3]
    best: Optional[Bursts] = None
    for g in cands[:50]:
        b = _measure(_group(ev, g), g)
        if b is None:
            continue
        if best is None:
            best = b; continue
        if (b.n >= 10 and best.n >= 10 and b.period_cv < best.period_cv) or \
           (b.n >= 10 > best.n) or (b.n < 10 and best.n < 10 and b.n > best.n):
            best = b
    return best
