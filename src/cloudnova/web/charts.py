"""Inline SVG charts, no JavaScript and no external assets.

A strict CSP blocks every CDN, and a server-rendered page should not need a
charting library to draw a line through fifteen points. Hover text comes from
SVG <title> elements, which browsers surface natively and screen readers read,
so the chart needs no script to be useful.

One chart earns its place in this product: posture over time. The severity
breakdown is already a row of labelled, status-coloured counts, and a pie of
five slices would say less than the numbers do.
"""

from __future__ import annotations

import html
from dataclasses import dataclass

# Risk score runs 0 to 100 where higher is worse, so a rising line means
# posture getting worse. That is the intuitive reading for a risk measure, and
# the axis says so rather than relying on the reader to guess.
_MAX_SCORE = 100

_W, _H = 680, 170
_PAD_L, _PAD_R, _PAD_T, _PAD_B = 34, 14, 14, 26


@dataclass(frozen=True)
class TrendPoint:
    label: str
    score: int
    grade: str


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _x(i: int, n: int) -> float:
    if n <= 1:
        return _PAD_L
    span = _W - _PAD_L - _PAD_R
    return _PAD_L + (span * i / (n - 1))


def _y(score: int) -> float:
    span = _H - _PAD_T - _PAD_B
    return _PAD_T + span * (1 - (min(max(score, 0), _MAX_SCORE) / _MAX_SCORE))


def posture_trend_svg(points: list[TrendPoint]) -> str:
    """A single-series risk-score line. Returns "" for fewer than two points.

    One point is not a trend, and drawing an axis around a lone dot overstates
    what is known. The caller shows the score on its own in that case.
    """
    n = len(points)
    if n < 2:
        return ""

    # Recessive grid: three reference lines, no box, no tick marks.
    grid = "".join(
        f'<line x1="{_PAD_L}" y1="{_y(v):.1f}" x2="{_W - _PAD_R}" y2="{_y(v):.1f}" '
        f'stroke="#26262f" stroke-width="1"/>'
        f'<text x="{_PAD_L - 7}" y="{_y(v) + 3.5:.1f}" text-anchor="end" '
        f'fill="#8b8b99" font-size="10">{v}</text>'
        for v in (0, 50, 100)
    )

    coords = [(_x(i, n), _y(p.score)) for i, p in enumerate(points)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)

    # Area under the line, anchored to the baseline, at low opacity so the
    # line stays the thing being read.
    base = _H - _PAD_B
    area = f"{coords[0][0]:.1f},{base:.1f} " + line + f" {coords[-1][0]:.1f},{base:.1f}"

    marks = []
    for (x, y), p in zip(coords, points, strict=True):
        # A 2px surface ring keeps overlapping markers legible.
        marks.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="#ff6b81" '
            f'stroke="#141419" stroke-width="2">'
            f"<title>{_e(p.label)}: score {p.score}, grade {_e(p.grade)}</title>"
            f"</circle>"
        )

    # Label only the ends. A number on every point is noise.
    first, last = points[0], points[-1]
    lx, ly = coords[-1]
    labels = (
        f'<text x="{lx:.1f}" y="{ly - 11:.1f}" text-anchor="end" fill="#ececef" '
        f'font-size="12" font-weight="700">{last.score}</text>'
        f'<text x="{_PAD_L}" y="{_H - 8}" fill="#8b8b99" font-size="10">{_e(first.label)}</text>'
        f'<text x="{_W - _PAD_R}" y="{_H - 8}" text-anchor="end" fill="#8b8b99" '
        f'font-size="10">{_e(last.label)}</text>'
    )

    return f"""
    <figure class="chart">
      <figcaption>Risk score over the last {n} scans. Higher is worse.</figcaption>
      <svg viewBox="0 0 {_W} {_H}" width="100%" height="{_H}" role="img"
           aria-label="Risk score across the last {n} scans, most recent {last.score} of 100">
        <defs>
          <linearGradient id="cnfill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#ff2e4d" stop-opacity="0.26"/>
            <stop offset="100%" stop-color="#ff2e4d" stop-opacity="0"/>
          </linearGradient>
        </defs>
        {grid}
        <polygon points="{area}" fill="url(#cnfill)"/>
        <polyline points="{line}" fill="none" stroke="#ff6b81" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round"/>
        {"".join(marks)}
        {labels}
      </svg>
    </figure>"""
