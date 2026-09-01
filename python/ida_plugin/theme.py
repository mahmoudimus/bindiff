"""Semantic tints derived from the palette, so light and dark both land.

No stylesheet colours anywhere in the plugin: a hard-coded green that reads
on IDA's light theme is invisible on the dark one. The three verdict tints
and the two washes are blended from the widget's own text and base colours
at call time. This module is the arithmetic; the Qt layer feeds it QPalette
roles as (r, g, b) triples.
"""

from __future__ import annotations

from typing import Dict, Tuple

RGB = Tuple[int, int, int]

_AMBER: RGB = (0xE0, 0x9A, 0x1E)
_RED: RGB = (0xD1, 0x3B, 0x3B)
_WHITE: RGB = (255, 255, 255)


def blend(colour: RGB, toward: RGB, amount: float) -> RGB:
    amount = max(0.0, min(1.0, amount))
    return tuple(  # type: ignore[return-value]
        int(round(c + (t - c) * amount)) for c, t in zip(colour, toward))


def is_dark(base: RGB) -> bool:
    r, g, b = (channel / 255.0 for channel in base)
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) < 0.5


def semantic_tints(text: RGB, base: RGB) -> Dict[str, RGB]:
    """The verdict colours for one palette.

    Strong is a slate grey -- the ordinary case earns no ink. Amber and red
    are reserved for Check and Weak, so a screenful of either means
    something. The seeds are lifted toward white on a dark ground because a
    saturated mid-tone that reads on paper goes muddy on black.
    """
    amber, red = _AMBER, _RED
    if is_dark(base):
        amber = blend(amber, _WHITE, 0.2)
        red = blend(red, _WHITE, 0.2)
    weak = blend(red, base, 0.15)
    return {
        "strong": blend(text, base, 0.55),
        "check": blend(amber, base, 0.15),
        "weak": weak,
        "replaces": blend(weak, base, 0.88),
        "dim": blend(text, base, 0.45),
    }
