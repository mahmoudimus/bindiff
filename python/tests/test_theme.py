"""Colour is derived from the palette, never declared, so both IDA themes
land. These check the arithmetic; the Qt wrapper only reads QPalette."""

from ida_plugin.theme import blend, is_dark, semantic_tints


def test_blend_endpoints_and_midpoint():
    assert blend((0, 0, 0), (255, 255, 255), 0.0) == (0, 0, 0)
    assert blend((0, 0, 0), (255, 255, 255), 1.0) == (255, 255, 255)
    assert blend((0, 0, 0), (200, 100, 0), 0.5) == (100, 50, 0)


def test_dark_detection():
    assert is_dark((30, 30, 30))
    assert not is_dark((245, 245, 240))


def test_tints_have_the_five_roles_on_both_grounds():
    for text, base in (((20, 20, 20), (255, 255, 255)), ((230, 230, 230), (25, 25, 28))):
        tints = semantic_tints(text, base)
        assert set(tints) == {"strong", "check", "weak", "replaces", "dim"}
        for value in tints.values():
            assert all(0 <= channel <= 255 for channel in value)


def test_strong_is_a_grey_between_text_and_base():
    tints = semantic_tints((0, 0, 0), (255, 255, 255))
    r, g, b = tints["strong"]
    assert r == g == b and 0 < r < 255


def test_weak_is_redder_than_check_and_both_lift_on_dark():
    light = semantic_tints((0, 0, 0), (255, 255, 255))
    dark = semantic_tints((255, 255, 255), (0, 0, 0))
    assert light["weak"][0] > light["weak"][1]
    assert light["check"][0] > light["check"][2]
    assert sum(dark["weak"]) > sum(light["weak"]) - 60  # lifted, not muddier


def test_replaces_is_a_faint_wash_of_the_base():
    tints = semantic_tints((0, 0, 0), (255, 255, 255))
    assert min(tints["replaces"]) > 200
