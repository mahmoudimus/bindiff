"""What the inspector shows for one pair.

Tier 2 of the vocabulary rule: every engine token appears beside its
expansion and its value, always all three, in the same view. The table shows
the plain reading; this is where the numbers and the letters live.

No Qt and no IDA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Tuple

from ida_plugin.trust import (BLOCK_COVERAGE_CAVEAT, Trust, algorithm_class,
                              explain, found_by)
from ida_plugin.ui_logic import MatchRow, change_expansions, is_generated_name

# ResultMeta is read for two names and nothing else, so it is a shape here
# rather than a dependency -- importing session at runtime would drag the
# whole session layer into a module the tests exercise on its own.
if TYPE_CHECKING:
    from ida_plugin.session import ResultMeta


@dataclass(frozen=True)
class Measure:
    label: str
    token: str
    value: str


@dataclass(frozen=True)
class Inspection:
    title: str
    subtitle: str
    trust: str
    trust_explanation: str
    measures: Tuple[Measure, ...]
    coverage_caveat: str
    changed: Tuple[tuple, ...]
    would_port: Tuple[str, ...]
    port_label: str
    engine_algorithm: str


def _counted(matched: int, here: int, there: int) -> str:
    if here or there:
        return f"{matched} of {here} / {there}"
    return str(matched)


def build_inspection(row: MatchRow, meta: Optional["ResultMeta"], *,
                     threshold: float) -> Inspection:
    other_real = not is_generated_name(row.name_secondary)
    title = row.name_secondary if other_real else row.name_primary
    this_label = f"{meta.this_name} " if meta else ""
    other_label = f"{meta.other_name} " if meta else ""
    subtitle = (f"{other_label}{row.address_secondary:X} → "
                f"{this_label}{row.address_primary:X}")

    trust = Trust(row.trust) if row.trust in Trust._value2member_map_ else Trust.CHECK
    measures = (
        Measure("Similarity", "similarity", f"{row.similarity:.2f}"),
        Measure("Block coverage", "confidence", f"{row.confidence:.2f}"),
        Measure("Algorithm class", "algorithm class",
                algorithm_class(row.algorithm).value),
        Measure("Found by", row.algorithm, found_by(row.algorithm)),
        Measure("Matched blocks", "basicblocks",
                _counted(row.basic_blocks, row.basic_blocks_primary,
                         row.basic_blocks_secondary)),
        Measure("Matched instructions", "instructions",
                _counted(row.instructions, row.instructions_primary,
                         row.instructions_secondary)),
        Measure("Matched edges", "edges",
                _counted(row.edges, row.edges_primary, row.edges_secondary)),
    )

    lines = []
    name_to_write = other_real and row.name_secondary != row.name_primary
    if name_to_write:
        lines.append(f"Name {row.name_secondary}")
        if is_generated_name(row.name_primary):
            lines.append(f"over {row.name_primary} — auto-generated, safe to replace")
        else:
            lines.append(f"over {row.name_primary} — a name you wrote")
    elif other_real:
        lines.append(f"Name already {row.name_primary}")
    else:
        lines.append("No name to port")
    comments = row.comments_available
    if comments:
        lines.append(f"{comments} comment{'s' if comments != 1 else ''}")
    if row.similarity < threshold:
        lines.append(f"Below the {threshold:.2f} threshold — the inspector's "
                     f"Port button writes it anyway")

    if name_to_write and comments:
        port_label = f"Port name + {comments} comment{'s' if comments != 1 else ''}"
    elif name_to_write:
        port_label = "Port name"
    elif comments:
        port_label = f"Port {comments} comment{'s' if comments != 1 else ''}"
    else:
        port_label = "Nothing to port"

    return Inspection(
        title=title, subtitle=subtitle, trust=row.trust,
        trust_explanation=explain(trust, row.algorithm, row.similarity,
                                  row.confidence),
        measures=measures, coverage_caveat=BLOCK_COVERAGE_CAVEAT,
        changed=tuple(change_expansions(row.change_flags)),
        would_port=tuple(lines), port_label=port_label,
        engine_algorithm=row.algorithm)
