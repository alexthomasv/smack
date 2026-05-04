from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .impact import ImpactResult
from .provenance import OriginSet, ParsedBoogieProgram


@dataclass
class CutEntry:
    side: str
    node_id: str
    kind: str | None
    origins: OriginSet
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "side": self.side,
            "node_id": self.node_id,
            "kind": self.kind,
            "reason": self.reason,
            "origins": self.origins.to_json(),
        }


def failure_cut_from_text(
    left: ParsedBoogieProgram,
    right: ParsedBoogieProgram,
    verifier_output: str,
) -> list[CutEntry]:
    cut: list[CutEntry] = []
    for side, parsed in (("left", left), ("right", right)):
        for node_id in sorted(parsed.provenance.origins):
            label = parsed.provenance.block_labels.get(node_id)
            if node_id in verifier_output or (label and label in verifier_output):
                cut.append(
                    CutEntry(
                        side=side,
                        node_id=node_id,
                        kind=parsed.provenance.node_kinds.get(node_id),
                        origins=parsed.provenance.origin_set(node_id),
                        reason="verifier-output",
                    )
                )
    return cut


def provisional_failure_cut(
    left: ParsedBoogieProgram,
    right: ParsedBoogieProgram,
    impact: ImpactResult,
) -> list[CutEntry]:
    """A minimal cut before relational verification exists for a failure."""

    cut: list[CutEntry] = []
    for side, parsed, impacted in (
        ("left", left, impact.left.impacted_blocks),
        ("right", right, impact.right.impacted_blocks),
    ):
        for node_id in sorted(impacted):
            cut.append(
                CutEntry(
                    side=side,
                    node_id=node_id,
                    kind=parsed.provenance.node_kinds.get(node_id),
                    origins=parsed.provenance.origin_set(node_id),
                    reason="impact-cut",
                )
            )
    return cut
