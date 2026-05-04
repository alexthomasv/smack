from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .diff import parse_unified_diff
from .failure_cut import CutEntry, failure_cut_from_text, provisional_failure_cut
from .impact import ImpactResult, analyze_boogie_impact
from .product import ProductArtifact, build_product_artifact
from .provenance import ParsedBoogieProgram, parse_boogie_with_provenance
from .summaries import SummaryPlan, build_summary_plan


@dataclass
class DiffProductResult:
    left: ParsedBoogieProgram
    right: ParsedBoogieProgram
    impact: ImpactResult
    summaries: SummaryPlan
    product: ProductArtifact
    failure_cut: list[CutEntry] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "impact": self.impact.to_json(
                left_program=self.left,
                right_program=self.right,
            ),
            "summaries": self.summaries.to_json(),
            "product": self.product.to_json(),
            "failure_cut": [entry.to_json() for entry in self.failure_cut],
            "diagnostics": self.diagnostics,
        }


def build_from_bpl(
    *,
    left_bpl: str,
    right_bpl: str,
    diff_text: str,
    left_name: str = "left",
    right_name: str = "right",
    left_entry: str | None = None,
    right_entry: str | None = None,
    verifier_output: str | None = None,
    alignment: str = "corerel",
    no_egraph: bool = False,
    egraph_timeout_s: int = 10,
) -> DiffProductResult:
    hunks = parse_unified_diff(diff_text)
    left = parse_boogie_with_provenance(left_bpl, source_name=left_name)
    right = parse_boogie_with_provenance(right_bpl, source_name=right_name)
    impact = analyze_boogie_impact(left, right, hunks)
    summaries = build_summary_plan(left, right, impact)
    product = build_product_artifact(
        left_text=left_bpl,
        right_text=right_bpl,
        diff_text=diff_text,
        left=left,
        right=right,
        impact=impact,
        summaries=summaries,
        left_entry=left_entry,
        right_entry=right_entry,
        alignment=alignment,
        no_egraph=no_egraph,
        egraph_timeout_s=egraph_timeout_s,
    )
    if verifier_output:
        failure_cut = failure_cut_from_text(left, right, verifier_output)
    else:
        failure_cut = provisional_failure_cut(left, right, impact)
    diagnostics: list[str] = []
    diagnostics.extend(left.diagnostics)
    diagnostics.extend(right.diagnostics)
    diagnostics.extend(impact.diagnostics)
    diagnostics.extend(summaries.diagnostics)
    diagnostics.extend(product.diagnostics)
    return DiffProductResult(
        left=left,
        right=right,
        impact=impact,
        summaries=summaries,
        product=product,
        failure_cut=failure_cut,
        diagnostics=diagnostics,
    )
