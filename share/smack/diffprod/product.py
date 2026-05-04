from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .impact import ImpactResult
from .provenance import ParsedBoogieProgram
from .smack_lowerer import UnsupportedSmackBoogie, lower_smack_boogie_proc_to_ir
from .summaries import SummaryPlan


@dataclass
class ProductArtifact:
    text: str
    actual_product_available: bool
    diagnostics: list[str] = field(default_factory=list)
    mode: str | None = None
    actual_source: str | None = None
    delta_left_blocks: list[str] = field(default_factory=list)
    delta_right_blocks: list[str] = field(default_factory=list)
    lockstep_outcomes: list[dict[str, Any]] = field(default_factory=list)
    egraph_outcomes: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "actual_product_available": self.actual_product_available,
            "actual_source": self.actual_source,
            "mode": self.mode,
            "delta": {
                "left_blocks": self.delta_left_blocks,
                "right_blocks": self.delta_right_blocks,
            },
            "lockstep_outcomes": self.lockstep_outcomes,
            "egraph_outcomes": self.egraph_outcomes,
            "egraph_success": any(
                outcome.get("success") and outcome.get("resolution") == "egraph"
                for outcome in self.egraph_outcomes
            ),
            "diagnostics": self.diagnostics,
        }


def build_product_artifact(
    *,
    left_text: str,
    right_text: str,
    diff_text: str,
    left: ParsedBoogieProgram,
    right: ParsedBoogieProgram,
    impact: ImpactResult,
    summaries: SummaryPlan,
    left_entry: str | None = None,
    right_entry: str | None = None,
    alignment: str = "corerel",
    no_egraph: bool = False,
    egraph_timeout_s: int = 10,
) -> ProductArtifact:
    """Build the product output for this slice.

    The existing product pass is used when it can lower the selected Boogie
    procedures. SMACK-generated Boogie often contains memory-model constructs
    outside that subset, so this function always falls back to a valid Boogie
    impact/summary artifact instead of failing the whole pipeline.
    """

    diagnostics: list[str] = []
    actual = try_build_smack_product(
        left=left,
        right=right,
        impact=impact,
        left_entry=left_entry,
        right_entry=right_entry,
        diff_text=diff_text,
        alignment=alignment,
        no_egraph=no_egraph,
        egraph_timeout_s=egraph_timeout_s,
        diagnostics=diagnostics,
    )
    if actual is not None:
        return actual

    actual = try_build_generic_product(
        left_text=left_text,
        right_text=right_text,
        diff_text=diff_text,
        left_entry=left_entry,
        right_entry=right_entry,
        alignment=alignment,
        no_egraph=no_egraph,
        egraph_timeout_s=egraph_timeout_s,
        diagnostics=diagnostics,
    )
    if actual is not None:
        return actual

    diagnostics.append(
        "emitted impact/summary product artifact because selected SMACK Boogie "
        "was outside the current relational-product lowering subset"
    )
    return ProductArtifact(
        text=emit_metadata_product(left, right, impact, summaries),
        actual_product_available=False,
        diagnostics=diagnostics,
    )


def try_build_actual_product(
    *,
    left_text: str,
    right_text: str,
    diff_text: str,
    left_entry: str | None,
    right_entry: str | None,
    diagnostics: list[str],
) -> str | None:
    artifact = try_build_generic_product(
        left_text=left_text,
        right_text=right_text,
        diff_text=diff_text,
        left_entry=left_entry,
        right_entry=right_entry,
        alignment="corerel",
        no_egraph=False,
        egraph_timeout_s=10,
        diagnostics=diagnostics,
    )
    return artifact.text if artifact is not None else None


def try_build_smack_product(
    *,
    left: ParsedBoogieProgram,
    right: ParsedBoogieProgram,
    impact: ImpactResult,
    left_entry: str | None,
    right_entry: str | None,
    diff_text: str,
    alignment: str,
    no_egraph: bool,
    egraph_timeout_s: int,
    diagnostics: list[str],
) -> ProductArtifact | None:
    if not ensure_diffprod_package_on_path():
        diagnostics.append("diffprod library product pass was not found")
        return None
    try:
        from diffprod import bpl_emit
        from diffprod.product_pass import (
            DiffHints,
            ProductPassOptions,
            build_product_pass,
        )
    except Exception as exc:
        diagnostics.append(f"failed to import diffprod product pass: {exc}")
        return None

    try:
        program_p = lower_smack_boogie_proc_to_ir(left, left_entry)
        program_q = lower_smack_boogie_proc_to_ir(right, right_entry)
    except UnsupportedSmackBoogie as exc:
        diagnostics.append(f"SMACK Boogie lowering failed: {exc}")
        return None

    try:
        product = build_product_pass(
            program_p,
            program_q,
            diff=DiffHints(
                unified_diff=diff_text,
                delta_node_ids_p=frozenset(impact.left.impacted_blocks),
                delta_node_ids_q=frozenset(impact.right.impacted_blocks),
            ),
            options=ProductPassOptions(
                alignment=alignment,
                no_egraph=no_egraph,
                egraph_timeout_s=egraph_timeout_s,
            ),
        )
        text = bpl_emit.emit(product.program)
    except Exception as exc:
        diagnostics.append(f"SMACK product construction failed: {exc}")
        return None

    diagnostics.extend(product.diagnostics)
    return product_artifact_from_result(
        text=text,
        result=product,
        diagnostics=diagnostics,
        actual_source="smack-boogie",
    )


def try_build_generic_product(
    *,
    left_text: str,
    right_text: str,
    diff_text: str,
    left_entry: str | None,
    right_entry: str | None,
    alignment: str,
    no_egraph: bool,
    egraph_timeout_s: int,
    diagnostics: list[str],
) -> ProductArtifact | None:
    if not ensure_diffprod_package_on_path():
        diagnostics.append("diffprod library product pass was not found")
        return None
    try:
        from diffprod import bpl_emit
        from diffprod.boogie_bridge import build_product_from_boogie
        from diffprod.product_pass import ProductPassOptions
    except Exception as exc:
        diagnostics.append(f"failed to import diffprod product pass: {exc}")
        return None

    proc_name: str | tuple[str | None, str | None] | None
    if left_entry or right_entry:
        proc_name = (left_entry, right_entry)
    else:
        proc_name = None

    try:
        result = build_product_from_boogie(
            left_text,
            right_text,
            diff_text,
            proc_name=proc_name,
            options=ProductPassOptions(
                alignment=alignment,
                no_egraph=no_egraph,
                egraph_timeout_s=egraph_timeout_s,
            ),
        )
    except Exception as exc:
        diagnostics.append(f"actual product construction failed: {exc}")
        return None

    diagnostics.extend(result.diagnostics)
    diagnostics.extend(getattr(result.product, "diagnostics", []) or [])
    if result.product is None:
        return None
    try:
        text = bpl_emit.emit(result.product.program)
    except Exception as exc:
        diagnostics.append(f"actual product emission failed: {exc}")
        return None

    return product_artifact_from_result(
        text=text,
        result=result.product,
        diagnostics=diagnostics,
        actual_source="generic-boogie",
    )


def product_artifact_from_result(
    *,
    text: str,
    result: Any,
    diagnostics: list[str],
    actual_source: str,
) -> ProductArtifact:
    return ProductArtifact(
        text=text,
        actual_product_available=True,
        diagnostics=list(diagnostics),
        mode=result.mode,
        actual_source=actual_source,
        delta_left_blocks=sorted(result.delta.delta_p),
        delta_right_blocks=sorted(result.delta.delta_q),
        lockstep_outcomes=[lockstep_outcome_json(o) for o in result.lockstep_outcomes],
        egraph_outcomes=[egraph_outcome_json(o) for o in result.align_outcomes],
    )


def lockstep_outcome_json(outcome: Any) -> dict[str, Any]:
    return {
        "p_head_label": outcome.p_head_label,
        "q_head_label": outcome.q_head_label,
        "success": outcome.success,
        "reason": outcome.reason,
        "coupling_vars": list(outcome.coupling_vars),
        "guard_resolution": outcome.guard_resolution,
        "body_resolution": outcome.body_resolution,
        "preheader_resolution": outcome.preheader_resolution,
        "in_delta": outcome.in_delta,
    }


def egraph_outcome_json(outcome: Any) -> dict[str, Any]:
    return {
        "region": {
            "left_blocks": list(outcome.region.p_blocks),
            "right_blocks": list(outcome.region.q_blocks),
            "live_out": list(outcome.region.live_out),
        },
        "success": outcome.success,
        "reason": outcome.reason,
        "resolution": outcome.resolution,
    }


def ensure_diffprod_package_on_path() -> bool:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "diffprod" / "diffprod" / "boogie_bridge.py"
        if candidate.exists():
            package_root = str(parent / "diffprod")
            if package_root not in sys.path:
                sys.path.insert(0, package_root)
            return True
    return False


def emit_metadata_product(
    left: ParsedBoogieProgram,
    right: ParsedBoogieProgram,
    impact: ImpactResult,
    summaries: SummaryPlan,
) -> str:
    lines: list[str] = [
        "// generated by SMACK diff-product",
        "// This artifact records the impacted Boogie cut and summary regions.",
        "",
        "procedure smack_diff_product_metadata();",
        "implementation smack_diff_product_metadata()",
        "{",
        "entry:",
        '  assume {:diff.product "metadata"} true;',
    ]
    for side, parsed, impacted in (
        ("left", left, impact.left),
        ("right", right, impact.right),
    ):
        for block_id in sorted(impacted.impacted_blocks):
            label = parsed.provenance.block_labels.get(block_id, block_id)
            lines.append(
                "  assume "
                f'{{:diff.impacted "{_bpl_string(side)}" "{_bpl_string(block_id)}" '
                f'"{_bpl_string(label)}"}} true;'
            )
        for stmt_id in sorted(impacted.impacted_statements):
            lines.append(
                "  assume "
                f'{{:diff.impacted.stmt "{_bpl_string(side)}" '
                f'"{_bpl_string(stmt_id)}"}} true;'
            )
    for side, regions in (("left", summaries.left), ("right", summaries.right)):
        for region in regions:
            eq = region.equivalent_to or ""
            lines.append(
                "  assume "
                f'{{:diff.summary "{_bpl_string(side)}" '
                f'"{_bpl_string(region.block_id)}" "{_bpl_string(eq)}"}} true;'
            )
    lines.extend(["  return;", "}", ""])
    return "\n".join(lines)


def _bpl_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
