from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .impact import ImpactResult
from .provenance import ParsedBoogieProgram
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
    structural: dict[str, Any] | None = None
    selection: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "actual_product_available": self.actual_product_available,
            "actual_source": self.actual_source,
            "mode": self.mode,
            "structural": self.structural,
            "selection": self.selection,
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
    alignment: str = "auto",
    no_egraph: bool = False,
    egraph_timeout_s: int = 10,
    llvm_match: dict[str, Any] | None = None,
) -> ProductArtifact:
    """Build the product output for this slice.

    The existing product pass is used when it can lower the selected Boogie
    procedures. SMACK-generated Boogie often contains memory-model constructs
    outside that subset, so this function always falls back to a valid Boogie
    impact/summary artifact instead of failing the whole pipeline.
    """

    diagnostics: list[str] = []
    actual = try_build_generic_product(
        left_text=left_text,
        right_text=right_text,
        diff_text=diff_text,
        left=left,
        right=right,
        impact=impact,
        left_entry=left_entry,
        right_entry=right_entry,
        alignment=alignment,
        no_egraph=no_egraph,
        egraph_timeout_s=egraph_timeout_s,
        llvm_match=llvm_match,
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
        alignment="auto",
        no_egraph=False,
        egraph_timeout_s=10,
        diagnostics=diagnostics,
    )
    return artifact.text if artifact is not None else None


def try_build_generic_product(
    *,
    left_text: str,
    right_text: str,
    diff_text: str,
    left: ParsedBoogieProgram | None = None,
    right: ParsedBoogieProgram | None = None,
    impact: ImpactResult | None = None,
    left_entry: str | None,
    right_entry: str | None,
    alignment: str,
    no_egraph: bool,
    egraph_timeout_s: int,
    llvm_match: dict[str, Any] | None = None,
    diagnostics: list[str],
) -> ProductArtifact | None:
    if not ensure_diffprod_package_on_path():
        diagnostics.append("diffprod library product pass was not found")
        return None
    try:
        from diffprod import bpl_emit, ir
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
            left if left is not None else left_text,
            right if right is not None else right_text,
            diff_text,
            proc_name=proc_name,
            options=ProductPassOptions(
                alignment=alignment,
                no_egraph=no_egraph,
                egraph_timeout_s=egraph_timeout_s,
                structural_fallback=llvm_match is None,
            ),
            delta_node_ids_p=frozenset(impact.left.impacted_blocks)
            if impact is not None
            else frozenset(),
            delta_node_ids_q=frozenset(impact.right.impacted_blocks)
            if impact is not None
            else frozenset(),
        )
    except Exception as exc:
        diagnostics.append(f"actual product construction failed: {exc}")
        return None

    diagnostics.extend(result.diagnostics)
    diagnostics.extend(getattr(result.product, "diagnostics", []) or [])
    if result.product is None:
        return None
    try:
        text = emit_product_text(result.product.program, bpl_emit, ir)
    except Exception as exc:
        diagnostics.append(f"actual product emission failed: {exc}")
        return None

    return product_artifact_from_result(
        text=text,
        result=result.product,
        diagnostics=diagnostics,
        actual_source="boogie-ast",
    )


def product_artifact_from_result(
    *,
    text: str,
    result: Any,
    diagnostics: list[str],
    actual_source: str,
) -> ProductArtifact:
    return ProductArtifact(
        text=add_trace_pair_comments(text, result),
        actual_product_available=True,
        diagnostics=list(diagnostics),
        mode=result.mode,
        actual_source=actual_source,
        delta_left_blocks=sorted(result.delta.delta_p),
        delta_right_blocks=sorted(result.delta.delta_q),
        lockstep_outcomes=[lockstep_outcome_json(o) for o in result.lockstep_outcomes],
        egraph_outcomes=[egraph_outcome_json(o) for o in result.align_outcomes],
        structural=structural_json(getattr(result, "structural", None)),
        selection=[
            candidate.to_json()
            for candidate in getattr(result, "candidate_reports", []) or []
        ],
    )


def structural_json(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "block_count": value.block_count,
        "stmt_count": value.stmt_count,
        "p_block_count": value.p_block_count,
        "q_block_count": value.q_block_count,
        "cartesian_pair_cost": value.cartesian_pair_cost,
        "cross_side_assert_count": value.cross_side_assert_count,
        "sync_density": value.sync_density,
    }


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
        "debug_steps": list(getattr(outcome, "debug_steps", []) or []),
    }


def add_trace_pair_comments(text: str, result: Any) -> str:
    comments = trace_pair_comments(result) + egraph_step_comments(result)
    if not comments:
        return text
    return "\n".join(comments) + "\n" + text


def trace_pair_comments(result: Any) -> list[str]:
    comments: list[str] = []
    for outcome in getattr(result, "align_outcomes", []) or []:
        if not getattr(outcome, "success", False):
            continue
        region = outcome.region
        left = ",".join(sorted(region.p_blocks))
        right = ",".join(sorted(region.q_blocks))
        live_out = ",".join(sorted(region.live_out))
        resolution = outcome.resolution or "unknown"
        comments.append(
            "// diffprod.trace_pair "
            f"resolution={resolution} left={left} right={right} live_out={live_out}"
        )
    return comments


def egraph_step_comments(result: Any) -> list[str]:
    comments: list[str] = []
    for outcome in getattr(result, "align_outcomes", []) or []:
        region = outcome.region
        left = ",".join(sorted(region.p_blocks))
        right = ",".join(sorted(region.q_blocks))
        region_text = f"{left}->{right}"
        for index, step in enumerate(getattr(outcome, "debug_steps", []) or []):
            phase = _comment_value(step.get("phase", "unknown"))
            fields = [
                f"region={_comment_value(region_text)}",
                f"index={index}",
                f"phase={phase}",
            ]
            for key in (
                "success",
                "resolution",
                "reason",
                "left_statement_count",
                "right_statement_count",
                "aligned_pair_count",
                "run_steps",
                "command_count",
                "error_type",
                "error",
            ):
                if key in step and step[key] not in (None, ""):
                    fields.append(f"{key}={_comment_value(step[key])}")
            if step.get("phase") == "encode-egglog":
                bindings = step.get("bindings") or {}
                if isinstance(bindings, dict):
                    if "p_term" in bindings:
                        fields.append(f"p_term={_comment_value(bindings['p_term'])}")
                    if "q_term" in bindings:
                        fields.append(f"q_term={_comment_value(bindings['q_term'])}")
                if "check_expr" in step:
                    fields.append(f"check_expr={_comment_value(step['check_expr'])}")
            comments.append("// diffprod.egraph.step " + " ".join(fields))
    return comments


def _comment_value(value: Any) -> str:
    text = str(value).replace("\n", "\\n")
    if len(text) > 240:
        text = text[:237] + "..."
    if any(ch.isspace() for ch in text) or text == "":
        text = '"' + text.replace('"', '\\"') + '"'
    return text


def emit_product_text(program: Any, bpl_emit: Any, ir: Any) -> str:
    text = bpl_emit.emit(program)
    decls = uninterpreted_function_declarations(program, ir)
    if not decls:
        return text
    return "\n".join(decls) + "\n\n" + text


def uninterpreted_function_declarations(program: Any, ir: Any) -> list[str]:
    env = program_type_env(program)
    functions: dict[tuple[str, int], tuple[list[tuple[Any, int]], tuple[Any, int]]] = {}
    for block in program.blocks:
        for stmt in block.stmts:
            collect_stmt_functions(stmt, env, functions, ir)
        if getattr(block, "structured_while", None) is not None:
            collect_expr_functions(
                block.structured_while.guard,
                (ir.Ty.BOOL, 0),
                env,
                functions,
                ir,
            )
            for invariant in block.structured_while.invariants:
                collect_expr_functions(invariant, (ir.Ty.BOOL, 0), env, functions, ir)
            for stmt in block.structured_while.body:
                collect_stmt_functions(stmt, env, functions, ir)
    out: list[str] = []
    for (name, _arity), (args, ret) in sorted(functions.items()):
        arg_decls = ", ".join(
            f"a{index}: {boogie_type(arg_ty, arg_dims, ir)}"
            for index, (arg_ty, arg_dims) in enumerate(args)
        )
        out.append(
            f"function {name}({arg_decls}) returns ({boogie_type(ret[0], ret[1], ir)});"
        )
    return out


def program_type_env(program: Any) -> dict[str, tuple[Any, int]]:
    env: dict[str, tuple[Any, int]] = {}
    for decl in [*program.params, *program.returns, *program.locals]:
        env[decl.name] = (decl.ty, decl.dims)
    return env


def collect_stmt_functions(
    stmt: Any,
    env: dict[str, tuple[Any, int]],
    functions: dict[tuple[str, int], tuple[list[tuple[Any, int]], tuple[Any, int]]],
    ir: Any,
) -> None:
    if isinstance(stmt, ir.Assign):
        collect_expr_functions(
            stmt.rhs,
            env.get(stmt.lhs, (ir.Ty.INT, 0)),
            env,
            functions,
            ir,
        )
        return
    if isinstance(stmt, ir.ArrayAssign):
        for index in stmt.indices:
            collect_expr_functions(index, (ir.Ty.INT, 0), env, functions, ir)
        collect_expr_functions(stmt.rhs, (ir.Ty.INT, 0), env, functions, ir)
        return
    if isinstance(stmt, (ir.Assume, ir.Assert)):
        collect_expr_functions(stmt.expr, (ir.Ty.BOOL, 0), env, functions, ir)
        return
    if isinstance(stmt, ir.Call):
        for arg in stmt.args:
            collect_expr_functions(arg, None, env, functions, ir)


def collect_expr_functions(
    expr: Any,
    expected: tuple[Any, int] | None,
    env: dict[str, tuple[Any, int]],
    functions: dict[tuple[str, int], tuple[list[tuple[Any, int]], tuple[Any, int]]],
    ir: Any,
) -> None:
    if isinstance(expr, (ir.IntLit, ir.BoolLit, ir.Var)):
        return
    if isinstance(expr, ir.FuncApp):
        arg_types = [infer_expr_type(arg, env, ir) for arg in expr.args]
        key = (expr.name, len(expr.args))
        functions.setdefault(key, (arg_types, expected or (ir.Ty.INT, 0)))
        for arg, arg_type in zip(expr.args, arg_types):
            collect_expr_functions(arg, arg_type, env, functions, ir)
        return
    if isinstance(expr, ir.BinExpr):
        if expr.op in (ir.BinOp.AND, ir.BinOp.OR, ir.BinOp.IMPLIES):
            lhs_expected = rhs_expected = (ir.Ty.BOOL, 0)
        else:
            lhs_expected = rhs_expected = (ir.Ty.INT, 0)
        collect_expr_functions(expr.lhs, lhs_expected, env, functions, ir)
        collect_expr_functions(expr.rhs, rhs_expected, env, functions, ir)
        return
    if isinstance(expr, ir.NotExpr):
        collect_expr_functions(expr.inner, (ir.Ty.BOOL, 0), env, functions, ir)
        return
    if isinstance(expr, ir.IteExpr):
        collect_expr_functions(expr.cond, (ir.Ty.BOOL, 0), env, functions, ir)
        collect_expr_functions(expr.then_, expected, env, functions, ir)
        collect_expr_functions(expr.else_, expected, env, functions, ir)
        return
    if isinstance(expr, ir.ArrayRead):
        collect_expr_functions(expr.base, None, env, functions, ir)
        collect_expr_functions(expr.index, (ir.Ty.INT, 0), env, functions, ir)


def infer_expr_type(expr: Any, env: dict[str, tuple[Any, int]], ir: Any) -> tuple[Any, int]:
    if isinstance(expr, ir.BoolLit):
        return (ir.Ty.BOOL, 0)
    if isinstance(expr, ir.Var):
        return env.get(expr.name, (ir.Ty.INT, 0))
    if isinstance(expr, ir.BinExpr) and expr.op in (
        ir.BinOp.EQ,
        ir.BinOp.NEQ,
        ir.BinOp.LT,
        ir.BinOp.LE,
        ir.BinOp.GT,
        ir.BinOp.GE,
        ir.BinOp.AND,
        ir.BinOp.OR,
        ir.BinOp.IMPLIES,
    ):
        return (ir.Ty.BOOL, 0)
    if isinstance(expr, ir.NotExpr):
        return (ir.Ty.BOOL, 0)
    if isinstance(expr, ir.IteExpr):
        return infer_expr_type(expr.then_, env, ir)
    return (ir.Ty.INT, 0)


def boogie_type(ty: Any, dims: int, ir: Any) -> str:
    if ty == ir.Ty.BOOL:
        return "bool"
    if ty == ir.Ty.INT_MAP:
        if dims <= 0:
            dims = 1
        return f"[{', '.join(['int'] * dims)}]int"
    return "int"


def ensure_diffprod_package_on_path() -> bool:
    try:
        from diffprod import bpl_emit  # noqa: F401

        return True
    except ImportError:
        sys.modules.pop("diffprod", None)

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "diffprod" / "diffprod" / "boogie_bridge.py"
        if candidate.exists():
            package_root = str(parent / "diffprod")
            if package_root not in sys.path:
                sys.path.insert(0, package_root)
            try:
                from diffprod import bpl_emit  # noqa: F401

                return True
            except ImportError:
                sys.modules.pop("diffprod", None)
                continue
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
