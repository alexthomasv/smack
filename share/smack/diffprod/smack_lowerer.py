from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .provenance import ParsedBoogieProgram, boogie_classes


class UnsupportedSmackBoogie(ValueError):
    """Raised when SMACK Boogie is outside the current product subset."""


def lower_smack_boogie_proc_to_ir(
    parsed: ParsedBoogieProgram,
    proc_name: str | None,
) -> Any:
    """Lower a selected SMACK-generated Boogie procedure to diffprod IR.

    This is deliberately narrower than a general Boogie lowerer. It keeps
    scalar semantics and removes SMACK instrumentation/provenance commands.
    """

    ir = diffprod_ir()
    proc = select_proc(parsed, proc_name)
    type_env = type_aliases(parsed.declarations)

    params = lower_storage_decls(getattr(proc, "parameters", []), type_env, ir)
    returns = lower_storage_decls(getattr(proc, "returns", []), type_env, ir)
    locals_ = lower_storage_decls(getattr(proc.body, "locals", []), type_env, ir)

    blocks: list[Any] = []
    for block in proc.body.blocks:
        block_id = f"proc:{proc.name}:block:{block.name}"
        stmts: list[Any] = []
        transfer = ir.Transfer(ir.TransferKind.RETURN, [])
        raw_stmts = list(block.statements)
        for stmt_index, stmt in enumerate(raw_stmts):
            stmt_id = f"{block_id}:stmt:{stmt_index}"
            lowered = lower_smack_stmt(stmt, stmt_id, parsed, ir)
            if lowered == "skip":
                continue
            if lowered == "return":
                transfer = ir.Transfer(ir.TransferKind.RETURN, [])
                continue
            if isinstance(lowered, tuple) and lowered[0] == "goto":
                transfer = ir.Transfer(ir.TransferKind.GOTO, lowered[1])
                continue
            stmts.extend(lowered)
        blocks.append(
            ir.Block(
                label=block.name,
                stmts=stmts,
                transfer=transfer,
                meta=ir.NodeMetadata(
                    node_id=block_id,
                    span=to_diffprod_span(
                        parsed.provenance.origin_set(block_id).primary_span(), ir
                    ),
                ),
            )
        )

    if not blocks:
        raise UnsupportedSmackBoogie(f"{proc.name}: body has no blocks")

    return ir.Program(
        name=proc.name,
        params=params,
        returns=returns,
        locals=locals_,
        blocks=blocks,
        entry_label=blocks[0].label,
        meta=ir.NodeMetadata(node_id=f"proc:{proc.name}"),
    )


def lower_smack_stmt(
    stmt: Any,
    stmt_id: str,
    parsed: ParsedBoogieProgram,
    ir: Any,
) -> list[Any] | tuple[str, list[str]] | str:
    classes = boogie_classes()
    meta = ir.NodeMetadata(
        node_id=stmt_id,
        span=to_diffprod_span(parsed.provenance.origin_set(stmt_id).primary_span(), ir),
    )
    line = meta.span.start_line if meta.span is not None else 0

    if isinstance(stmt, classes["AssumeStatement"]):
        if is_true_expr(stmt.expression):
            return "skip"
        return [ir.Assume(lower_expr(stmt.expression, ir), source_line=line, meta=meta)]

    if isinstance(stmt, classes["AssertStatement"]):
        return [ir.Assert(lower_expr(stmt.expression, ir), source_line=line, meta=meta)]

    if isinstance(stmt, classes["AssignStatement"]):
        out: list[Any] = []
        for lhs, rhs in zip(stmt.lhs, stmt.rhs):
            name = storage_name(lhs)
            if name == "$exn" and is_false_expr(rhs):
                continue
            out.append(
                ir.Assign(
                    lhs=name,
                    rhs=lower_expr(rhs, ir),
                    source_line=line,
                    meta=meta,
                )
            )
        return out or "skip"

    if isinstance(stmt, classes["CallStatement"]):
        if is_smack_instrumentation_call(stmt):
            return "skip"
        rets = [storage_name(lhs) for lhs in stmt.assignments]
        return [
            ir.Call(
                rets=rets,
                proc=stmt.procedure.name,
                args=[lower_expr(arg, ir) for arg in stmt.arguments],
                source_line=line,
                meta=meta,
            )
        ]

    if isinstance(stmt, classes["GotoStatement"]):
        return ("goto", [ident.name for ident in stmt.identifiers])

    if isinstance(stmt, classes["ReturnStatement"]):
        if getattr(stmt, "expression", None) is not None:
            raise UnsupportedSmackBoogie(f"{stmt_id}: return with expression")
        return "return"

    if isinstance(stmt, classes["HavocStatement"]):
        return [
            ir.Havoc(
                [ident.name for ident in stmt.identifiers],
                source_line=line,
                meta=meta,
            )
        ]

    raise UnsupportedSmackBoogie(f"{stmt_id}: unsupported {type(stmt).__name__}")


def lower_expr(expr: Any, ir: Any) -> Any:
    classes = boogie_classes()

    if isinstance(expr, classes["IntegerLiteral"]):
        return ir.IntLit(int(expr.value))
    if isinstance(expr, classes["BooleanLiteral"]):
        return ir.BoolLit(bool_value(expr))
    if isinstance(expr, classes["Identifier"]):
        return ir.Var(expr.name)
    if isinstance(expr, classes["LogicalNegation"]):
        return ir.NotExpr(lower_expr(expr.expression, ir))
    if isinstance(expr, classes["ArithmeticNegation"]):
        return ir.BinExpr(ir.BinOp.SUB, ir.IntLit(0), lower_expr(expr.expression, ir))
    if isinstance(expr, classes["BinaryExpression"]):
        return ir.BinExpr(
            lower_binop(expr.op, ir),
            lower_expr(expr.lhs, ir),
            lower_expr(expr.rhs, ir),
        )
    if isinstance(expr, classes["IfExpression"]):
        return ir.IteExpr(
            lower_expr(expr.condition, ir),
            lower_expr(expr.then, ir),
            lower_expr(expr.else_, ir),
        )
    if isinstance(expr, classes["FunctionApplication"]):
        return lower_function_application(expr, ir)
    if isinstance(expr, classes["MapSelect"]):
        base, indexes = flatten_map_select(expr)
        lowered = lower_expr(base, ir)
        for index in indexes:
            lowered = ir.ArrayRead(lowered, lower_expr(index, ir))
        return lowered

    raise UnsupportedSmackBoogie(f"unsupported expression {type(expr).__name__}: {expr}")


def lower_function_application(expr: Any, ir: Any) -> Any:
    name = expr.function.name
    args = [lower_expr(arg, ir) for arg in expr.arguments]
    op = smack_function_binop(name, ir)
    if op is not None and len(args) == 2:
        return ir.BinExpr(op, args[0], args[1])
    if name.startswith("$not.") and len(args) == 1:
        return ir.NotExpr(args[0])
    return ir.FuncApp(name, tuple(args))


def smack_function_binop(name: str, ir: Any) -> Any | None:
    prefixes = {
        "$add.": ir.BinOp.ADD,
        "$sub.": ir.BinOp.SUB,
        "$mul.": ir.BinOp.MUL,
        "$idiv.": ir.BinOp.DIV,
        "$sdiv.": ir.BinOp.DIV,
        "$udiv.": ir.BinOp.DIV,
        "$smod.": ir.BinOp.MOD,
        "$srem.": ir.BinOp.MOD,
        "$urem.": ir.BinOp.MOD,
        "$eq.": ir.BinOp.EQ,
        "$ne.": ir.BinOp.NEQ,
        "$slt.": ir.BinOp.LT,
        "$ult.": ir.BinOp.LT,
        "$sle.": ir.BinOp.LE,
        "$ule.": ir.BinOp.LE,
        "$sgt.": ir.BinOp.GT,
        "$ugt.": ir.BinOp.GT,
        "$sge.": ir.BinOp.GE,
        "$uge.": ir.BinOp.GE,
    }
    for prefix, op in prefixes.items():
        if name.startswith(prefix):
            return op
    return None


def lower_binop(op: str, ir: Any) -> Any:
    mapping = {
        "+": ir.BinOp.ADD,
        "-": ir.BinOp.SUB,
        "*": ir.BinOp.MUL,
        "/": ir.BinOp.DIV,
        "%": ir.BinOp.MOD,
        "==": ir.BinOp.EQ,
        "<==>": ir.BinOp.EQ,
        "!=": ir.BinOp.NEQ,
        "<": ir.BinOp.LT,
        "<=": ir.BinOp.LE,
        ">": ir.BinOp.GT,
        ">=": ir.BinOp.GE,
        "&&": ir.BinOp.AND,
        "||": ir.BinOp.OR,
        "==>": ir.BinOp.IMPLIES,
    }
    if op not in mapping:
        raise UnsupportedSmackBoogie(f"unsupported binary operator {op}")
    return mapping[op]


def is_smack_instrumentation_call(stmt: Any) -> bool:
    name = stmt.procedure.name
    return (
        name == "$initialize"
        or name.startswith("boogie_si_record_")
        or name.startswith("llvm.dbg.")
        or name.startswith("__SMACK_top_decl")
    )


def is_true_expr(expr: Any) -> bool:
    BooleanLiteral = boogie_classes()["BooleanLiteral"]
    return isinstance(expr, BooleanLiteral) and bool_value(expr)


def is_false_expr(expr: Any) -> bool:
    BooleanLiteral = boogie_classes()["BooleanLiteral"]
    return isinstance(expr, BooleanLiteral) and not bool_value(expr)


def bool_value(expr: Any) -> bool:
    value = getattr(expr, "value", False)
    if isinstance(value, str):
        return value == "true"
    return bool(value)


def storage_name(lhs: Any) -> str:
    StorageIdentifier = boogie_classes()["StorageIdentifier"]
    if not isinstance(lhs, StorageIdentifier):
        raise UnsupportedSmackBoogie(f"unsupported lhs {lhs}")
    return lhs.name


def flatten_map_select(expr: Any) -> tuple[Any, list[Any]]:
    MapSelect = boogie_classes()["MapSelect"]
    indexes: list[Any] = []
    cur = expr
    while isinstance(cur, MapSelect):
        indexes = list(cur.indexes) + indexes
        cur = cur.map
    return cur, indexes


def lower_storage_decls(decls: list[Any], type_env: dict[str, Any], ir: Any) -> list[Any]:
    out: list[Any] = []
    for decl in decls:
        ty, dims = lower_type(decl.type, type_env, ir)
        for name in decl.names:
            if name == "$exn":
                continue
            out.append(ir.Param(name, ty, dims=dims))
    return out


def lower_type(type_node: Any, type_env: dict[str, Any], ir: Any) -> tuple[Any, int]:
    from interpreter.parser.type import BooleanType, CustomType, IntegerType, MapType

    if isinstance(type_node, IntegerType):
        return ir.Ty.INT, 0
    if isinstance(type_node, BooleanType):
        return ir.Ty.BOOL, 0
    if isinstance(type_node, MapType):
        range_ty, _ = lower_type(type_node.range, type_env, ir)
        if range_ty not in (ir.Ty.INT, ir.Ty.BOOL):
            raise UnsupportedSmackBoogie(f"unsupported map range type {type_node}")
        return ir.Ty.INT_MAP, len(type_node.domain)
    if isinstance(type_node, CustomType):
        alias = type_env.get(type_node.name)
        if alias is not None:
            return lower_type(alias, type_env, ir)
        if type_node.name == "bool":
            return ir.Ty.BOOL, 0
        if type_node.name == "float":
            raise UnsupportedSmackBoogie("float type is outside scalar integer subset")
        return ir.Ty.INT, 0
    raise UnsupportedSmackBoogie(f"unsupported type {type_node}")


def type_aliases(declarations: list[Any]) -> dict[str, Any]:
    from interpreter.parser.declaration import TypeDeclaration

    return {
        decl.name: decl.type
        for decl in declarations
        if isinstance(decl, TypeDeclaration) and getattr(decl, "type", None) is not None
    }


def select_proc(parsed: ParsedBoogieProgram, proc_name: str | None) -> Any:
    procs = parsed.procedures()
    if proc_name is None:
        if len(procs) == 1:
            return procs[0]
        names = ", ".join(proc.name for proc in procs[:8])
        raise UnsupportedSmackBoogie(f"choose a procedure; candidates: {names}")
    for proc in procs:
        if proc.name == proc_name:
            return proc
    raise UnsupportedSmackBoogie(f"procedure not found: {proc_name}")


def to_diffprod_span(span: Any, ir: Any) -> Any | None:
    if span is None:
        return None
    return ir.SourceSpan(
        file=span.file,
        start_line=span.start_line,
        end_line=span.end_line,
        start_col=span.start_col,
        end_col=span.end_col,
    )


def diffprod_ir() -> Any:
    ensure_diffprod_package_on_path()
    from diffprod import ir

    return ir


def ensure_diffprod_package_on_path() -> None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "diffprod" / "diffprod" / "ir.py"
        if candidate.exists():
            package_root = str(parent / "diffprod")
            if package_root not in sys.path:
                sys.path.insert(0, package_root)
            return
    raise UnsupportedSmackBoogie("diffprod package was not found")
