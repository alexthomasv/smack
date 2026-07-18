"""Unit tests for smack.pipeline.translate."""

import argparse

from smack.cli.results import VProperty
from smack.pipeline import translate
from smack.pipeline.translate import (
    llvm_to_bpl,
    memsafety_subproperty_selection,
    replace_reach_error,
)


def make_args(**overrides):
    defaults = dict(
        bpl_file=None,
        check=VProperty.NONE,
        language="c",
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def make_translate_args(**overrides):
    defaults = dict(
        linked_bc_file="input.bc",
        bpl_file="output.bpl",
        warn="silent",
        provenance_syms=False,
        diff_product_mode=None,
        entry_points=["main"],
        checked_functions=[],
        debug=False,
        debug_only=None,
        ll_file=None,
        mem_mod="no-reuse-impls",
        static_unroll=False,
        integer_encoding="unbounded-integer",
        timing_annotations=False,
        pointer_encoding="integer",
        no_byte_access_inference=False,
        rewrite_bitwise_ops=False,
        no_memory_splitting=False,
        memory_partition_report=None,
        devirt_report=None,
        static_init_zero_memset_threshold=None,
        check=VProperty.NONE,
        fail_on_loop_exit=False,
        llvm_assumes=None,
        float=False,
        modular=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --- replace_reach_error ---


def test_replace_reach_error_skips_non_svcomp(tmp_path):
    bpl = tmp_path / "t.bpl"
    body = "call reach_error();\n"
    bpl.write_text(body)
    replace_reach_error(make_args(bpl_file=str(bpl), language="c"))
    assert bpl.read_text() == body


def test_replace_reach_error_skips_memory_safety(tmp_path):
    bpl = tmp_path / "t.bpl"
    body = "call reach_error();\n"
    bpl.write_text(body)
    replace_reach_error(
        make_args(bpl_file=str(bpl), language="svcomp", check=VProperty.MEMORY_SAFETY)
    )
    assert bpl.read_text() == body


def test_replace_reach_error_skips_memleak(tmp_path):
    bpl = tmp_path / "t.bpl"
    body = "call reach_error();\n"
    bpl.write_text(body)
    replace_reach_error(make_args(bpl_file=str(bpl), language="svcomp", check=VProperty.MEMLEAK))
    assert bpl.read_text() == body


def test_replace_reach_error_skips_integer_overflow(tmp_path):
    bpl = tmp_path / "t.bpl"
    body = "call reach_error();\n"
    bpl.write_text(body)
    replace_reach_error(
        make_args(bpl_file=str(bpl), language="svcomp", check=VProperty.INTEGER_OVERFLOW)
    )
    assert bpl.read_text() == body


def test_replace_reach_error_rewrites_svcomp_assertion(tmp_path):
    bpl = tmp_path / "t.bpl"
    bpl.write_text("procedure foo() { call reach_error(); }\n")
    replace_reach_error(make_args(bpl_file=str(bpl), language="svcomp", check=VProperty.ASSERTIONS))
    assert "assert false; call reach_error();" in bpl.read_text()


# --- memsafety_subproperty_selection ---


def test_memsafety_subproperty_returns_early_if_full_memory_safety(tmp_path):
    # Should not touch the file at all when full MEMORY_SAFETY is requested.
    bpl = tmp_path / "t.bpl"
    body = "  assert {:valid_deref} a == b;\n"
    bpl.write_text(body)
    memsafety_subproperty_selection(make_args(bpl_file=str(bpl), check=VProperty.MEMORY_SAFETY))
    assert bpl.read_text() == body


def test_memsafety_subproperty_keeps_selected_attrs(tmp_path):
    bpl = tmp_path / "t.bpl"
    bpl.write_text("  assert {:valid_deref} a == b;\n")
    memsafety_subproperty_selection(make_args(bpl_file=str(bpl), check=VProperty.VALID_DEREF))
    # Original assertion kept since valid_deref is selected.
    assert "valid_deref" in bpl.read_text()
    assert "a == b" in bpl.read_text()


def test_memsafety_subproperty_replaces_unselected_with_true(tmp_path):
    bpl = tmp_path / "t.bpl"
    bpl.write_text("  assert {:valid_deref} a == b;\n")
    memsafety_subproperty_selection(make_args(bpl_file=str(bpl), check=VProperty.VALID_FREE))
    # valid_deref NOT selected — assertion body becomes `true`.
    out = bpl.read_text()
    assert "true" in out
    assert "a == b" not in out


# --- llvm_to_bpl command assembly ---


def test_llvm_to_bpl_uses_only_universal_memory_options(monkeypatch):
    captured = {}

    def fake_try_command(cmd, console):
        captured["cmd"] = cmd
        captured["console"] = console

    monkeypatch.setattr(translate, "try_command", fake_try_command)
    monkeypatch.setattr(translate, "annotate_bpl", lambda args: None)
    monkeypatch.setattr(translate, "memsafety_subproperty_selection", lambda args: None)
    monkeypatch.setattr(translate, "replace_reach_error", lambda args: None)
    monkeypatch.setattr(translate, "transform_bpl", lambda args: None)

    llvm_to_bpl(
        make_translate_args(
            memory_partition_report="partition.json",
            devirt_report="devirt.json",
        )
    )

    assert captured["console"] is True
    cmd = captured["cmd"]
    assert cmd[cmd.index("-smack-memory-partition-report") + 1] == "partition.json"
    assert cmd[cmd.index("-smack-devirt-report") + 1] == "devirt.json"
    retired = ("sea-dsa", "memory-partitioner", "partition-oracle", "smack-svf")
    assert all(not any(marker in arg for marker in retired) for arg in cmd)
