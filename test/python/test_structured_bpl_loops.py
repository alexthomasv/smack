import json
import re
import shutil
import subprocess
import sys

import pytest
from smack_test_paths import (
    BOOGIE_PARSER_ROOT,
    REPO_ROOT,
    run_with_timeout,
    tool_path,
)

sys.path.insert(0, str(BOOGIE_PARSER_ROOT))
from interpreter.parser.boogie_parser import parse_boogie


def matching_llvm_tool(name):
    version = subprocess.run(
        [tool_path("llvm2bpl"), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ).stdout
    match = re.search(r"LLVM version (\d+)", version)
    assert match, version
    path = shutil.which(f"{name}-{match.group(1)}")
    assert path, f"{name} for {version.strip()} not found"
    return path


def compile_c_to_linked_bc(tmp_path, name, source):
    src = tmp_path / f"{name}.c"
    bc = tmp_path / f"{name}.bc"
    runtime_bc = tmp_path / f"{name}-smack-runtime.bc"
    linked = tmp_path / f"{name}-linked.bc"
    src.write_text(source)
    run_with_timeout(
        [
            matching_llvm_tool("clang"),
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            str(src),
            "-o",
            str(bc),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    run_with_timeout(
        [
            matching_llvm_tool("clang"),
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            f"-I{REPO_ROOT / 'share' / 'smack' / 'include'}",
            str(REPO_ROOT / "share" / "smack" / "lib" / "smack.c"),
            "-o",
            str(runtime_bc),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    run_with_timeout(
        [matching_llvm_tool("llvm-link"), str(bc), str(runtime_bc), "-o", str(linked)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    return linked


def emit_bpl(tmp_path, name, source, *extra_args):
    linked = compile_c_to_linked_bc(tmp_path, name, source)
    bpl = tmp_path / f"{name}.bpl"
    completed = run_with_timeout(
        [
            tool_path("llvm2bpl"),
            *extra_args,
            f"--bpl={bpl}",
            "--entry-points=f",
            str(linked),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )
    assert completed.returncode == 0, completed.stdout
    return bpl.read_text(), completed.stdout


def emit_paired_product_bpl(tmp_path, name, source, *extra_args):
    left = compile_c_to_linked_bc(tmp_path, f"{name}_left", source)
    right = compile_c_to_linked_bc(tmp_path, f"{name}_right", source)
    left_bpl = tmp_path / f"{name}_left.bpl"
    right_bpl = tmp_path / f"{name}_right.bpl"
    match_json = tmp_path / f"{name}_match.json"
    completed = run_with_timeout(
        [
            tool_path("llvm-diffmatch2bpl"),
            "--left-bc",
            str(left),
            "--right-bc",
            str(right),
            "--left-entry",
            "f",
            "--right-entry",
            "f",
            "--left-bpl",
            str(left_bpl),
            "--right-bpl",
            str(right_bpl),
            "--match-json",
            str(match_json),
            "-entry-points",
            "f",
            *extra_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )
    assert completed.returncode == 0, completed.stdout
    return left_bpl.read_text(), right_bpl.read_text(), completed.stdout


def run_llvm2bpl_on_linked(tmp_path, name, linked, entry_point, *extra_args):
    bpl = tmp_path / f"{name}.bpl"
    return run_with_timeout(
        [
            tool_path("llvm2bpl"),
            *extra_args,
            f"--bpl={bpl}",
            f"--entry-points={entry_point}",
            str(linked),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )


def run_llvm2bpl(tmp_path, name, source, *extra_args):
    linked = compile_c_to_linked_bc(tmp_path, name, source)
    return run_llvm2bpl_on_linked(tmp_path, name, linked, "f", *extra_args)


def assert_structured_boogie(text):
    assert "while (true)" in text
    assert "break;" in text
    assert "assume {:loop_header" in text
    parse_boogie(text)


def test_c_line_metadata_uses_debug_file_directory_not_process_cwd(tmp_path):
    source_dir = tmp_path / "source"
    first_cwd = tmp_path / "first-cwd"
    second_cwd = tmp_path / "second-cwd"
    source_dir.mkdir()
    first_cwd.mkdir()
    second_cwd.mkdir()
    source = source_dir / "relative_source.c"
    source.write_text("int f(int x) {\n  return x + 7;\n}\n")
    bitcode = tmp_path / "relative_source.bc"
    runtime = tmp_path / "smack-runtime.bc"
    linked = tmp_path / "relative_source-linked.bc"

    run_with_timeout(
        [
            matching_llvm_tool("clang"),
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            source.name,
            "-o",
            str(bitcode),
        ],
        cwd=source_dir,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    run_with_timeout(
        [
            matching_llvm_tool("clang"),
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            f"-I{REPO_ROOT / 'share' / 'smack' / 'include'}",
            str(REPO_ROOT / "share" / "smack" / "lib" / "smack.c"),
            "-o",
            str(runtime),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    run_with_timeout(
        [
            matching_llvm_tool("llvm-link"),
            str(bitcode),
            str(runtime),
            "-o",
            str(linked),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )

    outputs = []
    for index, cwd in enumerate((first_cwd, second_cwd)):
        bpl = tmp_path / f"cwd-{index}.bpl"
        completed = run_with_timeout(
            [
                tool_path("llvm2bpl"),
                f"--bpl={bpl}",
                "--entry-points=f",
                "--source-loc-syms",
                str(linked),
            ],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout_name="SMACK_TOOL",
            default_timeout=120,
        )
        assert completed.returncode == 0, completed.stdout
        outputs.append(bpl.read_text())

    c_line = '{:c_line "return x + 7;"}'
    assert c_line in outputs[0]
    assert c_line in outputs[1]
    assert [line for line in outputs[0].splitlines() if "{:c_line" in line] == [
        line for line in outputs[1].splitlines() if "{:c_line" in line
    ]


def test_structured_bpl_loops_are_opt_in(tmp_path):
    source = """
int f(int n) {
  int i = 0;
  int s = 0;
  while (i < n) {
    s += i;
    i++;
  }
  return s;
}
"""
    flat, _ = emit_bpl(tmp_path, "flat", source)
    paired_flat, _, _ = emit_paired_product_bpl(tmp_path, "paired_flat", source)
    structured, _, log = emit_paired_product_bpl(
        tmp_path, "structured", source, "--structured-bpl-loops-strict"
    )
    rejected = run_llvm2bpl(tmp_path, "single_rejected", source, "--structured-bpl-loops")

    assert "while (true)" not in flat
    assert "while (true)" not in paired_flat
    assert rejected.returncode != 0
    assert "structured-bpl-loops" in rejected.stdout
    assert "SMACK structured Boogie loop" in log
    assert_structured_boogie(structured)


def test_structured_bpl_loop_driver_flag_requires_product_mode(tmp_path):
    source = tmp_path / "single.c"
    source.write_text("int f(int x) { return x; }\n")

    completed = run_with_timeout(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(REPO_ROOT / 'share')!r}); "
                "from smack import top; "
                "sys.argv = ['smack', "
                "'--diff-product-structured-bpl-loops', "
                "sys.argv[1]]; "
                "top.arguments()"
            ),
            str(source),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="PYTHON",
        default_timeout=30,
    )

    assert completed.returncode != 0
    assert "only valid in --diff-product or --product-mode" in completed.stdout


def test_llvm2bpl_pipeline_report_records_phases(tmp_path):
    source = "int f(int x) { return x + 1; }\n"
    report = tmp_path / "pipeline-report.json"
    completed = run_llvm2bpl(
        tmp_path,
        "pipeline_report",
        source,
        f"--smack-pipeline-report={report}",
    )

    assert completed.returncode == 0, completed.stdout
    data = json.loads(report.read_text())
    assert data["schema_version"] == 1
    assert data["llvm_version"]
    assert data["pipeline"] in {"legacy", "newpm"}
    assert data["input"].endswith("pipeline_report-linked.bc")
    assert data["outputs"]["bpl"].endswith("pipeline_report.bpl")
    assert data["outputs"]["ll"] is None
    assert data["options"]["modular"] is False
    assert data["options"]["static_unroll"] is False
    phase_names = [phase["name"] for phase in data["phases"]]
    assert "parse-ir" in phase_names
    if data["pipeline"] == "newpm":
        assert "newpm-full" in phase_names
        assert data["passes"]
    else:
        assert "pre-bpl" in phase_names
    assert all(phase["wall_ms"] >= 0 for phase in data["phases"])
    assert isinstance(data["passes"], list)


def test_llvm2bpl_default_memory_partitioner_is_svf_andersen(tmp_path):
    source = "int f(int *p) { return *p; }\n"
    linked = compile_c_to_linked_bc(tmp_path, "default_memory_partitioner", source)
    report = tmp_path / "default_memory_partitioner.memory.json"

    completed = run_llvm2bpl_on_linked(
        tmp_path,
        "default_memory_partitioner",
        linked,
        "f",
        f"--smack-memory-partition-report={report}",
    )

    assert completed.returncode == 0, completed.stdout
    text = (tmp_path / "default_memory_partitioner.bpl").read_text()
    parse_boogie(text)
    data = json.loads(report.read_text())
    assert data["partitioner"] == "svf-andersen"
    assert data["dsa_mode"] == "svf-andersen"
    assert data["region_count"] >= 1
    assert data["svf_field_windows"] is False
    assert data["windowed_region_count"] == 0
    assert data["split_component_count"] == 0
    assert data["svf_noalias_seed_count"] == 0


def test_llvm2bpl_memory_partition_report_records_regions(tmp_path):
    source = """
#include <stdlib.h>
struct Cell {
  int value;
};
int f(int x) {
  struct Cell *cell = malloc(sizeof(struct Cell));
  cell->value = x + 1;
  return cell->value;
}
"""
    report = tmp_path / "memory-partition-report.json"
    completed = run_llvm2bpl(
        tmp_path,
        "memory_report",
        source,
        f"--smack-memory-partition-report={report}",
    )

    assert completed.returncode == 0, completed.stdout
    data = json.loads(report.read_text())
    assert data["schema_version"] == 2
    assert data["llvm_version"]
    assert data["pipeline"] in {"legacy", "newpm"}
    assert data["partitioner"] == "svf-andersen"
    assert data["dsa_mode"] == "svf-andersen"
    assert data["region_count"] > 0
    assert data["memory_access_count"] > 0
    assert data["svf_field_windows"] is False
    assert data["windowed_region_count"] == 0
    assert data["split_component_count"] == 0
    assert data["svf_noalias_seed_count"] == 0
    assert set(data["regions"]) == {
        "singleton",
        "allocated",
        "bytewise",
        "incomplete",
        "complicated",
        "collapsed",
        "typed",
        "untyped",
    }
    assert all(value >= 0 for value in data["regions"].values())
    assert isinstance(data["fallback_reasons"], list)


@pytest.mark.parametrize(
    "name, source, min_while_count",
    [
        (
            "nested",
            """
int f(int n) {
  int i = 0;
  int s = 0;
  while (i < n) {
    int j = 0;
    while (j < i) {
      s += j;
      j++;
    }
    i++;
  }
  return s;
}
""",
            2,
        ),
        (
            "continue_loop",
            """
int f(int n) {
  int i = 0;
  int s = 0;
  while (i < n) {
    i++;
    if (i == 3) continue;
    s += i;
  }
  return s;
}
""",
            1,
        ),
        (
            "break_loop",
            """
int f(int n) {
  int i = 0;
  int s = 0;
  while (i < n) {
    if (i == 3) break;
    s += i;
    i++;
  }
  return s;
}
""",
            1,
        ),
        (
            "branchy_loop",
            """
int f(int n) {
  int i = 0;
  int s = 0;
  while (i < n) {
    if ((i & 1) == 0) {
      s += i;
    } else {
      s -= i;
    }
    i++;
  }
  return s;
}
""",
            1,
        ),
    ],
)
def test_structured_bpl_loops_handle_common_reducible_shapes(
    tmp_path, name, source, min_while_count
):
    structured, _, _ = emit_paired_product_bpl(
        tmp_path, name, source, "--structured-bpl-loops-strict"
    )

    assert structured.count("while (true)") >= min_while_count
    assert_structured_boogie(structured)
