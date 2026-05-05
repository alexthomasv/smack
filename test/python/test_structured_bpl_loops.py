import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, "/home/ubuntu/boogie-parser")
from interpreter.parser.boogie_parser import parse_boogie


def tool_path(name):
    candidates = [
        f"/home/ubuntu/boogie-parser/smack/build-llvm22c/{name}",
        shutil.which(name),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    pytest.skip(f"{name} not found")


def clang_path():
    candidates = [shutil.which("clang-22"), shutil.which("clang")]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    pytest.skip("clang not found")


def llvm_link_path():
    candidates = [shutil.which("llvm-link-22"), shutil.which("llvm-link")]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    pytest.skip("llvm-link not found")


def compile_c_to_linked_bc(tmp_path, name, source):
    src = tmp_path / f"{name}.c"
    bc = tmp_path / f"{name}.bc"
    runtime_bc = tmp_path / f"{name}-smack-runtime.bc"
    linked = tmp_path / f"{name}-linked.bc"
    src.write_text(source)
    subprocess.run(
        [
            clang_path(),
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
    )
    subprocess.run(
        [
            clang_path(),
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            "-I/home/ubuntu/boogie-parser/smack/share/smack/include",
            "/home/ubuntu/boogie-parser/smack/share/smack/lib/smack.c",
            "-o",
            str(runtime_bc),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        [llvm_link_path(), str(bc), str(runtime_bc), "-o", str(linked)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return linked


def emit_bpl(tmp_path, name, source, *extra_args):
    linked = compile_c_to_linked_bc(tmp_path, name, source)
    bpl = tmp_path / f"{name}.bpl"
    completed = subprocess.run(
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
    )
    assert completed.returncode == 0, completed.stdout
    return bpl.read_text(), completed.stdout


def emit_paired_product_bpl(tmp_path, name, source, *extra_args):
    left = compile_c_to_linked_bc(tmp_path, f"{name}_left", source)
    right = compile_c_to_linked_bc(tmp_path, f"{name}_right", source)
    left_bpl = tmp_path / f"{name}_left.bpl"
    right_bpl = tmp_path / f"{name}_right.bpl"
    match_json = tmp_path / f"{name}_match.json"
    completed = subprocess.run(
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
    )
    assert completed.returncode == 0, completed.stdout
    return left_bpl.read_text(), right_bpl.read_text(), completed.stdout


def run_llvm2bpl(tmp_path, name, source, *extra_args):
    linked = compile_c_to_linked_bc(tmp_path, name, source)
    bpl = tmp_path / f"{name}.bpl"
    return subprocess.run(
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
    )


def assert_structured_boogie(text):
    assert "while (true)" in text
    assert "break;" in text
    assert "assume {:loop_header" in text
    parse_boogie(text)


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
    rejected = run_llvm2bpl(
        tmp_path, "single_rejected", source, "--structured-bpl-loops"
    )

    assert "while (true)" not in flat
    assert "while (true)" not in paired_flat
    assert rejected.returncode != 0
    assert "structured-bpl-loops" in rejected.stdout
    assert "SMACK structured Boogie loop" in log
    assert_structured_boogie(structured)


def test_structured_bpl_loop_driver_flag_requires_product_mode(tmp_path):
    source = tmp_path / "single.c"
    source.write_text("int f(int x) { return x; }\n")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.path.insert(0, '/home/ubuntu/boogie-parser/smack/share'); "
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
    )

    assert completed.returncode != 0
    assert "only valid in --diff-product or --product-mode" in completed.stdout


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
