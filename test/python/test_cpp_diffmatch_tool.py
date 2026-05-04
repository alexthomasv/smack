import json
import os
import shutil
import subprocess

import pytest


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
    candidates = [
        "/usr/lib/llvm-22/bin/clang-22",
        shutil.which("clang-22"),
        shutil.which("clang"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    pytest.skip("clang not found")


def llvm_link_path():
    candidates = [
        "/usr/lib/llvm-22/bin/llvm-link-22",
        shutil.which("llvm-link-22"),
        shutil.which("llvm-link"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    pytest.skip("llvm-link not found")


def compile_c_to_bc(tmp_path, name, source):
    src = tmp_path / f"{name}.c"
    bc = tmp_path / f"{name}.bc"
    src.write_text(source)
    subprocess.run(
        [
            clang_path(),
            "-c",
            "-emit-llvm",
            "-O0",
            "-g",
            "-gcolumn-info",
            "-Xclang",
            "-disable-O0-optnone",
            "-o",
            str(bc),
            str(src),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return bc


def compile_support_lib_to_bc(tmp_path, lib_name):
    source = f"/home/ubuntu/boogie-parser/smack/share/smack/lib/{lib_name}"
    bc = tmp_path / f"{lib_name}.bc"
    subprocess.run(
        [
            clang_path(),
            "-c",
            "-emit-llvm",
            "-O0",
            "-g",
            "-gcolumn-info",
            "-Wno-error=implicit-function-declaration",
            "-Wno-error=implicit-int",
            "-Wno-error=int-conversion",
            "-Wno-error=incompatible-pointer-types",
            "-Xclang",
            "-disable-O0-optnone",
            "-I/home/ubuntu/boogie-parser/smack/share/smack/include",
            "-DMEMORY_MODEL_NO_REUSE_IMPLS",
            "-o",
            str(bc),
            source,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return bc


def link_with_smack_support(tmp_path, name, bc):
    linked = tmp_path / f"{name}-linked.bc"
    support = [
        compile_support_lib_to_bc(tmp_path, "smack.c"),
        compile_support_lib_to_bc(tmp_path, "stdlib.c"),
        compile_support_lib_to_bc(tmp_path, "errno.c"),
        compile_support_lib_to_bc(tmp_path, "smack-rust.c"),
    ]
    subprocess.run(
        [llvm_link_path(), "-o", str(linked), str(bc), *map(str, support)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return linked


def run_diffmatch(tmp_path, extra_args=None):
    left_bc = compile_c_to_bc(
        tmp_path,
        "left",
        "int f(int x) {\n  int y = x + 0;\n  return y + 1;\n}\n",
    )
    right_bc = compile_c_to_bc(
        tmp_path,
        "right",
        "int f(int x) {\n  int y = x - 0;\n  return y + 1;\n}\n",
    )
    left_linked = link_with_smack_support(tmp_path, "left", left_bc)
    right_linked = link_with_smack_support(tmp_path, "right", right_bc)
    left_bpl = tmp_path / "left.bpl"
    right_bpl = tmp_path / "right.bpl"
    match_json = tmp_path / "match.json"
    cmd = [
        tool_path("llvm-diffmatch2bpl"),
        "--left-bc",
        str(left_linked),
        "--right-bc",
        str(right_linked),
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
        "-warn-type",
        "silent",
        "-sea-dsa=ci",
        "-source-loc-syms",
        "-provenance-syms",
        "-entry-points",
        "f",
    ]
    if extra_args:
        cmd.extend(extra_args)
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout
    assert left_bpl.exists()
    assert right_bpl.exists()
    assert match_json.exists()
    return left_bpl, right_bpl, json.loads(match_json.read_text())


def test_cpp_diffmatch2bpl_emits_bpl_and_match_json_without_ll_by_default(tmp_path):
    left_bpl, right_bpl, match = run_diffmatch(tmp_path)

    assert "procedure" in left_bpl.read_text()
    assert "procedure" in right_bpl.read_text()
    assert match["source"] == "smack-cpp"
    assert match["chunks"]
    assert match["stats"]["left_blocks"] >= 1
    assert match["stats"]["right_blocks"] >= 1
    assert match["stats"]["left_instructions"] >= 1
    assert match["stats"]["right_instructions"] >= 1
    assert match["stats"]["matcher_ms"] >= 0
    assert not (tmp_path / "left.ll").exists()
    assert not (tmp_path / "right.ll").exists()


def test_cpp_diffmatch2bpl_dumps_ll_only_when_requested(tmp_path):
    run_diffmatch(
        tmp_path,
        [
            "--left-ll",
            str(tmp_path / "left.ll"),
            "--right-ll",
            str(tmp_path / "right.ll"),
        ],
    )

    assert "define" in (tmp_path / "left.ll").read_text()
    assert "define" in (tmp_path / "right.ll").read_text()
