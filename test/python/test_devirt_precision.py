import json
import re
import shutil
import subprocess

from smack_test_paths import (
    REPO_ROOT,
    run_with_timeout,
    tool_path,
)


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

def compile_source_to_linked_bc(tmp_path, name, source, *, cxx=False):
    suffix = "cpp" if cxx else "c"
    src = tmp_path / f"{name}.{suffix}"
    bc = tmp_path / f"{name}.bc"
    runtime_bc = tmp_path / f"{name}-smack-runtime.bc"
    linked = tmp_path / f"{name}-linked.bc"
    src.write_text(source)

    compiler = matching_llvm_tool("clang++" if cxx else "clang")
    cmd = [
        compiler,
        "-O0",
        "-g",
        "-emit-llvm",
        "-c",
        str(src),
        "-o",
        str(bc),
    ]
    if cxx:
        cmd.insert(1, "-fno-exceptions")
        cmd.insert(2, "-fno-rtti")
    run_with_timeout(
        cmd,
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


def run_with_devirt_report(tmp_path, name, source, *, entry="f", cxx=False):
    linked = compile_source_to_linked_bc(tmp_path, name, source, cxx=cxx)
    report = tmp_path / f"{name}.devirt.json"
    bpl = tmp_path / f"{name}.bpl"
    completed = run_with_timeout(
        [
            tool_path("llvm2bpl"),
            f"-smack-devirt-report={report}",
            f"--bpl={bpl}",
            f"--entry-points={entry}",
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
    return json.loads(report.read_text())


def emit_devirt(tmp_path, name, linked, *, entry="f"):
    report = tmp_path / f"{name}.devirt.json"
    output = tmp_path / f"{name}.devirt.bc"
    completed = run_with_timeout(
        [
            tool_path("llvm2bpl"),
            str(linked),
            f"-emit-devirt-bc={output}",
            f"-smack-devirt-report={report}",
            f"-entry-points={entry}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )
    assert completed.returncode == 0, completed.stdout
    return json.loads(report.read_text()), output


def disassemble(bitcode):
    completed = run_with_timeout(
        [matching_llvm_tool("llvm-dis"), str(bitcode), "-o", "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout_name="LLVM",
        default_timeout=60,
    )
    return completed.stdout


def test_devirt_report_resolves_constant_function_pointer_table(tmp_path):
    source = """
typedef int (*fp_t)(int);
int only(int x) { return x + 1; }
int other(int x) { return x + 2; }
volatile int choose;
fp_t noise = other;
static fp_t const table[1] = { only };
int f(int x) {
  if (choose) return noise(x);
  return table[0](x);
}
"""
    data = run_with_devirt_report(tmp_path, "fp_table", source)

    assert data["schema_version"] == 3
    assert all("callsite_id" in call for call in data["callsites"])
    assert any(
        call["complete"]
        and call["target_count"] == 1
        and call["targets"] == ["only"]
        and call["reason"] == "svf-complete"
        for call in data["callsites"]
    ), data


def test_devirt_falls_back_for_external_function_pointer_source(tmp_path):
    source = """
typedef int (*fp_t)(int);
extern fp_t unknown_fp(void);
int only(int x) { return x + 1; }
int other(int x) { return x + 2; }
fp_t keep = other;
fp_t keep2 = only;
int f(int x) {
  if (x == 12345) return keep(x);
  if (x == 54321) return keep2(x);
  fp_t p = unknown_fp();
  return p(x);
}
"""
    data = run_with_devirt_report(tmp_path, "fp_external_source", source)

    assert any(
        not call["complete"]
        and call["flta"]
        and call["target_count"] >= 2
        and call["reason"].startswith("flta:")
        for call in data["callsites"]
    ), data


def test_devirt_resolves_cpp_vtable_slot_without_same_signature_noise(tmp_path):
    source = """
struct Base {
  virtual int value() { return 1; }
};
struct Derived : Base {
  int value() override { return 2; }
};
extern "C" int other(Base *b) { return b ? 3 : 4; }
using Raw = int (*)(Base *);
Raw keep = other;
extern "C" int f(int c) {
  Base base;
  Derived derived;
  Base *b = c ? &base : &derived;
  return b->value();
}
"""
    data = run_with_devirt_report(tmp_path, "cpp_vtable", source, cxx=True)

    virtual_calls = [
        call
        for call in data["callsites"]
        if call["complete"] and any("value" in target for target in call["targets"])
    ]
    assert virtual_calls, data
    assert all("other" not in target for call in virtual_calls for target in call["targets"])
    assert any(call["target_count"] <= 2 for call in virtual_calls)


def test_devirt_report_indices_are_local_to_each_function(tmp_path):
    source = """
typedef int (*fp_t)(int);
int left(int x) { return x + 1; }
int right(int x) { return x + 2; }
fp_t left_slot = left;
fp_t right_slot = right;
int f(int x) { return left_slot(x); }
int g(int x) { return right_slot(x); }
"""
    linked = compile_source_to_linked_bc(tmp_path, "function_local_ids", source)
    data, _ = emit_devirt(tmp_path, "function_local_ids", linked)
    ids = {call["callsite_id"] for call in data["callsites"]}
    assert "f:indirect:0" in ids
    assert "g:indirect:0" in ids


def test_devirt_declines_returns_twice_target_and_translation_fails_closed(tmp_path):
    source = """
typedef int (*fp_t)(void *);
extern int __attribute__((returns_twice)) rt(void *);
fp_t slot = rt;
int f(void *env) { return slot(env); }
"""
    linked = compile_source_to_linked_bc(tmp_path, "returns_twice", source)
    data, output = emit_devirt(tmp_path, "returns_twice", linked)
    call = next(call for call in data["callsites"] if call["function"] == "f")
    assert call["reason"] == "unsupported-target:returns-twice:rt"
    assert not call["complete"]
    assert "devirtbounce" not in disassemble(output)

    completed = run_with_timeout(
        [
            tool_path("llvm2bpl"),
            str(linked),
            "--entry-points=f",
            f"--bpl={tmp_path / 'returns_twice.bpl'}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )
    assert completed.returncode != 0
    assert "cannot soundly translate returns_twice control flow" in completed.stdout


def test_devirt_declines_invoke_instead_of_swallowing_exception_state(tmp_path):
    source = tmp_path / "indirect_invoke.ll"
    source.write_text(
        r"""
target triple = "x86_64-unknown-linux-gnu"

@slot = global ptr @target

declare i32 @__gxx_personality_v0(...)

define i32 @target() {
entry:
  ret i32 7
}

define i32 @f() personality ptr @__gxx_personality_v0 {
entry:
  %callee = load ptr, ptr @slot
  %value = invoke i32 %callee()
          to label %normal unwind label %exception
normal:
  ret i32 %value
exception:
  %landing = landingpad { ptr, i32 } cleanup
  ret i32 -1
}
"""
    )
    data, output = emit_devirt(tmp_path, "indirect_invoke", source)
    call = next(call for call in data["callsites"] if call["function"] == "f")
    assert call["reason"] == "unsupported-callsite:invoke"
    assert not call["complete"]
    ir = disassemble(output)
    assert "invoke i32 %callee()" in ir
    assert "devirtbounce" not in ir


def test_devirt_declines_caller_sensitive_target(tmp_path):
    source = """
typedef void *(*fp_t)(void);
void *target(void) { return __builtin_return_address(0); }
fp_t slot = target;
void *f(void) { return slot(); }
"""
    linked = compile_source_to_linked_bc(tmp_path, "caller_sensitive", source)
    data, output = emit_devirt(tmp_path, "caller_sensitive", linked)
    call = next(call for call in data["callsites"] if call["function"] == "f")
    assert call["reason"] == "unsupported-target:caller-sensitive:target"
    assert not call["complete"]
    assert "devirtbounce" not in disassemble(output)


def test_devirt_does_not_rewrite_its_residual_calls(tmp_path):
    source = """
typedef int (*fp_t)(int);
int target(int x) { return x + 1; }
fp_t slot = target;
int f(int x) { return slot(x); }
"""
    linked = compile_source_to_linked_bc(tmp_path, "idempotent", source)
    _, first = emit_devirt(tmp_path, "idempotent_first", linked)
    _, second = emit_devirt(tmp_path, "idempotent_second", first)
    first_ir = disassemble(first)
    second_ir = disassemble(second)
    assert len(re.findall(r"define internal .*@devirtbounce", first_ir)) == 1
    assert len(re.findall(r"define internal .*@devirtbounce", second_ir)) == 1
