import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from smack_test_paths import REPO_ROOT, run_with_timeout, tool_path_env

READONLY_NOALIAS_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define internal i32 @read_pair(ptr noalias readonly %a,
                               ptr noalias readonly %b) {
entry:
  %x = load i32, ptr %a, align 4
  %y = load i32, ptr %b, align 4
  %sum = add i32 %x, %y
  ret i32 %sum
}

define void @f(ptr %runtime) {
entry:
  ; Passing the same address to two read-only noalias formals is permitted:
  ; neither access modifies the referenced object. Metadata therefore cannot
  ; certify address separation for SMACK memory maps.
  %unused = call i32 @read_pair(ptr %runtime, ptr %runtime)
  ret void
}
"""


ENTRY_DISJOINT_CONTRACT_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define void @f(ptr noalias %left, ptr noalias %right) {
entry:
  ; For the selected entrypoint only, the verification harness interprets
  ; noalias as a closed-input contract: these are separate top-level buffers.
  store volatile i8 1, ptr %left, align 1
  %value = load volatile i8, ptr %right, align 1
  ret void
}
"""


ENTRY_DISJOINT_WITH_UNCALLED_UNKNOWN_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define internal void @uncalled_objectless(ptr %p) {
entry:
  %value = load volatile i8, ptr %p, align 1
  ret void
}

define void @f(ptr noalias %left, ptr noalias %right) {
entry:
  store volatile i8 1, ptr %left, align 1
  %value = load volatile i8, ptr %right, align 1
  ret void
}
"""


ENTRY_DERIVED_POINTER_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define void @f(ptr noalias %left, ptr noalias %right) {
entry:
  store volatile i8 1, ptr %left, align 1
  %left.next = getelementptr inbounds i8, ptr %left, i64 1
  store volatile i8 2, ptr %left.next, align 1
  %right.value = load volatile i8, ptr %right, align 1
  ret void
}
"""


ENTRY_DISJOINT_WITH_RAW_ALLOCA_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define void @f(ptr noalias %input) {
entry:
  %local = alloca i8, align 1
  store volatile i8 1, ptr %input, align 1
  store volatile i8 2, ptr %local, align 1
  ret void
}
"""


VALUE_RESULT_USED_AS_ADDRESS_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

declare ptr @__SMACK_value(...)

define void @f(ptr noalias %input) {
entry:
  %arbitrary = call ptr (ptr, ...) @__SMACK_value(ptr %input)
  store volatile i8 1, ptr %arbitrary, align 1
  ret void
}
"""


COALESCIBLE_CONSTANT_DERIVED_POINTER_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = private unnamed_addr constant [2 x i8] [i8 1, i8 2]
@right = private unnamed_addr constant [2 x i8] [i8 3, i8 4]

define void @f() {
entry:
  %left.first = load volatile i8, ptr @left, align 1
  %left.second.ptr = getelementptr inbounds [2 x i8], ptr @left, i64 0, i64 1
  %left.second = load volatile i8, ptr %left.second.ptr, align 1
  %right.first = load volatile i8, ptr @right, align 1
  ret void
}
"""


LIVE_UNRESOLVED_FALSE_PROOF_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = private global i32 0
@ext = external global i32

declare void @__VERIFIER_assert(i32)

define void @f(i1 %choose, i64 %addr) {
entry:
  store i32 0, ptr @ext, align 4
  %unknown = inttoptr i64 %addr to ptr
  %selected = select i1 %choose, ptr @known, ptr %unknown
  ; Keep the store in this procedure: an intervening call's modifies-all frame
  ; would mask the cross-map false proof that this witness is meant to expose.
  store i32 7, ptr %selected, align 4
  %value = load i32, ptr @ext, align 4
  %unchanged = icmp eq i32 %value, 0
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


INITIALIZER_POINTER_SLOT_FALSE_PROOF_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@slot = internal global ptr @left

declare void @__VERIFIER_assert(i32)

define void @f() {
entry:
  ; SMACK inserts a modular call to $initialize before this code. Its summary
  ; has no postcondition fixing @slot to @left, so after that call the Boogie
  ; value loaded from @slot can equal @right even though Andersen sees only the
  ; LLVM initializer. Separate maps would then falsely make this store unable
  ; to change the two @right reads.
  %right.before = load volatile i8, ptr @right, align 1
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


MALLOC_RETURN_FALSE_PROOF_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@right = internal global i8 0

declare ptr @malloc(i64)
declare void @__VERIFIER_assert(i32)

define void @f() {
entry:
  ; The generated malloc wrapper's Boogie signature does not constrain its
  ; return value. Capture @right after the call so the wrapper's modifies frame
  ; cannot by itself mask whether the returned pointer aliases @right.
  %allocated = call ptr @malloc(i64 1)
  %right.before = load volatile i8, ptr @right, align 1
  store volatile i8 7, ptr %allocated, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


ALLOCA_RETURN_FALSE_PROOF_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@right = internal global i8 0

declare void @__VERIFIER_assert(i32)

define void @f() {
entry:
  ; SMACK lowers alloca to a modular $alloc call whose result has no freshness
  ; postcondition. In the generated Boogie model %local can equal @right.
  %local = alloca i8, align 1
  %right.before = load volatile i8, ptr @right, align 1
  store volatile i8 7, ptr %local, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


TYPE_PUNNED_POINTER_LOAD_FALSE_PROOF_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@slot = internal global i64 0, align 8

declare void @__VERIFIER_assert(i32)

define void @seed_left() {
entry:
  ; The declared global type contains no pointer, but opaque pointers permit
  ; storing one into its eight bytes. This gives Andersen the known @left seed.
  store ptr @left, ptr @slot, align 8
  ret void
}

define void @f() {
entry:
  %right.before = load volatile i8, ptr @right, align 1
  ; $initialize has no postcondition for these bytes, so this Boogie ref value
  ; is arbitrary even though the flow-insensitive LLVM seed says only @left.
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}

define void @__SMACK_static_init() {
entry:
  store i8 0, ptr @left, align 1
  store i8 0, ptr @right, align 1
  store i64 0, ptr @slot, align 8
  ret void
}
"""


FREE_HAVOCS_POINTER_STORAGE_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@slot.bytes = internal global [8 x i8] zeroinitializer, align 8

declare void @free(ptr)
declare void @__VERIFIER_assert(i32)

define void @f() {
entry:
  ; Use byte-typed storage so this witness does not rely on a pointer-valued
  ; global initializer. The modular free wrapper may havoc the slot's map.
  store ptr @left, ptr @slot.bytes, align 8
  call void @free(ptr null)
  %right.before = load volatile i8, ptr @right, align 1
  %selected = load volatile ptr, ptr @slot.bytes, align 8
  store volatile i8 7, ptr %selected, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}

define void @__SMACK_static_init() {
entry:
  ret void
}
"""


POINTER_CMPXCHG_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@slot.bytes = internal global [8 x i8] zeroinitializer, align 8

declare void @__VERIFIER_assert(i32)

define void @f() {
entry:
  ; The successful exchange writes @right into byte-typed pointer storage.
  ; Pointer-valued atomics must be part of the sound-origin audit.
  store ptr @left, ptr @slot.bytes, align 8
  %exchanged = cmpxchg volatile ptr @slot.bytes, ptr @left, ptr @right
               seq_cst seq_cst
  %right.before = load volatile i8, ptr @right, align 1
  %selected = load volatile ptr, ptr @slot.bytes, align 8
  store volatile i8 7, ptr %selected, align 1
  %right.after = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %right.before, %right.after
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


HIDDEN_RUNTIME_ARM_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = internal global i8 0
@other = internal global i8 0

define void @f(i1 %choose, ptr %runtime) {
entry:
  ; Andersen may retain only @known in the select result even though the
  ; externally supplied arm can equal @other in a defined execution.
  %selected = select i1 %choose, ptr @known, ptr %runtime
  store volatile i8 7, ptr %selected, align 1
  %other.value = load volatile i8, ptr @other, align 1
  ret void
}
"""


EXTERNAL_MUTATES_POINTER_SLOT_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = global i8 0
@other = global i8 0
@slot = global ptr @known

declare void @unknown_external()

define void @f() {
entry:
  ; The declaration may mutate any memory, including storing @other into
  ; @slot. A pre-call points-to value of {@known} is not a post-call proof.
  call void @unknown_external()
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %other.value = load volatile i8, ptr @other, align 1
  ret void
}
"""


EXTERNAL_POINTER_STORAGE_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = internal global i8 0
@other = internal global i8 0
@slot = external global ptr

define internal void @seed_known_target() {
entry:
  ; This dead store gives Andersen a nonempty, apparently precise target for
  ; loads from @slot. External code can still write any pointer into @slot.
  store ptr @known, ptr @slot, align 8
  ret void
}

define void @f() {
entry:
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %other.value = load volatile i8, ptr @other, align 1
  ret void
}
"""


VERIFIER_NONDET_MUTATES_SLOT_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = internal global i8 0
@other = internal global i8 0
@slot = global ptr @known

declare i32 @__VERIFIER_nondet_int()

define void @f() {
entry:
  ; This is a bodyless declaration with ordinary call-side effects. Its name
  ; constrains the return value convention, not its ability to mutate @slot.
  %ignored = call i32 @__VERIFIER_nondet_int()
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %other.value = load volatile i8, ptr @other, align 1
  ret void
}
"""


UNHANDLED_INTRINSIC_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@known = internal global i8 0
@other = internal global i8 0
@slot = global ptr @known

declare void @llvm.sideeffect()

define void @f() {
entry:
  ; Keep an intrinsic outside the explicit harmless allowlist visible to the
  ; partition audit. Unknown declaration semantics cannot certify separation.
  call void @llvm.sideeffect()
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %other.value = load volatile i8, ptr @other, align 1
  ret void
}
"""


LIFETIME_INTRINSIC_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0

declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)

define void @f() {
entry:
  ; Lifetime markers may be erased as a sound over-approximation, but they must
  ; not become modular Boogie calls whose frames havoc unrelated memory maps.
  call void @llvm.lifetime.start.p0(i64 1, ptr @left)
  store volatile i8 3, ptr @left, align 1
  %right.value = load volatile i8, ptr @right, align 1
  ret void
}
"""


COLLAPSED_LATE_RESOLVED_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@later = internal global i32 0

define void @f(i64 %address) {
entry:
  %unsupported = inttoptr i64 %address to ptr
  store volatile i8 1, ptr %unsupported, align 1
  ; This resolved object is queried after the unsupported access. Once the
  ; module collapses, its first routing query must still return only $M.0.
  store volatile i32 2, ptr @later, align 4
  %later.value = load volatile i32, ptr @later, align 4
  ret void
}
"""


MODULAR_POINTER_FORMAL_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0

define internal void @write_through_formal(ptr %p) #0 {
entry:
  ; The only LLVM caller supplies @left, so Andersen can constrain %p to
  ; @left. The generated Boogie procedure is nevertheless verified modularly:
  ; its formal is arbitrary and can equal @right.
  store volatile i8 3, ptr %p, align 1
  ret void
}

define void @f() {
entry:
  call void @write_through_formal(ptr @left)
  %right.value = load volatile i8, ptr @right, align 1
  ret void
}

attributes #0 = { noinline }
"""


MODULAR_AGGREGATE_FORMAL_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

%nested.pointer = type { i32, { ptr } }

@left = internal global i8 0
@right = internal global i8 0

define internal void @write_through_nested_formal(%nested.pointer %arg) #0 {
entry:
  ; Pointer-bearing aggregate formals have the same modularity boundary as a
  ; direct ptr formal, even when the sole LLVM caller inserts @left.
  %p = extractvalue %nested.pointer %arg, 1, 0
  store volatile i8 3, ptr %p, align 1
  ret void
}

define void @f() {
entry:
  %arg.0 = insertvalue %nested.pointer poison, i32 0, 0
  %arg.1 = insertvalue %nested.pointer %arg.0, ptr @left, 1, 0
  call void @write_through_nested_formal(%nested.pointer %arg.1)
  %right.value = load volatile i8, ptr @right, align 1
  ret void
}

attributes #0 = { noinline }
"""


MODULAR_MEMORY_HAVOC_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@slot = internal global ptr @left

define internal void @noop() #0 {
entry:
  ret void
}

define void @f() {
entry:
  ; The generated modular procedure contract for @noop modifies memory maps.
  ; It can therefore havoc @slot before this load even though the LLVM body is
  ; empty. The loaded pointer cannot remain partitioned using its pre-call SVF
  ; target of @left: its Boogie value can now equal @right.
  call void @noop()
  %selected = load volatile ptr, ptr @slot, align 8
  store volatile i8 7, ptr %selected, align 1
  %right.value = load volatile i8, ptr @right, align 1
  ret void
}

attributes #0 = { noinline }
"""


MODULAR_POINTER_RETURN_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0

define internal ptr @return_left() #0 {
entry:
  ret ptr @left
}

define void @f() {
entry:
  ; Andersen sees the defined helper return only @left, but the generated
  ; Boogie procedure has no postcondition constraining its return formal.
  ; Modularly, %selected can equal @right at this call.
  %selected = call ptr @return_left()
  store volatile i8 7, ptr %selected, align 1
  %right.value = load volatile i8, ptr @right, align 1
  ret void
}

attributes #0 = { noinline }
"""


DEVIRT_EPOCH_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global i8 0
@function.slot = internal global ptr @target

define internal i8 @target(ptr %p) {
entry:
  store volatile i8 3, ptr %p, align 1
  ret i8 3
}

define void @f() {
entry:
  %callee = load volatile ptr, ptr @function.slot, align 8
  %value = call i8 %callee(ptr @left)
  store volatile i8 %value, ptr @right, align 1
  ret void
}
"""


PROVEN_DISTINCT_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i32 0
@right = internal global i32 0

define void @f() {
entry:
  store i32 11, ptr @left, align 4
  store i32 22, ptr @right, align 4
  %x = load i32, ptr @left, align 4
  %y = load i32, ptr @right, align 4
  %unused = add i32 %x, %y
  ret void
}
"""


DYNAMIC_GEP_CROSS_MAP_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global [1 x i8] zeroinitializer
@right = internal global i8 0

declare void @__VERIFIER_assert(i32)

define void @f(i64 %index) {
entry:
  store volatile i8 0, ptr @right, align 1
  %p = getelementptr inbounds [1 x i8], ptr @left, i64 0, i64 %index
  store volatile i8 7, ptr %p, align 1
  %value = load volatile i8, ptr @right, align 1
  %unchanged = icmp eq i8 %value, 0
  %unchanged.i32 = zext i1 %unchanged to i32
  call void @__VERIFIER_assert(i32 %unchanged.i32)
  ret void
}
"""


HUGE_GLOBAL_LAYOUT_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@a = internal global i64 0
@big = internal global <536870912 x i64> zeroinitializer

declare void @__VERIFIER_assert(i32)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg)

define void @f() {
entry:
  %p = getelementptr <536870912 x i64>, ptr @big, i64 0, i64 129
  %from.big = load volatile i64, ptr %p, align 8
  %from.a = load volatile i64, ptr @a, align 8
  %same = icmp eq ptr %p, @a
  %same.i32 = zext i1 %same to i32
  call void @__VERIFIER_assert(i32 %same.i32)
  ret void
}

define void @__SMACK_static_init() {
entry:
  store i64 0, ptr @a, align 8
  call void @llvm.memset.p0.i64(ptr @big, i8 0, i64 4294967296, i1 false)
  ret void
}
"""


CALLBR_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define void @f(i32 %x) {
entry:
  callbr void asm sideeffect "", "r,!i"(i32 %x)
          to label %fallthrough [label %indirect]

fallthrough:
  ret void

indirect:
  ret void
}
"""


INLINE_ASM_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

define void @f() {
entry:
  call void asm sideeffect "", "~{memory}"()
  ret void
}
"""


GEP_INDEX_WIDTH_MISMATCH_IR = r"""
target datalayout = "e-p:64:64:64:8"
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i8 0
@right = internal global [257 x i8] zeroinitializer

define void @f() {
entry:
  store volatile i8 1, ptr @left, align 1
  %wrapped.by.llvm = getelementptr i8, ptr @right, i64 1281
  store volatile i8 2, ptr %wrapped.by.llvm, align 1
  ret void
}
"""


DYNAMIC_GEP_WITHOUT_NOWRAP_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@buffer = internal global [8 x i8] zeroinitializer

define void @f(i64 %index) {
entry:
  %p = getelementptr [8 x i8], ptr @buffer, i64 0, i64 %index
  store volatile i8 1, ptr %p, align 1
  ret void
}
"""


ANNOTATION_RANGE_OVERFLOW_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

declare ptr @__SMACK_values(ptr, i128)

define void @f() {
entry:
  %buffer = alloca [1 x i8], align 1
  %annotated = call ptr @__SMACK_values(
      ptr %buffer, i128 1267650600228229401496703205376)
  ret void
}
"""


UNRESOLVED_INDIRECT_INVOKE_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@tracked = internal global i8 0

declare i32 @__gxx_personality_v0(...)

define i32 @f(ptr %callee) personality ptr @__gxx_personality_v0 {
entry:
  %value = invoke i32 %callee()
          to label %normal unwind label %exception

normal:
  %normal.byte = load volatile i8, ptr @tracked, align 1
  ret i32 %value

exception:
  %landing = landingpad { ptr, i32 } cleanup
  %exception.byte = load volatile i8, ptr @tracked, align 1
  ret i32 -1
}
"""


UNDEF_OR_POISON_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@left = internal global i32 0
@right = internal global i32 0

define void @f() {
entry:
  store i32 7, ptr {unknown_pointer}, align 4
  %x = load i32, ptr @left, align 4
  %y = load i32, ptr @right, align 4
  ret void
}
"""


NULL_POINTER_IS_VALID_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@tracked = internal global i32 0

define void @f() #0 {
entry:
  ; This function explicitly gives address zero valid memory semantics.
  store i32 7, ptr null, align 4
  %value = load i32, ptr @tracked, align 4
  ret void
}

attributes #0 = { null_pointer_is_valid }
"""


CONSTANT_ADDRESS_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@tracked = internal global i8 0

define void @f() {
entry:
  %constant.address = inttoptr i64 4096 to ptr
  %constant.address.value = load volatile i8, ptr %constant.address, align 1
  store volatile i8 %constant.address.value, ptr @tracked, align 1
  ret void
}
"""


OBJECTLESS_IR = r"""
target triple = "x86_64-unknown-linux-gnu"

@tracked = internal global i8 0

define internal void @objectless(ptr %p) {
entry:
  %value = load volatile i8, ptr %p, align 1
  ret void
}

define void @f() {
entry:
  store i8 1, ptr @tracked, align 1
  ret void
}
"""


SMACK_SUPPORT_IR = r"""
define void @__SMACK_check_overflow(i32 %flag) {
entry:
  ret void
}

define void @__VERIFIER_assume(i32 %condition) {
entry:
  ret void
}
"""


def _llvm2bpl_builds():
    candidates = []
    if os.environ.get("SMACK_BUILD_DIR"):
        candidates.append(Path(os.environ["SMACK_BUILD_DIR"]) / "llvm2bpl")
    candidates.extend(
        [
            REPO_ROOT / "build-svf-newpm" / "llvm2bpl",
            REPO_ROOT / "build-svf" / "llvm2bpl",
        ]
    )
    result = []
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve() if candidate.exists() else candidate
        if candidate.is_file() and resolved not in seen:
            result.append(candidate)
            seen.add(resolved)
    if not result:
        installed = shutil.which("llvm2bpl")
        if installed:
            result.append(Path(installed))
    return result


LLVM2BPL_BUILDS = _llvm2bpl_builds()


@pytest.fixture(
    params=LLVM2BPL_BUILDS or [None],
    ids=lambda path: path.parent.name if path else "llvm2bpl-missing",
)
def llvm2bpl(request):
    if request.param is None:
        pytest.skip("llvm2bpl not found")
    return request.param


def _environment(llvm2bpl: Path, extra=None):
    env = tool_path_env()
    llvm_tool_dirs = []
    for tool in ("clang-21", "clang++-21", "llvm-link-21"):
        path = shutil.which(tool)
        if path:
            llvm_tool_dirs.append(str(Path(path).parent))
    env["PATH"] = os.pathsep.join([str(llvm2bpl.parent), *llvm_tool_dirs, env.get("PATH", "")])
    if extra:
        env.update(extra)
    return env


def _translate(tmp_path, stem, ir, llvm2bpl, *, env_extra=None, extra_args=()):
    source = tmp_path / f"{stem}.ll"
    bpl_path = tmp_path / f"{stem}.bpl"
    report_path = tmp_path / f"{stem}.memory.json"
    source.write_text(ir + SMACK_SUPPORT_IR)
    completed = run_with_timeout(
        [
            str(llvm2bpl),
            str(source),
            "--entry-points=f",
            "--mem-mod-impls",
            "--warn-type=silent",
            *extra_args,
            f"--bpl={bpl_path}",
            f"--smack-memory-partition-report={report_path}",
        ],
        env=_environment(llvm2bpl, env_extra),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )
    assert completed.returncode == 0, completed.stdout
    report = json.loads(report_path.read_text())
    expected_pipeline = {
        "build-svf-newpm": "newpm",
        "build-svf": "legacy",
    }.get(llvm2bpl.parent.name)
    if expected_pipeline:
        assert report["pipeline"] == expected_pipeline
    return bpl_path.read_text(), report


def _memory_map_declarations(bpl):
    return re.findall(r"^(const|var)\s+(\$M\.\d+):", bpl, flags=re.MULTILINE)


def _all_declared_memory_names(bpl):
    names = set(
        re.findall(
            r"^(?:const(?: unique)?|var)\s+(\$M[^: ]*):",
            bpl,
            flags=re.MULTILINE,
        )
    )
    return names - {"$MALLOC_TOP", "$MOP"}


def _assert_only_mutable_maps(bpl, report):
    declarations = _memory_map_declarations(bpl)
    assert declarations
    assert {kind for kind, _ in declarations} == {"var"}
    names = {name for _, name in declarations}
    assert len(names) == report["region_count"]
    assert _all_declared_memory_names(bpl) == names


def _assert_universal_collapse(bpl, report):
    assert report["svf_universal_region"] is True
    assert report["region_count"] == 1
    assert _all_declared_memory_names(bpl) == {"$M.0"}
    _assert_only_mutable_maps(bpl, report)


def _assert_no_synthetic_partition_evidence(report):
    assert report["partitioner"] == "svf-andersen"
    assert report["dsa_mode"] == "svf-andersen"
    assert report["late_region_count"] == 0
    assert report["svf_noalias_seed_count"] == 0
    assert report["svf_noalias_seeded_region_count"] == 0
    assert report["svf_allocator_model"] is False
    assert report["svf_field_windows"] is False
    assert report["svf_offset_known_count"] == 0
    assert report["windowed_region_count"] == 0
    assert report["split_component_count"] == 0
    assert (
        report["svf_live_unresolved_access_count"]
        == report["svf_unresolved_access_count"]
    )
    assert (
        report["svf_blackhole_access_count"]
        == report["svf_unknown_target_access_count"]
    )
    assert report["svf_reachable_function_count"] <= report["svf_scanned_function_count"]
    for name, value in report.items():
        if name.startswith("oracle_"):
            assert value == 0, name
    assert "no-representative" not in {reason["name"] for reason in report["fallback_reasons"]}


def _assert_boogie_refutes(tmp_path, stem, bpl, extra_declarations=""):
    boogie = shutil.which("boogie")
    if not boogie:
        return

    # Minimal raw-LLVM fixtures omit smack.c's Boogie globals and allocator
    # primitives. Add only the declarations needed to check the generated
    # procedure contract; the memory routing under test remains unchanged.
    boogie_bpl_path = tmp_path / f"{stem}-boogie.bpl"
    prefix = "var $exn: bool;\nvar $exnv: int;\n" + extra_declarations
    boogie_bpl_path.write_text(prefix + bpl)
    checked = run_with_timeout(
        [
            boogie,
            "/inferModifies",
            "/proc:f",
            "/timeLimit:10",
            "/errorLimit:1",
            str(boogie_bpl_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="BOOGIE",
        default_timeout=30,
    )
    assert "0 verified, 1 error" in checked.stdout, checked.stdout
    assert "1 verified, 0 errors" not in checked.stdout


def test_readonly_noalias_same_pointer_collapses_to_universal_map(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "readonly-noalias", READONLY_NOALIAS_IR, llvm2bpl)

    # The runtime argument has no proven concrete allocation. SVF's sound
    # catch-all therefore joins every live access, while the read-only noalias
    # attributes contribute no synthetic separation evidence.
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_selected_entry_noalias_activates_closed_input_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "entry-disjoint-contract",
        ENTRY_DISJOINT_CONTRACT_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    assert report["svf_closed_input_contract"] is True
    assert report["svf_allocator_model"] is False
    assert report["svf_noalias_seed_count"] == 2
    assert report["svf_universal_region"] is False
    assert report["region_count"] == 2
    assert report["svf_unresolved_access_count"] == 0
    assert report["svf_unknown_target_access_count"] == 0
    assert report["svf_unsupported_pointer_origin_count"] == 0
    assert report["svf_scanned_function_count"] == 3
    assert report["svf_noalias_seeded_region_count"] == 2
    assert report["svf_stack_region_count"] == 0
    assert report["svf_heap_region_count"] == 0
    assert report["svf_global_region_count"] == 0
    assert report["svf_mixed_authority_region_count"] == 0
    assert len(report["svf_region_authorities"]) == 2
    assert all(
        authority["noalias_seed"]
        and not authority["stack_allocation"]
        and not authority["heap_allocation"]
        and not authority["global_allocation"]
        for authority in report["svf_region_authorities"]
    )
    _assert_only_mutable_maps(bpl, report)


def test_entry_contract_does_not_hide_unresolved_emitted_function(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "entry-contract-uncalled-unknown",
        ENTRY_DISJOINT_WITH_UNCALLED_UNKNOWN_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    assert report["svf_closed_input_contract"] is True
    assert report["svf_noalias_seed_count"] == 2
    _assert_universal_collapse(bpl, report)
    assert report["svf_unresolved_access_count"] > 0
    assert report["svf_scanned_function_count"] == 4


def test_entry_buffer_and_derived_gep_share_one_component(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path, "entry-derived-pointer", ENTRY_DERIVED_POINTER_IR, llvm2bpl
    )

    assert report["svf_closed_input_contract"] is True
    assert report["svf_noalias_seed_count"] == 2
    assert report["svf_universal_region"] is False
    assert report["region_count"] == 2
    assert report["svf_unresolved_access_count"] == 0
    assert report["svf_noalias_seeded_region_count"] == 2
    assert report["svf_mixed_authority_region_count"] == 0
    _assert_only_mutable_maps(bpl, report)


def test_entry_contract_cannot_substitute_for_missing_allocator_model(
    tmp_path, llvm2bpl
):
    bpl, report = _translate(
        tmp_path,
        "entry-disjoint-raw-alloca",
        ENTRY_DISJOINT_WITH_RAW_ALLOCA_IR,
        llvm2bpl,
    )

    assert report["svf_closed_input_contract"] is True
    assert report["svf_allocator_model"] is False
    assert report["svf_noalias_seed_count"] == 1
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0


def test_unconstrained_value_annotation_result_cannot_address_a_split_map(
    tmp_path, llvm2bpl
):
    bpl, report = _translate(
        tmp_path,
        "value-result-used-as-address",
        VALUE_RESULT_USED_AS_ADDRESS_IR,
        llvm2bpl,
    )

    assert report["svf_closed_input_contract"] is True
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0


def test_coalescible_constant_base_and_gep_share_one_component(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "coalescible-constant-derived-pointer",
        COALESCIBLE_CONSTANT_DERIVED_POINTER_IR,
        llvm2bpl,
    )

    assert report["svf_closed_input_contract"] is False
    assert report["svf_noalias_seed_count"] == 0
    assert report["svf_universal_region"] is False
    assert report["region_count"] == 1
    assert report["svf_unresolved_access_count"] == 0
    assert report["svf_global_region_count"] == 1
    assert report["svf_mixed_authority_region_count"] == 0
    assert report["svf_region_authorities"] == [
        {
            "region": 0,
            "noalias_seed": False,
            "stack_allocation": False,
            "heap_allocation": False,
            "global_allocation": True,
        }
    ]
    _assert_only_mutable_maps(bpl, report)


def test_live_inttoptr_collapses_and_boogie_cannot_prove_false_assertion(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "live-unresolved", LIVE_UNRESOLVED_FALSE_PROOF_IR, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)

    _assert_boogie_refutes(tmp_path, "live-unresolved", bpl)


def test_pointer_static_initializer_cannot_drive_partition_after_boogie_initialize(
    tmp_path, llvm2bpl
):
    bpl, report = _translate(
        tmp_path,
        "initializer-pointer-slot",
        INITIALIZER_POINTER_SLOT_FALSE_PROOF_IR,
        llvm2bpl,
    )

    _assert_boogie_refutes(tmp_path, "initializer-pointer-slot", bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "call $initialize();" in bpl
    assert "procedure __SMACK_static_init()" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_malloc_return_cannot_drive_heap_global_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "malloc-return",
        MALLOC_RETURN_FALSE_PROOF_IR,
        llvm2bpl,
    )

    _assert_boogie_refutes(
        tmp_path,
        "malloc-return",
        bpl,
        "procedure $malloc(n: ref) returns (p: ref);\n",
    )
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "procedure malloc(" in bpl
    assert "$malloc(" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_alloca_return_cannot_drive_stack_global_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "alloca-return",
        ALLOCA_RETURN_FALSE_PROOF_IR,
        llvm2bpl,
    )

    _assert_boogie_refutes(
        tmp_path,
        "alloca-return",
        bpl,
        "procedure $alloc(n: ref) returns (p: ref);\n",
    )
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "call $p0 := $alloc(" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_type_punned_global_pointer_load_cannot_use_andersen_seed(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "type-punned-pointer-load",
        TYPE_PUNNED_POINTER_LOAD_FALSE_PROOF_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_boogie_refutes(tmp_path, "type-punned-pointer-load", bpl)
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "procedure seed_left()" in bpl
    assert "$load.ref(" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_free_havoc_before_pointer_load_forces_universal_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "free-havoc-pointer-storage",
        FREE_HAVOCS_POINTER_STORAGE_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_boogie_refutes(
        tmp_path,
        "free-havoc-pointer-storage",
        bpl,
        "procedure $free(p: ref);\n",
    )
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "procedure free_(" in bpl
    assert "$free(" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_pointer_cmpxchg_forces_universal_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "pointer-cmpxchg",
        POINTER_CMPXCHG_IR,
        llvm2bpl,
    )

    _assert_boogie_refutes(tmp_path, "pointer-cmpxchg", bpl)
    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert '{:llvm.op "cmpxchg"}' in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_runtime_pointer_hidden_by_known_select_arm_forces_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "hidden-runtime-arm", HIDDEN_RUNTIME_ARM_IR, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_unknown_external_call_invalidates_loaded_pointer_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "external-mutates-pointer-slot",
        EXTERNAL_MUTATES_POINTER_SLOT_IR,
        llvm2bpl,
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_external_pointer_storage_with_known_andersen_target_forces_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "external-pointer-storage",
        EXTERNAL_POINTER_STORAGE_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert report["svf_unresolved_access_count"] == 0
    _assert_no_synthetic_partition_evidence(report)


def test_bodyless_verifier_nondet_call_invalidates_pointer_slot_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "verifier-nondet-mutates-slot",
        VERIFIER_NONDET_MUTATES_SLOT_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert report["svf_unresolved_access_count"] == 0
    _assert_no_synthetic_partition_evidence(report)


def test_unhandled_bodyless_intrinsic_forces_universal_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "unhandled-intrinsic",
        UNHANDLED_INTRINSIC_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert report["svf_unresolved_access_count"] == 0
    _assert_no_synthetic_partition_evidence(report)


def test_lifetime_intrinsic_is_a_non_havocing_noop(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "lifetime-intrinsic",
        LIFETIME_INTRINSIC_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    assert report["svf_universal_region"] is False
    assert report["region_count"] == 2
    assert report["svf_unsupported_pointer_origin_count"] == 0
    assert "procedure llvm.lifetime.start.p0(" in bpl
    assert "call llvm.lifetime.start.p0(" not in bpl
    _assert_no_synthetic_partition_evidence(report)
    _assert_only_mutable_maps(bpl, report)


def test_collapsed_routing_keeps_late_resolved_query_on_m0(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "collapsed-late-resolved",
        COLLAPSED_LATE_RESOLVED_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "$M.1" not in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_modular_pointer_formal_cannot_use_llvm_callsite_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "modular-pointer-formal",
        MODULAR_POINTER_FORMAL_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "write_through_formal" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_modular_recursive_pointer_aggregate_formal_forces_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "modular-aggregate-formal",
        MODULAR_AGGREGATE_FORMAL_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "write_through_nested_formal" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_modular_memory_havoc_invalidates_loaded_pointer_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "modular-memory-havoc",
        MODULAR_MEMORY_HAVOC_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "procedure noop()" in bpl
    assert "call noop();" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_modular_pointer_return_cannot_use_llvm_body_partition(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "modular-pointer-return",
        MODULAR_POINTER_RETURN_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    assert "procedure return_left()" in bpl
    assert re.search(r"call \$p\d+ := return_left\(\);", bpl)
    _assert_no_synthetic_partition_evidence(report)


def test_devirt_ir_epoch_change_forces_universal_map_and_residual_fallback(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "devirt-epoch", DEVIRT_EPOCH_IR, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_ir_snapshot_match"] is False
    assert "{:unresolved_indirect}" in bpl
    assert "$unresolved.indirect.i8" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_svf_proven_distinct_objects_receive_distinct_mutable_maps(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "proven-distinct", PROVEN_DISTINCT_IR, llvm2bpl)

    assert report["svf_universal_region"] is False
    assert report["region_count"] == 2
    assert report["svf_unresolved_access_count"] == 0
    assert report["svf_unsupported_pointer_origin_count"] == 0
    assert report["svf_ir_snapshot_match"] is True
    _assert_no_synthetic_partition_evidence(report)
    _assert_only_mutable_maps(bpl, report)


def test_dynamic_gep_cannot_numerically_cross_between_boogie_maps(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "dynamic-gep-cross-map",
        DYNAMIC_GEP_CROSS_MAP_IR,
        llvm2bpl,
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)
    _assert_boogie_refutes(tmp_path, "dynamic-gep-cross-map", bpl)


def test_large_global_layout_preserves_distinct_numeric_addresses(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "huge-global-layout",
        HUGE_GLOBAL_LAYOUT_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    assert report["svf_universal_region"] is False
    assert report["region_count"] == 2
    assert report["svf_unsupported_pointer_origin_count"] == 0
    _assert_no_synthetic_partition_evidence(report)
    _assert_only_mutable_maps(bpl, report)
    _assert_boogie_refutes(tmp_path, "huge-global-layout", bpl)


@pytest.mark.parametrize(
    ("stem", "ir", "diagnostic"),
    [
        (
            "gep-index-width-mismatch",
            GEP_INDEX_WIDTH_MISMATCH_IR,
            "DataLayout index width differs from its pointer width",
        ),
        (
            "dynamic-gep-without-nowrap",
            DYNAMIC_GEP_WITHOUT_NOWRAP_IR,
            "dynamic GEP to mathematical Boogie pointer arithmetic",
        ),
        (
            "annotation-range-overflow",
            ANNOTATION_RANGE_OVERFLOW_IR,
            "__SMACK_values: element count exceeds 64 bits",
        ),
    ],
)
def test_gep_forms_outside_exact_boogie_arithmetic_are_rejected(
    tmp_path, llvm2bpl, stem, ir, diagnostic
):
    source = tmp_path / f"{stem}.ll"
    bpl_path = tmp_path / f"{stem}.bpl"
    source.write_text(ir + SMACK_SUPPORT_IR)
    completed = run_with_timeout(
        [
            str(llvm2bpl),
            str(source),
            "--entry-points=f",
            "--warn-type=silent",
            f"--bpl={bpl_path}",
        ],
        env=_environment(llvm2bpl),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )

    assert completed.returncode != 0
    assert diagnostic in completed.stdout


def test_unresolved_indirect_invoke_havocs_exception_state(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "unresolved-indirect-invoke",
        UNRESOLVED_INDIRECT_INVOKE_IR,
        llvm2bpl,
        extra_args=("--smack-skip-devirt",),
    )

    _assert_universal_collapse(bpl, report)
    assert "{:unresolved_indirect}" in bpl
    assert "procedure $unresolved.indirect.invoke.i32()" in bpl
    assert "modifies $exn, $exnv, $M.0;" in bpl
    _assert_no_synthetic_partition_evidence(report)


def test_callbr_is_rejected_instead_of_erasing_call_and_control_effects(tmp_path, llvm2bpl):
    source = tmp_path / "callbr.ll"
    bpl_path = tmp_path / "callbr.bpl"
    source.write_text(CALLBR_IR + SMACK_SUPPORT_IR)
    completed = run_with_timeout(
        [
            str(llvm2bpl),
            str(source),
            "--entry-points=f",
            "--warn-type=silent",
            f"--bpl={bpl_path}",
        ],
        env=_environment(llvm2bpl),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )

    assert completed.returncode != 0
    assert "SMACK cannot soundly translate callbr" in completed.stdout


def test_inline_assembly_is_rejected_instead_of_erasing_effects(tmp_path, llvm2bpl):
    source = tmp_path / "inline-asm.ll"
    bpl_path = tmp_path / "inline-asm.bpl"
    source.write_text(INLINE_ASM_IR + SMACK_SUPPORT_IR)
    completed = run_with_timeout(
        [
            str(llvm2bpl),
            str(source),
            "--entry-points=f",
            "--warn-type=silent",
            f"--bpl={bpl_path}",
        ],
        env=_environment(llvm2bpl),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout_name="SMACK_TOOL",
        default_timeout=120,
    )

    assert completed.returncode != 0
    assert "SMACK cannot soundly translate inline assembly" in completed.stdout


@pytest.mark.parametrize("unknown_pointer", ["undef", "poison"])
def test_undef_or_poison_pointer_forces_universal_collapse(tmp_path, llvm2bpl, unknown_pointer):
    ir = UNDEF_OR_POISON_IR.replace("{unknown_pointer}", unknown_pointer)
    bpl, report = _translate(tmp_path, f"{unknown_pointer}-pointer", ir, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_null_pointer_is_valid_access_forces_universal_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "null-valid", NULL_POINTER_IS_VALID_IR, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unresolved_access_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_constant_inttoptr_origin_forces_universal_collapse(tmp_path, llvm2bpl):
    bpl, report = _translate(tmp_path, "constant-address", CONSTANT_ADDRESS_IR, llvm2bpl)

    _assert_universal_collapse(bpl, report)
    assert report["svf_unsupported_pointer_origin_count"] > 0
    _assert_no_synthetic_partition_evidence(report)


def test_uncalled_objectless_access_collapses_whole_module(tmp_path, llvm2bpl):
    bpl, report = _translate(
        tmp_path,
        "objectless",
        OBJECTLESS_IR,
        llvm2bpl,
        extra_args=("--smack-skip-pre-bpl",),
    )

    _assert_universal_collapse(bpl, report)
    assert report["svf_unresolved_access_count"] > 0
    assert report["svf_scanned_function_count"] == 4
    _assert_no_synthetic_partition_evidence(report)


def test_retired_partition_controls_are_rejected(tmp_path, llvm2bpl):
    source = tmp_path / "controls.ll"
    source.write_text(PROVEN_DISTINCT_IR)
    retired = [
        "--svf-field-windows=true",
        "--smack-const-regions=true",
        "--smack-memory-partitioner=sea-dsa",
        "--memory-partitioner=svf",
    ]

    for flag in retired:
        completed = run_with_timeout(
            [str(llvm2bpl), str(source), flag],
            env=_environment(llvm2bpl),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout_name="SMACK_TOOL",
            default_timeout=30,
        )
        assert completed.returncode != 0, flag
        assert "Unknown command line argument" in completed.stdout, completed.stdout


def test_retired_environment_toggles_are_inert(tmp_path, llvm2bpl):
    clean_bpl, clean_report = _translate(tmp_path, "env-clean", PROVEN_DISTINCT_IR, llvm2bpl)
    toggled_bpl, toggled_report = _translate(
        tmp_path,
        "env-toggled",
        PROVEN_DISTINCT_IR,
        llvm2bpl,
        env_extra={
            "SMACK_SVF_WINDOWS": "1",
            "SMACK_CONST_REGIONS": "1",
            "SMACK_MEMORY_PARTITIONER": "sea-dsa",
        },
    )

    report_fields = (
        "partitioner",
        "dsa_mode",
        "region_count",
        "svf_universal_region",
        "svf_noalias_seed_count",
        "svf_field_windows",
        "svf_offset_known_count",
        "windowed_region_count",
        "split_component_count",
    )
    assert {key: clean_report[key] for key in report_fields} == {
        key: toggled_report[key] for key in report_fields
    }
    assert _memory_map_declarations(clean_bpl) == _memory_map_declarations(toggled_bpl)
    _assert_no_synthetic_partition_evidence(toggled_report)
    _assert_only_mutable_maps(toggled_bpl, toggled_report)
