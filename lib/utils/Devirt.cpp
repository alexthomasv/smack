//===- Devirt.cpp - Devirtualize indirect function calls via SVF ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Rewrites each indirect call `(*fp)(args)` into a direct dispatch over its
// possible targets (a "bounce" function), so SMACK's translator -- which
// cannot emit a genuine indirect call -- can handle function-pointer / vtable
// code. Two resolution tiers:
//  - Andersen-COMPLETE: SVF proves the fp points only to known functions (its
//    points-to excludes the black-hole) -> bounce with an `unreachable`
//    no-match branch (provably infeasible).
//  - FLTA fallback: Andersen failed; targets = every address-taken function
//    with a callsite-compatible signature -> bounce whose no-match branch is
//    the RESIDUAL indirect call, which the translator models as an
//    unknown-callee havoc (sound over-approximation, never `unreachable`).
// Callsites with no candidates at all are left as-is (unknown-callee model).
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "devirt"

#include "utils/Devirt.h"
#include "utils/InitializePasses.h"

#include "smack/DSAWrapper.h"
#include "smack/DSAWrapperAnalysis.h"
#include "smack/InitializePasses.h"
#include "smack/Debug.h"
#include "smack/LlvmCompat.h"
#include "smack/Naming.h"
#include "smack/SmackOptions.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"

// SVF: the (sound) source of indirect-call targets. Reused from the analysis
// DSAWrapper builds once; see DSAWrapper::cachedSVF.
#include "Graphs/CallGraph.h"
#include "Graphs/ICFGNode.h"
#include "MemoryModel/PointsTo.h"
#include "SVF-LLVM/LLVMModule.h"
#include "SVFIR/SVFIR.h"
#include "SVFIR/SVFVariables.h"
#include "WPA/Andersen.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

// Pass statistics
STATISTIC(FuncAdded, "Number of bounce functions added");
STATISTIC(CSConvert, "Number of call sites converted");
STATISTIC(DeadFnStubbed,
          "Number of SVF-call-graph-unreachable functions stubbed with "
          "`unreachable`");

static cl::opt<std::string> DevirtReportFilename(
    "smack-devirt-report",
    cl::desc("Output SMACK devirtualization target report as JSON"),
    cl::init(""), cl::value_desc("filename"));

// Type-based filtering (default ON). SVF's points-to over-approximates a vtable
// method slot to also include signature-INCOMPATIBLE functions (e.g. a 3-arg RSA
// fn appears as a candidate for a 2-arg hash-method slot). A well-typed indirect
// call can never reach such a target -- calling through a signature-incompatible
// fp is UB -- so it is an SVF false positive. Dropping it keeps the bounce's
// else-`assume false` sound while resolving far more sites. This is what LLVM
// whole-program devirt does. UNMAPPED targets (no module function of that name)
// are NOT filtered: that is a name-mapping failure, not UB evidence, so the
// whole site is declined regardless of this flag. Pass -devirt-strict-types to
// also decline the whole site on any signature-incompatible target (the safety
// valve).
static cl::opt<bool> DevirtStrictTypes(
    "devirt-strict-types",
    cl::desc("Decline a devirt site if ANY SVF target is signature-incompatible, "
             "instead of type-filtering it (default: filter)."),
    cl::init(false));

//===----------------------------------------------------------------------===//
// IR-rewrite helpers (unchanged from the original devirt pass).
//===----------------------------------------------------------------------===//

//
// Return a pointer to the LLVM type for a void pointer.
//
static inline PointerType *getVoidPtrType(LLVMContext &C) {
  Type *Int8Type = IntegerType::getInt8Ty(C);
  return PointerType::getUnqual(Int8Type);
}

//
// Given an LLVM value, insert a cast instruction to make it a given type.
//
static inline Value *castTo(Value *V, Type *Ty, std::string Name,
                            Value *InsertPt) {
  // Don't bother creating a cast if it's already the correct type.
  if (V->getType() == Ty)
    return V;

  // If it's a constant, just create a constant expression.
  if (Constant *C = dyn_cast<Constant>(V)) {
    Constant *CE = nullptr;
    if (C->getType()->isIntegerTy() && Ty->isIntegerTy()) {
      auto srcBits = C->getType()->getIntegerBitWidth();
      auto dstBits = Ty->getIntegerBitWidth();
      CE = srcBits == dstBits
               ? C
               : ConstantExpr::getCast(srcBits < dstBits ? Instruction::ZExt
                                                         : Instruction::Trunc,
                                       C, Ty);
    } else
      CE = ConstantExpr::getBitCast(C, Ty);
    return CE;
  }

  // Otherwise, insert a cast instruction.
  if (auto I = dyn_cast<Instruction>(InsertPt))
    return CastInst::CreateZExtOrBitCast(V, Ty, Name, I);
  else if (auto B = dyn_cast<BasicBlock>(InsertPt))
    return CastInst::CreateZExtOrBitCast(V, Ty, Name, B);
  else
    llvm_unreachable("Unexpected insertion point.");
}

static inline bool isZExtOrBitCastable(Value *V, Type *T) {
  return CastInst::castIsValid(Instruction::ZExt, V->getType(), T) ||
         CastInst::castIsValid(Instruction::BitCast, V->getType(), T);
}

// Pick a valid DebugLoc for a devirt-created call replacing `orig`: reuse orig's
// location, else (orig has none but its function carries debug info) a synthetic
// line-0 location in that function's scope, so the inliner can anchor the inlined
// debug info of the (debug-info-bearing) callees. Empty when the function has no
// debug info -- then the verifier requires no !dbg.
static DebugLoc devirtCallLoc(const Instruction *orig) {
  if (const DebugLoc &DL = orig->getDebugLoc())
    return DL;
  if (DISubprogram *SP = orig->getFunction()->getSubprogram())
    return DILocation::get(orig->getContext(), 0, 0, SP);
  return DebugLoc();
}

//
// Is target F callable at call site CS with (at most ZExt/BitCast) argument
// adaptation? The bounce performs these casts, so an incompatible target could
// not be dispatched -- such a target forces us to leave the callsite untouched
// (see resolveSVFTargets) rather than silently drop a possible runtime target.
//
static inline bool match(CallBase *CS, const Function &F) {
  auto N = CS->arg_size();
  auto T = F.getFunctionType();
  auto M = T->getNumParams();
  auto RT = T->getReturnType();
  auto IT = CS->getType();

  if (RT != IT && !CastInst::isBitCastable(RT, IT))
    return false;

  if (N < M)
    return false;

  if (N > M && !F.isVarArg())
    return false;

  for (unsigned i = 0; i < M; i++) {
    auto A = CS->getArgOperand(i);
    auto PT = T->getParamType(i);
    if (A->getType() != PT && !isZExtOrBitCastable(A, PT))
      return false;
  }

  return true;
}

// SMACK's value-tracking intrinsic is never a real runtime function-pointer
// target, so it is skipped (without making the resolution "incomplete").
static bool isIgnoredTarget(const Function &F) {
  return F.getName() == "__SMACK_value";
}

static std::vector<const Function *>
sortedTargets(const std::set<const Function *> &targets) {
  std::vector<const Function *> out(targets.begin(), targets.end());
  std::sort(out.begin(), out.end(), [](const Function *lhs, const Function *rhs) {
    return lhs->getName() < rhs->getName();
  });
  return out;
}

//===----------------------------------------------------------------------===//
// SVF target resolution + soundness completeness gate.
//===----------------------------------------------------------------------===//

namespace {

struct SvfResolution {
  // True only when SVF resolved EVERY possible target (no black-hole) and each
  // maps to a signature-compatible llvm::Function -- the precondition for a
  // sound `unreachable` no-match branch.
  bool complete = false;
  // True when Andersen could NOT bound the targets but function-level type
  // analysis (FLTA) enumerated the signature-compatible address-taken
  // candidates. An FLTA bounce dispatches those precisely and falls back to
  // the residual indirect call (translated as an unknown-callee havoc) -- it
  // must NEVER get the `unreachable` no-match branch.
  bool flta = false;
  std::vector<const Function *> targets;
  std::string reason; // diagnostic: why complete / why not
};

//
// Resolve the targets of indirect call CS from SVF's Andersen call graph.
//
// Soundness: the `unreachable` no-match branch is emitted ONLY when the
// resolution is complete, i.e. SVF proves the function pointer points only to
// known functions. The gate is:
//   (1) SVF has resolved callees for this site (hasIndCSCallees), AND
//   (2) the function pointer's points-to set excludes the black-hole (SVF's
//       "points to some unknown object" marker), AND
//   (3) every resolved callee maps to a signature-compatible llvm::Function.
// If any callee cannot be mapped or matched, we BAIL (mark incomplete) rather
// than drop a possible target -- dropping one would make the bounce's
// `unreachable` reachable at runtime, which is unsound.
//
SvfResolution resolveAndersenTargets(CallBase *CS) {
  SvfResolution R;
  Module &M = *CS->getModule();

  SVF::LLVMModuleSet *ms = nullptr;
  SVF::SVFIR *pag = nullptr;
  SVF::Andersen *ander = nullptr;
  if (!smack::DSAWrapper::cachedSVF(ms, pag, ander) || !ms || !pag || !ander) {
    R.reason = "svf-unavailable";
    return R;
  }

  SVF::CallICFGNode *cnode = ms->getCallICFGNode(CS);
  if (!cnode) {
    R.reason = "no-icfg-node";
    return R;
  }

  if (!ander->hasIndCSCallees(cnode)) {
    R.reason = "svf-no-callees";
    return R;
  }

  // Completeness gate (the crux): the function pointer must point only to known
  // objects. If its points-to set contains the black-hole, SVF could not bound
  // the target set, so the `unreachable` fallback would be unsound -> leave the
  // call untouched.
  const SVF::SVFVar *funPtr = cnode->getIndFunPtr();
  if (!funPtr) {
    R.reason = "no-fun-ptr";
    return R;
  }
  const SVF::PointsTo &pts = ander->getPts(funPtr->getId());
  if (pts.empty()) {
    R.reason = "empty-pts";
    return R;
  }
  if (pts.test(pag->getBlackHoleNode())) {
    R.reason = "black-hole";
    return R;
  }

  // Map each resolved callee to its llvm::Function.
  std::set<const Function *> resolved;
  for (const SVF::FunObjVar *fo : ander->getIndCSCallees(cnode)) {
    const std::string &name = fo->getName();
    Function *F = M.getFunction(name);
    if (!F) {
      // An SVF target with no corresponding module function is a NAME-MAPPING
      // failure (e.g. an extapi-internal symbol), not evidence the target
      // cannot execute — unlike a signature mismatch, which is UB to call
      // through this fp. Silently dropping it could make the bounce's
      // `unreachable` fallback reachable, so decline the whole site (the
      // translator then models the call as an unknown callee).
      R.reason = "target-unmapped:" + name;
      return R;
    }
    if (isIgnoredTarget(*F))
      continue;
    if (!match(CS, *F)) {
      if (DevirtStrictTypes) {
        R.reason = "target-type-mismatch:" + name;
        return R;
      }
      continue; // signature-incompatible: UB to call through this fp => SVF
                // false positive for a well-typed program. Type-filter it.
    }
    resolved.insert(F);
  }
  if (resolved.empty()) {
    R.reason = "no-usable-targets";
    return R;
  }

  R.targets = sortedTargets(resolved);
  R.complete = true;
  R.reason = "svf-complete";
  return R;
}

//
// Resolution entry point: Andersen first; when Andersen cannot bound the
// targets, fall back to function-level type analysis (FLTA): every
// address-taken function the callsite could legally invoke (the same match()
// signature filter that already justifies type-filtering -- calling through an
// incompatible fp is UB). FLTA target sets are small in practice (only
// address-taken functions qualify), and the resulting bounce keeps a residual
// indirect call as its no-match branch, so FLTA is sound even if a real target
// somehow escaped the enumeration: the residual is translated as an
// unknown-callee havoc, never `unreachable`.
//
SvfResolution resolveSVFTargets(CallBase *CS, bool allowFlta) {
  SvfResolution R = resolveAndersenTargets(CS);
  if (R.complete || !allowFlta)
    return R;

  Module &M = *CS->getModule();
  std::set<const Function *> flta;
  for (Function &F : M) {
    if (F.isIntrinsic() || !F.hasAddressTaken())
      continue;
    if (F.getName().starts_with("devirtbounce") || isIgnoredTarget(F))
      continue; // never dispatch into our own bounces / SMACK intrinsics
    if (!match(CS, F))
      continue;
    flta.insert(&F);
  }
  if (!flta.empty()) {
    R.targets = sortedTargets(flta);
    R.flta = true;
    R.reason = "flta:" + std::to_string(flta.size()) + "(" + R.reason + ")";
  }
  return R;
}

} // namespace

//===----------------------------------------------------------------------===//
// Optional JSON report (consumed by the devirt validation oracle).
//===----------------------------------------------------------------------===//

namespace {

struct DevirtReportEntry {
  std::string callsiteId;
  unsigned callsiteIndex = 0;
  std::string function;
  std::string file;
  unsigned line = 0;
  unsigned column = 0;
  std::string instruction;
  bool complete = false;
  bool flta = false;
  unsigned targetCount = 0;
  std::string reason;
  std::vector<std::string> targets;
};

std::vector<DevirtReportEntry> DevirtReportEntries;
std::map<const CallBase *, unsigned> DevirtCallsiteIndices;

std::string valueToString(const Value &V) {
  std::string out;
  raw_string_ostream os(out);
  V.print(os);
  return os.str();
}

unsigned indirectCallsiteIndex(const CallBase &CS) {
  const Function *F = CS.getFunction();
  unsigned index = 0;
  for (const Instruction &I : instructions(F)) {
    if (const auto *CB = dyn_cast<CallBase>(&I)) {
      if (!CB->isIndirectCall())
        continue;
      if (CB == &CS)
        return index;
      ++index;
    }
  }
  return index;
}

std::string makeCallsiteId(const CallBase &CS, unsigned index) {
  std::string function = CS.getFunction()->getName().str();
  return function + ":indirect:" + std::to_string(index);
}

void addDebugLoc(DevirtReportEntry &entry, const CallBase &CS) {
  if (const DebugLoc &loc = CS.getDebugLoc()) {
    entry.line = loc.getLine();
    entry.column = loc.getCol();
    if (const auto *scope = dyn_cast_or_null<DIScope>(loc.getScope()))
      entry.file = scope->getFilename().str();
  }
}

void recordDevirtResolution(const CallBase &CS,
                            const SvfResolution &resolution) {
  if (DevirtReportFilename.empty())
    return;

  DevirtReportEntry entry;
  auto assigned = DevirtCallsiteIndices.find(&CS);
  entry.callsiteIndex = assigned != DevirtCallsiteIndices.end()
                            ? assigned->second
                            : indirectCallsiteIndex(CS);
  entry.callsiteId = makeCallsiteId(CS, entry.callsiteIndex);
  entry.function = CS.getParent()->getParent()->getName().str();
  entry.instruction = valueToString(CS);
  entry.complete = resolution.complete;
  entry.flta = resolution.flta;
  entry.targetCount = resolution.targets.size();
  entry.reason = resolution.reason;
  addDebugLoc(entry, CS);
  for (const Function *F : resolution.targets)
    entry.targets.push_back(F->getName().str());
  DevirtReportEntries.push_back(std::move(entry));
}

void writeDevirtReport(const Module &M) {
  if (DevirtReportFilename.empty())
    return;

  std::error_code EC;
  ToolOutputFile F(DevirtReportFilename.c_str(), EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Could not write " << DevirtReportFilename << ": " << EC.message()
           << "\n";
    return;
  }

  json::OStream J(F.os(), 2);
  J.object([&] {
    J.attribute("schema_version", 3);
    J.attribute("module", M.getModuleIdentifier());
    J.attribute("target_source", "svf");
    J.attributeArray("callsites", [&] {
      for (const auto &entry : DevirtReportEntries) {
        J.object([&] {
          J.attribute("callsite_id", entry.callsiteId);
          J.attribute("callsite_index", entry.callsiteIndex);
          J.attribute("function", entry.function);
          if (entry.file.empty())
            J.attribute("file", json::Value(nullptr));
          else
            J.attribute("file", entry.file);
          J.attribute("line", entry.line);
          J.attribute("column", entry.column);
          J.attribute("instruction", entry.instruction);
          J.attribute("complete", entry.complete);
          J.attribute("flta", entry.flta);
          J.attribute("target_count", entry.targetCount);
          J.attribute("reason", entry.reason);
          J.attributeArray("targets", [&] {
            for (const auto &target : entry.targets)
              J.value(target);
          });
        });
      }
    });
  });
  F.keep();
}

} // namespace

//===----------------------------------------------------------------------===//
// The bounce-function rewrite (unchanged from the original devirt pass).
//===----------------------------------------------------------------------===//

//
// Method: buildBounce()
//
// Description:
//  Builds a bounce function that compares the incoming function pointer to each
//  target and, on a match, performs the direct call. The no-match branch
//  depends on the resolution kind:
//   - complete (Andersen bounded the targets): `unreachable` -- provably
//     infeasible;
//   - FLTA fallback (unknownFallback=true): the residual indirect call through
//     the incoming function pointer -- the translator models it as an
//     unknown-callee havoc, so a target that escaped FLTA's enumeration is
//     over-approximated instead of pruned.
//
Function *Devirtualize::buildBounce(CallBase *CS,
                                    std::vector<const Function *> &Targets,
                                    bool unknownFallback) {
  // Update the statistics on the number of bounce functions added.
  ++FuncAdded;
  // Create a bounce function whose signature matches the call, plus an extra
  // leading pointer argument carrying the function pointer to dispatch on.
  Value *ptr = CS->getCalledOperand();
  std::vector<Type *> TP;
  TP.insert(TP.begin(), ptr->getType());
  for (auto i = CS->arg_begin(); i != CS->arg_end(); ++i) {
    TP.push_back((*i)->getType());
  }

  FunctionType *NewTy = FunctionType::get(CS->getType(), TP, false);
  Module *M = CS->getParent()->getParent()->getParent();
  Function *F =
      Function::Create(NewTy, GlobalValue::InternalLinkage, "devirtbounce", M);

  // Synthetic DISubprogram for the bounce so its dispatch calls can carry a !dbg
  // location -- the inliner requires one to anchor the inlined debug info of the
  // (debug-info-bearing) real callees, else LLVM's verifier rejects the module
  // once the bounce is inlined. `bounceLoc` stays empty when the module has no
  // debug info (then F has no subprogram and no !dbg is needed).
  DebugLoc bounceLoc;
  if (DISubprogram *callerSP = CS->getFunction()->getSubprogram()) {
    DIBuilder DIB(*M);
    DISubprogram *SP = DIB.createFunction(
        callerSP->getUnit(), F->getName(), F->getName(), callerSP->getFile(),
        /*LineNo=*/0, DIB.createSubroutineType(DIB.getOrCreateTypeArray({})),
        /*ScopeLine=*/0, DINode::FlagArtificial,
        DISubprogram::SPFlagDefinition | DISubprogram::SPFlagLocalToUnit);
    F->setSubprogram(SP);
    DIB.finalizeSubprogram(SP);
    bounceLoc = DILocation::get(M->getContext(), 0, 0, SP);
  }

  // Set the names of the arguments.
  F->arg_begin()->setName("funcPtr");
  for (auto A = std::next(F->arg_begin()), E = F->arg_end(); A != E; ++A)
    A->setName("arg");

  // Create an entry basic block.
  BasicBlock *entryBB = BasicBlock::Create(M->getContext(), "entry", F);

  // For each function target, create a basic block that calls it directly.
  std::map<const Function *, BasicBlock *> targets;
  for (unsigned index = 0; index < Targets.size(); ++index) {
    const Function *FL = Targets[index];
    const FunctionType *FT = FL->getFunctionType();

    // Create the basic block for doing the direct call.
    BasicBlock *BL = BasicBlock::Create(M->getContext(), FL->getName(), F);
    targets[FL] = BL;

    // Create the direct function call.
    std::vector<Value *> Args;
    Function::arg_iterator P, PE;
    FunctionType::param_iterator T, TE;
    for (P = std::next(F->arg_begin()), PE = F->arg_end(), T = FT->param_begin(),
        TE = FT->param_end();
         P != PE && T != TE; ++P, ++T)
      Args.push_back(castTo(&*P, *T, "", BL));
    // A vararg target consumes the remaining callsite arguments unchanged.
    // Dropping the variadic tail would silently alter the call's semantics —
    // an argument the callee reads would vanish from the model.
    if (FL->isVarArg())
      for (; P != PE; ++P)
        Args.push_back(&*P);

    CallInst *directCall =
        CallInst::Create(const_cast<Function *>(FL), Args, "", BL);
    directCall->setDebugLoc(bounceLoc);

    // Add the return instruction for the basic block.
    if (CS->getType()->isVoidTy())
      ReturnInst::Create(M->getContext(), BL);
    else
      ReturnInst::Create(M->getContext(), directCall, BL);
  }

  // Create the no-match block. For a completeness-gated bounce it is
  // `unreachable` (provably infeasible). For an FLTA bounce it performs the
  // RESIDUAL INDIRECT CALL through the incoming function pointer -- the
  // translator turns that into the unknown-callee havoc model, so behaviors
  // outside the enumerated targets are over-approximated, never pruned.
  BasicBlock *failBB = BasicBlock::Create(M->getContext(), "fail", F);

  if (unknownFallback) {
    std::vector<Value *> Args;
    for (auto A = std::next(F->arg_begin()), E = F->arg_end(); A != E; ++A)
      Args.push_back(&*A);
    CallInst *residual = CallInst::Create(CS->getFunctionType(),
                                          &*F->arg_begin(), Args, "", failBB);
    residual->setDebugLoc(bounceLoc);
    if (CS->getType()->isVoidTy())
      ReturnInst::Create(M->getContext(), failBB);
    else
      ReturnInst::Create(M->getContext(), residual, failBB);
  } else if (Targets.size())
    new UnreachableInst(M->getContext(), failBB);
  else
    ReturnInst::Create(M->getContext(), failBB);

  // Entry block initially branches to the failure block; rewired below.
  BranchInst *InsertPt = BranchInst::Create(failBB, entryBB);

  // Build the comparison chain over the function pointer.
  Type *VoidPtrType = getVoidPtrType(M->getContext());
  Value *FArg = castTo(&*F->arg_begin(), VoidPtrType, "", InsertPt);
  BasicBlock *tailBB = failBB;
  for (unsigned index = 0; index < Targets.size(); ++index) {
    Value *TargetInt = castTo(const_cast<Function *>(Targets[index]),
                              VoidPtrType, "", InsertPt);

    BasicBlock *TB = targets[Targets[index]];
    BasicBlock *newB = BasicBlock::Create(
        M->getContext(), "test." + Targets[index]->getName(), F);
    CmpInst *setcc = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ,
                                     TargetInt, FArg, "sc", newB);
    BranchInst::Create(TB, tailBB, setcc, newB);

    tailBB = newB;
  }

  // Make the entry block branch to the first comparison block.
  InsertPt->setSuccessor(0, tailBB);
  return F;
}

//
// Method: findInCache()
//
// Looks for an existing bounce function reusable for this call site.
//
const Function *Devirtualize::findInCache(const CallBase *CS,
                                          std::set<const Function *> &Targets,
                                          bool unknownFallback) {
  for (auto I = bounceCache.begin(); I != bounceCache.end(); ++I) {
    const Function *bounceFunc = I->first;

    // An `unreachable`-fallback bounce and an FLTA (residual-indirect-call)
    // bounce are semantically different even over identical target sets.
    if (I->second.unknownFallback != unknownFallback)
      continue;

    // Check the return type.
    if (CS->getType() != bounceFunc->getReturnType())
      continue;

    // The bounce's signature is (funcPtr, <original callsite arg types...>).
    // Under opaque pointers a pointer-type check no longer discriminates, so
    // require the callsite's arity and argument types to match the bounce's
    // parameters exactly — mismatched reuse would mint an out-of-bounds
    // getParamType / ill-typed dispatch call. (Non-vararg targets force equal
    // arity via match(), but an all-vararg target set can be reached from
    // callsites of different shapes.)
    FunctionType *BT = bounceFunc->getFunctionType();
    if (BT->getNumParams() != CS->arg_size() + 1)
      continue;
    bool argsMatch = true;
    for (unsigned i = 0, n = CS->arg_size(); i < n; ++i)
      if (CS->getArgOperand(i)->getType() != BT->getParamType(i + 1)) {
        argsMatch = false;
        break;
      }
    if (!argsMatch)
      continue;

    // Determine whether the targets are identical.
    if (Targets == I->second.targets)
      return I->first;
  }

  return 0;
}

//
// Method: makeDirectCall()
//
// Transforms the specified indirect call site into a direct call, IF SVF
// resolves it completely; otherwise leaves it untouched.
//
void Devirtualize::makeDirectCall(CallBase *CS, bool allowFlta) {
  SvfResolution resolution = resolveSVFTargets(CS, allowFlta);
  recordDevirtResolution(*CS, resolution);

  // Dispatch when either (a) Andersen bounded the targets completely -- the
  // bounce gets the `unreachable` no-match branch -- or (b) the FLTA fallback
  // enumerated the signature-compatible address-taken candidates -- the bounce
  // keeps a residual indirect call as its no-match branch. Anything else is
  // left as an indirect call for the unknown-callee translation.
  if (!(resolution.complete || resolution.flta) || resolution.targets.empty())
    return;

  std::vector<const Function *> Targets = resolution.targets;
  std::set<const Function *> targetSet(Targets.begin(), Targets.end());
  if (resolution.flta)
    fltaTargets.insert(targetSet.begin(), targetSet.end());
  const Function *NF = findInCache(CS, targetSet, resolution.flta);

  if (!NF) {
    NF = buildBounce(CS, Targets, resolution.flta);
    bounceCache[NF] = {targetSet, resolution.flta};
  }

  // Replace the original call with a call to the bounce function.
  if (CallInst *CI = dyn_cast<CallInst>(CS)) {
    std::vector<Value *> Params;
    Params.push_back(CI->getCalledOperand());
    for (unsigned i = 0; i < CI->arg_size(); i++) {
      Params.push_back(castTo(CI->getArgOperand(i),
                              NF->getFunctionType()->getParamType(i + 1), "",
                              CS));
    }

    std::string name = CI->hasName() ? CI->getName().str() + ".dv" : "";
    CallInst *CN = CallInst::Create(const_cast<Function *>(NF), Params, name, CI);
    CN->setDebugLoc(devirtCallLoc(CI));
    CI->replaceAllUsesWith(CN);
    CI->eraseFromParent();
  } else if (InvokeInst *CI = dyn_cast<InvokeInst>(CS)) {
    std::vector<Value *> Params;
    Params.push_back(CI->getCalledOperand());
    for (unsigned i = 0; i < CI->arg_size(); i++)
      Params.push_back(castTo(CI->getArgOperand(i),
                              NF->getFunctionType()->getParamType(i + 1), "",
                              CS));
    std::string name = CI->hasName() ? CI->getName().str() + ".dv" : "";
    InvokeInst *CN =
        InvokeInst::Create(const_cast<Function *>(NF), CI->getNormalDest(),
                           CI->getUnwindDest(), Params, name, CI);
    CN->setDebugLoc(devirtCallLoc(CI));
    CI->replaceAllUsesWith(CN);
    CI->eraseFromParent();
  }

  // Update the statistics on the number of transformed call sites.
  ++CSConvert;
}

//
// Method: processCallSite()
//
// If CS is an indirect call, queue it for transformation. Whether it is
// actually devirtualized is decided in makeDirectCall (completeness gate).
//
void Devirtualize::processCallSite(CallBase *CS) {
  if (!CS->isIndirectCall())
    return;

  DevirtCallsiteIndices[CS] = Worklist.size();
  Worklist.push_back(CS);
}

//
// Stub every function that is UNREACHABLE in SVF's (sound) call graph:
// replace its body with `unreachable`. Such a function is provably never
// called (no caller, not a resolved target of any indirect call, and not an
// FLTA fallback target — those are passed in as extra roots), so its body is
// dead and the stub is sound. This is points-to-informed dead-code
// elimination: LLVM's globaldce conservatively keeps these functions because
// they are address-taken (e.g. a vtable constant lists them), but SVF proves
// no call edge actually reaches them. Two payoffs: (1) an unresolved indirect
// call inside a dead function disappears instead of becoming an unknown-callee
// havoc site (example: BearSSL's `br_gcm_aad_inject`, listed in
// `br_gcm_vtable` but never dispatched); (2) dead bodies vanish from the
// emitted .bpl, shrinking parse/translation cost on library-scale benchmarks.
//
// `extraRoots` = FLTA fallback targets: an FLTA bounce dispatches to them on
// dynamically taken edges SVF's call graph does not contain, so they must be
// treated as live. (Andersen-complete bounce targets need no such treatment —
// the ind-call edges that justified the bounce are already in the call graph.)
//
// SVF-call-graph reachability from the functions SMACK keeps live (same root
// predicate as its internalize pass: entry points, smack-internal names, the
// assume intrinsic), extended with `extraRoots`, following direct +
// SVF-resolved indirect call edges. Fills `byName` (function name -> call-graph
// node). Returns an EMPTY set when no primary root exists (e.g. a direct
// llvm2bpl invocation without -entry-points) — callers must treat that as
// "reachability unknown" and stay conservative, mirroring
// DSAWrapper::computeReachable's empty-roots fallback.
static std::set<const SVF::CallGraphNode *>
cgReachable(Module &M,
            std::map<std::string, const SVF::CallGraphNode *> &byName,
            const std::set<const Function *> &extraRoots) {
  std::set<const SVF::CallGraphNode *> reachable;
  byName.clear();

  SVF::LLVMModuleSet *ms = nullptr;
  SVF::SVFIR *pag = nullptr;
  SVF::Andersen *ander = nullptr;
  if (!smack::DSAWrapper::cachedSVF(ms, pag, ander) || !ander)
    return reachable;
  SVF::CallGraph *cg = ander->getCallGraph();
  if (!cg)
    return reachable;

  for (const auto &item : *cg)
    byName[item.second->getName()] = item.second;

  std::vector<const SVF::CallGraphNode *> work;
  auto visit_root = [&](const SVF::CallGraphNode *n) {
    if (n && reachable.insert(n).second)
      work.push_back(n);
  };
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    StringRef nm = F.getName();
    if (smack::SmackOptions::isEntryPoint(nm) || smack::Naming::isSmackName(nm) ||
        nm.contains("__VERIFIER_assume")) {
      auto it = byName.find(nm.str());
      if (it != byName.end())
        visit_root(it->second);
    }
  }
  if (reachable.empty())
    return reachable; // no primary roots -> "unknown", stay conservative
  for (const Function *F : extraRoots) {
    auto it = byName.find(F->getName().str());
    if (it != byName.end())
      visit_root(it->second);
  }
  while (!work.empty()) {
    const SVF::CallGraphNode *n = work.back();
    work.pop_back();
    for (const SVF::CallGraphEdge *e : n->getOutEdges())
      visit_root(e->getDstNode());
  }
  return reachable;
}

static void
stubUnreachableFunctions(Module &M,
                         const std::set<const Function *> &extraRoots) {
  std::map<std::string, const SVF::CallGraphNode *> byName;
  std::set<const SVF::CallGraphNode *> reachable =
      cgReachable(M, byName, extraRoots);
  if (reachable.empty())
    return; // SVF unavailable or no roots -> skip stubbing entirely

  for (Function &F : M) {
    if (F.isDeclaration() || F.empty())
      continue;
    auto it = byName.find(F.getName().str());
    if (it == byName.end())
      continue; // not modeled by SVF -> conservatively leave it
    if (reachable.count(it->second))
      continue; // reachable from a root -> live
    // Already a bare `unreachable` stub -> idempotent, skip.
    if (F.size() == 1 && F.front().size() == 1 &&
        isa<UnreachableInst>(F.front().front()))
      continue;

    // Replace the body with a single `unreachable` (preserve linkage so any
    // vtable constant referencing the function stays valid).
    auto linkage = F.getLinkage();
    for (BasicBlock &BB : F)
      BB.dropAllReferences();
    while (!F.empty())
      F.begin()->eraseFromParent();
    BasicBlock *bb = BasicBlock::Create(F.getContext(), "", &F);
    new UnreachableInst(F.getContext(), bb);
    F.setLinkage(linkage);
    ++DeadFnStubbed;
  }
}

//
// Method: runOnModule()
//
// Entry point: find indirect calls and turn the completely-resolved ones into
// direct calls.
//
bool Devirtualize::runOnModule(Module &M) {
  Worklist.clear();
  DevirtCallsiteIndices.clear();
  fltaTargets.clear();
  if (!DevirtReportFilename.empty())
    DevirtReportEntries.clear();

  TD = &M.getDataLayout();

  // Collect indirect call sites, then transform. FLTA fallbacks are gated on
  // the callsite's function being SVF-cg-reachable: a dead function's body is
  // stubbed below anyway, and letting its unresolved callsites enumerate FLTA
  // targets would needlessly root large parts of the module live. (Callsites
  // inside FLTA targets themselves are conservatively NOT FLTA'd this pass —
  // they translate as unknown-callee havoc; a fixpoint could refine that if it
  // ever matters.)
  visit(M);
  std::map<std::string, const SVF::CallGraphNode *> byName;
  std::set<const SVF::CallGraphNode *> live = cgReachable(M, byName, {});
  auto isLive = [&](const Function *F) {
    if (live.empty())
      return true; // reachability unknown -> allow FLTA everywhere
    auto it = byName.find(F->getName().str());
    return it == byName.end() || live.count(it->second) != 0;
  };
  for (unsigned index = 0; index < Worklist.size(); ++index)
    makeDirectCall(Worklist[index],
                   isLive(Worklist[index]->getFunction()));

  // Neutralize unreachable functions (points-to-informed dead-code
  // elimination); FLTA targets count as live roots.
  stubUnreachableFunctions(M, fltaTargets);

  writeDevirtReport(M);

  // Conservatively assume we've changed one or more call sites.
  return true;
}

void Devirtualize::getAnalysisUsage(AnalysisUsage &AU) const {
  // Forces DSAWrapper (which builds the SVF analysis devirt reuses) to run
  // first. We only need the side effect -- the SVF singletons -- which we read
  // via DSAWrapper::cachedSVF.
  AU.addRequired<smack::DSAWrapper>();
}

// Pass ID variable
char Devirtualize::ID = 0;

llvm::PreservedAnalyses
DevirtualizeNewPM::run(Module &M, ModuleAnalysisManager &MAM) {
  // Ensure SVF is built (DSAWrapperAnalysis caches it) before devirt resolves.
  MAM.getResult<smack::DSAWrapperAnalysis>(M);
  Devirtualize pass;
  bool changed = pass.runOnModule(M);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

using namespace smack;
// Pass registration
INITIALIZE_PASS_BEGIN(Devirtualize, "devirt",
                      "Devirtualize indirect function calls", false, false)
INITIALIZE_PASS_DEPENDENCY(DSAWrapper)
INITIALIZE_PASS_END(Devirtualize, "devirt",
                    "Devirtualize indirect function calls", false, false)
