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
// possible targets (a "bounce" function), so known targets become precise
// direct calls. Every bounce retains the original indirect call as its no-match
// branch. The translator models that residual as unknown-callee havoc, so an
// incomplete SVF/FLTA target set can never remove a runtime behavior.
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

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"

// SVF supplies the over-approximated indirect-call targets. Reuse the analysis
// DSAWrapper builds once; see DSAWrapper::cachedSVF.
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

static cl::opt<std::string> DevirtReportFilename(
    "smack-devirt-report",
    cl::desc("Output SMACK devirtualization target report as JSON"),
    cl::init(""), cl::value_desc("filename"));

// Type-based filtering (default ON). SVF's points-to over-approximates a vtable
// method slot to also include signature-INCOMPATIBLE functions (e.g. a 3-arg RSA
// fn appears as a candidate for a 2-arg hash-method slot). A well-typed indirect
// call can never reach such a target -- calling through a signature-incompatible
// fp is UB -- so it is an SVF false positive. Dropping it keeps the direct
// branches precise; the residual indirect branch still covers every unmatched
// runtime target. UNMAPPED targets (no module function of that name) are not
// filtered: that is a name-mapping failure, not UB evidence, so the whole site
// is declined regardless of this flag. Pass -devirt-strict-types to also decline
// the whole site on any signature-incompatible target (the safety valve).
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

static bool hasAbiParameterAttributes(const AttributeList &attributes,
                                      unsigned argumentCount) {
  static constexpr Attribute::AttrKind abiKinds[] = {
      Attribute::InReg,        Attribute::Nest,
      Attribute::SExt,         Attribute::ZExt,
      Attribute::SwiftAsync,   Attribute::SwiftError,
      Attribute::SwiftSelf,    Attribute::ByRef,
      Attribute::ByVal,        Attribute::ElementType,
      Attribute::ImmArg,       Attribute::InAlloca,
      Attribute::NoExt,        Attribute::Preallocated,
      Attribute::StructRet};
  for (unsigned argument = 0; argument < argumentCount; ++argument)
    for (Attribute::AttrKind kind : abiKinds)
      if (attributes.hasParamAttr(argument, kind))
        return true;
  return false;
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
static inline bool hasCompatibleCallShape(CallBase *CS, const Function &F) {
  auto N = CS->arg_size();
  auto T = F.getFunctionType();
  auto M = T->getNumParams();
  auto RT = T->getReturnType();
  auto IT = CS->getType();

  const auto *calledPointer =
      dyn_cast<PointerType>(CS->getCalledOperand()->getType());
  if (!calledPointer || calledPointer->getAddressSpace() != 0 ||
      F.getAddressSpace() != 0 || RT != IT ||
      CS->getCallingConv() != F.getCallingConv() || N < M ||
      (N > M && !F.isVarArg()))
    return false;

  for (unsigned i = 0; i < M; i++)
    if (CS->getArgOperand(i)->getType() != T->getParamType(i))
      return false;

  return true;
}

static bool containsCallerSensitiveIntrinsic(const Function &F) {
  if (F.isDeclaration())
    return false;
  for (const Instruction &I : instructions(F)) {
    const auto *CB = dyn_cast<CallBase>(&I);
    const Function *callee = CB ? CB->getCalledFunction() : nullptr;
    if (!callee || !callee->isIntrinsic())
      continue;
    const StringRef name = callee->getName();
    if (name.starts_with("llvm.returnaddress") ||
        name.starts_with("llvm.frameaddress") ||
        name.starts_with("llvm.addressofreturnaddress"))
      return true;
  }
  return false;
}

// A helper frame is itself observable for these features. A residual indirect
// edge cannot repair that semantic change: the unsupported target would still
// execute inside the helper. One such possible target therefore declines the
// entire callsite rather than merely being filtered from the direct branches.
static std::string unsupportedTargetRewrite(CallBase *CS, const Function &F) {
  if (!hasCompatibleCallShape(CS, F))
    return "";
  if (F.hasFnAttribute(Attribute::ReturnsTwice))
    return "unsupported-target:returns-twice:" + F.getName().str();
  if (F.hasFnAttribute(Attribute::StrictFP))
    return "unsupported-target:strictfp:" + F.getName().str();
  if (F.isConvergent())
    return "unsupported-target:convergent:" + F.getName().str();
  if (F.hasFnAttribute(Attribute::NoDuplicate))
    return "unsupported-target:noduplicate:" + F.getName().str();
  if (containsCallerSensitiveIntrinsic(F))
    return "unsupported-target:caller-sensitive:" + F.getName().str();
  return "";
}

static inline bool match(CallBase *CS, const Function &F) {
  auto N = CS->arg_size();
  auto T = F.getFunctionType();
  auto M = T->getNumParams();

  // A bounce is an ordinary internal function. Restrict rewrites to the exact
  // ABI subset it preserves; dropping non-ABI semantic attributes only adds
  // behaviors, while the residual indirect edge handles every excluded
  // callsite without dropping a possible execution.
  if (!hasCompatibleCallShape(CS, F) || CS->getNumOperandBundles() != 0 ||
      hasAbiParameterAttributes(CS->getAttributes(), N) ||
      hasAbiParameterAttributes(F.getAttributes(), M) || CS->isConvergent() ||
      F.isConvergent() || CS->hasFnAttr(Attribute::NoDuplicate) ||
      F.hasFnAttribute(Attribute::NoDuplicate) ||
      CS->hasFnAttr(Attribute::StackAlignment) ||
      F.hasFnAttribute(Attribute::StackAlignment) ||
      CS->getAttributes().hasRetAttr(Attribute::InReg) ||
      CS->getAttributes().hasRetAttr(Attribute::NoExt) ||
      CS->getAttributes().hasRetAttr(Attribute::SExt) ||
      CS->getAttributes().hasRetAttr(Attribute::ZExt) ||
      F.getAttributes().hasRetAttr(Attribute::InReg) ||
      F.getAttributes().hasRetAttr(Attribute::NoExt) ||
      F.getAttributes().hasRetAttr(Attribute::SExt) ||
      F.getAttributes().hasRetAttr(Attribute::ZExt))
    return false;
  if (const auto *CI = dyn_cast<CallInst>(CS))
    if (CI->isMustTailCall())
      return false;

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
// SVF target resolution.
//===----------------------------------------------------------------------===//

namespace {

//
// Resolve the targets of indirect call CS from SVF's Andersen call graph.
//
// The bounded-target gate is:
//   (1) SVF has resolved callees for this site (hasIndCSCallees), AND
//   (2) the function pointer's points-to set excludes the black-hole (SVF's
//       "points to some unknown object" marker), AND
//   (3) every resolved callee maps to a signature-compatible llvm::Function.
// If the gate fails, FLTA may still provide direct-target precision. The
// residual indirect edge always covers omitted runtime targets.
//
DevirtResolution resolveAndersenTargets(CallBase *CS) {
  DevirtResolution R;
  Module &M = *CS->getModule();

  SVF::LLVMModuleSet *ms = nullptr;
  SVF::SVFIR *pag = nullptr;
  SVF::Andersen *ander = nullptr;
  if (!smack::DSAWrapper::cachedSVF(M, ms, pag, ander) || !ms || !pag ||
      !ander) {
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

  // A black-hole means Andersen did not bound the target set; use FLTA instead.
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
      // cannot execute. Decline this Andersen set and let FLTA/residual
      // handling preserve the callsite.
      R.reason = "target-unmapped:" + name;
      return R;
    }
    if (isIgnoredTarget(*F))
      continue;
    if (std::string unsupported = unsupportedTargetRewrite(CS, *F);
        !unsupported.empty()) {
      R.rewriteSafe = false;
      R.reason = std::move(unsupported);
      return R;
    }
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
// unknown-callee havoc.
//
DevirtResolution resolveSVFTargets(CallBase *CS, bool allowFlta) {
  DevirtResolution R;
  if (isa<InvokeInst>(CS)) {
    R.rewriteSafe = false;
    R.reason = "unsupported-callsite:invoke";
    return R;
  }
  if (CS->hasFnAttr(Attribute::ReturnsTwice)) {
    R.rewriteSafe = false;
    R.reason = "unsupported-callsite:returns-twice";
    return R;
  }
  if (CS->hasFnAttr(Attribute::StrictFP) ||
      CS->getFunction()->hasFnAttribute(Attribute::StrictFP)) {
    R.rewriteSafe = false;
    R.reason = "unsupported-callsite:strictfp";
    return R;
  }
  if (CS->getFunction()->hasGC()) {
    R.rewriteSafe = false;
    R.reason = "unsupported-callsite:gc";
    return R;
  }

  R = resolveAndersenTargets(CS);
  if (!R.rewriteSafe || R.complete || !allowFlta)
    return R;

  Module &M = *CS->getModule();
  std::set<const Function *> flta;
  for (Function &F : M) {
    if (F.isIntrinsic() || !F.hasAddressTaken())
      continue;
    if (F.getName().starts_with("devirtbounce") ||
        F.hasFnAttribute("smack.devirt.bounce") || isIgnoredTarget(F))
      continue; // never dispatch into our own bounces / SMACK intrinsics
    if (std::string unsupported = unsupportedTargetRewrite(CS, F);
        !unsupported.empty()) {
      R.targets.clear();
      R.flta = false;
      R.rewriteSafe = false;
      R.reason = std::move(unsupported);
      return R;
    }
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
                            const DevirtResolution &resolution) {
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
//  target and, on a match, performs the direct call. The no-match branch always
//  executes the residual indirect call. The translator models it as an
//  unknown-callee havoc, so a target omitted by SVF/FLTA is over-approximated.
//
Function *Devirtualize::buildBounce(CallBase *CS,
                                    std::vector<const Function *> &Targets) {
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
  F->setCallingConv(CS->getCallingConv());

  // Bounces are synthetic and intentionally carry no DISubprogram. Pre-BPL
  // cleanup can leave caller debug scopes without a retained compile unit;
  // manufacturing a definition-scoped DISubprogram from such metadata creates
  // invalid IR. An empty location is valid for these dead-last dispatch calls.
  DebugLoc bounceLoc;

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
    directCall->setCallingConv(FL->getCallingConv());
    directCall->setDebugLoc(bounceLoc);

    // Add the return instruction for the basic block.
    if (CS->getType()->isVoidTy())
      ReturnInst::Create(M->getContext(), BL);
    else
      ReturnInst::Create(M->getContext(), directCall, BL);
  }

  // The no-match block performs the residual indirect call through the incoming
  // function pointer. Translation turns it into unknown-callee havoc.
  BasicBlock *failBB = BasicBlock::Create(M->getContext(), "fail", F);

  std::vector<Value *> Args;
  for (auto A = std::next(F->arg_begin()), E = F->arg_end(); A != E; ++A)
    Args.push_back(&*A);
  CallInst *residual = CallInst::Create(CS->getFunctionType(),
                                        &*F->arg_begin(), Args, "", failBB);
  residual->setCallingConv(CS->getCallingConv());
  residual->setDebugLoc(bounceLoc);
  if (CS->getType()->isVoidTy())
    ReturnInst::Create(M->getContext(), failBB);
  else
    ReturnInst::Create(M->getContext(), residual, failBB);

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
                                          std::set<const Function *> &Targets) {
  for (auto I = bounceCache.begin(); I != bounceCache.end(); ++I) {
    const Function *bounceFunc = I->first;

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
// Transforms an indirect call when Andersen or FLTA supplies direct targets.
//
void Devirtualize::makeDirectCall(CallBase *CS,
                                  const DevirtResolution &resolution) {
  // A helper call cannot preserve InvokeInst's unwind edge or CallBrInst's
  // indirect destinations. Only ordinary calls enter the bounce rewrite.
  if (!isa<CallInst>(CS))
    return;

  // Without any candidate, leave the original indirect call for unknown-callee
  // translation.
  if (!resolution.rewriteSafe ||
      (!(resolution.complete || resolution.flta) ||
       resolution.targets.empty()))
    return;

  std::vector<const Function *> Targets = resolution.targets;
  std::set<const Function *> targetSet(Targets.begin(), Targets.end());
  // SVF/FLTA targets are precision hints, never an exhaustiveness authority.
  // Every bounce keeps the residual indirect call on the no-match edge.
  const Function *NF = findInCache(CS, targetSet);

  if (!NF) {
    NF = buildBounce(CS, Targets);
    bounceCache[NF] = {targetSet};
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
    CallInst *CN =
        CallInst::Create(const_cast<Function *>(NF), Params, name, CI);
    CN->setCallingConv(CI->getCallingConv());
    CN->setDebugLoc(devirtCallLoc(CI));
    CI->replaceAllUsesWith(CN);
    CI->eraseFromParent();
  }

  // Update the statistics on the number of transformed call sites.
  ++CSConvert;
  Changed = true;
}

//
// Method: processCallSite()
//
// If CS is an indirect call, queue it for transformation. Whether it is
// actually devirtualized is decided in makeDirectCall (target availability).
//
void Devirtualize::processCallSite(CallBase *CS) {
  if (!CS->isIndirectCall() ||
      (!isa<CallInst>(CS) && !isa<InvokeInst>(CS)))
    return;

  // A prior early-devirtualization run already modeled these residual calls.
  // Processing them again only nests equivalent bounces indefinitely.
  const Function *caller = CS->getFunction();
  if (caller->getName().starts_with("devirtbounce") ||
      caller->hasFnAttribute("smack.devirt.bounce"))
    return;

  DevirtCallsiteIndices[CS] = indirectCallsiteIndex(*CS);
  Worklist.push_back(CS);
}

//
// Method: runOnModule()
//
// Entry point: turn resolvable indirect calls into direct-target dispatches
// with a residual indirect fallback.
//
bool Devirtualize::runOnModule(Module &M) {
  Worklist.clear();
  bounceCache.clear();
  DevirtCallsiteIndices.clear();
  Changed = false;
  if (!DevirtReportFilename.empty())
    DevirtReportEntries.clear();

  TD = &M.getDataLayout();

  // The residual no-match edge makes both Andersen and FLTA target lists safe
  // precision hints, so every remaining callsite may use FLTA.
  visit(M);
  std::vector<DevirtResolution> resolutions;
  resolutions.reserve(Worklist.size());
  for (CallBase *CS : Worklist) {
    resolutions.push_back(resolveSVFTargets(CS, true));
    recordDevirtResolution(*CS, resolutions.back());
  }
  for (unsigned index = 0; index < Worklist.size(); ++index)
    makeDirectCall(Worklist[index], resolutions[index]);

  writeDevirtReport(M);

  return Changed;
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
  // Building that result may normalize M in place on its first run. Invalidate
  // every other cached analysis even when no bounce was emitted; preserving
  // them would expose pre-normalization facts to the remaining pipeline.
  MAM.getResult<smack::DSAWrapperAnalysis>(M);
  Devirtualize pass;
  pass.runOnModule(M);
  return PreservedAnalyses::none();
}

using namespace smack;
// Pass registration
INITIALIZE_PASS_BEGIN(Devirtualize, "devirt",
                      "Devirtualize indirect function calls", false, false)
INITIALIZE_PASS_DEPENDENCY(DSAWrapper)
INITIALIZE_PASS_END(Devirtualize, "devirt",
                    "Devirtualize indirect function calls", false, false)
