//
// This file is distributed under the MIT License. See LICENSE for details.
//
// SVF-backed DSAWrapper. See include/smack/DSAWrapper.h for the design.
//
#include "smack/DSAWrapper.h"
#include "smack/Debug.h"
#include "smack/InitializePasses.h"
#include "smack/LlvmCompat.h"
#include "smack/Naming.h"
#include "smack/SmackOptions.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include <algorithm>
#include "llvm/ADT/SmallPtrSet.h"
#include <cstdlib>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"

#include "MemoryModel/PointsTo.h"
#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SVFIR/SVFVariables.h"
#include "Util/SVFUtil.h"
#include "WPA/Andersen.h"

#define DEBUG_TYPE "smack-dsa-wrapper"

namespace smack {

using namespace llvm;

// Recover the allocation origin of ordinary GEP/cast chains and of the common
// single-store pointer spill produced at -O0. The spill case is a must-equality:
// its address does not escape, it has exactly one non-volatile pointer store,
// and every direct load therefore returns that stored pointer.
static const llvm::Value *underlyingThroughSpill(const llvm::Value *V,
                                                 unsigned depth = 2) {
  const llvm::Value *base = llvm::getUnderlyingObject(V);
  if (depth == 0)
    return base;
  const auto *load = llvm::dyn_cast<llvm::LoadInst>(base);
  if (!load || load->isVolatile())
    return base;
  const auto *slot =
      llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
  if (!slot)
    return base;

  const llvm::StoreInst *stored = nullptr;
  for (const llvm::User *user : slot->users()) {
    if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
      if (store->getPointerOperand() != slot || store->isVolatile() ||
          !store->getValueOperand()->getType()->isPointerTy() || stored)
        return base;
      stored = store;
    } else if (const auto *directLoad =
                   llvm::dyn_cast<llvm::LoadInst>(user)) {
      if (directLoad->getPointerOperand() != slot)
        return base;
    } else if (const auto *intrinsic =
                   llvm::dyn_cast<llvm::IntrinsicInst>(user)) {
      switch (intrinsic->getIntrinsicID()) {
      case llvm::Intrinsic::dbg_declare:
      case llvm::Intrinsic::dbg_value:
      case llvm::Intrinsic::lifetime_start:
      case llvm::Intrinsic::lifetime_end:
        break;
      default:
        return base;
      }
    } else {
      return base;
    }
  }
  return stored ? underlyingThroughSpill(stored->getValueOperand(), depth - 1)
                : base;
}

// SVF is built ONCE into these process-global handles and reused across
// DSAWrapper re-runs AND by the SVF-based devirtualizer: SVF cannot be rebuilt
// in-process (release()+rebuild trips SVFIRBuilder::initialiseNodes' node/sym
// count assert — its many singletons do not fully reset). Kept at file scope (not
// function-local statics) so DSAWrapper::cachedSVF can hand them to the devirt
// pass, which runs after DSAWrapper and must reuse the same pre-devirt points-to.
static SVF::LLVMModuleSet *g_svfModuleSet = nullptr;
static SVF::SVFIR *g_svfIR = nullptr;
static SVF::Andersen *g_svfAndersen = nullptr;
static const llvm::Module *g_svfModule = nullptr;
static std::string g_svfModuleSnapshot;
static std::vector<const llvm::Value *> g_svfValueIdentity;
static bool g_svfSnapshotStale = false;

static std::string moduleSnapshot(const llvm::Module &M) {
  std::string text;
  llvm::raw_string_ostream out(text);
  M.print(out, nullptr);
  return text;
}

static std::vector<const llvm::Value *>
moduleValueIdentity(const llvm::Module &M) {
  // Pointer identity complements the textual epoch: erase-and-recreate cannot
  // accidentally reuse SVF NodeIDs merely because the printed IR is unchanged.
  std::vector<const llvm::Value *> identity;
  for (const llvm::GlobalVariable &G : M.globals())
    identity.push_back(&G);
  for (const llvm::GlobalAlias &A : M.aliases())
    identity.push_back(&A);
  for (const llvm::GlobalIFunc &I : M.ifuncs())
    identity.push_back(&I);
  for (const llvm::Function &F : M) {
    identity.push_back(&F);
    for (const llvm::Argument &A : F.args())
      identity.push_back(&A);
    for (const llvm::BasicBlock &B : F) {
      identity.push_back(&B);
      for (const llvm::Instruction &I : B)
        identity.push_back(&I);
    }
  }
  return identity;
}

static bool containsIntToPtr(const llvm::Value *V) {
  if (llvm::isa<llvm::IntToPtrInst>(V))
    return true;
  auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(V);
  if (!CE)
    return false;
  if (CE->getOpcode() == llvm::Instruction::IntToPtr)
    return true;
  for (const llvm::Use &U : CE->operands())
    if (containsIntToPtr(U.get()))
      return true;
  return false;
}

static bool typeContainsPointer(const llvm::Type *T) {
  if (T->isPointerTy())
    return true;
  if (auto *AT = llvm::dyn_cast<llvm::ArrayType>(T))
    return typeContainsPointer(AT->getElementType());
  if (auto *VT = llvm::dyn_cast<llvm::VectorType>(T))
    return typeContainsPointer(VT->getElementType());
  if (auto *ST = llvm::dyn_cast<llvm::StructType>(T))
    for (llvm::Type *Element : ST->elements())
      if (typeContainsPointer(Element))
        return true;
  return false;
}

static bool typeUsesErasedAddressSpace(const llvm::Type *T,
                                       const llvm::DataLayout &DL) {
  if (auto *PT = llvm::dyn_cast<llvm::PointerType>(T))
    return PT->getAddressSpace() != 0 ||
           DL.isNonIntegralAddressSpace(PT->getAddressSpace());
  if (auto *AT = llvm::dyn_cast<llvm::ArrayType>(T))
    return typeUsesErasedAddressSpace(AT->getElementType(), DL);
  if (auto *VT = llvm::dyn_cast<llvm::VectorType>(T))
    return typeUsesErasedAddressSpace(VT->getElementType(), DL);
  if (auto *ST = llvm::dyn_cast<llvm::StructType>(T))
    for (llvm::Type *Element : ST->elements())
      if (typeUsesErasedAddressSpace(Element, DL))
        return true;
  return false;
}

static bool containsUnsupportedPointerConstant(
    const llvm::Value *V,
    llvm::SmallPtrSetImpl<const llvm::Value *> &visited) {
  if (!visited.insert(V).second)
    return false;
  if ((llvm::isa<llvm::UndefValue>(V) || llvm::isa<llvm::PoisonValue>(V)) &&
      typeContainsPointer(V->getType()))
    return true;
  if (containsIntToPtr(V))
    return true;
  auto *C = llvm::dyn_cast<llvm::Constant>(V);
  if (!C)
    return false;
  for (const llvm::Use &U : C->operands())
    if (containsUnsupportedPointerConstant(U.get(), visited))
      return true;
  return false;
}

static bool containsUnsupportedPointerConstant(const llvm::Value *V) {
  llvm::SmallPtrSet<const llvm::Value *, 16> visited;
  return containsUnsupportedPointerConstant(V, visited);
}

static bool hasStableGlobalIdentity(const llvm::GlobalValue &GV) {
  if (GV.isDeclarationForLinker() || GV.hasExternalWeakLinkage() ||
      GV.isInterposable())
    return false;
  return GV.hasLocalLinkage() || GV.isDSOLocal();
}

static bool isClosedConstantDataGlobal(const llvm::GlobalVariable &G,
                                       const llvm::DataLayout &DL) {
  return G.isConstant() && G.hasInitializer() && G.getValueType()->isSized() &&
         !G.isExternallyInitialized() && hasStableGlobalIdentity(G) &&
         !typeContainsPointer(G.getValueType()) &&
         !typeUsesErasedAddressSpace(G.getType(), DL) &&
         !typeUsesErasedAddressSpace(G.getValueType(), DL);
}

// SVF 3.1 aborts on some LLVM-21 pointer constants before it can return a
// points-to set (notably ptrauth and nested nonzero-address-space expressions).
// Admit only the constant forms whose pointer provenance is explicitly handled
// below, so an unknown future constant fails closed before SVF construction.
static bool auditedPointerConstant(
    const llvm::Value *V, const llvm::DataLayout &DL,
    llvm::SmallPtrSetImpl<const llvm::Value *> &active) {
  if (!typeContainsPointer(V->getType())) {
    const auto *C = llvm::dyn_cast<llvm::Constant>(V);
    if (!C)
      return true;
    if (!active.insert(V).second)
      return false;
    bool audited = true;
    for (const llvm::Use &U : C->operands())
      if (llvm::isa<llvm::Constant>(U.get()) &&
          !auditedPointerConstant(U.get(), DL, active)) {
        audited = false;
        break;
      }
    active.erase(V);
    return audited;
  }
  if (!active.insert(V).second)
    return false;

  bool audited = false;
  if (llvm::isa<llvm::ConstantPointerNull>(V) ||
      llvm::isa<llvm::ConstantAggregateZero>(V)) {
    audited = true;
  } else if (const auto *GV = llvm::dyn_cast<llvm::GlobalValue>(V)) {
    audited = !llvm::isa<llvm::GlobalIFunc>(GV);
  } else if (const auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(V)) {
    const unsigned opcode = CE->getOpcode();
    audited = (opcode == llvm::Instruction::BitCast ||
               opcode == llvm::Instruction::GetElementPtr) &&
              !typeUsesErasedAddressSpace(CE->getType(), DL);
    if (audited)
      for (const llvm::Use &U : CE->operands())
        if (typeContainsPointer(U->getType()) &&
            (!auditedPointerConstant(U.get(), DL, active) ||
             typeUsesErasedAddressSpace(U->getType(), DL))) {
          audited = false;
          break;
        }
  } else if (const auto *C = llvm::dyn_cast<llvm::Constant>(V)) {
    // Aggregate pointer constants are safe only when every pointer-bearing
    // element recursively uses one of the scalar forms above.
    audited = !C->getType()->isPointerTy() &&
              !llvm::isa<llvm::UndefValue>(C) &&
              !llvm::isa<llvm::PoisonValue>(C) &&
              !llvm::isa<llvm::ConstantPtrAuth>(C) &&
              !llvm::isa<llvm::BlockAddress>(C);
    if (audited) {
      for (const llvm::Use &U : C->operands())
        if (typeContainsPointer(U->getType())) {
          if (!auditedPointerConstant(U.get(), DL, active) ||
              typeUsesErasedAddressSpace(U->getType(), DL)) {
            audited = false;
            break;
          }
        }
    }
  }

  active.erase(V);
  return audited && !typeUsesErasedAddressSpace(V->getType(), DL);
}

static bool auditedPointerConstant(const llvm::Value *V,
                                   const llvm::DataLayout &DL) {
  llvm::SmallPtrSet<const llvm::Value *, 16> active;
  return auditedPointerConstant(V, DL, active);
}

static void saturatingIncrement(unsigned &count) {
  if (count != std::numeric_limits<unsigned>::max())
    ++count;
}

static unsigned preSVFUnsupportedConstantCount(const llvm::Module &M) {
  const llvm::DataLayout &DL = M.getDataLayout();
  unsigned count = 0;
  for (const llvm::GlobalVariable &G : M.globals())
    if (G.hasInitializer() &&
        !auditedPointerConstant(G.getInitializer(), DL))
      saturatingIncrement(count);
  for (const llvm::GlobalAlias &A : M.aliases())
    if (!auditedPointerConstant(A.getAliasee(), DL))
      saturatingIncrement(count);
  for (const llvm::Function &F : M)
    for (const llvm::Instruction &I : llvm::instructions(F))
      for (const llvm::Use &U : I.operands())
        if (llvm::isa<llvm::Constant>(U.get()) &&
            !auditedPointerConstant(U.get(), DL))
          saturatingIncrement(count);
  return count;
}

struct StaticGlobalOffset {
  const llvm::GlobalVariable *base;
  uint64_t offset;
};

static bool fixedAllocSize(const llvm::DataLayout &DL, const llvm::Type *T,
                           uint64_t &size) {
  if (!T || !T->isSized())
    return false;
  const llvm::TypeSize typeSize =
      DL.getTypeAllocSize(const_cast<llvm::Type *>(T));
  if (typeSize.isScalable())
    return false;
  size = typeSize.getFixedValue();
  return true;
}

static bool fixedStoreSize(const llvm::DataLayout &DL, const llvm::Type *T,
                           uint64_t &size) {
  if (!T || !T->isSized())
    return false;
  const llvm::TypeSize typeSize =
      DL.getTypeStoreSize(const_cast<llvm::Type *>(T));
  if (typeSize.isScalable())
    return false;
  size = typeSize.getFixedValue();
  return true;
}

static bool checkedAdd(uint64_t lhs, uint64_t rhs, uint64_t &sum) {
  if (lhs > std::numeric_limits<uint64_t>::max() - rhs)
    return false;
  sum = lhs + rhs;
  return true;
}

static bool exactNonnegativeGepOffset(const llvm::GEPOperator &GEP,
                                      const llvm::DataLayout &DL,
                                      uint64_t &offset) {
  const unsigned indexBits = DL.getIndexTypeSizeInBits(GEP.getType());
  std::vector<const llvm::Value *> indices;
  indices.reserve(GEP.getNumIndices());
  for (unsigned operand = 1; operand < GEP.getNumOperands(); ++operand)
    indices.push_back(GEP.getOperand(operand));
  int64_t signedOffset = 0;
  if (!exactNoWrapConstantGepOffset(
          GEP.getSourceElementType(),
          llvm::ArrayRef<const llvm::Value *>(indices), indexBits, DL,
          signedOffset) ||
      signedOffset < 0)
    return false;
  offset = static_cast<uint64_t>(signedOffset);
  return true;
}

// Prove that every raw Boogie address denoted by V stays inside one stable
// internal global allocation. This is stronger than LLVM's defined-behavior
// provenance rule: it also prevents an out-of-bounds GEP from numerically
// reaching the ref assigned to a different Boogie map.
static bool proveStaticGlobalAccess(const llvm::Value *V, uint64_t width,
                                    const llvm::DataLayout &DL) {
  std::vector<StaticGlobalOffset> origins;
  llvm::SmallPtrSet<const llvm::Value *, 16> active;
  std::function<bool(const llvm::Value *,
                     std::vector<StaticGlobalOffset> &)>
      collect = [&](const llvm::Value *P,
                    std::vector<StaticGlobalOffset> &out) -> bool {
    if (!P || !P->getType()->isPointerTy() || !active.insert(P).second)
      return false;

    bool ok = false;
    if (const auto *A = llvm::dyn_cast<llvm::GlobalAlias>(P)) {
      ok = collect(A->getAliasee(), out);
    } else if (const auto *G = llvm::dyn_cast<llvm::GlobalVariable>(P)) {
      ok = (isClosedConstantDataGlobal(*G, DL) ||
            (hasStableGlobalIdentity(*G) &&
             !G->hasAtLeastLocalUnnamedAddr())) &&
           !G->isExternallyInitialized() && G->hasInitializer() &&
           G->getValueType()->isSized() &&
           !typeContainsPointer(G->getValueType()) &&
           !typeUsesErasedAddressSpace(G->getType(), DL) &&
           !typeUsesErasedAddressSpace(G->getValueType(), DL);
      if (ok)
        out.push_back({G, 0});
    } else if (const auto *GEP = llvm::dyn_cast<llvm::GEPOperator>(P)) {
      std::vector<StaticGlobalOffset> bases;
      uint64_t amount = 0;
      ok = collect(GEP->getPointerOperand(), bases) &&
           exactNonnegativeGepOffset(*GEP, DL, amount);
      if (ok) {
        for (StaticGlobalOffset origin : bases) {
          if (!checkedAdd(origin.offset, amount, origin.offset)) {
            ok = false;
            break;
          }
          out.push_back(origin);
        }
      }
    } else if (const auto *BC = llvm::dyn_cast<llvm::BitCastOperator>(P)) {
      ok = collect(BC->getOperand(0), out);
    } else if (const auto *Phi = llvm::dyn_cast<llvm::PHINode>(P)) {
      ok = true;
      for (const llvm::Value *incoming : Phi->incoming_values())
        if (!collect(incoming, out)) {
          ok = false;
          break;
        }
    } else if (const auto *Sel = llvm::dyn_cast<llvm::SelectInst>(P)) {
      ok = collect(Sel->getTrueValue(), out) &&
           collect(Sel->getFalseValue(), out);
    }

    active.erase(P);
    return ok;
  };

  if (width == 0 || !collect(V, origins) || origins.empty())
    return false;
  for (const StaticGlobalOffset &origin : origins) {
    uint64_t size = 0;
    if (!fixedAllocSize(DL, origin.base->getValueType(), size))
      return false;
    if (origin.offset > size || width > size - origin.offset)
      return false;
  }
  return true;
}

static bool trustedIntrinsic(const llvm::Function &F) {
  if (!F.isIntrinsic())
    return false;
  switch (F.getIntrinsicID()) {
  case llvm::Intrinsic::assume:
  case llvm::Intrinsic::bitreverse:
  case llvm::Intrinsic::bswap:
  case llvm::Intrinsic::convert_from_fp16:
  case llvm::Intrinsic::convert_to_fp16:
  case llvm::Intrinsic::ctlz:
  case llvm::Intrinsic::ctpop:
  case llvm::Intrinsic::cttz:
  case llvm::Intrinsic::dbg_declare:
  case llvm::Intrinsic::dbg_label:
  case llvm::Intrinsic::lifetime_start:
  case llvm::Intrinsic::lifetime_end:
  case llvm::Intrinsic::expect:
  case llvm::Intrinsic::fabs:
  case llvm::Intrinsic::fma:
  case llvm::Intrinsic::is_fpclass:
  case llvm::Intrinsic::sqrt:
  case llvm::Intrinsic::maxnum:
  case llvm::Intrinsic::minnum:
  case llvm::Intrinsic::ceil:
  case llvm::Intrinsic::floor:
  case llvm::Intrinsic::nearbyint:
  case llvm::Intrinsic::rint:
  case llvm::Intrinsic::round:
  case llvm::Intrinsic::trunc:
  case llvm::Intrinsic::experimental_noalias_scope_decl:
    return true;
  default:
    return false;
  }
}

// __SMACK_value(s) is an annotation producer, but its generated Boogie
// procedure returns an unconstrained ref. It is harmless only when that return
// is consumed exclusively by the bodyless public/private metadata sinks; if it
// reaches a memory address, SVF's LLVM-level points-to facts cannot constrain
// the Boogie value and the whole partition must fail closed.
static bool metadataOnlyPointerResult(const llvm::CallInst &call) {
  if (!call.getType()->isPointerTy())
    return false;
  for (const llvm::User *user : call.users()) {
    const auto *sink = llvm::dyn_cast<llvm::CallBase>(user);
    if (!sink || sink->getCalledOperand() == &call)
      return false;
    const llvm::Function *callee = llvm::dyn_cast<llvm::Function>(
        sink->getCalledOperand()->stripPointerCasts());
    if (!callee || !callee->isDeclaration() ||
        (callee->getName() != "public_in" &&
         callee->getName() != "private_in"))
      return false;
  }
  return true;
}

unsigned DSAWrapper::ufFind(unsigned x) {
  auto it = ufParent.find(x);
  if (it == ufParent.end()) {
    ufParent[x] = x;
    return x;
  }
  while (ufParent[x] != x) {
    ufParent[x] = ufParent[ufParent[x]];
    x = ufParent[x];
  }
  return x;
}

bool DSAWrapper::ufUnite(unsigned a, unsigned b) {
  ufParent.emplace(a, a);
  ufParent.emplace(b, b);
  unsigned ra = ufFind(a), rb = ufFind(b);
  if (ra != rb) {
    ufParent[ra] = rb;
    return true;
  }
  return false;
}

void DSAWrapper::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
  // We run SVF directly inside runOnModule; no LLVM analysis dependency. SVF
  // normalizes the LLVM module in place, so claiming setPreservesAll is false.
}

void DSAWrapper::computeReachable(llvm::Module &M) {
  reachableFuncs.clear();
  std::vector<llvm::Function *> work;
  for (llvm::Function &F : M) {
    const llvm::StringRef name = F.getName();
    if (!F.isDeclaration() &&
        (SmackOptions::isEntryPoint(name) || name == Naming::STATIC_INIT_PROC ||
         name.starts_with(Naming::INIT_FUNC_PREFIX)) &&
        reachableFuncs.insert(&F).second)
      work.push_back(&F);
  }
  if (work.empty())
    for (llvm::Function &F : M)
      if (!F.isDeclaration() && reachableFuncs.insert(&F).second)
        work.push_back(&F);

  while (!work.empty()) {
    llvm::Function *F = work.back();
    work.pop_back();
    for (llvm::Instruction &I : llvm::instructions(F)) {
      auto *call = llvm::dyn_cast<llvm::CallBase>(&I);
      if (!call)
        continue;
      if (llvm::Function *callee = call->getCalledFunction()) {
        if (!callee->isDeclaration() && reachableFuncs.insert(callee).second)
          work.push_back(callee);
      } else if (!call->isInlineAsm() && call->getCalledOperand() &&
                 ms->hasValueNode(call->getCalledOperand())) {
        if (SVF::CallICFGNode *node = ms->getCallICFGNode(call))
          if (ander->hasIndCSCallees(node))
            for (const SVF::FunObjVar *target :
                 ander->getIndCSCallees(node))
              if (llvm::Function *callee = M.getFunction(target->getName()))
                if (!callee->isDeclaration() &&
                    reachableFuncs.insert(callee).second)
                  work.push_back(callee);
      }
    }
  }
}

void DSAWrapper::buildUnionFind(llvm::Module &M) {
  computeReachable(M);
  // Activate the stronger harness contract only when it has one unambiguous
  // selected entrypoint. Distinct selected entrypoints may be invoked in
  // separate executions with equal actual addresses, so their parameters must
  // never be used as mutually-disjoint partition seeds.
  unsigned contractEntryCount = 0;
  for (llvm::Function &F : M) {
    if (F.isDeclaration() || !SmackOptions::isEntryPoint(F.getName()))
      continue;
    bool hasNoAliasPointer = false;
    for (const llvm::Argument &A : F.args())
      hasNoAliasPointer = hasNoAliasPointer ||
                          (A.getType()->isPointerTy() && A.hasNoAliasAttr());
    if (hasNoAliasPointer) {
      contractEntry = &F;
      ++contractEntryCount;
    }
  }
  closedInputContractActive = contractEntryCount == 1;
  if (!closedInputContractActive)
    contractEntry = nullptr;

  // Stack objects are separate allocation identities in LLVM, but SMACK lowers
  // each alloca through the modular Boogie $alloc procedure. Authorize stack
  // components only when the linked SMACK support module that supplies the
  // allocator body and its initialization is present. A raw llvm2bpl input may
  // otherwise leave $alloc unconstrained, in which case separate stack maps
  // could falsely prove non-interference.
  const llvm::Function *allocatorDecls =
      M.getFunction(Naming::DECLARATIONS_PROC);
  const llvm::Function *allocatorInit =
      M.getFunction(Naming::INIT_FUNC_PREFIX + "_memory_model");
  allocatorModelActive = allocatorDecls && !allocatorDecls->isDeclaration() &&
                         allocatorInit && !allocatorInit->isDeclaration();

  // Unsupported pointer origins are a module-wide fail-closed gate. Andersen
  // can silently omit an inttoptr arm from a select, leaving a nonempty but
  // under-approximated points-to set. Unknown external code can likewise write
  // pointer values that its cached graph never contains. Neither result may
  // authorize separate maps.
  const llvm::DataLayout &DL = M.getDataLayout();
  for (const llvm::GlobalVariable &G : M.globals()) {
    if (!isClosedConstantDataGlobal(G, DL) &&
        (G.hasAtLeastLocalUnnamedAddr() || !hasStableGlobalIdentity(G) ||
         G.isExternallyInitialized() ||
         typeContainsPointer(G.getValueType()) ||
         typeUsesErasedAddressSpace(G.getType(), DL) ||
         typeUsesErasedAddressSpace(G.getValueType(), DL)))
      saturatingIncrement(unsupportedPointerOriginCount);
    if (G.hasInitializer() &&
        containsUnsupportedPointerConstant(G.getInitializer()))
      saturatingIncrement(unsupportedPointerOriginCount);
  }
  for (const llvm::GlobalAlias &A : M.aliases())
    if (A.hasAtLeastLocalUnnamedAddr() || !hasStableGlobalIdentity(A) ||
        typeUsesErasedAddressSpace(A.getType(), DL))
      saturatingIncrement(unsupportedPointerOriginCount);
  if (!M.ifunc_empty())
    saturatingIncrement(unsupportedPointerOriginCount);

  for (llvm::Function &F : M) {
    if (typeUsesErasedAddressSpace(F.getType(), DL) ||
        typeUsesErasedAddressSpace(F.getReturnType(), DL))
      saturatingIncrement(unsupportedPointerOriginCount);
    if (F.hasFnAttribute(llvm::Attribute::NullPointerIsValid))
      saturatingIncrement(unsupportedPointerOriginCount);
    if (!F.isDeclaration()) {
      if (F.isVarArg())
        saturatingIncrement(unsupportedPointerOriginCount);
      if (typeContainsPointer(F.getReturnType()))
        saturatingIncrement(unsupportedPointerOriginCount);
      for (const llvm::Argument &A : F.args())
        if (typeUsesErasedAddressSpace(A.getType(), DL))
          saturatingIncrement(unsupportedPointerOriginCount);
    }

    for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
      llvm::Instruction *inst = &*I;
      bool unsupported = containsIntToPtr(inst) ||
                         typeUsesErasedAddressSpace(inst->getType(), DL);
      // A raw/minimal Boogie environment may leave $alloc unconstrained. Only
      // the linked SMACK allocator model authorizes distinct stack components;
      // the selected-entry buffer contract is independent evidence and cannot
      // substitute for allocator freshness.
      if (llvm::isa<llvm::AllocaInst>(inst) && !allocatorModelActive)
        unsupported = true;
      for (const llvm::Use &U : inst->operands()) {
        unsupported = containsUnsupportedPointerConstant(U.get()) ||
                      typeUsesErasedAddressSpace(U.get()->getType(), DL) ||
                      unsupported;
        if (typeContainsPointer(U.get()->getType()) &&
            (isa<UndefValue>(U.get()) || isa<PoisonValue>(U.get()) ||
             (F.hasFnAttribute(Attribute::NullPointerIsValid) &&
              isa<ConstantPointerNull>(U.get()))))
          unsupported = true;
      }

      // Fail closed for new or partially modeled pointer-producing opcodes.
      // Only these scalar operations preserve a pointer already covered by an
      // audited origin; Andersen unions every incoming PHI/select target. All
      // other pointer-bearing results require an explicit soundness review.
      if (typeContainsPointer(inst->getType())) {
        const auto *directCall = llvm::dyn_cast<llvm::CallInst>(inst);
        const llvm::Function *directCallee =
            directCall
                ? llvm::dyn_cast<llvm::Function>(
                      directCall->getCalledOperand()->stripPointerCasts())
                : nullptr;
        const llvm::StringRef directName =
            directCallee && directCallee->hasName() ? directCallee->getName()
                                                    : "";
        const bool auditedDerivedPointer =
            inst->getType()->isPointerTy() &&
            (isa<llvm::GetElementPtrInst>(inst) ||
             isa<llvm::BitCastInst>(inst) || isa<llvm::PHINode>(inst) ||
             isa<llvm::SelectInst>(inst) || isa<llvm::AllocaInst>(inst) ||
             (directCall &&
              directName.find(Naming::VALUE_PROC) != llvm::StringRef::npos &&
              metadataOnlyPointerResult(*directCall)));
        if (!auditedDerivedPointer)
          unsupported = true;
      }

      // SVF does not constrain pointer values introduced by freeze or va_arg.
      // In particular, freezing poison may choose any defined pointer.
      if (auto *FI = dyn_cast<llvm::FreezeInst>(inst))
        if (typeContainsPointer(FI->getType()))
          unsupported = true;
      if (auto *VAI = dyn_cast<llvm::VAArgInst>(inst))
        if (typeContainsPointer(VAI->getType()))
          unsupported = true;

      // A pointer loaded from Boogie memory may have been produced by static
      // initialization, type-punned byte storage, or a modular map havoc. The
      // generated contracts do not constrain that value to SVF's cached set.
      if (auto *LI = dyn_cast<llvm::LoadInst>(inst))
        if (typeContainsPointer(LI->getType()))
          unsupported = true;

      // SVF's atomic transfer functions do not reliably propagate a pointer
      // payload written by cmpxchg/atomicrmw into later loads. Such a payload
      // may therefore cross components even when the cached points-to set does
      // not show it.
      if (auto *CX = dyn_cast<llvm::AtomicCmpXchgInst>(inst))
        if (typeContainsPointer(CX->getCompareOperand()->getType()) ||
            typeContainsPointer(CX->getNewValOperand()->getType()) ||
            typeContainsPointer(CX->getType()))
          unsupported = true;
      if (auto *RMW = dyn_cast<llvm::AtomicRMWInst>(inst))
        if (typeContainsPointer(RMW->getValOperand()->getType()) ||
            typeContainsPointer(RMW->getType()))
          unsupported = true;

      if (auto *CB = dyn_cast<llvm::CallBase>(inst)) {
        if (CB->isInlineAsm()) {
          unsupported = true;
        } else if (const llvm::Function *callee =
                       llvm::dyn_cast<llvm::Function>(
                           CB->getCalledOperand()->stripPointerCasts())) {
          // Direct declarations and definitions are translated as calls whose
          // procedure summaries modify every map. A pointer result remains
          // subject to the access-origin scan below before it can select a map.
          if (callee->isIntrinsic() && !trustedIntrinsic(*callee) &&
              !llvm::isa<llvm::MemIntrinsic>(inst))
            unsupported = true;
        }
      }
      if (unsupported) {
        if (std::getenv("SMACK_DEBUG_REGIONS"))
          llvm::errs() << "[svf-region] unsupported instruction in "
                       << F.getName() << ": " << *inst << "\n";
        saturatingIncrement(unsupportedPointerOriginCount);
      }
    }
  }
  const unsigned unsupportedBeforeRangeAudit = unsupportedPointerOriginCount;

  // Union all objects that co-occur in any pointer's points-to set, over every
  // pointer-typed operand/result of every instruction (a sound superset of the
  // pointers SMACK will later query). Track memcpy/memset operand objects.
  auto unionPts = [&](const llvm::Value *p, bool memOpd) {
    if (!p || !ms->hasValueNode(p))
      return;
    const SVF::PointsTo &pts = ander->getPts(ms->getValueNode(p));
    unsigned first = 0;
    bool have = false;
    for (SVF::NodeID o : pts) {
      if (o == pag->getConstantNode())
        continue; // SVF sentinel, not one concrete memory allocation
      ufFind(o); // ensure present
      if (!have) {
        first = o;
        have = true;
      } else
        ufUnite(first, o);
      if (memOpd)
        memOpdObjs.insert(o);
    }
  };

  for (auto &F : M)
    for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
      Instruction *inst = &*I;
      bool isMemIntr = isa<MemCpyInst>(inst) || isa<MemSetInst>(inst) ||
                       isa<MemMoveInst>(inst);
      if (inst->getType()->isPointerTy())
        unionPts(inst, false);
      for (Use &U : inst->operands()) {
        Value *op = U.get();
        if (op && op->getType()->isPointerTy())
          unionPts(op, isMemIntr);
      }
    }

  // Realize true field-insensitivity: collapse every field/sub-object into its
  // base object. SVF's Andersen is field-SENSITIVE, so a buffer accessed at
  // distinct CONSTANT offsets yields distinct singleton GepObjVars that never
  // co-occur in any one points-to set — leaving each field in its own region.
  // The whole-buffer `__SMACK_values` annotation then binds to a single field
  // object that the per-byte stores miss, severing the buffer's data flow
  // (observed on aes_cbc_ct/ossl_aes_cbc; mee-cbc/aead escaped only because
  // their variable/loop offsets already collapse to the base in SVF). Uniting
  // each object with its base makes one buffer one region — coarser but sound,
  // and makes the partition component-only by construction.
  std::vector<unsigned> objs;
  objs.reserve(ufParent.size());
  for (auto &kv : ufParent)
    objs.push_back(kv.first);
  for (unsigned o : objs)
    if (pag->hasGNode(o))
      if (const SVF::BaseObjVar *bo = pag->getBaseObject(o))
        ufUnite(o, bo->getId());

  // LLVM may merge `unnamed_addr` constants with each other. Put every closed
  // read-only constant allocation in one component so such equality never
  // crosses maps, while keeping that component disjoint from input and stack
  // allocations.
  unsigned constantDataRoot = 0;
  for (llvm::GlobalVariable &G : M.globals())
    if (isClosedConstantDataGlobal(G, DL)) {
      if (!constantDataRoot) {
        while (ufParent.count(nextSyntheticRoot))
          --nextSyntheticRoot;
        constantDataRoot = nextSyntheticRoot--;
        ufFind(constantDataRoot);
        syntheticObjects.insert(constantDataRoot);
        constantDataObjects.insert(constantDataRoot);
      }
      explicitRoots[&G] = constantDataRoot;
      // Also join SVF's real object nodes to the synthetic component. Direct
      // uses of @G prefer explicitRoots, while an alias or derived value may
      // reach the same allocation only through Andersen; both routes must
      // therefore name exactly one map.
      if (ms->hasValueNode(&G))
        for (SVF::NodeID object : ander->getPts(ms->getValueNode(&G)))
          if (object != pag->getConstantNode() &&
              object != pag->getBlackHoleNode() && pag->hasGNode(object))
            ufUnite(constantDataRoot, object);
    }

  // The selected entry point's `noalias` pointer parameters are the explicit
  // closed-input contract requested by the harness: each denotes a separately
  // allocated top-level buffer. This is not inferred from LLVM's generic
  // noalias rule; SMACK deliberately consumes it here as a stronger verifier
  // assumption for entry points only.
  if (contractEntry)
    for (const llvm::Argument &A : contractEntry->args())
      if (A.getType()->isPointerTy() && A.hasNoAliasAttr()) {
        while (ufParent.count(nextSyntheticRoot))
          --nextSyntheticRoot;
        const unsigned root = nextSyntheticRoot--;
        ufFind(root);
        syntheticObjects.insert(root);
        noAliasSeedObjects.insert(root);
        explicitRoots[&A] = root;
        ++noAliasSeedCount;
      }

  auto knownRoot = [&](const llvm::Value *V) -> unsigned {
    if (!V || !V->getType()->isPointerTy())
      return 0;
    auto explicitIt = explicitRoots.find(V);
    if (explicitIt != explicitRoots.end())
      return ufFind(explicitIt->second) + 1;
    // GEPs, casts, and audited single-store spills preserve their underlying
    // allocation. Prefer that explicit contract before consulting SVF: SVF may
    // represent an unconstrained entry parameter with a black-hole/dummy node,
    // which is not a second allocation and must never split a derived address
    // from its top-level buffer.
    const llvm::Value *base = underlyingThroughSpill(V);
    explicitIt = explicitRoots.find(base);
    if (explicitIt != explicitRoots.end())
      return ufFind(explicitIt->second) + 1;
    if (ms->hasValueNode(V)) {
      const SVF::PointsTo &points = ander->getPts(ms->getValueNode(V));
      for (SVF::NodeID object : points) {
        if (object == pag->getConstantNode() ||
            object == pag->getBlackHoleNode() || !pag->hasGNode(object))
          continue;
        const SVF::BaseObjVar *baseObject = pag->getBaseObject(object);
        if (baseObject && !baseObject->isBlackHoleObj())
          return ufFind(object) + 1;
      }
    }
    if (base && base != V && ms->hasValueNode(base)) {
      const SVF::PointsTo &points = ander->getPts(ms->getValueNode(base));
      for (SVF::NodeID object : points) {
        if (object == pag->getConstantNode() ||
            object == pag->getBlackHoleNode() || !pag->hasGNode(object))
          continue;
        const SVF::BaseObjVar *baseObject = pag->getBaseObject(object);
        if (baseObject && !baseObject->isBlackHoleObj())
          return ufFind(object) + 1;
      }
    }
    return 0;
  };

  auto bindEqual = [&](const llvm::Value *actual,
                       const llvm::Argument *formal) -> bool {
    const unsigned actualRoot = knownRoot(actual);
    const unsigned formalRoot = knownRoot(formal);
    if (actualRoot && formalRoot) {
      const bool merged = ufUnite(actualRoot - 1, formalRoot - 1);
      const llvm::Value *actualBase = underlyingThroughSpill(actual);
      if (explicitRoots.count(actual) ||
          (actualBase && explicitRoots.count(actualBase)))
        explicitRoots.emplace(formal, ufFind(actualRoot - 1));
      return merged;
    }
    if (actualRoot) {
      explicitRoots.emplace(formal, actualRoot - 1);
      return true;
    }
    if (formalRoot) {
      explicitRoots.emplace(actual, formalRoot - 1);
      return true;
    }
    return false;
  };

  // Propagate the allocation component through must-equality edges to a true
  // fixpoint. Every update either adds one binding or merges two components.
  while (true) {
    bool changed = false;
    for (llvm::Function &F : M) {
      for (llvm::Instruction &I : llvm::instructions(F)) {
        auto bindAlternatives = [&](llvm::Value *result,
                                    llvm::ArrayRef<llvm::Value *> values) {
          unsigned component = 0;
          bool unknown = false;
          for (llvm::Value *value : values) {
            const llvm::Value *stripped = value->stripPointerCasts();
            if (llvm::isa<llvm::ConstantPointerNull>(stripped) ||
                llvm::isa<llvm::UndefValue>(stripped))
              continue;
            const unsigned root = knownRoot(value);
            if (!root) {
              if (underlyingThroughSpill(value) == result)
                continue;
              unknown = true;
              continue;
            }
            if (!component)
              component = root;
            else
              changed = ufUnite(component - 1, root - 1) || changed;
          }
          if (unknown || !component)
            return;
          const unsigned resultRoot = knownRoot(result);
          if (resultRoot)
            changed = ufUnite(component - 1, resultRoot - 1) || changed;
          else if (explicitRoots.emplace(result, component - 1).second)
            changed = true;
        };

        if (auto *phi = llvm::dyn_cast<llvm::PHINode>(&I)) {
          if (phi->getType()->isPointerTy()) {
            llvm::SmallVector<llvm::Value *, 4> incoming;
            for (llvm::Value *value : phi->incoming_values())
              incoming.push_back(value);
            bindAlternatives(phi, incoming);
          }
        } else if (auto *select = llvm::dyn_cast<llvm::SelectInst>(&I)) {
          if (select->getType()->isPointerTy()) {
            llvm::Value *alternatives[] = {select->getTrueValue(),
                                            select->getFalseValue()};
            bindAlternatives(select, alternatives);
          }
        }

        auto *call = llvm::dyn_cast<llvm::CallBase>(&I);
        if (!call || call->isInlineAsm())
          continue;
        auto bindCallee = [&](llvm::Function *callee) {
          if (!callee || callee->isDeclaration())
            return;
          const unsigned count =
              std::min<unsigned>(call->arg_size(), callee->arg_size());
          for (unsigned index = 0; index < count; ++index)
            if (call->getArgOperand(index)->getType()->isPointerTy() &&
                callee->getArg(index)->getType()->isPointerTy())
              changed = bindEqual(call->getArgOperand(index),
                                  callee->getArg(index)) ||
                        changed;
        };
        if (llvm::Function *callee = call->getCalledFunction()) {
          bindCallee(callee);
        } else if (call->getCalledOperand() &&
                   ms->hasValueNode(call->getCalledOperand())) {
          if (SVF::CallICFGNode *node = ms->getCallICFGNode(call))
            if (ander->hasIndCSCallees(node))
              for (const SVF::FunObjVar *target :
                   ander->getIndCSCallees(node))
                bindCallee(M.getFunction(target->getName()));
        }
      }
    }
    if (!changed)
      break;
  }
  valueRootPlus1.clear();

  // Every non-global access in a separated component must stay within its
  // allocation. Dynamic GEP translation already requires inbounds/nusw; also
  // reject a non-inbounds GEP in these components so plain Boogie ref arithmetic
  // cannot walk numerically into another allocation.
  for (llvm::Function &F : M) {
    for (llvm::Instruction &I : llvm::instructions(F))
      if (const auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I))
        if (!GEP->isInBounds() && knownRoot(GEP) != 0 &&
            !proveStaticGlobalAccess(GEP, 1, DL))
          saturatingIncrement(unsupportedPointerOriginCount);
  }
  const unsigned unsupportedAfterGepAudit = unsupportedPointerOriginCount;

  auto requireProvenRange = [&](const llvm::Value *address, uint64_t width) {
    if (width == 0)
      return;
    if (proveStaticGlobalAccess(address, width, DL))
      return;
    const unsigned rootPlusOne = knownRoot(address);
    bool allocationContract = false;
    if (rootPlusOne) {
      const unsigned root = ufFind(rootPlusOne - 1);
      bool sawAllocation = false;
      bool sawUnsupportedObject = false;
      for (const auto &entry : ufParent) {
        if (ufFind(entry.first) != root)
          continue;
        if (syntheticObjects.count(entry.first)) {
          sawAllocation = true;
          continue;
        }
        if (!pag->hasGNode(entry.first)) {
          sawUnsupportedObject = true;
          continue;
        }
        const SVF::BaseObjVar *object = pag->getBaseObject(entry.first);
        if (!object || object->isBlackHoleObj() || object->isHeap()) {
          sawUnsupportedObject = true;
          continue;
        }
        if (object->isStack())
          sawAllocation = true;
      }
      allocationContract = sawAllocation && !sawUnsupportedObject;
    }
    if (!allocationContract)
      saturatingIncrement(unsupportedPointerOriginCount);
  };
  auto requireFixedAccess = [&](const llvm::Value *address,
                                const llvm::Type *accessType) {
    uint64_t width = 0;
    if (!fixedStoreSize(DL, accessType, width))
      saturatingIncrement(unsupportedPointerOriginCount);
    else
      requireProvenRange(address, width);
  };
  for (llvm::Function &F : M) {
    for (llvm::Instruction &I : llvm::instructions(F)) {
      if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(&I)) {
        requireFixedAccess(load->getPointerOperand(), load->getType());
      } else if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&I)) {
        requireFixedAccess(store->getPointerOperand(),
                           store->getValueOperand()->getType());
      } else if (const auto *exchange =
                     llvm::dyn_cast<llvm::AtomicCmpXchgInst>(&I)) {
        requireFixedAccess(exchange->getPointerOperand(),
                           exchange->getCompareOperand()->getType());
      } else if (const auto *rmw = llvm::dyn_cast<llvm::AtomicRMWInst>(&I)) {
        requireFixedAccess(rmw->getPointerOperand(),
                           rmw->getValOperand()->getType());
      } else if (const auto *memory =
                     llvm::dyn_cast<llvm::MemIntrinsic>(&I)) {
        const auto *length =
            llvm::dyn_cast<llvm::ConstantInt>(memory->getLength());
        if (!length || length->getValue().getActiveBits() > 64) {
          saturatingIncrement(unsupportedPointerOriginCount);
        } else {
          const uint64_t width = length->getZExtValue();
          requireProvenRange(memory->getRawDest(), width);
          if (const auto *transfer =
                  llvm::dyn_cast<llvm::MemTransferInst>(memory))
            requireProvenRange(transfer->getRawSource(), width);
        }
      } else if (const auto *call = llvm::dyn_cast<llvm::CallInst>(&I)) {
        const llvm::Function *callee = call->getCalledFunction();
        const llvm::StringRef name =
            callee && callee->hasName() ? callee->getName() : "";
        const bool regionAnnotation =
            name.find("__SMACK_value") != llvm::StringRef::npos ||
            name.find(Naming::CODE_PROC) != llvm::StringRef::npos ||
            name.find(Naming::INV_PROC_PREFIX) != llvm::StringRef::npos ||
            name.find(Naming::MOD_PROC) != llvm::StringRef::npos;
        if (regionAnnotation)
          for (const llvm::Use &argument : call->args())
            if (argument->getType()->isPointerTy())
              requireProvenRange(argument.get(), 1);
      }
    }
  }
  if (std::getenv("SMACK_DEBUG_REGIONS"))
    llvm::errs() << "[svf-region] unsupported origin="
                 << unsupportedBeforeRangeAudit
                 << " gep="
                 << unsupportedAfterGepAudit - unsupportedBeforeRangeAudit
                 << " range="
                 << unsupportedPointerOriginCount - unsupportedAfterGepAudit
                 << "\n";

  // SOUND CATCH-ALL. Any translated mem-op pointer that SVF left unresolved
  // (no region)
  // may alias ANY object; the split-memory invariant (may-alias => same region)
  // can then only be kept by putting everything in one region. The audit scans
  // every function in the module, including procedures outside the selected
  // entrypoint's call graph, because Regions and Boogie emission are module-wide.
  // This set matches every address Regions indexes: load/store/atomic pointers,
  // memory-intrinsic destinations and sources, and __SMACK_values annotations.
  auto hasUnknownTarget = [&](const llvm::Value *addr) {
    const llvm::Value *base = addr ? underlyingThroughSpill(addr) : nullptr;
    if ((addr && explicitRoots.count(addr)) ||
        (base && explicitRoots.count(base)))
      return false;
    if (!addr || !ms->hasValueNode(addr))
      return false;
    const SVF::PointsTo &pts = ander->getPts(ms->getValueNode(addr));
    for (SVF::NodeID o : pts) {
      // ConstantNode is a sentinel rather than an arbitrary allocation. If it
      // is the only target, rootPlus1 below still reports this access unresolved.
      if (o == pag->getConstantNode())
        continue;
      if (o == pag->getBlackHoleNode())
        return true;
      if (!pag->hasGNode(o))
        return true;
      const SVF::BaseObjVar *bo = pag->getBaseObject(o);
      if (!bo || bo->isBlackHoleObj() || !ms->hasLLVMValue(bo))
        return true;
    }
    return false;
  };
  unsigned unresolvedDebugCount = 0;
  auto isUnresolvedAccess = [&](const llvm::Value *addr) {
    if (!addr)
      return false;
    bool unknownTarget = hasUnknownTarget(addr);
    const unsigned root = rootPlus1(addr);
    bool unresolved = root == 0 || unknownTarget;
    if (unresolved) {
      ++unresolvedAccessCount;
      if (unknownTarget)
        ++unknownTargetAccessCount;
      if (std::getenv("SMACK_DEBUG_REGIONS") && unresolvedDebugCount++ < 24) {
        const llvm::Value *base = underlyingThroughSpill(addr);
        llvm::errs() << "[svf-region] unresolved root=" << root
                     << " unknown=" << unknownTarget << " addr=" << *addr
                     << " base=";
        if (base)
          llvm::errs() << *base;
        else
          llvm::errs() << "<none>";
        llvm::errs() << "\n";
      }
    }
    return unresolved;
  };
  bool unresolved = unsupportedPointerOriginCount != 0;
  scannedFunctionCount = 0;
  for (auto &F : M) {
    if (F.isDeclaration())
      continue;
    ++scannedFunctionCount;
    for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
      bool unresolvedHere = false;
      if (auto *L = dyn_cast<LoadInst>(&*I))
        unresolvedHere = isUnresolvedAccess(L->getPointerOperand());
      else if (auto *S = dyn_cast<StoreInst>(&*I))
        unresolvedHere = isUnresolvedAccess(S->getPointerOperand());
      else if (auto *CX = dyn_cast<AtomicCmpXchgInst>(&*I))
        unresolvedHere = isUnresolvedAccess(CX->getPointerOperand());
      else if (auto *RMW = dyn_cast<AtomicRMWInst>(&*I))
        unresolvedHere = isUnresolvedAccess(RMW->getPointerOperand());
      else if (auto *MI = dyn_cast<MemIntrinsic>(&*I)) {
        unresolvedHere = isUnresolvedAccess(MI->getRawDest());
        if (auto *MT = dyn_cast<MemTransferInst>(MI))
          unresolvedHere = isUnresolvedAccess(MT->getRawSource()) ||
                           unresolvedHere;
      } else if (auto *CI = dyn_cast<CallInst>(&*I)) {
        const llvm::Function *callee = CI->getCalledFunction();
        const std::string name =
            callee && callee->hasName() ? callee->getName().str() : "";
        const bool isValue = name.find("__SMACK_value") != std::string::npos;
        const bool isCodeOrInv =
            name.find(Naming::CODE_PROC) != std::string::npos ||
            name.find(Naming::INV_PROC_PREFIX) != std::string::npos ||
            name.find(Naming::MOD_PROC) != std::string::npos;
        auto check = [&](const llvm::Value *addr) {
          if (!addr)
            return;
          addr = addr->stripPointerCasts();
          if (addr->getType()->isPointerTy())
            unresolvedHere = isUnresolvedAccess(addr) || unresolvedHere;
        };

        // Mirror Regions::visitCallInst: pointer-returning external calls,
        // annotation pointers, and code/invariant/modifies pointers become
        // memory-region queries during translation. malloc is already covered
        // by the unsupported-call gate above and therefore uses the universal
        // component even though Regions handles its allocation specially.
        if (callee && callee->isDeclaration() && CI->getType()->isPointerTy() &&
            name != "malloc" && !isValue && !isCodeOrInv)
          check(CI);

        if (isValue) {
          for (const llvm::Use &U : CI->args()) {
            const llvm::Value *arg = U.get();
            if (!arg->getType()->isPointerTy())
              continue;
            check(arg);
            if (auto *load = dyn_cast<LoadInst>(arg->stripPointerCasts()))
              check(load->getPointerOperand());
          }
        } else if (isCodeOrInv) {
          for (const llvm::Use &U : CI->args())
            if (U.get()->getType()->isPointerTy())
              check(U.get());
        }
      }
      unresolved = unresolved || unresolvedHere;
    }
  }
  if (unresolved) {
    unsigned root = ufParent.empty() ? pag->getBlackHoleNode()
                                     : ufParent.begin()->first;
    ufFind(root);
    for (auto &kv : ufParent)
      ufUnite(root, kv.first);
    collapsed = true;
    collapsedRoot = ufFind(root);
    valueRootPlus1.clear(); // pre-collapse cached regions are now stale
    llvm::errs() << "[svf-region] SOUND CATCH-ALL engaged: an unresolved "
                    "pointer forced a single universal region (sound, coarse)\n";
  }

  // Opt-in diagnostic: for vtable globals, dump each object's base + final
  // union-find component, to see why field-split globals (e.g. br_*_vtable)
  // land in different regions despite the field->base collapse above.
  if (std::getenv("SMACK_DEBUG_REGIONS")) {
    std::set<std::string> namedGlobals;
    for (unsigned o : objs) {
      if (!pag->hasGNode(o))
        continue;
      const SVF::BaseObjVar *bo = pag->getBaseObject(o);
      if (bo && ms->hasLLVMValue(bo))
        if (const llvm::Value *V = ms->getLLVMValue(bo))
          if (V->hasName() && llvm::isa<llvm::GlobalVariable>(V))
            namedGlobals.insert(V->getName().str());
    }
    llvm::errs() << "[REGIONDBG] union-find objs=" << objs.size()
                 << " named-global-objs=" << namedGlobals.size() << "\n";
    for (const auto &g : namedGlobals)
      llvm::errs() << "[REGIONDBG]   global-in-uf: " << g << "\n";
    // Also: is the vtable global even a tracked SVF value?
    for (llvm::GlobalVariable &G : module->globals())
      if (G.getName().contains("vtable"))
        llvm::errs() << "[REGIONDBG] module global '" << G.getName()
                     << "' hasValueNode=" << ms->hasValueNode(&G) << "\n";

    // Stage-0 mechanism probe: for every pointer load/store in the gcm/aes_ct/
    // static-init functions, log its union-find component (rootPlus1) and the
    // base-globals in the pointer's points-to. Lets us compare the static-init
    // store of the vtable fn-ptr (should carry the vtable) against the funcPtr
    // load through gc->bctx->vtable (which severs) — and see WHAT the load
    // resolves to instead of the vtable global.
    auto baseGlobalName = [&](SVF::NodeID o) -> std::string {
      if (!pag->hasGNode(o))
        return "";
      const SVF::BaseObjVar *bo = pag->getBaseObject(o);
      if (bo && ms->hasLLVMValue(bo))
        if (const llvm::Value *V = ms->getLLVMValue(bo))
          if (V->hasName())
            return V->getName().str();
      return "";
    };
    for (llvm::Function &F : M) {
      llvm::StringRef fn = F.getName();
      if (!(fn.contains("gcm") || fn.contains("aes_ct") ||
            fn.contains("static_init")))
        continue;
      for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
        const llvm::Value *addr = nullptr;
        const char *kind = nullptr;
        if (auto *L = dyn_cast<llvm::LoadInst>(&*I)) {
          if (!L->getType()->isPointerTy())
            continue; // only the fn-ptr / vtable-ptr chain
          addr = L->getPointerOperand();
          kind = "load.ptr";
        } else if (auto *S = dyn_cast<llvm::StoreInst>(&*I)) {
          if (!S->getValueOperand()->getType()->isPointerTy())
            continue;
          addr = S->getPointerOperand();
          kind = "store.ptr";
        }
        if (!addr || !ms->hasValueNode(addr))
          continue;
        const SVF::PointsTo &pts = ander->getPts(ms->getValueNode(addr));
        std::string bases;
        bool hasVtable = false;
        for (SVF::NodeID o : pts) {
          std::string g = baseGlobalName(o);
          if (!g.empty()) {
            bases += g + " ";
            if (g.find("vtable") != std::string::npos)
              hasVtable = true;
          }
        }
        llvm::errs() << "[REGIONDBG-OP] fn=" << fn.str() << " " << kind
                     << " comp=" << rootPlus1(addr)
                     << " ptsN=" << pts.count() << " vtable=" << hasVtable
                     << " bases={ " << bases << "}\n";
      }
    }

    // For each SVF-resolved indirect callsite, log the funcPtr
    // load-address component vs the component(s) holding the resolved target
    // functions (reverse points-to). This pins down exactly which components
    // to union so the loaded fp matches the static-init store.
    if (std::getenv("SMACK_PROBE_DEVIRT")) {
      for (llvm::Function &F : M) {
        for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
          auto *CI = dyn_cast<llvm::CallInst>(&*I);
          if (!CI || CI->isInlineAsm() || CI->getCalledFunction())
            continue; // direct call / asm
          const llvm::Value *callee = CI->getCalledOperand();
          if (!ms->hasValueNode(callee))
            continue;
          SVF::CallICFGNode *cnode = ms->getCallICFGNode(CI);
          if (!cnode || !ander->hasIndCSCallees(cnode))
            continue;
          // funcPtr load address component (where the dispatch reads from).
          unsigned loadComp = 0;
          if (auto *L = dyn_cast<llvm::LoadInst>(callee->stripPointerCasts()))
            loadComp = rootPlus1(L->getPointerOperand());
          llvm::errs() << "[DEVIRT-PROBE] fn=" << F.getName().str()
                       << " calleePtsComp=" << rootPlus1(callee)
                       << " loadAddrComp=" << loadComp << "\n";
          for (const SVF::FunObjVar *fo : ander->getIndCSCallees(cnode)) {
            std::string holders;
            for (SVF::NodeID n : ander->getRevPts(fo->getId())) {
              std::string g = baseGlobalName(n);
              holders += "[" + (g.empty() ? std::string("?") : g) + " comp=" +
                         std::to_string(ufFind(n) + 1) + "] ";
            }
            llvm::errs() << "[DEVIRT-PROBE]   target=" << fo->getName()
                         << " heldBy=" << holders << "\n";
          }
        }
      }
    }
  }
}

void DSAWrapper::aggregateRegions() {
  // Collect a stable list of object ids first (ufFind mutates ufParent).
  std::vector<unsigned> objs;
  objs.reserve(ufParent.size());
  for (auto &kv : ufParent)
    objs.push_back(kv.first);

  for (unsigned obj : objs) {
    unsigned root = ufFind(obj);
    RegionInfo &ri = regionInfo[root];
    if (syntheticObjects.count(obj)) {
      ri.allocated = true;
      ri.arrayLike = true;
      if (noAliasSeedObjects.count(obj))
        ri.noAliasSeeded = true;
      if (constantDataObjects.count(obj))
        ri.globalAllocation = true;
      continue;
    }
    const SVF::BaseObjVar *bo = nullptr;
    // getBaseObject is valid for object nodes (FI and Gep); guard defensively.
    if (pag->hasGNode(obj))
      bo = pag->getBaseObject(obj);
    if (!bo) {
      ri.complicated = true;
      ri.incomplete = true;
      continue;
    }
    if (bo->isHeap() || bo->isStack())
      ri.allocated = true;
    if (bo->isStack())
      ri.stackAllocation = true;
    if (bo->isHeap())
      ri.heapAllocation = true;
    if (bo->isBlackHoleObj()) {
      ri.complicated = true;
      ri.incomplete = true;
    }
    if (bo->isArray())
      ri.arrayLike = true;
    if (bo->isGlobalObj()) {
      ri.globalAllocation = true;
      ri.numGlobals++;
      if (ms->hasLLVMValue(bo))
        if (auto *GV = dyn_cast<GlobalVariable>(ms->getLLVMValue(bo))) {
          if (GV->hasInitializer())
            ri.staticInitd = true;
        }
    }
    if (memOpdObjs.count(obj))
      ri.memOpd = true;
  }
}

bool DSAWrapper::cachedSVF(const llvm::Module &M, SVF::LLVMModuleSet *&ms,
                           SVF::SVFIR *&pag, SVF::Andersen *&ander) {
  ms = nullptr;
  pag = nullptr;
  ander = nullptr;
  if (!g_svfAndersen || g_svfSnapshotStale || g_svfModule != &M ||
      moduleSnapshot(M) != g_svfModuleSnapshot ||
      moduleValueIdentity(M) != g_svfValueIdentity) {
    if (g_svfAndersen)
      g_svfSnapshotStale = true;
    return false;
  }
  ms = g_svfModuleSet;
  pag = g_svfIR;
  ander = g_svfAndersen;
  return true;
}

bool DSAWrapper::runOnModule(llvm::Module &M) {
  module = &M;
  dataLayout = &M.getDataLayout();
  ufParent.clear();
  regionInfo.clear();
  memOpdObjs.clear();
  explicitRoots.clear();
  syntheticObjects.clear();
  noAliasSeedObjects.clear();
  constantDataObjects.clear();
  reachableFuncs.clear();
  contractEntry = nullptr;
  closedInputContractActive = false;
  allocatorModelActive = false;
  valueRootPlus1.clear();
  collapsed = false;
  irSnapshotMatch = true;
  collapsedRoot = 0;
  unresolvedAccessCount = 0;
  unknownTargetAccessCount = 0;
  unsupportedPointerOriginCount = 0;
  scannedFunctionCount = 0;
  nextSyntheticRoot = std::numeric_limits<unsigned>::max() - 1;
  noAliasSeedCount = 0;

  // Some LLVM pointer constants are outside SVF's accepted IR subset and make
  // its builder abort. Detect them before constructing the singleton graph and
  // produce a conservative region directly. This is still the SVF partitioner:
  // the preflight is its fail-closed input boundary, never another alias
  // analysis or a source of separation evidence.
  unsupportedPointerOriginCount = preSVFUnsupportedConstantCount(M);
  if (unsupportedPointerOriginCount != 0) {
    if (g_svfAndersen)
      g_svfSnapshotStale = true;
    collapsed = true;
    collapsedRoot = 0;
    ufParent.emplace(0, 0);
    RegionInfo &universal = regionInfo[0];
    universal.allocated = true;
    universal.complicated = true;
    universal.incomplete = true;
    for (const llvm::Function &F : M)
      if (!F.isDeclaration())
        ++scannedFunctionCount;
    llvm::errs() << "[svf-region] SOUND CATCH-ALL engaged: LLVM contains a "
                    "pointer constant outside SVF's audited input subset\n";
    return false;
  }

  // Build SVF once (see g_svf* declarations above). The cache belongs to exactly
  // one LLVM Module: SVF's singleton state and NodeIDs cannot safely be reused
  // for a different module. Paired/multi-module callers must request universal
  // memory and therefore avoid DSAWrapper entirely. The exact printed module
  // plus the ordered identity of every LLVM Value bind cached NodeIDs to the
  // post-SVF IR epoch. A same-module rerun after any intervening IR change
  // returns a universal region without querying stale SVF nodes.
  if (g_svfAndersen && g_svfModule != &M) {
    // A process-global SVF graph belongs to the first Module only. A later
    // module fails closed without touching its nodes; poison the global cache
    // as well so devirtualization cannot accidentally query side one's graph.
    g_svfSnapshotStale = true;
    irSnapshotMatch = false;
    collapsed = true;
    collapsedRoot = 0;
    ufParent.emplace(0, 0);
    RegionInfo &universal = regionInfo[0];
    universal.allocated = true;
    universal.complicated = true;
    universal.incomplete = true;
    for (const llvm::Function &F : M)
      if (!F.isDeclaration())
        ++scannedFunctionCount;
    llvm::errs() << "[svf-region] SOUND CATCH-ALL engaged: process SVF cache "
                    "belongs to another LLVM module\n";
    return false;
  }
  if (g_svfAndersen &&
      (g_svfSnapshotStale || moduleSnapshot(M) != g_svfModuleSnapshot ||
       moduleValueIdentity(M) != g_svfValueIdentity)) {
    g_svfSnapshotStale = true;
    irSnapshotMatch = false;
    collapsed = true;
    collapsedRoot = 0;
    ufParent.emplace(0, 0);
    RegionInfo &universal = regionInfo[0];
    universal.allocated = true;
    universal.complicated = true;
    universal.incomplete = true;
    for (const llvm::Function &F : M)
      if (!F.isDeclaration())
        ++scannedFunctionCount;
    llvm::errs() << "[svf-region] SOUND CATCH-ALL engaged: LLVM IR changed "
                    "after the cached SVF epoch\n";
    return false;
  }

  bool builtSVF = false;
  if (g_svfAndersen == nullptr) {
    // NOTE: SVF mutates M in place (BreakConstantGEPs + UnifyFunctionExitNodes);
    // fine for llvm2bpl's one-shot use, and it preserves llvm::Value* identity for
    // the pointer queries below.
    SVF::LLVMModuleSet::buildSVFModule(M);
    g_svfModuleSet = SVF::LLVMModuleSet::getLLVMModuleSet();
    SVF::SVFIRBuilder builder;
    g_svfIR = builder.build();
    g_svfAndersen = SVF::AndersenWaveDiff::createAndersenWaveDiff(g_svfIR);
    g_svfModule = &M;
    g_svfModuleSnapshot = moduleSnapshot(M);
    g_svfValueIdentity = moduleValueIdentity(M);
    g_svfSnapshotStale = false;
    builtSVF = true;
  }
  ms = g_svfModuleSet;
  pag = g_svfIR;
  ander = g_svfAndersen;

  buildUnionFind(M);
  aggregateRegions();
  return builtSVF; // the first SVF construction normalizes LLVM IR in place
}

DSAWrapper::~DSAWrapper() {
  // One-shot tool: let process exit reclaim SVF singletons. Releasing here is
  // unsafe because SmackRep/translation may still hold llvm::Value*s into the
  // SVF-touched module.
}

unsigned DSAWrapper::rootPlus1(const llvm::Value *v) {
  if (collapsed)
    return v ? collapsedRoot + 1 : 0;
  auto it = valueRootPlus1.find(v);
  if (it != valueRootPlus1.end())
    return it->second;
  unsigned result = 0;
  auto explicitIt = explicitRoots.find(v);
  if (explicitIt != explicitRoots.end())
    result = ufFind(explicitIt->second) + 1;
  const llvm::Value *base = v ? underlyingThroughSpill(v) : nullptr;
  if (result == 0) {
    explicitIt = explicitRoots.find(base);
    if (explicitIt != explicitRoots.end())
      result = ufFind(explicitIt->second) + 1;
  }
  if (result == 0 && v && ms && ms->hasValueNode(v)) {
    const SVF::PointsTo &pts = ander->getPts(ms->getValueNode(v));
    for (SVF::NodeID o : pts)
      if (o != pag->getConstantNode()) {
        result = ufFind(o) + 1;
        break;
      }
  }
  if (result == 0 && v) {
    if (result == 0 && base && base != v && ms->hasValueNode(base)) {
      const SVF::PointsTo &points = ander->getPts(ms->getValueNode(base));
      for (SVF::NodeID object : points) {
        if (object == pag->getConstantNode() ||
            object == pag->getBlackHoleNode() || !pag->hasGNode(object))
          continue;
        const SVF::BaseObjVar *baseObject = pag->getBaseObject(object);
        if (baseObject && !baseObject->isBlackHoleObj()) {
          result = ufFind(object) + 1;
          break;
        }
      }
    }
  }
  // SOUND catch-all: once collapsed, every still-unresolved pointer maps to the
  // single universal region — it may alias anything, and everything resolved was
  // already united into that region. This includes null and undef: undef may
  // choose an arbitrary pointer, and null dereference can be defined in a module
  // with null_pointer_is_valid.
  // (Resolved pointers reach here with result != 0 already == collapsedRoot+1,
  // since unite-all merged their objects; only objectless values need this
  // override.)
  valueRootPlus1[v] = result;
  return result;
}

const DSAWrapper::RegionInfo *DSAWrapper::infoOf(MemNodeRef n) {
  if (!n)
    return nullptr;
  unsigned root = decode(n) - 1;
  auto it = regionInfo.find(root);
  return it == regionInfo.end() ? nullptr : &it->second;
}

MemNodeRef DSAWrapper::getNode(const llvm::Value *v) {
  unsigned r = rootPlus1(v);
  return r ? encode(r) : nullptr;
}

unsigned DSAWrapper::getPointedTypeSize(const llvm::Value *v) {
  // Opaque-pointer-safe: recover the access width from v's load/store users.
  for (const User *u : v->users()) {
    if (auto *L = dyn_cast<LoadInst>(u))
      if (L->getPointerOperand() == v)
        return dataLayout->getTypeStoreSize(L->getType());
    if (auto *S = dyn_cast<StoreInst>(u))
      if (S->getPointerOperand() == v)
        return dataLayout->getTypeStoreSize(S->getValueOperand()->getType());
  }
  return 1;
}

bool DSAWrapper::isRead(const llvm::Value *) {
  // Conservative: assume read (CodifyStaticInits then codifies initializers —
  // sound to over-approximate).
  return true;
}

bool DSAWrapper::isTypeSafe(const llvm::Value *) {
  // Conservative (spike): never treat a region as type-safe, which disables the
  // singleton optimization. Sound; loses some precision/perf to be revisited.
  //
  // WARNING before making this precise: isTypeSafe==false is what keeps three
  // dormant translation paths dead — Region::isSingleton (scalar-collapse of a
  // whole region into one Boogie variable), per-region `bytewise` divergence
  // in Region::init, and VectorOperations' unconditional map treatment of
  // memType(R). Returning true re-arms all three, and each is SILENTLY UNSOUND
  // if the underlying properties (getNumGlobals / isArray / isMemOpd /
  // isAllocated, byte-access inference) are not exactly right. Review those
  // consumers before changing this.
  return false;
}

unsigned DSAWrapper::getNumGlobals(MemNodeRef n) {
  auto *i = infoOf(n);
  return i ? i->numGlobals : 0;
}
bool DSAWrapper::isStaticInitd(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->staticInitd;
}
bool DSAWrapper::isMemOpd(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->memOpd;
}
bool DSAWrapper::isAllocated(MemNodeRef n) {
  auto *i = infoOf(n);
  return !i || i->allocated; // unknown -> conservative (allocated)
}
bool DSAWrapper::isComplicated(MemNodeRef n) {
  auto *i = infoOf(n);
  return !i || i->complicated;
}
bool DSAWrapper::isIncomplete(MemNodeRef n) {
  auto *i = infoOf(n);
  return !i || i->incomplete;
}
bool DSAWrapper::isArray(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->arrayLike;
}
bool DSAWrapper::hasNoAliasSeed(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->noAliasSeeded;
}
bool DSAWrapper::hasStackAllocation(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->stackAllocation;
}
bool DSAWrapper::hasHeapAllocation(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->heapAllocation;
}
bool DSAWrapper::hasGlobalAllocation(MemNodeRef n) {
  auto *i = infoOf(n);
  return i && i->globalAllocation;
}
} // namespace smack

char smack::DSAWrapper::ID = 0;

using namespace smack;
INITIALIZE_PASS(DSAWrapper, "smack-dsa-wrapper",
                "SMACK SVF-based Memory Region Partition Wrapper", false, false)
