//
// This file is distributed under the MIT License. See LICENSE for details.
//
#include "smack/Regions.h"
#include "smack/DSAWrapper.h"
#include "smack/DSAWrapperAnalysis.h"
#include "smack/Debug.h"
#include "smack/InitializePasses.h"
#include "smack/LlvmCompat.h"
#include "smack/Naming.h"
#include "smack/SmackOptions.h"
#include "smack/SmackPipeline.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <utility>

#define DEBUG_TYPE "regions"

namespace smack {

const DataLayout *Region::DL = nullptr;
DSAWrapper *Region::DSA = nullptr;

Region::Region()
    : representative(nullptr), type(nullptr), singleton(false), allocated(true),
      bytewise(SmackOptions::BitPrecise), incomplete(true), complicated(true),
      collapsed(true) {}

namespace {

// Opaque-pointer-safe access-type recovery: SMACK runs under opaque pointers,
// where PointerType::getElementType() is gone. Recover the element type from a
// load/store user of the pointer; callers fall back to i8 when none is found.
const Type *accessTypeFromUsers(const Value *V) {
  for (const User *u : V->users()) {
    if (auto *L = dyn_cast<LoadInst>(u)) {
      if (L->getPointerOperand() == V)
        return L->getType();
    } else if (auto *S = dyn_cast<StoreInst>(u)) {
      if (S->getPointerOperand() == V)
        return S->getValueOperand()->getType();
    }
  }
  return nullptr;
}

} // namespace

void Region::init(Module &M, Pass &P) {
  DL = &M.getDataLayout();
  DSA = &P.getAnalysis<DSAWrapper>();
}

void Region::init(Module &M, DSAWrapper &dsa) {
  DL = &M.getDataLayout();
  DSA = &dsa;
}

bool Region::isSingleton(const Value *v, uint64_t length) {
  // TODO can we do something for non-global nodes?
  auto node = DSA->getNode(v);

  return !isAllocated(node) && DSA->getNumGlobals(node) == 1 &&
         !DSA->isArray(node) && DSA->isTypeSafe(v) && !DSA->isMemOpd(node);
}

bool Region::isAllocated(MemNodeRef N) { return DSA->isAllocated(N); }

bool Region::isComplicated(MemNodeRef N) { return DSA->isComplicated(N); }

void Region::init(const Value *V, const Type *accessType, uint64_t length) {
  assert(V->getType()->isPointerTy() && "Expected pointer argument.");
  const Type *memoryType = accessType ? accessType : accessTypeFromUsers(V);
  if (!memoryType)
    memoryType = Type::getInt8Ty(V->getContext());
  representative = DSA ? DSA->getNode(V) : nullptr;
  this->type = memoryType;
  singleton = DL && representative && isSingleton(V, length);
  allocated = !representative || isAllocated(representative);
  bytewise = DSA && SmackOptions::BitPrecise &&
             (SmackOptions::NoByteAccessInference ||
              (!representative || !DSA->isTypeSafe(V)) ||
              (memoryType && memoryType->isIntegerTy(8)));
  incomplete = !representative || DSA->isIncomplete(representative);
  complicated = !representative || isComplicated(representative);
  collapsed = DSA && DSA->usedUniversalRegion();
}

Region::Region(const Value *V) {
  uint64_t length = DSA ? DSA->getPointedTypeSize(V) : UNBOUNDED;
  init(V, nullptr, length);
}

Region::Region(const Value *V, uint64_t length) { init(V, nullptr, length); }

Region::Region(const Value *V, const Type *accessType) {
  uint64_t length = UNBOUNDED;
  if (accessType && accessType->isSized() && DL)
    length = fixedTypeStoreSize(*DL, accessType);
  else if (DSA)
    length = DSA->getPointedTypeSize(V);
  init(V, accessType, length);
}

Region::Region(const Value *V, const Type *accessType, uint64_t length) {
  init(V, accessType, length);
}

Region::Region(const LoadInst &I) {
  uint64_t length = UNBOUNDED;
  if (I.getType()->isSized() && DL)
    length = fixedTypeStoreSize(*DL, I.getType());
  else if (DSA)
    length = DSA->getPointedTypeSize(I.getPointerOperand());
  init(I.getPointerOperand(), I.getType(), length);
}

Region::Region(const StoreInst &I) {
  const Type *accessType = I.getValueOperand()->getType();
  uint64_t length = UNBOUNDED;
  if (accessType->isSized() && DL)
    length = fixedTypeStoreSize(*DL, accessType);
  else if (DSA)
    length = DSA->getPointedTypeSize(I.getPointerOperand());
  init(I.getPointerOperand(), accessType, length);
}

void Region::merge(Region &R) {
  bool collapse = type != R.type;
  singleton = singleton && R.singleton;
  allocated = allocated || R.allocated;
  bytewise = SmackOptions::BitPrecise && (bytewise || R.bytewise || collapse);
  incomplete = incomplete || R.incomplete;
  complicated = complicated || R.complicated;
  collapsed = collapsed || R.collapsed;
  type = (bytewise || collapse) ? nullptr : type;
}

bool Region::overlaps(Region &R) {
  return representative == R.representative;
}

void Region::print(raw_ostream &O) {
  // TODO identify the representative
  O << "<Node:";
  if (type)
    O << *type;
  else
    O << "*";
  O << ">{";
  if (singleton)
    O << "S";
  if (bytewise)
    O << "B";
  if (complicated)
    O << "C";
  if (incomplete)
    O << "I";
  if (collapsed)
    O << "L";
  if (allocated)
    O << "A";
  O << "}";
}

} // namespace smack

char smack::Regions::ID = 0;

using namespace smack;
INITIALIZE_PASS(Regions, "smack-regions", "SMACK Memory Regions Pass", false,
                false)

namespace smack {

void Regions::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
  AU.setPreservesAll();
  if (!universalMode())
    AU.addRequired<DSAWrapper>();
}

bool Regions::universalMode() const {
  return forceUniversal || SmackOptions::NoMemoryRegionSplitting;
}

void Regions::runUniversal() {
  regions.clear();
  regions.emplace_back();
  memoryAccessCount = 0;
  mergeCount = 0;
  lateRegionCount = 0;
  initialScanComplete = true;
}

unsigned Regions::universalIdx() {
  ++memoryAccessCount;
  if (regions.empty())
    regions.emplace_back();
  return 0;
}

void Regions::runImpl(Module &M, DSAWrapper &dsa) {
  if (universalMode()) {
    runUniversal();
    return;
  }
  regions.clear();
  memoryAccessCount = 0;
  mergeCount = 0;
  lateRegionCount = 0;
  initialScanComplete = false;
  Region::init(M, dsa);
  visit(M);
  initialScanComplete = true;
}

bool Regions::runOnModule(Module &M) {
  // Pre-scan every address translation will index. Regions with the same SVF
  // union-find representative merge; distinct representatives remain distinct
  // only after DSAWrapper has ruled out every unsupported/objectless origin.
  // Later translation queries may reuse or append a proven component, while a
  // missing representative fails closed in idx(Region &).
  if (universalMode()) {
    runUniversal();
    return false;
  }
  regions.clear();
  memoryAccessCount = 0;
  mergeCount = 0;
  lateRegionCount = 0;
  initialScanComplete = false;
  Region::init(M, *this);
  visit(M);
  initialScanComplete = true;

  return false;
}

llvm::AnalysisKey RegionsAnalysis::Key;

RegionsAnalysis::Result
RegionsAnalysis::run(Module &M, llvm::ModuleAnalysisManager &MAM) {
  RegionsResult r;
  r.regions = std::make_unique<Regions>(forceUniversal);
  if (forceUniversal || SmackOptions::NoMemoryRegionSplitting) {
    r.regions->runUniversal();
  } else {
    auto &dsa = MAM.getResult<DSAWrapperAnalysis>(M);
    r.regions->runImpl(M, *dsa.wrapper);
  }
  return r;
}

unsigned Regions::size() const { return regions.size(); }

Region &Regions::get(unsigned R) { return regions[R]; }

void Regions::snapshotReport(SmackMemoryPartitionReport &report) const {
  if (universalMode()) {
    report.partitioner = "universal";
    report.dsaMode = "disabled";
    report.regionCount = 1;
    report.memoryAccessCount = memoryAccessCount;
    report.mergeCount = 0;
    report.lateRegionCount = 0;
    report.svfUniversalRegion = true;
    report.svfNoAliasSeedCount = 0;
    report.svfFieldWindows = false;
    report.svfOffsetKnownCount = 0;
    report.windowedRegionCount = 0;
    report.splitComponentCount = 0;
    report.singletonCount = 0;
    report.allocatedCount = 1;
    report.bytewiseCount = regions.front().bytewiseAccess() ? 1 : 0;
    report.incompleteCount = 1;
    report.complicatedCount = 1;
    report.collapsedCount = 1;
    report.typedCount = 0;
    report.untypedCount = 1;
    report.fallbackReasons.clear();
    report.fallbackReasons.push_back({"universal-map", 1});
    return;
  }
  // Region-level diagnostics only. The oracle/SVF-evidence counters that the
  // old sea-dsa+oracle path filled stay at their zero defaults (the feature is
  // gone). This keeps llvm2bpl's --memory-partition-report JSON populated for
  // the SVF-andersen partition without resurrecting the oracle machinery.
  report.partitioner = "svf-andersen";
  report.dsaMode = "svf-andersen";
  report.regionCount = regions.size();
  report.memoryAccessCount = memoryAccessCount;
  report.mergeCount = mergeCount;
  report.lateRegionCount = lateRegionCount;
  if (auto *dsa = Region::getDSA()) {
    report.svfUniversalRegion = dsa->usedUniversalRegion();
    report.svfUnresolvedAccessCount = dsa->getUnresolvedAccessCount();
    report.svfUnknownTargetAccessCount = dsa->getUnknownTargetAccessCount();
    report.svfUnsupportedPointerOriginCount =
        dsa->getUnsupportedPointerOriginCount();
    report.svfScannedFunctionCount = dsa->getScannedFunctionCount();
    report.svfReachableFunctionCount = dsa->getReachableFunctionCount();
    report.svfIrSnapshotMatch = dsa->matchedIrSnapshot();
    report.svfNoAliasSeedCount = dsa->getNoAliasSeedCount();
    report.svfClosedInputContract = dsa->usedClosedInputContract();
    report.svfAllocatorModel = dsa->usedAllocatorModel();
    report.svfFieldWindows = false;
    report.svfOffsetKnownCount = 0;
  }
  report.windowedRegionCount = 0;
  report.splitComponentCount = 0;

  unsigned noRepresentative = 0;
  DSAWrapper *dsa = Region::getDSA();
  report.svfNoAliasSeededRegionCount = 0;
  report.svfStackRegionCount = 0;
  report.svfHeapRegionCount = 0;
  report.svfGlobalRegionCount = 0;
  report.svfMixedAuthorityRegionCount = 0;
  report.svfRegionAuthorities.clear();
  unsigned regionIndex = 0;
  for (const auto &region : regions) {
    if (region.isSingleton())
      ++report.singletonCount;
    if (region.isAllocated())
      ++report.allocatedCount;
    if (region.bytewiseAccess())
      ++report.bytewiseCount;
    if (region.isIncomplete())
      ++report.incompleteCount;
    if (region.isComplicated())
      ++report.complicatedCount;
    if (region.isCollapsed())
      ++report.collapsedCount;
    if (region.getType())
      ++report.typedCount;
    else
      ++report.untypedCount;
    if (!region.hasRepresentative())
      ++noRepresentative;
    if (dsa && region.hasRepresentative()) {
      MemNodeRef representative = region.getRepresentative();
      const bool noAlias = dsa->hasNoAliasSeed(representative);
      const bool stack = dsa->hasStackAllocation(representative);
      const bool heap = dsa->hasHeapAllocation(representative);
      const bool global = dsa->hasGlobalAllocation(representative);
      report.svfRegionAuthorities.push_back(
          {regionIndex, noAlias, stack, heap, global});
      report.svfNoAliasSeededRegionCount += noAlias;
      report.svfStackRegionCount += stack;
      report.svfHeapRegionCount += heap;
      report.svfGlobalRegionCount += global;
      if (static_cast<unsigned>(noAlias) + static_cast<unsigned>(stack) +
              static_cast<unsigned>(heap) + static_cast<unsigned>(global) >
          1)
        ++report.svfMixedAuthorityRegionCount;
    }
    ++regionIndex;
  }

  report.fallbackReasons.clear();
  if (report.svfUnsupportedPointerOriginCount)
    report.fallbackReasons.push_back(
        {"unsupported-pointer-origin",
         report.svfUnsupportedPointerOriginCount});
  if (report.svfUnresolvedAccessCount)
    report.fallbackReasons.push_back(
        {"unresolved-access", report.svfUnresolvedAccessCount});
  if (report.svfUnknownTargetAccessCount)
    report.fallbackReasons.push_back(
        {"blackhole-access", report.svfUnknownTargetAccessCount});
  if (!report.svfIrSnapshotMatch)
    report.fallbackReasons.push_back({"ir-snapshot-mismatch", 1});
  if (noRepresentative)
    report.fallbackReasons.push_back({"no-representative", noRepresentative});
  if (report.incompleteCount)
    report.fallbackReasons.push_back({"incomplete", report.incompleteCount});
  if (report.complicatedCount)
    report.fallbackReasons.push_back({"complicated", report.complicatedCount});
  if (report.collapsedCount)
    report.fallbackReasons.push_back({"collapsed", report.collapsedCount});
  if (report.bytewiseCount)
    report.fallbackReasons.push_back({"bytewise", report.bytewiseCount});
  if (report.untypedCount)
    report.fallbackReasons.push_back({"untyped", report.untypedCount});
}

unsigned Regions::idx(const Value *V) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for: " << *V << "\n"; auto U = V;
         while (U && !isa<Instruction>(U) && !U->use_empty()) U =
             U->user_back();
         if (auto I = dyn_cast<Instruction>(U)) {
           auto F = I->getParent()->getParent();
           if (I != V)
             errs() << "  at instruction: " << *I << "\n";
           errs() << "  in function: " << F->getName() << "\n";
         });
  Region R(V);
  return idx(R);
}

unsigned Regions::idx(const Value *V, uint64_t length) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for: " << *V << " with length " << length << "\n";
         auto U = V; while (U && !isa<Instruction>(U) && !U->use_empty()) U =
                         U->user_back();
         if (auto I = dyn_cast<Instruction>(U)) {
           auto F = I->getParent()->getParent();
           if (I != V)
             errs() << "  at instruction: " << *I << "\n";
           errs() << "  in function: " << F->getName() << "\n";
         });
  Region R(V, length);
  return idx(R);
}

unsigned Regions::idx(const Value *V, const Type *accessType) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for: " << *V << " with access type ";
         if (accessType) accessType->print(errs()); else errs() << "<unknown>";
         errs() << "\n";);
  Region R(V, accessType);
  return idx(R);
}

unsigned Regions::idx(const Value *V, const Type *accessType,
                      uint64_t length) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for: " << *V << " with access type ";
         if (accessType) accessType->print(errs()); else errs() << "<unknown>";
         errs() << " and length " << length << "\n";);
  Region R(V, accessType, length);
  return idx(R);
}

unsigned Regions::idx(const LoadInst &I) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for load access: " << I << "\n";);
  Region R(I);
  return idx(R);
}

unsigned Regions::idx(const StoreInst &I) {
  if (universalMode())
    return universalIdx();
  SDEBUG(errs() << "[regions] for store access: " << I << "\n";);
  Region R(I);
  return idx(R);
}

unsigned Regions::idx(Region &R) {
  ++memoryAccessCount;
  if (!R.hasRepresentative())
    llvm::report_fatal_error(
        "SMACK regions: split-memory query has no SVF component; the "
        "pre-partition unresolved-access scan missed a translated pointer");
  unsigned r;

  SDEBUG(errs() << "[regions]   using region: ");
  SDEBUG(R.print(errs()));
  SDEBUG(errs() << "\n");

  for (r = 0; r < regions.size(); ++r) {
    if (regions[r].overlaps(R)) {

      SDEBUG(errs() << "[regions]   found overlap at index " << r << ": ");
      SDEBUG(regions[r].print(errs()));
      SDEBUG(errs() << "\n");

      regions[r].merge(R);

      SDEBUG(errs() << "[regions]   merged region: ");
      SDEBUG(regions[r].print(errs()));
      SDEBUG(errs() << "\n");

      break;
    }
  }

  if (r == regions.size()) {
    regions.emplace_back(R);
    if (initialScanComplete)
      ++lateRegionCount;

  } else {
    ++mergeCount;
    // Here is the tricky part: in case R was merged with an existing region,
    // we must now also merge any other region which intersects with R.
    unsigned q = r + 1;
    while (q < regions.size()) {
      if (regions[r].overlaps(regions[q])) {
        ++mergeCount;

        // FROZEN-PARTITION INVARIANT (W4). SmackRep queries idx() lazily
        // DURING translation, after the initial scan; a cascade here ERASES a
        // region and shifts every later index, silently retargeting already
        // emitted `$M.k` references — memory corruption in the model. A
        // post-scan query may merge INTO one existing region (index-stable)
        // or append a new one; a cascade means the scan under-covered some
        // access (a scan-coverage bug) and must fail closed.
        if (initialScanComplete)
          llvm::report_fatal_error(
              "SMACK regions: post-scan region merge cascade — a translation-"
              "time query window straddles two scanned regions; already-"
              "emitted $M indexes would be silently retargeted. This is a "
              "region-scan coverage bug.");

        SDEBUG(errs() << "[regions]   found extra overlap at index " << q
                      << ": ");
        SDEBUG(regions[q].print(errs()));
        SDEBUG(errs() << "\n");

        regions[r].merge(regions[q]);
        regions.erase(regions.begin() + q);

        SDEBUG(errs() << "[regions]   merged region: ");
        SDEBUG(regions[r].print(errs()));
        SDEBUG(errs() << "\n");

      } else {
        q++;
      }
    }
  }

  SDEBUG(errs() << "[regions]   returning index: " << r << "\n\n");

  return r;
}

void Regions::visitLoadInst(LoadInst &I) { idx(I); }

void Regions::visitStoreInst(StoreInst &I) { idx(I); }

void Regions::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
  idx(I.getPointerOperand(), I.getCompareOperand()->getType());
}

void Regions::visitAtomicRMWInst(AtomicRMWInst &I) {
  idx(I.getPointerOperand(), I.getValOperand()->getType());
}

void Regions::visitMemSetInst(MemSetInst &I) {
  uint64_t length;

  if (auto CI = dyn_cast<ConstantInt>(I.getLength()))
    length = CI->getZExtValue();
  else
    length = Region::UNBOUNDED;

  idx(I.getDest(), length);
}

void Regions::visitMemTransferInst(MemTransferInst &I) {
  uint64_t length;

  if (auto CI = dyn_cast<ConstantInt>(I.getLength()))
    length = CI->getZExtValue();
  else
    length = Region::UNBOUNDED;

  // We need to visit the source location otherwise
  // extra merges will happen in the translation phrase,
  // resulting in ``hanging'' regions.
  idx(I.getSource(), length);
  idx(I.getDest(), length);
}

void Regions::visitCallInst(CallInst &I) {
  Function *F = I.getCalledFunction();
  std::string name = F && F->hasName() ? F->getName().str() : "";
  bool isValue = name.find("__SMACK_value") != std::string::npos;
  bool isCodeOrInv = name.find(Naming::CODE_PROC) != std::string::npos ||
                     name.find(Naming::INV_PROC_PREFIX) != std::string::npos ||
                     name.find(Naming::MOD_PROC) != std::string::npos;

  if (F && F->isDeclaration() && I.getType()->isPointerTy() &&
      name != "malloc" && !isValue && !isCodeOrInv)
    idx(&I);

  // Scan annotation/intrinsic-referenced pointers before translation. This
  // guarantees every later idx() query sees the already-established component
  // and cannot introduce an undeclared map.
  auto coverWhole = [&](const Value *P) {
    if (!P)
      return;
    P = P->stripPointerCasts();
    if (P->getType()->isPointerTy())
      idx(P, Region::UNBOUNDED);
  };

  if (isValue) {
    // arg0 (and, for the load-from-field forms, its pointer operand) name the
    // annotated object; fuse their components.
    for (const Use &U : I.args()) {
      const Value *A = U.get();
      if (A->getType()->isPointerTy()) {
        coverWhole(A);
        if (auto *LI = dyn_cast<LoadInst>(A->stripPointerCasts()))
          coverWhole(LI->getPointerOperand());
      }
    }
  } else if (isCodeOrInv) {
    for (const Use &U : I.args())
      if (U.get()->getType()->isPointerTy())
        coverWhole(U.get());
  }
}

} // namespace smack
