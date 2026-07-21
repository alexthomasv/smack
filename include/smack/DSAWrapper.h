//
// This file is distributed under the MIT License. See LICENSE for details.
//
// SVF-backed replacement for the old sea-dsa DSAWrapper. It produces a SOUND
// DISJOINT memory-region partition for SMACK's split-memory Boogie model from
// SVF's Andersen points-to analysis:
//
//   region(p) = the union-find component containing every object in pts(p).
//
// Two pointers placed in DISTINCT regions are non-aliasing by one of two
// authorities: disjoint SVF allocation components, or the verification
// contract that `noalias` pointer parameters on a selected entry point denote
// separately allocated, externally owned top-level buffers. The latter is
// deliberately stronger than LLVM's generic access-based `noalias` semantics;
// it is the closed-input assumption selected by SMACK harnesses such as
// canonical AEAD. Stack-allocation separation additionally requires SMACK's
// concrete allocator declarations and initialization procedure to be present.
//
#ifndef DSAWRAPPER_H
#define DSAWRAPPER_H

#include <limits>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

namespace SVF {
class SVFIR;
class Andersen;
class LLVMModuleSet;
} // namespace SVF

namespace smack {

// Opaque handle to a disjoint memory region. Distinct non-null refs are
// non-aliasing by SVF points-to disjointness. Before a universal collapse,
// nullptr means SVF supplied no concrete component for the pointer. After a
// collapse every translated pointer, including null and undef, receives the
// universal region handle.
using MemNodeRef = const void *;

class DSAWrapper : public llvm::ModulePass {
private:
  llvm::Module *module = nullptr;
  const llvm::DataLayout *dataLayout = nullptr;

  SVF::SVFIR *pag = nullptr;
  SVF::Andersen *ander = nullptr;
  SVF::LLVMModuleSet *ms = nullptr;

  // Union-find over SVF object NodeIDs.
  std::map<unsigned, unsigned> ufParent;
  unsigned ufFind(unsigned x);
  bool ufUnite(unsigned a, unsigned b);

  // Synthetic allocation objects for explicitly disjoint top-level buffers.
  // Pointer equality is propagated from each entry argument through derived
  // values and call edges; propagation only merges components.
  std::unordered_map<const llvm::Value *, unsigned> explicitRoots;
  std::unordered_set<unsigned> syntheticObjects;
  std::unordered_set<unsigned> noAliasSeedObjects;
  std::unordered_set<unsigned> constantDataObjects;
  unsigned nextSyntheticRoot = std::numeric_limits<unsigned>::max() - 1;
  unsigned noAliasSeedCount = 0;
  const llvm::Function *contractEntry = nullptr;
  bool closedInputContractActive = false;
  bool allocatorModelActive = false;

  // Per-component (region) aggregate properties, keyed by component root.
  struct RegionInfo {
    bool allocated = false;   // contains a heap or stack (alloca) object
    bool complicated = false; // contains an unknown/external/blackhole object
    bool incomplete = false;  // points-to may be incomplete (unknown object)
    bool arrayLike = false;   // contains an array object
    bool staticInitd = false; // contains a global with an initializer
    bool memOpd = false;      // is a memcpy/memset operand
    bool noAliasSeeded = false; // contains an explicit entry-buffer seed
    bool stackAllocation = false;
    bool heapAllocation = false;
    bool globalAllocation = false;
    unsigned numGlobals = 0;  // number of distinct global objects merged in
  };
  std::unordered_map<unsigned, RegionInfo> regionInfo; // root -> info
  std::unordered_set<unsigned> memOpdObjs;             // objs used by memcpy/memset

  // Closed program rooted at the selected SMACK entry points and initialization
  // procedures. This is reported as audit metadata; the partition proof itself
  // checks every emitted definition because Regions translates the whole module.
  std::unordered_set<const llvm::Function *> reachableFuncs;
  void computeReachable(llvm::Module &M);

  // Cache: pointer Value -> component root + 1 (0 == no region).
  std::unordered_map<const llvm::Value *, unsigned> valueRootPlus1;

  // SOUND catch-all. Set when any translated mem-op pointer is unresolved (SVF
  // gave it no concrete region). Such a pointer may alias ANY object, so the
  // global split-memory invariant
  // (may-alias => same region) can only be kept by placing everything in one
  // region. When set, rootPlus1 returns the single universal region for every
  // pointer. This is the only sound treatment of an unresolved access.
  bool collapsed = false;
  bool irSnapshotMatch = true;
  unsigned collapsedRoot = 0;
  unsigned unresolvedAccessCount = 0;
  unsigned unknownTargetAccessCount = 0;
  unsigned unsupportedPointerOriginCount = 0;
  unsigned scannedFunctionCount = 0;

  void buildUnionFind(llvm::Module &M);
  void aggregateRegions();
  // Returns component root + 1 for the region of pointer v, or 0 if none.
  unsigned rootPlus1(const llvm::Value *v);
  static MemNodeRef encode(unsigned rootPlus1) {
    return reinterpret_cast<MemNodeRef>(static_cast<uintptr_t>(rootPlus1));
  }
  static unsigned decode(MemNodeRef n) {
    return static_cast<unsigned>(reinterpret_cast<uintptr_t>(n));
  }
  const RegionInfo *infoOf(MemNodeRef n);

public:
  static char ID;
  DSAWrapper() : ModulePass(ID) {}
  ~DSAWrapper() override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
  bool runOnModule(llvm::Module &M) override;

  // Pointer queries.
  MemNodeRef getNode(const llvm::Value *v);
  unsigned getPointedTypeSize(const llvm::Value *v);
  bool isRead(const llvm::Value *v);
  bool isTypeSafe(const llvm::Value *v);

  // Access the process-global SVF analysis (module set / SVFIR / Andersen)
  // that runOnModule builds once and reuses. Returns false if SVF has not been
  // built yet or its exact IR snapshot no longer matches. The SVF-based
  // devirtualizer uses this only after DSAWrapper (enforced via AnalysisUsage).
  static bool cachedSVF(const llvm::Module &M, SVF::LLVMModuleSet *&ms,
                        SVF::SVFIR *&pag, SVF::Andersen *&ander);

  // Region (node) queries.
  unsigned getNumGlobals(MemNodeRef n);
  bool isStaticInitd(MemNodeRef n);
  bool isMemOpd(MemNodeRef n);
  bool isAllocated(MemNodeRef n);  // heap || stack
  bool isComplicated(MemNodeRef n);
  bool isIncomplete(MemNodeRef n);
  bool isArray(MemNodeRef n);
  bool hasNoAliasSeed(MemNodeRef n);
  bool hasStackAllocation(MemNodeRef n);
  bool hasHeapAllocation(MemNodeRef n);
  bool hasGlobalAllocation(MemNodeRef n);
  bool usedUniversalRegion() const { return collapsed; }
  unsigned getUnresolvedAccessCount() const { return unresolvedAccessCount; }
  unsigned getUnknownTargetAccessCount() const {
    return unknownTargetAccessCount;
  }
  unsigned getUnsupportedPointerOriginCount() const {
    return unsupportedPointerOriginCount;
  }
  unsigned getScannedFunctionCount() const { return scannedFunctionCount; }
  unsigned getReachableFunctionCount() const {
    return static_cast<unsigned>(reachableFuncs.size());
  }
  bool matchedIrSnapshot() const { return irSnapshotMatch; }
  unsigned getNoAliasSeedCount() const { return noAliasSeedCount; }
  bool usedClosedInputContract() const { return closedInputContractActive; }
  bool usedAllocatorModel() const { return allocatorModelActive; }
};
} // namespace smack

#endif // DSAWRAPPER_H
