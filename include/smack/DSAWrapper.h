//
// This file is distributed under the MIT License. See LICENSE for details.
//
// SVF-backed replacement for the old sea-dsa DSAWrapper. It produces a SOUND
// DISJOINT memory-region partition for SMACK's split-memory Boogie model from
// SVF's Andersen points-to analysis:
//
//   region(p) = the union-find component containing every object in pts(p).
//
// Two pointers placed in DISTINCT regions are non-aliasing, by one of two
// authorities: SVF-proven points-to disjointness, or — for entry-point
// parameters carrying LLVM's `noalias` (the harness's `restrict` contract) —
// a synthetic per-parameter component (see buildUnionFind). Either way the
// split-memory invariant (may-alias => same region) holds. (sea-dsa got
// disjointness natively from its unification model; SVF is inclusion-based,
// so we derive it via union-find.)
//
#ifndef DSAWRAPPER_H
#define DSAWRAPPER_H

#include <map>
#include <limits>
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
// non-aliasing — proven by SVF points-to disjointness or granted by the
// harness's `restrict`/noalias contract (synthetic entry-parameter
// components). nullptr means "no region" (e.g. undef / null pointer / a
// pointer SVF could not resolve to any object).
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

  // Sound synthetic objects for pointer parameters carrying LLVM's noalias
  // contract. SVF leaves externally supplied entry pointers objectless; noalias
  // is the authority that permits distinct regions in a disjoint harness.
  std::unordered_map<const llvm::Value *, unsigned> explicitRoots;
  std::unordered_set<unsigned> syntheticObjects;
  unsigned nextSyntheticRoot = std::numeric_limits<unsigned>::max() - 1;
  unsigned noAliasSeedCount = 0;

  // Per-component (region) aggregate properties, keyed by component root.
  struct RegionInfo {
    bool allocated = false;   // contains a heap or stack (alloca) object
    bool complicated = false; // contains an unknown/external/blackhole object
    bool incomplete = false;  // points-to may be incomplete (unknown object)
    bool arrayLike = false;   // contains an array object
    bool staticInitd = false; // contains a global with an initializer
    bool memOpd = false;      // is a memcpy/memset operand
    unsigned numGlobals = 0;  // number of distinct global objects merged in
    // Every object in the component is a constant global (LLVM isConstant()).
    // Such a region is only ever written by __SMACK_static_init (storing to a
    // constant global anywhere else is UB), so it can be modeled as a Boogie
    // `const` map fixed by axioms. Starts true; any non-const-global object
    // clears it.
    bool constOnly = true;
    bool sawObject = false; // guards constOnly against empty regions
  };
  std::unordered_map<unsigned, RegionInfo> regionInfo; // root -> info
  std::unordered_set<unsigned> memOpdObjs;             // objs used by memcpy/memset

  // Cache: pointer Value -> component root + 1 (0 == no region).
  std::unordered_map<const llvm::Value *, unsigned> valueRootPlus1;

  // Field-window offset engine (feature -svf-field-windows / env
  // SMACK_SVF_WINDOWS): per pointer value, a PROVEN constant byte offset from
  // the base of the allocation it points into. Values absent from both maps
  // have no proven offset and get the whole-component window [0, inf).
  bool fieldWindowsEnabled = false;
  std::unordered_map<const llvm::Value *, int64_t> knownOffset;
  std::unordered_set<const llvm::Value *> offsetBottom;
  unsigned offsetKnownCount = 0;
  void computeValueOffsets(llvm::Module &M);

  // Reachable (LIVE) functions: BFS over the call graph (direct + SVF-resolved
  // indirect edges) from the entry roots. Mem-ops in UNREACHABLE functions never
  // execute, so their pointers cannot cause a runtime alias.
  std::unordered_set<const llvm::Function *> reachableFuncs;
  void computeReachable(llvm::Module &M);

  // SOUND catch-all. Set when a LIVE mem-op pointer is unresolved (SVF gave it no
  // region). Such a pointer may alias ANY object, so the split-memory invariant
  // (may-alias => same region) can only be kept by placing everything in one
  // region. When set, rootPlus1 returns the single universal region for every
  // pointer. This is the only sound treatment of a live unresolved pointer; the
  // R1/R2/R3 precise resolvers exist to keep this from triggering where possible.
  bool collapsed = false;
  unsigned collapsedRoot = 0;
  unsigned liveUnresolvedAccessCount = 0;
  unsigned blackholeAccessCount = 0;

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
  // Proven constant byte offset of v from its allocation base (0 when
  // unproven — pair with hasKnownOffset; an unproven offset must widen the
  // access window to the whole component).
  uint64_t getOffset(const llvm::Value *v);
  bool hasKnownOffset(const llvm::Value *v);
  unsigned getPointedTypeSize(const llvm::Value *v);
  bool isRead(const llvm::Value *v);
  bool isTypeSafe(const llvm::Value *v);

  // Access the process-global SVF analysis (module set / SVFIR / Andersen)
  // that runOnModule builds once and reuses. Returns false if SVF has not been
  // built yet (DSAWrapper has not run). The SVF-based devirtualizer uses this to
  // reuse the same pre-devirt points-to information — it MUST run after
  // DSAWrapper (enforced via AnalysisUsage), so by the time it calls this the
  // handles are populated.
  static bool cachedSVF(SVF::LLVMModuleSet *&ms, SVF::SVFIR *&pag,
                        SVF::Andersen *&ander);

  // Region (node) queries.
  unsigned getNumGlobals(MemNodeRef n);
  bool isStaticInitd(MemNodeRef n);
  bool isMemOpd(MemNodeRef n);
  bool isAllocated(MemNodeRef n);  // heap || stack
  bool isComplicated(MemNodeRef n);
  bool isIncomplete(MemNodeRef n);
  bool isArray(MemNodeRef n);
  bool isCollapsed(MemNodeRef n);
  // Component holds only constant globals (see RegionInfo::constOnly). Only
  // meaningful when the universal catch-all did NOT engage.
  bool isConstOnly(MemNodeRef n);
  bool usedUniversalRegion() const { return collapsed; }
  unsigned getLiveUnresolvedAccessCount() const {
    return liveUnresolvedAccessCount;
  }
  unsigned getBlackholeAccessCount() const { return blackholeAccessCount; }
  unsigned getReachableFunctionCount() const { return reachableFuncs.size(); }
  unsigned getNoAliasSeedCount() const { return noAliasSeedCount; }
  bool fieldWindowsActive() const { return fieldWindowsEnabled && !collapsed; }
  unsigned getOffsetKnownCount() const { return offsetKnownCount; }
};
} // namespace smack

#endif // DSAWRAPPER_H
