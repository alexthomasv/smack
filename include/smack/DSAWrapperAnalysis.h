//
// This file is distributed under the MIT License. See LICENSE for details.
//
// NewPM bridge for the legacy pass that constructs the exact-IR-epoch SVF
// analysis consumed by devirtualization and memory partitioning.
//

#ifndef SMACK_DSAWRAPPER_ANALYSIS_H
#define SMACK_DSAWRAPPER_ANALYSIS_H

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"

#include "smack/DSAWrapper.h"

#include <memory>

namespace smack {

class DSAWrapperAnalysis
    : public llvm::AnalysisInfoMixin<DSAWrapperAnalysis> {
  friend llvm::AnalysisInfoMixin<DSAWrapperAnalysis>;
  static llvm::AnalysisKey Key;

public:
  // Result holds a legacy PassManager keeping DSAWrapper alive for as long as
  // MAM caches this analysis. The `wrapper` pointer is non-owning; PM owns it.
  struct Result {
    std::unique_ptr<llvm::legacy::PassManager> pm;
    DSAWrapper *wrapper = nullptr;

    // MAM invalidation hook. Honor explicit preservation: invalidate when a
    // transform reports `none()`. A recomputation compares the current module
    // with the cached SVF snapshot and fails closed to universal on any drift.
    bool invalidate(llvm::Module &, const llvm::PreservedAnalyses &PA,
                    llvm::ModuleAnalysisManager::Invalidator &) {
      auto PAC = PA.getChecker<DSAWrapperAnalysis>();
      return !PAC.preserved() &&
             !PAC.preservedSet<llvm::AllAnalysesOn<llvm::Module>>();
    }
  };

  Result run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
};

} // namespace smack

#endif // SMACK_DSAWRAPPER_ANALYSIS_H
