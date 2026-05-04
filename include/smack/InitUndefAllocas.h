//
// This file is distributed under the MIT License. See LICENSE for details.
//
// Promote disconnected uninitialized-local undefs into a single named
// nondet so the verifier sees one variable per C local instead of one
// per LLVM use.
//
#ifndef INIT_UNDEF_ALLOCAS_H
#define INIT_UNDEF_ALLOCAS_H

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"

namespace llvm {
class AnalysisUsage;
}

namespace smack {

class InitUndefAllocas : public llvm::FunctionPass {
public:
  static char ID;
  InitUndefAllocas() : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &F) override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

  llvm::StringRef getPassName() const override {
    return "InitUndefAllocas";
  }
};

} // namespace smack

#endif // INIT_UNDEF_ALLOCAS_H
