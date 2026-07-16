//===-- MergeGEP.cpp - Merge GEPs for indexing in arrays ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Merge chained GEPs; Specially useful for arrays inside structs
//
//===----------------------------------------------------------------------===//
#define DEBUG_TYPE "merge-gep"

#include "utils/MergeGEP.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/FormattedStream.h"
#include "smack/Debug.h"

#include <vector>
// Pass statistics
STATISTIC(numMerged, "Number of GEPs merged");

using namespace llvm;

static void simplifyGEP(GetElementPtrInst *GEP);

namespace {
// Shared body for both the legacy ModulePass wrapper and the NewPM sibling.
bool runMergeArrayGEPImpl(Module &M) {
  bool changed;
  do {
    changed = false;
    for (auto &F : M) {
      for (auto &B : F) {
        for (BasicBlock::iterator I = B.begin(), BE = B.end(); I != BE;) {
          GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&*I++);
          if (GEP == nullptr)
            continue;
          simplifyGEP(GEP);
        }
      }
    }
  } while (changed);
  return true;
}
} // namespace

//
// Method: runOnModule()
//
// Description:
//  Entry point for this LLVM pass.
//  Merge chained GEPs into a single GEP
//
bool MergeArrayGEP::runOnModule(Module &M) { return runMergeArrayGEPImpl(M); }

PreservedAnalyses MergeArrayGEPNewPM::run(Module &M, ModuleAnalysisManager &) {
  bool changed = runMergeArrayGEPImpl(M);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

//
// Method: simplifyGEP()
//
// Description:
//  Check if this GEP's pointer argument is a GEP(Inst/ConstExpr)
//  If so check if we can merge the two GEPs into a single GEP
//
// Inputs:
//  GEP - A pointer to the GEP to simplify
//
static void simplifyGEP(GetElementPtrInst *GEP) {
  Value *PtrOp = GEP->getOperand(0);
  if (GEPOperator *Src = dyn_cast<GEPOperator>(PtrOp)) {
    if (Src->getNumOperands() < 2)
      return; // degenerate GEP with no indices
    // Under opaque pointers a GEP chain may switch element types mid-chain
    // (e.g. an i8 byte-offset GEP off a struct-typed GEP). Merging such a
    // chain re-scales the junction index by the WRONG element size — a silent
    // miscompilation. Only merge type-coherent chains (the same guard
    // InstCombine's visitGEPOfGEP applies).
    if (Src->getResultElementType() != GEP->getSourceElementType())
      return;
    // Note that if our source is a gep chain itself that we wait for that
    // chain to be resolved before we perform this transformation.  This
    // avoids us creating a TON of code in some cases.
    //
    if (GetElementPtrInst *SrcGEP =
        dyn_cast<GetElementPtrInst>(Src->getOperand(0)))
      if (SrcGEP->getNumOperands() == 2)
        return;   // Wait until our source is folded to completion.

    SmallVector<Value*, 8> Indices;

    // Find out whether the last index in the source GEP is a sequential idx.
    // NOTE the first GEP index steps over the POINTER (always sequential,
    // does not descend into the source element type); only the remaining
    // indices navigate inside it. Feeding the first index through the
    // element-type walk (an off-by-one this loop used to have) misclassifies
    // a src ending on a STRUCT FIELD as sequential; the Sum below then adopts
    // the outer GEP's i64 index type for a struct-field position, which is
    // invalid IR (struct indices must be i32) — the LLVM verifier rejects it
    // and SVF's gep-type walk crashes on it.
    bool EndsWithSequential = true;
    Type *IndexedTy = Src->getSourceElementType();
    for (auto I = Src->idx_begin() + 1, E = Src->idx_end(); I != E; ++I) {
      if (!IndexedTy)
        return;

      if (auto *STy = dyn_cast<StructType>(IndexedTy)) {
        EndsWithSequential = false;
        if (!STy->indexValid(*I))
          return;
        IndexedTy = STy->getTypeAtIndex(*I);
      } else {
        EndsWithSequential = true;
        if (auto *ATy = dyn_cast<ArrayType>(IndexedTy))
          IndexedTy = ATy->getElementType();
        else if (auto *VTy = dyn_cast<VectorType>(IndexedTy))
          IndexedTy = VTy->getElementType();
        else
          IndexedTy = nullptr;
      }
    }

    // Can we combine the two pointer arithmetics offsets?
    if (EndsWithSequential) {
      // Replace: gep (gep %P, long B), long A, ...
      // With:    T = long A+B; gep %P, T, ...
      //
      Value *Sum;
      Value *SO1 = Src->getOperand(Src->getNumOperands()-1);
      Value *GO1 = GEP->getOperand(1);
      if (SO1 == Constant::getNullValue(SO1->getType())) {
        Sum = GO1;
      } else if (GO1 == Constant::getNullValue(GO1->getType())) {
        Sum = SO1;
      } else {
        // If they aren't the same type, then the input hasn't been processed
        // by the loop above yet (which canonicalizes sequential index types to
        // intptr_t).  Just avoid transforming this until the input has been
        // normalized.
        if (SO1->getType() != GO1->getType())
          return;
        Sum = llvm::BinaryOperator::Create(BinaryOperator::Add,
                                           SO1, GO1, 
                                           PtrOp->getName()+".sum",GEP);
      }

      // Update the GEP in place if possible.
      if (Src->getNumOperands() == 2) {
        GEP->setOperand(0, Src->getOperand(0));
        GEP->setOperand(1, Sum);
        numMerged++;
        return;
      }
      Indices.append(Src->op_begin()+1, Src->op_end()-1);
      Indices.push_back(Sum);
      Indices.append(GEP->op_begin()+2, GEP->op_end());
    } else if (isa<Constant>(GEP->idx_begin()) &&
               cast<Constant>(GEP->idx_begin())->isNullValue() &&
               Src->getNumOperands() != 1) {
      // Otherwise we can do the fold if the first index of the GEP is a zero
      Indices.append(Src->op_begin()+1, Src->op_end());
      Indices.append(GEP->idx_begin()+1, GEP->idx_end());
    }

    if (!Indices.empty()){
      GetElementPtrInst *GEPNew =  (GEP->isInBounds() && Src->isInBounds()) ?
        GetElementPtrInst::CreateInBounds(Src->getSourceElementType(),
			                  Src->getOperand(0), Indices,
                                          GEP->getName(), GEP) :
        GetElementPtrInst::Create(Src->getSourceElementType(), Src->getOperand(0), Indices,
                                  GEP->getName(), GEP);
      numMerged++;
      GEP->replaceAllUsesWith(GEPNew);
      GEP->eraseFromParent();
    }
  }
}

// Pass ID variable
char MergeArrayGEP::ID = 0;

// Register the pass
static RegisterPass<MergeArrayGEP>
X("mergearrgep", "Merge GEPs for arrays indexing");
