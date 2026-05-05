//
// This file is distributed under the MIT License. See LICENSE for details.
//

#define DEBUG_TYPE "smack-pipeline"

#include "smack/SmackPipeline.h"

#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/IPO/Internalize.h"

#include "seadsa/InitializePasses.hh"
#include "seadsa/support/Debug.h"
#include "seadsa/support/RemovePtrToInt.hh"
#include "smack/AddTiming.h"
#include "smack/AnnotateLoopExits.h"
#include "smack/BplFilePrinter.h"
#include "smack/CodifyStaticInits.h"
#include "smack/ExtractContracts.h"
#include "smack/InitializePasses.h"
#include "smack/InitUndefAllocas.h"
#include "smack/IntegerOverflowChecker.h"
#include "smack/MemorySafetyChecker.h"
#include "smack/Naming.h"
#include "smack/NormalizeLoops.h"
#include "smack/RemoveDeadDefs.h"
#include "smack/RewriteBitwiseOps.h"
#include "smack/RustFixes.h"
#include "smack/SimplifyLibCalls.h"
#include "smack/SmackModuleGenerator.h"
#include "smack/SmackOptions.h"
#include "smack/SmackWarnings.h"
#include "smack/SplitAggregateValue.h"
#include "smack/VerifierCodeMetadata.h"
#include "utils/Devirt.h"
#include "utils/InitializePasses.h"
#include "utils/MergeGEP.h"
#include "utils/SimplifyExtractValue.h"
#include "utils/SimplifyInsertValue.h"

using namespace llvm;

namespace smack {
namespace {

TargetMachine *getTargetMachine(Triple TheTriple, StringRef CPUStr,
                                StringRef FeaturesStr,
                                const TargetOptions &Options) {
  std::string Error;
  const std::string MArch;

  const Target *TheTarget =
      TargetRegistry::lookupTarget(MArch, TheTriple, Error);

  assert(TheTarget &&
         "If we don't have a target machine, can't do timing analysis");

  return TheTarget->createTargetMachine(
      TheTriple, CPUStr, FeaturesStr, Options, Reloc::Static, std::nullopt,
      CodeGenOptLevel::None);
}

void configureModule(Module &module, const SmackPipelineOptions &options) {
  if (module.getDataLayoutStr().empty())
    module.setDataLayout(options.defaultDataLayout);

  if (SmackOptions::WarningLevel == SmackWarnings::WarningLevel::Info)
    seadsa::SeaDsaEnableLog("dsa-warn");
}

} // namespace

void initializeSmackPipelinePasses() {
  PassRegistry &Registry = *PassRegistry::getPassRegistry();
  initializeAnalysis(Registry);

  initializeCodifyStaticInitsPass(Registry);
  initializeDevirtualizePass(Registry);
  initializeRemovePtrToIntPass(Registry);
}

void addSmackPreBplPasses(Module &module, legacy::PassManager &passManager,
                          const SmackPipelineOptions &options) {
  configureModule(module, options);
  initializeSmackPipelinePasses();

  // This runs before DSA because some Rust functions cause problems.
  passManager.add(new RustFixes);

  if (!options.modular) {
    auto PreserveKeyGlobals = [=](const GlobalValue &GV) {
      auto name = GV.getName();
      return SmackOptions::isEntryPoint(name) || Naming::isSmackName(name) ||
             name.find("__VERIFIER_assume") != StringRef::npos;
    };
    internalizeModule(module, PreserveKeyGlobals);
    passManager.add(createGlobalDCEPass());
    passManager.add(createDeadCodeEliminationPass());
    passManager.add(createGlobalDCEPass());
    passManager.add(createDeadCodeEliminationPass());
    passManager.add(new RemoveDeadDefs());
  }

  passManager.add(new InitUndefAllocas());
  passManager.add(seadsa::createRemovePtrToIntPass());
  passManager.add(createLowerSwitchPass());
  passManager.add(createPromoteMemoryToRegisterPass());

  if (options.staticUnroll) {
    passManager.add(createLoopSimplifyPass());
    passManager.add(createLoopUnrollPass(32767));
  }

  passManager.add(new NormalizeLoops());
  if (SmackOptions::FailOnLoopExit)
    passManager.add(new AnnotateLoopExits());
  passManager.add(new SimplifyEV());
  passManager.add(new SimplifyIV());
  passManager.add(new ExtractContracts());
  passManager.add(new VerifierCodeMetadata());
  passManager.add(createDeadCodeEliminationPass());
  passManager.add(createCodifyStaticInitsPass());
  if (!options.modular)
    passManager.add(new RemoveDeadDefs());
  passManager.add(new MergeArrayGEP());
  passManager.add(new Devirtualize());
  passManager.add(new SplitAggregateValue());

  if (SmackOptions::MemorySafety)
    passManager.add(new MemorySafetyChecker());

  passManager.add(new IntegerOverflowChecker());

  if (SmackOptions::RewriteBitwiseOps &&
      !(SmackOptions::BitPrecise || SmackOptions::BitPrecisePointers))
    passManager.add(new RewriteBitwiseOps());

  if (SmackOptions::AddTiming) {
    Triple ModuleTriple(module.getTargetTriple());
    assert(
        ModuleTriple.getArch() &&
        "Module has no defined architecture: unable to add timing annotations");

    const TargetOptions Options;
    std::string CPUStr = "";
    std::string FeaturesStr = "";
    TargetMachine *Machine =
        getTargetMachine(ModuleTriple, CPUStr, FeaturesStr, Options);

    assert(Machine &&
           "Module did not have a Target Machine: Cannot set up timing pass");
    TargetLibraryInfoImpl TLII(ModuleTriple);
    passManager.add(new TargetLibraryInfoWrapperPass(TLII));
    passManager.add(createTargetTransformInfoWrapperPass(
        Machine->getTargetIRAnalysis()));
    passManager.add(new AddTiming());
  }
}

void addSmackBplPasses(legacy::PassManager &passManager, raw_ostream &out,
                       const SmackBplOptions &options) {
  passManager.add(new SmackModuleGenerator(options.structuredLoops,
                                           options.structuredLoopsStrict));
  passManager.add(new BplFilePrinter(out));
}

void addSmackBplPasses(legacy::PassManager &passManager, raw_ostream &out) {
  addSmackBplPasses(passManager, out, SmackBplOptions{});
}

void runSmackPreBplPipeline(Module &module,
                            const SmackPipelineOptions &options) {
  legacy::PassManager passManager;
  addSmackPreBplPasses(module, passManager, options);
  passManager.run(module);
}

void emitSmackBpl(Module &module, raw_ostream &out,
                  const SmackBplOptions &options) {
  legacy::PassManager passManager;
  addSmackBplPasses(passManager, out, options);
  passManager.run(module);
}

void emitSmackBpl(Module &module, raw_ostream &out) {
  emitSmackBpl(module, out, SmackBplOptions{});
}

} // namespace smack
