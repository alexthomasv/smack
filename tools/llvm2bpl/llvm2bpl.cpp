//
// Copyright (c) 2013 Pantazis Deligiannis (p.deligiannis@imperial.ac.uk)
// This file is distributed under the MIT License. See LICENSE for details.
//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"

#include "smack/SmackPipeline.h"

#include <vector>

using namespace llvm;

static cl::opt<std::string> InputFilename(cl::Positional,
                                          cl::desc("<input LLVM bitcode file>"),
                                          cl::Required,
                                          cl::value_desc("filename"));

static cl::opt<std::string> OutputFilename("bpl",
                                           cl::desc("Output Boogie filename"),
                                           cl::init(""),
                                           cl::value_desc("filename"));

static cl::opt<std::string>
    FinalIrFilename("ll", cl::desc("Output the finally-used LLVM IR"),
                    cl::init(""), cl::value_desc("filename"));

static cl::opt<bool> StaticUnroll(
    "static-unroll",
    cl::desc("Use LLVM to statically unroll loops when possible"),
    cl::init(false));

static cl::opt<std::string>
    DefaultDataLayout("default-data-layout",
                      cl::desc("data layout string to use if not specified by "
                               "module"),
                      cl::init(""), cl::value_desc("layout-string"));

static cl::opt<bool> Modular(
    "modular",
    cl::desc("Enable contracts-based modular deductive verification"),
    cl::init(false));

namespace {
void check(std::string E) {
  if (!E.empty()) {
    if (errs().has_colors())
      errs().changeColor(raw_ostream::RED);
    errs() << E << "\n";
    if (errs().has_colors())
      errs().resetColor();
    exit(1);
  }
}
} // namespace

int main(int argc, char **argv) {
  llvm_shutdown_obj shutdown;
  cl::ParseCommandLineOptions(
      argc, argv, "llvm2bpl - LLVM bitcode to Boogie transformation\n");

  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram PSTP(argc, argv);
  EnableDebugBuffering = true;

  SMDiagnostic err;
  LLVMContext Context;

  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
  InitializeAllAsmParsers();

  std::unique_ptr<Module> module = parseIRFile(InputFilename, err, Context);
  if (!err.getMessage().empty())
    check("Problem reading input bitcode/IR: " + err.getMessage().str());

  smack::SmackPipelineOptions options;
  options.staticUnroll = StaticUnroll;
  options.modular = Modular;
  options.defaultDataLayout = DefaultDataLayout;

  legacy::PassManager passManager;
  smack::addSmackPreBplPasses(*module, passManager, options);

  std::vector<ToolOutputFile *> files;

  if (!FinalIrFilename.empty()) {
    std::error_code EC;
    auto F = new ToolOutputFile(FinalIrFilename.c_str(), EC, sys::fs::OF_None);
    if (EC)
      check(EC.message());
    F->keep();
    files.push_back(F);
    passManager.add(createPrintModulePass(F->os()));
  }

  if (!OutputFilename.empty()) {
    std::error_code EC;
    auto F = new ToolOutputFile(OutputFilename.c_str(), EC, sys::fs::OF_None);
    if (EC)
      check(EC.message());
    F->keep();
    files.push_back(F);
    smack::addSmackBplPasses(passManager, F->os());
  }

  passManager.run(*module);

  for (auto F : files)
    delete F;

  return 0;
}
