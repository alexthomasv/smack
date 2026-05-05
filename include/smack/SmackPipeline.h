//
// This file is distributed under the MIT License. See LICENSE for details.
//

#ifndef SMACK_SMACKPIPELINE_H
#define SMACK_SMACKPIPELINE_H

#include <string>

namespace llvm {
class Module;
namespace legacy {
class PassManager;
} // namespace legacy
class raw_ostream;
} // namespace llvm

namespace smack {

struct SmackPipelineOptions {
  bool staticUnroll = false;
  bool modular = false;
  std::string defaultDataLayout;
};

struct SmackBplOptions {
  bool structuredLoops = false;
  bool structuredLoopsStrict = false;
};

void initializeSmackPipelinePasses();

void addSmackPreBplPasses(llvm::Module &module,
                          llvm::legacy::PassManager &passManager,
                          const SmackPipelineOptions &options);

void addSmackBplPasses(llvm::legacy::PassManager &passManager,
                       llvm::raw_ostream &out);
void addSmackBplPasses(llvm::legacy::PassManager &passManager,
                       llvm::raw_ostream &out,
                       const SmackBplOptions &options);

void runSmackPreBplPipeline(llvm::Module &module,
                            const SmackPipelineOptions &options);

void emitSmackBpl(llvm::Module &module, llvm::raw_ostream &out);
void emitSmackBpl(llvm::Module &module, llvm::raw_ostream &out,
                  const SmackBplOptions &options);

} // namespace smack

#endif
