//
// This file is distributed under the MIT License. See LICENSE for details.
//

#ifndef SMACK_DIFFPRODUCTMATCHER_H
#define SMACK_DIFFPRODUCTMATCHER_H

#include <string>

namespace llvm {
class Module;
} // namespace llvm

namespace smack {

std::string buildDiffProductMatchJson(llvm::Module &leftModule,
                                      llvm::Module &rightModule,
                                      const std::string &leftEntry,
                                      const std::string &rightEntry);

} // namespace smack

#endif
