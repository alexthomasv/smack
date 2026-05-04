//
// This file is distributed under the MIT License. See LICENSE for details.
//

#include "smack/DiffProductMatcher.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include "smack/Naming.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace llvm;

namespace smack {
namespace {

struct InstructionInfo {
  unsigned index = 0;
  std::string opcode;
  std::string exact;
  std::string shape;
  std::vector<std::string> sourceSpans;
};

struct BlockInfo {
  std::string function;
  std::string label;
  std::vector<InstructionInfo> instructions;

  std::vector<std::string> exactFingerprint() const {
    std::vector<std::string> out;
    for (const auto &I : instructions)
      out.push_back(I.exact);
    return out;
  }

  std::vector<std::string> shapeFingerprint() const {
    std::vector<std::string> out;
    for (const auto &I : instructions)
      out.push_back(I.shape);
    return out;
  }

  std::vector<std::string> opcodes() const {
    std::vector<std::string> out;
    for (const auto &I : instructions)
      out.push_back(I.opcode);
    return out;
  }
};

struct FunctionInfo {
  std::string name;
  std::vector<BlockInfo> blocks;
};

struct ChunkInfo {
  std::string matchId;
  std::string kind;
  double similarity = 0.0;
  const BlockInfo *left = nullptr;
  const BlockInfo *right = nullptr;
};

struct MatchStats {
  unsigned stable = 0;
  unsigned similar = 0;
  unsigned changed = 0;
  unsigned leftOnly = 0;
  unsigned rightOnly = 0;
  unsigned leftBlocks = 0;
  unsigned rightBlocks = 0;
  unsigned leftInstructions = 0;
  unsigned rightInstructions = 0;
  long long matcherMs = 0;
};

std::string typeKey(Type *T) {
  if (!T)
    return "";
  if (T->isVoidTy())
    return "void";
  if (T->isIntegerTy())
    return "i" + std::to_string(T->getIntegerBitWidth());
  if (T->isPointerTy())
    return "ptr";
  if (T->isFloatingPointTy())
    return "float";
  if (T->isArrayTy())
    return "array";
  if (T->isStructTy())
    return "struct";
  if (T->isVectorTy())
    return "vector";
  std::string S;
  raw_string_ostream OS(S);
  T->print(OS);
  return OS.str();
}

std::string constantKey(const Constant *C, bool keepConstants) {
  if (!keepConstants)
    return "#";
  if (auto *CI = dyn_cast<ConstantInt>(C)) {
    SmallString<32> S;
    CI->getValue().toString(S, 10, true);
    return "int:" + S.str().str();
  }
  if (isa<ConstantPointerNull>(C))
    return "null";
  if (isa<UndefValue>(C))
    return "undef";
  if (auto *CFP = dyn_cast<ConstantFP>(C)) {
    SmallString<32> S;
    CFP->getValueAPF().toString(S);
    return "fp:" + S.str().str();
  }
  if (auto *GV = dyn_cast<GlobalValue>(C))
    return "global:" + GV->getName().str();
  return "const";
}

std::string valueKey(const Value *V, bool keepConstants) {
  if (!V)
    return "";
  if (auto *C = dyn_cast<Constant>(V))
    return constantKey(C, keepConstants) + ":" + typeKey(C->getType());
  if (isa<BasicBlock>(V))
    return "bb";
  if (isa<Argument>(V))
    return "arg:" + typeKey(V->getType());
  if (isa<Instruction>(V))
    return "value:" + typeKey(V->getType());
  return "value:" + typeKey(V->getType());
}

std::string instructionKey(const Instruction &I, bool keepConstants) {
  std::vector<std::string> parts;
  parts.push_back(I.getOpcodeName());
  parts.push_back(typeKey(I.getType()));

  if (auto *Cmp = dyn_cast<CmpInst>(&I))
    parts.push_back(Cmp->getPredicateName(Cmp->getPredicate()).str());

  if (auto *CB = dyn_cast<CallBase>(&I)) {
    if (const Function *F = CB->getCalledFunction()) {
      parts.push_back(keepConstants ? ("call:" + F->getName().str())
                                    : "call");
    }
  }

  parts.push_back("argc:" + std::to_string(I.getNumOperands()));
  for (const Use &U : I.operands())
    parts.push_back(valueKey(U.get(), keepConstants));

  std::string out;
  for (unsigned i = 0; i < parts.size(); ++i) {
    if (i)
      out += "|";
    out += parts[i];
  }
  return out;
}

std::vector<std::string> sourceSpans(const Instruction &I) {
  std::vector<std::string> out;
  if (!I.getDebugLoc())
    return out;
  DebugLoc DL = I.getDebugLoc();
  auto *Scope = dyn_cast_or_null<DIScope>(DL.getScope());
  if (!Scope)
    return out;
  std::stringstream SS;
  SS << Scope->getFilename().str() << ":" << DL.getLine() << ":"
     << DL.getCol();
  out.push_back(SS.str());
  return out;
}

unsigned instructionIndex(const Instruction &I) {
  unsigned index = 0;
  if (!I.getParent())
    return index;
  for (const Instruction &Other : *I.getParent()) {
    if (&Other == &I)
      return index;
    if (!isa<DbgInfoIntrinsic>(Other))
      index++;
  }
  return index;
}

Function *selectFunction(Module &module, const std::string &entry,
                         std::vector<std::string> &diagnostics,
                         const std::string &side) {
  std::string normalized = entry;
  if (!normalized.empty() && normalized[0] == '@')
    normalized.erase(normalized.begin());

  if (Function *F = module.getFunction(normalized))
    return F;

  std::string escaped = normalized;
  std::replace(escaped.begin(), escaped.end(), '.', '$');
  if (Function *F = module.getFunction(escaped))
    return F;

  Function *only = nullptr;
  unsigned definitions = 0;
  std::vector<std::string> available;
  for (Function &F : module) {
    if (F.isDeclaration())
      continue;
    available.push_back(F.getName().str());
    only = &F;
    definitions++;
  }
  if (definitions == 1) {
    diagnostics.push_back(side + ": entry '" + normalized +
                          "' not found; using only function '" +
                          only->getName().str() + "'");
    return only;
  }

  std::sort(available.begin(), available.end());
  std::string msg = side + ": entry '" + normalized +
                    "' not found in LLVM IR; available=";
  for (unsigned i = 0; i < available.size(); ++i) {
    if (i)
      msg += ",";
    msg += available[i];
  }
  diagnostics.push_back(msg);
  return nullptr;
}

FunctionInfo collectFunction(Function &F) {
  Naming naming;
  naming.reset();

  FunctionInfo info;
  info.name = naming.get(F);

  for (BasicBlock &BB : F) {
    BlockInfo block;
    block.function = info.name;
    block.label = naming.get(BB);
    for (Instruction &I : BB) {
      if (isa<DbgInfoIntrinsic>(I))
        continue;
      InstructionInfo inst;
      inst.index = instructionIndex(I);
      inst.opcode = I.getOpcodeName();
      inst.exact = instructionKey(I, true);
      inst.shape = instructionKey(I, false);
      inst.sourceSpans = sourceSpans(I);
      block.instructions.push_back(inst);
    }
    info.blocks.push_back(block);
  }

  return info;
}

double lcsSimilarity(const std::vector<std::string> &left,
                     const std::vector<std::string> &right) {
  if (left.empty() && right.empty())
    return 1.0;
  if (left.empty() || right.empty())
    return 0.0;

  std::vector<unsigned> prev(right.size() + 1, 0);
  std::vector<unsigned> curr(right.size() + 1, 0);
  for (unsigned i = 1; i <= left.size(); ++i) {
    for (unsigned j = 1; j <= right.size(); ++j) {
      if (left[i - 1] == right[j - 1])
        curr[j] = prev[j - 1] + 1;
      else
        curr[j] = std::max(prev[j], curr[j - 1]);
    }
    std::swap(prev, curr);
    std::fill(curr.begin(), curr.end(), 0);
  }
  return (2.0 * static_cast<double>(prev[right.size()])) /
         static_cast<double>(left.size() + right.size());
}

double similarity(const BlockInfo &left, const BlockInfo &right) {
  auto leftShape = left.shapeFingerprint();
  auto rightShape = right.shapeFingerprint();
  if (leftShape.empty() && rightShape.empty())
    return 1.0;
  if (!leftShape.empty() || !rightShape.empty())
    return lcsSimilarity(leftShape, rightShape);
  return lcsSimilarity(left.opcodes(), right.opcodes());
}

int bestUnmatchedBlock(const BlockInfo &left,
                       const std::vector<BlockInfo> &rightBlocks,
                       const std::set<unsigned> &usedRight) {
  double bestScore = 0.0;
  int bestIndex = -1;
  for (unsigned i = 0; i < rightBlocks.size(); ++i) {
    if (usedRight.count(i))
      continue;
    double score = similarity(left, rightBlocks[i]);
    if (bestIndex < 0 || score > bestScore) {
      bestScore = score;
      bestIndex = static_cast<int>(i);
    }
  }
  return bestScore >= 0.50 ? bestIndex : -1;
}

std::vector<ChunkInfo> matchFunctions(const FunctionInfo &left,
                                      const FunctionInfo &right) {
  std::vector<ChunkInfo> chunks;
  std::set<unsigned> usedRight;
  std::map<std::string, unsigned> rightByLabel;
  for (unsigned i = 0; i < right.blocks.size(); ++i)
    rightByLabel[right.blocks[i].label] = i;

  for (unsigned i = 0; i < left.blocks.size(); ++i) {
    const BlockInfo &leftBlock = left.blocks[i];
    int rightIndex = -1;
    auto byLabel = rightByLabel.find(leftBlock.label);
    if (byLabel != rightByLabel.end() && !usedRight.count(byLabel->second))
      rightIndex = static_cast<int>(byLabel->second);
    if (rightIndex < 0)
      rightIndex = bestUnmatchedBlock(leftBlock, right.blocks, usedRight);

    ChunkInfo chunk;
    chunk.matchId = "m" + std::to_string(chunks.size());
    chunk.left = &leftBlock;

    if (rightIndex < 0) {
      chunk.kind = "left_only";
      chunks.push_back(chunk);
      continue;
    }

    const BlockInfo &rightBlock = right.blocks[rightIndex];
    usedRight.insert(static_cast<unsigned>(rightIndex));
    chunk.right = &rightBlock;
    chunk.similarity = similarity(leftBlock, rightBlock);
    if (leftBlock.exactFingerprint() == rightBlock.exactFingerprint())
      chunk.kind = "stable";
    else if (leftBlock.shapeFingerprint() == rightBlock.shapeFingerprint() ||
             chunk.similarity >= 0.72)
      chunk.kind = "similar";
    else
      chunk.kind = "changed";
    chunks.push_back(chunk);
  }

  for (unsigned i = 0; i < right.blocks.size(); ++i) {
    if (usedRight.count(i))
      continue;
    ChunkInfo chunk;
    chunk.matchId = "m" + std::to_string(chunks.size());
    chunk.kind = "right_only";
    chunk.right = &right.blocks[i];
    chunks.push_back(chunk);
  }

  return chunks;
}

std::string jsonEscape(const std::string &S) {
  std::string out;
  for (char C : S) {
    switch (C) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out += C;
      break;
    }
  }
  return out;
}

void writeStringArray(std::ostream &OS, const std::vector<std::string> &items) {
  OS << "[";
  for (unsigned i = 0; i < items.size(); ++i) {
    if (i)
      OS << ", ";
    OS << "\"" << jsonEscape(items[i]) << "\"";
  }
  OS << "]";
}

void writeSide(std::ostream &OS, const BlockInfo *block) {
  if (!block) {
    OS << "null";
    return;
  }

  OS << "{";
  OS << "\"function\": \"" << jsonEscape(block->function) << "\", ";
  OS << "\"block\": \"" << jsonEscape(block->label) << "\", ";
  OS << "\"instructions\": [";
  for (unsigned i = 0; i < block->instructions.size(); ++i) {
    if (i)
      OS << ", ";
    OS << block->instructions[i].index;
  }
  OS << "], ";

  OS << "\"opcodes\": ";
  writeStringArray(OS, block->opcodes());
  OS << ", \"source_spans\": ";
  std::vector<std::string> spans;
  for (const auto &I : block->instructions)
    spans.insert(spans.end(), I.sourceSpans.begin(), I.sourceSpans.end());
  writeStringArray(OS, spans);
  OS << "}";
}

void updateStats(MatchStats &stats, const std::vector<ChunkInfo> &chunks,
                 const FunctionInfo *left, const FunctionInfo *right) {
  if (left) {
    stats.leftBlocks = left->blocks.size();
    for (const auto &B : left->blocks)
      stats.leftInstructions += B.instructions.size();
  }
  if (right) {
    stats.rightBlocks = right->blocks.size();
    for (const auto &B : right->blocks)
      stats.rightInstructions += B.instructions.size();
  }
  for (const auto &C : chunks) {
    if (C.kind == "stable")
      stats.stable++;
    else if (C.kind == "similar")
      stats.similar++;
    else if (C.kind == "changed")
      stats.changed++;
    else if (C.kind == "left_only")
      stats.leftOnly++;
    else if (C.kind == "right_only")
      stats.rightOnly++;
  }
}

std::string renderJson(const std::string &leftEntry, const std::string &rightEntry,
                       const std::vector<ChunkInfo> &chunks,
                       const MatchStats &stats,
                       const std::vector<std::string> &diagnostics) {
  std::ostringstream OS;
  OS << "{\n";
  OS << "  \"version\": 1,\n";
  OS << "  \"source\": \"smack-cpp\",\n";
  OS << "  \"left_entry\": \"" << jsonEscape(leftEntry) << "\",\n";
  OS << "  \"right_entry\": \"" << jsonEscape(rightEntry) << "\",\n";
  OS << "  \"chunks\": [\n";
  for (unsigned i = 0; i < chunks.size(); ++i) {
    const auto &C = chunks[i];
    OS << "    {\"match_id\": \"" << jsonEscape(C.matchId)
       << "\", \"kind\": \"" << jsonEscape(C.kind) << "\", \"similarity\": "
       << std::fixed << std::setprecision(4) << C.similarity << ", \"left\": ";
    writeSide(OS, C.left);
    OS << ", \"right\": ";
    writeSide(OS, C.right);
    OS << "}";
    if (i + 1 != chunks.size())
      OS << ",";
    OS << "\n";
  }
  OS << "  ],\n";
  OS << "  \"stats\": {\n";
  OS << "    \"stable\": " << stats.stable << ",\n";
  OS << "    \"similar\": " << stats.similar << ",\n";
  OS << "    \"changed\": " << stats.changed << ",\n";
  OS << "    \"left_only\": " << stats.leftOnly << ",\n";
  OS << "    \"right_only\": " << stats.rightOnly << ",\n";
  OS << "    \"left_blocks\": " << stats.leftBlocks << ",\n";
  OS << "    \"right_blocks\": " << stats.rightBlocks << ",\n";
  OS << "    \"left_instructions\": " << stats.leftInstructions << ",\n";
  OS << "    \"right_instructions\": " << stats.rightInstructions << ",\n";
  OS << "    \"matcher_ms\": " << stats.matcherMs << "\n";
  OS << "  },\n";
  OS << "  \"diagnostics\": ";
  writeStringArray(OS, diagnostics);
  OS << "\n";
  OS << "}\n";
  return OS.str();
}

} // namespace

std::string buildDiffProductMatchJson(Module &leftModule, Module &rightModule,
                                      const std::string &leftEntry,
                                      const std::string &rightEntry) {
  auto start = std::chrono::steady_clock::now();
  std::vector<std::string> diagnostics;
  std::vector<ChunkInfo> chunks;
  MatchStats stats;

  Function *leftFunction =
      selectFunction(leftModule, leftEntry, diagnostics, "left");
  Function *rightFunction =
      selectFunction(rightModule, rightEntry, diagnostics, "right");

  FunctionInfo leftInfo;
  FunctionInfo rightInfo;
  FunctionInfo *leftPtr = nullptr;
  FunctionInfo *rightPtr = nullptr;

  if (leftFunction) {
    leftInfo = collectFunction(*leftFunction);
    leftPtr = &leftInfo;
  }
  if (rightFunction) {
    rightInfo = collectFunction(*rightFunction);
    rightPtr = &rightInfo;
  }
  if (leftPtr && rightPtr)
    chunks = matchFunctions(*leftPtr, *rightPtr);

  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  stats.matcherMs = elapsed.count();
  updateStats(stats, chunks, leftPtr, rightPtr);
  return renderJson(leftEntry, rightEntry, chunks, stats, diagnostics);
}

} // namespace smack
