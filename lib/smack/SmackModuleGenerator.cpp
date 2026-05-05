//
// This file is distributed under the MIT License. See LICENSE for details.
//
#define DEBUG_TYPE "smack-mod-gen"
#include "smack/SmackModuleGenerator.h"
#include "smack/BoogieAst.h"
#include "smack/Debug.h"
#include "smack/Naming.h"
#include "smack/Prelude.h"
#include "smack/Regions.h"
#include "smack/SmackInstGenerator.h"
#include "smack/SmackOptions.h"
#include "smack/SmackRep.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace smack {
namespace {

bool hasAttr(const Stmt *stmt, const std::string &name) {
  if (auto *assume = llvm::dyn_cast<const AssumeStmt>(stmt))
    return assume->hasAttr(name);
  return false;
}

bool isLoopHeader(Block *block) {
  auto &stmts = block->getStatements();
  return !stmts.empty() && hasAttr(stmts.front(), "loop_header");
}

bool isPartitionAssume(const Stmt *stmt) {
  return hasAttr(stmt, "partition");
}

const AssumeStmt *leadingPartition(Block *block) {
  for (auto *stmt : block->getStatements()) {
    auto *assume = llvm::dyn_cast<const AssumeStmt>(stmt);
    if (assume && assume->hasAttr("partition"))
      return assume;
  }
  return nullptr;
}

bool isLoopBodyEntry(Block *block) {
  bool sawPartition = false;
  for (auto *stmt : block->getStatements()) {
    if (isPartitionAssume(stmt)) {
      sawPartition = true;
      continue;
    }
    if (hasAttr(stmt, "loop_body"))
      return sawPartition;
    if (!llvm::isa<AssumeStmt>(stmt))
      return false;
  }
  return false;
}

const GotoStmt *trailingGoto(Block *block) {
  auto &stmts = block->getStatements();
  if (stmts.empty())
    return nullptr;
  return llvm::dyn_cast<const GotoStmt>(stmts.back());
}

bool hasInteriorGoto(Block *block) {
  auto &stmts = block->getStatements();
  if (stmts.empty())
    return false;
  auto last = stmts.end();
  --last;
  for (auto it = stmts.begin(); it != last; ++it) {
    if (llvm::isa<GotoStmt>(*it))
      return true;
  }
  return false;
}

bool hasSingleGotoTarget(Block *block, std::string &target) {
  auto *go = trailingGoto(block);
  if (!go || go->getTargets().size() != 1)
    return false;
  target = go->getTargets().front();
  return true;
}

bool isAssumeOnlyDispatch(Block *block, std::string &target) {
  if (!hasSingleGotoTarget(block, target) || !leadingPartition(block))
    return false;
  auto &stmts = block->getStatements();
  for (auto it = stmts.begin(); it != stmts.end(); ++it) {
    auto next = it;
    ++next;
    if (next == stmts.end())
      return llvm::isa<GotoStmt>(*it);
    if (!llvm::isa<AssumeStmt>(*it))
      return false;
  }
  return false;
}

bool endsWithGotoTo(Block *block, const std::string &target) {
  std::string actual;
  return hasSingleGotoTarget(block, actual) && actual == target;
}

std::map<std::string, Block *> blockMap(ProcDecl *proc) {
  std::map<std::string, Block *> blocks;
  for (auto *block : proc->getBlocks()) {
    if (block->getName() != "")
      blocks[block->getName()] = block;
  }
  return blocks;
}

bool gotoTargetsBlock(Block *block, const std::string &target) {
  auto *go = trailingGoto(block);
  if (!go)
    return false;
  for (auto &candidate : go->getTargets()) {
    if (candidate == target)
      return true;
  }
  return false;
}

std::list<const Stmt *> withoutTrailingGoto(Block *block) {
  std::list<const Stmt *> result;
  auto &stmts = block->getStatements();
  for (auto it = stmts.begin(); it != stmts.end(); ++it) {
    auto next = it;
    ++next;
    if (next == stmts.end() && llvm::isa<GotoStmt>(*it))
      continue;
    result.push_back(*it);
  }
  return result;
}

std::list<const Stmt *> withoutLeadingPartition(Block *block) {
  std::list<const Stmt *> result;
  bool skipped = false;
  for (auto *stmt : block->getStatements()) {
    if (!skipped && isPartitionAssume(stmt)) {
      skipped = true;
      continue;
    }
    result.push_back(stmt);
  }
  return result;
}

struct LoopPathBuilder {
  std::map<std::string, Block *> blocks;
  Block *header;
  std::set<Block *> exits;
  std::set<Block *> used;
  std::set<Block *> active;
  std::string reason;

  bool emit(Block *block, std::list<const Stmt *> &out) {
    if (block == header)
      return true;
    if (exits.count(block)) {
      if (auto *partition = leadingPartition(block))
        out.push_back(partition);
      out.push_back(Stmt::break_());
      return true;
    }
    if (!block) {
      reason = "loop path reaches a missing block";
      return false;
    }
    if (isLoopHeader(block)) {
      reason = "loop path reaches an unstructured nested loop";
      return false;
    }
    if (active.count(block)) {
      reason = "loop path contains a cycle that is not the loop backedge";
      return false;
    }

    active.insert(block);
    used.insert(block);

    auto prefix = withoutTrailingGoto(block);
    out.insert(out.end(), prefix.begin(), prefix.end());

    auto *go = trailingGoto(block);
    if (!go) {
      active.erase(block);
      return true;
    }

    if (go->getTargets().size() == 1) {
      auto targetName = go->getTargets().front();
      if (!blocks.count(targetName)) {
        reason = "loop path reaches an unknown successor";
        return false;
      }
      bool ok = emit(blocks[targetName], out);
      active.erase(block);
      return ok;
    }

    if (go->getTargets().size() == 2) {
      auto targetIt = go->getTargets().begin();
      Block *thenBlock = blocks.count(*targetIt) ? blocks[*targetIt] : nullptr;
      ++targetIt;
      Block *elseBlock = blocks.count(*targetIt) ? blocks[*targetIt] : nullptr;
      auto *thenPartition = thenBlock ? leadingPartition(thenBlock) : nullptr;
      if (!thenBlock || !elseBlock || !thenPartition) {
        reason = "loop branch target is missing partition metadata";
        return false;
      }

      std::list<const Stmt *> thenStmts;
      std::list<const Stmt *> elseStmts;
      if (!emit(thenBlock, thenStmts) || !emit(elseBlock, elseStmts)) {
        active.erase(block);
        return false;
      }
      out.push_back(
          Stmt::if_(thenPartition->getExpr(), thenStmts, elseStmts));
      active.erase(block);
      return true;
    }

    reason = "loop path contains a multi-way branch";
    active.erase(block);
    return false;
  }
};

bool hasUnsafeIncomingEdge(ProcDecl *proc, Block *target,
                           const std::set<Block *> &allowedSources) {
  for (auto *source : proc->getBlocks()) {
    if (!gotoTargetsBlock(source, target->getName()))
      continue;
    if (!allowedSources.count(source))
      return true;
  }
  return false;
}

void removeBlocks(ProcDecl *proc, const std::set<Block *> &removed) {
  auto &blocks = proc->getBlocks();
  for (auto it = blocks.begin(); it != blocks.end();) {
    if (removed.count(*it))
      it = blocks.erase(it);
    else
      ++it;
  }
}

bool structureLoopHeader(ProcDecl *proc, Block *header, std::string &reason) {
  auto blocks = blockMap(proc);
  const std::string headerName = header->getName();
  auto *headerGoto = trailingGoto(header);
  if (!headerGoto || headerGoto->getTargets().size() != 2) {
    reason = "loop header does not end in a binary branch";
    return false;
  }
  if (hasInteriorGoto(header)) {
    reason = "loop header contains an interior goto";
    return false;
  }

  auto targetIt = headerGoto->getTargets().begin();
  std::string firstName = *targetIt++;
  std::string secondName = *targetIt;
  if (!blocks.count(firstName) || !blocks.count(secondName)) {
    reason = "loop header branch target is missing";
    return false;
  }

  Block *first = blocks[firstName];
  Block *second = blocks[secondName];
  Block *bodyEntry = nullptr;
  Block *exitBranch = nullptr;
  if (isLoopBodyEntry(first) && leadingPartition(second)) {
    bodyEntry = first;
    exitBranch = second;
  } else if (isLoopBodyEntry(second) && leadingPartition(first)) {
    bodyEntry = second;
    exitBranch = first;
  } else {
    reason = "loop branch does not expose one body target and one exit target";
    return false;
  }

  auto *exitPartition = leadingPartition(exitBranch);
  if (!exitPartition) {
    reason = "loop exit is missing a partition assume";
    return false;
  }

  Block *exitContinuation = exitBranch;
  std::set<Block *> exitBlocks{exitBranch};
  std::string dispatchTarget;
  if (isAssumeOnlyDispatch(exitBranch, dispatchTarget)) {
    if (!blocks.count(dispatchTarget)) {
      reason = "loop exit dispatch target is missing";
      return false;
    }
    exitContinuation = blocks[dispatchTarget];
    exitBlocks.insert(exitContinuation);
  }

  LoopPathBuilder builder{blocks, header, exitBlocks, {}, {}, ""};
  std::list<const Stmt *> loopPath;
  if (!builder.emit(bodyEntry, loopPath)) {
    reason = builder.reason;
    return false;
  }

  std::vector<Block *> preheaders;
  for (auto *block : proc->getBlocks()) {
    if (block == header || exitBlocks.count(block) || builder.used.count(block))
      continue;
    if (endsWithGotoTo(block, headerName))
      preheaders.push_back(block);
  }
  if (preheaders.size() != 1) {
    reason = "loop does not have exactly one preheader";
    return false;
  }
  Block *preheader = preheaders.front();
  if (hasInteriorGoto(preheader)) {
    reason = "loop preheader contains an interior goto";
    return false;
  }

  std::set<Block *> allowedIncoming = builder.used;
  allowedIncoming.insert(header);
  allowedIncoming.insert(exitBranch);
  for (auto *used : builder.used) {
    if (hasUnsafeIncomingEdge(proc, used, allowedIncoming)) {
      reason = "loop body has an incoming edge from outside the loop region";
      return false;
    }
  }
  for (auto *exitBlock : exitBlocks) {
    if (hasUnsafeIncomingEdge(proc, exitBlock, allowedIncoming)) {
      reason = "loop exit has an incoming edge from outside the loop region";
      return false;
    }
  }

  std::list<const Stmt *> newPreheader = withoutTrailingGoto(preheader);
  std::list<const Stmt *> whileBody = withoutTrailingGoto(header);
  std::list<const Stmt *> guardExit;
  guardExit.push_back(exitPartition);
  guardExit.push_back(Stmt::break_());
  whileBody.push_back(Stmt::if_(exitPartition->getExpr(), guardExit));
  whileBody.insert(whileBody.end(), loopPath.begin(), loopPath.end());
  newPreheader.push_back(Stmt::while_(Expr::lit(true), {}, whileBody));

  auto exitStmts = withoutLeadingPartition(exitContinuation);
  newPreheader.insert(newPreheader.end(), exitStmts.begin(), exitStmts.end());
  preheader->getStatements() = newPreheader;

  std::set<Block *> removed = builder.used;
  removed.insert(header);
  removed.insert(exitBlocks.begin(), exitBlocks.end());
  removeBlocks(proc, removed);
  llvm::errs() << "SMACK structured Boogie loop: " << headerName << " via "
               << preheader->getName() << "\n";
  return true;
}

void structureBoogieLoops(ProcDecl *proc, bool strict) {
  bool changed = true;
  std::vector<std::string> failures;

  while (changed) {
    changed = false;
    std::vector<Block *> headers;
    for (auto *block : proc->getBlocks()) {
      if (isLoopHeader(block))
        headers.push_back(block);
    }

    for (auto it = headers.rbegin(); it != headers.rend(); ++it) {
      std::string reason;
      if (structureLoopHeader(proc, *it, reason)) {
        changed = true;
        break;
      }
    }
  }

  for (auto *block : proc->getBlocks()) {
    if (!isLoopHeader(block))
      continue;
    std::string reason;
    if (!structureLoopHeader(proc, block, reason)) {
      failures.push_back(block->getName() + ": " + reason);
    }
  }

  if (!failures.empty()) {
    std::stringstream msg;
    msg << "SMACK could not structure " << failures.size()
        << " loop(s) in procedure " << proc->getName();
    for (auto &failure : failures)
      msg << "\n  " << failure;
    std::string text = msg.str();
    if (strict)
      llvm::report_fatal_error(llvm::StringRef(text), false);
    llvm::errs() << text << "\n";
  }
}

} // namespace

llvm::RegisterPass<SmackModuleGenerator> X("smack", "SMACK generator pass");
char SmackModuleGenerator::ID = 0;

SmackModuleGenerator::SmackModuleGenerator()
    : SmackModuleGenerator(false, false) {}

SmackModuleGenerator::SmackModuleGenerator(bool structuredBplLoops,
                                           bool structuredBplLoopsStrict)
    : ModulePass(ID), structuredBplLoops(structuredBplLoops),
      structuredBplLoopsStrict(structuredBplLoopsStrict) {
  program = new Program();
}

void SmackModuleGenerator::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
  AU.setPreservesAll();
  AU.addRequired<llvm::LoopInfoWrapperPass>();
  AU.addRequired<Regions>();
}

bool SmackModuleGenerator::runOnModule(llvm::Module &m) {
  generateProgram(m);
  return false;
}

void SmackModuleGenerator::generateProgram(llvm::Module &M) {

  Naming naming;
  SmackRep rep(&M.getDataLayout(), &naming, program, &getAnalysis<Regions>());
  std::list<Decl *> &decls = program->getDeclarations();

  SDEBUG(errs() << "Analyzing globals...\n");

  for (auto &G : M.globals()) {
    auto ds = rep.globalDecl(&G);
    decls.insert(decls.end(), ds.begin(), ds.end());
  }

  SDEBUG(errs() << "Analyzing functions...\n");

  for (auto &F : M) {

    // Reset the counters for per-function names
    naming.reset();

    SDEBUG(errs() << "Analyzing function: " << naming.get(F) << "\n");

    auto ds = rep.globalDecl(&F);
    decls.insert(decls.end(), ds.begin(), ds.end());

    auto procs = rep.procedure(&F);
    assert(procs.size() > 0);

    if (naming.get(F) != Naming::DECLARATIONS_PROC)
      decls.insert(decls.end(), procs.begin(), procs.end());

    if (F.isDeclaration())
      continue;

    if (!F.empty() && !F.getEntryBlock().empty()) {
      SDEBUG(errs() << "Analyzing function body: " << naming.get(F) << "\n");

      for (auto P : procs) {
        SmackInstGenerator igen(
            getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo(), &rep, P,
            &naming);
        SDEBUG(errs() << "Generating body for " << naming.get(F) << "\n");
        igen.visit(F);
        SDEBUG(errs() << "\n");

        // First execute static initializers, in the main procedure.
        if (F.hasName() && SmackOptions::isEntryPoint(F.getName())) {
          P->insert(Stmt::call(Naming::INITIALIZE_PROC));

        } else if (naming.get(F).find(Naming::INIT_FUNC_PREFIX) == 0)
          rep.addInitFunc(&F);

        if (structuredBplLoops || structuredBplLoopsStrict)
          structureBoogieLoops(P, structuredBplLoopsStrict);
      }
      SDEBUG(errs() << "Finished analyzing function: " << naming.get(F)
                    << "\n\n");
    }

    // MODIFIES
    // ... to do below, after memory splitting is determined.
  }

  auto ds = rep.auxiliaryDeclarations();
  decls.insert(decls.end(), ds.begin(), ds.end());
  decls.insert(decls.end(), rep.getInitFuncs());

  // NOTE we must do this after instruction generation, since we would not
  // otherwise know how many regions to declare.
  Prelude prelude(rep);
  program->appendPrelude(prelude.getPrelude());

  std::list<Decl *> kill_list;
  for (auto D : *program) {
    if (auto P = dyn_cast<ProcDecl>(D)) {
      if (rep.isContractExpr(D->getName())) {
        decls.insert(decls.end(), Decl::code(P));
        kill_list.push_back(P);
      }
    }
  }
  for (auto D : kill_list)
    decls.erase(std::remove(decls.begin(), decls.end(), D), decls.end());
}

} // namespace smack
