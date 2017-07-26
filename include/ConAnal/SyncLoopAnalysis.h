//===-------------------------- SyncLoopAnalysis.h -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===---------------------------------------------------------------------===//
//
// This file is a skeleton of an implementation for the DOL
// pass of Columbia University in the City of New York. For this program,
// our goal is to find those particular concurrency bugs that will make
// the system vulnerable to malicious actions.
//
//===---------------------------------------------------------------------===//

#ifndef INCLUDE_CONANAL_SYNCLOOP_H_
#define INCLUDE_CONANAL_SYNCLOOP_H_

#include <list>
#include <unistd.h>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Type.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "ConAnal/ControlDependenceGraph.h"
#include "ConAnal/typedefs.h"
#include "ConAnal/Inst2Int.h"

using namespace llvm;

namespace ConAnal {
class SyncLoop : public ModulePass {
 public:
    static char ID; // Pass identification, replacement for typeid
    SyncLoop() : ModulePass(ID) {}
    void clearClassDataMember();
    bool printInst(Instruction *i);
    virtual bool runOnModule(Module &M);

    //**********************************************************************
    // print (do not change this method)
    //
    // If this pass is run with -f -analyze, this method will be called
    // after each call to runOnModule.
    //**********************************************************************
    virtual void print(std::ostream &O, const Module *M) const;

    //**********************************************************************
    // getAnalysisUsage
    //**********************************************************************

    // We don't modify the program, so we preserve all analyses
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesAll();
      AU.addRequired<Inst2Int>();
      AU.addRequired<LoopInfo>();
      AU.addRequired<ControlDependenceGraphs>();
    }
 private:
    std::set<Value *> finishedVars_;
    FuncInstList readFuncInstList_;
    FuncInstList writeFuncInstList_;
    Inst2Int *I2I = nullptr;
    ControlDependenceGraphs *CDG = nullptr;
    std::set<Value *> corruptedIR_;
    std::list<Value *> orderedcorruptedIR_;
    std::map<Value *, std::list<GepIdxStruct *>> corruptedPtr_;
    std::list<Instruction *> corruptedBr_;

    bool add2CrptList(Value * corruptedVal);
    Loop * checkLoop(Module &M);
    Loop * iterateLoops(std::set<BasicBlock *> &firstInsBBSet, Loop *L,
        unsigned nesting);
    void parseInput(std::string inputfile, FuncFileLineList &csinput);
    void initialize(FuncFileLineList &csInput);
    bool intraFlowAnalysis(Function * F, Instruction * ins);
    bool adhocSyncAnalysis(FuncFileLineList &input, Loop * iL);
};
}// namespace ConAnal
#endif  // INCLUDE_CONANAL_SYNCLOOP_H_
