//===---------------------------- ConAnalysis.h ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a skeleton of an implementation for the ConAnalysis
// pass of Columbia University in the City of New York. For this program,
// our goal is to find those particular concurrency bugs that will make
// the system vulnerable to malicious actions.
//
//===----------------------------------------------------------------------===//

#ifndef INCLUDE_CONANAL_CONANALYSIS_H_
#define INCLUDE_CONANAL_CONANALYSIS_H_

#include <cstdint>
#include <list>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <map>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "ConAnal/DangerOpLabel.h"
#include "ConAnal/ControlDependenceGraph.h"
#include "ConAnal/Inst2Int.h"
#include "ConAnal/typedefs.h"

using namespace llvm;

namespace ConAnal {
class ConAnalysis : public ModulePass {

 public:
    static char ID; // Pass identification, replacement for typeid
    ConAnalysis() : ModulePass(ID) {
    }

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
      AU.addRequired<DOL>();
      AU.addRequired<ControlDependenceGraphs>();
    }

 private:
    Inst2Int *I2I = nullptr;
    ControlDependenceGraphs *CDGs = nullptr;
    bool controlDependent = false;
    std::set<Value *> corruptedIR_;
    std::list<Instruction *> corruptedBr_;
    std::list<Instruction *> corruptedCallIns_;
    std::map<FileLine, std::list<Value *>> interCtrlDepPtr_;
    std::map<FileLine, std::list<Value *>> interCtrlDepFunc_;
    std::set<Value *> finishedVars_;
    std::map<Value *, std::list<GepIdxStruct *>> corruptedPtr_;
    std::map<Function *, EnterExitVal> funcEnterExitValMap_;
    std::map<Function *, BB2SetMap> dominatorMap_;
    std::list<Value *> orderedcorruptedIR_;
    FuncInstList callStack_;
    FuncInstList callStackHead_;
    FuncInstList callStackBody_;
    std::map<Value *, std::list<Value *>> corruptedMap_;

    /// Avoid funky problems of uninitialized data member
    void clearClassDataMember();
    ///
    const Function* findEnclosingFunc(const Value* V);
    ///
    const MDNode* findVar(const Value* V, const Function* F);
    ///
    StringRef getOriginalName(const Value* V);
    ///
    bool add2CrptList(Value * corruptedVal);
    /// Print the global index of the instructions and IR form
    void printList(std::list<Value *> &inputset);
    ///
    void printSet(std::set<BasicBlock *> &inputset);
    /// This method reads the initial value of callstack from
    /// the associated files.
    void parseInput(std::string inputfile, FuncFileLineList &csinput);
    /// This method intialize the call stack with the first corrupted 
    /// variable instruction and its callers.
    void initializeCallStack(FuncFileLineList &csInput);
    ///
    virtual bool runOnModule(Module &M);
    ///
    virtual bool getCorruptedIRs(Module &M, DOL &labels);
    ///
    virtual bool intraDataflowAnalysis(Function *, Instruction *,
                                       CorruptedArgs &corruptedparams,
                                       bool ctrlDep, DOL &labels);
    virtual uint32_t printInterCtrlDepResult(
        std::map<FileLine, std::list<Value *>> resultMap);
    ///
    virtual uint32_t getDominators(Module &M, FuncFileLineList &csinput,
        std::set<Function *> &corruptedIRFuncSet);
    /// Returns the intersection between two lists
    virtual bool getFeasiblePath(Module &M,
                                 std::list<Value *> &dominantfrontiers);
    ///
    void computeDominators(Function &F, std::map<BasicBlock *,
                           std::set<BasicBlock *>> & dominators);
    ///
    void printDominators(Function &F, std::map<BasicBlock *,
                         std::set<BasicBlock *>> & dominators);
};
}// namespace ConAnal
#endif  // INCLUDE_CONANAL_CONANALYSIS_H_
