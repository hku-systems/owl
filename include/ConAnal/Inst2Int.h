//===-------------------------- DangerOpLable.h ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a skeleton of an implementation for the Inst2Int
// pass of Columbia University in the City of New York. For this program,
// our goal is to find those particular concurrency bugs that will make
// the system vulnerable to malicious actions.
//
//===----------------------------------------------------------------------===//

#ifndef INCLUDE_CONANAL_INST2INT_H_
#define INCLUDE_CONANAL_INST2INT_H_

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

#include "ConAnal/typedefs.h"

using namespace llvm;

namespace ConAnal {
class Inst2Int : public ModulePass {
 public:
    static char ID; // Pass identification, replacement for typeid
    Inst2Int() : ModulePass(ID) {}
    bool createMaps(Module &M);
    Inst2IntMap & getInst2IntMap();
    FileLine2InstListMap & getFileLine2InstListMap();
    bool printMap(Module &M);
    bool printInst(Instruction *I);
    bool printMappedInstruction(Value * v);
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
      AU.addRequired<AliasAnalysis>();
    }
 private:
    std::map<Instruction *, uint64_t> ins2int_;
    uint64_t ins_count_ = 1;
    FileLine2InstListMap sourcetoIRmap_;
    void clearClassDataMember();
};
}// namespace ConAnal
#endif  // INCLUDE_CONANAL_INST2INT_H_
