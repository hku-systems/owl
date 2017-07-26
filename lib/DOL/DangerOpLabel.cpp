//===------------------------- DangerOpLabel.cpp --------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Copyright (c) 2015 Columbia University. All rights reserved.
// This file is a skeleton of an implementation for the ConAnalysis
// pass of Columbia University in the City of New York. For this program,
// our goal is to find those particular concurrency bugs that will make
// the system vulnerable to malicious actions.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "dol"

#include "ConAnal/DangerOpLabel.h"

#include <fstream>
#include <iterator>

using namespace llvm;
using namespace ConAnal;

static cl::opt<std::string> danInputFile("danFuncFile",                         
            cl::desc("dangerous function input file"), cl::Required);

void DOL::clearClassDataMember() {
  danPtrOps_.clear();
  danFuncOps_.clear();
  danFuncs_.clear();
}

bool DOL::compareIndirectCall(CallSite * cs, FunctionType * fnType) {
  if (cs == NULL || fnType == NULL) {
    errs() << "Couldn't obtain FunctionType for indirect calls\n";
    abort();
  }
  // Compare the arg number
  // Tail call use no para style. Thus, we utilize extra call site info.
  if (cs != NULL) {
    if (cs->arg_size() != fnType->getNumParams())
      return false;
  }
  // Compare the return type
  Type * rtp1, * rtp2;
  rtp1 = cs->getType();
  rtp2 = fnType->getReturnType();
  if (rtp1->getTypeID() != rtp2->getTypeID()) {
    return false;
  }
  unsigned argSize = fnType->getNumParams();
  // Compare the arg type within the arg list
  for (unsigned i = 0; i < argSize; i++) {
    Type * tp1, * tp2;
    tp1 = cs->getArgument(i)->getType();
    tp2 = fnType->getParamType(i);
    if (tp1->getTypeID() != tp2->getTypeID())
      return false;
  }
  return true;
}

bool DOL::findDangerousOp(Module &M, AliasAnalysis &AA, FuncSet &fnSet) {
  for (auto funciter = M.getFunctionList().begin();
      funciter != M.getFunctionList().end(); funciter++) {
    Function *F = funciter;
    for (auto I = inst_begin(F), E = inst_end(F); I != E; ++I) {
      if (isa<GetElementPtrInst>(*I)) {
        if (MDNode *N = I->getMetadata("dbg")) {
          DILocation Loc(N);
          std::string fileName = Loc.getFilename().str();
          fileName = fileName.substr(fileName.find_last_of("\\/") + 1);
          std::string funcName = F->getName();
          uint32_t lineNum = Loc.getLineNumber();
          FuncFileLine opEntry = std::make_tuple(funcName, fileName, lineNum);
          FileLine opMapEntry = std::make_pair(fileName, lineNum);
          // TODO: This should be changed to use the map
          if (std::find(danPtrOps_.begin(), danPtrOps_.end(), opEntry) ==
              danPtrOps_.end()) {
            DEBUG(errs() << funcName << " (" << fileName
                << ":" << lineNum << ")\n");
            danPtrOps_.push_front(opEntry);
            danPtrOpsMap_[opMapEntry] = false;
          }
        }
      } else if (isa<CallInst>(&*I) || isa<InvokeInst>(&*I)) {
        CallSite cs(&*I);
        Function * calleeFn = cs.getCalledFunction();
        Value * calleeVal = cs.getCalledValue();
        StrSet fnNames;
        // Skip the llvm.dbg function
        if (!calleeFn) {
          DEBUG(errs() << "Found indirect functions calls\n");
          DEBUG(I->print(errs()));
          DEBUG(errs() << "\n");
          // Compare the function type & params to find alias
          for (auto fnI = fnSet.begin(); fnI != fnSet.end(); ++fnI) {
            if (compareIndirectCall(&cs, (*fnI)->getFunctionType())) {
              if (!AA.alias(calleeVal, *fnI))
                continue;
              fnNames.insert((*fnI)->getName().str());
              DEBUG(errs() << "Resolving it to " << (*fnI)->getName().str() 
                  << "\n");
            }
          }
        } else {
          fnNames.insert(calleeFn->getName().str());
        }
        if (calleeFn != NULL)
          if ((calleeFn->getName().str()).compare(0, 5, "llvm.") == 0)
            continue;
        StrSet intersect;
        set_intersection(fnNames.begin(), fnNames.end(),
            danFuncs_.begin(), danFuncs_.end(),
            std::inserter(intersect,intersect.begin()));
        if (!fnNames.empty() && !intersect.empty()) { 
          if (MDNode *N = I->getMetadata("dbg")) {
            DILocation Loc(N);
            std::string funcName = F->getName();
            std::string fileName = Loc.getFilename().str();
            fileName = fileName.substr(fileName.find_last_of("\\/") + 1);
            uint32_t lineNum = Loc.getLineNumber();
            FuncFileLine opEntry = std::make_tuple(funcName, fileName, 
                lineNum);
            FileLine opMapEntry = std::make_pair(fileName, lineNum);
            // TODO: This should be changed to use the map
            if (std::find(danFuncOps_.begin(), danFuncOps_.end(), opEntry) ==
                danFuncOps_.end()) {
              DEBUG(errs() << funcName << " (" << fileName
                << ":" << lineNum << ")\n");
                danFuncOps_.push_front(opEntry);
                danFuncOpsMap_[opMapEntry] = false;
            }
          }
        }
      }
    }
  }
  return false;
}

uint32_t DOL::parseInput(std::string inputfile) {
  std::ifstream ifs(inputfile);
  if (!ifs.is_open()) {
    errs() << "Runtime Error: Couldn't find dangerous_func_list.txt\n";
    abort();
  }
  std::string line;
  DEBUG(errs() << "Replaying the input file:\n");
  DEBUG(errs() << "Read from file " << inputfile << "\n");

  while (std::getline(ifs, line)) {
    char funcName[300];
    sscanf(line.c_str(), "%s\n", funcName);
    danFuncs_.insert(std::string(funcName));
    line.clear();
  }
  return danFuncs_.size();
}

bool DOL::runOnModule(Module &M) {
  clearClassDataMember();
  errs() << "---------------------------------------\n";
  errs() << "           Start DOL Pass              \n";
  errs() << "---------------------------------------\n";
  AliasAnalysis &AA = getAnalysis<AliasAnalysis>();
  FuncSet allFuncs;
  allFuncs.clear();
  for (Module::iterator F = M.begin(); F != M.end(); ++F) {
    if ((F->getName().str()).compare(0, 5, "llvm.") == 0)
      continue;
    allFuncs.insert(F);
  }
  uint32_t inNum = parseInput(danInputFile);
  errs() << "Read " << inNum << " dangerous functions from " << danInputFile 
    << "\n";
  findDangerousOp(M, AA, allFuncs);
  errs() << "\n";
  return false;
}

//**********************************************************************
// print (do not change this method)
//
// If this pass is run with -f -analyze, this method will be called
// after each call to runOnModule.
//**********************************************************************
void DOL::print(std::ostream &O, const Module *M) const {
  O << "This is Concurrency Bug Analysis.\n";
}



char DOL::ID = 0;
// register the DOL class:
//  - give it a command-line argument (DOL)
//  - a name ("Dangerous Operation Labelling")
//  - a flag saying that we don't modify the CFG
//  - a flag saying this is not an analysis pass
static RegisterPass<DOL> X("DOL",
                           "dangerous operation labelling",
                           true, true);
