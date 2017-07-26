//===------------------------- Inst2Int.cpp --------------------------===//
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

#define DEBUG_TYPE "inst2int"

#include "ConAnal/Inst2Int.h"

#include <fstream>
#include <iterator>

using namespace llvm;
using namespace ConAnal;


void Inst2Int::clearClassDataMember() {
  ins2int_.clear();
  sourcetoIRmap_.clear();
}

bool Inst2Int::createMaps(Module &M) {
  bool rv = true;
  for (auto funciter = M.getFunctionList().begin();
      funciter != M.getFunctionList().end(); funciter++) {
    Function *F = funciter;
    for (auto I = inst_begin(F), E = inst_end(F); I != E; ++I) {
      ins2int_[&(*I)] = ins_count_++;
      if (MDNode *N = I->getMetadata("dbg")) {
        DILocation Loc(N);
        uint32_t line = Loc.getLineNumber();
        std::string file = Loc.getFilename().str();
        file = file.substr(file.find_last_of("\\/") + 1);
        sourcetoIRmap_[std::make_pair(file, line)].push_back(&*I);
      } else {
        rv = false;
        // We comment the following lines because there might be a lot of
        // generated LLVM IRs couldn't map to any line of the source code.
        //errs() << "Warning: Couldn't dbg Metadata for LLVM IR\n";
        //I->print(errs()); errs() << "\n";
        if (isa<PHINode>(&*I) || isa<AllocaInst>(&*I) || isa<BranchInst>(&*I)) {
        } else if (isa<CallInst>(&*I) || isa<InvokeInst>(&*I)) {
        }
      }
    }
  }
  return rv;
}

bool Inst2Int::printInst(Instruction *i) {
  DEBUG(errs() << "%" << ins2int_[i] << ":\t");
  DEBUG(errs() << Instruction::getOpcodeName(i->getOpcode()) << "\t");
  for (uint32_t op_i = 0; op_i < i->getNumOperands(); op_i++) {
    Value * v = i->getOperand(op_i);
    if (isa<Instruction>(v)) {
      DEBUG(errs() << "%" << ins2int_[cast<Instruction>(v)] << " ");
    } else if (v->hasName()) {
      DEBUG(errs() << v->getName() << " ");
    } else {
      DEBUG(errs() << "XXX ");
    }
  }
  if (MDNode *N = i->getMetadata("dbg")) {
    DILocation Loc(N);
    uint32_t line = Loc.getLineNumber();
    std::string file = Loc.getFilename().str();
    file = file.substr(file.find_last_of("\\/") + 1);
    DEBUG(errs() << " | " << file << " : " << line);
  }
  DEBUG(errs() << "\n");
  return true;
}

bool Inst2Int::printMap(Module &M) {
  for (auto funcIter = M.getFunctionList().begin();
      funcIter != M.getFunctionList().end(); funcIter++) {
    Function *F = funcIter;
    DEBUG(errs() << "\nFUNCTION " << F->getName().str() << "\n");
    for (auto blk = F->begin(); blk != F->end(); ++blk) {
      DEBUG(errs() << "\nBASIC BLOCK " << blk->getName() << "\n");
      for (auto i = blk->begin(); i != blk->end(); ++i) {
        DEBUG(errs() << "%" << ins2int_[i] << ":\t");
        DEBUG(errs() << Instruction::getOpcodeName(i->getOpcode()) << "\t");
        for (uint32_t op_i = 0; op_i < i->getNumOperands(); op_i++) {
          Value * v = i->getOperand(op_i);
          if (isa<Instruction>(v)) {
            DEBUG(errs() << "%" << ins2int_[cast<Instruction>(v)] << " ");
          } else if (v->hasName()) {
            DEBUG(errs() << v->getName() << " ");
          } else {
            DEBUG(errs() << "XXX ");
          }
        }
        if (MDNode *N = i->getMetadata("dbg")) {
          DILocation Loc(N);
          uint32_t line = Loc.getLineNumber();
          std::string file = Loc.getFilename().str();
          file = file.substr(file.find_last_of("\\/") + 1);
          DEBUG(errs() << " | " << file << " : " << line);
        }
        DEBUG(errs() << "\n");
      }
    }
  }
  return false;
}

Inst2IntMap & Inst2Int::getInst2IntMap() {
  return ins2int_;
}

FileLine2InstListMap & Inst2Int::getFileLine2InstListMap() {
  return sourcetoIRmap_;
}

bool Inst2Int::printMappedInstruction(Value * v) {
  if (isa<Instruction>(v)) {
    Instruction * i = dyn_cast<Instruction>(v);
    errs() << "%" << ins2int_[i] << ":\t";
    errs() << Instruction::getOpcodeName(i->getOpcode()) << "\t";
    for (uint32_t op_i = 0; op_i < i->getNumOperands(); op_i++) {
      Value * v = i->getOperand(op_i);
      if (isa<Instruction>(v)) {
        errs() << "%" << ins2int_[cast<Instruction>(v)] << " ";
      } else if (v->hasName()) {
        errs() << v->getName() << " ";
      } else {
        errs() << "XXX ";
      }
    }
    if (MDNode *N = dyn_cast<Instruction>(v)->getMetadata("dbg")) {
      DILocation Loc(N);
      std::string fileName = Loc.getFilename().str();
      errs() << " Location: " << "("
          << fileName.substr(fileName.find_last_of("\\/") + 1) << ":"
          << Loc.getLineNumber() << ")";
    }
  } else {
    errs() << "Function args: " << v->getName();
  }

  errs() << "\n";
  return true;
}

bool Inst2Int::runOnModule(Module &M) {
  //clearClassDataMember();
  errs() << "---------------------------------------\n";
  errs() << "        Start Inst2Int Pass            \n";
  errs() << "---------------------------------------\n";
  createMaps(M);
#ifdef DEBUG_TYPE
  printMap(M);
#endif
  return false;
}

//**********************************************************************
// print (do not change this method)
//
// If this pass is run with -f -analyze, this method will be called
// after each call to runOnModule.
//**********************************************************************
void Inst2Int::print(std::ostream &O, const Module *M) const {
  O << "Instruction to integer map.\n";
}

char Inst2Int::ID = 0;
// register the Inst2Int class:
//  - give it a command-line argument (Inst2Int)
//  - a name ("Numbering the instructions")
//  - a flag saying that we don't modify the CFG
//  - a flag saying this is not an analysis pass
static RegisterPass<Inst2Int> X("Inst2Int",
                           "creating a inst to int map",
                           true, true);
