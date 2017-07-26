//===------------------------- SyncLoopAnalysis.cpp -----------------------===//
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

#define DEBUG_TYPE "syncloop"

#include "ConAnal/ControlDependenceGraph.h"
#include "ConAnal/Inst2Int.h"
#include "ConAnal/SyncLoopAnalysis.h"

#include <fstream>
#include <iterator>

using namespace llvm;
using namespace ConAnal;

static cl::opt<std::string> racingWrite("writeVar",
    cl::init("0"),
    cl::desc("Manually input the racing write variable"));

static cl::opt<std::string> racingRead("readVar",
    cl::init("0"),
    cl::desc("Manually input the racing read variable"));

static cl::opt<std::string> RaceReportInput("raceReport",
    cl::desc("race report input file"), cl::Required);

void SyncLoop::clearClassDataMember() {
  finishedVars_.clear();
  readFuncInstList_.clear();
  writeFuncInstList_.clear();
  corruptedIR_.clear();
  orderedcorruptedIR_.clear();
  corruptedPtr_.clear();
  corruptedBr_.clear();
}

bool SyncLoop::add2CrptList(Value * v) {
  if (!corruptedIR_.count(v)) {
    orderedcorruptedIR_.push_back(v);
    corruptedIR_.insert(v);
    return true;
  }
  return false;
}

bool SyncLoop::printInst(Instruction *i) {
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  errs() << "%" << ins2int[i] << ":\t";
  errs() << Instruction::getOpcodeName(i->getOpcode()) << "\t";
  for (uint32_t op_i = 0; op_i < i->getNumOperands(); op_i++) {
    Value * v = i->getOperand(op_i);
    if (isa<Instruction>(v)) {
    errs() << "%" << ins2int[cast<Instruction>(v)] << " ";
    } else if (v->hasName()) {
      errs() << v->getName() << " ";
    } else {
      errs() << "XXX ";
    }
  }
  if (MDNode *N = i->getMetadata("dbg")) {
    DILocation Loc(N);
    uint32_t line = Loc.getLineNumber();
    std::string file = Loc.getFilename().str();
    file = file.substr(file.find_last_of("\\/") + 1);
    errs() << " | " << file << " : " << line;
  }
  return true;
}

void SyncLoop::parseInput(std::string inputfile, FuncFileLineList &csinput) {
  std::ifstream ifs(inputfile);
  if (!ifs.is_open()) {
    errs() << "Runtime Error: Couldn't find input file " << inputfile << "\n";
    errs() << "Please check the file path.\n";
    abort();
  }
  // The first line is the write instruction, the second line is the read.
  for (int i = 0; i < 2; i++) {
    std::string line;
    std::getline(ifs, line);
    // The maximum file length in linux is 255
    char fileName[256];
    char funcName[256];
    uint32_t lineNum;
    int rv = 0;
    // Input format: funcName (fileName:lineNum)
    rv = sscanf(line.c_str(), "%s (%[^ :]:%u)\n", funcName, fileName, &lineNum);
    assert(rv > 0 && "Invalid input line!\n");
    std::string s1(funcName), s2(fileName);
    csinput.push_back(std::make_tuple(s1, s2, lineNum));
  }
}

void SyncLoop::initialize(FuncFileLineList &csinput) {
  errs() << "---- Replaying Racing Instruction Input ----\n";
  int csinputidx = 0;
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  FileLine2InstListMap & sourcetoIRmap = I2I->getFileLine2InstListMap();
  for (auto cs_it = csinput.begin(); cs_it != csinput.end();
      ++cs_it, csinputidx++) {
    std::string filename = std::get<1>(*cs_it);
    uint32_t line = std::get<2>(*cs_it);
    errs() << "(" << filename << " : " << line << ")\n";
    auto mapitr = sourcetoIRmap.find(std::make_pair(filename, line));
    if (mapitr == sourcetoIRmap.end()) {
      // It's tolerable if some instructions in certain functions are missing
      // due to some library linking issue. However, it doesn't make any
      // sense if the corrupted variable instruction is missing.
      if (csinputidx == 0) {
        errs() << "Warning: <" << std::get<1>(*cs_it) << " "
               << std::get<2>(*cs_it) << ">"
               << " sourcetoIRmap_ look up failed.\n";
        errs() << "Warning: Missing debug info for the write racing instruction\n";
        continue;
      }
      else {
        errs() << "Error: <" << std::get<1>(*cs_it) << " "
               << std::get<2>(*cs_it) << ">"
               << " sourcetoIRmap_ look up failed.\n";
        errs() << "Error: Missing debug info for the read instruction, aborting...\n";
        abort();
      }
    }
    std::list<Instruction *>& insList = mapitr->second;
    if (insList.begin() == insList.end()) {
      errs() << "Error: <" << std::get<1>(*cs_it) << " "
             << std::get<2>(*cs_it) << ">"
             << " No matching instructions.\n";
      abort();
    }
    for (auto listit = insList.begin(); listit != insList.end(); ++listit) {
      if (csinputidx == 0) {
        Function * func = &*(((*listit)->getParent())->getParent());
        writeFuncInstList_.push_back(std::make_pair(&*func, *listit));
        errs() << "---- ";
        printInst(*listit);
        errs() << " ----\n";
        continue;
      }
      if (isa<GetElementPtrInst>(*listit)) {
        // This flag checks if the corrupted variable is already added
        // to the head.
        bool flagAlreadyAddedVar = false;
        for (uint32_t op_i = 0; op_i < (*listit)->getNumOperands(); op_i++) {
          if (finishedVars_.count((*listit)->getOperand(op_i))) {
            flagAlreadyAddedVar = true;
            break;
          }
        }
        if (flagAlreadyAddedVar)
          break;
        Function * func = &*(((*listit)->getParent())->getParent());
        DEBUG(errs() << func->getName() << " contains the above ins\n");
        readFuncInstList_.push_back(std::make_pair(&*func, *listit));
        finishedVars_.insert(*listit);
        errs() << "---- ";
        printInst(*listit);
        errs() << " ----\n";
      } else if (isa<CallInst>(*listit) || isa<InvokeInst>(*listit)) {
        CallSite cs(*listit);
        Function * callee = cs.getCalledFunction();
        if (callee != NULL) {
          // Skip llvm intrinsic function
          if (callee->isIntrinsic())
            continue;
        }
        if (listit == insList.begin()) {
          errs() << "Warning: Call Inst %" << ins2int[*listit]
                 << " is the first one in the call stack!\n";
          continue;
        }
      } else {
        Function * func = ((*listit)->getParent())->getParent();
        bool flagAlreadyAddedVar = false;
        bool hasGlobal = false;
        bool isPointer = false;
        bool isBitCast = false;
        for (uint32_t op_i = 0; op_i < (*listit)->getNumOperands(); op_i++) {
          Value * v = (*listit)->getOperand(op_i);
          if (finishedVars_.count(v)) {
            flagAlreadyAddedVar = true;
            finishedVars_.insert(*listit);
          }
          if (isa<GlobalVariable>(v)) {
            hasGlobal = true;
          }
          if (isa<GetElementPtrInst>(v)) {
            isPointer = true;
          }
          if (isa<BitCastInst>(v)) {
            isBitCast = true;
          }
        }
        if (*listit != insList.back() ||
            (!readFuncInstList_.empty() || !writeFuncInstList_.empty())) {
          if (flagAlreadyAddedVar ||
              (!hasGlobal && isa<LoadInst>(*listit)) ||
              (!isBitCast && !isPointer && !isa<LoadInst>(*listit)))
            continue;
        }
        readFuncInstList_.push_back(std::make_pair(&*func, *listit));
        finishedVars_.insert(*listit);
        errs() << "---- ";
        printInst(*listit);
        errs() << " ----\n";
      }
    }
    DEBUG(errs() << "\n");
  }
  errs() << "\n";
  // Overwrite existing input if there is manual input
  uint64_t write = std::stoi(racingWrite);
  uint64_t read = std::stoi(racingRead);

  for (auto it = ins2int.begin(); it != ins2int.end();
      ++it) {
    if (it->second == write) {
      Function * func = &*(((it->first)->getParent())->getParent());
      writeFuncInstList_.clear();
      writeFuncInstList_.push_back(std::make_pair(&*func, it->first));
      (it->first)->print(errs());errs() << "\n";
      errs() << "Racing write is manually inputed."
             << "The value is " << write << "\n";
      break;
    } else if (it->second == read) {
      Function * func = &*(((it->first)->getParent())->getParent());
      readFuncInstList_.clear();
      readFuncInstList_.push_back(std::make_pair(&*func, it->first));
      (it->first)->print(errs());errs() << "\n";
      errs() << "Racing read is manually inputed."
             << "The value is " << read << "\n";
      break;
    }
  }
  return;
}

Loop * SyncLoop::checkLoop(Module &M) {
  std::set<BasicBlock *> firstInsBBSet;
  auto cs_itr = readFuncInstList_.front();
  firstInsBBSet.insert(cs_itr.second->getParent());
  for (auto funciter = M.getFunctionList().begin();
        funciter != M.getFunctionList().end(); funciter++) {
    Loop * res = NULL;
    if (funciter->isDeclaration())
      continue;
    LoopInfo &LI = getAnalysis<LoopInfo>(*funciter);
    // Only need to use one because they are in the same line
    for (LoopInfo::iterator i = LI.begin(), e = LI.end(); i != e; ++i) {
      res = iterateLoops(firstInsBBSet, *i, 0);
      if (res != NULL)
        return res;
    }
  }
  return NULL;
}

Loop * SyncLoop::iterateLoops(std::set<BasicBlock *> &firstInsBBSet, Loop *L,
    unsigned nesting) {
  Loop::block_iterator bb;
  for(bb = L->block_begin(); bb != L->block_end(); ++bb) {
    if (firstInsBBSet.count(*bb)) {
      return L;
    }
  }
  std::vector<Loop*> subLoops= L->getSubLoops();
  Loop::iterator j, f;
  Loop * res = NULL;
  for (j = subLoops.begin(), f = subLoops.end(); j != f; ++j) {
    res = iterateLoops(firstInsBBSet,*j, nesting + 1);
    if (res != NULL)
      return res;
  }
  return NULL;
}

bool SyncLoop::intraFlowAnalysis(Function * F, Instruction * ins) {
  bool rv = false;
  std::list<Instruction *> localCorruptedBr_;
  auto I = inst_begin(F);
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  for (; I != inst_end(F); ++I) {
    if (&*I == &*ins) {
      if (!corruptedIR_.count(&*I)) {
        orderedcorruptedIR_.push_back(&*I);
        corruptedIR_.insert(&*I);
        DEBUG(errs() << "Adding corrupted variable: ");
        DEBUG(errs() << "%" << ins2int[&*I] << "\n");
        rv = true;
      }
      break;
    }
  }
  assert(I != inst_end(F) && "Couldn't find callstack instruction.");
  // Obtain the Control Dependence Graph of the current function
  bool noGraph = false;
  if (CDG->graphs.find(F) == CDG->graphs.end())
    noGraph = true;
  ControlDependenceGraphBase &cdgBase = (*CDG)[F];

  if (I == inst_end(F)) {
    DEBUG(errs() << "Couldn't obtain the source code of function \""
        << F->getName() << "\"\n");
  }
  // Forward taint analysis on each instruction
  for (; I != inst_end(F); ++I) {
    // Check if the current instruction is control dependent on any corrupted
    // intra-procedural branch instruction
    for (auto brIns : localCorruptedBr_) {
      if (noGraph)
        break;
      BasicBlock * brBB = brIns->getParent();
      BasicBlock * insBB = I->getParent();
      if (cdgBase.influences(brBB, insBB)) {
        add2CrptList(&*I);
        break;
      }
    }
    if (isa<GetElementPtrInst>(&*I)) {
      int op_ii = I->getNumOperands();
      if (corruptedPtr_.count(I->getOperand(0))) {
        auto coPtrList = corruptedPtr_[I->getOperand(0)];
        if (op_ii == 2) {
          Value * gepIdx = I->getOperand(1);
          for (auto it : coPtrList) {
            if (it->idxType == GEP_TWO_OP) {
              if (it->gepIdx.idx == gepIdx) {
                DEBUG(errs() << "Add %" << ins2int[&*I] << " to crpt list\n");
                add2CrptList(&*I);
              }
            }
          }
        } else if (op_ii == 3) {
          auto gepIdxPair = std::make_pair(I->getOperand(1), I->getOperand(2));
          for (auto it : coPtrList) {
            if (it->idxType == GEP_THREE_OP) {
              if (it->gepIdx.array_idx == gepIdxPair) {
                DEBUG(errs() << "Add %" << ins2int[&*I]
                             << " to crpt list\n");
                add2CrptList(&*I);
              }
            }
          }
        }
      }
      for (uint32_t op_i = 0, op_num = I->getNumOperands(); op_i < op_num;
           op_i++) {
        Value * v = I->getOperand(op_i);
        if (corruptedIR_.count(v)) {
          if (!corruptedIR_.count(&*I)) {
            orderedcorruptedIR_.push_back(&*I);
            corruptedIR_.insert(&*I);
            DEBUG(errs() << "Add %" << ins2int[&*I]
                         << " to crpt list\n");
            int op_ii = I->getNumOperands();
            GepIdxStruct * gep_idx = reinterpret_cast<GepIdxStruct *>
                (malloc(sizeof(GepIdxStruct)));
            if (op_ii == 3) {
              gep_idx->idxType = GEP_THREE_OP;
              gep_idx->gepIdx.array_idx = std::make_pair(I->getOperand(1),
                                                         I->getOperand(2));
            } else if (op_ii == 2) {
              gep_idx->idxType = 1;
              gep_idx->gepIdx.idx = I->getOperand(1);
            } else {
              errs() << "Error: Cannot parse GetElementPtrInst\n";
              abort();
            }
            corruptedPtr_[I->getOperand(1)].push_back(gep_idx);
          }
        }
      }
    } else {
      for (uint32_t op_i = 0, op_num = I->getNumOperands(); op_i < op_num;
           op_i++) {
        Value * v = I->getOperand(op_i);
        if (corruptedIR_.count(v)) {
          if (!corruptedIR_.count(&*I)) {
            orderedcorruptedIR_.push_back(&*I);
            corruptedIR_.insert(&*I);
            if (isa<StoreInst>(&*I)) {
              Value * v = I->getOperand(1);
              add2CrptList(v);
            } else if (isa<BranchInst>(&*I)) {
              bool found = (std::find(corruptedBr_.begin(), corruptedBr_.end(),
                                      &*I) != corruptedBr_.end());
              if (!found)
                corruptedBr_.push_back(&*I);
              localCorruptedBr_.push_back(&*I);
            }
            rv = true;
          }
          break;
        }
      }
    }
  }
  return rv;
}

bool SyncLoop::adhocSyncAnalysis(FuncFileLineList &input, Loop * iL) {
  bool constantWrite = false;
  for (auto cs_itr : writeFuncInstList_) {
    Instruction *I = cs_itr.second;
    I->print(errs());
    errs() << "\n";
    if (isa<StoreInst>(I)) {
      if (isa<Constant>(I->getOperand(0)))
        constantWrite = true;
    }
  }
  if (!constantWrite) {
    errs() << "!!!! Write side is not constant ! !!!!\n";
    return false;
  }
  for (auto cs_itr : readFuncInstList_) {
    Function *F = cs_itr.first;
    Instruction *I = cs_itr.second;
    intraFlowAnalysis(F, I);
    for (auto itr = orderedcorruptedIR_.begin();
        itr != orderedcorruptedIR_.end(); itr++) {
      bool corruptInBr = false;
      if (isa<ICmpInst>(*itr) || isa<BinaryOperator>(*itr)) {
        errs() << "==== Corrupted Branch Statement Found ! ====\n";
        F = dyn_cast<Instruction>(*itr)->getParent()->getParent();
        I = dyn_cast<Instruction>(*itr);
        printInst(I); errs() << "\n";
        corruptInBr = true;
      }
    
      FuncFileLineList::iterator it = input.begin();
      if (corruptInBr) {
        BasicBlock * BB = I->getParent();
        if (iL->isLoopExiting(BB)) {
          errs() << "**************************************************\n";
          errs() << "           Adhoc Synchronization Loop Detected!   \n";
          errs() << "Write Inst ";
          errs() << "(" << std::get<1>(*it) << " : " << std::get<2>(*it) << ") ";
          it++;
          errs() << "Read Inst ";
          errs() << "(" << std::get<1>(*it) << " : " << std::get<2>(*it) << ")\n";
          printInst(I);
          errs() << "\n**************************************************\n";
          errs() << "\n";
          break;
        }
      }
    }
    // Clear data sets for next iteration
    corruptedIR_.clear();
    orderedcorruptedIR_.clear();
    corruptedPtr_.clear();
    corruptedBr_.clear();
  }
  return true;
}

bool SyncLoop::runOnModule(Module &M) {
  Loop * inLoop = NULL;
  FuncFileLineList racingLines;
  FuncInstList racingFuncInstList;
  I2I = &getAnalysis<Inst2Int>();
  CDG = &getAnalysis<ControlDependenceGraphs>();
  clearClassDataMember();
  errs() << "---------------------------------------\n";
  errs() << "        Start SyncLoop Pass            \n";
  errs() << "---------------------------------------\n";

  parseInput(RaceReportInput, racingLines);
  initialize(racingLines);
  inLoop = checkLoop(M);
  if (inLoop) {
    errs() << "==== First Instruction Is In A Loop ! ====\n";
    errs() << "==== Start Adhoc Synchronization Analysis ====\n";
    adhocSyncAnalysis(racingLines, inLoop);
  }
  return false;
}

//**********************************************************************
// print (do not change this method)
//
// If this pass is run with -f -analyze, this method will be called
// after each call to runOnModule.
//**********************************************************************
void SyncLoop::print(std::ostream &O, const Module *M) const {
  O << "Synchronization Loop Analysis.\n";
}

char SyncLoop::ID = 0;
// register the SyncLoop class:
//  - give it a command-line argument (SyncLoop)
//  - a name ("Synchronization Loop Labelling")
//  - a flag saying that we don't modify the CFG
//  - a flag saying this is not an analysis pass
static RegisterPass<SyncLoop> X("SyncLoop",
                           "synchronization loop labelling",
                           true, true);
