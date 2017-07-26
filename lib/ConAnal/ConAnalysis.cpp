//===---------------------------- ConAnalysis.cpp -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Copyright (c) 2016 Columbia University. All rights reserved.
// This file is a skeleton of an implementation for the ConAnalysis
// pass of Columbia University in the City of New York. For this program,
// our goal is to find those particular concurrency bugs that will make
// the system vulnerable to malicious actions.
//
//===----------------------------------------------------------------------===//
#define DEBUG_TYPE "con-analysis"

#include "ConAnal/ConAnalysis.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <sstream>
#include <stack>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace llvm;
using namespace ConAnal;

static cl::opt<bool> PtrDerefCheck("ptrderef",
    cl::desc("Enable ptr deref check"));
static cl::opt<bool> DanFuncCheck("danfunc",
    cl::desc("do dangerous function check"));
static cl::opt<std::string> CorruptedVariable("corruptVar",
    cl::init("0"),
    cl::desc("Manually input the corrupted variable"));
static cl::opt<std::string> RaceReportInput("raceReport",
    cl::desc("race report input file"), cl::Required);

void ConAnalysis::clearClassDataMember() {
  corruptedIR_.clear();
  finishedVars_.clear();
  corruptedPtr_.clear();
  orderedcorruptedIR_.clear();
  callStack_.clear();
  callStackHead_.clear();
  callStackBody_.clear();
  corruptedMap_.clear();
  funcEnterExitValMap_.clear();
}

const Function* ConAnalysis::findEnclosingFunc(const Value* V) {
  if (const Argument* Arg = dyn_cast<Argument>(V)) {
    return Arg->getParent();
  }
  if (const Instruction* I = dyn_cast<Instruction>(V)) {
    return I->getParent()->getParent();
  }
  return NULL;
}

const MDNode* ConAnalysis::findVar(const Value* V, const Function* F) {
  for (const_inst_iterator Iter = inst_begin(F), End = inst_end(F);
      Iter != End; ++Iter) {
    const Instruction * I = &*Iter;
    if (const DbgDeclareInst* DbgDeclare = dyn_cast<DbgDeclareInst>(I)) {
      if (DbgDeclare->getAddress() == V)
        return DbgDeclare->getVariable();
    } else if (const DbgValueInst* DbgValue = dyn_cast<DbgValueInst>(I)) {
      if (DbgValue->getValue() == V)
        return DbgValue->getVariable();
    }
  }
  return NULL;
}

StringRef ConAnalysis::getOriginalName(const Value* V) {
  const Function* F = findEnclosingFunc(V);
  if (!F)
    return V->getName();
  const MDNode* Var = findVar(V, F);
  if (!Var)
    return "tmp";
  return DIVariable(Var).getName();
}

void ConAnalysis::printList(std::list<Value *> &inputset) {
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  errs() << "[ ";
  for (auto& iter : inputset) {
    if (isa<Instruction>(iter)) {
      errs() << ins2int[cast<Instruction>(iter)] << " ";
    } else {
      errs() << iter->getName() << " ";
    }
  }
  errs() << "]\n";
  for (auto& iter : inputset) {
    I2I->printMappedInstruction(iter);
  }
}

void ConAnalysis::printSet(std::set<BasicBlock *> &inputset) {
  std::list<std::string> tmplist;
  for (auto& it : inputset) {
    tmplist.push_back(it->getName().str());
  }
  tmplist.sort();
  for (auto& it : tmplist) {
    errs() << it << " ";
  }
}

bool ConAnalysis::add2CrptList(Value * crptVal) {
  if (!corruptedIR_.count(&*crptVal)) {
    orderedcorruptedIR_.push_back(&*crptVal);
    corruptedIR_.insert(&*crptVal);
    return true;
  }
  return false;
}

void ConAnalysis::parseInput(std::string inputfile, FuncFileLineList &csinput) {
  std::ifstream ifs(inputfile);
  if (!ifs.is_open()) {
    errs() << "Runtime Error: Couldn't find " << inputfile << "\n";
    errs() << "Please check the file path\n";
    abort();
  }
  std::string line;
  while (std::getline(ifs, line)) {
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
    line.clear();
  }
}

void ConAnalysis::initializeCallStack(FuncFileLineList &csinput) {
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  FileLine2InstListMap & sourcetoIRmap = I2I->getFileLine2InstListMap();
  errs() << "---- Replaying Call Stack Input ----\n";
  for (auto cs_it = csinput.begin(); cs_it != csinput.end(); ++cs_it) {
    std::string filename = std::get<1>(*cs_it);
    uint32_t line = std::get<2>(*cs_it);
    errs() << "(" << filename << " : " << line << ")\n";
    auto mapitr = sourcetoIRmap.find(std::make_pair(filename, line));
    if (mapitr == sourcetoIRmap.end()) {
      // It's tolerable if some instructions in certain functions are missing
      // due to some library linking issue. However, it doesn't make any 
      // sense if the corrupted variable instruction is missing.
      errs() << "ERROR: <" << std::get<1>(*cs_it) << " "
             << std::get<2>(*cs_it) << ">"
             << " sourcetoIRmap look up failed.\n";
      if (cs_it == csinput.begin()) {
        errs() << "Fisrt instruction failed, aborting...\n";
        abort();
      }
      continue;
    }
    std::list<Instruction *>& insList = mapitr->second;
    if (insList.begin() == insList.end()) {
      errs() << "ERROR: <" << std::get<1>(*cs_it) << " "
             << std::get<2>(*cs_it) << ">"
             << " No matching instructions.\n";
      abort();
    }
    bool firstInsIsCall = false;
    for (auto listit = insList.begin(); listit != insList.end(); ++listit) {
      // This makes sure that other than the first one, all the other callstack
      // layers are filled with call instruction.
      if (isa<GetElementPtrInst>(*listit)) {
        if (cs_it != csinput.begin() || firstInsIsCall)
          continue;
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
        callStackHead_.push_back(std::make_pair(&*func, *listit));
        finishedVars_.insert(*listit);
        errs() << "-------------------------\n";
        (*listit)->print(errs());errs() << "\n"; 
        errs() << "-------------------------\n";
      } else if (isa<CallInst>(*listit) || isa<InvokeInst>(*listit)) {
        CallSite cs(*listit);
        Function * callee = cs.getCalledFunction();
        if (callee != NULL) {
          // Skip llvm intrinsic function
          if (callee->isIntrinsic())
            continue;
        }
        if (cs_it == csinput.begin() && listit == insList.begin()) {
          errs() << "Warning: Call Inst %" << ins2int[*listit]
                 << " is the first one in the call stack!\n";
          firstInsIsCall = true;
          continue;
        }
        Function * func = &*(((*listit)->getParent())->getParent());
        DEBUG((*listit)->print(errs()); errs() << "\n";);
        DEBUG(errs() << func->getName() << " contains the above ins\n");
        callStackBody_.push_back(std::make_pair(&*func, *listit));
        break;
      } else {
        if (cs_it != csinput.begin() || firstInsIsCall)
          continue;
        Function * func = &*(((*listit)->getParent())->getParent());
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
        if (*listit != insList.back() || !callStackHead_.empty()) {
          if (flagAlreadyAddedVar || 
              (!hasGlobal && isa<LoadInst>(*listit)) || 
              (!isBitCast && !isPointer && !isa<LoadInst>(*listit)))
            continue;
        }
        callStackHead_.push_back(std::make_pair(&*func, *listit));
        finishedVars_.insert(*listit);
        errs() << "-------------------------\n";
        (*listit)->print(errs());errs() << "\n";
        errs() << "-------------------------\n";
      }
    }
    DEBUG(errs() << "\n");
  }
  errs() << "\n";
  // Overwrite callStackHead if there is manual input
  uint64_t var = std::stoi(CorruptedVariable);
  if (var != 0) {
    for (auto it = ins2int.begin(); it != ins2int.end(); ++it) {
      if (it->second == var) {
        Function * func = &*(((it->first)->getParent())->getParent());
        callStackHead_.clear();
        callStackHead_.push_back(std::make_pair(&*func, it->first));
        (it->first)->print(errs());errs() << "\n";
        errs() << "Corrupted variable is manually inputed."
               << "The value is " << var << "\n";
        break;
      }
    }
  }
  return;
}

bool ConAnalysis::runOnModule(Module &M) {
  clearClassDataMember();
  I2I = &getAnalysis<Inst2Int>();
  CDGs = &getAnalysis<ControlDependenceGraphs>();
  DOL &labels = getAnalysis<DOL>();
  FuncFileLineList raceReport;
  errs() << "---------------------------------------\n";
  errs() << "       Start ConAnalysis Pass          \n";
  errs() << "---------------------------------------\n";
#ifdef DEBUG_TYPE
  I2I->printMap(M);
#endif
  parseInput(RaceReportInput, raceReport);
  initializeCallStack(raceReport);
  getCorruptedIRs(M, labels);
  return false;
}

bool ConAnalysis::getCorruptedIRs(Module &M, DOL &labels) {
  DEBUG(errs() << "---- Getting Corrupted LLVM IRs ----\n");
  assert(callStackHead_.size() != 0 && "Error: callStackHead_ is empty!");
  for (auto cs_itr : callStackHead_) {
    // Each time, we create a call stack using one element from callStackHead
    // and the whole callStackBody
    callStack_.clear();
    callStack_ = callStackBody_;
    callStack_.push_front(cs_itr);
    orderedcorruptedIR_.clear();
    corruptedIR_.clear();
    corruptedPtr_.clear();
    funcEnterExitValMap_.clear();

    while (!callStack_.empty()) {
      auto& loc = callStack_.front();
      CorruptedArgs coparams;
      DEBUG(errs() << "Original Callstack: Go into \"" << loc.first->getName()
             << "\"\n");
      bool addFuncRet = false;
      addFuncRet = intraDataflowAnalysis(loc.first, loc.second, coparams,
          false, labels);
      DEBUG(errs() << "Callstack POP " << loc.first->getName() << "\n");
      callStack_.pop_front();
      if (addFuncRet && !callStack_.empty()) {
        auto& loc = callStack_.front();
        add2CrptList(&*loc.second);
      }
    }
    DEBUG(errs() << "\n");
    errs() << "---- Part 1: Dataflow Result ---- \n";
    printList(orderedcorruptedIR_);
    errs() << "\n";

    std::set<Function *> corruptedIRFuncSet;
    for (auto IR = corruptedIR_.begin(); IR != corruptedIR_.end(); IR++) {
      if (!isa<Instruction> (*IR))
        continue;
      Function * func = dyn_cast<Instruction>(*IR)->getParent()->getParent();
      corruptedIRFuncSet.insert(func);
    }

    if (PtrDerefCheck) {
      errs() << "*********************************************************\n";
      errs() << "     Pointer Dereference Analysis Result                 \n";
      errs() << "   # of static pointer deference statements: "
        << labels.danPtrOps_.size() << "\n";
      uint32_t vulNum = printInterCtrlDepResult(interCtrlDepPtr_);
      vulNum += getDominators(M, labels.danPtrOps_, corruptedIRFuncSet);
      errs() << "\n   # of detected potential vulnerabilities: "
        << vulNum << "\n";
      errs() << "*********************************************************\n";
      errs() << "\n";
    }
    if (DanFuncCheck) {
      errs() << "*********************************************************\n";
      errs() << "     Dangerous Function Analysis Result                  \n";
      errs() << "   # of static dangerous function statements: "
        << labels.danFuncs_.size() << "\n";
      uint32_t vulNum = printInterCtrlDepResult(interCtrlDepFunc_);
      vulNum += getDominators(M, labels.danFuncOps_, corruptedIRFuncSet);
      errs() << "\n   # of detected potential vulnerabilities: "
        << vulNum << "\n";
      errs() << "*********************************************************\n";
      errs() << "\n";
    }
  }
  return false;
}

bool ConAnalysis::intraDataflowAnalysis(Function * F, Instruction * ins,
                                        CorruptedArgs &corruptedparams,
                                        bool ctrlDep, DOL &labels) {
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  bool rv = false;
  bool ctrlDepWithinCurFunc = false;
  std::list<Instruction *> localCorruptedBr_;
  auto I = inst_begin(F);
  if (ins != nullptr) {
    for (; I != inst_end(F); ++I) {
      if (&*I == &*ins) {
        // Skip the previous call instruction after returned.
        if (isa<CallInst>(&*I)) {
          ++I;
        } else {
          if (!corruptedIR_.count(&*I)) {
            orderedcorruptedIR_.push_back(&*I);
            corruptedIR_.insert(&*I);
            DEBUG(errs() << "Adding corrupted variable: ");
            DEBUG(errs() << "%" << ins2int[&*I] << "\n");
            if (isa<GetElementPtrInst>(&*I)) {
              int op_num = I->getNumOperands();
              GepIdxStruct * gep_idx = reinterpret_cast<GepIdxStruct *>
                  (malloc(sizeof(GepIdxStruct)));
              if (op_num == 3) {
                gep_idx->idxType = GEP_THREE_OP;
                gep_idx->gepIdx.array_idx = std::make_pair(I->getOperand(1),
                                                           I->getOperand(2));
              } else if (op_num == 2) {
                gep_idx->idxType = GEP_TWO_OP;
                gep_idx->gepIdx.idx = I->getOperand(1);
              } else {
                errs() << "Error: Cannot parse GetElementPtrInst\n";
                abort();
              }
              Value * v = I->getOperand(0);
              DEBUG(errs() << "Adding " << &*v << " to crptPtr list\n");
              corruptedPtr_[v].push_back(gep_idx);
            }
            rv = true;
          }
        }
        break;
      }
    }
    assert(I != inst_end(F) && "Couldn't find callstack instruction.");
  }

  // Obtain the Control Dependence Graph of the current function
  bool noGraph = false;
  if (CDGs->graphs.find(F) == CDGs->graphs.end())
    noGraph = true;
  ControlDependenceGraphBase &cdgBase = (*CDGs)[F];

  if (I == inst_end(F)) {
    DEBUG(errs() << "Couldn't obtain the source code of function \""
        << F->getName() << "\"\n");
  }
  // Handle the corrupted var passed in as function parameters
  uint32_t op_i = 0;
  for (Function::arg_iterator args = F->arg_begin();
       args != F->arg_end(); ++args, ++op_i) {
    if (corruptedparams.count(op_i)) {
      if (I == inst_end(F))
        return true;
      Value * calleeArgs = &*args;
      DEBUG(errs() << "Corrupted Arg: " << calleeArgs->getName() << "\n");
      if (corruptedIR_.count(corruptedparams[op_i])
          && !corruptedIR_.count(calleeArgs)) {
        DEBUG(errs() << "Add " << calleeArgs->getName() << " to list\n");
        orderedcorruptedIR_.push_back(calleeArgs);
        corruptedIR_.insert(calleeArgs);
      }
      Value * callerArgs = corruptedparams[op_i];
      if (corruptedPtr_.count(&*callerArgs)) {
        DEBUG(errs() << "Add arg " << &*calleeArgs << " to crptPtr list\n");
        corruptedPtr_[&*calleeArgs] = corruptedPtr_[&*callerArgs];
      }
    }
  }
  // Forward taint analysis on each instruction
  for (; I != inst_end(F); ++I) {
    // Check if the current instruction is control dependent on any corrupted
    // intra-procedural branch instruction
    bool influence = false;
    for (auto brIns : localCorruptedBr_) {
      if (noGraph)
        break;
      BasicBlock * brBB = brIns->getParent();
      BasicBlock * insBB = I->getParent();
      if (cdgBase.influences(brBB, insBB)) {
        ctrlDepWithinCurFunc = true;
        influence = true;
        break;
      }
    }
    
    if (!influence)
      ctrlDepWithinCurFunc = false;

    // Check if this instruction is a dangerous operation and if the cross
    // function ctrl dep flag is on or it's dependent on a local corrupted
    // branch.
    if (MDNode *N = I->getMetadata("dbg")) {
      DILocation Loc(N);
      std::string fileName = Loc.getFilename().str();
      fileName = fileName.substr(fileName.find_last_of("\\/") + 1);
      uint32_t lineNum = Loc.getLineNumber();
      FileLine opMapEntry = std::make_pair(fileName, lineNum);

      if (ctrlDep && !ctrlDepWithinCurFunc) {
        // Do a intersection between callins & brIns.
        // Then store the results in a list
        if (labels.danPtrOpsMap_.count(opMapEntry) != 0) {
          std::list<Value *> ctrlDepBrs;
          for (auto call : corruptedCallIns_) {
            BasicBlock * callBB = call->getParent();
            for (auto br : corruptedBr_) {
              BasicBlock * brBB = br->getParent();
              if (callBB->getParent() != brBB->getParent())
                continue;
              if (CDGs->graphs.find(callBB->getParent()) != CDGs->graphs.end()) {
                ControlDependenceGraphBase &cdg = (*CDGs)[callBB->getParent()];
                if (cdg.influences(brBB, callBB)) {
                  bool found = (std::find(ctrlDepBrs.begin(),
                    ctrlDepBrs.end(), br) != ctrlDepBrs.end());
                  if (!found)
                    ctrlDepBrs.push_back(br);
                }
              }
            }
          }
          interCtrlDepPtr_[opMapEntry] = ctrlDepBrs;
        } else if (labels.danFuncOpsMap_.count(opMapEntry) != 0) {
          std::list<Value *> ctrlDepBrs;
          for (auto call : corruptedCallIns_) {
            BasicBlock * callBB = call->getParent();
            for (auto br : corruptedBr_) {
              BasicBlock * brBB = br->getParent();
              if (callBB->getParent() != brBB->getParent())
                continue;
              if (CDGs->graphs.find(callBB->getParent()) != CDGs->graphs.end()) {
              ControlDependenceGraphBase &cdg = (*CDGs)[callBB->getParent()];
                if (cdg.influences(brBB, callBB)) {
                  bool found = (std::find(ctrlDepBrs.begin(),
                    ctrlDepBrs.end(), br) != ctrlDepBrs.end());
                  if (!found)
                    ctrlDepBrs.push_back(br);
                }
              }
            }
          }
          interCtrlDepFunc_[opMapEntry] = ctrlDepBrs;
        } 
      }
    }

    if (isa<CallInst>(&*I)) {
      CallSite cs(&*I);
      Function * callee = cs.getCalledFunction();
      if (!callee) {
        DEBUG(errs() << "Couldn't get callee for instruction ");
        DEBUG(I->print(errs()); errs() << "\n");
        continue;
      }
      // Skip all the llvm intrinsic function
      if (callee->isIntrinsic())
        continue;
      std::string fnname = callee->getName().str();
      // Check for cycles
      bool cycle_flag = false;
      for (auto& csit : callStack_) {
        if ((std::get<0>(csit))->getName().str().compare(
                (callee->getName()).str()) == 0) {
          cycle_flag = true;
          break;
        }
      }
      if (cycle_flag) continue;
      CorruptedArgs coparams;
      bool paramsCorrupted = false;
      // Iterate through all the parameters to find the corrupted ones
      for (uint32_t op_i = 0, op_num = I->getNumOperands(); op_i < op_num;
           op_i++) {
        Value * v = I->getOperand(op_i);
        if (isa<Instruction>(v)) {
          if (corruptedIR_.count(v) || corruptedPtr_.count(v)) {
            paramsCorrupted = true;
            DEBUG(errs() << "Param No." << op_i << " %"
            << ins2int[dyn_cast<Instruction>(v)] << " contains corruption.\n");
            coparams[op_i] = &*v;
          }
        }
      }
      // Notice: Here, we relax the contraint of our data flow analysis a
      // little bit. If the arguments of a call instruction is corrupted and
      // we couldn't obtain its function body(external function), we'll treat
      // the return value of the call instruction as corrupted.
      if (callee->begin() == callee->end() && paramsCorrupted) {
        add2CrptList(&*I);
        continue;
      }
      if (funcEnterExitValMap_.count(callee) != 0) {
        EnterExitVal funcVal = funcEnterExitValMap_[callee];
        if (funcVal.enterVal == funcVal.exitVal) {
          if (funcEnterExitValMap_[callee].enterVal < corruptedIR_.size()) {
            funcEnterExitValMap_[callee].enterVal = corruptedIR_.size();
          } else if (funcEnterExitValMap_[callee].enterVal ==
              corruptedIR_.size()) {
            DEBUG(errs() << "Skip function " << fnname << "\n");
            continue;
          }
        }
      } else {
        funcEnterExitValMap_[callee].enterVal = corruptedIR_.size();
      }
      DEBUG(errs() << "\"" << F->getName() << "\"" << " calls "
             << "\"" << callee->getName() << "\"\n");
      DEBUG(errs() << "Callstack PUSH " << callee->getName() << "\n");
      callStack_.push_front(std::make_pair(callee, nullptr));
      bool addFuncRet = false;
      // If any of the control dependent indicator is on, we'll pass it to the
      // callee function.
      bool flag = false;
      if (ctrlDep || ctrlDepWithinCurFunc) {
        bool found = (std::find(corruptedCallIns_.begin(),
              corruptedCallIns_.end(),
              &*I) != corruptedCallIns_.end());
        if (!found)
          corruptedCallIns_.push_back(&*I);
        flag = true;
      }
      addFuncRet = intraDataflowAnalysis(callee, nullptr, coparams,
          flag, labels);
      if (addFuncRet) {
        add2CrptList(&*I);
      }
      DEBUG(errs() << "Callstack POP " << callStack_.front().first->getName() 
          << "\n");
      funcEnterExitValMap_[callee].exitVal = corruptedIR_.size();
      callStack_.pop_front();
    } else if (isa<GetElementPtrInst>(&*I)) {
      int op_ii = I->getNumOperands();
      if (corruptedPtr_.count(I->getOperand(0))) {
        auto coPtrList = corruptedPtr_[I->getOperand(0)];
        if (op_ii == 2) {
          Value * gepIdx = I->getOperand(1);
          for (auto it : coPtrList) {
            if (it->idxType == GEP_TWO_OP) {
              if (it->gepIdx.idx == gepIdx) {
                DEBUG(errs() << "Add %" << ins2int[&*I]<< " to crpt list\n");
                add2CrptList(&*I);
              }
            }
          }
        } else if (op_ii == 3) {
          auto gepIdxPair = std::make_pair(I->getOperand(1), I->getOperand(2));
          for (auto it : coPtrList) {
            if (it->idxType == GEP_THREE_OP) {
              if (it->gepIdx.array_idx == gepIdxPair) {
                DEBUG(errs() << "Add %" << ins2int[&*I]<< " to crpt list\n");
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
            DEBUG(errs() << "Add %" << ins2int[&*I] << " to crpt list\n");
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
              bool found = (std::find(corruptedBr_.begin(),
                corruptedBr_.end(),
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

uint32_t ConAnalysis::printInterCtrlDepResult(
    std::map<FileLine, std::list<Value *>> resultMap) {
  
  for (auto res : resultMap) {
    std::string fileName = std::get<0>(res.first);
    uint32_t lineNum = std::get<1>(res.first);
    errs() << "\n---- Part 2: Cross Function Ctrl Dependent ----\n";
    printList(res.second);
    errs() << "Dangerous Operation Location: " << "("
      << fileName.substr(fileName.find_last_of("\\/") + 1) << ":"
      << lineNum << ")\n";
  }
  return resultMap.size(); 
}

uint32_t ConAnalysis::getDominators(Module &M, FuncFileLineList &danOps,
    std::set<Function *> &corruptedIRFuncSet) {
  Inst2IntMap & ins2int = I2I->getInst2IntMap();
  FileLine2InstListMap & sourcetoIRmap = I2I->getFileLine2InstListMap();
  uint32_t rv = 0;
  // ffl means FuncFileLine
  for (auto fflTuple = danOps.begin(); fflTuple != danOps.end(); fflTuple++) {
    BB2SetMap dominators;
    std::list<Value *> dominatorSubset;
    std::string funcName = std::get<0>(*fflTuple);
    std::string fileName = std::get<1>(*fflTuple);
    uint32_t line = std::get<2>(*fflTuple);
    InstructionList iList = sourcetoIRmap[std::make_pair(fileName, line)];
    Function *F = iList.front()->getParent()->getParent();
    if (!corruptedIRFuncSet.count(F)) {
      continue;
    }
    assert(F != NULL && "Couldn't obtain Function * for dangerous op");
    if (F->getName().str().compare(std::get<0>(*fflTuple)) == 0) {
      if (dominatorMap_.count(F) == 0) {
        computeDominators(*F, dominators);
        dominatorMap_[F] = dominators;
      } else {
        dominators = dominatorMap_[F];
      }
      //printDominators(*F, dominators);
      std::string filename = std::get<1>(*fflTuple);
      uint32_t line = std::get<2>(*fflTuple);
      // filename, lineNum -> Instruction *
      auto mapitr = sourcetoIRmap.find(std::make_pair(filename, line));
      if (mapitr == sourcetoIRmap.end()) {
        errs() << "ERROR: <" << std::get<0>(*fflTuple) << " "
               << std::get<2>(*fflTuple) << ">"
               << " sourcetoIRmap look up failed.\n";
        abort();
      }
      auto fileLinePair = std::make_pair(filename, line);
      Instruction * danOpI = sourcetoIRmap[fileLinePair].front();
      auto it = dominators[danOpI->getParent()].begin();
      auto it_end = dominators[danOpI->getParent()].end();
      bool corruptBranchFlag = false;
      for (; it != it_end; ++it) {
        for (auto i = (*it)->begin(); i != (*it)->end(); ++i) {
          if (isa<BranchInst>(&*i) && corruptedIR_.count(&*i)) {
            corruptBranchFlag = true;
          }
          dominatorSubset.push_back(&*i);
          if (&*i == danOpI)
            break;
        }
      }
      if (!corruptBranchFlag || !getFeasiblePath(M, dominatorSubset))
        continue;
      DEBUG(errs() << "Dangerous Operation Basic Block & Instruction\n");
      DEBUG(errs() << danOpI->getParent()->getName() << " & "
             << ins2int[&*danOpI] << "\n");
      if (MDNode *N = danOpI->getMetadata("dbg")) {
        DILocation Loc(N);
        std::string fileName = Loc.getFilename().str();
        errs() << "Function: " << F->getName().str() << "(...)"
            << " Location: " << "("
            << fileName.substr(fileName.find_last_of("\\/") + 1) << ":"
            << Loc.getLineNumber() << ")\n";
      }
      rv++;
    }
    //errs() << "---------------------------------------\n";
    //errs() << "         Dominator Result              \n";
    //errs() << "---------------------------------------\n";
    //printList(dominantfrontiers);
    //errs() << "\n";
  }
  return rv;
}

bool ConAnalysis::getFeasiblePath(Module &M, 
    std::list<Value *> &dominantfrontiers) {
  std::list<Value *> feasiblepath;
  for (auto& listitr : orderedcorruptedIR_) {
    for (auto& listitr2 : dominantfrontiers) {
      if (listitr == listitr2) {
        feasiblepath.push_back(listitr);
      }
    }
  }
  if (feasiblepath.empty())
    return false;
  errs() << "\n---- Part 3: Path Intersection ----\n";
  printList(feasiblepath);
  return true;
}

void ConAnalysis::computeDominators(Function &F, std::map<BasicBlock *,
                                    std::set<BasicBlock *>> & dominators) {
  std::vector<BasicBlock *> worklist;
  // For all the nodes but N0, initially set dom(N) = {all nodes}
  auto entry = F.begin();
  for (auto blk = F.begin(); blk != F.end(); blk++) {
    if (blk != F.begin()) {
      if (pred_begin(blk) != pred_end(blk)) {
        for (auto blk_p = F.begin(); blk_p != F.end(); ++blk_p) {
          dominators[&*blk].insert(&*blk_p);
        }
      } else {
        dominators[&*blk].insert(&*blk);
      }
    }
  }
  // dom(N0) = {N0} where N0 is the start node
  dominators[entry].insert(&*entry);
  // Push each node but N0 onto the worklist
  for (auto SI = succ_begin(entry), E = succ_end(entry); SI != E; ++SI) {
    worklist.push_back(*SI);
  }
  // Use the worklist algorithm to compute dominators
  while (!worklist.empty()) {
    BasicBlock * Z = worklist.front();
    worklist.erase(worklist.begin());
    std::set<BasicBlock *> intersects = dominators[*pred_begin(Z)];
    for (auto PI = pred_begin(Z), E = pred_end(Z);
        PI != E; ++PI) {
      std::set<BasicBlock *> newDoms;
      for (auto dom_it = dominators[*PI].begin(),
          dom_end = dominators[*PI].end();
          dom_it != dom_end; dom_it++) {
        if (intersects.count(*dom_it))
          newDoms.insert(*dom_it);
      }
      intersects = newDoms;
    }
    intersects.insert(Z);

    if (dominators[Z] != intersects) {
      dominators[Z] = intersects;
      for (auto SI = succ_begin(Z), E = succ_end(Z); SI != E; ++SI) {
        if (*SI == entry) {
          continue;
        } else if (std::find(worklist.begin(),
                            worklist.end(), *SI) == worklist.end()) {
          worklist.push_back(*SI);
        }
      }
    }
  }
}

void ConAnalysis::printDominators(Function &F, std::map<BasicBlock *,
                                  std::set<BasicBlock *>> & dominators) {
  errs() << "\nFUNCTION " << F.getName() << "\n";
  for (auto blk = F.begin(); blk != F.end(); ++blk) {
    errs() << "BASIC BLOCK " << blk->getName() << " DOM-Before: { ";
    dominators[&*blk].erase(&*blk);
    printSet(dominators[&*blk]);
    errs() << "}  DOM-After: { ";
    if (pred_begin(blk) != pred_end(blk) || blk == F.begin()) {
      dominators[&*blk].insert(&*blk);
    }
    printSet(dominators[&*blk]);
    errs() << "}\n";
  }
}

//**********************************************************************
// print (do not change this method)
//
// If this pass is run with -f -analyze, this method will be called
// after each call to runOnModule.
//**********************************************************************
void ConAnalysis::print(std::ostream &O, const Module *M) const {
    O << "This is Concurrency Bug Analysis.\n";
}

char ConAnalysis::ID = 0;

// register the ConAnalysis class:
//  - give it a command-line argument (ConAnalysis)
//  - a name ("Concurrency Bug Analysis")
//  - a flag saying that we don't modify the CFG
//  - a flag saying this is not an analysis pass
static RegisterPass<ConAnalysis> X("ConAnalysis",
                                   "concurrency bug analysis code",
                                    true, false);
