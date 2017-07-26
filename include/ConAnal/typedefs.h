#ifndef INCLUDE_CONANAL_TYPEDEFS_H_
#define INCLUDE_CONANAL_TYPEDEFS_H_

#include <list>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"

using namespace llvm;

#define GEP_THREE_OP 0
#define GEP_TWO_OP 1

namespace ConAnal {
/* <functionName, fileName, lineNum> */
typedef std::tuple<std::string, std::string, uint32_t> FuncFileLine;
typedef std::pair<std::string, uint32_t> FileLine;
typedef std::pair<Function *, Instruction *> FuncInst;
typedef std::list<FuncFileLine> FuncFileLineList;
typedef std::list<Instruction *> InstructionList;
typedef std::list<std::pair<Function *, Instruction *>> FuncInstList;
typedef std::set<std::string> StrSet;
typedef std::set<Function *> FuncSet;
typedef std::map<uint32_t, Value *> CorruptedArgs;
typedef std::map<BasicBlock *, std::set<BasicBlock *>> BB2SetMap;
typedef std::map<FileLine, bool> FileLineMap;
typedef std::map<Instruction *, uint64_t> Inst2IntMap;
typedef std::map<std::pair<std::string, uint32_t>, InstructionList> FileLine2InstListMap;

typedef struct {
  char fileName[200];
  char funcName[100];
  int lineNum;
  Instruction * danOpI;
} part2_input;
/// Stores the index info of GEP
typedef union PtrIdxUnion {
  std::pair<Value *, Value *> array_idx;
  Value * idx;
} GepIdxUnion;
/// idxType: GEP_THREE_OP, GEP_TWO_OP
typedef struct PtrIdxStruct {
  uint16_t idxType;
  GepIdxUnion gepIdx;
} GepIdxStruct;
/// Stores the corrupted variable set size for each enter & exit
typedef struct EnterExitVal {
  uint32_t enterVal;
  uint32_t exitVal;
} EnterExitVal;
}// namespace ConAnal


#endif  // INCLUDE_CONANAL_TYPEDEFS_H_
