#!/bin/bash
set -x

if [ ! $# -eq 1 ]; then
  echo "Usage: $0 apache-21287"
  exit 1
fi

# The command will be called at top level of build folder
TEST_DIR='TESTS/apache-21287'
INST2INT_DIR='lib/Misc/Inst2Int'
BITCODE_DIR="$CONANAL_ROOT/build/TESTS/${1}"                                    

cd $BITCODE_DIR     
# Only the standard output info will be printed
opt -load ../../$INST2INT_DIR/libInst2Int.so -Inst2Int ../../../TESTS/${1}/${1}.bc > /dev/null
# ConAnalysis Debug info will be enabled
#opt -debug-only=inst2int -load ../../$INST2INT_DIR/libInst2Int.so -Inst2Int ../../../TESTS/${1}/${1}.bc > /dev/null
