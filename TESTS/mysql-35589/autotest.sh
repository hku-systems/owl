#!/bin/bash
set -x

if [ ! $# -eq 2 ]; then
  echo "Usage: $0 mysql-35589 race_report.txt"
  exit 1
fi

# The command will be called at top level of build folder
TEST_DIR='TESTS/mysql-35589'
CONANAL_DIR='lib/ConAnal'
DOL_DIR='lib/DOL'
CDG_DIR='lib/CDG'
BITCODE_DIR="$CONANAL_ROOT/build/TESTS/${1}"

cd $BITCODE_DIR
# Only the standard output info will be printed
opt -load ../../$DOL_DIR/libDOL.so --danFuncFile danMemFuncLists.txt -load ../../$CDG_DIR/libCDG.so -load ../../$CONANAL_DIR/libConAnalysis.so -ConAnalysis ../../../TESTS/${1}/${1}.bc --ptrderef --danfunc --raceReport ${2} > /dev/null
# ConAnalysis Debug info will be enabled
#opt -debug-only=con-analysis -load ../../$DOL_DIR/libDOL.so --danFuncFile danMemFuncLists.txt -load ../../$CDG_DIR/libCDG.so -load ../../$CONANAL_DIR/libConAnalysis.so -ConAnalysis ../../../TESTS/${1}/${1}.bc --ptrderef --danfunc --raceReport ${2} > /dev/null

echo "ConAnalysis Done!"
