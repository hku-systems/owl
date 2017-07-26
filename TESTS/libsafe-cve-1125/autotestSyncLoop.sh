#!/bin/bash
set -x

if [ ! $# -eq 2 ]; then
  echo "Usage: $0 libsafe-cve-1125 race_report.txt"
  exit 1
fi

# The command will be called at top level of build folder
TEST_DIR='TESTS/libsafe-cve-1125'
INST2INT_DIR='lib/Misc/Inst2Int'
CDG_DIR='lib/CDG'
SYNC_LOOP_DIR='lib/SyncLoop'
BITCODE_DIR="$CONANAL_ROOT/build/TESTS/${1}"

cd $BITCODE_DIR
# Only the standard output info will be printed
opt -load ../../$INST2INT_DIR/libInst2Int.so -load ../../$CDG_DIR/libCDG.so -load ../../$SYNC_LOOP_DIR/libSyncLoop.so -SyncLoop ../../../TESTS/${1}/${1}.bc --raceReport ${2}> /dev/null
# ConAnalysis Debug info will be enabled
#opt -debug-only=inst2int -load ../../$INST2INT_DIR/libInst2Int.so -Inst2Int ../../../TESTS/${1}/${1}.bc > /dev/null
