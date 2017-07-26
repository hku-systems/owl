#!/bin/bash
set -x

if [ ! $# -eq 1 ]; then
  echo -e "Please input the argument"
  exit -1
fi

OBJECT_DIR=./lib/ConAnal
BITCODE_DIR=./TESTS/${1}

cd ${BITCODE_DIR} && opt -mem2reg ${1}.bc -o ${1}.mem2reg && mv ${1}.mem2reg ${1}.bc && 
 opt -load ../../lib/ConAnal/libConAnalysis.so -ConAnalysis ${1}.bc 2>&1 | grep '^\['
