#!/bin/bash
set -xe
LLVM="$1"
rm -rf tblgen-build
mkdir tblgen-build
cd tblgen-build
cmake "$LLVM" -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=
make -j4 llvm-tblgen
cp -a bin/llvm-tblgen ../
cd ..
rm -rf tblgen-build
