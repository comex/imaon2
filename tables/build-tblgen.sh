#!/bin/bash
set -xe
LLVM="$1"
rm -rf tblgen-build
mkdir tblgen-build
cd tblgen-build
"$LLVM/configure" --enable-optimized
make -j4 BUILD_DIRS_ONLY=1
cp -a Release+Asserts/bin/llvm-tblgen ../
cd ..
rm -rf tblgen-build
