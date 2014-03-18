#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm-c/Core.h"
using namespace llvm;

extern "C" void LLVMShimReplaceUse(LLVMUseRef use, LLVMValueRef replacement) {
    unwrap(use)->set(unwrap(replacement));
}
