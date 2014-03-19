// This file is public domain.

#define protected public // lol
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm-c/Core.h"
using namespace llvm;

struct Slice {
    void *data;
    unsigned length;
};

extern "C" void LLVMShimReplaceUse(LLVMUseRef use, LLVMValueRef replacement) {
    unwrap(use)->set(unwrap(replacement));
}

extern "C" Slice LLVMShimGetOperandList(LLVMValueRef val) {
    User *v = cast<User>(unwrap(val));
    return Slice { v->op_begin(), (unsigned) (v->op_end() - v->op_begin()) };
}

extern "C" unsigned LLVMShimGetValueID(LLVMValueRef val) {
    return unwrap(val)->getValueID();
}

extern "C" unsigned LLVMShimGetSubclassData(LLVMValueRef val) {
    return unwrap(val)->getSubclassDataFromValue();
}

extern "C" unsigned LLVMShimGetSubclassOptionalData(LLVMValueRef val) {
    return unwrap(val)->getRawSubclassOptionalData();
}
