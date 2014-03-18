extern crate rustc;
use rustc::lib::llvm::{UseRef, ValueRef};

extern {
    pub fn LLVMShimReplaceUse(use_: UseRef, repl: ValueRef);
}
