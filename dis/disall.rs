extern crate dis;
#[cfg(use_llvm)]
extern crate llvmdis;
#[cfg(use_llvm)]
extern crate llvm_debug_dis;
use std::marker::PhantomData;
use dis::{DisassemblerFamily, DisassemblerFamilyImpl};

pub static ALL_FAMILIES: &'static [&'static dis::DisassemblerFamily] = &[
    #[cfg(use_llvm)]
    (&DisassemblerFamilyImpl::<llvmdis::LLVMDisassembler>(PhantomData) as &DisassemblerFamily),
    #[cfg(use_llvm)]
    (&DisassemblerFamilyImpl::<llvm_debug_dis::LLVMDebugDisassembler>(PhantomData) as &DisassemblerFamily),
];
