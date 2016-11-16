extern crate dis;
#[cfg(feature = "use_llvm")]
extern crate llvmdis;
#[cfg(feature = "use_llvm")]
extern crate llvm_debug_dis;
use std::marker::PhantomData;
use dis::{DisassemblerFamily, DisassemblerFamilyImpl};

pub static ALL_FAMILIES: &'static [&'static dis::DisassemblerFamily] = &[
    #[cfg(feature = "use_llvm")]
    (&DisassemblerFamilyImpl::<llvmdis::LLVMDisassembler>(PhantomData) as &DisassemblerFamily),
    #[cfg(feature = "use_llvm")]
    (&DisassemblerFamilyImpl::<llvm_debug_dis::LLVMDebugDisassembler>(PhantomData) as &DisassemblerFamily),
];
