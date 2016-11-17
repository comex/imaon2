extern crate dis;
#[cfg(feature = "use_llvm")]
extern crate dis_llvmdis as llvmdis;
#[cfg(feature = "use_llvm")]
extern crate dis_llvm_debug as dis_llvm_debug;
use std::marker::PhantomData;
use dis::{DisassemblerFamily, DisassemblerFamilyImpl};

pub static ALL_FAMILIES: &'static [&'static dis::DisassemblerFamily] = &[
    #[cfg(feature = "use_llvm")]
    (&DisassemblerFamilyImpl::<llvmdis::LLVMDisassembler>(PhantomData) as &DisassemblerFamily),
    #[cfg(feature = "use_llvm")]
    (&DisassemblerFamilyImpl::<dis_llvm_debug::LLVMDebugDisassembler>(PhantomData) as &DisassemblerFamily),
];
