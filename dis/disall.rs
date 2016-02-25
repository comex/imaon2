extern crate dis;
#[cfg(use_llvm)]
extern crate llvmdis;
use std::marker::PhantomData;

pub static ALL_FAMILIES: &'static [&'static dis::DisassemblerFamily] = &[
    #[cfg(use_llvm)]
    &dis::DisassemblerFamilyImpl::<llvmdis::LLVMDisassembler>(PhantomData) as &dis::DisassemblerFamily,
];
