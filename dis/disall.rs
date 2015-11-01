extern crate dis;
extern crate llvmdis;
use std::marker::PhantomData;

pub static ALL_FAMILIES: &'static [&'static dis::DisassemblerFamily] = &[
    &dis::DisassemblerFamilyImpl::<llvmdis::LLVMDisassembler>(PhantomData) as &dis::DisassemblerFamily,
];
