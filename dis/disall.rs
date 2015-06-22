extern crate dis;
extern crate llvmdis;

static LDF: llvmdis::LLVMDisassemblerFamily = llvmdis::LLVMDisassemblerFamily;

pub fn all_families() -> Vec<&'static dis::DisassemblerFamilyBoxy> {
    vec![&LDF as &'static dis::DisassemblerFamilyBoxy]
}
