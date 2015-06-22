extern crate util;
extern crate autollvm as al;
extern crate dis;
extern crate bsdlike_getopts as getopts;

use std::sync::{Once, ONCE_INIT};
static s_llvm_init_once: Once = ONCE_INIT;

struct LLVMDisassembler;
impl dis::Disassembler for LLVMDisassembler {
}

struct LLVMDisassemblerFamily;
impl dis::DisassemblerFamily for LLVMDisassemblerFamily {
    type Dis = LLVMDisassembler;
    fn create_disassembler(&self, arch: arch::Arch, args: &[&str]) -> Result<Box<Self::Dis>, Box<Error>> {
        let mut optgrps = vec![
            getopts::

        ];
        util::do_getopts
        
    }
}
pub fn something() {
    unsafe {

        al::LLVMInitializeAllTargetInfos();
        al::LLVMInitializeAllTargetMCs();
        al::LLVMInitializeAllDisassemblers();
    }
}
