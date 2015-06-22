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
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Self::Dis>, Box<dis::CreateDisError>> {
        let mut optgrps = vec![
            getopts::optopt("", "triple",      "triple to pass to LLVM", ""),
            getopts::optopt("", "cpu",         "CPU name to pass to LLVM", ""),
            getopts::optopt("", "features",    "feature string to pass to LLVM", ""),

        ];
        let m = try!(util::do_getopts_or_usage(args, 0, 0, &mut optgrps).map_err(|e| box );
        .map_err(
        
    }
}
pub fn something() {
    unsafe {

        al::LLVMInitializeAllTargetInfos();
        al::LLVMInitializeAllTargetMCs();
        al::LLVMInitializeAllDisassemblers();
    }
}
