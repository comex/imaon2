#![feature(box_syntax)]
extern crate exec;
extern crate util;
extern crate autollvm as al;
extern crate dis;
extern crate bsdlike_getopts as getopts;
use exec::arch;

use std::ffi::CString;

use std::sync::{Once, ONCE_INIT};
static LLVM_INIT_ONCE: Once = ONCE_INIT;

pub struct LLVMDisassembler {
    dcr: al::LLVMDisasmContextRef,
}

impl LLVMDisassembler {
    pub fn new(arch: arch::Arch, triple: Option<&str>, cpu: Option<&str>, features: Option<&str>) -> Option<Self> {
        LLVM_INIT_ONCE.call_once(|| {
            unsafe {
                al::LLVMInitializeAllTargetInfos();
                al::LLVMInitializeAllTargetMCs();
                al::LLVMInitializeAllDisassemblers();
            }
        });

        let triple = triple.unwrap_or_else(|| {
            "arm-apple-darwin9"
        });
        let triple_cs = CString::new(triple).unwrap();
        let cpu_cs = CString::new(cpu.unwrap_or("")).unwrap();
        let features_cs = CString::new(features.unwrap_or("")).unwrap();

        let dcr = unsafe {
            al::LLVMCreateDisasmCPUFeatures(
                triple_cs.as_ptr(),
                cpu_cs.as_ptr(),
                features_cs.as_ptr(),
                std::ptr::null_mut(),
                0,
                None,
                None,
            )
        };

        if dcr == std::ptr::null_mut() {
            return None;
        }

        Some(LLVMDisassembler { dcr: dcr })
    }
}


impl dis::Disassembler for LLVMDisassembler {
}

pub struct LLVMDisassemblerFamily;
impl dis::DisassemblerFamily for LLVMDisassemblerFamily {
    type Dis = LLVMDisassembler;
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Self::Dis>, Box<dis::CreateDisError>> {
        let mut optgrps = vec![
            getopts::optopt("", "triple",      "triple to pass to LLVM", ""),
            getopts::optopt("", "cpu",         "CPU name to pass to LLVM", ""),
            getopts::optopt("", "features",    "feature string to pass to LLVM", ""),

        ];
        let m = try!(util::do_getopts_or_usage(args, "llvmdis ...", 0, 0, &mut optgrps).map_err(|e| box dis::CreateDisError::InvalidArgs(e)));

        let triple = m.opt_str("triple");
        let cpu = m.opt_str("cpu");
        let features = m.opt_str("features");

        match LLVMDisassembler::new(arch, triple.as_ref().map(|x| &**x), cpu.as_ref().map(|x| &**x), features.as_ref().map(|x| &**x)) {
            Some(d) => Ok(box d),
            None => Err(box dis::CreateDisError::Other(box util::GenericError("LLVMCreateDisasmCPUFeatures failed".to_owned()))),
        }
    }
}
