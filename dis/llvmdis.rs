#![feature(box_syntax, libc)]
extern crate exec;
extern crate util;
extern crate autollvm as al;
extern crate dis;
extern crate libc;
extern crate bsdlike_getopts as getopts;
use exec::arch;
use exec::arch::ArchAndOptions;
use libc::c_char;

use std::ffi::CString;

use std::sync::{Once, ONCE_INIT};
static LLVM_INIT_ONCE: Once = ONCE_INIT;

pub struct LLVMDisassembler {
    arch: arch::ArchAndOptions,
    dcr: al::LLVMDisasmContextRef,
}

impl LLVMDisassembler {
    pub fn new(arch: arch::ArchAndOptions, triple: Option<&str>, cpu: Option<&str>, features: Option<&str>) -> Result<Self, util::GenericError> {
        LLVM_INIT_ONCE.call_once(|| {
            unsafe {
                al::LLVMInitializeAllTargetInfos();
                al::LLVMInitializeAllTargetMCs();
                al::LLVMInitializeAllDisassemblers();
            }
        });

        let triple = if let Some(t) = triple { t } else {
            match arch {
                ArchAndOptions::ARM(..) => "armv7",
                ArchAndOptions::X86_64(..) => "x86_64",
                ArchAndOptions::X86(..) => "x86",
                ArchAndOptions::UnknownArch(..) => return Err(util::GenericError("can't create disassembler for unknown arch".to_owned())),
                _ => panic!("todo"),
            }
        };
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
            return Err(util::GenericError("LLVMCreateDisasmCPUFeatures failed".to_owned()));
        }

        Ok(LLVMDisassembler { arch: arch, dcr: dcr })
    }
}

impl Drop for LLVMDisassembler {
    fn drop(&mut self) {
        unsafe { al::LLVMDisasmDispose(self.dcr); }
    }
}


impl dis::Disassembler for LLVMDisassembler {
    fn arch(&self) -> &arch::ArchAndOptions { &self.arch }
    fn can_disassemble_to_str(&self) -> bool { true }
    fn disassemble_insn_to_str(&self, input: dis::DisassemblerInput) -> Option<(Option<String>, u32)> {
        let mut tmp: [u8; 256] = unsafe { std::mem::uninitialized() };
        let res = unsafe { al::LLVMDisasmInstruction(self.dcr, input.data.as_ptr() as *mut u8, input.data.len() as u64, input.pc.0, &mut tmp[0] as *mut u8 as *mut c_char, 256) };
        if res == 0 {
            None
        } else {
            Some((Some(util::from_cstr(&tmp as &[u8]).lossy().into_owned()), res as u32))
        }
    }
}
impl dis::DisassemblerStatics for LLVMDisassembler {
    fn new_with_args(arch: arch::ArchAndOptions, args: &[String]) -> Result<LLVMDisassembler, dis::CreateDisError> {
        let mut optgrps = vec![
            getopts::optopt("", "triple",      "triple to pass to LLVM", ""),
            getopts::optopt("", "cpu",         "CPU name to pass to LLVM", ""),
            getopts::optopt("", "features",    "feature string to pass to LLVM", ""),

        ];
        let m = try!(util::do_getopts_or_usage(args, "llvmdis ...", 0, 0, &mut optgrps).map_err(|e| dis::CreateDisError::InvalidArgs(e)));

        let triple = m.opt_str("triple");
        let cpu = m.opt_str("cpu");
        let features = m.opt_str("features");

        LLVMDisassembler::new(
            arch,
            triple.as_ref().map(|x| &**x),
            cpu.as_ref().map(|x| &**x),
            features.as_ref().map(|x| &**x)
        ).map_err(|e| dis::CreateDisError::Other(box e))
    }
    fn name() -> &'static str { "llvm" }
}
