extern crate dis_llvm_debug_generated;
use dis_llvm_debug_generated::*;

extern crate dis;
extern crate exec;
extern crate util;

use std::fmt::Write;

use exec::arch::{ArchAndOptions, ARMMode};
use dis::{Disassembler, DisassemblerStatics, DisassemblerInput};
use util::{Endian, copy_from_slice};

pub struct LLVMDebugDisassembler { arch: ArchAndOptions }

impl Disassembler for LLVMDebugDisassembler {
    fn arch(&self) -> &ArchAndOptions { &self.arch }
    fn can_disassemble_to_str(&self) -> bool { true }
    fn disassemble_insn_to_str(&self, input: DisassemblerInput) -> Option<(Option<String>, u32)> {
        match (self.arch, input.mode) {
            (ArchAndOptions::ARM(opts), ARMMode { thumb }) => go_arm(input, thumb, opts.endian),
            _ => panic!("unsupported arch"),
        }
    }

}

impl DisassemblerStatics for LLVMDebugDisassembler {
    fn new_with_args(arch: ArchAndOptions, args: &[String]) -> Result<Self, dis::CreateDisError> {
        if args.len() > 0 {
            return Err(dis::CreateDisError::InvalidArgs("llvm-debug: no supported args".to_owned()));
        }

        Ok(LLVMDebugDisassembler { arch: arch })
    }
    fn name() -> &'static str { "llvm-debug" }
}

fn go_arm(input: DisassemblerInput, thumb: bool, endian: Endian) -> Option<(Option<String>, u32)> {
    let mut res: String = String::new();
    let len = {
        let mut cb: Callback = &mut |name: &str, ops: &[Operand]| {
            res.push_str(name);
            for op in ops {
                write!(&mut res, " {}=0x{:x}", op.0, op.1).unwrap();
            }
        };
        if thumb {
            if input.data.len() < 2 { return None; }
            let x: u16 = copy_from_slice(&input.data[..2], endian);
            let is32 =  (x >> 13 & 7) == 7 && (x >> 11 & 3) != 0;
            if is32 {
                if input.data.len() < 4 { return None; }
                let y: u32 = copy_from_slice(&input.data[..4], endian);
                d::thumb2::decode(y, &mut cb);
                4
            } else {
                d::thumb::decode(x as u32, &mut cb);
                2
            }
        } else {
            if input.data.len() < 4 { return None; }
            let x: u32 = copy_from_slice(&input.data[..4], endian);
            d::arm::decode(x, &mut cb);
            4
        }
    };
    Some((Some(res), len))
}
