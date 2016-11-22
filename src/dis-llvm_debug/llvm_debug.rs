extern crate dis_llvm_debug_generated;
use dis_llvm_debug_generated::{Operand, MAX_OPS, DebugDisFn};

#[macro_use]
extern crate macros;

extern crate dis;
extern crate exec;
extern crate util;

use std::fmt::Write;

use exec::arch::{ArchAndOptions, ARMMode};
use dis::{Disassembler, DisassemblerStatics, DisassemblerInput};
use util::{Endian, LittleEndian, copy_from_slice, Swap};

pub struct LLVMDebugDisassembler { arch: ArchAndOptions }

impl Disassembler for LLVMDebugDisassembler {
    fn arch(&self) -> &ArchAndOptions { &self.arch }
    fn can_disassemble_to_str(&self) -> bool { true }
    fn disassemble_insn_to_str(&self, input: DisassemblerInput) -> Option<(Option<String>, u32)> {
        match (self.arch, input.mode) {
            (ArchAndOptions::ARM(opts), ARMMode { thumb }) => go_arm(input, thumb, opts.endian),
            (ArchAndOptions::AArch64(_), _) => go_common(input, LittleEndian, 4, dis_llvm_debug_generated::debug_dis_AArch64),
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
    if thumb {
        if input.data.len() < 2 { return None; }
        let x: u16 = copy_from_slice(&input.data[..2], endian);
        let is32 =  (x >> 13 & 7) == 7 && (x >> 11 & 3) != 0;
        if is32 {
            go_common(input, endian, 4, dis_llvm_debug_generated::debug_dis_Thumb2)
        } else {
            go_common(input, endian, 2, dis_llvm_debug_generated::debug_dis_Thumb)
        }
    } else {
        go_common(input, endian, 4, dis_llvm_debug_generated::debug_dis_ARM)
    }
}

fn go_common(input: DisassemblerInput, endian: Endian, size: usize, debug_dis: DebugDisFn) -> Option<(Option<String>, u32)> {
    if input.data.len() < size { return None; }
    let mut val: u32 = 0;
    for i in 0..size { val |= (input.data[i] as u32) << (8 * i); }
    if endian != LittleEndian { val.bswap(); }
    let mut ops = [Operand { name: "", val: 0 }; MAX_OPS];
    let mut name = "";
    unsafe { debug_dis(val, &mut name, &mut ops); }
    let mut out: String = format!("0x{:0.*x}: {}", 2 * size, val, name);
    for op in &ops {
        if op.name.len() == 0 { break; }
        write!(&mut out, " {}=0x{:x}", op.name, op.val).unwrap();
    }
    Some((Some(out), size as u32))
}

