extern crate dis_generated_debug_dis;
use dis_generated_debug_dis::{Operand, MAX_OPS, DebugDisFn};
//extern crate dis_generated_jump_dis;
//use dis_generated_jump_dis::{JumpDisCtx, JumpDisFn};

#[macro_use]
extern crate macros;

extern crate dis;
extern crate exec;
extern crate util;

use std::fmt::Write;

use exec::VMA;
use exec::arch::{ArchAndOptions, ARMMode, OtherMode};
use dis::{Disassembler, DisassemblerStatics, DisassemblerInput, TrawlLead, TrawlLeadKind};
use util::{Endian, LittleEndian, copy_from_slice};

pub struct GenDisassembler { arch: ArchAndOptions }

impl Disassembler for GenDisassembler {
    fn arch(&self) -> &ArchAndOptions { &self.arch }
    fn can_disassemble_to_str(&self) -> bool { true }
    fn disassemble_insn_to_str(&self, input: &DisassemblerInput) -> Option<(Option<String>, u32)> {
        match (self.arch, input.mode) {
            (ArchAndOptions::ARM(opts), ARMMode { thumb }) => debug_arm(input, thumb, opts.endian),
            (ArchAndOptions::AArch64(_), _) => debug_common(input, LittleEndian, 4, dis_generated_debug_dis::debug_dis_AArch64),
            _ => panic!("unsupported arch"),
        }
    }

/*
    fn can_trawl(&self) -> bool { true }
    fn trawl(&self, input: &DisassemblerInput, leads: &mut Vec<TrawlLead>) -> Option<()> {
        match (self.arch, input.mode) {
            (ArchAndOptions::AArch64(_), _) => trawl_common(input, leads, LittleEndian, 4, dis_generated_jump_dis::jump_dis_AArch64),
            _ => panic!("unsupported arch"),
        }
    }
    */
}

impl DisassemblerStatics for GenDisassembler {
    fn new_with_args(arch: ArchAndOptions, args: &[String]) -> Result<Self, dis::CreateDisError> {
        if args.len() > 0 {
            return Err(dis::CreateDisError::InvalidArgs("gen: no supported args".to_owned()));
        }

        Ok(GenDisassembler { arch: arch })
    }
    fn name() -> &'static str { "gen" }
}

fn debug_arm(input: &DisassemblerInput, thumb: bool, endian: Endian) -> Option<(Option<String>, u32)> {
    if thumb {
        if input.data.len() < 2 { return None; }
        let x: u16 = copy_from_slice(&input.data[..2], endian);
        let is32 =  (x >> 13 & 7) == 7 && (x >> 11 & 3) != 0;
        if is32 {
            debug_common(input, endian, 4, dis_generated_debug_dis::debug_dis_Thumb2)
        } else {
            debug_common(input, endian, 2, dis_generated_debug_dis::debug_dis_Thumb)
        }
    } else {
        debug_common(input, endian, 4, dis_generated_debug_dis::debug_dis_ARM)
    }
}

#[inline]
fn get_word_common(input: &DisassemblerInput, endian: Endian, size: usize) -> Option<u32> {
    if input.data.len() < size { return None; }
    match size {
        4 => Some(copy_from_slice(&input.data[..4], endian)),
        2 => {
            let x: u16 = copy_from_slice(&input.data[..2], endian);
            Some(x as u32)
        },
        _ => panic!()
    }
}

fn debug_common(input: &DisassemblerInput, endian: Endian, size: usize, debug_dis: DebugDisFn) -> Option<(Option<String>, u32)> {
    let val = some_or!(get_word_common(input, endian, size), { return None; });
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

/*
fn trawl_common(input: &DisassemblerInput, leads: &mut Vec<TrawlLead>, endian: Endian, size: usize, jump_dis: JumpDisFn) -> Option<()> {
    let val = some_or!(get_word_common(input, endian, size), { return None; });
    let mut ctx = JumpDisCtx::default();
    ctx.base_addr = input.pc.0;
    unsafe { jump_dis(&mut ctx, val); }
    if ctx.have_target_addr {
        leads.push(TrawlLead {
            addr: VMA(ctx.target_addr),
            kind: if ctx.target_addr_is_data {
                TrawlLeadKind::OtherRef
            } else {
                TrawlLeadKind::JumpRef { mode: OtherMode }
            },
        });
    }
    if !ctx.is_tail {
        leads.push(TrawlLead { addr: input.pc + (size as u64), kind: TrawlLeadKind::NextInsn });
    }
    Some(())
}
*/
