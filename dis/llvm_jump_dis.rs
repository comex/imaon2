#![allow(non_snake_case)]

extern crate dis;
extern crate exec;
use exec::arch;
use dis::{Disassembler, DisassemblerStatics};

pub struct Run(u8, u8, u8); // inpos, outpos, len
pub struct Bitslice { runs: [Run; 5] }
impl Bitslice {
    #[cfg_attr(opt, inline(always))]
    fn get(&self, insn: u32) -> u32 {
        let mut val = 0;
        for run in self.runs {
            val |= insn.rotate_left(run.1.wrapping_sub(run.0) & 31) & ((1 << run.2) - 1);
        }
        val
    }
    fn set(&self, insn: u32, field_val: u32) -> u32 {
        let mut val = 0;
        for run in self.runs {
            let rot = run.1.wrapping_sub(run.0) & 31;
            let mask = (1 << run.2) - 1;
            val = val & ~(mask.rotate_left(rot)) | field_val.rotate_left(rot);
        }
        val
    }
}
#[path="../out-common/jump-dis-arm.rs"]
mod arm;
#[path="../out-common/jump-dis-thumb.rs"]
mod thumb;
#[path="../out-common/jump-dis-thumb2.rs"]
mod thumb2;

pub struct LLVMJumpDisassembler { arch: arch::ArchAndOptions }

impl Disassembler for LLVMJumpDisassembler {
    fn arch(&self) -> &arch::ArchAndOptions { &self.arch }
    fn can_trawl(&self) -> bool { true }
    fn trawl(&self, input: DisassemblerInput, leads: &mut Vec<TrawlLead>) {
        match (self.arch, input.mode) {
            (arch::ARM, arch::ARMMode { thumb }) => trawl_arm(input, leads, thumb),
            _ => panic!("unsupported arch"),
        }
    }

}

fn trawl_arm(input: DisassemblerInput, leads: &mut Vec<TrawlLead>, thumb: bool) {
    panic!()
}

struct Handler { insn: u32 }
enum HandlerResult { Stop, Continue }
impl arm::Handler<HandlerResult> for Handler {
    fn RdHi_out_RdLo_out_13_SMLAL(&mut self, RdLo: Bitslice, RdHi: Bitslice) -> HandlerResult {}
    fn Rn_regs_wb_out_8_LDMDA_UPD(&mut self, regs: Bitslice, Rn: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_20_FLDMXDB_UPD(&mut self, Rn: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_Rt2_out_Rt_out_addr_1_LDRD_PRE(&mut self, addr: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_Rt2_out_Rt_out_offset_1_LDRD_POST(&mut self, offset: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_Rt_out_addr_7_LDRB_PRE_IMM(&mut self, addr: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_Rt_out_offset_11_LDRBT_POST_IMM(&mut self, offset: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_addr_6_STRB_PRE_IMM(&mut self, addr: Bitslice) -> HandlerResult {}
    fn Rn_wb_out_offset_10_STRBT_POST_IMM(&mut self, offset: Bitslice) -> HandlerResult {}
    fn Rt2_out_Rt_out_3_MRRC(&mut self, Rt: Bitslice, Rt2: Bitslice) -> HandlerResult {}
    fn Rt2_out_Rt_out_addr_1_LDRD(&mut self, addr: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn Rt_out_base_wb_out_3_LDRHTr(&mut self, Rt: Bitslice) -> HandlerResult {}
    fn Rt_out_base_wb_out_offset_3_LDRHTi(&mut self, offset: Bitslice, Rt: Bitslice) -> HandlerResult {}
    fn addr_5_LDRBi12(&mut self, addr: Bitslice) -> HandlerResult {}
    fn base_wb_out_1_STRHTr(&mut self) -> HandlerResult {}
    fn base_wb_out_offset_1_STRHTi(&mut self, offset: Bitslice) -> HandlerResult {}
    fn func_2_BL(&mut self, func: Bitslice) -> HandlerResult {}
    fn label_1_ADR(&mut self, label: Bitslice) -> HandlerResult {}
    fn shift_2_LDRBrs(&mut self, shift: Bitslice) -> HandlerResult {}
    fn target_2_BLXi(&mut self, target: Bitslice) -> HandlerResult {}
    fn x_201_ADCri(&mut self) -> HandlerResult {
        // if we got here, the output register must be PC
        HandlerResult::Stop
    }
    fn unidentified(&mut self) -> HandlerResult { HandlerResult::Continue }
}

