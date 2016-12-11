#![allow(non_snake_case)]
extern crate build_run_gen;
extern crate util;
use util::{Signedness, Signed, Unsigned, SignExtend, ReadCell};
extern crate exec;
use exec::VMA;

use std::mem::transmute;

include!(concat!(env!("OUT_DIR"), "/jump-dis-aarch64-istub.rs"));
use jump_dis_AArch64 as aarch64;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reg(pub i8);
impl Default for Reg {
    #[inline] fn default() -> Self { Reg(-1) }
}
impl Reg {
    #[inline] pub fn invalid() -> Self { Reg(-1) }
}
fn reg(r: u32) -> Reg { Reg(r as i8) }

#[derive(Default)]
pub struct AArch64Handler {
    // input
    addr: VMA,
    op: u32,
    // output
    info: InsnInfo,
}

#[derive(Copy, Clone, Default)]
pub struct InsnInfo {
    pub kills_reg: [Reg; 3],
    pub target_addr: TargetAddr,
    pub kind: InsnKind,
}
impl InsnInfo {
    pub fn kills_reg(&self, reg: Reg) -> bool {
        self.kills_reg.contains(&reg)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum TargetAddr {
    None, Data(VMA), Code(VMA),
}

impl Default for TargetAddr { fn default() -> Self { TargetAddr::None } }

#[derive(Copy, Clone, Debug)]
pub enum InsnKind {
    Other,
    Tail,
    Unidentified,
    Load(Reg, Addrish, Size, Signedness),
    Set(Reg, Addrish),
    CmpImm(Reg, u64),
    Bcc(CC),
    Br(Reg),
}

impl Default for InsnKind { fn default() -> Self { InsnKind::Unidentified } }

#[derive(Copy, Clone, Debug)]
pub enum Addrish {
    Imm(u64),
    AddImm(Reg, u64),
    AddReg(Reg, Reg, u8 /*shift*/),
}

#[derive(Clone, Copy, Debug)]
pub enum Size { Size8 = 0, Size16 = 1, Size32 = 2, Size64 = 3 }
pub use Size::*;
#[derive(Clone, Copy, Debug)]
pub enum CC { Gtu, Geu, Ltu, Leu, Other }

impl Size {
    pub fn bytes(self) -> u64 { 1 << self.log2_bytes() }
    pub fn bits(self) -> u64 { 8 << self.log2_bytes() }
    pub fn log2_bytes(self) -> u8 { unsafe { transmute(self) } }
}

impl CC {
    fn from_a64(cond: u32) -> Self {
        assert!(cond <= 0b1111);
        match cond {
            0b1000 => CC::Gtu,
            0b1001 => CC::Leu,
            0b0010 => CC::Geu,
            0b0011 => CC::Ltu,
            _ => CC::Other,
        }
    }
}
pub trait GenericHandler {
    fn decode<'a>(&'a mut self, addr: VMA, data: &[ReadCell<u8>]) -> (usize, &'a InsnInfo);
}

impl GenericHandler for AArch64Handler {
    fn decode<'a>(&'a mut self, addr: VMA, data: &[ReadCell<u8>]) -> (usize, &'a InsnInfo) {
        self.info = Default::default();
        let mut size = 0;
        if data.len() >= 4 {
            size = 4;
            let op: u32 = util::copy_from_slice(&data[..4], util::LittleEndian);
            self.op = op;
            self.addr = addr;
            aarch64::decode(op, self);
        }
        (size, &self.info)
    }
}

impl AArch64Handler {
    pub fn new() -> AArch64Handler {
        Default::default()
    }
}

impl aarch64::Handler for AArch64Handler {
    type Res = ();
    #[inline]
    fn R1_out_skipped_Rd_out_8_ADDSWrx(&mut self, Rd: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rd);
    }
    #[inline]
    fn Rd_out_174_ADCSWr(&mut self, Rd: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rd);
    }
    #[inline]
    fn Rd_out_Rn_addi_skipped_imm_1_ADDXri(&mut self, Rd: u32, Rn: u32, imm: u32) -> Self::Res {
        self.info.kind = InsnKind::Set(reg(Rd), Addrish::AddImm(reg(Rn), imm as u64));
        self.info.kills_reg[0] = reg(Rd);
    }
    #[inline]
    fn Rd_out_skipped_Rn_cmp_skipped_imm_2_SUBSWri(&mut self, Rn: u32, imm: u32) -> Self::Res {
        self.info.kind = InsnKind::CmpImm(reg(Rn), imm as u64);
    }
    #[inline]
    fn Rd_out_skipped_dst_out_24_ADDSWrs(&mut self, dst: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(dst);
    }
    #[inline]
    fn Rm_Rn_Rt_out_extend_ldr_shifted_skipped_28_LDRBBroW(&mut self, Rt: u32, Rn: u32, _extend: u32, Rm: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);

        let op = self.op;
        let opc = (op >> 22) & 0x3;
        let scale = op >> 30;
        // sloppily ignore reg size
        let signedness = match opc {
            0b00 => panic!("store?"),
            0b01 => Unsigned,
            0b10 | 0b11 => {
                if scale == 0b11 { panic!("preload?"); }
                Signed
            },
            _ => panic!(),
        };
        self.info.kind = InsnKind::Load(
            reg(Rt),
            Addrish::AddReg(reg(Rn), reg(Rm), if op & 0x1000 != 0 { scale as u8 } else { 0 }),

            [Size8, Size16, Size32, Size64][scale as usize],
            signedness
        );
    }
    #[inline]
    fn Rn_Rt2_out_Rt_out_wback_out_skipped_6_LDPSWpost(&mut self, Rt: u32, Rn: u32, Rt2: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);
        self.info.kills_reg[1] = reg(Rt2);
        self.info.kills_reg[2] = reg(Rn);
    }
    #[inline]
    fn Rn_Rt_out_wback_out_skipped_18_LDRBBpost(&mut self, Rt: u32, Rn: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);
        self.info.kills_reg[1] = reg(Rn);
    }
    #[inline]
    fn Rn_wback_out_skipped_214_LD1Fourv16b_POST(&mut self, Rn: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rn);
    }
    #[inline]
    fn Rs_out_out_skipped_16_CASALb(&mut self, Rs: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rs);
    }
    #[inline]
    fn Rt2_out_Rt_out_7_LDAXPW(&mut self, Rt: u32, Rt2: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);
        self.info.kills_reg[1] = reg(Rt2);
    }
    #[inline]
    fn Rt_out_188_LDADDALb(&mut self, Rt: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);
    }
    #[inline]
    fn Rt_out_label_3_LDRSWl(&mut self, Rt: u32, label: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Rt);
        self.info.target_addr = TargetAddr::Data(self.addr.wrapping_add((label << 2).sign_extend(21)));
    }
    #[inline]
    fn Ws_out_12_STLXPW(&mut self, Ws: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Ws);
    }
    #[inline]
    fn Xd_out_adrp_skipped_label_1_ADRP(&mut self, Xd: u32, label: u32) -> Self::Res {
        self.info.kills_reg[0] = reg(Xd);
        let a = self.addr.wrapping_add((label << 12).sign_extend(33));
        self.info.target_addr = TargetAddr::Data(a);
        self.info.kind = InsnKind::Set(reg(Xd), Addrish::Imm(a.0));
    }
    #[inline]
    fn Xd_out_label_1_ADR(&mut self, Xd: u32, label: u32) -> Self::Res {
        // same as previous but without the * 0x1000
        self.info.kills_reg[0] = reg(Xd);
        let a = self.addr.wrapping_add(label.sign_extend(21));
        self.info.target_addr = TargetAddr::Data(a);
        self.info.kind = InsnKind::Set(reg(Xd), Addrish::Imm(a.0));
    }
    #[inline]
    fn addr_1_BL(&mut self, addr: u32) -> Self::Res {
        self.info.target_addr = TargetAddr::Code(self.addr.wrapping_add((addr << 2).sign_extend(28)));
    }
    #[inline]
    fn addr_branchy_skipped_1_B(&mut self, addr: u32) -> Self::Res {
        self.info.kind = InsnKind::Tail;
        self.info.target_addr = TargetAddr::Code(self.addr.wrapping_add((addr << 2).sign_extend(28)));
    }
    #[inline]
    fn bcc_skipped_cond_target_1_Bcc(&mut self, cond: u32, target: u32) -> Self::Res {
        self.info.kind = InsnKind::Bcc(CC::from_a64(cond));
        self.info.target_addr = TargetAddr::Code(self.addr.wrapping_add((target << 2).sign_extend(21)));
    }
    #[inline]
    fn branchy_skipped_3_DRPS(&mut self) -> Self::Res {
        self.info.kind = InsnKind::Tail;
    }
    #[inline]
    fn Rn_br_skipped_1_BR(&mut self, Rn: u32) -> Self::Res {
        self.info.kind = InsnKind::Br(reg(Rn));
    }
    #[inline]
    fn condbranchy_skipped_target_8_CBNZW(&mut self, target: u32) -> Self::Res {
        self.info.target_addr = TargetAddr::Code(self.addr.wrapping_add((target << 2).sign_extend(21)));
    }
    #[inline]
    fn label_3_LDRDl(&mut self, label: u32) -> Self::Res {
        self.info.target_addr = TargetAddr::Data(self.addr.wrapping_add((label << 2).sign_extend(21)));
    }
    #[inline]
    fn uninteresting_2023_ABSv16i8(&mut self) -> Self::Res {}
    #[inline]
    fn unidentified(&mut self) -> Self::Res {
        self.info.kind = InsnKind::Unidentified;
    }
}


