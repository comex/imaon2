#![allow(non_snake_case)]
fn unreachable() { unreachable!() }
struct Run(u8, u8, u8); // inpos, outpos, len
struct Bitslice { runs: [Run; 5] }
impl Bitslice {
    fn 
}
include!("../out-common/jump-dis-arm.inc.rs");

struct XHandler;
type Res = ();
impl Handler<Res> for XHandler {
    fn addr_offset_none_addr_10_LDC2L_OPTION(&mut self, addr: Bitslice) -> Res {}
    fn addr_offset_none_addr_S_23_STC2L_OPTION(&mut self, addr: Bitslice) -> Res {}
    fn addr_offset_none_addr_unk_Rd_S_8_STLEX(&mut self, addr: Bitslice) -> Res;
    fn addr_offset_none_addr_unk_Rt_29_LDA(&mut self, addr: Bitslice) -> Res;
    fn addrmode3_addr_S_2_STRD(&mut self, addr: Bitslice) -> Res;
    fn addrmode3_addr_unk_Rt_4_LDRD(&mut self, addr: Bitslice) -> Res;
    fn addrmode3_pre_addr_S_2_STRD_PRE(&mut self, addr: Bitslice) -> Res;
    fn addrmode3_pre_addr_unk_Rt_4_LDRD_PRE(&mut self, addr: Bitslice) -> Res;
    fn addrmode5_addr_8_LDC2L_OFFSET(&mut self, addr: Bitslice) -> Res;
    fn addrmode5_addr_S_4_STC2L_OFFSET(&mut self, addr: Bitslice) -> Res;
    fn addrmode5_pre_addr_4_LDC2L_PRE(&mut self, addr: Bitslice) -> Res;
    fn addrmode5_pre_addr_S_4_STC2L_PRE(&mut self, addr: Bitslice) -> Res;
    fn addrmode_imm12_addr_S_2_STRBi12(&mut self, addr: Bitslice) -> Res;
    fn addrmode_imm12_addr_unk_Rt_2_LDRBi12(&mut self, addr: Bitslice) -> Res;
    fn addrmode_imm12_pre_addr_S_2_STRB_PRE_IMM(&mut self, addr: Bitslice) -> Res;
    fn addrmode_imm12_pre_addr_unk_Rt_2_LDRB_PRE_IMM(&mut self, addr: Bitslice) -> Res;
    fn adrlabel_label_unk_Rd_1_ADR(&mut self, label: Bitslice) -> Res;
    fn br_target_target_B_1_Bcc(&mut self, target: Bitslice) -> Res;
    fn ldst_so_reg_addr_S_2_STRB_PRE_REG(&mut self, addr: Bitslice) -> Res;
    fn ldst_so_reg_addr_unk_Rt_2_LDRB_PRE_REG(&mut self, addr: Bitslice) -> Res;
    fn unk_RdLo_unk_RdHi_13_SMLAL(&mut self, RdLo: Bitslice, RdHi: Bitslice) -> Res;
    fn unk_Rd_161_ADCri(&mut self) -> Res;
    fn unk_Rt_2_LDRBrs(&mut self) -> Res;
    fn unidentified(&mut self) -> Res;


}
pub fn foo(op: u32) {
    println!("{}", decode(op, &mut XHandler));
}
