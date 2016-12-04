struct Reg(u8);
enum Size { Size8 = 0, Size16 = 1, Size32 = 2, Size64 = 3 }
enum CC { Gtu, Geu, Ltu, Leu, Other }
enum InsnKind {
    SetPcRel(Reg, u64),
    AddImm(Reg, Reg, u64),
    LoadShifted(Reg, Reg, Reg, u8, Size, Signedness),
    CmpImm(Reg, u64),
    Bcc(CC, VMA),
    B(VMA),
    Other,
    OtherTail,
    Fail,
}

type InsnIdx = usize;

struct InsnInfo {
    is_thumb: bool,
    flow_sources: Vec<InsnIdx>,
}

struct CodeMap {
    insn_data: &[Cell<u8>],
    region_start: VMA,
    region_size: u64,
    grain_shift: u8,
    // 0 => unseen
    // -x => distance to previous instruction, which flows to this one
    // +x => index into insn_state_other
    insn_state: Vec<i32>,
    insn_state_other: Vec<InsnStateOther>,
    todo: VecDeque<InsnIdx>,
}

impl CodeMap {
    fn new(region_start: VMA, region_size: u64, grain_shift: u8) -> Self {
        let num_insns: usize = (region_size >> grain_shift).narrow().unwrap()
        CodeMap {
            region_start: region_start,
            region_size: region_size,
            grain_shift: grain_shift,
            insn_state: util::zero_vec(num_insns),
            insn_state_other: Vec::new(),
            flow_sources: HashMap::new(),
        }
    }
    fn addr_to_idx(&self, addr: VMA) -> Option<InsnIdx> {
        let offset = addr.wrapping_sub(region_start);
        if offset < region_size &&
           offset & ((1 << self.grain_shift) - 1) == 0 {
            Some(offset >> self.grain_shift)
        } else {
            None
        }
    }
    fn mark_flow(&mut self, from: InsnIdx, to: InsnIdx, is_jump: bool) {
        let state = &mut self.insn_state[to];
        let old = *state;
        if old < 0 {
            if !is_jump && to - from == old { panic!("dual regular flow?"); }
            // weird
            *state = self.insn_state_other.len();
            self.insn_state_other.push(InsnStateOther { flows_from: vec![to + old, from], });
        } else if old > 0 {
            let iso = &mut self.insn_state_other[old as usize];
            iso.flows_from.push(from);
        } else {
            if !is_jump {
                *state = -((to - from) as i32);
            } else {
                *state = self.insn_state_other.len();
                self.insn_state_other.push(InsnStateOther { flows_from: vec![from], });
            }
            self.todo.push_back(to);
        }
    }
    fn mark_root(&mut self, idx: InsnIdx) -> bool /*unseen*/ {
        // this should only happen at the beginning
        assert!(self.insn_state[idx] == 0);
        self.insn_state[idx] = self.insn_state_other.len();
        self.insn_state_other.push(InsnStateOther { flows_from: vec![], });
        self.todo.push_back(idx);
    }
    fn go(&mut self) {
        while let Some(mut idx) = self.todo.pop_front() {
            loop {
                let offset = idx << self.grain_shift;
                let data = &self.insn_data[offset..];
                let addr = self.region_start + (offset as u64);
                let (kind, siz) = trawl_insn(addr, data);

            }

        }
    }
}


use self::Size::*;
use self::InsnKind::*;
fn trawl_insn(op_addr: VMA, data: &[Cell<u8>]) -> (InsnKind, u32) {
    if data.len() < 4 { return Fail; }
    let op: u32 = util::copy_from_slice(&data[..4], util::LittleEndian);
    (trawl_insn_arm64_inner(op_addr, op), 4)

}
fn trawl_insn_arm64_inner(mut op_addr: VMA, op: u32) -> InsnKind {
    if op & 0x1f000000 == 0x10000000 { // ADR/ADRP
        let page = op & 0x80000000 != 0;
        let label = ((op & 0xffffe0) >> 3 | (op & 0x60000000) >> 29) as u64;
        let mut imm = label.sign_extend(21);
        let mut base = op_addr;
        if page {
            imm <<= 12;
            base &= !0xfff;
        }
        return SetPcRel(Reg(op & 0x1f as u8), base.wrapping_add(imm));
    }
    if op & 0x7f800000 == 0x11000000 { // ADD/SUB
        let mut imm: u32 = (op >> 10) & 0xfff;
        if op & 0x400000 != 0 { imm <<= 12; }
        if op & 0x40000000 != 0 { imm = 0.wrapping_sub(imm); }
        //let sf_size = if op & 0x80000000 { Size64 } else { Size32 };
        return AddImm(Reg(op & 0x1f as u8), Reg((op >> 5) & 0x1f as u8), imm);
    }
    if op & 0x7f80001f == 0x7100001f { // CMP
        let mut imm: u32 = (op >> 10) & 0xfff;
        if op & 0x400000 != 0 { imm <<= 12; }
        return CmpImm(Reg((op >> 5) & 0x1f as u8), imm);
    }
    if op & 0xff000010 == 0x54000000 { // Bcc
        let offset = (((op >> 5) & 0x7ffff) << 2).sign_extend(21);
        let target = op_addr.wrapping_add(offset);
        let cc = match op & 0xf {
            0b1000 => CC::Gtu,
            0b1001 => CC::Leu,
            0b0010 => CC::Geu,
            0b0011 => CC::Ltu,
            _ => CC::Other,
        };
        return Bcc(cc, target);
    }
    if op & 0xfc000000 == 0x14000000 { // B
        let offset = ((op & 0x3ffffff) << 2).sign_extend(28);
        let target = op_addr.wrapping_add(offset);
        return B(target);
    }
    if op & 0x3f200c00 == 0x38200800 { // load shifted
        let opc = (op >> 22) & 0x3;
        let scale = op >> 30;
        // sloppily ignore reg size
        let signedness = match opc {
            0b00 => return Other, // store
            0b01 => Unsigned,
            0b10 | 0b11 => {
                if size == 0b11 { return Other; }
                Signed
            },
        };
        return LoadShifted(Reg(op & 0x1f as u8), Reg((op >> 5) & 0x1f as u8),
                           Reg((op >> 16) & 0x1f as u8),
                           if op & 0x1000 != 0 { scale } else { 0 },
                           scale as Size);
    }
}

