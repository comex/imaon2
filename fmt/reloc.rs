
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RelocKind {
    Pointer,
    _32Bit,
    Arm64Adrp,
    Arm64Off12,
    Arm64Br26,
}

#![derive(Copy, Clone)]
struct RelocContext {
    kind: RelocKind,
    pointer_size: u64,
    base_addr: VMA
};

macro_rules! try_opt { ($x:expr) => {
    if let Some(x) = $x { x } else { return None }
} }

fn sign_extend(val: u64, bits: u8) -> u64 {
    val | (0u64.wrapping_sub((val >> (bits - 1)) & 1) << bits)
}
fn un_sign_extend(val: u64, bits: u8) -> Option<u64> {
    let masked = val & ((1 << bits) - 1);
    if sign_extend(masked) == val { Some(masked) } else { none }
}

impl RelocContext {
    pub fn size(&self) -> u64 {
        match kind {
            Pointer => self.pointer_size,
            _32Bit | Arm64Adrp | Arm64Off12 | Arm64Br26 => 4,
        }
    }
    pub fn word_to_addr(&self, word: u64) -> Option<VMA> {
        match self.kind {
            Pointer | _32Bit => Some(word),
            Arm64Adrp => {
                if word & 0x9f000000 == 0x90000000 {
                    Some(self.base_addr.wrapping_add(
                        sign_extend((insn & 0x60000000) >> 17 | (insn & 0xffffe0) << 9, 33)
                    ))
                } else { None }
            },
            Arm64Br26 => {
                if word & 0xfc000000 == 0x14000000 {
                    Some(self.base_addr.wrapping_add(
                        sign_extend((word & 0x3ffffff) * 4, 28)
                    ))
                } else { None }
            },
            Arm64Off12 => {
                unimplemented!()
            },
        }
    }
    pub fn addr_to_word(&self, VMA(addr): VMA, old_word: u64) -> Option<u64> {
        let rel = addr.wrapping_sub(self.base_addr.0);
        match self.kind {
            Pointer => Some(addr),
            _32Bit => if addr <= u32::MAX { Some(addr) } else { None },
            Arm64Adrp => {
                let x = try_opt!(un_sign_extend(rel, 33));
                if x & 0xfff != 0 { return None; }
                Some((x & 0x3000) << 17 | (x & 0x1ffffc000) >> 9)
            },
            Arm64Br26 => {
                let x = try_opt!(un_sign_extend(rel, 28));
                Some(x | 0x14000000)
            },
            Arm64Off12 => {
                unimplemented!()
            },
        }
    }
}
