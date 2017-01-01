use VMA;
use ::util;
use ::util::{SignExtend, UnSignExtend, Endian, Narrow, Ext};
use std::cell::Cell;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RelocKind {
    Pointer,
    _64Bit,
    _32Bit,
    Arm64Br26,
}
use RelocKind::*;

#[derive(Copy, Clone)]
pub struct RelocContext {
    pub kind: RelocKind,
    pub base_addr: VMA,
    pub pointer_size: usize,
    pub endian: Endian,
}

macro_rules! try_opt { ($x:expr) => {
    if let Some(x) = $x { x } else { return None }
} }

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RelocPackFail {
    AddrOutOfRange,
    Truncated,
    UnexpectedData,
}

impl RelocContext {
    pub fn size(&self) -> usize {
        match self.kind {
            Pointer => self.pointer_size,
            _32Bit => 4, _64Bit => 8,
            Arm64Br26 => 4,
        }
    }
    pub fn pack_unpack_insn(&self, data: &[Cell<u8>], new: Option<VMA>) -> Result<VMA, RelocPackFail> {
        let mut kind = self.kind;
        if kind == Pointer { kind = if self.pointer_size == 8 { _64Bit } else { _32Bit }; }
        match kind {
            Pointer => unreachable!(),
            _64Bit => {
                if data.len() < 8 { return Err(RelocPackFail::Truncated); }
                let old: u64 = util::copy_from_slice(&data[..8], self.endian);
                if let Some(VMA(new)) = new {
                    util::copy_to_slice(&data[..8], &new, self.endian);
                }
                Ok(VMA(old))
            },
            _32Bit => {
                if data.len() < 4 { return Err(RelocPackFail::Truncated); }
                let old: u32 = util::copy_from_slice(&data[..4], self.endian);
                if let Some(VMA(new)) = new {
                    let new: u32 = try!(new.narrow().ok_or(RelocPackFail::AddrOutOfRange));
                    util::copy_to_slice(&data[..4], &new, self.endian);
                }
                Ok(VMA(old.ext()))
            },
            Arm64Br26 => {
                if data.len() < 4 { return Err(RelocPackFail::Truncated); }
                let old_word: u32 = util::copy_from_slice(&data[..4], self.endian);
                if old_word & 0x7c000000 != 0x14000000 { return Err(RelocPackFail::UnexpectedData); }
                let old_addr = self.base_addr.wrapping_add(
                    ((old_word & 0x3ffffff) * 4).sign_extend(28)
                );
                if let Some(new) = new {
                    let rel = new.wrapping_sub(self.base_addr);
                    let base = old_word & !0x3ffffff;
                    if rel & 3 != 0 { return Err(RelocPackFail::AddrOutOfRange); }
                    let x: u32 = try!(rel.un_sign_extend(28).ok_or(RelocPackFail::AddrOutOfRange));
                    let word = x >> 2 | base;
                    util::copy_to_slice(&data[..4], &word, self.endian);
                }
                Ok(old_addr)
            },
        }
    }
}
