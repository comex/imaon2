#![feature(macro_rules)]
#![allow(non_camel_case_types)]

use arch::Arch;
pub mod arch;

pub type vma = u64;

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

pub struct Segment {
    addr: vma,
    offset: u64,
    size: u64,
    name: Option<~str>,
    r: bool,
    w: bool,
    x: bool,
    section_segment_idx: Option<uint>,
}

pub static default_segment : Segment = Segment {
    addr: 0,
    offset: 0,
    size: 0,
    name: None,
    r: false,
    w: false,
    x: false,
    section_segment_idx: None,
};

pub struct ExecBase {
    arch: Arch,
    subarch: Option<~str>,
    segments: ~[Segment],
    sections: ~[Segment],
}

#[macro_export]
macro_rules! ty_branch {
    ($cond:expr, $tyname:ident, $true_ty:ty, $false_ty:ty, $expr:expr) => {
        if $cond {
            type $tyname = $true_ty;
            $expr
        } else {
            type $tyname = $false_ty;
            $expr
        }
    }
}

#[test]
fn test_ty_branch() {
    for i in range(0, 2) {
        ty_branch!(i == 1, iXX, i32, i64, {
            assert_eq!(i, (i as iXX) as int);
        })
    }
}

