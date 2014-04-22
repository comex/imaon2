#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate collections;
use arch::Arch;
use collections::hashmap::HashMap;
use std::vec::Vec;
pub mod arch;

pub type vma = u64;

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

pub struct Segment {
    pub addr: vma,
    pub offset: u64,
    pub size: u64,
    pub name: Option<~str>,
    pub r: bool,
    pub w: bool,
    pub x: bool,
    pub section_segment_idx: Option<uint>,
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

#[deriving(Default)]
pub struct ExecBase {
    pub arch: Arch,
    pub endian: util::Endian,
    pub subarch: Option<~str>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Segment>,
}

pub trait Exec {
    fn get_exec_base<'a>(&'a self) -> &'a ExecBase;
}

pub trait ExecProber {
    fn probe(&self, buf: &[u8]) -> bool;
    // May fail.
    fn create(&self, buf: &[u8], settings: &HashMap<&str, &str>) -> ~Exec;
}

