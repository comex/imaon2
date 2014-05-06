#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate collections;
use arch::Arch;
//use collections::hashmap::HashMap;
use std::vec::Vec;
use std::any::Any;
pub mod arch;

#[deriving(Default)]
pub struct VMA(pub u64);

#[deriving(Default)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

#[deriving(Default)]
pub struct Segment {
    pub vmaddr: VMA,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub name: Option<~str>,
    pub prot: Prot,
    pub section_segment_idx: Option<uint>,
    pub private: uint,
}

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
    fn name() -> &str;
    fn probe(&self, buf: &[u8]) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, buf: &[u8], pr: &ProbeResult, args: &str) -> ~Exec;
}

pub struct ProbeResult {
    pub desc: ~str,
    pub arch: Arch,
    pub fmtdata: ~Any,
}

pub fn probe_all(eps: &Vec<&'static ExecProber>, buf: &[u8]) -> Vec<(&'static ExecProber, ProbeResult)> {
    let mut result = vec!();
    for epp in eps.iter() {
        for pr in epp.probe(buf).move_iter() {
            result.push((*epp, pr))
        }
    }
    result
}

