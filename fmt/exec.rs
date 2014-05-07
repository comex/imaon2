#![feature(macro_rules)]
#![allow(non_camel_case_types)]
#![feature(phase)]

#[phase(syntax, link)]
extern crate util;
extern crate collections;
use arch::Arch;
//use collections::hashmap::HashMap;
use std::vec::Vec;
pub mod arch;

#[deriving(Default, Copy, Clone, Show, Eq, Ord)]
pub struct VMA(pub u64);

delegate_arith!(VMA, Sub, sub, u64)
delegate_arith!(VMA, Add, add, u64)

#[deriving(Default, Copy, Clone, Show, Eq)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

pub static prot_all : Prot = Prot { r: true, w: true, x: true };

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

#[deriving(Default, Clone)]
pub struct Segment {
    pub vmaddr: VMA,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub name: Option<~str>,
    pub prot: Prot,
    pub private: uint,
}

#[deriving(Default)]
pub struct ExecBase {
    pub arch: Arch,
    pub endian: util::Endian,
    pub segments: Vec<Segment>,
    pub sections: Vec<Segment>,
}

pub trait Exec {
    fn get_exec_base<'a>(&'a self) -> &'a ExecBase;
}

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, buf: &[u8]) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, buf: &[u8], pr: &ProbeResult, args: &str) -> ~Exec;
}

pub struct ProbeResult {
    pub desc: ~str,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: ~str,
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

