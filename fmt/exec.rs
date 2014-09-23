#![feature(macro_rules)]
#![allow(non_camel_case_types)]
#![feature(phase)]

#[phase(plugin, link)]
extern crate util;
extern crate collections;
use arch::Arch;
//use collections::hashmap::HashMap;
use std::vec::Vec;

pub mod arch;

#[deriving(Default, Copy, Clone, Show, PartialEq, Eq, PartialOrd, Ord)]
pub struct VMA(pub u64);

delegate_arith!(VMA, Sub, sub, u64)
delegate_arith!(VMA, Add, add, u64)

#[deriving(Default, Copy, Clone, Show, PartialEq, Eq)]
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
    pub name: Option<String>,
    pub prot: Prot,
    pub private: uint,
}

#[deriving(Default)]
pub struct ExecBase {
    pub arch: Arch,
    pub endian: util::Endian,
    pub segments: Vec<Segment>,
    pub sections: Vec<Segment>,
    pub buf: Option<util::ArcMC>,
}

pub trait Exec {
    fn get_exec_base<'a>(&'a self) -> &'a ExecBase;
}

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, buf: util::ArcMC, eps: &Vec<&'static ExecProber+'static>) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, buf: util::ArcMC, pr: &ProbeResult, args: &str) -> Box<Exec>;
}

pub struct ProbeResult {
    pub desc: String,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: Vec<String>,
}

pub fn probe_all(eps: &Vec<&'static ExecProber+'static>, buf: util::ArcMC) -> Vec<(&'static ExecProber+'static, ProbeResult)> {
    let mut result = vec!();
    for epp in eps.iter() {
        for pr in epp.probe(buf.clone(), eps).into_iter() {
            result.push((*epp, pr))
        }
    }
    result
}

