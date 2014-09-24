#![feature(macro_rules)]
#![feature(unboxed_closures, unboxed_closure_sugar)]
#![allow(non_camel_case_types)]
#![feature(phase)]

#[phase(plugin)]
extern crate macros;
extern crate util;
extern crate collections;
extern crate getopts;
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
    pub buf: Option<util::MCRef>,
}

pub trait Exec {
    fn get_exec_base<'a>(&'a self) -> &'a ExecBase;
}

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef, args: Vec<String>) -> Box<Exec>;
}

pub struct ProbeResult {
    pub desc: String,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: Vec<String>,
}

pub fn probe_all(eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef) -> Vec<(&'static ExecProber+'static, ProbeResult)> {
    let mut result = vec!();
    for epp in eps.iter() {
        for pr in epp.probe(eps, buf.clone()).into_iter() {
            result.push((*epp, pr))
        }
    }
    result
}

pub fn create(eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef, mut args: Vec<String>) -> Box<Exec+'static> {
    let prober_name = args.remove(0).unwrap();
    for epp in eps.iter() {
        if epp.name() == prober_name.as_slice() {
            return epp.create(eps, buf, args)
        }
    }
    fail!("no format named {}", prober_name)
}

