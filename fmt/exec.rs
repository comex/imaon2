#![feature(macro_rules)]
#![feature(unboxed_closures, unboxed_closure_sugar)]
#![feature(tuple_indexing)]
#![allow(non_camel_case_types)]
#![allow(non_uppercase_statics)]
#![feature(phase)]

#[phase(plugin)]
extern crate macros;
extern crate util;
extern crate collections;
extern crate "bsdlike_getopts" as getopts;
use arch::Arch;
//use collections::hashmap::HashMap;
use std::vec::Vec;
use std::fmt;
use std::mem::replace;

pub mod arch;

#[deriving(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VMA(pub u64);

impl fmt::Show for VMA {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::FormatError> {
        write!(fmt, "0x");
        self.0.fmt(fmt);
    }
}

delegate_arith!(VMA, Sub, sub, u64)
delegate_arith!(VMA, Add, add, u64)
delegate_arith!(VMA, BitOr, bitor, u64)
delegate_arith!(VMA, BitAnd, bitand, u64)
delegate_arith!(VMA, BitXor, bitxor, u64)

#[deriving(Default, Copy, Clone, PartialEq, Eq)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl fmt::Show for Prot {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::FormatError> {
        write!(fmt, "{}{}{}",
            if self.r { 'r' } else { '-' },
            if self.w { 'w' } else { '-' },
            if self.x { 'x' } else { '-' })
    }
}

pub static prot_all : Prot = Prot { r: true, w: true, x: true };

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

#[deriving(Default, Show, Clone)]
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
    pub buf: util::MCRef,
}

#[deriving(Show, PartialEq, Eq)]
pub enum SymbolValue<'a> {
    Addr(VMA),
    Undefined,
    Resolver(VMA),
    ReExport(&'a [u8]),
}

#[deriving(Show, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub is_public: bool,
    pub is_weak: bool,
    pub val: SymbolValue<'a>,
    pub private: uint,
}

#[deriving(Show, PartialEq, Eq)]
pub enum SymbolSource {
    AllSymbols,
    ImportedSymbols,
    ExportedSymbols,
}

pub trait Exec :'static {
    fn get_exec_base(&self) -> &ExecBase;

    fn as_any(&self) -> &std::any::Any {
        self as &std::any::Any
    }

    // Todo: add a monomorphizable iterator version of this
    fn get_symbol_list(&self, source: SymbolSource) -> Vec<Symbol>;
}

// Prober:

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef, args: Vec<String>) -> (Box<Exec>, Vec<String>);
}

pub struct ProbeResult {
    pub desc: String,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: Vec<String>,
}

pub fn probe_all(eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef) -> Vec<ProbeResult> {
    let mut result = vec!();
    for epp in eps.iter() {
        result.extend(epp.probe(eps, buf.clone()).into_iter());
    }
    result
}

pub fn create(eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef, mut args: Vec<String>) -> (Box<Exec+'static>, Vec<String>) {
    let prober_name = args.remove(0).unwrap();
    if prober_name.equiv(&"auto") {
        return create_auto(eps, buf, args)
    }
    for epp in eps.iter() {
        if epp.name() == prober_name[] {
            return epp.create(eps, buf, args)
        }
    }
    fail!("no format named {}", prober_name)
}

fn create_auto(eps: &Vec<&'static ExecProber+'static>, buf: util::MCRef, args: Vec<String>) -> (Box<Exec+'static>, Vec<String>) {
    let m = util::do_getopts(args[], "auto [--arch arch]", 0, std::uint::MAX, &mut vec!(
        getopts::optopt("", "arch", "Architecture bias", "arch"),
    ));
    let mut results = probe_all(eps, buf.clone());
    match m.opt_str("arch") {
        Some(arch_str) => {
            let arch = from_str(arch_str[]).unwrap();
            for pr in results.iter_mut() {
                if pr.likely && pr.arch == arch {
                    return (create(eps, buf, replace(&mut pr.cmd, vec!())).0, m.free)
                }
            }
        }
        None => ()
    }
    for pr in results.iter_mut() {
        if pr.likely {
            return (create(eps, buf, replace(&mut pr.cmd, vec!())).0, m.free)
        }
    }
    for pr in results.iter_mut() {
        return (create(eps, buf, replace(&mut pr.cmd, vec!())).0, m.free)
    }
    fail!("create_auto: no formats, not even raw_binary??");

}
