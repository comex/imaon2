#![feature(unboxed_closures)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![feature(collections, into_cow)]

#[macro_use]
extern crate macros;
extern crate util;
extern crate collections;
extern crate bsdlike_getopts as getopts;
use arch::Arch;
//use collections::hashmap::HashMap;
use std::vec::Vec;
use std::fmt;
use std::mem::replace;
use std::mem::transmute;
use std::str::FromStr;

pub mod arch;

#[derive(Copy, Debug, Clone)]
pub enum ErrorKind {
    BadData,
    Other
}

#[derive(Clone, Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: std::borrow::Cow<'static, str>,
}
pub type ExecResult<T> = Result<T, Error>;
pub fn err<T, S: std::borrow::IntoCow<'static, str>>(kind: ErrorKind, s: S) -> ExecResult<T> {
    Err(Error { kind: kind, message: s.into_cow() })
}

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VMA(pub u64);

impl fmt::Debug for VMA {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "0x{:x}", self.0)
    }
}
display_as_debug!(VMA);

delegate_arith!(VMA, Sub, sub, u64);
delegate_arith!(VMA, Add, add, u64);
delegate_arith!(VMA, BitOr, bitor, u64);
delegate_arith!(VMA, BitAnd, bitand, u64);

// TODO - should this be signed or something?
impl std::ops::Sub<VMA> for VMA {
    type Output = u64;
    fn sub(self, VMA(rhs): VMA) -> u64 {
        let lhs = self.0;
        lhs - rhs
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl fmt::Display for Prot {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
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

#[derive(Default, Debug, Clone)]
pub struct Segment {
    pub vmaddr: VMA,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub name: Option<String>,
    pub prot: Prot,
    pub data: Option<util::MCRef>,
    pub seg_idx: Option<usize>, // for sections
    pub private: usize,
}

impl Segment {
    pub fn pretty_name(&self) -> &str {
        self.name.as_ref().map_or("unnamed", |a| a)
    }
    pub fn get_data(&self) -> &[u8] {
        self.data.as_ref().unwrap().get()
    }
}

#[derive(Default)]
pub struct ExecBase {
    pub arch: Arch,
    pub endian: util::Endian,
    pub segments: Vec<Segment>,
    pub sections: Vec<Segment>,
    pub whole_buf: Option<util::MCRef>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SymbolValue<'a> {
    Addr(VMA),
    Undefined,
    Resolver(VMA),
    ReExport(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub is_public: bool,
    pub is_weak: bool,
    pub val: SymbolValue<'a>,
    pub private: usize,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SymbolSource {
    All,
    Imported,
    Exported,
}

pub trait Exec : 'static {
    fn get_exec_base(&self) -> &ExecBase;

    // Todo: add a monomorphizable iterator version of this
    fn get_symbol_list(&self, _source: SymbolSource) -> Vec<Symbol> {
        vec!()
    }

    fn as_any(&self) -> &std::any::Any;// { self as &std::any::Any }
    #[allow(mutable_transmutes)]
    fn as_any_mut(&mut self) -> &mut std::any::Any { unsafe { transmute(self.as_any()) } }
}

// Prober:

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, eps: &Vec<ExecProberRef>, buf: util::MCRef) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, eps: &Vec<ExecProberRef>, buf: util::MCRef, args: Vec<String>) -> ExecResult<(Box<Exec>, Vec<String>)>;
}

pub type ExecProberRef = &'static (ExecProber+'static);

pub struct ProbeResult {
    pub desc: String,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: Vec<String>,
}

pub fn probe_all(eps: &Vec<ExecProberRef>, buf: util::MCRef) -> Vec<ProbeResult> {
    let mut result = vec!();
    for epp in eps.iter() {
        result.extend(epp.probe(eps, buf.clone()).into_iter());
    }
    result
}

pub fn create(eps: &Vec<ExecProberRef>, buf: util::MCRef, mut args: Vec<String>) -> ExecResult<(Box<Exec+'static>, Vec<String>)> {
    let prober_name = args.remove(0);
    if prober_name == "auto" {
        return create_auto(eps, buf, args);
    }
    for epp in eps.iter() {
        if epp.name() == prober_name {
            return epp.create(eps, buf, args);
        }
    }
    panic!("no format named {}", prober_name)
}

fn create_auto(eps: &Vec<ExecProberRef>, buf: util::MCRef, args: Vec<String>) -> ExecResult<(Box<Exec+'static>, Vec<String>)> {
    // TODO: error conversion
    let m = util::do_getopts_or_panic(&*args, "auto [--arch arch]", 0, std::usize::MAX, &mut vec![
        getopts::optopt("", "arch", "Architecture bias", "arch"),
    ]);
    let mut results = probe_all(eps, buf.clone());
    if let Some(arch_str) = m.opt_str("arch") {
        let arch: Arch = FromStr::from_str(&*arch_str).unwrap();
        for pr in results.iter_mut() {
            if pr.likely && pr.arch == arch {
                return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
            }
        }
    }
    for pr in results.iter_mut() {
        if pr.likely {
            return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
        }
    }
    for pr in results.iter_mut() {
        return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
    }
    panic!("create_auto: no formats, not even raw_binary??");

}

pub fn addr_to_off(segs: &[Segment], addr: VMA, len: u64) -> Option<u64> {
    for seg in segs {
        if addr >= seg.vmaddr && addr - seg.vmaddr < seg.vmsize && seg.vmsize - (addr - seg.vmaddr) >= len {
            return Some(seg.fileoff + (addr - seg.vmaddr));
        }
    }
    None
}

pub fn off_to_addr(segs: &[Segment], off: u64, len: u64) -> Option<VMA> {
    for seg in segs {
        if off >= seg.fileoff && off - seg.fileoff < seg.filesize && seg.filesize - (off - seg.fileoff) >= len {
            return Some(seg.vmaddr + (off - seg.fileoff));
        }
    }
    None
}

pub fn addr_to_seg_off_range(segs: &[Segment], addr: VMA) -> Option<(&Segment, u64, u64)> {
    for seg in segs {
        if addr >= seg.vmaddr && addr - seg.vmaddr < seg.vmsize {
            return Some((seg, addr - seg.vmaddr, seg.vmsize - (addr - seg.vmaddr)));
        }
    }
    None
}
