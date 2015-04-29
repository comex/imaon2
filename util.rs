#![feature(plugin)]
#![plugin(regex_macros)]
#![feature(libc, collections)]

extern crate libc;
extern crate bsdlike_getopts as getopts;

extern crate regex;
#[macro_use]
extern crate macros;
extern crate collections;

use std::mem::{size_of, uninitialized, transmute};
use std::ptr::{copy, null_mut};
use std::sync::Arc;
use std::default::Default;
use std::io::{SeekFrom, Seek};
use std::os::unix::prelude::AsRawFd;
use std::num::ParseIntError;

pub use Endian::*;
//use std::ty::Unsafe;

pub fn copy_from_slice<T: Copy + Swap>(slice: &[u8], end: Endian) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = uninitialized();
        copy(transmute(slice.as_ptr()), &mut t, 1);
        t.bswap_from(end);
        t
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Endian {
    BigEndian,
    LittleEndian,
}

impl Default for Endian {
    fn default() -> Endian { BigEndian }
}

pub trait Swap {
    fn bswap(&mut self);
    fn bswap_from(&mut self, end: Endian) {
        if end == BigEndian { self.bswap() }
    }
}

macro_rules! impl_swap {($ty:ident) => {
    impl Swap for $ty {
        fn bswap(&mut self) {
            *self = self.swap_bytes();
        }
    }
    impl IntStuff for $ty {
        fn from_str_radix(src: &str, radix: u32) -> Result<$ty, ParseIntError> {
            $ty::from_str_radix(src, radix)
        }
    }
}}

macro_rules! impl_signed {($ty:ident) => {
    impl_swap!($ty);
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { Some(-self) }
    }
}}
macro_rules! impl_unsigned {($ty:ident) => {
    impl_swap!($ty);
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { None }
    }
}}

impl_unsigned!(u64);
impl_signed!(i64);
impl_unsigned!(u32);
impl_signed!(i32);
impl_unsigned!(u16);
impl_signed!(i16);

impl Swap for u8 {
    fn bswap(&mut self) {}
}
impl Swap for i8 {
    fn bswap(&mut self) {}
}

// dumb
macro_rules! impl_for_array{($cnt:expr) => (
    impl<T> Swap for [T; $cnt] {
        fn bswap(&mut self) {}
    }
)}
impl_for_array!(1);
impl_for_array!(2);
impl_for_array!(4);
impl_for_array!(16);
impl<T> Swap for Option<T> {
    fn bswap(&mut self) {}
}

// TODO remove this
pub trait ToUi {
    fn to_ui(&self) -> usize;
}
impl ToUi for i32 { fn to_ui(&self) -> usize { *self as usize } }
impl ToUi for u32 { fn to_ui(&self) -> usize { *self as usize } }
impl ToUi for i16 { fn to_ui(&self) -> usize { *self as usize } }
impl ToUi for u16 { fn to_ui(&self) -> usize { *self as usize } }
impl ToUi for i8 { fn to_ui(&self) -> usize { *self as usize } }
impl ToUi for u8 { fn to_ui(&self) -> usize { *self as usize } }

pub trait X8 {} //: std::marker::MarkerTrait {}
impl X8 for u8 {}
impl X8 for i8 {}

pub fn trim_to_null<T: X8>(chs_: &[T]) -> &[u8] {
    let chs: &[u8] = unsafe { transmute(chs_) };
    match chs.iter().position(|c| *c == 0) {
        None => chs,
        Some(i) => &chs[..i],
    }
}

pub fn from_cstr<T: X8>(chs_: &[T]) -> String {
    let truncated = trim_to_null(chs_);
    String::from_utf8_lossy(truncated).to_string()
}

#[derive(Clone, Default)]
pub struct MCRef {
    mm: Option<Arc<MemoryMap>>,
    off: usize,
    len: usize
}

// XXX using my own MemoryMap for now
struct MemoryMap {
    ptr: *mut u8,
    size: usize
}

impl MemoryMap {
    fn new(fd: libc::c_int, size: usize) -> MemoryMap {
        unsafe {
            let ptr = libc::mmap(0 as *mut libc::c_void, size as libc::size_t, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE, fd, 0);
            if ptr == null_mut() {
                panic!("mmap failed");
            }
            MemoryMap { ptr: transmute(ptr), size: size }
        }
    }
    fn data(&self) -> *mut u8 { self.ptr }
    fn len(&self) -> usize { self.size }
}
impl Drop for MemoryMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size as libc::size_t);
        }
    }
}


unsafe impl Send for MCRef {}

impl MCRef {
    pub fn slice(&self, from: usize, to: usize) -> MCRef {
        let len = to - from;
        if from > self.len || len > self.len - from {
            panic!("MCRef::slice: bad slice");
        }
        MCRef { mm: self.mm.clone(), off: self.off + from, len: len }
    }
    pub fn get<'a>(&'a self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts::<u8>(
            transmute(self.mm.as_ref().unwrap().data().offset(self.off as isize) as *const u8),
            self.len
        ) }
    }
    pub fn offset_in(&self, other: &MCRef) -> Option<usize> {
        match (&self.mm, &other.mm) {
            (&Some(ref mm1), &Some(ref mm2)) => {
                if (&**mm1 as *const MemoryMap) == (&**mm2 as *const MemoryMap) &&
                   other.off <= self.off && self.off <= other.off + other.len {
                    Some(self.off - other.off)
                } else { None }
            }
            _ => None
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
}

pub fn safe_mmap(fil: &mut std::fs::File) -> MCRef {
    let oldpos = fil.seek(SeekFrom::Current(0)).unwrap();
    let size = fil.seek(SeekFrom::End(0)).unwrap();
    fil.seek(SeekFrom::Start(oldpos)).unwrap();
    let rounded = std::cmp::max(size, 0x1000);
    let rsize = rounded as usize;
    if rsize as u64 != rounded {
        panic!("safe_mmap: file too big");
    }
    let fd = fil.as_raw_fd();
    /*
    XXX put back when MemoryMap is back
    let mm = MemoryMap::new(rsize, &[
        std::os::MapOption::MapReadable,
        std::os::MapOption::MapWritable,
        std::os::MapOption::MapFd(fd),
    ]).unwrap();
    */
    let mm = MemoryMap::new(fd, rsize);
    assert!(mm.len() >= size as usize);
    MCRef { mm: Some(Arc::new(mm)), off: 0, len: size as usize }
}


pub fn do_getopts(args: &[String], min_expected_free: usize, max_expected_free: usize, optgrps: &mut Vec<getopts::OptGroup>) -> Option<getopts::Matches> {
    if let Ok(m) = getopts::getopts(args, &optgrps) {
        if m.free.len() >= min_expected_free &&
            m.free.len() <= max_expected_free {
            return Some(m);
        }
    }
    None
}

pub fn do_getopts_or_panic(args: &[String], top: &str, min_expected_free: usize, max_expected_free: usize, optgrps: &mut Vec<getopts::OptGroup>) -> getopts::Matches {
    do_getopts(args, min_expected_free, max_expected_free, optgrps).unwrap_or_else(|| { usage(top, optgrps); panic!(); })
}

pub fn usage(top: &str, optgrps: &mut Vec<getopts::OptGroup>) {
    optgrps.push(getopts::optflag("h", "help", "This help"));
    println!("{}", getopts::usage(top, &optgrps));
}

pub fn exit() -> ! {
    unsafe { libc::exit(1) }
}

fn isprint(c: char) -> bool {
    let c = c as u32;
    if c >= 32 { c < 127 } else { (1 << c) & 0x3e00 != 0 }
}

pub fn shell_quote(args: &[String]) -> String {
    let mut sb = std::string::String::new();
    for arg_ in args.iter() {
        let arg = &arg_[..];
        if sb.len() != 0 { sb.push(' ') }
        if regex!(r"^[a-zA-Z0-9_\.@/+-]+$").is_match(arg) {
            sb.push_str(arg);
        } else {
            sb.push('"');
            for ch_ in arg.as_bytes().iter() {
                let ch = *ch_ as char;
                if ch == '$' || ch == '`' || ch == '\\' || ch == '"' || ch == '\n' {
                    if ch == '\n' {
                        sb.push_str("\\n");
                    } else {
                        sb.push('\\');
                        sb.push(ch);
                    }
                } else if !isprint(ch) {
                    sb.push_str(&format!("\\\\x{:02x}", *ch_));
                } else {
                    sb.push(ch);
                }
            }
            sb.push('"');
        }
    }
    sb
}


pub trait OptionExt<T> {
    fn unwrap_ref(&self) -> &T;
}
impl<T> OptionExt<T> for Option<T> {
    fn unwrap_ref(&self) -> &T { self.as_ref().unwrap() }
}

pub trait VecStrExt {
    fn strings(&self) -> Vec<String>;
}
impl<T: std::string::ToString> VecStrExt for Vec<T> {
    fn strings(&self) -> Vec<String> { self.iter().map(|x| x.to_string()).collect() }
}

pub trait IntStuffSU {
    fn neg_if_possible(self) -> Option<Self>;
}

pub trait IntStuff : IntStuffSU {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;
}


pub fn stoi<T: IntStuff>(mut s: &str) -> Option<T> {
    if s == "" { return None; }
    let neg = &s[..1] == "-";
    if neg { s = &s[1..]; }
    let mut base = 10;
    if s.len() > 2 && &s[2..3] != "-" {
        let prefix = &s[..2];
        if prefix == "0x" {
            base = 16;
            s = &s[2..];
        } else if prefix == "0b" {
            base = 2;
            s = &s[2..];
        } else if prefix == "0o" {
            base = 8;
            s = &s[2..];
        }
    }
    let result = IntStuff::from_str_radix(s, base);
    let mut result = result.ok();
    if neg { result = result.and_then(|x: T| x.neg_if_possible()); }
    result
}

#[test]
fn test_branch() {
    let do_i = |i: usize| {
        branch!(if i == 1 {
            // Due to rustc being a piece of shit, ... I don't even.  You can only have one `let` (or any expression-as-statement), so make it count.  Maybe tomorrow I will figure this out.  Such a waste of time...
            type A = isize;
            type B = isize;
            let (b, c) = (7usize, 8)
        } else {
            type A = usize;
            type B = usize;
            let (b, c) = (8usize, 9)
        } then {
            println!("{}", (b + c) as A);
        })
    };
    for i in range(0, 2) {
        do_i(i)
    }
}

