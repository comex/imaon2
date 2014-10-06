#![feature(macro_rules)]
#![feature(phase)]

extern crate native;
extern crate libc;
extern crate "bsdlike_getopts" as getopts;
extern crate sync;

extern crate regex;
#[phase(plugin)]
extern crate regex_macros;
#[phase(plugin)]
extern crate macros;
extern crate collections;

use std::kinds::Copy;
use std::mem::{size_of, uninitialized, transmute};
use std::ptr::{copy_memory, zero_memory};
use std::rc::Rc;
use sync::Arc;
use std::cell::Cell;
use std::intrinsics;
use std::default::Default;
use native::io::file;
use std::os::MemoryMap;
use std::rt::rtio;
use std::rt::rtio::RtioFileStream;
//use std::ty::Unsafe;

pub fn copy_from_slice<T: Copy + Swap>(slice: &[u8], end: Endian) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = uninitialized();
        copy_memory(&mut t, transmute(slice.as_ptr()), 1);
        t.bswap_from(end);
        t
    }
}

// derp
struct RcBox<T> {
    value: T,
    strong: Cell<uint>,
    weak: Cell<uint>
}

#[inline]
pub fn get_mut_if_nonshared<'a, T>(rc: &'a mut Rc<T>) -> Option<&'a mut T> {
    unsafe {
        let bp : *const *mut RcBox<T> = transmute(rc);
        if (**bp).strong.get() == 1 && (**bp).weak.get() == 1 {
            Some(&mut (**bp).value)
        } else {
            None
        }
    }
}

#[test]
#[allow(unused_variable)]
fn test_gmin() {
    let mut a: Rc<int> = Rc::new(42);
    assert!(!get_mut_if_nonshared(&mut a).is_none());
    let b = a.clone();
    assert!(get_mut_if_nonshared(&mut a).is_none());
}

#[inline]
pub fn bswap64(x: u64) -> u64 {
    unsafe { intrinsics::bswap64(x) }
}
#[inline]
pub fn bswap32(x: u32) -> u32 {
    unsafe { intrinsics::bswap32(x) }
}
#[inline]
pub fn bswap16(x: u16) -> u16 {
    unsafe { intrinsics::bswap16(x) }
}

#[deriving(Show, PartialEq, Eq)]
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

macro_rules! impl_swap(
    ($ty:ty, $bsty:ty, $bsfun:ident) => (
        impl Swap for $ty {
            fn bswap(&mut self) {
                *self = $bsfun(*self as $bsty) as $ty;
            }
        }
    )
)

impl_swap!(u64, u64, bswap64)
impl_swap!(i64, u64, bswap64)
impl_swap!(u32, u32, bswap32)
impl_swap!(i32, u32, bswap32)
impl_swap!(u16, u16, bswap16)
impl_swap!(i16, u16, bswap16)

impl Swap for u8 {
    fn bswap(&mut self) {}
}
impl Swap for i8 {
    fn bswap(&mut self) {}
}

// dumb
macro_rules! impl_for_array(($cnt:expr) => (
    impl<T> Swap for [T, ..$cnt] {
        fn bswap(&mut self) {}
    }
))
impl_for_array!(1)
impl_for_array!(2)
impl_for_array!(4)
impl_for_array!(16)
impl<T> Swap for Option<T> {
    fn bswap(&mut self) {}
}

pub unsafe fn zeroed_t<T>() -> T {
    let mut me : T = uninitialized();
    zero_memory(&mut me, 1);
    me
}

pub trait ToUi {
    fn to_ui(&self) -> uint;
}
impl<T : ToPrimitive> ToUi for T {
    fn to_ui(&self) -> uint {
        self.to_uint().unwrap()
    }
}

pub trait X8 {}
impl X8 for u8 {}
impl X8 for i8 {}

pub fn trim_to_null<T: X8>(chs_: &[T]) -> &[u8] {
    let chs: &[u8] = unsafe { transmute(chs_) };
    match chs.iter().position(|c| *c == 0) {
        None => chs,
        Some(i) => chs.slice_to(i)
    }
}

pub fn from_cstr<T: X8>(chs_: &[T]) -> String {
    let truncated = trim_to_null(chs_);
    String::from_utf8_lossy(truncated).to_string()
}

pub trait MCOwner: Send+Sync {
    fn dispose(&self, _buf: *mut u8, _len: uint) {}
}

#[deriving(Send, Clone, Default)]
pub struct MCRef {
    mm: Option<Arc<MemoryMap>>,
    off: uint,
    len: uint
}

impl MCRef {
    pub fn slice(&self, from: uint, to: uint) -> MCRef {
        let len = to - from;
        if from > self.len || len > self.len - from {
            fail!("MCRef::slice: bad slice");
        }
        MCRef { mm: self.mm.clone(), off: self.off + from, len: len }
    }
    pub fn get<'a>(&'a self) -> &'a [u8] {
        unsafe { std::slice::raw::buf_as_slice::<u8, &'a [u8]>(
            transmute(self.mm.as_ref().unwrap().data().offset(self.off as int)),
            self.len,
            |slice| transmute(slice)
        ) }
    }
    pub fn offset_in(&self, other: &MCRef) -> Option<uint> {
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
    pub fn len(&self) -> uint {
        self.len
    }
}

pub fn rtio_err_msg(e: rtio::IoError) -> String {
    format!("error {}: {}", e.code, e.detail)
}

pub trait RtioUnwrap<T> {
    fn rtio_unwrap(self) -> T;
}
impl<T> RtioUnwrap<T> for rtio::IoResult<T> {
    fn rtio_unwrap(self) -> T {
        self.map_err(rtio_err_msg).unwrap()
    }
}

pub fn safe_mmap(fd: &mut file::FileDesc) -> MCRef {
    let oldpos = fd.tell().rtio_unwrap();
    fd.seek(0, rtio::SeekEnd).rtio_unwrap();
    let size = fd.tell().rtio_unwrap();
    fd.seek(oldpos as i64, rtio::SeekSet).rtio_unwrap();
    let cfd = fd.fd();
    let size = std::cmp::max(size, 0x1000);
    let mm = MemoryMap::new(size.to_ui(), &[
        std::os::MapReadable,
        std::os::MapWritable,
        std::os::MapFd(cfd),
    ]).unwrap();
    let len = mm.len();
    MCRef { mm: Some(Arc::new(mm)), off: 0, len: len }
}


pub fn do_getopts(args: &[String], top: &str, min_expected_free: uint, max_expected_free: uint, optgrps: &mut Vec<getopts::OptGroup>) -> getopts::Matches {
    match getopts::getopts(args, optgrps.as_slice()) {
        Ok(m) => if m.free.len() >= min_expected_free &&
                    m.free.len() <= max_expected_free {
                        m
                 } else {
                   usage(top, optgrps) 
                 },
        _ => usage(top, optgrps),
    }
}

pub fn usage(top: &str, optgrps: &mut Vec<getopts::OptGroup>) -> ! {
    optgrps.push(getopts::optflag("h", "help", "This help"));
    println!("{}", getopts::usage(top, optgrps.as_slice()));
    fail!();
}

pub fn exit() -> ! {
    unsafe { libc::exit(1) }
}

pub fn errlnb(s: &str) {
    // who needs speed
    std::io::stdio::stderr().write_line(s).unwrap();
}

pub fn errln(s: String) {
    errlnb(s.as_slice())
}

pub fn shell_quote(args: &[String]) -> String {
    let mut sb = std::string::String::new();
    for arg_ in args.iter() {
        let arg = arg_.as_slice();
        if sb.len() != 0 { sb.push(' ') }
        if regex!(r"^[a-zA-Z0-9_-]+$").is_match(arg) {
            sb.push_str(arg);
        } else {
            sb.push('"');
            for ch_ in arg.as_bytes().iter() {
                let chu = *ch_;
                let ch = *ch_ as char;
                if ch == '$' || ch == '`' || ch == '\\' || ch == '"' || ch == '\n' {
                    if ch == '\n' {
                        sb.push_str("\\n");
                    } else {
                        sb.push('\\');
                        sb.push(ch);
                    }
                } else if !chu.is_ascii() || !chu.to_ascii().is_print() {
                    sb.push_str(format!("\\\\x{:02x}", chu).as_slice());
                } else {
                    sb.push(ch);
                }
            }
            sb.push('"');
        }
    }
    sb.into_string()
}


pub trait OptionExt<T> {
    fn unwrap_ref(&self) -> &T;
}
impl<T> OptionExt<T> for Option<T> {
    fn unwrap_ref(&self) -> &T { self.as_ref().unwrap() }
}

pub trait VecExt<T> {
    fn map<U>(&self, func: |&T| -> U) -> Vec<U>;
}
impl<T> VecExt<T> for Vec<T> {
    fn map<U>(&self, func: |&T| -> U) -> Vec<U> {
        self.iter().map(func).collect()
    }
}
pub trait VecStrExt {
    fn owneds(&self) -> Vec<String>;
}
impl<T: collections::str::StrAllocating> VecStrExt for Vec<T> {
    fn owneds(&self) -> Vec<String> { self.map(|x| x.to_owned()) }
}

#[test]
fn test_branch() {
    let do_i = |i: uint| {
        branch!(if i == 1 {
            // Due to rustc being a piece of shit, ... I don't even.  You can only have one `let` (or any expression-as-statement), so make it count.  Maybe tomorrow I will figure this out.  Such a waste of time...
            type A = int;@
            type B = int;@
            let (b, c) = (7u, 8)
        } else {
            type A = uint;@
            type B = uint;@
            let (b, c) = (8u, 9)
        } then {
            println!("{}", (b + c) as A);
        })
    };
    for i in range(0u, 2) {
        do_i(i)
    }
}

