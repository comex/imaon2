#![feature(macro_rules)]

extern crate native;
extern crate libc;
extern crate getopts;

use std::kinds::Copy;
use std::mem::{size_of, uninit};
use std::ptr::{copy_memory, zero_memory};
use std::cast::transmute;
use std::rc::Rc;
use std::cell::Cell;
use std::intrinsics;
use std::default::Default;
use native::io::file;
use std::os::MemoryMap;
use std::rt::rtio::RtioFileStream;

pub fn copy_from_slice<T: Copy + Swap>(slice: &[u8], end: Endian) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = uninit();
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
        let bp : **mut RcBox<T> = transmute(rc);
        if (**bp).strong.get() == 1 && (**bp).weak.get() == 1 {
            Some(&'a mut (**bp).value)
        } else {
            None
        }
    }
}

#[test]
#[allow(unused_variable)]
fn test_gmin() {
    let mut a = Rc::new(42);
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

#[deriving(Show, Eq)]
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
    let mut me : T = uninit();
    zero_memory(&mut me, size_of::<T>());
    me
}

// The usage could be prettier as an attribute / syntax extension, but this is drastically less ugly.
#[macro_escape]
#[macro_export]
macro_rules! deriving_swap(
    (
        $(twin $twin:ident)*
        pub struct $name:ident {
            $(
                pub $field:ident: $typ:ty
            ),+
            $(,)*
        }
        $($etc:item)*
    ) => (
        pub struct $name {
            $(
                pub $field: $typ
            ),+
        }
        impl Swap for $name {
            fn bswap(&mut self) {
                $(
                    self.$field.bswap();
                )+
            }
        }
        impl Default for $name {
            fn default() -> $name {
                unsafe { zeroed_t() }
            }
        }
        $($etc)*
    )
)

#[macro_escape]
#[macro_export]
macro_rules! branch(
    (if $cond:expr { $($a:stmt)|* } else { $($b:stmt)|* } then $c:expr) => (
        if $cond {
            $($a);*; $c
        } else {
            $($b);*; $c
        }
    )
)

#[test]
fn test_branch() {
    for i in range(0, 2) {
        branch!(if i == 1 {
            // Due to rustc being a piece of shit, ... I don't even.  You can only have one `let` (or any expression-as-statement), so make it count.  Maybe tomorrow I will figure this out.  Such a waste of time...
            type A = int;|
            let (b, c) = (7, 8)
        } else {
            type A = uint;|
            let (b, c) = (8, 9)
        } then {
            println!("{}", (b + c) as A);
        })
    }
}


pub trait ToUi {
    fn to_ui(&self) -> uint;
}
impl<T : ToPrimitive> ToUi for T {
    fn to_ui(&self) -> uint {
        self.to_uint().unwrap()
    }
}

pub fn from_cstr(chs: &[i8]) -> ~str {
    let chs_: &[char] = unsafe { transmute(chs) };
    let s = std::str::from_chars(chs_);
    match s.find('\0') {
        None => s,
        Some(i) => s.slice_to(i).to_owned()
    }
}

pub trait EmptyTrait {}
impl EmptyTrait for MemoryMap {}

pub struct MemoryContainer<'a> {
    pub buf: &'a mut [u8],
    owner: ~EmptyTrait,
}

pub fn safe_mmap(fd: &mut file::FileDesc) -> MemoryContainer {
    let oldpos = fd.tell().unwrap();
    fd.seek(0, std::io::SeekEnd).unwrap();
    let size = fd.tell().unwrap();
    fd.seek(oldpos as i64, std::io::SeekSet).unwrap();
    let cfd = fd.fd();
    let size = std::cmp::max(size, 0x1000);
    let mm = MemoryMap::new(size.to_ui(), &[
        std::os::MapReadable,
        std::os::MapWritable,
        std::os::MapFd(cfd),
    ]).unwrap();
    MemoryContainer {
        buf: unsafe { std::slice::raw::mut_buf_as_slice(mm.data, mm.len, |slice| transmute(slice)) },
        owner: ~mm as ~EmptyTrait,
    }
}


pub fn do_getopts(top: &str, expected_free: uint, optgrps: &[getopts::OptGroup]) -> getopts::Matches {
    match getopts::getopts(std::os::args().tail().as_slice(), optgrps) {
        Ok(m) => if !m.opt_present("help") && m.free.len() == expected_free
                 { m } else { usage(top, optgrps) },
        _ => usage(top, optgrps),
    }
}

pub fn usage(top: &str, optgrps: &[getopts::OptGroup]) -> ! {
    println!("{}", getopts::usage(top, optgrps));
    exit();
}

pub fn exit() -> ! {
    unsafe { libc::exit(1) }
}

pub fn errlnb(s: &str) {
    // who needs speed
    std::io::stdio::stderr().write_line(s).unwrap();
}

pub fn errln(s: ~str) {
    errlnb(s.as_slice())
}

#[macro_escape]
#[macro_export]
macro_rules! delegate_arith(($stru:ident, $traitname:ident, $methname:ident, $oty:ty) => (
    impl $traitname<$oty, $stru> for $stru {
        fn $methname(&self, rhs: &$oty) -> $stru {
            let $stru(a) = *self;
            $stru(a.$methname(rhs))
        }
    }
))

