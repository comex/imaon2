#![feature(libc, plugin, core_intrinsics)]

extern crate libc;
extern crate bsdlike_getopts as getopts;

#[macro_use]
extern crate macros;

use std::mem::{size_of, uninitialized, transmute};
use std::ptr::{copy, null_mut};
use std::sync::{Arc, Mutex};
use std::default::Default;
use std::io::{SeekFrom, Seek};
use std::os::unix::prelude::AsRawFd;
use std::num::ParseIntError;
use std::cmp::max;
use std::slice;
use std::fmt::{Debug, Display, Formatter};
use std::borrow::{Cow, Borrow, BorrowMut};
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeTo, RangeFull};
use std::cell::UnsafeCell;

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

pub fn copy_to_slice<T: Copy + Swap>(slice: &mut [u8], t: &T, end: Endian) {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let stp: *mut T = transmute(slice.as_ptr());
        copy(t, stp, 1);
        (*stp).bswap_from(end);
    }
}

pub fn copy_to_vec<T: Copy + Swap>(vec: &mut Vec<u8>, t: &T, end: Endian) {
    let size = size_of::<T>();
    let off = vec.len();
    assert!(off <= !0usize - size);
    unsafe {
        vec.reserve(size);
        vec.set_len(off + size);
        let stp: *mut T = transmute(vec.as_mut_ptr().offset(off as isize));
        copy(t, stp, 1);
        (*stp).bswap_from(end);
    }
}

pub fn copy_to_new_vec<T: Copy + Swap>(t: &T, end: Endian) -> Vec<u8> {
    unsafe {
        let mut res: Vec<u8> = slice::from_raw_parts(transmute(t), size_of::<T>()).to_vec();
        let newt: *mut T = transmute(res.as_mut_ptr());
        (*newt).bswap_from(end);
        res
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

pub trait CheckMath<Other, Dummy> {
    type Output;
    fn check_add(self, other: Other) -> Option<Self::Output>;
    fn check_sub(self, other: Other) -> Option<Self::Output>;
    fn check_mul(self, other: Other) -> Option<Self::Output>;
}


macro_rules! impl_int {($ty:ident) => {
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
    impl CheckMath<$ty, $ty> for $ty {
        type Output = $ty;
        #[inline]
        fn check_add(self, other: $ty) -> Option<Self::Output> {
            self.checked_add(other)
        }
        #[inline]
        fn check_sub(self, other: $ty) -> Option<Self::Output> {
            self.checked_sub(other)
        }
        #[inline]
        fn check_mul(self, other: $ty) -> Option<Self::Output> {
            self.checked_mul(other)
        }
    }
    impl_check_math_option!($ty, $ty);
}}


macro_rules! impl_signed {($ty:ident) => {
    impl_int!($ty);
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { Some(-self) }
    }
}}
macro_rules! impl_unsigned {($ty:ident) => {
    impl_int!($ty);
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { None }
    }
}}

impl_unsigned!(usize);
impl_signed!(isize);
impl_unsigned!(u64);
impl_signed!(i64);
impl_unsigned!(u32);
impl_signed!(i32);
impl_unsigned!(u16);
impl_signed!(i16);

pub trait Ext<Larger> {
    fn ext(self) -> Larger;
}
pub trait Trunc<Smaller> {
    fn trunc(self) -> Smaller;
    fn checked_trunc(self) -> Option<Smaller>;
}

macro_rules! impl_unsigned_unsigned {($sm:ident, $la:ident) => {
    impl Ext<$la> for $sm {
        fn ext(self) -> $la {
            self as $la
        }
    }
    impl Trunc<$sm> for $la {
        fn trunc(self) -> $sm {
            self as $sm
        }
        fn checked_trunc(self) -> Option<$sm> {
            let res = self as $sm;
            if res as $la == self { Some(res) } else { None }
        }
    }
}}

impl_unsigned_unsigned!(usize, u64);
impl_unsigned_unsigned!(u32, u64);
impl_unsigned_unsigned!(u16, u64);
impl_unsigned_unsigned!(u8, u64);
impl_unsigned_unsigned!(u32, usize);
impl_unsigned_unsigned!(u16, usize);
impl_unsigned_unsigned!(u8, usize);
impl_unsigned_unsigned!(u16, u32);
impl_unsigned_unsigned!(u8, u32);
impl_unsigned_unsigned!(u8, u16);


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

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteStr([u8]);
#[derive(Clone, PartialEq, Eq)]
pub struct ByteString(pub Vec<u8>);
impl ByteStr {
    #[inline]
    pub fn lossy<'a>(&'a self) -> Cow<'a, str> {
        String::from_utf8_lossy(&self.0)
    }
    #[inline]
    pub fn from_bytes(s: &[u8]) -> &ByteStr {
        unsafe { transmute(s) }
    }
    #[inline]
    pub fn from_str(s: &str) -> &ByteStr {
        ByteStr::from_bytes(s.as_bytes())
    }
    #[inline]
    pub fn from_bytes_mut(s: &mut [u8]) -> &mut ByteStr {
        unsafe { transmute(s) }
    }
    pub fn find<P>(&self, pat: u8) -> Option<usize> {
        let ptr = self.0.as_ptr();
        let chr = unsafe { memchr(ptr, pat as i32, self.0.len()) };
        if chr == 0 as *mut u8 {
            None
        } else {
            Some((chr as usize) - (ptr as usize))
        }
    }
    /*
    pub fn rfind<P>(&self, pat: P) -> Option<usize>
        where for<'b> P: Pattern<'b>,
              for<'b> <P as Pattern<'b>>::Searcher: ReverseSearcher<'b>
              */
    pub fn rfind(&self, pat: u8) -> Option<usize> {
        for i in (0..self.len()).rev() {
            if self[i] == pat {
                return Some(i);
            }
        }
        None
    }
}
pub trait SomeRange<T> {}
impl<T> SomeRange<T> for RangeTo<T> {}
impl<T> SomeRange<T> for RangeFrom<T> {}
impl<T> SomeRange<T> for Range<T> {}
impl<T> SomeRange<T> for RangeFull {}
impl<T> Index<T> for ByteStr
    where T: SomeRange<usize>, [u8]: Index<T> {
    type Output = ByteStr;
    #[inline]
    fn index(&self, idx: T) -> &Self::Output {
        unsafe { ByteStr::from_bytes(transmute(&self.0[idx])) }
    }
}
impl<T> IndexMut<T> for ByteStr
    where T: SomeRange<usize>, [u8]: IndexMut<T> {
    #[inline]
    fn index_mut(&mut self, idx: T) -> &mut Self::Output {
        unsafe { ByteStr::from_bytes_mut(transmute(&mut self.0[idx])) }
    }
}
impl Index<usize> for ByteStr {
    type Output = u8;
    #[inline]
    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}
impl IndexMut<usize> for ByteStr {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}
impl ByteString {
    pub fn from_bytes(s: &[u8]) -> Self {
        ByteString(s.to_owned())
    }
    pub fn from_str(s: &str) -> ByteString {
        ByteString::from_bytes(s.as_bytes())
    }
    pub fn from_vec(s: Vec<u8>) -> ByteString {
        ByteString(s)
    }
    pub fn from_string(s: String) -> ByteString {
        ByteString(s.into_bytes())
    }
}
impl Deref for ByteString {
    type Target = ByteStr;
    fn deref(&self) -> &ByteStr { unsafe { transmute::<&[u8], &ByteStr>(&self.0[..]) } }
}
impl DerefMut for ByteString {
    fn deref_mut(&mut self) -> &mut ByteStr { unsafe { transmute::<&mut [u8], &mut ByteStr>(&mut self.0[..]) } }
}
impl Deref for ByteStr {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}
impl DerefMut for ByteStr {
    fn deref_mut(&mut self) -> &mut [u8] { &mut self.0 }
}
impl Debug for ByteStr {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Debug::fmt(&self.lossy()[..], f)
    }
}
impl Display for ByteStr {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&self.lossy()[..], f)
    }
}
impl Debug for ByteString {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Debug::fmt(&**self, f)
    }
}
impl Display for ByteString {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&**self, f)
    }
}
impl Borrow<ByteStr> for ByteString {
    #[inline]
    fn borrow(&self) -> &ByteStr {
        &**self
    }
}
impl BorrowMut<ByteStr> for ByteString {
    #[inline]
    fn borrow_mut(&mut self) -> &mut ByteStr {
        &mut **self
    }
}
impl ToOwned for ByteStr {
    type Owned = ByteString;
    fn to_owned(&self) -> ByteString {
        ByteString(self.0.to_owned())
    }
}
impl<'a> From<&'a ByteStr> for Cow<'a, ByteStr> {
    fn from(s: &'a ByteStr) -> Self {
        Cow::Borrowed(s)
    }
}
impl<'a> From<ByteString> for Cow<'a, ByteStr> {
    fn from(s: ByteString) -> Self {
        Cow::Owned(s)
    }
}

pub trait X8 {} //: std::marker::MarkerTrait {}
impl X8 for u8 {}
impl X8 for i8 {}

#[inline]
pub fn from_cstr<T: X8>(chs: &[T]) -> &ByteStr {
    let chs: &[u8] = unsafe { transmute(chs) };
    let len = unsafe { strnlen(chs.as_ptr(), chs.len()) };
    ByteStr::from_bytes(&chs[..len])
}

#[inline]
pub fn from_cstr_strict<T: X8>(chs: &[T]) -> Option<&ByteStr> {
    let chs: &[u8] = unsafe { transmute(chs) };
    let len = unsafe { strnlen(chs.as_ptr(), chs.len()) };
    if len == chs.len() {
        None
    } else {
        Some(ByteStr::from_bytes(&chs[..len]))
    }
}


// XXX using my own MemoryMap for now
pub struct MemoryMap {
    ptr: *mut u8,
    len: usize
}

impl MemoryMap {
    pub fn with_fd_size(fd: Option<libc::c_int>, size: usize) -> MemoryMap {
        if size > std::usize::MAX - 0x1000 {
            panic!("MemoryMap::with_fd_size: size {} too big", size);
        }
        let rsize = max(size, 1);
        unsafe {
            let anon = if fd.is_some() { 0 } else { libc::MAP_ANON };
            let ptr = libc::mmap(0 as *mut libc::c_void, rsize as libc::size_t, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | anon, fd.unwrap_or(0), 0);
            if ptr == null_mut() {
                panic!("mmap failed");
            }
            MemoryMap { ptr: transmute(ptr), len: size }
        }
    }
    pub fn data(&self) -> *mut u8 { self.ptr }
    pub fn len(&self) -> usize { self.len }
    pub fn get_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut::<u8>(self.ptr, self.len) }
    }
}
impl Drop for MemoryMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len as libc::size_t);
        }
    }
}

#[derive(Clone)]
pub struct MCRef {
    mm: Option<Arc<MemoryMap>>,
    ptr: *mut u8,
    len: usize
}

unsafe impl Send for MCRef {}

impl std::default::Default for MCRef {
    fn default() -> MCRef {
        MCRef::empty()
    }
}

impl Debug for MCRef {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "MCRef({:?}, {})", self.ptr, self.len)
    }
}

impl MCRef {
    pub fn with_data(data: &[u8]) -> MCRef {
        let mut mm = MemoryMap::with_fd_size(None, data.len());
        copy_memory(data, mm.get_mut());
        MCRef::with_mm(mm)
    }

    pub fn with_mm(mm: MemoryMap) -> MCRef {
        let ptr = mm.data();
        let len = mm.len();
        MCRef {
            mm: Some(Arc::new(mm)),
            ptr: ptr,
            len: len
        }
    }

    #[inline]
    pub fn empty() -> MCRef {
        MCRef { mm: None, ptr: 0 as *mut u8, len: 0 }

    }

    pub fn slice(&self, from: usize, to: usize) -> Option<MCRef> {
        let len = to - from;
        if from > self.len || len > self.len - from {
            return None
        }
        unsafe {
            Some(MCRef { mm: self.mm.clone(), ptr: self.ptr.offset(from as isize), len: len })
        }
    }

    pub fn get(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts::<u8>(self.ptr, self.len) }
    }
    pub fn offset_in(&self, other: &MCRef) -> Option<usize> {
        let mine = self.ptr as usize;
        let theirs = other.ptr as usize;
        if mine >= theirs && mine < theirs + max(other.len, 1) {
            Some(mine - theirs)
        } else { None }
    }
    pub fn len(&self) -> usize {
        self.len
    }
}

pub fn safe_mmap(fil: &mut std::fs::File) -> MCRef {
    let oldpos = fil.seek(SeekFrom::Current(0)).unwrap();
    let size = fil.seek(SeekFrom::End(0)).unwrap();
    fil.seek(SeekFrom::Start(oldpos)).unwrap();
    let fd = fil.as_raw_fd();
    /*
    XXX put back when MemoryMap is back
    let mm = MemoryMap::new(rsize, &[
        std::os::MapOption::MapReadable,
        std::os::MapOption::MapWritable,
        std::os::MapOption::MapFd(fd),
    ]).unwrap();
    */
    if size > std::usize::MAX as u64 {
        panic!("safe_mmap: size {} too big", size);
    }
    MCRef::with_mm(MemoryMap::with_fd_size(Some(fd), size as usize))
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

pub fn do_getopts_or_usage(args: &[String], top: &str, min_expected_free: usize, max_expected_free: usize, optgrps: &mut Vec<getopts::OptGroup>) -> Result<getopts::Matches, String> {
    do_getopts(args, min_expected_free, max_expected_free, optgrps).ok_or_else(|| { usage(top, optgrps) })
}

pub fn usage(top: &str, optgrps: &mut Vec<getopts::OptGroup>) -> String {
    optgrps.push(getopts::optflag("h", "help", "This help"));
    getopts::usage(top, &optgrps)
}

pub fn exit() -> ! {
    unsafe { libc::exit(1) }
}

fn isprint(c: char) -> bool {
    let c = c as u32;
    if c >= 32 { c < 127 } else { (1 << c) & 0x3e00 != 0 }
}

fn shell_safe(c: char) -> bool {
    match c {
        'a' ... 'z' | 'A' ... 'Z' | '0' ... '9' |
        '_' | '\\' | '.' | '@' | '/' | '+' | '-'
          => true,
        _ => false
    }
}

pub fn shell_quote(args: &[String]) -> String {
    let mut sb = std::string::String::new();
    for arg_ in args.iter() {
        let arg = &arg_[..];
        if sb.len() != 0 { sb.push(' ') }
        if arg.chars().all(shell_safe) {
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
    fn and_tup<U>(self, other: Option<U>) -> Option<(T, U)>;
    fn is_some_and<P>(&self, pred: P) -> bool
        where P: FnOnce(&T) -> bool;
}
impl<T> OptionExt<T> for Option<T> {
    fn and_tup<U>(self, other: Option<U>) -> Option<(T, U)> {
        if let Some(s) = self {
            if let Some(o) = other {
                return Some((s, o));
            }
        }
        None
    }
    fn is_some_and<P>(&self, pred: P) -> bool
        where P: FnOnce(&T) -> bool {
        if let &Some(ref val) = self {
            pred(val)
        } else {
            false
        }
    }
}

pub trait SliceExt<T> {
    fn slice_opt(&self, start: usize, end: usize) -> Option<&[T]>;
}
impl<T> SliceExt<T> for [T] {
    fn slice_opt(&self, start: usize, end: usize) -> Option<&[T]> {
        let len = self.len();
        if end > len || start > end {
            None
        } else {
            unsafe { Some(std::slice::from_raw_parts(self.as_ptr().offset(start as isize), end - start)) }
        }
    }
}

pub trait VecCopyExt<T> {
    fn extend_slice(&mut self, other: &[T]);
}

impl<T: Copy> VecCopyExt<T> for Vec<T> {
    fn extend_slice(&mut self, other: &[T]) {
        unsafe {
            let ol = other.len();
            let sl = self.len();
            self.reserve(ol);
            self.set_len(sl + ol);
            copy(other.as_ptr(), self.as_mut_ptr().offset(sl as isize), ol);
        }
    }
}

pub trait VecStrExt {
    fn strings(&self) -> Vec<String>;
}
impl<T: std::string::ToString> VecStrExt for Vec<T> {
    fn strings(&self) -> Vec<String> { self.iter().map(|x| x.to_string()).collect() }
}

pub trait IntStuffSU : Sized {
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

#[derive(Debug, Clone)]
pub struct GenericError(pub String);
display_as_debug!(GenericError);
impl std::error::Error for GenericError {
    fn description(&self) -> &str { &*self.0 }
}

#[test]
fn test_branch() {
    let do_i = |i: usize| {
        branch!(if (i == 1) {
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

extern {
    fn memmove(dst: *mut u8, src: *const u8, len: usize);
    fn memset(dst: *mut u8, byte: i32, len: usize);
    fn memchr(src: *const u8, byte: i32, len: usize) -> *mut u8;
}
#[inline(always)]
unsafe fn strnlen(s: *const u8, maxlen: usize) -> usize {
    mod orig {
        extern { pub fn strnlen(s: *const u8, maxlen: usize) -> usize; }
    }
    let res = orig::strnlen(s, maxlen);
    std::intrinsics::assume(res <= maxlen);
    res
}
#[inline]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert_eq!(dst.len(), src.len());
    unsafe { memmove(dst.as_mut_ptr(), src.as_ptr(), dst.len()); }
}

pub trait XSetMemory {
    fn set_memory(&mut self, byte: u8);
}
impl XSetMemory for [u8] {
    #[inline]
    fn set_memory(&mut self, byte: u8) {
        unsafe { memset(self.as_mut_ptr(), byte as i32, self.len()); }
    }
}

pub fn into_cow<'a, T: ?Sized + ToOwned, S: Into<Cow<'a, T>>>(s: S) -> Cow<'a, T> {
    s.into()
}

enum MyOption<T> {
    None,
    _Fake(u8), // no optimization please
    Some(T)
}

pub struct Lazy<T> {
    mtx: Mutex<()>,
    val: UnsafeCell<MyOption<T>>, // bah, this extra wrap shouldn't be necessary
}
impl<T> Lazy<T> {
    pub fn new() -> Lazy<T> {
        Lazy { mtx: Mutex::new(()), val: UnsafeCell::new(MyOption::None) }
    }
    pub fn get<F>(&self, f: F) -> &T where F: FnOnce() -> T {
        unsafe {
            let ptr = self.val.get();
            if let MyOption::Some(ref t) = *ptr {
                t
            } else {
                {
                    let _guard = self.mtx.lock().unwrap();
                    *ptr = MyOption::Some(f());
                }
                if let MyOption::Some(ref t) = *ptr {
                    t
                } else {
                    panic!("wtf")
                }
            }
        }
    }
}
