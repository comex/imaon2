#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
extern crate libc;
extern crate bsdlike_getopts as getopts;
extern crate memmap;
use memmap::Mmap;

#[macro_use]
extern crate macros;

use std::mem::{size_of, uninitialized, transmute, transmute_copy, replace, forget};
use std::ptr;
use std::ptr::copy;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::default::Default;
use std::num::ParseIntError;
use std::cmp;
use std::cmp::max;
use std::slice;
use std::fmt::{Debug, Display, Formatter};
use std::borrow::{Cow, Borrow, BorrowMut};
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeTo, RangeFull, Add};
use std::cell::{UnsafeCell, Cell};
use std::marker::PhantomData;
use std::hash::{Hash, BuildHasherDefault};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::iter::FromIterator;

extern crate fnv;
use fnv::FnvHasher;
extern crate nodrop;
use nodrop::NoDrop;

//use std::ty::Unsafe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signedness {
    Unsigned,
    Signed,
}
pub use Signedness::*;
display_as_debug!(Signedness);
impl Signedness {
    pub fn with_bool(is_signed: bool) -> Self {
        if is_signed { Signed } else { Unsigned }
    }
}

mod trivial_hasher;
pub use trivial_hasher::*;

mod small_vector;
pub use small_vector::SmallVector;

pub struct ReadCell<T: Copy> {
    pub value: UnsafeCell<T>
}
impl<T: Copy> ReadCell<T> {
    #[inline]
    pub /*const*/ fn new(value: T) -> Self {
        ReadCell { value: UnsafeCell::new(value) }
    }
    #[inline]
    pub fn get(&self) -> T {
        unsafe { *self.value.get() }
    }
    // shortcut - can't do this for Cell though
    #[inline]
    pub fn copy<U>(&self, endian: Endian) -> U where U: Swap, T: Is<T=Unswapped<U>> {
        self.get().concretify().copy(endian)

    }
}
// really this should be copy, but lolrust
impl<T: Copy> Clone for ReadCell<T> {
    fn clone(&self) -> Self {
        ReadCell::new(self.get())
    }
}

pub unsafe trait ROSlicePtr<T> {
    fn as_ptr(&self) -> *const T;
    fn len(&self) -> usize;
}
pub unsafe trait RWSlicePtr<'a, T>: Sized {
    fn as_mut_ptr(self) -> *mut T;
    fn len(&self) -> usize;
    #[inline]
    fn set_memory(self, byte: u8) where T: Swap {
        let len = self.len();
        unsafe { memset(self.as_mut_ptr() as *mut u8, byte as i32, len * size_of::<T>()); }
    }
}
macro_rules! impl_rosp { ($T:ident, $ty:ty) => {
    unsafe impl<$T> ROSlicePtr<$T> for $ty where $T: Copy {
        #[inline(always)]
        fn as_ptr(&self) -> *const T {
            unsafe { transmute(self.as_ptr()) }
        }
        #[inline(always)]
        fn len(&self) -> usize { self.len() }
    }
} }
macro_rules! impl_rwsp { ($T:ident, $ty:ty) => {
    unsafe impl<'a, $T> RWSlicePtr<'a, $T> for $ty where $T: Copy {
        #[inline(always)]
        fn as_mut_ptr(self) -> *mut $T {
            unsafe { transmute(self.as_ptr()) }
        }
        #[inline(always)]
        fn len(&self) -> usize { (**self).len() }
    }
} }

impl_rosp!(T, [T]);
impl_rosp!(T, [Cell<T>]);
impl_rosp!(T, [ReadCell<T>]);

impl_rwsp!(T, &'a [Cell<T>]);
impl_rwsp!(T, &'a mut [T]);

#[inline]
pub fn copy_from_slice<'a, T: Copy + Swap, S: ?Sized + ROSlicePtr<u8>>(slice: &S, end: Endian) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = uninitialized();
        copy(transmute(slice.as_ptr()), &mut t, 1);
        t.bswap_from(end);
        t
    }
}

#[inline]
pub fn copy_to_slice<'a, T: Copy + Swap, S: RWSlicePtr<'a, u8>>(slice: S, t: &T, end: Endian) {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let stp: *mut T = transmute(slice.as_mut_ptr());
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

pub fn copy_to_new_vec<T: Swap>(t: &T, end: Endian) -> Vec<u8> {
    unsafe {
        let mut res: Vec<u8> = slice::from_raw_parts(transmute(t), size_of::<T>()).to_vec();
        let newt: *mut T = transmute(res.as_mut_ptr());
        (*newt).bswap_from(end);
        res
    }
}

#[derive(Clone, Copy)]
pub struct Unswapped<T: Swap> {
    pub unswapped: T,
}
impl<T: Swap> Swap for Unswapped<T> {
    #[inline]
    fn bswap(&mut self) {}
}

impl<T: Swap> Unswapped<T> {
    pub fn copy(&self, endian: Endian) -> T {
        let mut result = self.unswapped;
        result.bswap_from(endian);
        result
    }
}

pub trait Is {
    type T;
    #[inline(always)]
    fn concretify(self) -> Self::T where Self: Sized, Self::T: Sized {
        let res = unsafe { transmute_copy(&self) };
        forget(self);
        res
    }
}
impl<T> Is for T { type T = T; }

pub trait Cast<Other, Dummy>: Sized {
    type SelfBase: Swap;
    type OtherBase: Swap;
    fn _len(&self) -> usize;
    unsafe fn raw_cast(self) -> Other;

    #[inline]
    fn cast_to_u8(self) -> Other where Self::OtherBase: Is<T=u8> {
        unsafe { self.raw_cast() }
    }
    fn cast<U>(self) -> (Other, usize /*slack*/) where Self::SelfBase: Swap, U: Swap, Self::OtherBase: Is<T=Unswapped<U>> {
        let len = self._len();
        (unsafe { self.raw_cast() },
         len * size_of::<Self::SelfBase>() % size_of::<Self::OtherBase>())
    }
}

impl<'a, T: Swap, U: Swap> Cast<&'a [U], ()> for &'a [T] {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> &'a [U] {
        let len = self.len();
        slice::from_raw_parts(
            transmute(self.as_ptr()),
            len * size_of::<T>() / size_of::<U>()
        )
    }
}
impl<'a, T: Swap, U: Swap> Cast<&'a mut [U], ()> for &'a mut [T] {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> &'a mut [U] {
        let len = self.len();
        slice::from_raw_parts_mut(
            transmute(self.as_ptr()),
            len * size_of::<T>() / size_of::<U>()
        )
    }
}

pub fn downgrade<T: Copy>(a: &[Cell<T>]) -> &[ReadCell<T>] {
    unsafe { transmute(a) }
}

// These two impls cannot conflict with the generic read-only slice impl because of the Copy bound.
// ...But rustc thinks they do, hence the dummy parameter.  In the future, hack around this with
// specialization instead.
impl<'a, T: Swap, U: Swap> Cast<&'a [Cell<U>], i8> for &'a [Cell<T>] {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> &'a [Cell<U>] {
        let len = self.len();
        slice::from_raw_parts(
            transmute(self.as_ptr()),
            len * size_of::<T>() / size_of::<U>()
        )
    }
}
impl<'a, T: Swap, U: Swap> Cast<&'a [ReadCell<U>], i8> for &'a [ReadCell<T>] {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> &'a [ReadCell<U>] {
        let len = self.len();
        slice::from_raw_parts(
            transmute(self.as_ptr()),
            len * size_of::<T>() / size_of::<U>()
        )
    }
}
impl<'a, T: Swap, U: Swap> Cast<&'a [ReadCell<U>], i8> for &'a [Cell<T>] {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> &'a [ReadCell<U>] {
        let len = self.len();
        slice::from_raw_parts(
            transmute(self.as_ptr()),
            len * size_of::<T>() / size_of::<U>()
        )
    }
}
impl<T: Swap, U: Swap> Cast<Mem<U>, ()> for Mem<T> {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len }
    #[inline]
    unsafe fn raw_cast(self) -> Mem<U> {
        Mem {
            mc: self.mc,
            ptr: transmute(self.ptr),
            len: (self.len * size_of::<T>()) / size_of::<U>(),
        }
    }
}

impl<T: Swap, U: Swap> Cast<Vec<U>, ()> for Vec<T> {
    type SelfBase = T;
    type OtherBase = U;
    fn _len(&self) -> usize { self.len() }
    #[inline]
    unsafe fn raw_cast(self) -> Vec<U> {
        let (ptr, len, cap) = (self.as_ptr(), self.len(), self.capacity());
        let (sizeof_t, sizeof_u) = (size_of::<T>(), size_of::<U>());
        if cap * sizeof_t % sizeof_u != 0 {
            panic!("vec raw cast can't have slack since allocation might get wonky")
        }
        forget(self);
        Vec::from_raw_parts(transmute(ptr),
                            (len * sizeof_t) / sizeof_u,
                            (cap * sizeof_t) / sizeof_u)
    }
}


#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Endian {
    BigEndian,
    LittleEndian,
}
pub use Endian::*;

impl Default for Endian {
    fn default() -> Endian { BigEndian }
}

impl Endian {
    #[inline(always)]
    pub fn needs_swap(self) -> bool {
        self == BigEndian
    }
}

pub trait Swap: Copy {
    fn bswap(&mut self);
    #[inline]
    fn bswap_from(&mut self, end: Endian) {
        if end == BigEndian { self.bswap() }
    }
}

pub trait CheckAdd<Other, DummyForCoherence> {
    type Output;
    fn check_add(self, other: Other) -> Option<Self::Output>;
}
pub trait CheckSub<Other, DummyForCoherence> {
    type Output;
    fn check_sub(self, other: Other) -> Option<Self::Output>;
}
pub trait CheckMul<Other, DummyForCoherence> {
    type Output;
    fn check_mul(self, other: Other) -> Option<Self::Output>;
}


macro_rules! impl_int {($ty:ident) => {
    impl Swap for $ty {
        #[inline]
        fn bswap(&mut self) {
            *self = self.swap_bytes();
        }
    }
    impl IntStuff for $ty {
        fn from_str_radix(src: &str, radix: u32) -> Result<$ty, ParseIntError> {
            $ty::from_str_radix(src, radix)
        }
        fn align_up_to(self, size: $ty) -> $ty {
            let mask = size - 1;
            (self + mask) & !mask
        }
    }
    impl CheckAdd<$ty, $ty> for $ty {
        type Output = $ty;
        #[inline]
        fn check_add(self, other: $ty) -> Option<Self::Output> {
            self.checked_add(other)
        }
    }
    impl CheckSub<$ty, $ty> for $ty {
        type Output = $ty;
        #[inline]
        fn check_sub(self, other: $ty) -> Option<Self::Output> {
            self.checked_sub(other)
        }
    }
    impl CheckMul<$ty, $ty> for $ty {
        type Output = $ty;
        #[inline]
        fn check_mul(self, other: $ty) -> Option<Self::Output> {
            self.checked_mul(other)
        }
    }
    impl_check_x_option!(CheckAdd, check_add, $ty, $ty);
    impl_check_x_option!(CheckSub, check_sub, $ty, $ty);
    impl_check_x_option!(CheckMul, check_mul, $ty, $ty);
}}

pub trait ExtWrapper: Sized {
    #[inline(always)]
    fn ext_usize(self) -> usize where Self: Ext<usize> { self.ext() }
}
impl<T> ExtWrapper for T {}

pub trait TryExt<Larger> {
    fn try_ext(self) -> Option<Larger>;
}

pub trait Ext<Larger>: SignExtend<Larger> {
    fn ext(self) -> Larger;
}
pub trait SignExtend<Larger> {
    fn sign_extend(self, bits: u8) -> Larger;
}
pub trait Narrow<Smaller> {
    fn trunc(self) -> Smaller;
    fn narrow(self) -> Option<Smaller>;
}
pub trait UnSignExtend<Smaller> {
    fn un_sign_extend(self, bits: u8) -> Option<Smaller> where Self: Unsigned, Smaller: Unsigned;
}

macro_rules! impl_unsigned_unsigned {($sm:ident, $la:ident) => {
    impl Ext<$la> for $sm {
        #[inline(always)]
        fn ext(self) -> $la {
            self as $la
        }
    }
    impl Narrow<$sm> for $la {
        #[inline(always)]
        fn trunc(self) -> $sm {
            self as $sm
        }
        #[inline(always)]
        fn narrow(self) -> Option<$sm> {
            let res = self as $sm;
            if res as $la == self { Some(res) } else { None }
        }
    }
    impl_unsigned_unsigned_orself!($sm, $la);
}}

macro_rules! impl_unsigned_unsigned_orself {($sm:ident, $la:ident) => {
    impl SignExtend<$la> for $sm {
        #[inline(always)]
        fn sign_extend(self, bits: u8) -> $la where Self: Unsigned, $la: Unsigned {
            let x = self as $la;
            x | ((0 as $la).wrapping_sub((x >> (bits - 1)) & 1) << bits)
        }
    }
    impl UnSignExtend<$sm> for $la {
        #[inline(always)]
        fn un_sign_extend(self, bits: u8) -> Option<$sm> where Self: Unsigned, $sm: Unsigned {
            let masked = (self as $sm) & ((1 << bits) - 1);
            let x: $la = masked.sign_extend(bits);
            if x == self { Some(masked) } else { None }
        }
    }
}}

macro_rules! impl_signed_unsigned {($sm:ident, $la:ident) => {
    impl TryExt<$la> for $sm {
        #[inline(always)]
        fn try_ext(self) -> Option<$la> {
            if self >= 0 { Some(self as $la) } else { None }
        }
    }
    impl Narrow<$sm> for $la {
        #[inline(always)]
        fn trunc(self) -> $sm {
            self as $sm
        }
        #[inline(always)]
        fn narrow(self) -> Option<$sm> {
            let res = self as $sm;
            if res < 0 || res as $la == self { Some(res) } else { None }
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
impl_signed_unsigned!(i32, usize);

macro_rules! impl_signed {($ty:ident) => {
    impl_int!($ty);
    impl Signed for $ty {}
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { Some(-self) }
    }
}}
macro_rules! impl_unsigned {($ty:ident) => {
    impl_int!($ty);
    impl Unsigned for $ty {}
    impl IntStuffSU for $ty {
        fn neg_if_possible(self) -> Option<Self> { None }
    }
    impl_unsigned_unsigned_orself!($ty, $ty);
}}

impl_unsigned!(usize);
impl_signed!(isize);
impl_unsigned!(u64);
impl_signed!(i64);
impl_unsigned!(u32);
impl_signed!(i32);
impl_unsigned!(u16);
impl_signed!(i16);
impl_unsigned!(u8);
impl_signed!(i8);

pub trait X8 : Swap {}
impl X8 for u8 {}
impl X8 for i8 {}


impl<T> Swap for *mut T {
    fn bswap(&mut self) {
        let xself: &mut usize = unsafe { transmute(self) };
        xself.bswap()
    }
}
impl<T> Swap for *const T {
    fn bswap(&mut self) {
        let xself: &mut usize = unsafe { transmute(self) };
        xself.bswap()
    }
}

impl<A: Swap, B: Swap> Swap for (A, B) {
    fn bswap(&mut self) {
        self.0.bswap();
        self.1.bswap();
    }
}

// dumb
macro_rules! impl_for_array{($cnt:expr) => (
    impl<T: Swap> Swap for [T; $cnt] {
        fn bswap(&mut self) {}
    }
)}
impl_for_array!(1);
impl_for_array!(2);
impl_for_array!(3);
impl_for_array!(4);
impl_for_array!(8);
impl_for_array!(16);
impl_for_array!(20);
impl<T: Swap> Swap for Option<T> {
    fn bswap(&mut self) {}
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteStr([u8]);
#[derive(Clone, PartialEq, Eq, Hash)]
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
    pub fn find(&self, pat: u8) -> Option<usize> {
        slice_find_byte(&self.0, pat)
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
    pub fn find_bstr(&self, pat: &ByteStr) -> Option<usize> {
        let res = unsafe { memmem(self.as_ptr(), self.len(),
                                  pat.as_ptr(), pat.len()) };
        if res == 0 as *mut u8 {
            None
        } else {
            Some((res as usize) - (self.as_ptr() as usize))
        }
    }
    pub fn unix_basename(&self) -> &ByteStr {
        if let Some(pos) = self.rfind(b'/') { &self[pos+1..] } else { &self[..] }
    }
}
pub trait SomeRange<T> {}
impl<T> SomeRange<T> for RangeTo<T> {}
impl<T> SomeRange<T> for RangeFrom<T> {}
impl<T> SomeRange<T> for Range<T> {}
impl<T> SomeRange<T> for RangeFull {}
impl<T> Index<T> for ByteStr
    where T: SomeRange<usize>, [u8]: Index<T, Output=[u8]> {
    type Output = ByteStr;
    #[inline]
    fn index(&self, idx: T) -> &Self::Output {
        ByteStr::from_bytes(&self.0[idx])
    }
}
impl<T> IndexMut<T> for ByteStr
    where T: SomeRange<usize>, [u8]: IndexMut<T, Output=[u8]> {
    #[inline]
    fn index_mut(&mut self, idx: T) -> &mut Self::Output {
        ByteStr::from_bytes_mut(&mut self.0[idx])
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
    pub fn new(s: &ByteStr) -> Self {
        ByteString(s.0.to_owned())
    }
    pub fn from_bytes<S: ?Sized + ROSlicePtr<u8>>(s: &S) -> Self {
        ByteString(fast_slice_to_owned(s))
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
    pub fn with_capacity(c: usize) -> ByteString {
        ByteString(Vec::with_capacity(c))
    }
    pub fn concat2(left: &ByteStr, right: &ByteStr) -> ByteString {
        let mut result = ByteString::with_capacity(left.len() + right.len());
        result.push_bstr(left);
        result.push_bstr(right);
        result

    }
    pub fn push_bstr(&mut self, bs: &ByteStr) {
        self.0.extend_from_slice(&bs.0);
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
impl<'a> From<&'a str> for &'a ByteStr {
    fn from(s: &'a str) -> Self {
        ByteStr::from_bytes(s.as_bytes())
    }
}
impl<'a> Add<&'a ByteStr> for ByteString {
    type Output = ByteString;
    fn add(mut self, other: &ByteStr) -> ByteString {
        self.push_bstr(other);
        self
    }
}

impl PartialEq<str> for ByteStr {
    fn eq(&self, other: &str) -> bool {
        &**self == other.as_bytes()
    }
}
impl PartialEq<ByteStr> for ByteString {
    fn eq(&self, other: &ByteStr) -> bool {
        &***self == &**other
    }
}
impl PartialEq<str> for ByteString {
    fn eq(&self, other: &str) -> bool {
        &***self == other.as_bytes()
    }
}

#[inline]
pub fn from_cstr<'a, X: X8, S: ?Sized + ROSlicePtr<X>>(chs: &S) -> &'a ByteStr {
    let (ptr, len) = (chs.as_ptr() as *const u8, chs.len());;
    let true_len = unsafe { strnlen(ptr, len) };
    unsafe { ByteStr::from_bytes(std::slice::from_raw_parts(ptr, true_len)) }
}

#[inline]
pub fn from_cstr_strict<'a, X: X8, S: ?Sized + ROSlicePtr<X>>(chs: &S) -> Option<&'a ByteStr> {
    let (ptr, len) = (chs.as_ptr() as *const u8, chs.len());;
    let true_len = unsafe { strnlen(ptr, len) };
    if true_len == len {
        None
    } else {
        unsafe { Some(ByteStr::from_bytes(std::slice::from_raw_parts(ptr, true_len))) }
    }
}

type MaybeArc<T> = Arc<T>; // todo

enum MemoryContainer {
    Empty,
    MemoryMap(Mmap),
    BoxedSlice(Box<[u8]>),
}

#[derive(Clone)]
pub struct Mem<T: Swap> {
    mc: MaybeArc<MemoryContainer>,
    ptr: *const T,
    len: usize
}

unsafe impl<T: Swap> Send for Mem<T> {}
unsafe impl<T: Swap> Sync for Mem<T> {}

impl<T: Swap> std::default::Default for Mem<T> {
    fn default() -> Self {
        Mem::empty()
    }
}

impl<T: Swap> Debug for Mem<T> {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "Mem({:?}, {})", self.ptr, self.len)
    }
}

impl Mem<u8> {
    pub fn with_mm(mm: Mmap) -> Self {
        let (ptr, len) = (mm.ptr() as *const _, mm.len());
        Mem {
            mc: Arc::new(MemoryContainer::MemoryMap(mm)),
            ptr: ptr, len: len
        }
    }
}

impl<T: Swap> Mem<T> {
    pub fn with_data<S: ?Sized + ROSlicePtr<T>>(data: &S) -> Self where T: Clone {
        Mem::with_vec(fast_slice_to_owned(data))
    }

    pub fn with_vec(vec: Vec<T>) -> Self {
        let len = vec.len();
        let vec: Vec<u8> = unsafe { vec.raw_cast() };
        let bs = vec.into_boxed_slice();
        let ptr = bs.as_ptr();
        Mem {
            mc: Arc::new(MemoryContainer::BoxedSlice(bs)),
            ptr: unsafe { transmute(ptr) }, len: len
        }
    }

    #[inline]
    pub fn empty() -> Self {
        // todo
        Mem {
            mc: Arc::new(MemoryContainer::Empty),
            ptr: 0 as *const T,
            len: 0,
        }
    }

    pub fn into_vec(mut self) -> Vec<T> {
        if let Some(mc) = Arc::get_mut(&mut self.mc) {
            let ok = if let &mut MemoryContainer::BoxedSlice(ref bs) = mc {
                bs.as_ptr() == (self.ptr as *const u8) && bs.len() == self.len * size_of::<T>()
            } else { false };
            if ok {
                if let MemoryContainer::BoxedSlice(bs) = replace(mc, MemoryContainer::Empty) {
                    return unsafe { bs.into_vec().raw_cast() };
                } else { debug_assert!(false); }
            }
        }
        let _sw = stopwatch("into_vec copy");
        fast_slice_to_owned(self.get())
    }

    pub fn slice(&self, from: usize, to: usize) -> Option<Self> {
        let len = to - from;
        if from > self.len || len > self.len - from {
            return None
        }
        unsafe {
            Some(Mem { mc: self.mc.clone(), ptr: self.ptr.offset(from as isize), len: len })
        }
    }

    pub fn get_uniq(&mut self) -> Option<&mut [T]> {
        if let Some(_) = Arc::get_mut(&mut self.mc) {
            unsafe { return Some(std::slice::from_raw_parts_mut::<T>(self.ptr as *mut T, self.len)); }
        }
        None
    }

    pub fn get_uniq_decow(&mut self) -> &mut [T] {
        if let Some(sl) = self.get_uniq() {
            // sl is already &mut [T], but this fudges the lifetimes.  This shouldn't be necessary,
            // but since both mutable borrows (this one and the else branch) have the same lifetime
            // as self, rustc thinks the borrows conflict.
            let sl: &mut [T] = unsafe { transmute(sl) };
            return sl;
        }
        let _sw = stopwatch("get_uniq_decow decow (vec)");
        *self = Mem::with_vec(fast_slice_to_owned(self.get()));
        self.get_uniq().unwrap()
    }

    #[inline]
    pub fn get(&self) -> &[ReadCell<T>] {
        unsafe { transmute(std::slice::from_raw_parts(self.ptr, self.len)) }
    }

    // Note: This is technically illegal because of split reads.  It should be AtomicU8 or
    // something.  Todo...
    #[inline]
    pub fn get_mut(&self) -> &[Cell<T>] {
        unsafe { transmute(std::slice::from_raw_parts(self.ptr, self.len)) }
    }

    // only safe to call if nobody is going to mutate
    pub unsafe fn get_plain_slice(&self) -> &[T] {
        transmute(std::slice::from_raw_parts(self.ptr, self.len))
    }

    pub fn byte_offset_in(&self, other: &Mem<u8>) -> Option<usize> {
        let mine = self.ptr as usize;
        let theirs = other.ptr as usize;
        if mine >= theirs && mine < theirs + max(other.len, 1) {
            Some(mine - theirs)
        } else { None }
    }
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }
}

pub fn memmap(fil: &File) -> io::Result<Mem<u8>> {
    Ok(Mem::with_mm(try!(Mmap::open(fil, memmap::Protection::ReadCopy))))
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

pub trait VecStrExt {
    fn strings(&self) -> Vec<String>;
}
impl<T: std::string::ToString> VecStrExt for Vec<T> {
    fn strings(&self) -> Vec<String> { self.iter().map(|x| x.to_string()).collect() }
}

pub trait Unsigned: Sized {}
pub trait Signed: Sized {}
pub trait IntStuffSU : Sized {
    fn neg_if_possible(self) -> Option<Self>;
}

pub trait IntStuff : IntStuffSU {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;
    fn align_up_to(self, size: Self) -> Self;
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
    for i in 0..2 {
        do_i(i)
    }
}

extern {
    fn memmove(dst: *mut u8, src: *const u8, len: usize);
    fn memset(dst: *mut u8, byte: i32, len: usize);
    fn memchr(src: *const u8, byte: i32, len: usize) -> *mut u8;
    fn memmem(big: *const u8, big_len: usize, little: *const u8, little_len: usize) -> *mut u8;
}
#[inline(always)]
unsafe fn strnlen(s: *const u8, maxlen: usize) -> usize {
    mod orig {
        extern { pub fn strnlen(s: *const u8, maxlen: usize) -> usize; }
    }
    let res = orig::strnlen(s, maxlen);
    #[cfg(feature = "nightly")]
    std::intrinsics::assume(res <= maxlen);
    res
}
#[inline]
pub fn copy_memory<'a, T, Src: ?Sized, Dst>(src: &Src, dst: Dst)
    where T: Copy, Src: ROSlicePtr<T>, Dst: RWSlicePtr<'a, T> {
    let len = dst.len();
    assert_eq!(len, src.len());
    unsafe { memmove(dst.as_mut_ptr() as *mut u8,
                     src.as_ptr() as *const u8,
                     len * size_of::<T>()); }
}

pub fn into_cow<'a, T: ?Sized + ToOwned, S: Into<Cow<'a, T>>>(s: S) -> Cow<'a, T> {
    s.into()
}

pub struct Lazy<T> {
    mtx: Mutex<()>,
    val: UnsafeCell<NoDrop<T>>,
    is_valid: AtomicBool,
}
impl<T> Lazy<T> {
    pub fn new() -> Lazy<T> {
        Lazy {
            mtx: Mutex::new(()),
            val: unsafe { UnsafeCell::new(NoDrop::new(uninitialized())) },
            is_valid: AtomicBool::new(false),
        }
    }
    pub fn get<F>(&self, f: F) -> &T where F: FnOnce() -> T {
        unsafe {
            if !self.is_valid.load(Ordering::Acquire) {
                let _guard = self.mtx.lock().unwrap();
                ptr::write(&mut **self.val.get(), f());
                self.is_valid.store(true, Ordering::Release);
            }
            &*self.val.get()
        }
    }
}
unsafe impl<T> Sync for Lazy<T> {}
impl<T> Drop for Lazy<T> {
    fn drop(&mut self) {
        if self.is_valid.load(Ordering::Acquire) {
            unsafe { ptr::read(&mut **self.val.get()); }
        }
    }
}

pub struct LazyBox<T> {
    val: AtomicPtr<T>,
}

impl<T> LazyBox<T> {
    pub fn new() -> Self {
        LazyBox { val: AtomicPtr::new(ptr::null_mut()) }
    }
    pub fn get(&self) -> Option<&T> {
        unsafe { transmute(self.val.load(Ordering::Acquire)) }
    }
    pub fn store(&self, val: Box<T>) -> Option<Box<T>> {
        let val = Box::into_raw(val);
        let ret = self.val.compare_and_swap(0 as *mut T,
                                            val,
                                            Ordering::Release);
        if ret.is_null() {
            None
        } else {
            unsafe { Some(Box::from_raw(val)) }
        }
    }
}
impl<T> Drop for LazyBox<T> {
    fn drop(&mut self) {
        let ptr = self.val.load(Ordering::Acquire);
        if !ptr.is_null() {
            unsafe { let _ = Box::from_raw(ptr); }
        }
    }
}

pub struct FieldLens<Outer, Inner> {
    offset: usize,
    lol: PhantomData<fn(&Outer)->&Inner>,
}
impl<O, I> Clone for FieldLens<O, I> {
    fn clone(&self) -> Self { *self }
}
impl<O, I> Copy for FieldLens<O, I> {}

pub unsafe fn __field_lens<Outer, Inner>(offset: *const Inner) -> FieldLens<Outer, Inner> {
    FieldLens { offset: offset as usize, lol: PhantomData }
}

impl<Outer, Inner> FieldLens<Outer, Inner> {
    #[inline]
    pub fn get_mut(&self, outer: &mut Outer) -> &mut Inner {
        unsafe { transmute(transmute::<&mut Outer, *mut u8>(outer).offset(self.offset as isize)) }
    }
    #[inline]
    pub fn get(&self, outer: &Outer) -> &Inner {
        unsafe { transmute(transmute::<&Outer, *const u8>(outer).offset(self.offset as isize)) }
    }
    #[inline]
    pub unsafe fn get_mut_unsafe(&self, outer: *mut Outer) -> &mut Inner {
        transmute(transmute::<*mut Outer, *mut u8>(outer).offset(self.offset as isize))
    }
}

pub type Fnv = BuildHasherDefault<FnvHasher>;

pub fn new_fnv_hashmap<K: Eq + Hash, V>() -> HashMap<K, V, Fnv> {
    HashMap::with_hasher(Fnv::default())
}

pub fn new_fnv_hashset<T: Eq + Hash>() -> HashSet<T, Fnv> {
    HashSet::with_hasher(Fnv::default())
}

thread_local!(static STOPWATCH_INDENT: Cell<usize> = Cell::new(0));
static mut ENABLE_STOPWATCH: bool = true;
use std::time::Instant;

pub struct Stopwatch<'a> {
    desc: &'a str,
    start_time: Option<Instant>,
    indent: usize,
}

pub fn stopwatch(desc: &str) -> Stopwatch {
    if unsafe { ENABLE_STOPWATCH } {
        let indent = STOPWATCH_INDENT.with(|cell| {
            let indent = cell.get();
            cell.set(indent + 4);
            indent
        });
        Stopwatch { desc: desc, start_time: Some(Instant::now()), indent: indent }
    } else {
        Stopwatch { desc: desc, start_time: None, indent: 0 }
    }
}

impl<'a> Stopwatch<'a> {
    #[inline(always)]
    pub fn stop(self) {}
}
impl<'a> Drop for Stopwatch<'a> {
    fn drop(&mut self) {
        if unsafe { ENABLE_STOPWATCH } {
            let duration = Instant::now() - self.start_time.unwrap();
            let duration_f = (duration.as_secs() as f64 * 1000.0) + (duration.subsec_nanos() as f64 * 0.000001);
            errln!("{blank:spaces$}{desc}: {duration:?}ms", blank="", spaces=self.indent,
                   desc=self.desc, duration=duration_f);
            STOPWATCH_INDENT.with(|cell| cell.set(self.indent));
        }
    }
}

#[inline(always)]
pub fn empty_slice<T>() -> &'static [T] {
    unsafe { std::slice::from_raw_parts(!0 as *const T, 0) }
}

pub fn fast_slice_to_owned<T: Swap, S: ?Sized + ROSlicePtr<T>>(slice: &S) -> Vec<T> {
    // extend_from_slice is supposed to be fast.  in unoptimized mode, it takes 60s to copy a few hundred MB.
    let len = slice.len();
    let mut res: Vec<T> = Vec::with_capacity(len);
    unsafe {
        res.set_len(len);
        copy(slice.as_ptr(), res.as_mut_ptr() as *mut T, len);
    }
    res
}

pub fn slice_find_byte<X: X8, S: ?Sized + ROSlicePtr<X>>(slice: &S, pat: u8) -> Option<usize> {
    let ptr = slice.as_ptr() as *const u8;
    let chr = unsafe { memchr(ptr, pat as i32, slice.len()) };
    if chr == 0 as *mut u8 {
        None
    } else {
        Some((chr as usize) - (ptr as usize))
    }
}

// same as Vec::extend_from_slice but with ROSlicePtr
pub fn vec_extend_from_slice<T: Copy, S: ?Sized + ROSlicePtr<T>>(this: &mut Vec<T>, other: &S) {
    unsafe {
        let ol = other.len();
        let sl = this.len();
        this.reserve(ol);
        this.set_len(sl + ol);
        copy(other.as_ptr(), this.as_mut_ptr().offset(sl as isize), ol);
    }
}

pub fn subset_sorted_list<T, F, G>(list: &[T], mut ge_start: F, mut le_end: G) -> &[T]
    where F: FnMut(&T) -> bool, G: FnMut(&T) -> bool {
    // fast case
    if list.len() == 0 ||
       (ge_start(&list[0]) && le_end(&list[list.len() - 1])) {
       return list;
    }
    let start = list.binary_search_by(|p| {
        if ge_start(p) { cmp::Ordering::Greater } else { cmp::Ordering::Less }
    }).unwrap_err();
    let list = &list[start..];
    let end = list.binary_search_by(|p| {
        if le_end(p) { cmp::Ordering::Less } else { cmp::Ordering::Greater }
    }).unwrap_err();
    &list[..end]
}

pub unsafe trait Zeroable: Sized {
    fn zeroed() -> Self {
        unsafe {
            let mut buf: Self = uninitialized();
            memset(&mut buf as *mut Self as *mut u8, 0, size_of::<Self>());
            buf
        }
    }
}
unsafe impl<T: Swap> Zeroable for T {}

pub fn zero_vec<T: Zeroable>(size: usize) -> Vec<T> {
    let mut vec: Vec<T> = Vec::with_capacity(size);
    unsafe {
        vec.set_len(size);
        memset(vec.as_mut_ptr() as *mut u8, 0, size * size_of::<T>());
    }
    vec
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct BitSet32 { pub bits: u32 }
impl BitSet32 {
    #[inline]
    pub fn empty() -> BitSet32 { BitSet32 { bits: 0 } }
    #[inline]
    pub fn is_empty(self) -> bool { self.bits == 0 }
    #[inline]
    pub fn is_nonempty(self) -> bool { self.bits == 0 }
    #[inline]
    pub fn with_range(range: Range<u8>) -> BitSet32 {
        assert!(range.start <= range.end && range.end <= 32);
        let x = range.end - range.start;
        BitSet32 { bits: if x == 0 {
            0
        } else {
            (!0u32) >> (32 - x as u32) << (range.start as u32)
        } }
    }
    #[inline]
    pub fn highest_set_bit(self) -> Option<u8> {
        let lz = self.bits.leading_zeros() as u8;
        if lz == 32 { None } else { Some(31 - lz) }
    }
    #[inline]
    pub fn highest_set_bit_before(self, mut before: u8) -> Option<u8> {
        if before > 31 { before = 31; }
        let bits = self.bits << ((31 - before) as u32);
        let lz = bits.leading_zeros() as u8;
        if lz == 32 { None } else { Some(31 - lz) }
    }
    #[inline]
    pub fn lowest_set_bit(self) -> Option<u8> {
        let tz = self.bits.trailing_zeros() as u8;
        if tz == 32 { None } else { Some(tz) }
    }
    #[inline]
    pub fn lowest_set_bit_after(self, after: u8) -> Option<u8> {
        if after >= 32 { return None; }
        let bits = self.bits >> (after as u32);
        let tz = bits.trailing_zeros() as u8;
        if tz == 32 { None } else { Some(tz) }
    }
    #[inline]
    pub fn set_bits(self) -> SetBits32 {
        SetBits32(self)
    }
    #[inline]
    pub fn has(self, bit: u8) -> bool {
        assert!(bit < 32);
        self.bits & (1u32 << bit) != 0
    }
    #[inline]
    pub fn add(&mut self, bit: u8) {
        assert!(bit < 32);
        self.bits |= 1u32 << bit
    }
    #[inline]
    pub fn adding(self, bit: u8) -> Self {
        assert!(bit < 32);
        BitSet32 { bits: self.bits | 1u32 << bit }
    }
    #[inline]
    pub fn remove(&mut self, bit: u8) {
        assert!(bit < 32);
        self.bits &= !(1u32 << bit)
    }
    #[inline]
    pub fn removing(self, bit: u8) -> Self {
        assert!(bit < 32);
        BitSet32 { bits: self.bits & !(1u32 << bit) }
    }
    #[inline]
    pub fn assign(&mut self, bit: u8, val: bool) {
        if val { self.add(bit) } else { self.remove(bit) }
    }
    #[inline]
    pub fn assigning(self, bit: u8, val: bool) -> Self {
        if val { self.adding(bit) } else { self.removing(bit) }
    }
    #[inline]
    pub fn subset(self, range: Range<u8>) -> Self {
        self & BitSet32::with_range(range)
    }
    #[inline]
    pub fn count(self) -> u8 {
        self.bits.count_ones() as u8
    }
}
impl Debug for BitSet32 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "BitSet32{:?}", self)
    }
}
impl Display for BitSet32 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        try!(write!(f, "{{"));
        let mut first = true;
        for bit in self.set_bits() {
            try!(write!(f, "{}{}",
                        if first { "" } else { ", " },
                        bit));
            first = false;
        }
        write!(f, "}}")
    }
}
impl<T: Narrow<u8>> FromIterator<T> for BitSet32 {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
        let mut set = Self::empty();
        for val in iter {
            let val: u8 = val.narrow().expect("overflow in BitSet32::from_iter");
            set.add(val);
        }
        set
    }
}

impl std::ops::BitOr<BitSet32> for BitSet32 {
    type Output = BitSet32;
    fn bitor(self, rhs: BitSet32) -> BitSet32 { BitSet32 { bits: self.bits | rhs.bits } }
}
impl std::ops::BitAnd<BitSet32> for BitSet32 {
    type Output = BitSet32;
    fn bitand(self, rhs: BitSet32) -> BitSet32 { BitSet32 { bits: self.bits & rhs.bits } }
}
impl std::ops::Not for BitSet32 {
    type Output = BitSet32;
    fn not(self) -> BitSet32 { BitSet32 { bits: !self.bits } }
}

pub struct SetBits32(BitSet32);
impl Iterator for SetBits32 {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> {
        let res = self.0.lowest_set_bit();
        if let Some(bit) = res {
            self.0.bits &= !(1u32 << bit);
        }
        res
    }
}

#[cfg(feature = "nightly")] #[inline(always)]
pub fn likely(b: bool) -> bool { unsafe { std::intrinsics::likely(b) } }
#[cfg(feature = "nightly")] #[inline(always)]
pub fn unlikely(b: bool) -> bool { unsafe { std::intrinsics::unlikely(b) } }
#[cfg(not(feature = "nightly"))] #[inline(always)]
pub fn likely(b: bool) -> bool { b }
#[cfg(not(feature = "nightly"))] #[inline(always)]
pub fn unlikely(b: bool) -> bool { b }
