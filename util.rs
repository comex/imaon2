#![feature(macro_rules)]

use std::kinds::Copy;
use std::mem::{size_of, uninit};
use std::ptr::copy_memory;
use std::cast::transmute;
use std::rc::Rc;
use std::cell::Cell;
use std::intrinsics;

// Don't use this.  Use a real macro

pub fn copy_from_slice<T: Copy>(slice: &[u8]) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = uninit();
        copy_memory(&mut t, transmute(slice.as_ptr()), size_of::<T>());
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

pub trait Swap {
    fn bswap(&mut self);
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

