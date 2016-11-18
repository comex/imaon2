#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(improper_ctypes)] // bug?
#[macro_use]
extern crate macros;
extern crate util;
use util::Swap;

impl<T> Swap for __BindgenUnionField<T> {
    fn bswap(&mut self) {}
}

include!(concat!(env!("OUT_DIR"), "/out.rs"));

