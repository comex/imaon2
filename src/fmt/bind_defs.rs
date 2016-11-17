#![allow(non_camel_case_types, non_upper_case_globals, dead_code, non_snake_case)]

#[macro_use]
extern crate macros;
extern crate util;
extern crate libc;

use util::Swap;
pub type int64_t  = i64;
pub type int32_t  = i32;
pub type int16_t  = i16;
pub type int8_t   = i8;
pub type uint64_t = u64;
pub type uint32_t = u32;
pub type uint16_t = u16;
pub type uint8_t  = u8;

pub type c_char  = i8;
pub type c_schar  = i8;
pub type c_uchar  = u8;
pub type c_uint   = u32;
pub type c_int    = i32;
pub type c_ulong  = u32;

pub type c_void = u8;
