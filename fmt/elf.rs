#![feature(libc)]
#[macro_use]
extern crate macros;
extern crate util;
extern crate exec;
extern crate libc;

#[path="../out/elf_bind.rs"]
mod elf_bind;
