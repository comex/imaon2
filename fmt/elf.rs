#![feature(phase)]
#[phase(link, plugin)]
extern crate util;
extern crate exec;
extern crate libc;

#[path="../out/elf_bind.rs"]
mod elf_bind;
