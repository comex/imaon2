#![feature(phase)]
#[phase(link, syntax)]
#[path="../util.rs"]
extern crate util;
extern crate exec;

mod elf_bind;
