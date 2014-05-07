#![feature(phase)]
#[phase(link, syntax)]
#[path="../util.rs"]
extern crate util;
extern crate exec;

#[path="../out/elf_bind.rs"]
mod elf_bind;
