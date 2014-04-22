#![feature(phase)]
#[phase(link, syntax)]
#[path="../util.rs"]
extern crate util;

mod macho_bind;
