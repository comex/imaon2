extern crate macho;
extern crate elf;
extern crate raw_binary;
extern crate exec;
use self::exec::ExecProber;
use std::cast;

pub fn all_probers() -> Vec<&'static ExecProber> {
    // unsafe due to https://github.com/mozilla/rust/issues/13887
    unsafe {
        return vec!(
            cast::transmute(box self::macho::MachOProber as Box<ExecProber>),
            cast::transmute(box self::macho::FatMachOProber as Box<ExecProber>),
            cast::transmute(box self::raw_binary::RawProber as Box<ExecProber>),
        );
    }
}
