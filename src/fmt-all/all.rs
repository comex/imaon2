extern crate fmt_macho as macho;
extern crate fmt_elf as elf;
extern crate fmt_raw_binary as raw_binary;
extern crate exec;
use self::macho::dyldcache;
use self::exec::ExecProber;
use std::mem;

pub fn all_probers() -> Vec<exec::ExecProberRef> {
    // unsafe due to https://github.com/mozilla/rust/issues/13887
    unsafe {
        return vec!(
            mem::transmute(&self::macho::MachOProber    as &ExecProber),
            mem::transmute(&dyldcache::DyldWholeProber  as &ExecProber),
            mem::transmute(&dyldcache::DyldSingleProber as &ExecProber),
            mem::transmute(&self::macho::FatMachOProber as &ExecProber),
            mem::transmute(&self::elf::ElfProber        as &ExecProber),
            mem::transmute(&self::raw_binary::RawProber as &ExecProber),
        );
    }
}
