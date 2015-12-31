#![feature(libc, slice_bytes, box_syntax)]
static EM_NAMES: [&'static str; 95] = [
    // fmt/em_names.awk
    "none",
    "m32",
    "sparc",
    "386",
    "68k",
    "88k",
    "unk_6",
    "860",
    "mips",
    "s370",
    "mips_rs3_le",
    "unk_11",
    "unk_12",
    "unk_13",
    "unk_14",
    "parisc",
    "unk_16",
    "vpp500",
    "sparc32plus",
    "960",
    "ppc",
    "ppc64",
    "s390",
    "unk_23",
    "unk_24",
    "unk_25",
    "unk_26",
    "unk_27",
    "unk_28",
    "unk_29",
    "unk_30",
    "unk_31",
    "unk_32",
    "unk_33",
    "unk_34",
    "unk_35",
    "v800",
    "fr20",
    "rh32",
    "rce",
    "arm",
    "fake_alpha",
    "sh",
    "sparcv9",
    "tricore",
    "arc",
    "h8_300",
    "h8_300h",
    "h8s",
    "h8_500",
    "ia_64",
    "mips_x",
    "coldfire",
    "68hc12",
    "mma",
    "pcp",
    "ncpu",
    "ndr1",
    "starcore",
    "me16",
    "st100",
    "tinyj",
    "x86_64",
    "pdsp",
    "unk_64",
    "unk_65",
    "fx66",
    "st9plus",
    "st7",
    "68hc16",
    "68hc11",
    "68hc08",
    "68hc05",
    "svx",
    "st19",
    "vax",
    "cris",
    "javelin",
    "firepath",
    "zsp",
    "mmix",
    "huany",
    "prism",
    "avr",
    "fr30",
    "d10v",
    "d30v",
    "v850",
    "m32r",
    "mn10300",
    "mn10200",
    "pj",
    "openrisc",
    "arc_a5",
    "xtensa",
];
#[macro_use]
extern crate macros;
extern crate util;
extern crate exec;
extern crate libc;


use exec::arch::Arch;
use util::{MCRef, SliceExt};
use std::slice::bytes;

#[path="../out/elf_bind.rs"]
mod elf_bind;

use elf_bind::*;

struct Elf {
    pub eb: exec::ExecBase,

}

impl Elf {
    fn new(buf: MCRef) -> exec::ExecResult<Self> {
        let basics = try!(check_elf_basics(buf.get(), true).map_err(|a| exec::err_only(exec::ErrorKind::BadData, a)));
        let segs = vec![];
        let sects = vec![];
        let eb = exec::ExecBase {
            arch: basics.arch,
            endian: basics.endian,
            segments: segs,
            sections: sects,
            whole_buf: Some(buf),
        };
        Ok(Elf {
            eb: eb,
        })
    }
}

impl exec::Exec for Elf {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
    fn as_any(&self) -> &std::any::Any { self as &std::any::Any }

}

pub struct ElfProber;

struct ElfBasics {
    is64: bool,
    endian: util::Endian,
    abi: &'static str,
    type_: &'static str,
    machine: &'static str,
    arch: Arch,
}

fn check_elf_basics(buf: &[u8], warn: bool) -> Result<ElfBasics, &'static str> {
    let mut ident: [u8; 20] = [0; 20]; // plus e_{type, machine}
    bytes::copy_memory(some_or!(buf.slice_opt(0, 20), { return Err("too short"); }), &mut ident);
    if ident[0] != 0x7f ||
       ident[1] != 0x45 ||
       ident[2] != 0x4c ||
       ident[3] != 0x46 {
       return Err("bad magic");
    }
    if warn && ident[6] as u32 != EV_CURRENT {
        errln!("warning: EI_VERSION != EV_CURRENT");
    }
    if warn && ident[9..16].iter().any(|b| *b != 0) {
        errln!("warning: EI_PAD not zero filled");
    }
    let endian = match ident[5] as u32 {
        ELFDATA2LSB => util::LittleEndian,
        ELFDATA2MSB => util::BigEndian,
        _ => return Err("invalid EI_DATA (endianness)"),
    };
    let e_type: u16 = util::copy_from_slice(&ident[16..18], endian);
    let e_machine: u16 = util::copy_from_slice(&ident[18..20], endian);


    Ok(ElfBasics {
        is64: match ident[4] as u32 {
            ELFCLASS32 => false,
            ELFCLASS64 => true,
            _ => return Err("invalid EI_CLASS (64-bitness)"),
        },
        endian: endian,
        abi: match ident[7] as u32 {
            ELFOSABI_SYSV => "sysv",
            ELFOSABI_HPUX => "hpux",
            ELFOSABI_NETBSD => "netbsd",
            ELFOSABI_GNU => "gnu",
            ELFOSABI_SOLARIS => "solaris",
            ELFOSABI_AIX => "aix",
            ELFOSABI_IRIX => "irix",
            ELFOSABI_FREEBSD => "freebsd",
            ELFOSABI_TRU64 => "tru64",
            ELFOSABI_MODESTO => "modesto",
            ELFOSABI_OPENBSD => "openbsd",
            ELFOSABI_ARM_AEABI => "arm_aeabi",
            ELFOSABI_ARM => "arm",
            ELFOSABI_STANDALONE => "standalone",
            _ => {
                if warn { errln!("warning: invalid EI_OSABI {}", ident[7]); }
                "unknown-abi"
            },
        },
        type_: match e_type as u32 {
            ET_NONE => "none",
            ET_REL => "rel",
            ET_EXEC => "exec",
            ET_DYN => "dyn",
            ET_CORE => "core",
            _ => {
                if warn { errln!("warning: unknown e_type {}", e_type); }
                "unknown-type"
            },
        },
        machine: match e_machine as u32 {
            0x9026 => "alpha",
            0...94 => EM_NAMES[e_machine as usize],
            183 => "aarch64",
            188 => "tilepro",
            191 => "tilegx",
            _ => {
                if warn { errln!("warning: unknown e_machine {}", e_machine); }
                "unknown-machine"
            },

        },
        arch: match e_machine as u32 {
            EM_386 => Arch::X86,
            EM_X86_64 => Arch::X86_64,
            EM_ARM => Arch::ARM,
            EM_AARCH64 => Arch::AArch64,
            EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => Arch::Sparc,
            EM_MIPS | EM_MIPS_RS3_LE | EM_MIPS_X => Arch::Mips,
            EM_PPC | EM_PPC64 => Arch::PowerPC,
            _ => Arch::UnknownArch,
        }
    })
}

impl exec::ExecProber for ElfProber {
    fn name(&self) -> &str {
        "elf"
    }
    fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "elf ...", 0, std::usize::MAX, &mut vec!(
            // ...
        ))));
        let free = m.free;
        Elf::new(buf).map(|res| (box res as Box<exec::Exec>, free))
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        match check_elf_basics(buf.get(), false) {
            Err(_msg) => vec!(),
            Ok(ei) => {
                vec![exec::ProbeResult {
                    desc: format!("ELF {} {} {} {} {}",
                                  if ei.is64 { "64-bit" } else { "32-bit "},
                                  match ei.endian { util::BigEndian => "BE", util::LittleEndian => "LE" },
                                  ei.type_,
                                  ei.machine,
                                  ei.abi),
                    likely: true,
                    arch: ei.arch,
                    cmd: vec!["elf".to_string()],
                }]
            }
        }
    }
}
