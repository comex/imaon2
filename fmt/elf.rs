#![feature(libc, slice_bytes, box_syntax)]
#![allow(non_camel_case_types)]
static EM_NAMES: [&'static str; 95] = [
    // fmt/em_names.awk
    "none", "m32", "sparc", "386", "68k", "88k", "unk_6", "860", "mips", "s370", "mips_rs3_le",
    "unk_11", "unk_12", "unk_13", "unk_14", "parisc", "unk_16", "vpp500", "sparc32plus", "960",
    "ppc", "ppc64", "s390", "unk_23", "unk_24", "unk_25", "unk_26", "unk_27", "unk_28", "unk_29",
    "unk_30", "unk_31", "unk_32", "unk_33", "unk_34", "unk_35", "v800", "fr20", "rh32", "rce",
    "arm", "fake_alpha", "sh", "sparcv9", "tricore", "arc", "h8_300", "h8_300h", "h8s", "h8_500",
    "ia_64", "mips_x", "coldfire", "68hc12", "mma", "pcp", "ncpu", "ndr1", "starcore", "me16",
    "st100", "tinyj", "x86_64", "pdsp", "unk_64", "unk_65", "fx66", "st9plus", "st7", "68hc16",
    "68hc11", "68hc08", "68hc05", "svx", "st19", "vax", "cris", "javelin", "firepath", "zsp",
    "mmix", "huany", "prism", "avr", "fr30", "d10v", "d30v", "v850", "m32r", "mn10300", "mn10200",
    "pj", "openrisc", "arc_a5", "xtensa", 
];
#[macro_use]
extern crate macros;
extern crate util;
extern crate exec;
extern crate libc;

#[path="../out/elf_bind.rs"]
mod elf_bind;

use exec::arch::Arch;
use util::{MCRef, SliceExt};
use std::slice::bytes;
use std::mem::size_of;
use exec::{ExecResult, ErrorKind, Segment, VMA, Prot}; 
use elf_bind::*;

macro_rules! convert_each {
    ($val:expr, $ty:ident, $($field:ident),*) => {
        $ty { $($field: $val.$field.into()),* }
    }
}

struct ElfBasics {
    is64: bool,
    endian: util::Endian,
    abi: &'static str,
    type_: &'static str,
    machine: &'static str,
    arch: Arch,
}

struct OffCountSize {
    off: u64,
    count: u64,
    size: u64,
}

struct Ehdr {
    entry: VMA,
    flags: u32,
    ph: OffCountSize,
    sh: OffCountSize,
    shstrndx: u16,
    version: u32,
}
type Phdr = Elf64_Phdr;
type Shdr = Elf64_Shdr;

struct Elf {
    pub eb: exec::ExecBase,
    pub ehdr: Ehdr,

}

fn fix_ocs(cs: &mut OffCountSize, len: usize, what: &str) {
    // This could be simpler if we just wanted to verify correctness, but may as well diagnose the
    // nature of the problem...
    let end = cs.count.checked_mul(cs.size).and_then(|x| cs.off.checked_add(x));
    let end = end.unwrap_or_else(|| {
        errln!("warning: integer overflow in {}; off={} count={} size={}",
               what, cs.off, cs.count, cs.size);
        std::u64::MAX
    });
    if cs.off > len as u64 {
        errln!("warning: {} offset too large; off={} count={} size={}",
               what, cs.off, cs.count, cs.size);
        cs.count = 0;
    } else if end > len as u64 {
        errln!("warning: {} end too large; off={} count={} size={}",
               what, cs.off, cs.count, cs.size);
        cs.count = (len as u64 - cs.off) / cs.size;
    }
}

fn get_ehdr(basics: &ElfBasics, buf: &[u8]) -> ExecResult<Ehdr> {
    let mut eh = branch!(if basics.is64 == true { // '== true' due to macro suckage
        type ElfX_Ehdr = Elf64_Ehdr;
    } else {
        type ElfX_Ehdr = Elf32_Ehdr;
    } then {
        let ebytes = some_or!(buf.slice_opt(0, size_of::<ElfX_Ehdr>()), { return exec::err(ErrorKind::BadData, "too small for ehdr") });
        let xeh: ElfX_Ehdr = util::copy_from_slice(ebytes, basics.endian);
        Ehdr {
            entry: VMA(xeh.e_entry as u64),
            flags: xeh.e_flags,
            ph: OffCountSize { off: xeh.e_phoff as u64, count: xeh.e_phnum as u64, size: xeh.e_phentsize as u64 },
            sh: OffCountSize { off: xeh.e_shoff as u64, count: xeh.e_shnum as u64, size: xeh.e_shentsize as u64 },
            shstrndx: xeh.e_shstrndx,
            version: xeh.e_version,
        }
    });
    if eh.version != 1 {
        errln!("warning: e_version != EV_CURRENT");
    }
    fix_ocs(&mut eh.ph, buf.len(), "phdrs");
    fix_ocs(&mut eh.sh, buf.len(), "shdrs");
    Ok(eh)
}

fn get_phdrs(basics: &ElfBasics, buf: &[u8], ocs: &OffCountSize) -> Vec<Segment> {
    let mut off = ocs.off as usize;
    branch!(if basics.is64 == true {
        type ElfX_Phdr = Elf64_Phdr;
    } else {
        type ElfX_Phdr = Elf32_Phdr;
    } then {
        let sizeo = size_of::<ElfX_Phdr>();
        if ocs.size < sizeo as u64 {
            errln!("warning: phdr size ({}) too small, expected at least {}", ocs.size, sizeo);
            return Vec::new();
        }
        let realsize = ocs.size as usize;
        (0..ocs.count).map(|_| {
            let phdr: ElfX_Phdr = util::copy_from_slice(&buf[off..off+sizeo], basics.endian);
            let private = off;
            off += realsize;
            Segment {
                vmaddr: VMA(phdr.p_vaddr as u64),
                vmsize: phdr.p_memsz as u64,
                fileoff: phdr.p_offset as u64,
                filesize: phdr.p_filesz as u64,
                name: None,
                prot: Prot {
                    r: (phdr.p_flags & PF_R) != 0,
                    w: (phdr.p_flags & PF_W) != 0,
                    x: (phdr.p_flags & PF_X) != 0,
                },
                data: None, // fill in later
                seg_idx: None,
                private: std::usize::MAX,
            }
        }).collect()
    })
}

fn get_shdrs(basics: &ElfBasics, buf: &[u8], ocs: &OffCountSize) -> (Vec<Segment>, Vec<Shdr>) {
    let mut off = ocs.off as usize;
    let mut segs = Vec::new();
    let mut shdrs = Vec::new();
    branch!(if basics.is64 == true {
        type ElfX_Shdr = Elf64_Shdr;
        type FlagsTy = u64;
    } else {
        type ElfX_Shdr = Elf32_Shdr;
        type FlagsTy = u32;
    } then {
        let sizeo = size_of::<ElfX_Shdr>();
        if ocs.size < sizeo as u64 {
            errln!("warning: phdr size ({}) too small, expected at least {}", ocs.size, sizeo);
            return (Vec::new(), Vec::new());
        }
        let realsize = ocs.size as usize;
        for i in 0..ocs.count {
            let shdr: ElfX_Shdr = util::copy_from_slice(&buf[off..off+sizeo], basics.endian);
            off += realsize;
            segs.push(Segment {
                vmaddr: VMA(shdr.sh_addr as u64),
                vmsize: shdr.sh_size as u64,
                fileoff: shdr.sh_offset as u64,
                filesize: shdr.sh_size as u64,
                name: None, // fill in later
                prot: Prot {
                    r: true,
                    w: (shdr.sh_flags & (SHF_WRITE as FlagsTy)) != 0,
                    x: (shdr.sh_flags & (SHF_EXECINSTR as FlagsTy)) != 0,
                },
                data: None, // ditto
                seg_idx: None, // no seg_idx in ELF
                private: i as usize,
            });
            shdrs.push(
                convert_each!(shdr, Elf64_Shdr,
                    sh_name, sh_type, sh_flags, sh_addr,
                    sh_offset, sh_size, sh_link, sh_info,
                    sh_addralign, sh_entsize
                )
            );
        }
    });
    (segs, shdrs)
}

fn check_start_size(start: u64, size: u64) -> Option<(usize, usize)> {
    if start > (std::usize::MAX as u64) || size > (std::usize::MAX as u64) { return None; }
    let start = start as usize; let size = size as usize;
    start.checked_add(size).map(|end| (start, end))
}

fn fill_in_data(segs: &mut [Segment], buf: &MCRef) {
    for seg in segs {
        seg.data = check_start_size(seg.fileoff, seg.filesize).and_then(|(s, e)| buf.slice(s, e));
    }
}

fn fill_in_sect_names(sects: &mut [Segment], shdrs: &[Shdr], shstrndx: u16) {
    let shstrndx = shstrndx as usize;
    if shstrndx == SHN_UNDEF as usize { return; }
    let data = if let Some(strtab) = sects.get(shstrndx) {
        if let Some(ref data) = strtab.data {
            data.clone()
        } else {
            errln!("warning: section name string table out of file range");
            return
        }
    } else {
        errln!("warning: shstrndx ({}) out of bounds, only have {} sections", shstrndx, sects.len());
        return
    };
    let data = data.get();
    for (i, (sect, shdr)) in sects.into_iter().zip(shdrs).enumerate() {
        let sh_name = shdr.sh_name as usize;
        if let Some(rest) = data.slice_opt(sh_name, data.len()) {
            sect.name = Some(util::from_cstr(rest));
        } else {
            errln!("warning: sh_name for section {} out of bounds", i);
        }
    }
}

impl Elf {
    fn new(buf: MCRef) -> ExecResult<Self> {
        let mut res = {
            let b = buf.get();
            let basics = try!(check_elf_basics(b, true).map_err(|a| exec::err_only(ErrorKind::BadData, a)));
            let ehdr = try!(get_ehdr(&basics, b));
            let mut segs = get_phdrs(&basics, b, &ehdr.ph);
            let (mut sects, shdrs) = get_shdrs(&basics, b, &ehdr.sh);
            fill_in_data(&mut segs, &buf);
            fill_in_data(&mut sects, &buf);
            fill_in_sect_names(&mut sects, &shdrs, ehdr.shstrndx);
            let eb = exec::ExecBase {
                arch: basics.arch,
                endian: basics.endian,
                segments: segs,
                sections: sects,
                whole_buf: None,
            };
            Elf {
                ehdr: ehdr,
                eb: eb,
            }
        };
        res.eb.whole_buf = Some(buf);
        Ok(res)
    }
}

impl exec::Exec for Elf {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
    fn as_any(&self) -> &std::any::Any { self as &std::any::Any }

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

pub struct ElfProber;

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
