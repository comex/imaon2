#![feature(phase)]
#![feature(globs)]
#![allow(non_camel_case_types)]
#![allow(non_uppercase_pattern_statics)]
#[phase(link, syntax)]
extern crate util;
extern crate exec;
extern crate collections;
use util::ToUi;
use std::default::Default;
//use collections::HashMap;
use std::vec::Vec;
use std::mem::size_of;
use macho_bind::*;
use exec::arch;

mod macho_bind;

#[deriving(Default)]
pub struct MachO {
    eb: exec::ExecBase,
    is64: bool,
    mh: mach_header,
    seg_cmds: Vec<uint>,
    sect_cmds: Vec<uint>,
}

impl exec::Exec for MachO {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
}

fn copy_from_slice<T: Copy + util::Swap>(slice: &[u8], end: util::Endian) -> T {
    assert_eq!(slice.len(), size_of::<T>());
    unsafe {
        let mut t : T = std::mem::uninit();
        std::ptr::copy_memory(&mut t, std::cast::transmute(slice.as_ptr()), 1);
        t.bswap_from(end);
        t
    }
}

impl MachO {
    pub fn new(buf: &[u8], do_lcs: bool) -> Option<MachO> {
        let mut me: MachO = Default::default();

        let mut lc_off = size_of::<mach_header>();
        if buf.len() < lc_off { return None }
        let magic: u32 = copy_from_slice(buf.slice_to(4), util::BigEndian);
        let is64; let end;
        match magic {
            0xfeedface => { end = util::BigEndian; is64 = false; }
            0xfeedfacf => { end = util::BigEndian; is64 = true; }
            0xcefaedfe => { end = util::LittleEndian; is64 = false; }
            0xcffaedfe => { end = util::LittleEndian; is64 = true; }
            _ => fail!("shouldn't happen due to probe")
        }
        me.eb.endian = end;
        me.is64 = is64;
        me.mh = copy_from_slice(buf.slice_to(lc_off), end);
        // useless 'reserved' field
        if is64 { lc_off += 4; }

        me.parse_header();
        if do_lcs {
            me.parse_load_commands(buf, lc_off);
        }
        Some(me)
    }

    pub fn subtype_desc(&self) -> Option<&'static str> {
        Some(match (self.mh.cputype.to_ui(), self.mh.cpusubtype.to_ui()) {
            (CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_ALL) => "hppa",
            (CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL) => "i386",
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL) => "x86_64",
            (CPU_TYPE_I860, CPU_SUBTYPE_I860_ALL) => "i860",
            (CPU_TYPE_MC680x0, CPU_SUBTYPE_MC680x0_ALL) => "m68k",
            (CPU_TYPE_MC88000, CPU_SUBTYPE_MC88000_ALL) => "m88k",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL) => "ppc",
            (CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL) => "ppc64",
            (CPU_TYPE_SPARC, CPU_SUBTYPE_SPARC_ALL) => "sparc",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_ALL) => "arm",
            (CPU_TYPE_ANY, CPU_SUBTYPE_MULTIPLE) => "any",
            (CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_7100LC) => "hppa7100LC",
            (CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68030_ONLY) => "m68030",
            (CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68040) => "m68040",
            (CPU_TYPE_I386, CPU_SUBTYPE_486) => "i486",
            (CPU_TYPE_I386, CPU_SUBTYPE_486SX) => "i486SX",
            (CPU_TYPE_I386, CPU_SUBTYPE_PENT) => "pentium",
            (CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO) => "pentpro",
            (CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M3) => "pentIIm3",
            (CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M5) => "pentIIm5",
            (CPU_TYPE_I386, CPU_SUBTYPE_PENTIUM_4) => "pentium4",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_601) => "ppc601",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603) => "ppc603",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603e) => "ppc603e",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603ev) => "ppc603ev",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604) => "ppc604",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604e) => "ppc604e",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_750) => "ppc750",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7400) => "ppc7400",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7450) => "ppc7450",
            (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_970) => "ppc970",
            (CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_970) => "ppc970-64",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V4T) => "armv4t",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V5TEJ) => "armv5",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_XSCALE) => "xscale",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6) => "armv6",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7) => "armv7",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7F) => "armv7f",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S) => "armv7s",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K) => "armv7k",
            (CPU_TYPE_ANY, CPU_SUBTYPE_LITTLE_ENDIAN) => "little",
            (CPU_TYPE_ANY, CPU_SUBTYPE_BIG_ENDIAN) => "big",
            _ => return None,
        })
    }

    pub fn desc(&self) -> ~str {
        let ft_desc = match self.mh.filetype.to_ui() {
            MH_OBJECT => "object",
            MH_EXECUTE => "executable",
            MH_CORE => "core",
            MH_DYLIB => "dylib",
            MH_DYLINKER => "dylinker",
            MH_BUNDLE => "bundle",
            MH_DSYM => "dSYM",
            MH_KEXT_BUNDLE => "kext",
            _ => "<unknown filetype>"
        };
        let st_desc = match self.subtype_desc() {
            Some(d) => std::str::Slice(d),
            None => std::str::Owned(format!("<unknown cpu {}/{}>", self.mh.cputype, self.mh.cpusubtype))
        };
        format!("Mach-O {}/{}", ft_desc, st_desc)
    }

    fn parse_header(&mut self) {
        self.eb.arch = match self.mh.cputype.to_ui() {
            CPU_TYPE_X86 => arch::X86,
            CPU_TYPE_X86_64 => arch::X86_64,
            CPU_TYPE_ARM => arch::ARM,
            CPU_TYPE_ARM64 => arch::AArch64,
            CPU_TYPE_POWERPC => arch::PowerPC,
            CPU_TYPE_POWERPC64 => arch::PowerPC,
            // Even if we don't know the arch, we can at least do something.
            _ => arch::UnknownArch,
        }
        // we don't really care about cpusubtype but could fill it in
    }

    fn parse_load_commands(&mut self, buf: &[u8], mut lc_off: uint) {
        let end = self.eb.endian;
        let mut segi = 0;
        for _ in range(0, self.mh.ncmds - 1) {
            let lc: load_command = util::copy_from_slice(buf.slice(lc_off, lc_off + 8), end);
            let data = buf.slice(lc_off, lc_off + lc.cmdsize.to_ui());
            let this_lc_off = lc_off;
            let do_segment = |is64: bool| {
                branch!(if is64 {
                    type segment_command_x = segment_command_64;|
                    type section_x = section_64;
                } else {
                    type segment_command_x = segment_command;|
                    type section_x = section;
                } then {
                    let mut off = size_of::<segment_command_x>();
                    let sc: segment_command_x = util::copy_from_slice(data.slice_to(off), end);
                    let ip = sc.initprot.to_ui();
                    let segprot = exec::Prot {
                        r: (ip & VM_PROT_READ) != 0,
                        w: (ip & VM_PROT_WRITE) != 0,
                        x: (ip & VM_PROT_EXECUTE) != 0,
                    };
                    self.eb.segments.push(exec::Segment {
                        vmaddr: exec::VMA(sc.vmaddr as u64),
                        vmsize: sc.vmsize as u64,
                        fileoff: sc.fileoff as u64,
                        filesize: sc.filesize as u64,
                        name: Some(util::from_cstr(sc.segname)),
                        prot: segprot,
                        section_segment_idx: None,
                        private: this_lc_off,
                    });
                    for _ in range(0, sc.nsects) {
                        let s: section_x = util::copy_from_slice(data.slice(off, off + size_of::<section_x>()), end);
                        self.eb.sections.push(exec::Segment {
                            vmaddr: exec::VMA(s.addr as u64),
                            vmsize: s.size as u64,
                            fileoff: s.offset as u64,
                            filesize: s.size as u64,
                            name: Some(util::from_cstr(s.sectname)),
                            prot: segprot,
                            section_segment_idx: None,
                            private: this_lc_off + off,
                        });
                        off += size_of::<section_x>();
                    }
                })
                segi += 1;
            };
            match lc.cmd.to_ui() {
                LC_SEGMENT => do_segment(false),
                LC_SEGMENT_64 => do_segment(true),


                _ => ()
            }
            lc_off += lc.cmdsize.to_ui();
        }
    }
}


pub struct MachOProber;

impl exec::ExecProber for MachOProber {
    fn name() -> &str {
        "macho"
    }
    fn probe(&self, buf: &[u8]) -> Vec<exec::ProbeResult> {
        match MachO::new(buf, false) {
            Some(m) => vec!(exec::ProbeResult {
                desc: m.desc(),
                arch: m.eb.arch,
                fmtdata: ~0 as ~std::any::Any,
            }),
            None => vec!(),
        }
    }
    fn create(&self, buf: &[u8], pr: &exec::ProbeResult, args: &str) -> ~exec::Exec {
        let _ = pr; let _ = args;
        ~MachO::new(buf, true).unwrap() as ~exec::Exec
    }
}

//#[test]

