#![feature(phase)]
#![feature(globs)]
#![allow(non_camel_case_types)]
#![allow(non_uppercase_pattern_statics)]
#[phase(link, syntax)]
extern crate util;
extern crate exec;
extern crate collections;
extern crate sync;
use std::default::Default;
//use collections::HashMap;
use std::vec::Vec;
use std::mem::size_of;
use sync::Arc;
use util::ToUi;
use macho_bind::*;
use exec::arch;

#[path="../out/macho_bind.rs"]
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

fn mach_arch_desc(cputype: i32, cpusubtype: i32) -> Option<&'static str> {
    let cputype = cputype as u32;
    let cpusubtype = cpusubtype as u32;
    Some(match (cputype.to_ui(), cpusubtype.to_ui()) {
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
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL) => "arm64",
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8) => "arm64v8",
        (CPU_TYPE_ANY, CPU_SUBTYPE_LITTLE_ENDIAN) => "little",
        (CPU_TYPE_ANY, CPU_SUBTYPE_BIG_ENDIAN) => "big",
        _ => return None,
    })
}

impl MachO {
    pub fn new(mc: util::ArcMC, do_lcs: bool) -> Option<MachO> {
        let mut me: MachO = Default::default();
        {
            let buf = mc.get();
            let mut lc_off = size_of::<mach_header>();
            if buf.len() < lc_off { return None }
            let magic: u32 = util::copy_from_slice(buf.slice_to(4), util::BigEndian);
            let is64; let end;
            match magic {
                0xfeedface => { end = util::BigEndian; is64 = false; }
                0xfeedfacf => { end = util::BigEndian; is64 = true; }
                0xcefaedfe => { end = util::LittleEndian; is64 = false; }
                0xcffaedfe => { end = util::LittleEndian; is64 = true; }
                _ => return None
            }
            me.eb.endian = end;
            me.is64 = is64;
            me.mh = util::copy_from_slice(buf.slice_to(lc_off), end);
            // useless 'reserved' field
            if is64 { lc_off += 4; }

            me.parse_header();
            if do_lcs {
                me.parse_load_commands(lc_off);
            }
        }
        me.eb.buf = Some(mc);
        Some(me)
    }

    pub fn subtype_desc(&self) -> Option<&'static str> {
        mach_arch_desc(self.mh.cputype, self.mh.cpusubtype)
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

    fn parse_load_commands(&mut self, mut lc_off: uint) {
        let end = self.eb.endian;
        let buf = self.eb.buf.get_ref().get();
        let segs = &mut self.eb.segments;
        let sects = &mut self.eb.sections;
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
                    segs.push(exec::Segment {
                        vmaddr: exec::VMA(sc.vmaddr as u64),
                        vmsize: sc.vmsize as u64,
                        fileoff: sc.fileoff as u64,
                        filesize: sc.filesize as u64,
                        name: Some(util::from_cstr(sc.segname)),
                        prot: segprot,
                        private: this_lc_off,
                    });
                    for _ in range(0, sc.nsects) {
                        let s: section_x = util::copy_from_slice(data.slice(off, off + size_of::<section_x>()), end);
                        sects.push(exec::Segment {
                            vmaddr: exec::VMA(s.addr as u64),
                            vmsize: s.size as u64,
                            fileoff: s.offset as u64,
                            filesize: s.size as u64,
                            name: Some(util::from_cstr(s.sectname)),
                            prot: segprot,
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
    fn name(&self) -> &str {
        "macho"
    }
    fn probe(&self, buf: util::ArcMC, _eps: &Vec<&'static exec::ExecProber>) -> Vec<exec::ProbeResult> {
        match MachO::new(buf, false) {
            Some(m) => vec!(exec::ProbeResult {
                desc: m.desc(),
                arch: m.eb.arch,
                likely: true,
                cmd: vec!(),
            }),
            None => vec!(),
        }
    }
    fn create(&self, buf: util::ArcMC, pr: &exec::ProbeResult, args: &str) -> Box<exec::Exec> {
        let _ = pr; let _ = args;
        box MachO::new(buf, true).unwrap_or_else(|| fail!("not mach-o")) as Box<exec::Exec>
    }
}

pub struct FatMachOProber;

impl exec::ExecProber for FatMachOProber {
    fn name(&self) -> &str {
        "fatmacho"
    }
    fn probe(&self, mc: util::ArcMC, eps: &Vec<&'static exec::ExecProber>) -> Vec<exec::ProbeResult> {
        let buf = mc.get();
        if buf.len() < 8 { return vec!() }
        let fh: fat_header = util::copy_from_slice(buf.slice_to(8), util::BigEndian);
        if fh.magic != FAT_MAGIC as u32 { return vec!() }
        let nfat = fh.nfat_arch as u64;
        let mut off: uint = 8;
        if (buf.len() as u64) < (off as u64) + (nfat * size_of::<fat_arch>() as u64) {
            util::errln(format!("fatmacho: no room for {} fat archs", nfat));
            return vec!()
        }
        let mut result = Vec::new();
        for i in range(0, nfat) {
            let fa: fat_arch = util::copy_from_slice(buf.slice(off, off + size_of::<fat_arch>()), util::BigEndian);
            if (fa.offset as u64) + (fa.size as u64) >= (buf.len() as u64) {
                util::errln(format!("fatmacho: bad arch cputype={},{} offset={} size={} (truncated?)",
                              fa.cputype, fa.cpusubtype, fa.offset, fa.size));
            } else {
                let arch = match mach_arch_desc(fa.cputype, fa.cpusubtype) {
                    Some(desc) => desc.to_owned(),
                    None => format!("{}", i),
                };
                for (_ep, pr) in exec::probe_all(eps, Arc::new(util::slice_mc(mc.clone(), fa.offset.to_ui(), fa.size.to_ui()))).move_iter() {
                    let npr = exec::ProbeResult {
                        desc: format!("fat\\#{}: {}", i, pr.desc),
                        arch: pr.arch,
                        likely: pr.likely,
                        cmd: vec!("-arch".to_owned(), arch.clone()).append(pr.cmd.as_slice()),
                    };
                    result.push(npr);
                }
            }
            off += size_of::<fat_arch>();
        }
        result
    }
    fn create(&self, buf: util::ArcMC, pr: &exec::ProbeResult, args: &str) -> Box<exec::Exec> {
        unimplemented!();
    }
}


//#[test]

