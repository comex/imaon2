#![feature(macro_rules)]
#![feature(phase)]
#![feature(globs)]
#![allow(non_camel_case_types)]
#[phase(plugin)]
extern crate macros;
extern crate util;
extern crate exec;
extern crate "bsdlike_getopts" as getopts;
extern crate collections;
extern crate sync;
extern crate libc;
use std::default::Default;
//use collections::HashMap;
use std::vec::Vec;
use std::mem::replace;
use std::mem::size_of;
use util::{ToUi, OptionExt, VecStrExt, MCRef};
use macho_bind::*;
use exec::{arch, VMA};

#[path="../out/macho_bind.rs"]
mod macho_bind;

#[deriving(Default)]
pub struct MachO {
    eb: exec::ExecBase,
    is64: bool,
    mh: mach_header,
}

impl exec::Exec for MachO {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
}

fn mach_arch_desc(cputype: i32, cpusubtype: i32) -> Option<&'static str> {
    let cputype = cputype as u32;
    let cpusubtype = cpusubtype as u32;
    Some(match (cputype.to_ui(), cpusubtype.to_ui() & !0x80000000) {
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
    pub fn new(mc: MCRef, do_lcs: bool) -> Option<MachO> {
        let mut me: MachO = Default::default();
        let mut lc_off = size_of::<mach_header>();
        {
            let buf = mc.get();
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
        }
        me.eb.buf = Some(mc);
        me.parse_header();
        if do_lcs {
            me.parse_load_commands(lc_off);
        }
        Some(me)
    }

    pub fn subtype_desc(&self) -> Option<&'static str> {
        mach_arch_desc(self.mh.cputype, self.mh.cpusubtype)
    }

    pub fn desc(&self) -> String {
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
        let buf = self.eb.buf.unwrap_ref().get();
        let segs = &mut self.eb.segments;
        let sects = &mut self.eb.sections;
        let mut segi = 0u;
        for _ in range(0, self.mh.ncmds - 1) {
            let lc: load_command = util::copy_from_slice(buf.slice(lc_off, lc_off + 8), end);
            let data = buf.slice(lc_off, lc_off + lc.cmdsize.to_ui());
            let this_lc_off = lc_off;
            let do_segment = |is64: bool| {
                branch!(if is64 == true {
                    type segment_command_x = segment_command_64;@
                    type section_x = section_64;
                } else {
                    type segment_command_x = segment_command;@
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
                        vmaddr: VMA(sc.vmaddr as u64),
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
                            vmaddr: VMA(s.addr as u64),
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
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        match MachO::new(buf, false) {
            Some(m) => vec!(exec::ProbeResult {
                desc: m.desc(),
                arch: m.eb.arch,
                likely: true,
                cmd: vec!("macho".to_string()),
            }),
            None => vec!(),
        }
    }
   fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef, args: Vec<String>) -> (Box<exec::Exec>, Vec<String>) {
        (box MachO::new(buf, true)
            .unwrap_or_else(|| fail!("not mach-o"))
            as Box<exec::Exec>,
         args)
    }
}

pub struct FatMachOProber;

impl FatMachOProber {
    fn probe_cb(&self, mc: &MCRef, cb: |u64, fat_arch|) -> bool {
        let buf = mc.get();
        if buf.len() < 8 { return false }
        let fh: fat_header = util::copy_from_slice(buf.slice_to(8), util::BigEndian);
        if fh.magic != FAT_MAGIC as u32 { return false }
        let nfat = fh.nfat_arch as u64;
        let mut off: uint = 8;
        if (buf.len() as u64) < (off as u64) + (nfat * size_of::<fat_arch>() as u64) {
            util::errln(format!("fatmacho: no room for {} fat archs", nfat));
            return false
        }
        for i in range(0, nfat) {
            let fa: fat_arch = util::copy_from_slice(buf.slice(off, off + size_of::<fat_arch>()), util::BigEndian);
            if (fa.offset as u64) + (fa.size as u64) >= (buf.len() as u64) {
                util::errln(format!("fatmacho: bad arch cputype={},{} offset={} size={} (truncated?)",
                              fa.cputype, fa.cpusubtype, fa.offset, fa.size));
            } else {
                cb(i, fa);
            }
            off += size_of::<fat_arch>();
        }
        true
    }
}

impl exec::ExecProber for FatMachOProber {
    fn name(&self) -> &str {
        "fat"
    }
    fn probe(&self, eps: &Vec<&'static exec::ExecProber+'static>, mc: MCRef) -> Vec<exec::ProbeResult> {
        let mut result = Vec::new();
        let ok = self.probe_cb(&mc, |i, fa| { 
            let arch = match mach_arch_desc(fa.cputype, fa.cpusubtype) {
                Some(desc) => desc.to_string(),
                None => format!("{}", i),
            };
            let off = fa.offset.to_ui();
            let size = fa.size.to_ui();
            for (_ep, pr) in exec::probe_all(eps, mc.slice(off, off + size)).into_iter() {
                let npr = exec::ProbeResult {
                    desc: format!("(slice #{}) {}", i, pr.desc),
                    arch: pr.arch,
                    likely: pr.likely,
                    cmd: vec!("fat", "-arch", arch.as_slice()).owneds() + pr.cmd,
                };
                result.push(npr);
            }
        });
        if !ok { return vec!()}
        result
    }

    fn create(&self, eps: &Vec<&'static exec::ExecProber+'static>, mc: MCRef, mut args: Vec<String>) -> (Box<exec::Exec>, Vec<String>) {
        // -arch is so common in OS X that let's make an exception...
        for arg in args.iter_mut() {
            if !arg.as_slice().starts_with("-") { break }
            if arg.equiv(&"-arch") {
                *arg = "--arch".to_string();
            }
        }
        let top = "fat (-arch ARCH | -s SLICE)";
        let mut optgrps = vec!(
            getopts::optopt("", "arch", "choose by arch (OS X standard names)", "arch"),
            getopts::optopt("s", "slice", "choose by slice number", ""),
        );
        let mut m = util::do_getopts(args.as_slice(), top, 0, std::uint::MAX, &mut optgrps);
        let slice_num = m.opt_str("slice");
        let arch = m.opt_str("arch");
        if slice_num.is_some() == arch.is_some() {
            util::usage(top, &mut optgrps);
        }
        let slice_i = slice_num.map_or(0u64, |s| from_str(s.as_slice()).unwrap());
        let mut result = None;
        let ok = self.probe_cb(&mc, |i, fa| {
            if !result.is_some() && if arch.is_some() {
                  mach_arch_desc(fa.cputype, fa.cpusubtype).map_or(false, |d| d == arch.as_ref().unwrap().as_slice())
               } else {
                  i == slice_i
               }
            {
                let off = fa.offset.to_ui();
                let size = fa.size.to_ui();
                result = Some(exec::create(eps, mc.slice(off, off + size), replace(&mut m.free, vec!())));
            }
        });
        if !ok { fail!("invalid fat mach-o"); }
        match result {
            Some(e) => e,
            None => fail!("fat arch matching command line not found")
        }
    }
}


//#[test]

