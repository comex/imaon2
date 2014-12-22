#![feature(macro_rules)]
#![feature(phase)]
#![feature(globs)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#[phase(plugin)]
extern crate macros;
extern crate util;
extern crate exec;
extern crate "bsdlike_getopts" as getopts;
extern crate collections;
extern crate libc;
use std::default::Default;
//use collections::HashMap;
use std::vec::Vec;
use std::mem::replace;
use std::mem::size_of;
use util::{ToUi, VecStrExt, MCRef, Swap, zeroed_t};
use macho_bind::*;
use exec::{arch, VMA, SymbolValue};

#[path="../out/macho_bind.rs"]
mod macho_bind;

// dont bother with the unions
deriving_swap!(
#[repr(C)]
#[deriving(Copy)]
pub struct x_nlist {
    pub n_strx: uint32_t,
    pub n_type: uint8_t,
    pub n_sect: uint8_t,
    pub n_desc: int16_t,
    pub n_value: uint32_t,
}
);
deriving_swap!(
#[repr(C)]
#[deriving(Copy)]
pub struct x_nlist_64 {
    pub n_strx: uint32_t,
    pub n_type: uint8_t,
    pub n_sect: uint8_t,
    pub n_desc: uint16_t,
    pub n_value: uint64_t,
}
);

#[deriving(Default, Show, Copy)]
pub struct SymSubset(uint, uint);
#[deriving(Default, Show, Copy)]
pub struct RelSubset(uint, uint);

#[deriving(Default)]
pub struct MachO {
    pub eb: exec::ExecBase,
    pub is64: bool,
    pub mh: mach_header,
    // old-style symbol table:
    pub nlist_size: uint,
    pub symtab: MCRef,
    pub strtab: MCRef,
    pub localsym: SymSubset,
    pub extdefsym: SymSubset,
    pub undefsym: SymSubset,
    pub toc: MCRef,
    pub modtab: MCRef,
    pub extrefsym: MCRef,
    pub indirectsym: MCRef,
    pub extrel: RelSubset,
    pub locrel: RelSubset,
    // new-style
    pub dyld_rebase: MCRef,
    pub dyld_bind: MCRef,
    pub dyld_weak_bind: MCRef,
    pub dyld_lazy_bind: MCRef,
    pub dyld_export: MCRef,
}

impl exec::Exec for MachO {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }

    fn get_symbol_list(&self, source: exec::SymbolSource) -> Vec<exec::Symbol> {
        if source == exec::SymbolSource::All {
            self.nlist_symbols(0, self.symtab.len() / self.nlist_size)
        } else {
            unimplemented!()
        }
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
        me.eb.buf = mc;
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
            Some(d) => d.into_cow(),
            None => format!("<unknown cpu {}/{}>", self.mh.cputype, self.mh.cpusubtype).into_cow()
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
        self.nlist_size = if self.is64 { size_of::<nlist_64>() } else { size_of::<nlist>() };
        let end = self.eb.endian;
        let buf = self.eb.buf.get();
        //let buf_len = buf.len();
        let mut segi = 0u;
        for _ in range(0, self.mh.ncmds - 1) {
            let lc: load_command = util::copy_from_slice(buf.slice(lc_off, lc_off + 8), end);
            let lc_buf = buf.slice(lc_off, lc_off + lc.cmdsize.to_ui());
            let this_lc_off = lc_off;
            let do_segment = |is64: bool, segs: &mut Vec<exec::Segment>, sects: &mut Vec<exec::Segment>| {
                branch!(if is64 == true {
                    type segment_command_x = segment_command_64;
                    type section_x = section_64;
                } else {
                    type segment_command_x = segment_command;
                    type section_x = section;
                } then {
                    let mut off = size_of::<segment_command_x>();
                    let sc: segment_command_x = util::copy_from_slice(lc_buf.slice_to(off), end);
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
                        name: Some(util::from_cstr(&sc.segname)),
                        prot: segprot,
                        private: this_lc_off,
                    });
                    for _ in range(0, sc.nsects) {
                        let s: section_x = util::copy_from_slice(lc_buf.slice(off, off + size_of::<section_x>()), end);
                        sects.push(exec::Segment {
                            vmaddr: VMA(s.addr as u64),
                            vmsize: s.size as u64,
                            fileoff: s.offset as u64,
                            filesize: s.size as u64,
                            name: Some(util::from_cstr(&s.sectname)),
                            prot: segprot,
                            private: this_lc_off + off,
                        });
                        off += size_of::<section_x>();
                    }
                });
                segi += 1;
            };
            match lc.cmd.to_ui() {
                LC_SEGMENT => do_segment(false, &mut self.eb.segments, &mut self.eb.sections),
                LC_SEGMENT_64 => do_segment(true, &mut self.eb.segments, &mut self.eb.sections),
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    let di: dyld_info_command = util::copy_from_slice(lc_buf.slice_to(size_of::<dyld_info_command>()), end);
                    self.dyld_rebase = self.file_array("dyld rebase info", di.rebase_off, di.rebase_size, 1);
                    self.dyld_bind = self.file_array("dyld bind info", di.bind_off, di.bind_size, 1);
                    self.dyld_weak_bind = self.file_array("dyld weak bind info", di.weak_bind_off, di.weak_bind_size, 1);
                    self.dyld_lazy_bind = self.file_array("dyld lazy bind info", di.lazy_bind_off, di.lazy_bind_size, 1);
                    self.dyld_export = self.file_array("dyld lazy bind info", di.export_off, di.export_size, 1);

                },
                LC_SYMTAB => {
                    let sy: symtab_command = util::copy_from_slice(lc_buf.slice_to(size_of::<symtab_command>()), end);
                    self.symtab = self.file_array("symbol table", sy.symoff, sy.nsyms, self.nlist_size);
                    self.strtab = self.file_array("string table", sy.stroff, sy.strsize, 1);
                    //if sy.std::uint::MAX / nlist_size
                    //sy.symoff

                },
                LC_DYSYMTAB => {
                    let ds: dysymtab_command = util::copy_from_slice(lc_buf.slice_to(size_of::<dysymtab_command>()), end);
                    self.localsym = SymSubset(ds.ilocalsym.to_ui(), ds.nlocalsym.to_ui());
                    self.extdefsym = SymSubset(ds.iextdefsym.to_ui(), ds.nextdefsym.to_ui());
                    self.undefsym = SymSubset(ds.iundefsym.to_ui(), ds.nundefsym.to_ui());
                    self.toc = self.file_array("dylib table of contents", ds.tocoff, ds.ntoc, size_of::<dylib_table_of_contents>());
                    let dylib_module_size = if self.is64 { size_of::<dylib_module_64>() } else { size_of::<dylib_module>() };
                    self.modtab = self.file_array("module table", ds.modtaboff, ds.nmodtab, dylib_module_size);
                    self.extrefsym = self.file_array("referenced symbol table", ds.extrefsymoff, ds.nextrefsyms, size_of::<dylib_reference>());
                    self.indirectsym = self.file_array("'indirect symbol' table", ds.indirectsymoff, ds.nindirectsyms, 4);
                    self.extrel = RelSubset(ds.extreloff.to_ui(), ds.nextrel.to_ui());
                    self.locrel = RelSubset(ds.locreloff.to_ui(), ds.nlocrel.to_ui());
                },


                _ => ()
            }
            lc_off += lc.cmdsize.to_ui();
        }
    }

    fn file_array(&self, name: &str, off: u32, count: u32, elm_size: uint) -> MCRef {
        let off_ = off.to_ui();
        let count_ = count.to_ui();
        let buf_len = self.eb.buf.len();
        if off_ >= buf_len || count_ > (buf_len - off_) / elm_size {
            util::errln(format!("{} ({}, {} * {}-sized elements) out of bounds", name, off_, count_, elm_size));
            Default::default()
        } else {
            self.eb.buf.slice(off_, off_ + count_ * elm_size)
        }
    }


    fn nlist_symbols(&self, start: uint, count: uint) -> Vec<exec::Symbol> {
        let mut result = vec!();
        let data = self.symtab.get();
        let strtab = self.strtab.get();
        let mut off = start * self.nlist_size;
        for _ in range(start, start + count) {
            let slice = data.slice(off, off + self.nlist_size);
            branch!(if self.is64 == true {
                type nlist_x = x_nlist_64;
            } else {
                type nlist_x = x_nlist;
            } then {
                let nl: nlist_x = util::copy_from_slice(slice, self.eb.endian);
                let n_type_field = nl.n_type.to_ui();
                let n_desc_field = nl.n_desc.to_ui();
                let _n_pext = (n_type_field & N_PEXT) != 0;
                let _n_stab = (n_type_field & N_STAB) >> 5;
                let n_type = n_type_field & N_TYPE;
                let weak = (n_desc_field & (N_WEAK_REF | N_WEAK_DEF)) != 0;
                let public = (n_type_field & N_EXT) != 0;
                let name = util::trim_to_null(strtab.slice_from(nl.n_strx.to_ui()));
                let vma = VMA(nl.n_value as u64);
                let vma = if n_desc_field & N_ARM_THUMB_DEF != 0 { vma | 1 } else { vma };
                let val =
                    if n_desc_field & N_SYMBOL_RESOLVER != 0 {
                        SymbolValue::Resolver(vma)
                    } else if n_type == N_UNDF {
                        SymbolValue::Undefined
                    } else if n_type == N_INDR {
                        let indr_name = util::trim_to_null(strtab.slice_from(nl.n_value.to_ui()));
                        SymbolValue::ReExport(indr_name)

                    } else {
                        SymbolValue::Addr(vma)
                    };
                result.push(exec::Symbol {
                    name: name,
                    is_public: public,
                    is_weak: weak,
                    val: val,
                    private: off,
                })
            });
            off += self.nlist_size;
        }
        result
    }
}

#[deriving(Copy)]
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
        let m = util::do_getopts(&*args, "macho ...", 0, std::uint::MAX, &mut vec!(
            // ...
        ));
        (box MachO::new(buf, true)
            .unwrap_or_else(|| panic!("not mach-o"))
            as Box<exec::Exec>,
         m.free)
    }
}

#[deriving(Copy)]
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
    fn probe(&self, eps: &Vec<exec::ExecProberRef>, mc: MCRef) -> Vec<exec::ProbeResult> {
        let mut result = Vec::new();
        let ok = self.probe_cb(&mc, |i, fa| {
            let arch = match mach_arch_desc(fa.cputype, fa.cpusubtype) {
                Some(desc) => desc.to_string(),
                None => format!("{}", i),
            };
            let off = fa.offset.to_ui();
            let size = fa.size.to_ui();
            for pr in exec::probe_all(eps, mc.slice(off, off + size)).into_iter() {
                let npr = exec::ProbeResult {
                    desc: format!("(slice #{}) {}", i, pr.desc),
                    arch: pr.arch,
                    likely: pr.likely,
                    cmd: vec!("fat", "--arch", &*arch).strings() + &*pr.cmd,
                };
                result.push(npr);
            }
        });
        if !ok { return vec!()}
        result
    }

    fn create(&self, eps: &Vec<exec::ExecProberRef>, mc: MCRef, args: Vec<String>) -> (Box<exec::Exec>, Vec<String>) {
        let top = "fat (--arch ARCH | -s SLICE)";
        let mut optgrps = vec!(
            getopts::optopt("", "arch", "choose by arch (OS X standard names)", "arch"),
            getopts::optopt("s", "slice", "choose by slice number", ""),
        );
        let mut m = util::do_getopts(&*args, top, 0, std::uint::MAX, &mut optgrps);
        let slice_num = m.opt_str("slice");
        let arch = m.opt_str("arch");
        if slice_num.is_some() == arch.is_some() {
            util::usage(top, &mut optgrps);
        }
        let slice_i = slice_num.map_or(0u64, |s| from_str(&*s).unwrap());
        let mut result = None;
        let ok = self.probe_cb(&mc, |i, fa| {
            if if let (&None, &Some(ref arch_)) = (&result, &arch) {
                mach_arch_desc(fa.cputype, fa.cpusubtype).map_or(false, |d| d == &**arch_)
            } else {
                i == slice_i
            }
            {
                let off = fa.offset.to_ui();
                let size = fa.size.to_ui();
                result = Some(exec::create(eps, mc.slice(off, off + size), replace(&mut m.free, vec!())));
            }
        });
        if !ok { panic!("invalid fat mach-o"); }
        match result {
            Some(e) => e,
            None => panic!("fat arch matching command line not found")
        }
    }
}


//#[test]

