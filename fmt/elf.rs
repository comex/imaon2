#![feature(box_syntax)]
#![feature(stmt_expr_attributes)]
#![allow(non_camel_case_types)]
#[macro_use]
extern crate macros;
extern crate util;
extern crate exec;
extern crate elf_bind;

use std::mem::size_of;
use std::fmt::{Display, LowerHex};

use exec::arch::Arch;
use exec::ReadVMA;
use util::{MCRef, SliceExt, ByteStr, ByteString, copy_memory};
use exec::{ExecResult, ErrorKind, Segment, VMA, Prot}; 
use elf_bind::*;

macro_rules! convert_each {
    ($val:expr, $ty:ident, $($field:ident),*) => {
        $ty { $($field: $val.$field.into()),* }
    }
}

pub struct ElfBasics {
    is64: bool,
    endian: util::Endian,
    abi: &'static str,
    type_: &'static str,
    machine: &'static str,
    arch: Arch,
}

#[derive(Default, Debug)]
pub struct DynamicInfo {
    needed: Vec<ByteString>,
    pltgot: Option<VMA>,
    hash: Option<VMA>,
    strtab: Option<OffCountSize>,
    symtab: Option<VMA>,
    syment: Option<u64>,
    gnu_hash: Option<VMA>,
    rela: Option<OffCountSize>,
    rel: Option<OffCountSize>,
    init: Option<VMA>,
    fini: Option<VMA>,
    soname: Option<ByteString>,
    rpath: Vec<ByteString>,
    pltrel: Option<u32>, // type
    pltrelsz: Option<u64>,
    textrel: bool,
    jmprel: Option<VMA>,
    bind_now: bool,
    init_array: Option<OffCountSize>,
    fini_array: Option<OffCountSize>,
    preinit_array: Option<OffCountSize>,
    runpath: Option<ByteString>,
    flags: Option<u32>,
    versym: Option<VMA>,
    verneed: Option<OffCountSize>,
    // shouldn't be used really
    relacount: Option<u32>,
    relcount: Option<u32>,
    dtdebug: bool,
}

#[derive(Default, Debug)]
struct OptOffCountSize {
    off: Option<u64>,
    count: Option<u64>,
    size: Option<u64>,
}

#[derive(Default, Debug)]
struct DynamicInfoTemp {
    strtab: OptOffCountSize,
    rela: OptOffCountSize,
    rel: OptOffCountSize,
    init_array: OptOffCountSize,
    fini_array: OptOffCountSize,
    preinit_array: OptOffCountSize,
    verneed: OptOffCountSize,
}

fn read_cstr<'a>(reader: &ReadVMA, offset: VMA) -> Option<ByteString> {
    let mut size = 32;
    loop {
        let res = reader.read(offset, size);
        let res = res.get();
        if let Some(o) = res.iter().position(|&c| c == 0) {
            return Some(ByteString::from_bytes(&res[..o]));
        }
        if (res.len() as u64) < size { return None; }
        size *= 2;
    }
}


trait_alias!((T), DIFunc, FnMut(&mut T, u32) -> bool);

#[derive(PartialEq, Eq)]
enum OCSType {
    OCSCount,
    OCSTotalSize
}
use OCSType::*;

impl DynamicInfo {
    #[inline(always)]
    fn do_<OS: DIFunc<Option<ByteString>>,
           VS: DIFunc<Vec<ByteString>>,
           OVMA: DIFunc<Option<VMA>>,
           OOCS: FnMut(&mut Option<OffCountSize>, /*temp*/ &mut OptOffCountSize, (u32, u32, u32), OCSType) -> bool,
           OU32: DIFunc<Option<u32>>,
           OU64: DIFunc<Option<u64>>,
           B: DIFunc<bool>,
        >(&mut self, temp: &mut DynamicInfoTemp,
         mut os: OS, mut vs: VS, mut ovma: OVMA, mut oocs: OOCS, mut ou32: OU32,
         mut ou64: OU64, mut b: B) -> bool {
        vs(&mut self.needed, DT_NEEDED) ||
        ovma(&mut self.pltgot, DT_PLTGOT) ||
        ovma(&mut self.hash, DT_HASH) ||
        oocs(&mut self.strtab, &mut temp.strtab, (DT_STRTAB, DT_STRSZ, 0), OCSTotalSize) ||
        ovma(&mut self.symtab, DT_SYMTAB) ||
        ou64(&mut self.syment, DT_SYMENT) ||
        ovma(&mut self.gnu_hash, DT_GNU_HASH) ||
        oocs(&mut self.rela, &mut temp.rela, (DT_RELA, DT_RELASZ, DT_RELAENT), OCSTotalSize) ||
        oocs(&mut self.rel, &mut temp.rel, (DT_REL, DT_RELSZ, DT_RELENT), OCSTotalSize) ||
        ovma(&mut self.init, DT_INIT) ||
        ovma(&mut self.fini, DT_FINI) ||
        os(&mut self.soname, DT_SONAME) ||
        vs(&mut self.rpath, DT_RPATH) ||
        ou32(&mut self.pltrel, DT_PLTREL) ||
        ou64(&mut self.pltrelsz, DT_PLTRELSZ) ||
        b(&mut self.textrel, DT_TEXTREL) ||
        ovma(&mut self.jmprel, DT_JMPREL) ||
        b(&mut self.bind_now, DT_BIND_NOW) ||
        oocs(&mut self.init_array, &mut temp.init_array, (DT_INIT_ARRAY, DT_INIT_ARRAYSZ, 0), OCSTotalSize) ||
        oocs(&mut self.fini_array, &mut temp.fini_array, (DT_FINI_ARRAY, DT_FINI_ARRAYSZ, 0), OCSTotalSize) ||
        oocs(&mut self.preinit_array, &mut temp.preinit_array, (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, 0), OCSTotalSize) ||
        os(&mut self.runpath, DT_RUNPATH) ||
        ou32(&mut self.flags, DT_FLAGS) ||
        oocs(&mut self.verneed, &mut temp.verneed, (DT_VERNEED, DT_VERNEEDNUM, 0), OCSCount) ||
        ovma(&mut self.versym, DT_VERSYM) ||
        ou32(&mut self.relacount, DT_RELACOUNT) ||
        ou32(&mut self.relcount, DT_RELCOUNT) ||
        b(&mut self.dtdebug, DT_DEBUG)
    }
    fn decode(dyn: &[Dyn], reader: &ReadVMA, is64: bool) -> Self {
        // first, try to find some strtab; more detailed warnings will happen during the main loop
        let mut strtab: Option<VMA> = None;
        for d in dyn {
            if d.tag == DT_STRTAB as i64 {
                strtab = Some(VMA(d.val));
            }
        }
        let mut temp: DynamicInfoTemp = Default::default();
        let mut me: DynamicInfo = Default::default();
        temp.strtab.size = Some(1);
        temp.init_array.size = Some(1);
        temp.fini_array.size = Some(1);
        temp.preinit_array.size = Some(1);
        temp.verneed.size = Some(if is64 { size_of::<Elf64_Verneed>() } else { size_of::<Elf32_Verneed>() } as u64);
        for &d in dyn {
            let res = me.do_(&mut temp,
                     #[inline(always)] |os: &mut Option<ByteString>, tag| {
                        if d.tag != tag as i64 { return false; }
                        if let Some(s) = strtab {
                            if let Some(bs) = read_cstr(reader, s + d.val) {
                                *os = Some(bs);
                            } else {
                                errln!("warning: bad {} offset", d.tag_name().unwrap());
                            }
                        } else {
                            errln!("warning: got {} but no DT_STRTAB present", d.tag_name().unwrap());
                        }
                        true
                    },
                    #[inline(always)] |vs: &mut Vec<ByteString>, tag| {
                        if d.tag != tag as i64 { return false; }
                        if let Some(s) = strtab {
                            if let Some(bs) = read_cstr(reader, s + d.val) {
                                vs.push(bs);
                            } else {
                                errln!("warning: bad {} offset", d.tag_name().unwrap());
                            }
                        } else {
                            errln!("warning: got {} but no DT_STRTAB present", d.tag_name().unwrap());
                        }
                        true
                    },
                    #[inline(always)] |ov: &mut Option<VMA>, tag| {
                        if d.tag != tag as i64 { return false; }
                        *ov = Some(VMA(d.val));
                        true
                    },
                    #[inline(always)] |oocs: &mut Option<OffCountSize>, temp: &mut OptOffCountSize, (otag, ctag, stag), typ| {
                        {
                            let p =
                                 if d.tag == otag as i64 { &mut temp.off }
                            else if d.tag == ctag as i64 { &mut temp.count }
                            else if d.tag == stag as i64 { &mut temp.size }
                            else { return false };
                            if p.is_some() {
                                errln!("warning: {} already exists", d.tag_name().unwrap());
                                return true;
                            }
                            *p = Some(d.val);
                        }
                        if let OptOffCountSize { off: Some(off), count: Some(mut count), size: Some(size) } = *temp {
                            if typ == OCSTotalSize {
                                // 'count' is actually total size
                                if count % size != 0 {
                                    errln!("warning: {} total size({}) not divisible by element size({})",
                                           d_tag_to_str(otag).unwrap(), count, size);
                                }
                                count /= size;
                            }
                            if count.checked_mul(size).map(|a| a.checked_add(off)).is_none() {
                                errln!("warning: {} count({}) * size({}) + off({}) overflows",
                                       d_tag_to_str(otag).unwrap(), count, size, off);
                                count = (!0u64 - off) / size;
                            }
                            *oocs = Some(OffCountSize { off: off, count: count, size: size });
                        }
                        true
                    },
                    #[inline(always)] |ou32: &mut Option<u32>, tag| {
                        if d.tag != tag as i64 { return false; }
                        if d.val > 0xffffffff {
                            errln!("warning: {}: out-of-range value {}", d.tag_name().unwrap(), d.val);
                        }
                        *ou32 = Some((d.val & 0xffffffff) as u32);
                        true
                    },
                    #[inline(always)] |ou64: &mut Option<u64>, tag| {
                        if d.tag != tag as i64 { return false; }
                        *ou64 = Some(d.val);
                        true
                    },
                    #[inline(always)] |b: &mut bool, tag| {
                        if d.tag != tag as i64 { return false; }
                        if d.val != 0 {
                            errln!("warning: {} is a present/absent switch but val is {}, not 0",
                                   d.tag_name().unwrap(), d.val);
                        }
                        *b = true;
                        true
                    },
            );
            if !res {
                errln!("warning: unhandled dyn tag {} ({})", d.tag, d.tag_name().unwrap_or("?"));
            }
        }
        me

    }
    pub fn dump(&mut self) {
        let mut temp = DynamicInfoTemp::default(); // useless
        fn display<T: Display>(val: &mut Option<T>, tag: u32) -> bool {
            if let &mut Some(ref v) = val {
                println!("{}: {}", d_tag_to_str(tag).unwrap(), v);
            }
            false
        }
        fn display_hex<T: LowerHex>(val: &mut Option<T>, tag: u32) -> bool {
            if let &mut Some(ref v) = val {
                println!("{}: 0x{:x}", d_tag_to_str(tag).unwrap(), v);
            }
            false
        }
        self.do_(&mut temp,
            /*os*/ display,
            |vs: &mut Vec<ByteString>, tag| {
                for bs in vs {
                    println!("{}: {}", d_tag_to_str(tag).unwrap(), bs);
                }
                false
            },
            /*ovma*/ display,
            |oocs: &mut Option<OffCountSize>, temp: &mut OptOffCountSize, (otag, _ctag, _stag), _typ| {
                if let &mut Some(ref ocs) = oocs {
                    println!("{}: @0x{:x} {} entries of size 0x{:x}", d_tag_to_str(otag).unwrap(), ocs.off, ocs.count, ocs.size);
                }
                false
            },
            /*ou32*/ display_hex,
            /*ou64*/ display_hex,
            /*b*/ |b: &mut bool, tag| {
                if *b {
                    println!("{}: present", d_tag_to_str(tag).unwrap());
                }
                false
            },
        );
    }
    fn get_verneed(&self) {
        //TODO

    }
}

#[derive(Default, Debug)]
pub struct OffCountSize {
    pub off: u64,
    pub count: u64,
    pub size: u64,
}

pub struct Ehdr {
    pub entry: VMA,
    pub flags: u32,
    pub ph: OffCountSize,
    pub sh: OffCountSize,
    pub shstrndx: u16,
    pub version: u32,
}
pub type Phdr = Elf64_Phdr;
pub type Shdr = Elf64_Shdr;

pub struct Elf {
    pub eb: exec::ExecBase,
    pub basics: ElfBasics,
    pub ehdr: Ehdr,
    pub shdrs: Vec<Shdr>,
    pub dyns: Vec<Dyn>,
    pub dynamic_info: DynamicInfo,
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
    let mut eh = branch!(if (basics.is64) {
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

fn get_phdrs(basics: &ElfBasics, buf: &[u8], ocs: &OffCountSize) -> (Vec<Segment>, Vec<Phdr>) {
    let mut off = ocs.off as usize;
    let mut segs = Vec::new();
    let mut phdrs = Vec::new();
    branch!(if (basics.is64) {
        type ElfX_Phdr = Elf64_Phdr;
    } else {
        type ElfX_Phdr = Elf32_Phdr;
    } then {
        let sizeo = size_of::<ElfX_Phdr>();
        if ocs.size < sizeo as u64 {
            errln!("warning: phdr size ({}) too small, expected at least {}", ocs.size, sizeo);
            return (Vec::new(), Vec::new());
        }
        let realsize = ocs.size as usize;
        for i in 0..ocs.count {
            let phdr: ElfX_Phdr = util::copy_from_slice(&buf[off..off+sizeo], basics.endian);
            off += realsize;
            segs.push(Segment {
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
                private: i as usize,
            });
            phdrs.push(
                convert_each!(phdr, Elf64_Phdr,
                    p_type, p_offset, p_vaddr, p_paddr,
                    p_filesz, p_memsz, p_flags, p_align
                )
            );
        }
    });
    (segs, phdrs)
}

fn get_shdrs(basics: &ElfBasics, buf: &[u8], ocs: &OffCountSize) -> (Vec<Segment>, Vec<Shdr>) {
    let mut off = ocs.off as usize;
    let mut segs = Vec::new();
    let mut shdrs = Vec::new();
    branch!(if (basics.is64) {
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dyn {
    pub tag: i64,
    pub val: u64,
}

impl Dyn {
    pub fn tag_name(&self) -> Option<&'static str> {
        if 0 <= self.tag && self.tag <= std::u32::MAX as i64 {
            d_tag_to_str(self.tag as u32)
        } else { None }
    }
}


fn get_dynamic_data(segs: &[Segment], phdrs: &[Phdr], sects: &[Segment], shdrs: &[Shdr]) -> Option<(MCRef, bool)> {
    // following readelf, find ".dynamic" if possible, else PT_DYNAMIC
    let mut the_dynamic: Option<MCRef> = None;
    for (sect, shdr) in sects.iter().zip(shdrs) {
        if sect.name.is_some() && &**sect.name.as_ref().unwrap() == ByteStr::from_str(".dynamic") {
            if the_dynamic.is_some() {
                errln!("warning: extra .dynamic sections... using the later one");
            }
            if sect.data.is_none() {
                errln!("warning: .dynamic section out of file range, skipping this one");
                continue;
            }
            the_dynamic = sect.data.clone();
        } else if shdr.sh_type == SHT_DYNAMIC {
            errln!("warning: section named {} is SHT_DYNAMIC but not called .dynamic, so not using", sect.pretty_name());
        }
    }
    if let Some(x) = the_dynamic { return Some((x, true)); }
    for (seg, phdr) in segs.iter().zip(phdrs) {
        if phdr.p_type == PT_DYNAMIC {
            if the_dynamic.is_some() {
                errln!("warning: extra PT_DYNAMIC segments... using the later one");
            }
            if seg.data.is_none() {
                errln!("warning: PT_DYNAMIC segment out of file range, skipping this one");
                continue;
            }
            the_dynamic = seg.data.clone();
        }
    }
    if the_dynamic.is_some() && sects.len() > 0 {
        errln!("warning: found PT_DYNAMIC but no .dynamic, even though there *is* a section table.  weird.");
    }
    if let Some(x) = the_dynamic { return Some((x, false)); }
    None
}


fn get_dynamic(basics: &ElfBasics, segs: &[Segment], phdrs: &[Phdr], sects: &[Segment], shdrs: &[Shdr]) -> Vec<Dyn> {
    let (the_dynamic, found_in_section) = some_or!(get_dynamic_data(segs, phdrs, sects, shdrs), { return Vec::new(); });
    let buf = the_dynamic.get();
    let mut out = Vec::new();
    let mut offset = 0;
    branch!(if (basics.is64) {
        type ElfX_Dyn = Elf64_Dyn;
    } else {
        type ElfX_Dyn = Elf32_Dyn;
    } then {
        let sizeo = size_of::<ElfX_Dyn>();
        if found_in_section && buf.len() % sizeo != 0 {
            errln!("warning: .dynamic section length not divisible by sizeof(ElfX_Dyn)");
        }
        loop {
            let s = some_or!(buf.slice_opt(offset, offset + sizeo), {
                errln!("warning: ELF dynamic data doesn't end with DT_NULL");
                break;
            });
            let dyn: ElfX_Dyn = util::copy_from_slice(s, basics.endian);
            if dyn.d_tag == (DT_NULL as i32).into() {
                break;
            }
            out.push(Dyn {
                tag: dyn.d_tag.into(),
                // lol bindgen
                val: (unsafe { let mut d_un = dyn.d_un; *d_un.d_ptr() }).into()
            });
            offset += sizeo;
        }
    });
    out
}

impl Elf {
    fn new(buf: MCRef) -> ExecResult<Self> {
        let mut res = {
            let b = buf.get();
            let basics = try!(check_elf_basics(b, true).map_err(|a| exec::err_only(ErrorKind::BadData, a)));
            let ehdr = try!(get_ehdr(&basics, b));
            let (mut segs, phdrs) = get_phdrs(&basics, b, &ehdr.ph);
            let (mut sects, shdrs) = get_shdrs(&basics, b, &ehdr.sh);
            fill_in_data(&mut segs, &buf);
            fill_in_data(&mut sects, &buf);
            fill_in_sect_names(&mut sects, &shdrs, ehdr.shstrndx);
            let dyns = get_dynamic(&basics, &segs, &phdrs, &sects, &shdrs);
            let eb = exec::ExecBase {
                arch: basics.arch,
                endian: basics.endian,
                segments: segs,
                sections: sects,
                whole_buf: None,
            };
            Elf {
                eb: eb,
                basics: basics,
                ehdr: ehdr,
                shdrs: shdrs,
                dyns: dyns,
                dynamic_info: Default::default(),
            }
        };
        res.eb.whole_buf = Some(buf);
        res.dynamic_info = DynamicInfo::decode(&res.dyns, &res.eb, res.basics.is64);
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
    copy_memory(some_or!(buf.slice_opt(0, 20), { return Err("too short"); }), &mut ident);
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
        machine: e_machine_to_str(e_machine as u32).unwrap_or_else(|| {
                if warn { errln!("warning: unknown e_machine {}", e_machine); }
                "unknown-machine"
        }),
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
