extern crate util;
extern crate exec;
use macho_bind;
use util::MCRef;
use exec::ErrorKind::BadData;
use exec::arch;
use std::mem::{size_of};
use std::cmp::min;
use std::ops::Range;
use std::collections::HashSet;
use std;
pub use macho_bind::{dyld_cache_header, dyld_cache_mapping_info, dyld_cache_image_info, dyld_cache_local_symbols_info, dyld_cache_local_symbols_entry};
pub struct ImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path: String,
}

pub struct LocalSymbols {
    entries: MCRef,
    symtab: MCRef,
    strtab: MCRef,
    nlist_count: u32,
}

pub struct DyldCache {
    pub eb: exec::ExecBase,
    pub image_info: Vec<ImageInfo>,
    pub uuid: Option<[u8; 16]>,
    pub slide_info_blob: Option<MCRef>,
    pub cs_blob: Option<MCRef>,
    local_symbols: Option<LocalSymbols>,
}

trait RangeCast {
    fn range_cast(self) -> Range<usize>;
}
impl RangeCast for Range<u32> {
    fn range_cast(self) -> Range<usize> { (self.start as usize..self.end as usize) }
}
impl RangeCast for Range<u64> {
    fn range_cast(self) -> Range<usize> { (self.start as usize..self.end as usize) }
}

impl DyldCache {
    pub fn new(mc: MCRef) -> exec::ExecResult<DyldCache> {
        // note - not all fields in older caches, but at least a page should be there, so don't worry about size calculation
        let hdr_size = size_of::<dyld_cache_header>();
        let (arch, end, is64, hdr) = {
            let buf = mc.get();
            if buf.len() < hdr_size { return exec::err(BadData, "truncated"); }
            if &buf[..7] != b"dyld_v1" {
                return exec::err(BadData, "bad magic");
            }
            let padded_arch = &buf[7..16];
            let (arch, is64) = if padded_arch == b"    i386\0" {
                (arch::X86, false)
            } else if padded_arch == b"  x86_64\0" {
                (arch::X86_64, true)
            } else if padded_arch == b"   armv7\0" ||
                      padded_arch == b"   armv6\0" ||
                      padded_arch == b"  armv7s\0" ||
                      padded_arch == b"  armv7k\0" {
                (arch::ARM, false)
            } else if padded_arch == b"   arm64\0" {
                (arch::AArch64, true)
            } else {
                return exec::err(BadData, "unknown architecture, ergo can't determine endianness");
            };
            let end = util::LittleEndian;
            let hdr: dyld_cache_header = util::copy_from_slice(&buf[..hdr_size], end);
            (arch, end, is64, hdr)
        };
        let min_low_offset = min(min(hdr.mappingOffset, hdr.imagesOffset) as u64, hdr.slideInfoOffset) as usize;
        let cs_blob = if min_low_offset >= offset_of!(dyld_cache_header, codeSignatureSize) {
            Some(::file_array_64(&mc, "code signature", hdr.codeSignatureOffset, hdr.codeSignatureSize, 1))
        } else { None };
        let slide_info = if min_low_offset >= offset_of!(dyld_cache_header, slideInfoSize) {
            Some(::file_array_64(&mc, "slide info", hdr.slideInfoOffset, hdr.slideInfoSize, 1))
        } else { None };
        // TODO these checks should become bypassable
        let local_symbols = if min_low_offset >= offset_of!(dyld_cache_header, localSymbolsSize) {
            let ls_mc = ::file_array_64(&mc, "slide info blob", hdr.localSymbolsOffset, hdr.localSymbolsSize, 1);
            let so = size_of::<dyld_cache_local_symbols_info>() as u64;
            if hdr.localSymbolsSize < so {
                errln!("local symbols blob too small for header");
                None
            } else {
                let ls_hdr: dyld_cache_local_symbols_info = util::copy_from_slice(&ls_mc.get()[..so as usize], end);
                let nlist_size = if is64 {
                    size_of::<macho_bind::nlist_64>()
                } else {
                    size_of::<macho_bind::nlist>()
                } as usize;
                let symtab = ::file_array(&ls_mc, "dyld cache local symbols - nlist", ls_hdr.nlistOffset, ls_hdr.nlistCount, nlist_size);
                let strtab = ::file_array(&ls_mc, "dyld cache local symbols - strtab", ls_hdr.stringsOffset, ls_hdr.stringsSize, 1);
                let entry_size = size_of::<dyld_cache_local_symbols_entry>();
                let entries = ::file_array(&ls_mc, "dyld cache local symbols - entries", ls_hdr.entriesOffset, ls_hdr.entriesCount, entry_size);
                Some(LocalSymbols {
                    entries: entries,
                    symtab: symtab,
                    strtab: strtab,
                    nlist_count: ls_hdr.nlistCount,
                })
            }
        } else { None };
        let uuid = if min_low_offset >= size_of::<dyld_cache_header>() {
            Some(hdr.uuid)
        } else { None };

        let image_info = {
            let so = size_of::<dyld_cache_image_info>();
            let hdrmc = ::file_array(&mc, "images info", hdr.imagesOffset, hdr.imagesCount, so);
            let hdrbuf = hdrmc.get();
            let buf = mc.get();
            hdrbuf.chunks(so).map(|ii_buf| {
                let ii: dyld_cache_image_info = util::copy_from_slice(ii_buf, end);
                ImageInfo {
                    address: ii.address,
                    mod_time: ii.modTime,
                    inode: ii.inode,
                    path: util::from_cstr(&buf[ii.pathFileOffset as usize..]),
                }
            }).collect()
        };
        let segments: Vec<_> = {
            let so = size_of::<dyld_cache_mapping_info>();
            let mapping_mc = ::file_array(&mc, "mapping info", hdr.mappingOffset, hdr.mappingCount, so);
            let len = mc.len() as u64;
            mapping_mc.get().chunks(so).enumerate().map(|(i, mi_buf)| {
                let mut mi: dyld_cache_mapping_info = util::copy_from_slice(mi_buf, end);
                if mi.fileOffset >= len {
                    errln!("warning: mapping_info {} in shared cache offset ({}) past end of file ({})", i, mi.fileOffset, len);
                    mi.size = 0;
                    mi.fileOffset = 0;
                } else if mi.size > len - mi.fileOffset {
                    errln!("warning: mapping_info {} in shared cache bounds ({}+{}) extend past end of file ({}); truncating", i, mi.fileOffset, mi.size, len);
                    mi.size = len - mi.fileOffset;
                }

                exec::Segment {
                    vmaddr: exec::VMA(mi.address),
                    vmsize: mi.size,
                    fileoff: mi.fileOffset,
                    filesize: mi.size,
                    name: None,
                    prot: ::u32_to_prot(mi.initProt),
                    data: mc.slice(mi.fileOffset as usize, (mi.fileOffset + mi.size) as usize),
                    seg_idx: None,
                    private: hdr.mappingOffset as usize + i * so,
                }
            }).collect()
        };

        Ok(DyldCache {
            eb: exec::ExecBase {
                arch: arch,
                endian: end,
                segments: segments,
                sections: vec!(),
                whole_buf: Some(mc),
            },
            image_info: image_info,
            uuid: uuid,
            slide_info_blob: slide_info,
            cs_blob: cs_blob,
            local_symbols: local_symbols,
        })
    }
    pub fn get_ls_entry_for_offset(self, off: u64) -> Option<::DscTabs> {
        let entry_size = size_of::<dyld_cache_local_symbols_entry>();
        if let Some(ref ls) = self.local_symbols {
            let entries = ls.entries.get();
            for entry_slice in entries.chunks(entry_size) {
                let entry: dyld_cache_local_symbols_entry = util::copy_from_slice(entry_slice, self.eb.endian);
                if entry.dylibOffset as u64 == off {
                    if entry.nlistStartIndex > ls.nlist_count || entry.nlistCount > ls.nlist_count - entry.nlistStartIndex {
                        errln!("warning: shared cache local symbols entry out of range");
                        return None;
                    } else {
                        return Some(::DscTabs { symtab: ls.symtab.clone(), strtab: ls.strtab.clone(), start: entry.nlistStartIndex, count: entry.nlistCount });
                    }
                }
            }
            None
        } else { None }
    }
}

impl exec::Exec for DyldCache {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }

    fn as_any(&self) -> &std::any::Any { self as &std::any::Any }
}


#[derive(Copy, Clone)]
pub struct DyldWholeProber;
impl exec::ExecProber for DyldWholeProber {
    fn name(&self) -> &str {
        "dyld-whole"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        if let Ok(c) = DyldCache::new(buf) {
            vec![exec::ProbeResult {
                desc: "whole dyld cache".to_string(),
                arch: c.eb.arch,
                likely: true,
                cmd: vec!["dyld-whole".to_string()],
            }]
        } else {
            vec!()
        }
    }
   fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "dyld-whole", 0, std::usize::MAX, &mut vec!())));
        let c = try!(DyldCache::new(buf));
        Ok((Box::new(c) as Box<exec::Exec>, m.free))
    }
}

fn get_basename(ii: &ImageInfo) -> &str {
    if let Some(pos) = ii.path.rfind('/') { &ii.path[pos+1..] } else { &ii.path[..] }
}

#[derive(Copy, Clone)]
pub struct DyldSingleProber;
impl exec::ExecProber for DyldSingleProber {
    fn name(&self) -> &str {
        "dyld-single"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        if let Ok(c) = DyldCache::new(buf) {
            let mut seen_basenames = HashSet::new();
            c.image_info.iter().enumerate().map(|(i, ii)| {
                let cmd0 = "dyld-single".to_string();
                let basename = get_basename(ii);
                let cmd = if seen_basenames.insert(basename.to_string()) {
                    vec![cmd0, basename.to_string()]
                } else {
                    vec![cmd0, "-i".to_string(), format!("{}", i)]
                };
                exec::ProbeResult {
                    desc: ii.path.clone(),
                    arch: c.eb.arch,
                    likely: true,
                    cmd: cmd,
                }
            }).collect()
        } else {
            vec!()
        }
    }
   fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "dyld-single [--idx] <basename or full path to lib>", 1, std::usize::MAX, &mut vec![
            ::getopts::optflag("i", "idx", "choose by idx"),
        ])));
        let c = try!(DyldCache::new(buf.clone()));
        let mut free = m.free.clone();
        let path = &free.remove(0)[..];
        let idx = if m.opt_present("i") {
            let r: Result<usize, _> = path.parse();
            if let Ok(i) = r { i } else { return exec::err(exec::ErrorKind::Other, "--idx arg not a number") }
        } else {
            let is_basename = path.find('/') == None;
            let o = c.image_info.iter().position(|ii| {
                path == if is_basename { get_basename(ii) } else { &ii.path[..] }
            });
            if let Some(i) = o { i } else { return exec::err(exec::ErrorKind::Other, "no such file in shared cache") }
        };
        let off = {
            let ii = &c.image_info[idx];
            if let Some(o) = exec::addr_to_off(&c.eb.segments, exec::VMA(ii.address), 0) { o } else { return exec::err(exec::ErrorKind::BadData, "shared cache image said to be at an unmapped offset") }
        };
        let mut mo = try!(::MachO::new(buf, true, off as usize));
        mo.dsc_tabs = c.get_ls_entry_for_offset(off);
        Ok((Box::new(mo) as Box<exec::Exec>, free))
    }
}
