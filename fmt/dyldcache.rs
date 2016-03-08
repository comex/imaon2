extern crate util;
extern crate exec;
use macho_bind;
use util::{MCRef, ByteString};
use exec::ErrorKind::BadData;
use exec::arch;
use exec::{Reloc, RelocKind};
use std::mem::{size_of};
use std::cmp::min;
use std::ops::Range;
use std::collections::HashSet;
use std::any::Any;
use std;
use util::{ByteStr, CheckMath};
pub use macho_bind::{dyld_cache_header, dyld_cache_mapping_info, dyld_cache_image_info, dyld_cache_local_symbols_info, dyld_cache_local_symbols_entry, dyld_cache_slide_info};

pub struct ImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path: ByteString,
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

/*
// (off, size), (off, size)
fn range_check(big: (usize, usize), little: (usize, usize)) {
    little.0 >= big.0 && little.1 <= (big.0 + big.1 - little.0)
}
*/

pub fn iter_slide_info<F>(blob: &MCRef, end: util::Endian, range: Option<(u64, u64)>,
                          mut func: F) -> bool where F: FnMut(u64) {
    let slice = blob.get();
    let size = size_of::<dyld_cache_slide_info>();
    if blob.len() < size {
        errln!("iter_slide_info: slide info blob too small for header");
        return false;
    }
    let slide_info: dyld_cache_slide_info =  util::copy_from_slice(&slice[..size], end);
    if slide_info.version > 1 {
        errln!("iter_slide_info: slide info blob version > 1");
        return false;
    }
    let toc = ::file_array_64(blob, "toc", slide_info.toc_offset as u64,
                                           slide_info.toc_count as u64,
                                           2);
    let entries_size = slide_info.entries_size as usize;
    let entries = ::file_array_64(blob, "entries", slide_info.entries_offset as u64,
                                                   slide_info.entries_count as u64,
                                                   entries_size);
    if entries_size > 0xffff {
        errln!("iter_slide_info: entries_size {} way too big (should be 128)", entries_size);
        return false;
    }
    let entries = entries.get();
    let granularity = 4;
    let entry_bytes = entries_size * 8 * granularity;


    let mut toc = toc.get();
    let (base_off, range_size) = if let Some((start, size)) = range {
        let eb = entry_bytes as u64;
        let s = start / eb * 2;
        let e = some_or!(start.check_add(size).check_add(eb - 1),
                         { errln!("iter_slide_info: range overflow"); return false; })
                / eb * 2;
        let e = min(e, toc.len() as u64);
        let s = min(s, e);
        toc = &toc[s as usize..e as usize];
        (start % eb, size)
    } else {
        (0, !0)
    };
    let toc_iter = toc.chunks(2);

    let true_entries_count = entries.len() / entries_size;
    for (i, idx_blob) in toc_iter.enumerate() {
        let idx: u16 = util::copy_from_slice(idx_blob, end);
        if idx as usize >= true_entries_count {
            errln!("iter_slide_info: toc entry {} out of bounds ({})", i, idx);
            continue;
        }
        let off = (idx as usize) * entries_size;
        let subblob = &entries[off..off+entries_size];
        let mut addr_off = (entry_bytes * i) as u64;
        for &c in subblob.iter() {
            for j in 0..8 {
                if (c >> j) & 1 != 0 &&
                    addr_off.wrapping_sub(base_off) < range_size {
                    func(addr_off - base_off);
                }
                addr_off += 4;
            }
        }
    }
    true
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
    pub fn new(mc: MCRef, inner_sects: bool) -> exec::ExecResult<DyldCache> {
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
                if hdr.localSymbolsSize > 0 {
                    errln!("local symbols blob too small for header");
                }
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
                    path: util::from_cstr(&buf[ii.pathFileOffset as usize..]).to_owned(),
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
        let mut dc = DyldCache {
            eb: exec::ExecBase {
                arch: arch,
                pointer_size: if is64 { 8 } else { 4 },
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
        };
        if inner_sects {
            for ii in &dc.image_info {
                // todo better
                let prefix = ByteString::concat2(ii.path.unix_basename(), ":".into());
                if let Ok(mo) = dc.load_single_image(ii) {
                    for sect in mo.eb.sections.into_iter()
                         .chain(mo.eb.segments.into_iter()) {
                        dc.eb.sections.push(
                            exec::Segment { name: Some(ByteString::concat2(&prefix, sect.name.as_ref().unwrap())),
                                            ..sect }
                        );
                    }
                }
            }
        }
        Ok(dc)
    }
    pub fn get_ls_entry_for_offset(&self, off: u64) -> Option<::DscTabs> {
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
    pub fn load_single_image(&self, ii: &ImageInfo) -> exec::ExecResult<::MachO> {
        let off = some_or!(exec::addr_to_off(&self.eb.segments, exec::VMA(ii.address), 0),
            return exec::err(exec::ErrorKind::BadData,
                             "shared cache image said to be at an unmapped offset"));
        let buf = self.eb.whole_buf.as_ref().unwrap().clone();
        let mut mo = try!(::MachO::new(buf, true, off as usize));
        mo.dsc_tabs = self.get_ls_entry_for_offset(off);
        Ok(mo)
    }
}

impl exec::Exec for DyldCache {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
    fn get_reloc_list(&self, specific: Option<&Any>) -> Vec<Reloc> {
        assert!(specific.is_none());
        let mut ret = Vec::new();
        let slide_info_blob = some_or!(self.slide_info_blob.as_ref(), { return ret; });
        let data_seg = some_or!(self.eb.segments.get(1), {
            errln!("DyldCache::get_reloc_list: no data segment");
            return ret;
        });
        let (data_addr, data_size) = (data_seg.vmaddr, data_seg.vmsize);
        iter_slide_info(slide_info_blob,
                        self.eb.endian,
                        None,
                        |offset| {
            if offset > data_size {
                errln!("DyldCache::get_reloc_list: reloc out of bounds ({} data_size={})",
                       offset, data_size);
                return;
            }
            ret.push(Reloc { address: data_addr + offset, kind: RelocKind::_32Bit, addend: None });
        });
        ret
    }

    fn as_any(&self) -> &Any { self as &Any }
}


#[derive(Copy, Clone)]
pub struct DyldWholeProber;
impl exec::ExecProber for DyldWholeProber {
    fn name(&self) -> &str {
        "dyld-whole"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        if let Ok(c) = DyldCache::new(buf, false) {
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
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "dyld-whole", 1, std::usize::MAX, &mut vec![
            ::getopts::optflag("", "inner-sects", "show sections from inner libraries"),
        ])));
        let inner_sects = m.opt_present("inner-sects");
        let c = try!(DyldCache::new(buf, inner_sects));
        Ok((Box::new(c) as Box<exec::Exec>, m.free))
    }
}

#[derive(Copy, Clone)]
pub struct DyldSingleProber;
impl exec::ExecProber for DyldSingleProber {
    fn name(&self) -> &str {
        "dyld-single"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        if let Ok(c) = DyldCache::new(buf, false) {
            let mut seen_basenames = HashSet::new();
            c.image_info.iter().enumerate().map(|(i, ii)| {
                let cmd0 = "dyld-single".to_string();
                let basename = ii.path.unix_basename();
                let str_ver = std::str::from_utf8(basename).ok();
                let cmd = if str_ver.is_some() && seen_basenames.insert(str_ver) {
                    vec![cmd0, basename.to_string()]
                } else {
                    vec![cmd0, "-i".to_string(), format!("{}", i)]
                };
                exec::ProbeResult {
                    desc: ii.path.lossy().to_string(),
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
        let c = try!(DyldCache::new(buf, false));
        let mut free = m.free.clone();
        let path = &free.remove(0)[..];
        let bpath = ByteStr::from_str(path);
        let idx = if m.opt_present("i") {
            let r: Result<usize, _> = path.parse();
            if let Ok(i) = r { i } else { return exec::err(exec::ErrorKind::Other, "--idx arg not a number") }
        } else {
            let is_basename = path.find('/') == None;
            let o = c.image_info.iter().position(|ii| {
                bpath == if is_basename { ii.path.unix_basename() } else { &ii.path[..] }
            });
            if let Some(i) = o { i } else { return exec::err(exec::ErrorKind::Other, "no such file in shared cache") }
        };
        let mo = try!(c.load_single_image(&c.image_info[idx]));
        Ok((Box::new(mo) as Box<exec::Exec>, free))
    }
}
