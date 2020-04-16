use util;
use exec;
use macho_bind;
use util::{Mem, ByteString, Ext, SliceExt, ByteStr, Narrow, Lazy, Fnv, CheckMul, Cast, Unswapped, CheckSub, ReadCell, LazyBox, LittleEndian};
use exec::ErrorKind::BadData;
use exec::arch;
use exec::{Reloc, RelocKind, RelocTarget, ExecResult, err, ExecBase, VMA, Exec, ExecProber, ProbeResult, Segment, ErrorKind, intersect_start_size};
use std::mem::size_of;
use std::cmp::{min, max, Ordering};
use std::ops::Range;
use std::collections::{HashSet, HashMap};
use std::collections::hash_map::Entry;
use std::any::Any;
use std::cell::Cell;
use std;
pub use macho_bind::{dyld_cache_header, dyld_cache_mapping_info, dyld_cache_image_info, dyld_cache_local_symbols_info, dyld_cache_local_symbols_entry, dyld_cache_slide_info, dyld_cache_slide_info2, DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE, DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA, DYLD_CACHE_SLIDE_PAGE_ATTR_END};
use ::{MachO, GuessBrokenCacheSlideResult, MachODCInfo, file_array};

pub struct ImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path: ByteString,
}

pub struct LocalSymbols {
    entries: Mem<u8>,
    symtab: Mem<u8>,
    strtab: Mem<u8>,
    nlist_count: u32,
}

pub struct DyldCache {
    pub eb: ExecBase,
    pub slide_info: Option<SlideInfo>,
    pub image_info: Vec<ImageInfo>,
    pub uuid: Option<[u8; 16]>,
    pub cs_blob: Option<Mem<u8>>,
    pub local_symbols: Option<LocalSymbols>,
    pub have_images_text_offset: bool,
}

const SLIDE_GRANULARITY: u64 = 4;
pub struct SlideInfoV1 {
    pub toc: Mem<u8>,
    pub entries: Mem<u8>,
    pub entries_size: usize,
    data_addr: VMA,
    data_size: u64,
    endian: util::Endian,
}
const SLAB_PAGES: usize = 128;
pub struct SlideInfoV2 {
    pub page_size: u64,
    pub page_starts: Mem<Unswapped<u16>>,
    pub page_extras: Mem<Unswapped<u16>>,
    pub delta_mask: u64,
    pub delta_shift: u32, // not including the -2
    pub value_add: u64,
    rebase_list_by_slab: Vec<LazyBox<Vec<Reloc<'static>>>>,
}
pub enum SlideInfo {
    V1(SlideInfoV1),
    V2(SlideInfoV2),
}

impl SlideInfo {
    pub fn new(blob: Mem<u8>, end: util::Endian, is64: bool, data_addr: VMA, data_size: u64) -> ExecResult<SlideInfo> {
        let slide_info_version: u32 = {
            let slice = blob.get();
            if slice.len() < 4 {
                return err(BadData, "no data?");
            }
            util::copy_from_slice(&slice[..4], end)
        };
        match slide_info_version {
            1 => Ok(SlideInfo::V1(try!(SlideInfoV1::new(blob, end, data_addr, data_size)))),
            2 => Ok(SlideInfo::V2(try!(SlideInfoV2::new(blob, end, is64)))),
            _ => err(BadData, format!("unknown dyld slide info version {}", slide_info_version)),
        }
    }
    pub fn iter<F>(&self, eb: &ExecBase, range: Option<(VMA, u64)>, mut func: F) where F: FnMut(VMA) {
        match self {
            &SlideInfo::V1(ref v1) => v1.iter(range, func),
            &SlideInfo::V2(ref v2) => {
                let slabs = v2.save_rebase_list(eb, range);
                for slab in slabs {
                    let relocs = &slab.get().unwrap()[..];
                    for reloc in relocs {
                        if let Some((start_addr, size)) = range {
                            if reloc.address.wrapping_sub(start_addr) >= size { continue; }
                        }
                        func(reloc.address);
                    }
                }
            },
        }
    }
}
impl SlideInfoV1 {
    pub fn new(blob: Mem<u8>, end: util::Endian, data_addr: VMA, data_size: u64) -> ExecResult<Self> {
        let slice = blob.get();
        let size = size_of::<dyld_cache_slide_info>();
        if blob.len() < size {
            return err(BadData, "slide info blob too small for header");
        }
        let slide_info: dyld_cache_slide_info =  util::copy_from_slice(&slice[..size], end);
        let toc = file_array(&blob, "toc", slide_info.toc_offset.ext(),
                                           slide_info.toc_count.ext(),
                                           2);
        let entries_size = slide_info.entries_size.ext();
        let entries = file_array(&blob, "entries", slide_info.entries_offset.ext(),
                                                   slide_info.entries_count.ext(),
                                                   entries_size);
        if entries_size > 0xffff {
            return err(BadData, "entries_size too big");
        }
        Ok(SlideInfoV1 {
            toc: toc,
            endian: end,
            entries: entries,
            entries_size: entries_size,
            data_addr: data_addr,
            data_size: data_size,
        })
    }
    pub fn iter<F>(&self, range: Option<(VMA, u64)>, mut func: F) where F: FnMut(VMA) {
        let entries_size = self.entries_size;
        let entry_bytes = entries_size * 8 * (SLIDE_GRANULARITY as usize);
        let (entries, mut toc) = (self.entries.get(), self.toc.get());
        let end = self.endian;
        let (skipped_off, range_start, range_size) = if let Some((start, size)) = range {
            let start_off = start.wrapping_sub(self.data_addr);
            let eb = entry_bytes as u64;
            let s = start_off / eb;
            let e = start_off.saturating_add(size).saturating_add(eb - 1) / eb;
            let e = min(e, (toc.len() / 2) as u64);
            let s = min(s, e);
            toc = &toc[(s*2) as usize..(e*2) as usize];
            (s * (entry_bytes as u64), start, size)
        } else {
            (0, VMA(0), !0)
        };
        let toc_iter = toc.chunks(2);
        let (data_addr, data_size) = (self.data_addr, self.data_size);

        for (i, idx_blob) in toc_iter.enumerate() {
            let idx: u16 = util::copy_from_slice(idx_blob, end);
            let off = (idx as usize) * entries_size;
            let subblob = some_or!(entries.slice_opt(off, off + entries_size), {
                errln!("SlideInfo::iter: toc entry {} out of bounds ({})", i, idx);
                continue
            });
            let mut data_off = (entry_bytes * i) as u64 + skipped_off;
            for c in subblob.iter() {
                let c = c.get();
                for j in 0..8 {
                    if (c >> j) & 1 != 0 {
                        if data_off >= data_size {
                            errln!("DyldCache::get_reloc_list: reloc out of bounds ({} data_size={})",
                                   data_off, data_size);
                            return;
                        }
                        let addr = data_addr + data_off;
                        if addr.wrapping_sub(range_start) < range_size {
                            func(addr);
                        }
                    }
                    data_off += SLIDE_GRANULARITY;
                }
            }
        }
    }
}

impl SlideInfoV2 {
    pub fn new(blob: Mem<u8>, end: util::Endian, is64: bool) -> ExecResult<Self> {
        let size = size_of::<dyld_cache_slide_info2>();
        if blob.len() < size {
            return err(BadData, "slide info blob too small for header");
        }
        let slice = blob.get();
        let slide_info: dyld_cache_slide_info2 = util::copy_from_slice(&slice[..size], end);
        let (page_starts, _) =
            file_array(&blob, "page starts",
                       slide_info.page_starts_offset.ext(),
                       slide_info.page_starts_count.ext(),
                       2).cast();

        let (page_extras, _) =
            file_array(&blob, "page extras",
                            slide_info.page_extras_offset.ext(),
                            slide_info.page_extras_count.ext(),
                            2).cast();
        if slide_info.page_size % 4096 != 0 ||
           slide_info.page_size > 1048576 { // arbitrary
            return err(BadData, "unreasonable slide info 2 page size");
        }
        if slide_info.delta_mask == 0 ||
           (!is64 && slide_info.delta_mask >> 32 != 0) {
            return err(BadData, format!("strange delta_mask 0x{:x}", slide_info.delta_mask));
        }
        if (page_starts.len() as u64).check_mul(slide_info.page_size as u64).is_none() {
            return err(BadData, "unreasonable slide info 2 page count");
        }
        let delta_shift = slide_info.delta_mask.trailing_zeros();
        let num_slabs = (page_starts.len() + SLAB_PAGES - 1) / SLAB_PAGES;
        Ok(SlideInfoV2 {
            page_size: slide_info.page_size.ext(),
            page_starts: page_starts,
            page_extras: page_extras,
            delta_mask: slide_info.delta_mask,
            delta_shift: delta_shift,
            value_add: slide_info.value_add,
            rebase_list_by_slab: (0..num_slabs).map(|_| LazyBox::new()).collect(),
        })
    }
    pub fn save_rebase_list(&self, eb: &ExecBase, range: Option<(VMA, u64)>) -> &[LazyBox<Vec<Reloc<'static>>>] {
        //let _sw = util::stopwatch("save_rebase_list");
        let data_seg = some_or!(eb.segments.get(1), {
            errln!("SlideInfoV2::save_rebase_list: no data segment");
            return &[];
        });
        //println!("save_rebase_list: range={:?} data={:?}", range, (data_seg.vmaddr, data_seg.vmsize));
        if eb.endian != LittleEndian {
            errln!("SlideInfoV2::save_rebase_list: not little endian; hardcoded just for optimization's sake");
            return &[];
        }
        let (mut page_start, mut page_end) = (0usize, self.page_starts.len());
        if let Some((raddr, rsize)) = range {
            // need better utilities for ranges
            let (raddr, rsize) = intersect_start_size((raddr, rsize), (data_seg.vmaddr, data_seg.vmsize));
            page_start = max(page_start, ((raddr - data_seg.vmaddr) / self.page_size) as usize);
            page_end = min(page_end, ((raddr + rsize - data_seg.vmaddr + self.page_size - 1) / self.page_size) as usize);
        }
        //println!("save_rebase_list: page_start={} page_end={}", page_start, page_end);
        if page_start > page_end { return &[]; }
        let delta_mask = self.delta_mask;
        let delta_shift = self.delta_shift;
        let value_add = self.value_add;
        let slab_start = page_start / SLAB_PAGES;
        let slab_end = (page_end + SLAB_PAGES - 1) / SLAB_PAGES;
        for slab in slab_start..slab_end {
            let lazybox = &self.rebase_list_by_slab[slab];
            if lazybox.get().is_some() { continue; }
            let mut rebase_list: Vec<Reloc> = Vec::new();
            let page_extras = self.page_extras.get();
            let page_size = self.page_size as usize;
            let pointer_size = eb.pointer_size;
            assert!(data_seg.name.is_none()); // the eb has to be the whole dyldcache, not a member...
            let data_data: &[Cell<u8>] = data_seg.data.as_ref().unwrap().get_mut();
            let endian = eb.endian;
            let mut got_straddle = false;
            // for each page...
            let page_starts = &self.page_starts.get();
            //println!("slab={} page={}-{} len={}", slab, slab * SLAB_PAGES, (slab + 1) * SLAB_PAGES, page_starts.len());
            let page_starts = &page_starts[slab * SLAB_PAGES .. min((slab + 1) * SLAB_PAGES, page_starts.len())];
            for (i, ps) in page_starts.iter().enumerate() {
                let offset: usize = (slab * SLAB_PAGES + i) * page_size;
                let addr: VMA = data_seg.vmaddr.wrapping_add(offset as u64);
                let ps = ps.copy(endian);
                //println!("{:x}: ps={:x}", i, ps);
                let start: u16;
                let rest_extras: &[ReadCell<Unswapped<u16>>];
                if ps == (DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE as u16) {
                    continue;
                } else if ps & (DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA as u16) == 0 {
                    start = ps * 4;
                    rest_extras = &[];
                } else {
                    let extras_start_idx = (ps & 0x3fff) as usize;
                    let mut extras_idx = extras_start_idx;
                    loop {
                        let pe = some_or!(page_extras.get(extras_idx), {
                            errln!("SlideInfoV2::save_rebase_list: page_extras index out of range");
                            break;
                        });
                        let pe = pe.copy(endian);
                        if pe & (DYLD_CACHE_SLIDE_PAGE_ATTR_END as u16) != 0 { break; }
                        extras_idx += 1;
                    }
                    if extras_start_idx == extras_idx { continue; }
                    start = page_extras[extras_start_idx].copy(endian);
                    rest_extras = &page_extras[extras_start_idx+1..extras_idx];
                }
                let mut rest_extras = rest_extras.into_iter();
                let mut offset_in_page = start as usize;
                // for each linked list...
                loop {
                    // for each entry in the list...
                    loop {
                        //println!("offset={:x} offset_in_page={:x}", offset, offset_in_page);
                        if offset_in_page > page_size - 4 {
                            errln!("SlideInfoV2::save_rebase_list: offset-in-page past page size");
                            break;
                        }
                        if offset_in_page > page_size - pointer_size {
                            // a 64-bit pointer that straddles a page boundary is okay for some reason
                            // and isn't checked for being 0 nor subject to value_add (see vm_shared_region.c)
                            // value_add should be 0 for 64-bit platforms, per dyld
                            if (offset as u64) >= data_seg.vmsize.check_sub(page_size.ext()).unwrap_or(0) {
                                errln!("SlideInfoV2::save_rebase_list: broken straddle hits end?");
                            }
                            rebase_list.push(Reloc {
                                address: addr + offset_in_page.ext(),
                                kind: RelocKind::_32Bit,
                                base: None,
                                target: RelocTarget::ThisImageSlide,
                            });
                            got_straddle = true;
                            break;

                        }
                        let delta: usize;
                        branch! { if (pointer_size == 8) {
                            type Ptr = u64;
                        } else {
                            type Ptr = u32;
                        } then {
                            let slice = some_or!(data_data.slice_opt(offset + offset_in_page, offset + offset_in_page + size_of::<Ptr>()), {
                                errln!("SlideInfoV2::save_rebase_list: out of range of data segment");
                                break;
                            });
                            let number: Ptr = util::copy_from_slice(slice, LittleEndian);
                            //println!("number={:x} delta_shift={} delta_mask={:x}", number, self.delta_shift, self.delta_mask);
                            delta = (4 * ((number & (delta_mask as Ptr)) >> delta_shift)) as usize;
                            let mut value = number & !(delta_mask as Ptr);
                            if value != 0 {
                                value = value.wrapping_add(value_add as Ptr);
                            }
                            util::copy_to_slice(slice, &value, LittleEndian);
                        } }
                        rebase_list.push(Reloc {
                            address: addr + offset_in_page.ext(),
                            kind: RelocKind::Pointer,
                            base: None,
                            target: RelocTarget::ThisImageSlide,
                        });
                        if delta == 0 {
                            break;
                        }
                        if delta > page_size - offset_in_page {
                            errln!("SlideInfoV2::save_rebase_list: offset-in-page out of range");
                            break;
                        }
                        offset_in_page += delta;
                    }

                    let next = some_or!(rest_extras.next(), { break });
                    offset_in_page = (next.copy(endian) & !(DYLD_CACHE_SLIDE_PAGE_ATTR_END as u16)).ext();
                }
            }
            if got_straddle && self.value_add != 0 {
                errln!("warning: SlideInfoV2::save_rebase_list: value_add != 0 and we have 64-bit relocs straddling a page boundary? my behavior will be correct according to what xnu does as of writing, but this is weird so please double-check");
            }
            let _ = lazybox.store(Box::new(rebase_list)); // doesn't matter if this is a dupe
        }
        &self.rebase_list_by_slab[slab_start..slab_end]
    }
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

pub enum SlideMode {
    SlidToPristine,
    PristineToSlid,
}

impl DyldCache {
    pub fn new(mc: Mem<u8>, inner_sects: bool, unslide: bool) -> ExecResult<DyldCache> {
        // note - not all fields in older caches, but at least a page should be there, so don't worry about size calculation
        let hdr_size = size_of::<dyld_cache_header>();
        let (arch, end, is64, hdr) = {
            let buf = mc.get();
            if buf.len() < hdr_size { return err(BadData, "truncated"); }
            let top: [u8; 16] = util::copy_from_slice(&buf[..16], LittleEndian);
            if &top[..7] != b"dyld_v1" {
                return err(BadData, "bad magic");
            }
            let padded_arch = &top[7..16];
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
                return err(BadData, "unknown architecture, ergo can't determine endianness");
            };
            let end = LittleEndian;
            let hdr: dyld_cache_header = util::copy_from_slice(&buf[..hdr_size], end);
            (arch, end, is64, hdr)
        };
        let min_low_offset = min(min(hdr.mappingOffset, hdr.imagesOffset) as u64, hdr.slideInfoOffset) as usize;
        let cs_blob = if min_low_offset >= offset_of!(dyld_cache_header, codeSignatureSize) {
            Some(file_array(&mc, "code signature", hdr.codeSignatureOffset, hdr.codeSignatureSize, 1))
        } else { None };
        let slide_info_blob = if min_low_offset >= offset_of!(dyld_cache_header, slideInfoSize) {
            Some(file_array(&mc, "slide info", hdr.slideInfoOffset, hdr.slideInfoSize, 1))
        } else { None };
        // TODO these checks should become bypassable
        let local_symbols = if min_low_offset >= offset_of!(dyld_cache_header, localSymbolsSize) {
            let ls_mc = file_array(&mc, "slide info blob", hdr.localSymbolsOffset, hdr.localSymbolsSize, 1);
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
                let symtab = file_array(&ls_mc, "dyld cache local symbols - nlist", ls_hdr.nlistOffset.ext(), ls_hdr.nlistCount.ext(), nlist_size);
                let strtab = file_array(&ls_mc, "dyld cache local symbols - strtab", ls_hdr.stringsOffset.ext(), ls_hdr.stringsSize.ext(), 1);
                let entry_size = size_of::<dyld_cache_local_symbols_entry>();
                let entries = file_array(&ls_mc, "dyld cache local symbols - entries", ls_hdr.entriesOffset.ext(), ls_hdr.entriesCount.ext(), entry_size);
                Some(LocalSymbols {
                    entries: entries,
                    symtab: symtab,
                    strtab: strtab,
                    nlist_count: ls_hdr.nlistCount,
                })
            }
        } else { None };
        let uuid = if min_low_offset >= offset_of!(dyld_cache_header, cacheType) {
            Some(hdr.uuid)
        } else { None };
        // we don't actually care about the data
        let have_images_text_offset = min_low_offset >= size_of::<dyld_cache_header>();

        let image_info = {
            let so = size_of::<dyld_cache_image_info>();
            let hdrmc = file_array(&mc, "images info", hdr.imagesOffset.ext(), hdr.imagesCount.ext(), so);
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
            let mapping_mc = file_array(&mc, "mapping info", hdr.mappingOffset.ext(), hdr.mappingCount.ext(), so);
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

                Segment {
                    vmaddr: VMA(mi.address),
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
            eb: ExecBase {
                arch: arch,
                pointer_size: if is64 { 8 } else { 4 },
                endian: end,
                segments: segments,
                sections: vec!(),
                whole_buf: Some(mc),
            },
            slide_info: None,
            image_info: image_info,
            uuid: uuid,
            cs_blob: cs_blob,
            local_symbols: local_symbols,
            have_images_text_offset: have_images_text_offset,
        };
        if let Some(blob) = slide_info_blob {
            match dc.make_slide_info(blob) {
                Ok(x) => dc.slide_info = x,
                Err(e) => errln!("couldn't get slide info: {}", e),
            }
        }
        if inner_sects {
            for ii in &dc.image_info {
                // todo better
                let prefix = ByteString::concat2(ii.path.unix_basename(), ":".into());
                if let Ok(mo) = dc.load_single_image(ii, /*fix_data*/ false) {
                    for sect in mo.eb.sections.into_iter()
                         .chain(mo.eb.segments.into_iter()) {
                        dc.eb.sections.push(
                            Segment { name: Some(ByteString::concat2(&prefix, sect.name.as_ref().unwrap())),
                                            ..sect }
                        );
                    }
                }
            }
        }
        if unslide {
            dc.auto_unslide();
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
    pub fn load_single_image(&self, ii: &ImageInfo, fix_data: bool) -> ExecResult<MachO> {
        //let _sw = util::stopwatch("DyldCache::load_single_image");
        let off = some_or!(exec::addr_to_off(&self.eb.segments, VMA(ii.address), 0),
            return err(BadData,
                       "shared cache image said to be at an unmapped offset"));
        let buf = self.eb.whole_buf.as_ref().unwrap().clone();
        let mut mo = try!(MachO::new(buf, true, Some(MachODCInfo {
            hdr_offset: off as usize,
            have_images_text_offset: self.have_images_text_offset,
        })));
        mo.dsc_tabs = self.get_ls_entry_for_offset(off);
        if fix_data {
            let _sw2 = util::stopwatch("DyldCache::load_single_image fix_data");
            for seg in &mo.eb.segments {
                try!(self.fix_data(Some((seg.vmaddr, seg.vmsize))));
            }
        }
        Ok(mo)
    }
    fn make_slide_info(&self, blob: Mem<u8>) -> ExecResult<Option<SlideInfo>> {
        let data_seg = some_or!(self.eb.segments.get(1), {
            return err(BadData, "no data segment");
        });
        let (data_addr, data_size) = (data_seg.vmaddr, data_seg.vmsize);
        Ok(Some(try!(SlideInfo::new(blob, self.eb.endian, self.eb.pointer_size == 8, data_addr, data_size))))
    }
    pub fn auto_unslide(&mut self) {
        let slide = {
            let ii = some_or!(self.image_info.iter().filter(|ii| ii.path.ends_with(b"/libsystem_malloc.dylib")).next(), {
                errln!("auto_unslide: couldn't find libsystem_malloc.dylib - not a problem if the cache is OK, but won't check for broken slid cache");
                return
            });
            let slide = match self.load_single_image(ii, /*fix_data*/ true) {
                Ok(mo) => mo.guess_broken_cache_slide(self),
                Err(e) => {
                    errln!("auto_unslide: couldn't load libsystem_malloc.dylib: {}", e);
                    return
                }
            };
            match slide {
                GuessBrokenCacheSlideResult::GotNoBindSelf => {
                    errln!("auto_unslide: libsystem_malloc didn't contain any 'this-image' binds, which are supposed to be used to guess the slide; not unsliding");
                    return
                },
                GuessBrokenCacheSlideResult::Inconsistent => {
                    errln!("auto_unslide: not unsliding due to inconsistency");
                    return
                },
                GuessBrokenCacheSlideResult::BlownAway => {
                    errln!("auto_unslide: cache looks slid but can't unslide with new slide info version (data is gone); expect brokenness");
                    return
                },
                GuessBrokenCacheSlideResult::Guess(slide) => slide,
            }
        };
        if slide != 0 {
            let slide: u32 = some_or!(slide.narrow(), {
                errln!("auto_unslide: guessed slide was 0x{:x}, which is impossible as real slides must be < 2^32 (format upgrade?)", slide);
                return
            });
            errln!("auto_unslide: will unslide your broken preslid shared cache (thanks xnu)");
            if let Err(e) = self.unslide_v1(slide) {
                errln!("auto_unslide: ...but failed: {}", e);
            }
        }
    }
    pub fn fix_data(&self, range: Option<(VMA, u64)>) -> ExecResult<()> {
        match self.slide_info {
            Some(SlideInfo::V2(ref v2)) => {
                let _ = v2.save_rebase_list(&self.eb, range);
            },
            _ => (),
        }
        Ok(())
    }

    pub fn unslide_v1(&mut self, slide: u32) -> ExecResult<()> {
        let v1 = match self.slide_info {
            Some(SlideInfo::V1(ref v1)) => v1,
            _ => panic!("unslide_v1: not v1"),
        };
        if self.eb.endian != LittleEndian {
            return err(ErrorKind::Other, "unslide_v1: not little endian");
        }
        let mut overflow = false;
        {
            let whole_slice = self.eb.whole_buf.as_ref().unwrap().get_mut();
            for segment in &self.eb.segments {
                v1.iter(Some((segment.vmaddr, segment.vmsize)), |ptr| {
                    let off = (ptr - segment.vmaddr + segment.fileoff) as usize;
                    let slice = &whole_slice[off..off+4];
                    let old: u32 = util::copy_from_slice(slice, LittleEndian);
                    let new = old.wrapping_sub(slide);
                    overflow = overflow || new > old;
                    util::copy_to_slice(slice, &new, LittleEndian);
                });
            }
        }
        let check_overflow = self.eb.pointer_size > 4;
        if check_overflow && overflow {
            return err(ErrorKind::Other, "slide_by: slide failed due to overflow");
        }
        Ok(())
    }

    pub fn make_canonical_path_map(&self) -> Vec<usize> {
        let mut address_to_idx: HashMap<u64, usize, _> = util::new_fnv_hashmap();
        for (i, ii) in self.image_info.iter().enumerate() {
            match address_to_idx.entry(ii.address) {
                Entry::Vacant(va) => {va.insert(i);},
                Entry::Occupied(mut oc) => {
                    let old = oc.get_mut();
                    let old_path = &self.image_info[*old].path;
                    let new_path = &ii.path;
                    // silly heuristic
                    if new_path == "/usr/lib/libSystem.B.dylib" ||
                       (old_path != "/usr/lib/libSystem.B.dylib" &&
                        new_path.len() > old_path.len()) {
                        *old = i;
                    }
                },
            }
        }
        self.image_info.iter().map(|ii| address_to_idx[&ii.address]).collect()
    }
    pub fn image_info_idx(&self, ii: &ImageInfo) -> usize {
        let ii = ii as *const _ as usize;
        let ii0 = self.image_info.as_ptr() as usize;
        let idx = ii.wrapping_sub(ii0) / size_of::<ImageInfo>();
        assert!(ii == (&self.image_info[idx] as *const _ as usize));
        idx
    }
}

impl Exec for DyldCache {
    fn get_exec_base<'a>(&'a self) -> &'a ExecBase {
        &self.eb
    }
    fn get_reloc_list<'a>(&'a self, specific: Option<&'a Any>) -> Vec<Reloc<'a>> {
        assert!(specific.is_none());
        match self.slide_info {
            Some(SlideInfo::V1(ref v1)) => {
                let mut ret = Vec::new();
                v1.iter(None, |addr| {
                    ret.push(Reloc { address: addr, kind: RelocKind::_32Bit, base: None, target: RelocTarget::ThisImageSlide });
                });
                ret
            },
            Some(SlideInfo::V2(ref v2)) => {
                v2.save_rebase_list(&self.eb, None).iter().flat_map(|slab| {
                    let relocs = slab.get().unwrap();
                    relocs.iter()
                }).cloned().collect()
            },
            None => Vec::new(),
        }
    }

    fn as_any(&self) -> &Any { self as &Any }
}


#[derive(Copy, Clone)]
pub struct DyldWholeProber;
impl ExecProber for DyldWholeProber {
    fn name(&self) -> &str {
        "dyld-whole"
    }
    fn probe(&self, _eps: &Vec<&'static ExecProber>, buf: Mem<u8>) -> Vec<ProbeResult> {
        if let Ok(c) = DyldCache::new(buf, false, false) {
            vec![ProbeResult {
                desc: "whole dyld cache".to_string(),
                arch: c.eb.arch,
                likely: true,
                cmd: vec!["dyld-whole".to_string()],
            }]
        } else {
            vec!()
        }
    }
   fn create(&self, _eps: &Vec<&'static ExecProber>, buf: Mem<u8>, args: Vec<String>) -> ExecResult<(Box<Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "dyld-whole", 0, std::usize::MAX, &mut vec![
            ::getopts::optflag("", "inner-sects", "show sections from inner libraries"),
        ])));
        let inner_sects = m.opt_present("inner-sects");
        let dc = try!(DyldCache::new(buf, inner_sects, /*unslide*/ true));
        {
            let _sw = util::stopwatch("dyld-whole fix_data");
            try!(dc.fix_data(None));
        }
        Ok((Box::new(dc) as Box<Exec>, m.free))
    }
}

#[derive(Copy, Clone)]
pub struct DyldSingleProber;
impl ExecProber for DyldSingleProber {
    fn name(&self) -> &str {
        "dyld-single"
    }
    fn probe(&self, _eps: &Vec<&'static ExecProber>, buf: Mem<u8>) -> Vec<ProbeResult> {
        if let Ok(c) = DyldCache::new(buf, false, false) {
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
                ProbeResult {
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
   fn create(&self, _eps: &Vec<&'static ExecProber>, buf: Mem<u8>, args: Vec<String>) -> ExecResult<(Box<Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "dyld-single [--idx] <basename or full path to lib>", 1, std::usize::MAX, &mut vec![
            ::getopts::optflag("i", "idx", "choose by idx"),
        ])));
        let c = try!(DyldCache::new(buf, false, /*unslide*/ true));
        let mut free = m.free.clone();
        let path = &free.remove(0)[..];
        let bpath = ByteStr::from_str(path);
        let idx = if m.opt_present("i") {
            let r: Result<usize, _> = path.parse();
            if let Ok(i) = r { i } else { return err(ErrorKind::Other, "--idx arg not a number") }
        } else {
            let is_basename = path.find('/') == None;
            let o = c.image_info.iter().position(|ii| {
                bpath == if is_basename { ii.path.unix_basename() } else { &ii.path[..] }
            });
            if let Some(i) = o { i } else { return err(ErrorKind::Other, "no such file in shared cache") }
        };
        let mo = try!(c.load_single_image(&c.image_info[idx], /*fix_data*/ true));
        Ok((Box::new(mo) as Box<Exec>, free))
    }
}

pub struct ImageCache {
    pub seg_map: Vec<SegMapEntry>,
    pub cache: Vec<ImageCacheEntry>,
    pub path_map: HashMap<ByteString, usize, Fnv>,
    pub known_addrs: Lazy<Box<Any+Send>>, // see macho_dsc_extraction
}

pub struct ImageCacheEntry {
    pub mo: ExecResult<MachO>,
    pub addr_syms: Lazy<Box<Any+Send>>, // see macho_dsc_extraction
}

pub struct SegMapEntry {
    pub addr: VMA,
    pub size: u64,
    pub image_idx: usize,
    pub seg_idx: usize,
}

impl ImageCache {
    pub fn new(dc: &DyldCache) -> ImageCache {
        let mut cache = Vec::with_capacity(dc.image_info.len());
        let mut seg_map = Vec::new();
        let mut path_map = util::new_fnv_hashmap();
        for (i, ii) in dc.image_info.iter().enumerate() {
            let res = dc.load_single_image(ii, /*fix_data*/ false);
            if let Ok(ref mo) = res {
                for (j, seg) in mo.eb.segments.iter().enumerate() {
                    seg_map.push(SegMapEntry {
                        addr: seg.vmaddr,
                        size: seg.vmsize,
                        image_idx: i,
                        seg_idx: j,
                    });
                }
            }
            path_map.insert(ii.path.clone(), i);
            assert_eq!(i, cache.len());
            cache.push(ImageCacheEntry {
                mo: res,
                addr_syms: Lazy::new(),
            });
        }
        seg_map.sort_by_key(|entry| entry.addr);
        ImageCache { seg_map: seg_map, cache: cache, path_map: path_map, known_addrs: Lazy::new() }
    }
    pub fn lookup_addr(&self, addr: VMA) -> Option<&SegMapEntry> {
        self.seg_map.binary_search_by(|entry| {
            //println!("< got entry={},{} addr={}", entry.addr, entry.size, addr);
            if addr >= entry.addr + entry.size {
                Ordering::Less
            } else if addr < entry.addr {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }).ok().map(|i| &self.seg_map[i])
    }
    pub fn lookup_path<'a>(&'a self, path: &ByteStr) -> Option<&'a ImageCacheEntry> {
        self.path_map.get(path).map(|&idx| &self.cache[idx])
    }
}

