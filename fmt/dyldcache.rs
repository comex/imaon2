extern crate util;
extern crate exec;
use macho_bind;
use util::MCRef;
use exec::ErrorKind::BadData;
use exec::arch;
use std::mem::{size_of};
use std::cmp::min;
use std::ops::Range;
use std;
pub use macho_bind::{dyld_cache_header, dyld_cache_mapping_info, dyld_cache_image_info, dyld_cache_local_symbols_info, dyld_cache_local_symbols_entry};
pub struct ImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path: String,
}

pub struct DyldCache {
    pub eb: exec::ExecBase,
    pub image_info: Vec<ImageInfo>,
    pub uuid: Option<[u8; 16]>,
    pub slide_info_blob: Option<MCRef>,
    pub cs_blob: Option<MCRef>,
    ls_info: Option<(dyld_cache_local_symbols_info, MCRef)>,
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
                      padded_arch == b"   armv6\0" {
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
            Some(mc.slice(hdr.codeSignatureOffset as usize, (hdr.codeSignatureOffset+hdr.codeSignatureSize) as usize))
        } else { None };
        let slide_info = if min_low_offset >= offset_of!(dyld_cache_header, slideInfoSize) {
            Some(mc.slice(hdr.slideInfoOffset as usize, (hdr.slideInfoOffset+hdr.slideInfoSize) as usize))
        } else { None };
        // TODO these checks should become bypassable
        let ls_info = if min_low_offset >= offset_of!(dyld_cache_header, localSymbolsSize) {
            let ls_blob = mc.slice(hdr.slideInfoOffset as usize, (hdr.slideInfoOffset+hdr.slideInfoSize) as usize);
            let so = size_of::<dyld_cache_local_symbols_info>() as u64;
            if hdr.slideInfoSize < so {
                return exec::err(BadData, "local symbols blob too small for header");
            }
            let lshdr: dyld_cache_local_symbols_info = util::copy_from_slice(&ls_blob.get()[..so as usize], end);
            let nlist_size = if is64 {
                size_of::<macho_bind::nlist_64>()
            } else {
                size_of::<macho_bind::nlist>()
            } as u64;
            if lshdr.nlistOffset as u64 >= hdr.slideInfoSize || (hdr.slideInfoSize - lshdr.nlistOffset as u64) / nlist_size < lshdr.nlistCount as u64 {
                return exec::err(BadData, "bad nlist offset/count");
            }
            let entry_size = size_of::<dyld_cache_local_symbols_entry>() as u64;
            if lshdr.entriesOffset as u64 >= hdr.slideInfoSize || (hdr.slideInfoSize - lshdr.entriesOffset as u64) / entry_size < lshdr.entriesCount as u64 {
                return exec::err(BadData, "bad LS entry offset/count");
            }
            Some((lshdr, ls_blob))
        } else { None };
        let uuid = if min_low_offset >= size_of::<dyld_cache_header>() {
            Some(hdr.uuid)
        } else { None };

        let image_info = {
            let so = size_of::<dyld_cache_image_info>() as u64;
            let len = mc.len() as u64;
            let images_offset = hdr.imagesOffset as u64;
            let images_count = hdr.imagesCount as u64;
            if images_offset as u64 >= len || (len - images_offset as u64) / so < hdr.imagesCount as u64 {
                return exec::err(BadData, "bad image offset/count");
            }
            let buf = mc.get();
            let hdrbuf = &buf[(images_offset..images_offset + images_count * so).range_cast()];
            (0..images_count).map(|i| {
                let ii: dyld_cache_image_info = util::copy_from_slice(&hdrbuf[(i * so..(i + 1) * so).range_cast()], end);
                ImageInfo {
                    address: ii.address,
                    mod_time: ii.modTime,
                    inode: ii.inode,
                    path: util::from_cstr(&buf[ii.pathFileOffset as usize..]),
                }
            }).collect()
        };
        let segments = {
            let so = size_of::<dyld_cache_mapping_info>() as u64;
            let len = mc.len() as u64;
            let mapping_offset = hdr.mappingOffset as u64;
            let mapping_count = hdr.mappingCount as u64;
            if mapping_offset as u64 >= len || (len - mapping_offset as u64) / so < mapping_count {
                return exec::err(BadData, "bad mapping offset/count");
            }
            let buf = &(mc.get()[(mapping_offset..mapping_offset + mapping_count * so).range_cast()]);
            (0..mapping_count).map(|i| {
                let mi: dyld_cache_mapping_info = util::copy_from_slice(&buf[(i * so..(i + 1) * so).range_cast()], end);
                exec::Segment {
                    vmaddr: exec::VMA(mi.address),
                    vmsize: mi.size,
                    fileoff: mi.fileOffset,
                    filesize: mi.size,
                    name: None,
                    prot: ::u32_to_prot(mi.initProt),
                    private: (mapping_offset + i * so) as usize,
                }
            }).collect()
        };

        Ok(DyldCache {
            eb: exec::ExecBase {
                arch: arch,
                endian: end,
                segments: segments,
                sections: vec!(),
                buf: mc,
            },
            image_info: image_info,
            uuid: uuid,
            slide_info_blob: slide_info,
            cs_blob: cs_blob,
            ls_info: ls_info,
        })
    }
}

impl exec::Exec for DyldCache {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }

    fn as_any(&self) -> &std::any::Any { self as &std::any::Any }
}


#[derive(Copy)]
pub struct DyldSingleProber;
impl exec::ExecProber for DyldSingleProber {
    fn name(&self) -> &str {
        "dyld-single"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef) -> Vec<exec::ProbeResult> {
        if let Ok(c) = DyldCache::new(buf) {
            c.image_info.iter().map(|ii| {
                let basename = if let Some(pos) = ii.path.find('/') { &ii.path[pos+1..] } else { &ii.path[..] }.to_string();
                let cmd = vec!["dyld-single".to_string(), basename.clone()];
                exec::ProbeResult {
                    desc: basename,
                    arch: exec::arch::UnknownArch,
                    likely: true,
                    cmd: cmd,
                }
            }).collect()
        } else {
            vec!()
        }
    }
   fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: MCRef, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let m = util::do_getopts_or_panic(&*args, "dyldcache", 0, std::usize::MAX, &mut vec!());
        let c = try!(DyldCache::new(buf));
        Ok((Box::new(c) as Box<exec::Exec>, m.free))
    }
}
