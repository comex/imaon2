extern crate util;
extern crate exec;
extern crate fmt_macho as macho;
extern crate fmt_macho_bind as macho_bind;
#[macro_use] extern crate macros;
use macho::{MachO, copy_nlist_to_vec, exec_sym_to_nlist_64, copy_nlist_from_slice, ParseDyldBindState, x_nlist_64, DscTabs, MachOLookupExportOptions, strx_to_name};
use macho::dyldcache::{ImageCache, ImageCacheEntry, SegMapEntry, DyldCache};
use std::default::Default;
use std::vec::Vec;
use std::mem::{replace, transmute};
use util::{Mem, SliceExt, OptionExt, Endian, LittleEndian, Lazy, Fnv};
use macho_bind::*;
use exec::{arch, VMA, SymbolValue, SourceLib, SymbolSource, Exec, SegmentWriter, SWGetSaneError, RelocKind, RelocContext, ReadVMA, Symbol, UlebWriter};
use exec::arch::Arch;
use std::collections::{HashSet, HashMap};
use std::cell::Cell;
use std::any::Any;
use util::{ByteString, ByteStr, Ext, Narrow, CheckAdd, stopwatch, RWSlicePtr, ReadCell};

extern crate dis_generated_jump_dis;
use dis_generated_jump_dis::AArch64Handler;
extern crate dis_simple_trawl;
use dis_simple_trawl::CodeMap;

struct ReaggregatedSyms {
    localsym: Vec<u8>,
    extdefsym: Vec<u8>,
    undefsym: Vec<u8>,
    strtab: Vec<u8>,
    sym_name_to_idx: HashMap<ByteString, (usize, u8), Fnv>,
}

trait MachODscExtraction {
    fn update_indirectsym(&mut self, sym_name_to_idx: &HashMap<ByteString, (usize, u8), Fnv>);
    fn reaggregate_nlist_syms_from_cache<'a>(&'a self) -> ReaggregatedSyms;
    fn unbind(&mut self);
    fn sect_bounds_named(&self, sectname: &str) -> (VMA, u64);
    fn fix_objc_from_cache<'dc>(&mut self, dc: &'dc DyldCache);
    fn check_no_other_lib_refs<'a>(&'a self, dc: &'a DyldCache);
    fn guess_text_relocs(&self, stack_chk_fail: Option<VMA>) -> Vec<(VMA, RelocKind, VMA)>;
    fn stub_name_list(&self) -> Vec<(&ByteStr, VMA)>;
    fn fix_text_relocs_from_cache(&mut self, ic: &ImageCache, dc: &DyldCache);
    fn backwards_reexport_map<'a>(&'a self, ic: &'a ImageCache) -> HashMap<ByteString, &'a ByteStr, Fnv>;
    fn reconstruct_rebase(&self, dc: &DyldCache) -> Vec<u8>;
}
impl MachODscExtraction for MachO {
    fn update_indirectsym(&mut self, sym_name_to_idx: &HashMap<ByteString, (usize, u8), Fnv>) {
        // reallocate will stick this back into linkedit order of nlists has been preserved, so we
        // *could* just add whatever we shoved into extdefsym to each index... except imports of
        // reexports, which correspond to nlists that were removed, get 0 here!
        // so just redo it from scratch:
        // - for pointers, we have the exact addresses from bind info
        // - stubs point to pointers, so we can disassemble the stub (they also seem to be in the
        // same order as the bind info, so I originally tried to fill it in that way, but I had
        // some issues with this - maybe fixable, but this is better)
        let nindirectsym = self.indirectsym.len() / 4;
        let pointer_size = self.eb.pointer_size;
        struct IndirectPointingSectionInfo {
            ind_idx_base: usize,
            item_size: usize,
            sect_addr: VMA,
            sect_size: u64,
        }
        let mut pointers_sects_info = Vec::new();
        let mut stubs_sects_info = Vec::new();
        for sect in &self.eb.sections {
            let sp = &self.sect_private[sect.private];
            let section_type = sp.flags & SECTION_TYPE;
            let item_size = match section_type {
                S_SYMBOL_STUBS => sp.reserved2 as usize,
                S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS => pointer_size,
                _ => continue
            };
            let ind_count: usize = (sect.vmsize / item_size.ext()).narrow().unwrap(); // xxx
            let info = IndirectPointingSectionInfo {
                ind_idx_base: sp.reserved1 as usize,
                item_size: item_size,
                sect_addr: sect.vmaddr,
                sect_size: sect.vmsize,
            };
            if !info.ind_idx_base.check_add(ind_count).is_some_and(|&end| end <= nindirectsym) {
                errln!("warning: update_indirectsym: got bad indirect symbol table index/size for section {}", sect.name.as_ref().unwrap());
                continue;
            }

            if section_type == S_SYMBOL_STUBS {
                stubs_sects_info.push(info);
            } else {
                pointers_sects_info.push(info);
            }
        }
        let mut xindirectsym = replace(&mut self.indirectsym, Mem::<u8>::default());
        {
            let indirectsym = xindirectsym.get_uniq_decow();
            let end = self.eb.endian;
            self.parse_each_dyld_bind(&mut |state: &ParseDyldBindState| {
                if state.source_dylib == SourceLib::Self_ { return true; }
                let name = some_or!(state.symbol, return true);
                let seg = some_or!(state.seg, return true);
                let mut ind_idx = None;
                let addr = seg.vmaddr + state.seg_off.unwrap();
                for info in &pointers_sects_info {
                    let off = addr.wrapping_sub(info.sect_addr);
                    if off < info.sect_size {
                        ind_idx = Some(info.ind_idx_base + (off as usize) / pointer_size);
                        break;
                    }
                }
                let ind_idx = some_or!(ind_idx, return true);
                let sym_idx: u32 = if let Some(&(mut idx, which)) = sym_name_to_idx.get(name) {
                    if which >= 1 { idx += self.localsym.len() / self.nlist_size; }
                    if which >= 2 { idx += self.extdefsym.len() / self.nlist_size; }
                    idx.narrow().unwrap()
                } else {
                    errln!("warning: update_indirectsym: name '{}' from {:?} not found in nlist symbol table; can't fix indirect symbol table", name, state.which);
                    0
                };
                let ind_off = ind_idx * 4; // checked earlier
                let buf = &mut indirectsym[ind_off..ind_off+4];
                util::copy_to_slice(buf, &sym_idx, end);
                true
            });
            for info in &stubs_sects_info {
                let data = self.eb.read(info.sect_addr, info.sect_size);
                let data = data.get();
                if (data.len() as u64) < info.sect_size {
                    errln!("warning: update_indirectsym: couldn't read stubs section data");
                }
                for ((stub, addr), new_ind_idx) in data.chunks(info.item_size)
                                    .zip((0..).map(|i| i * (info.item_size as u64) + info.sect_addr)) // XXX step_by
                                    .zip(info.ind_idx_base..) {
                    if stub.len() < info.item_size { break; }
                    let target_addr = some_or!(decode_stub(stub, addr, self.eb.endian, self.eb.arch),
                                               continue);
                    let mut old_ind_idx = None;
                    for info in &pointers_sects_info {
                        let off = target_addr.wrapping_sub(info.sect_addr);
                        if off < info.sect_size {
                            old_ind_idx = Some(info.ind_idx_base + (off as usize) / pointer_size);
                            break;
                        }
                    }
                    let old_ind_idx = some_or!(old_ind_idx, {
                        errln!("warning: update_indirectsym: stub at {} target {} not in a known symbol pointers section",
                               addr, target_addr);
                        continue
                    });
                    let mut tmp: [u8; 4] = [0; 4];
                    tmp.copy_from_slice(&indirectsym[old_ind_idx * 4 .. old_ind_idx * 4 + 4]);
                    indirectsym[new_ind_idx * 4 .. new_ind_idx * 4 + 4].copy_from_slice(&tmp);
                }
            }
        }
        self.indirectsym = xindirectsym;
    }
    fn reaggregate_nlist_syms_from_cache<'a>(&'a self) -> ReaggregatedSyms {
        // Three sources: the localSymbol section of the cache (dsc_tabs), our own symtab, and the export table
        let end = self.eb.endian;
        let is64 = self.is64;
        let arch = self.eb.arch;
        let mut res = ReaggregatedSyms {
            localsym: Vec::new(),
            extdefsym: Vec::new(),
            undefsym: Vec::new(),
            strtab: vec![b'\0'],
            sym_name_to_idx: util::new_fnv_hashmap(),
        };
        // Why have this map?
        // 1. just in case a <redacted> is the only symbol we have for something, which shouldn't
        //    ever happen, but...
        // 2. to account for exports that are still in the symbol table.  dsc_extractor assumes it
        //    only needs to care about reexports; I think absolute symbols should also be in that
        //    list, but it's more robust to manually check for overlap.
        let mut seen_symbols: HashSet<(u64, &ByteStr), _> = util::new_fnv_hashset();

        let mut str_to_strtab_pos: HashMap<ByteString, u32, _> = util::new_fnv_hashmap();
        let mut add_string = |strtab: &mut Vec<u8>, s: &ByteStr| -> u32 {
            *str_to_strtab_pos.entry(s.to_owned()).or_insert_with(|| {
                let pos = strtab.len();
                if pos >= (std::u32::MAX as usize) - s.len() {
                    errln!("add_string: strtab way too big");
                    return 0;
                }
                strtab.extend_from_slice(&*s);
                strtab.push(b'\0');
                pos as u32
            })
        };
        {
            // nlist-to-nlist part: this whole thing is similar to get_symbol_list, but i want to copy directly
            // also, order needs to be preserved to avoid messing up indirectsyms
            // ^ not anymore, but whatever
            let _sw = stopwatch("reaggregate_nlist_syms_from_cache: nl-to-nl");
            let internal_symtab = self.symtab.get();
            let internal_strtab = self.strtab.get();
            let nlist_size = self.nlist_size;
            let (external_symtab, external_strtab) =
                if let Some(DscTabs { ref symtab, ref strtab, start, count }) = self.dsc_tabs {
                    let (start, count) = (start as usize, count as usize);
                    (&symtab.get()[start*nlist_size..(start+count)*nlist_size],
                     strtab.get())
                } else { (&[] as &[ReadCell<u8>], &[] as &[ReadCell<u8>]) };

            let mut external_chunks = external_symtab.chunks(nlist_size);

            for nlb in internal_symtab.chunks(nlist_size) {
                let mut int_nl: x_nlist_64 = copy_nlist_from_slice(nlb, end);
                let int_name = strx_to_name(internal_strtab, int_nl.n_strx.ext());
                let is_redacted = int_name == "<redacted>";
                let mut name = int_name;
                if is_redacted {
                    if let Some(ext_nlb) = external_chunks.next() {
                        let ext_nl: x_nlist_64 = copy_nlist_from_slice(ext_nlb, end);
                        let ext_name = strx_to_name(external_strtab, ext_nl.n_strx.ext());
                        if ext_nl.n_type != int_nl.n_type ||
                           ext_nl.n_sect != int_nl.n_sect ||
                           ext_nl.n_desc != int_nl.n_desc ||
                           ext_nl.n_value != int_nl.n_value {
                            errln!("warning: reaggregate_nlist_syms_from_cache: data mismatch for redacted symbol vs. {}; probably lost sync \
                                    (value={:x}/{:x})",
                                   ext_name, int_nl.n_value, ext_nl.n_value);
                        } else {
                            name = ext_name;
                        }
                    } else {
                        errln!("warning: reaggregate_nlist_syms_from_cache: got redacted symbol with value={:x} but ran out of localsyms",
                               int_nl.n_value);
                    }
                }
                int_nl.n_strx = add_string(&mut res.strtab, name);
                let n_type = int_nl.n_type as u32 & N_TYPE;
                if n_type == N_INDR {
                    // shouldn't happen
                    let imp_name = strx_to_name(internal_strtab, int_nl.n_value);
                    int_nl.n_value = add_string(&mut res.strtab, imp_name) as u64;
                } else {
                    let addr = int_nl.n_value |
                        if int_nl.n_desc as u32 & N_ARM_THUMB_DEF != 0 { 1 } else { 0 };
                    seen_symbols.insert((addr, name));
                }
                let (which, which_idx) = if n_type == N_UNDF {
                    (&mut res.undefsym, 2)
                } else if int_nl.n_type as u32 & N_EXT != 0 {
                    (&mut res.extdefsym, 1)
                } else {
                    (&mut res.localsym, 0)
                };
                res.sym_name_to_idx.insert(name.to_owned(), (which.len() / nlist_size, which_idx));
                copy_nlist_to_vec(which, &int_nl, end, is64);
            }
        }
        let stopw = stopwatch("reaggregate_nlist_syms_from_cache: sym-to-nl");
        // for the conversion I may as well just use it
        for sym in self.get_symbol_list(SymbolSource::Exported, None) {
            let name = &*sym.name;
            // this is not quite right due to different types
            if let Some(addr) = sym.val.some_vma() {
                if seen_symbols.contains(&(addr.0, name)) {
                    continue;
                }
            }
            let nl = match exec_sym_to_nlist_64(
                &sym,
                add_string(&mut res.strtab, name),
                if let SymbolValue::ReExport(ref imp_name, _) = sym.val {
                    Some(add_string(&mut res.strtab, imp_name))
                } else { None },
                arch,
                &mut || { // is_text
                    // cheat because absolute symbols are probably not text :$
                    false
                },
                false // for_obj
            ) {
                Ok(nl) => nl,
                Err(e) => {
                    errln!("warning: when converting exported symbols: {}", e);
                    continue;
                },
            };
            assert!(sym.is_public);
            copy_nlist_to_vec(&mut res.extdefsym, &nl, end, is64);
        }
        stopw.stop();
        res
    }
    fn unbind(&mut self) {
        let _sw = stopwatch("unbind");
        // helps IDA, because it treats these as 'rel' (addend = whatever's in that slot already)
        // when they're actually 'rela' (explicit addend).
        let mut segw = SegmentWriter::new(&mut self.eb.segments);

        self.parse_each_dyld_bind(&mut |state| {
            let seg_off = some_or!(state.seg_off, { return true; }) as usize;
            // xxx perf
            segw.make_seg_rw(state.seg_idx);
            let nc = segw.access_rw(state.seg_idx).unwrap();
            if !self.is64 ||
               state.typ == (BIND_TYPE_TEXT_ABSOLUTE32 as u8) ||
               state.typ == (BIND_TYPE_TEXT_PCREL32 as u8) {
                util::copy_to_slice(&nc[seg_off..seg_off+4], &0u32, LittleEndian);
            } else {
                util::copy_to_slice(&nc[seg_off..seg_off+8], &0u64, LittleEndian);
            }
            true
        });

        segw.finish(&mut self.eb.segments);
    }
    fn sect_bounds_named(&self, sectname: &str) -> (VMA, u64) {
        let sectname = ByteStr::from_str(sectname);
        for section in &self.eb.sections {
            if section.name.as_ref().unwrap() == sectname {
                return (section.vmaddr, section.vmsize);
            }
        }
        (VMA(0), 0)
    }
    fn fix_objc_from_cache<'dc>(&mut self, dc: &'dc DyldCache) {
        /* Yay, 200 line long function...
           Could be optimized a bit more.
           The optimizations dyld does:
            Harmless/idempotent:
            - IvarOffsetOptimizer
            - MethodListSorter 
            Proto refs moved in:
            - __objc_classlist -> class in __objc_data -> class data in __objc_const -> baseProtocols
            -                      ^- isa (metaclass) -^
            - __objc_protorefs (every word)
            - __objc_protolist -> protocol in __data -> protocols in __objc_const?
            And:
            - Selectors moved to other binaries.
        */

        let _sw = stopwatch("fix_objc_from_cache");

        let mut segw = SegmentWriter::new(&mut self.eb.segments);
        { // <-
        for (i, seg) in self.eb.segments.iter().enumerate() {
            if let Some(ref name) = seg.name {
                if name == "__TEXT" || name.starts_with(b"__DATA") {
                    segw.make_seg_rw(i);
                }
            }
        }
        let outer_read = |vma: VMA, size: u64| -> Option<&'dc [Cell<u8>]> {
            if vma.0 == 4 { panic!() }
            let res = dc.eb.get_sane(vma, size);
            if let None = res {
                errln!("fix_objc_from_cache: read error at {}", vma);
            }
            res
        };
        //let rw = |addr: VMA, size: u64| -> Option<&[Cell<u8>]>
        // WTF - rustc can't infer return lifetimes for even simple closures
        // http://is.gd/2uRGhH
        fn rw(segw: &SegmentWriter, addr: VMA, size: u64) -> Option<&[Cell<u8>]> {
            match segw.get_sane_rw(addr, size) {
                Ok(slice) => Some(slice),
                Err(SWGetSaneError::NotWritable) => {
                    errln!("fix_objc_from_cache: pointer {} unexpectedly not in __DATA", addr);
                    None
                },
                Err(SWGetSaneError::Unmapped) => {
                    errln!("fix_objc_from_cache: pointer {} unmapped", addr);
                    None
                },
            }
        };

        let pointer_size64 = self.eb.pointer_size as u64;

        macro_rules! read_ptr { ($loc:expr, $action:stmt) => {
            self.eb.ptr_from_slice(some_or!(outer_read($loc, pointer_size64), $action))
        } }

        let mut sel_name_to_addr: HashMap<&ByteStr, VMA, _> = util::new_fnv_hashmap();

        {
            let (mut methname_addr, methname_size) = self.sect_bounds_named("__objc_methname");
            let mut methname = segw.get_sane_ro(methname_addr, methname_size).unwrap();
            loop {
                let name = some_or!(util::from_cstr_strict(methname), break);
                let inc = name.len() + 1;
                sel_name_to_addr.insert(name, methname_addr);
                methname = &methname[inc..];
                methname_addr = methname_addr + inc.ext();
            }
        }

        let proto_name = |proto_ptr: VMA| -> Option<&'dc ByteStr> {
            let name_addr = read_ptr!(some_or!(proto_ptr.check_add(pointer_size64), {
                errln!("fix_objc_from_cache: integer overflow");
                return None;
            }), return None);
            let res = dc.eb.read_cstr_sane(VMA(name_addr));
            if res.is_none() {
                errln!("fix_objc_from_cache: can't read name at {} for protocol at {}", name_addr, proto_ptr);
            }
            res
        };

        let visit_selector_pp = |selector_pp: VMA| {
            let selector_data = some_or!(rw(&segw, selector_pp, pointer_size64), return);
            let old_strp = VMA(self.eb.ptr_from_slice(selector_data));
            // todo cache by address?
            let name = some_or!(dc.eb.read_cstr_sane(old_strp), {
                errln!("fix_objc_from_cache: can't read selector name in other image at {}", old_strp);
                return;
            });
            if let Some(&my_addr) = sel_name_to_addr.get(name) {
                self.eb.ptr_to_slice(selector_data, my_addr.0);
            } else {
                errln!("fix_objc_from_cache: can't find selector named {} in __objc_methname, referenced from {}", name, selector_pp);
            }
        };

        let visit_method_list = |method_list: VMA| {
            if method_list.0 == 0 { return; }
            let (entsize, count): (u32, u32) =
                util::copy_from_slice(some_or!(outer_read(method_list, 8), return),
                                      self.eb.endian);
            let entsize = entsize & !3;
            let mut sel_pp = method_list + 8;
            for _ in 0..count {
                // methods start with selector ptr
                visit_selector_pp(sel_pp);
                sel_pp = some_or!(sel_pp.check_add(entsize as u64),
                                  { errln!("visit_method_list: integer overflow"); break; });
            }
        };

        let mut proto_name_to_addr: HashMap<&ByteStr, VMA, _> = util::new_fnv_hashmap();
        {
            let (protolist_addr, protolist_size) = self.sect_bounds_named("__objc_protolist");
            let protolist = segw.get_sane_ro(protolist_addr, protolist_size).unwrap();
            for proto_ptr_buf in protolist.chunks(self.eb.pointer_size) {
                let proto_ptr = VMA(self.eb.ptr_from_slice(proto_ptr_buf));
                let name = some_or!(proto_name(proto_ptr), continue);
                proto_name_to_addr.insert(name, proto_ptr);
                for i in 3..7 {
                    visit_method_list(VMA(read_ptr!(proto_ptr + i * pointer_size64, continue)));
                }
            }
        }

        let visit_protocol_pp = |protocol_pp: VMA| {
            let protocol_data = some_or!(rw(&segw, protocol_pp, pointer_size64), return);
            let protocol_ptr = VMA(self.eb.ptr_from_slice(protocol_data));
            let name = some_or!(proto_name(protocol_ptr), return);
            if let Some(&my_addr) = proto_name_to_addr.get(&name) {
                self.eb.ptr_to_slice(protocol_data, my_addr.0);
            } else {
                errln!("fix_objc_from_cache: can't find protocol named {} in __objc_protolist, referenced from {}", name, protocol_pp);
            }
        };

        let visit_proto_list = |list: VMA| {
            if list.0 == 0 { return; }
            let protocol_count = read_ptr!(list, return);
            let mut protocol_pp = list.saturating_add(pointer_size64);
            for _ in 0..protocol_count {
                visit_protocol_pp(protocol_pp);
                protocol_pp = protocol_pp.saturating_add(pointer_size64);
            }
        };

        {
            for &proto in proto_name_to_addr.values() {
                let proto_list = VMA(read_ptr!(proto.saturating_add(2 * pointer_size64), continue));
                visit_proto_list(proto_list);
            }
        }

        {
            let (classlist_addr, classlist_size) = self.sect_bounds_named("__objc_classlist");
            let classlist = segw.get_sane_ro(classlist_addr, classlist_size).unwrap();
            for cls_ptr_buf in classlist.chunks(self.eb.pointer_size) {
                let mut cls_ptr = VMA(dc.eb.ptr_from_slice(cls_ptr_buf));
                let mut is_meta = false;
                loop {
                    let cls_data_ptr = VMA(read_ptr!(cls_ptr + 4 * pointer_size64, break));
                    // protocols
                    let base_protocols = VMA(read_ptr!(cls_data_ptr + 8 + 4 * pointer_size64, break));
                    visit_proto_list(base_protocols);
                    // methods
                    let base_methods = VMA(read_ptr!(cls_data_ptr + 8 + 3 * pointer_size64, break));
                    visit_method_list(base_methods);


                    //
                    if !is_meta {
                        let isa = VMA(read_ptr!(cls_ptr, break));
                        cls_ptr = isa;
                        is_meta = true;
                    } else {
                        break;
                    }
                }
            }

        }
        {
            let (catlist_addr, catlist_size) = self.sect_bounds_named("__objc_catlist");
            let catlist = segw.get_sane_ro(catlist_addr, catlist_size).unwrap();
            for cat_ptr_buf in catlist.chunks(self.eb.pointer_size) {
                let cat_ptr = VMA(self.eb.ptr_from_slice(cat_ptr_buf));
                if cat_ptr.check_add(4 * pointer_size64).is_none() {
                    errln!("fix_objc_from_cache: integer overflow");
                    continue;
                }
                let instance_methods = VMA(read_ptr!(cat_ptr + 2 * pointer_size64, continue));
                visit_method_list(instance_methods);
                let class_methods = VMA(read_ptr!(cat_ptr + 3 * pointer_size64, continue));
                visit_method_list(class_methods);
            }
        }

        {
            let (base_addr, len) = self.sect_bounds_named("__objc_protorefs");
            for i in 0..(len / pointer_size64) {
                visit_selector_pp(base_addr + i * pointer_size64);
            }
        }
        {
            let (base_addr, len) = self.sect_bounds_named("__objc_selrefs");
            for i in 0..(len / pointer_size64) {
                visit_selector_pp(base_addr + i * pointer_size64);
            }
        }
        {
            // If this is libobjc itself, we should clear the preoptimization stuff - in the
            // original dylib it's all 0 except the 4 byte version at the start of RO
            let (opt_ro_addr, opt_ro_size) = self.sect_bounds_named("__objc_opt_ro");
            if opt_ro_size != 0 {
                if opt_ro_size < 4 {
                    errln!("fix_objc_from_cache: __objc_opt_ro size too small");
                } else {
                    segw.get_sane_rw(opt_ro_addr + 4, opt_ro_size - 4).unwrap()
                        .set_memory(0);
                }
            }
            let (opt_rw_addr, opt_rw_size) = self.sect_bounds_named("__objc_opt_rw");
            if opt_rw_size != 0 {
                segw.get_sane_rw(opt_rw_addr + 4, opt_rw_size - 4).unwrap()
                    .set_memory(0);
            }
        }
        } // <-
        segw.finish(&mut self.eb.segments);

    }
    fn check_no_other_lib_refs<'a>(&'a self, dc: &'a DyldCache) {
        fn sect_name(sections: &[exec::Segment], addr: VMA) -> &ByteStr {
             if let Some((seg, _, _)) = exec::addr_to_seg_off_range(sections, addr) {
                &**seg.name.as_ref().unwrap()
             } else { ByteStr::from_str("??") }
        }

        let sli = some_or!(dc.slide_info.as_ref(), {
            // no slide info so can't do it, oh well...
            return;
        });
        let arch = self.eb.arch;
        for segment in &self.eb.segments {
            let content = segment.data.as_ref().unwrap().get();
            let pointer_size = self.eb.pointer_size;
            sli.iter(&dc.eb, Some((segment.vmaddr, segment.vmsize)), |ptr| {
                let offset = (ptr - segment.vmaddr) as usize;
                let mut val: u64 = self.eb.ptr_from_slice(some_or!(content.slice_opt(offset, offset+pointer_size), {
                    return;
                }));

                if val == 0 { return; }
                if arch == arch::AArch64 {
                    // http://sourcerytools.com/pipermail/cxx-abi-dev/2013-November/002623.html
                    val &= !(0xffu64 << 56);
                }
                let val = VMA(val);
                if exec::addr_to_seg_off_range(&dc.eb.segments, val).is_none() {
                    errln!("odd {} -> {}, sourcesect = {}, destsect = {}", ptr, val,
                           sect_name(&self.eb.sections, ptr),
                           sect_name(&dc.eb.sections, val));
                }
            });
        }
    }
    // currently for cache extraction on arm64 only
    fn guess_text_relocs(&self, stack_chk_fail: Option<VMA>) -> Vec<(VMA, RelocKind, VMA)> {
        let _sw = stopwatch("guess_text_relocs");
        let mut relocs = Vec::new();
        if self.eb.arch != arch::AArch64 {
            return relocs;
        }
        let end = self.eb.endian;
        let pointer_size = self.eb.pointer_size;
        for sect in &self.eb.sections {
            if self.sect_private[sect.private].flags & S_ATTR_SOME_INSTRUCTIONS == 0 {
                continue;
            }
            if let Some(ref name) = sect.name {
                if name == "__stubs" || name == "__stub_helper" {
                    continue;
                }
            }
            let sectdata = some_or!(self.eb.get_sane(sect.vmaddr, sect.filesize), {
                errln!("warning: guess_text_relocs: couldn't read section named {}", sect.name.as_ref().unwrap());
                continue;
            });
            let grain_shift: u8 = 2; // xxx
            let start_addr = sect.vmaddr;
            let mut codemap = CodeMap::new(start_addr, grain_shift, util::downgrade(sectdata), end, &self.eb.segments);
            if let Some(stack_chk_fail) = stack_chk_fail {
                codemap.mark_noreturn_addr(stack_chk_fail);
            }
            {
                // TODO sort? only useful if there are many sections like this
                for group in &[self.localsym.get(), self.extdefsym.get()] {
                    for chunk in group.chunks(self.nlist_size) {
                        let nl = copy_nlist_from_slice(chunk, end);
                        let vma = VMA(nl.n_value as u64);
                        if let Some(idx) = codemap.addr_to_idx(vma) {
                            codemap.mark_root(idx);
                        } else {
                            //println!("(not doing {} for {:?} start={} len=0x{:x})", vma, sect.name, start_addr, sectdata.len());
                        }
                    }
                }
            }
            codemap.go(&mut AArch64Handler::new(), &mut |addr, size| self.eb.get_sane(addr, size).map(util::downgrade));
            for &idx in &codemap.out_of_range_idxs {
                let addr = codemap.idx_to_addr(idx);
                let off: usize = (addr - start_addr).narrow().unwrap();
                let rc = RelocContext {
                    kind: RelocKind::Arm64Br26,
                    pointer_size: pointer_size,
                    base_addr: addr,
                    endian: self.eb.endian,
                };
                let target = match rc.pack_unpack_insn(&sectdata[off..], None) {
                    Ok(target) => target,
                    Err(e) => {
                        errln!("guess_text_relocs: unexpected instruction at {} ({:?}) - probably data being marked as code", addr, e);
                        continue
                    },
                };
                if exec::addr_to_seg_off_range(&self.eb.segments, target).is_none() {
                    relocs.push((addr, rc.kind, target));
                }
            }
        }
        relocs
    }
    fn stub_name_list(&self) -> Vec<(&ByteStr, VMA)> {
        let mut res = Vec::new();
        let indirectsym = self.indirectsym.get();
        let indirectsym_count = indirectsym.len() / 4;
        let symtab = self.symtab.get();
        let strtab = self.strtab.get();
        let end = self.eb.endian;
        let nlist_size = self.nlist_size;
        for sect in &self.eb.sections {
            let sp = &self.sect_private[sect.private];
            if sp.flags & SECTION_TYPE != S_SYMBOL_STUBS { continue; }
            let (ind_idx, stub_size) = (sp.reserved1 as usize, sp.reserved2 as usize);
            let stub_count = sect.filesize / stub_size.ext();
            if ind_idx > indirectsym_count {
                errln!("warning: stub_name_list: reserved1 ({}) > stub count ({}) for section {:?}",
                       ind_idx, stub_count, sect.name);
                continue;
            }
            let stub_count = if stub_count > (indirectsym_count - ind_idx).ext() {
                errln!("warning: stub_name_list: reserved1 ({}) + stub count ({}) goes off end of indirect table \
                        for section {:?}", ind_idx, stub_count, sect.name);
                indirectsym_count - ind_idx
            } else { stub_count as usize };
            let mut stub_addr = sect.vmaddr;
            for indirect_buf in indirectsym[ind_idx * 4 .. (ind_idx + stub_count) * 4].chunks(4) {
                let sym_idx: u32 = util::copy_from_slice(indirect_buf, end);
                let off = (sym_idx as usize).saturating_mul(nlist_size);
                let sa = stub_addr;
                stub_addr = stub_addr.wrapping_add(stub_size.ext());
                let nlist_buf = some_or!(symtab.slice_opt(off, off + nlist_size), {
                    errln!("warning: stub_name_list: bad symbol table index {}", sym_idx);
                    continue;
                });
                let nl = copy_nlist_from_slice(nlist_buf, end);
                let name = strx_to_name(strtab, nl.n_strx.ext());
                res.push((name, sa));
            }
        }
        res
    }
    fn fix_text_relocs_from_cache(&mut self, ic: &ImageCache, dc: &DyldCache) {
        let _sw = stopwatch("fix_text_relocs_from_cache");
        let pointer_size = self.eb.pointer_size;
        let end = self.eb.endian;

        { // <-

        let mut my_stubs_by_name: HashMap<&ByteStr, VMA, _> = util::new_fnv_hashmap();
        for (name, stub_addr) in self.stub_name_list() {
            my_stubs_by_name.insert(name, stub_addr);
        }

        let __stack_chk_fail = ic_get_known_addrs(ic).__stack_chk_fail;
        let guess = self.guess_text_relocs(__stack_chk_fail);
        if guess.len() == 0 { return; }

        let mut target_cache: HashMap<VMA, Option<VMA>, _> = util::new_fnv_hashmap();
        let bmap: Lazy<_> = Lazy::new();
        let this: &MachO = self;
        for (source, kind, target) in guess {
            let new_target = target_cache.entry(target).or_insert_with(|| {
                let (target, sme) = some_or!(resolve_trampolines(dc, ic, target, source, self.eb.endian),
                                             return None);
                let image_name = &dc.image_info[sme.image_idx].path[..];
                let ice = &ic.cache[sme.image_idx];
                if let Err(ref e) = ice.mo {
                    errln!("warning: fix_text_relocs_from_cache: addr {} (ref'd by {}) points to bad image ({})", target, source, e);
                    return None;
                };
                let syms = ice_get_addr_syms(ice);
                let idx = some_or!(syms.binary_search_by(|sym| sym.val.some_vma().unwrap().cmp(&target)).ok(), {
                    errln!("warning: fix_text_relocs_from_cache: found image '{}' for {} (ref'd by {}), but no symbol", image_name, target, source);
                    return None;
                });
                let min_idx = (0..idx).rev().take_while(|&idx2| syms[idx2].val.some_vma().unwrap() == target)
                                      .last().unwrap_or(idx);
                let max_idx = (idx..syms.len()).take_while(|&idx2| syms[idx2].val.some_vma().unwrap() == target)
                                      .last().unwrap_or(idx);
                for idx in min_idx..max_idx+1 {
                    let sym_name = &syms[idx].name;
                    // todo data relocs
                    if let Some(&res) = my_stubs_by_name.get(&**sym_name) {
                        return Some(res);
                    }
                }
                // No exact name match.  But it might be the target of a reexport (possibly
                // multiple levels of reexport), which is annoying - it's not even
                // unambiguous.  We have to check all our imports to see if they resolve to
                // some reexport.
                let bmap = bmap.get(|| this.backwards_reexport_map(ic));
                for idx in min_idx..max_idx+1 {
                    let sym_name = &syms[idx].name;
                    if let Some(orig_name) = bmap.get(&**sym_name) {
                        if let Some(&res) = my_stubs_by_name.get(orig_name) {
                            return Some(res);
                        }
                    }
                }
                // we fail
                errln!("warning: fix_text_relocs_from_cache: couldn't find stub for symbol (addr {} ref'd by {}), name possibilities: {{",
                       target, source);
                for idx in min_idx..max_idx+1 {
                    let sym_name = &syms[idx].name;
                    println!("  {}", sym_name);
                    if let Some(orig_name) = bmap.get(&**sym_name) {
                        // really this should have been found as a stub
                        println!("  <- {}", orig_name);
                    }
                }
                errln!("}}");
                None
            });
            if let Some(new_target) = *new_target {
                //println!("OK! {} => {}", source, new_target);
                let rc = RelocContext {
                    kind: kind,
                    pointer_size: pointer_size,
                    base_addr: source,
                    endian: end,
                };

                let cell_ptr = self.eb.get_sane(source, 4).unwrap();
                rc.pack_unpack_insn(cell_ptr, Some(new_target)).unwrap();
                //println!("patching {} -> {:x} newt={}", source, insn, new_target);
            }
        }
        } // <-
    }
    fn backwards_reexport_map<'a>(&'a self, ic: &'a ImageCache) -> HashMap<ByteString, &'a ByteStr, Fnv> {
        let opts = MachOLookupExportOptions { using_image_cache: Some(unsafe { transmute::<&'a ImageCache, &'static ImageCache>(ic) }) };
        let mut res = util::new_fnv_hashmap();
        let mut prev_source_info: Option<(usize, &ImageCacheEntry)> = None;
        self.parse_each_dyld_bind(&mut |state: &ParseDyldBindState<'a>| {
            if state.already_bound_this_symbol { return true; }
            let orig_name = some_or!(state.symbol, { return true; });
            let source_dylib: usize = match state.source_dylib {
                SourceLib::Ordinal(ord) => ord.ext(),
                _ => return true,
            };
            let mut ice = match prev_source_info {
                Some((prev_dylib, prev_ice)) if prev_dylib == source_dylib
                    => prev_ice,
                _ => {
                    let path = &self.load_dylib[source_dylib].path;
                    let ice = some_or!(ic.lookup_path(path), {
                        errln!("backwards_reexport_map: didn't find {} in cache", path);
                        return true;
                    });
                    prev_source_info = Some((source_dylib, ice));
                    ice
                },
            };
            let mut cur_name_owned: Option<ByteString> = None;
            loop {
                let mo = some_or!(ice.mo.as_ref().ok(), { continue; });
                let new = (|| {
                    let cur_name = if let Some(ref name) = cur_name_owned { &name[..] } else { orig_name };
                    for export in mo.lookup_export(cur_name, Some(&opts as &Any)) {
                        if let SymbolValue::ReExport(n, source_dylib) = export.val {
                            // it's owned to start with so
                            let source_dylib = match source_dylib {
                                SourceLib::Ordinal(o) => o,
                                _ => panic!()
                            };
                            return Some((n.into_owned(), source_dylib as usize))
                        }
                    }
                    None
                })();
                if let Some((new_name, source_dylib)) = new {
                    // no cache here, but this should be rare...
                    let path = &mo.load_dylib[source_dylib].path;
                    ice = some_or!(ic.lookup_path(path), {
                        errln!("backwards_reexport_map: didn't find {} in cache (after first step)", path);
                        return true;
                    });
                    cur_name_owned = Some(new_name);
                } else {
                    // otherwise, it's the end of the line.  did we get past the first lookup?
                    if let Some(name) = cur_name_owned {
                        //println!("! {} -> {}", name, orig_name);
                        if &name != orig_name {
                            res.insert(name, orig_name);
                        }
                    }
                    break;
                }
            }
            true
        });
        res
    }

    fn reconstruct_rebase(&self, dc: &DyldCache) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        // not optimally compressed but whatever
        if let Some(ref slide_info) = dc.slide_info {
            let mut w = UlebWriter::new(&mut output);
            let mut cur_seg_idx: Option<u8> = None;
            let mut cur_offset: u64 = 0; // dontcare initializer
            for (seg_idx, segment) in self.eb.segments.iter().enumerate() {
                if seg_idx > 15 {
                    errln!("reconstruct_rebase: seg_idx > 15? o.0 format doesn't support...");
                    break;
                }
                let seg_idx = seg_idx as u8;
                slide_info.iter(&dc.eb, Some((segment.vmaddr, segment.vmsize)), &mut |vma| {
                    let offset = vma - segment.vmaddr;
                    if cur_seg_idx != Some(seg_idx) {
                        if cur_seg_idx.is_some() {
                            w.write_u8(REBASE_OPCODE_DO_REBASE_IMM_TIMES as u8 | 1);
                        } else {
                            w.write_u8(REBASE_OPCODE_SET_TYPE_IMM as u8 | 1);
                        }
                        w.write_u8(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB as u8 | seg_idx);
                        w.write_uleb(offset);
                        cur_seg_idx = Some(seg_idx);
                    } else {
                        // this is actually the /previous/ rebase
                        w.write_u8(REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB as u8);
                        w.write_uleb(offset - cur_offset);
                    }
                    cur_offset = offset;
                });
            }
            if cur_seg_idx.is_some() {
                w.write_u8(REBASE_OPCODE_DO_REBASE_IMM_TIMES as u8 | 1);
            }
        }
        output
    }
}

fn resolve_trampolines<'a>(dc: &DyldCache, ic: &'a ImageCache, mut target: VMA, refd_by: VMA, end: Endian) -> Option<(VMA, &'a SegMapEntry)> {
    let mut num = 0usize;
    let mut prev = refd_by;
    loop {
        if let Some(sme) = ic.lookup_addr(target) {
            return Some((target, sme));
        }
        // if it's in an image, then it could be a B but not a trampoline, so need to check this first
        let insn_buf = some_or!(dc.eb.get_sane(target, 4), {
            errln!("resolve_trampolines: invalid address {} (ref'd after following {} trampoline(s) from {}, most recently {})",
                   target, num, refd_by, prev);
            return None;
        });
        let insn: u32 = util::copy_from_slice(insn_buf, end);
        // stricter mask as BL is no good
        if insn & 0xfc000000 != 0x14000000 {
            errln!("resolve_trampolines: address {} not found in image, but is not a B (insn = 0x{:08x}) \
                    (ref'd by {}, most recently by {})", target, insn, refd_by, prev);
            return None;
        }
        prev = target;
        let rc = RelocContext {
            kind: RelocKind::Arm64Br26,
            pointer_size: 8,
            endian: end,
            base_addr: target,
        };
        target = rc.pack_unpack_insn(insn_buf, None).unwrap();
        num += 1;
    }
}

fn ice_get_addr_syms(this: &ImageCacheEntry) -> &Vec<exec::Symbol<'static>> {
    let any = this.addr_syms.get(|| {
        let mo = this.mo.as_ref().unwrap();
        let mut list: Vec<Symbol<'static>> = mo.get_exported_symbol_list(None);
        list.retain(|sym| match sym.val {
            SymbolValue::Addr(_) => true,
            _ => false
        });
        list.sort_by_key(|sym| match sym.val {
            SymbolValue::Addr(vma) => vma,
            _ => panic!()
        });
        Box::new(list) as Box<Any+Send>
    });
    any.downcast_ref().unwrap()
}

#[derive(Default)]
struct KnownAddrs {
    __stack_chk_fail: Option<VMA>,
}

fn ic_get_known_addrs(this: &ImageCache) -> &KnownAddrs {
    let any = this.known_addrs.get(|| {
        let mut ka = Box::new(KnownAddrs::default());
        scope! { 'foo: {
            let libsystem_c = some_or!(this.lookup_path(ByteStr::from_str("/usr/lib/system/libsystem_c.dylib")).and_then(|ice| ice.mo.as_ref().ok()), {
                errln!("ic_get_known_addrs: no libsystem_c.dylib so won't find __stack_chk_fail");
                break 'foo;
            });
            let lex = libsystem_c.lookup_export(ByteStr::from_str("___stack_chk_fail"), None);
            let sym = some_or!(lex.first(), {
                errln!("ic_get_known_addrs: __stack_chk_fail symbol not found in libsystem_c.dylib");
                break 'foo;
            });
            if let SymbolValue::Addr(vma) = sym.val {
                ka.__stack_chk_fail = Some(vma);
            } else {
                errln!("ic_get_known_addrs: __stack_chk_fail symbol not found in libsystem_c.dylib");
            }
        } }
        ka
    });
    any.downcast_ref().unwrap()
}


fn decode_stub(stub: &[ReadCell<u8>], stub_addr: VMA, end: Endian, arch: Arch) -> Option<VMA> {
    match arch {
        arch::X86 | arch::X86_64 => {
            assert_eq!(end, LittleEndian);
            if stub.len() != 6 { return None; }
            let bytes: [u8; 2] = util::copy_from_slice(&stub[0..2], LittleEndian);
            if bytes != [0xff, 0x25] { return None; }
            let rel: i32 = util::copy_from_slice(&stub[2..], LittleEndian);
            let mut res = stub_addr.wrapping_add(rel as u64);
            if arch == arch::X86 { res = res.trunc32(); }
            Some(res)
        },
        arch::ARM => {
            match stub.len() {
                16 => {
                    let insns: [u32; 3] = [0xe59fc004, 0xe08fc00c, 0xe59cf000];
                    let real_insns: [u32; 4] = util::copy_from_slice(stub, end);
                    if insns != &real_insns[..3] { return None; }
                    Some((stub_addr + 8).wrapping_add(real_insns[3] as u64).trunc32())
                },
                12 => {
                    let insns: [u32; 2] = [0xe59fc000, 0xe59cf000];
                    let real_insns: [u32; 3] = util::copy_from_slice(stub, end);
                    if insns != &real_insns[..2] { return None; }
                    Some(VMA(real_insns[2].ext()))
                },
                _ => None
            }

        },
        arch::AArch64 => {
            if stub.len() != 12 { return None; }
            let insns: [u32; 3] = util::copy_from_slice(stub, end);
            if insns[0] & 0x9f00001f != 0x90000010 ||
               insns[1] & 0xffc003ff != 0xf9400210 ||
               insns[2] != 0xd61f0200 { return None; }
            let mut page_rel: u64 = (insns[0] as u64 & 0x60000000) >> 17 |
                                    (insns[0] as u64 & 0xffffe0) << 9;
            if page_rel & (1u64 << 32) != 0 {
                page_rel |= 0xffffffffu64 << 32;
            }
            let page = (stub_addr.0 & !0xfff).wrapping_add(page_rel);
            let pageoff = ((insns[1] & 0x3ffc00) >> 10) * 8;
            if pageoff >= 0x1000 { return None; }
            Some(VMA(page + pageoff as u64))
        },
        _ => {
            errln!("warning: decode_stub: unknown arch {:?}", arch);
            None
        }
    }
}

pub fn extract_as_necessary(mo: &mut MachO, dc: Option<&DyldCache>, image_cache: Option<&ImageCache>, minimal_processing: bool) -> exec::ExecResult<()> {
    let _sw = stopwatch("extract_as_necessary");
    if mo.text_fileoff() != 0 && !minimal_processing {
        let x: Option<DyldCache>;
        let dc = if let Some(dc) = dc { dc } else {
            let inner_sections = true; // xxx
            x = Some(try!(DyldCache::new(mo.eb.whole_buf.as_ref().unwrap().clone(), inner_sections, /*unslide*/ false)));
            x.as_ref().unwrap()
        };
        // we're in a cache...
        mo.dyld_rebase = Mem::with_vec(mo.reconstruct_rebase(dc));
        let res = mo.reaggregate_nlist_syms_from_cache();
        mo.localsym = Mem::<u8>::with_data(&res.localsym[..]);
        mo.extdefsym = Mem::<u8>::with_data(&res.extdefsym[..]);
        mo.undefsym = Mem::<u8>::with_data(&res.undefsym[..]);
        mo.strtab = Mem::<u8>::with_data(&res.strtab[..]);
        mo.xsym_to_symtab();
        mo.update_indirectsym(&res.sym_name_to_idx);
        if let Some(ic) = image_cache {
            // must come after indirectsym
            mo.fix_text_relocs_from_cache(ic, dc);
        }
        mo.unbind();
        mo.fix_objc_from_cache(dc);
        mo.check_no_other_lib_refs(dc);
    }
    try!(mo.reallocate());
    mo.rewhole();
    Ok(())
}
