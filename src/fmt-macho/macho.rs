#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
extern crate vec_map;
#[macro_use]
extern crate macros;
extern crate util;
extern crate exec;
extern crate bsdlike_getopts as getopts;
extern crate libc;
extern crate fmt_macho_bind as macho_bind;
use std::default::Default;
use std::vec::Vec;
use std::mem::{replace, size_of, transmute};
use std::str::FromStr;
use std::cmp::max;
use util::{VecStrExt, Mem, Swap, VecCopyExt, SliceExt, OptionExt, copy_memory, into_cow, IntStuff, Endian};
use macho_bind::*;
use exec::{arch, VMA, SymbolValue, ByteSliceIterator, DepLib, SourceLib, ErrorKind, err, SymbolSource, Symbol};
use std::{u64, u32, usize};
use vec_map::VecMap;
use std::collections::{HashSet};
use std::borrow::Cow;
use std::any::Any;
use util::{ByteString, ByteStr, FieldLens, Ext, Narrow, CheckAdd, CheckSub, TrivialState, stopwatch};

pub mod dyldcache;
use dyldcache::{DyldCache, ImageCache, SlideInfo};

pub const VM_PROT_WRITE: u32 = 2;
pub const VM_PROT_READ: u32 = 1;
pub const VM_PROT_EXECUTE: u32 = 4;

// perl -ne 'if (/^#define\s+(CPU_.*?)\s+\(\(.*\) ([0-9]+)\)/) { print "pub const $1: u32 = $2;\n" }' externals/mach-o/mach/machine.h
// perl -ne 'if (/^#define\s+(CPU_.*?)\s+CPU_SUBTYPE_INTEL\(([0-9]+), ([0-9]+)\)/) { print "pub const $1: u32 = ($3 * 0x10 + $2);\n" }' externals/mach-o/mach/machine.h 
pub const CPU_TYPE_ANY: u32 = 0xffffffff;
pub const CPU_SUBTYPE_MULTIPLE: u32 = 0xffffffff;
pub const CPU_TYPE_VAX: u32 = 1;
pub const CPU_TYPE_MC680x0: u32 = 6;
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_I386: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = 0x01000000 | 7;
pub const CPU_TYPE_MC98000: u32 = 10;
pub const CPU_TYPE_HPPA: u32 = 11;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = 0x01000000 | 12;
pub const CPU_TYPE_MC88000: u32 = 13;
pub const CPU_TYPE_SPARC: u32 = 14;
pub const CPU_TYPE_I860: u32 = 15;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = 0x01000000 | 18;
pub const CPU_SUBTYPE_I386_ALL: u32 = (0 * 0x10 + 3);
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
pub const CPU_SUBTYPE_386: u32 = (0 * 0x10 + 3);
pub const CPU_SUBTYPE_486: u32 = (0 * 0x10 + 4);
pub const CPU_SUBTYPE_486SX: u32 = (8 * 0x10 + 4);
pub const CPU_SUBTYPE_586: u32 = (0 * 0x10 + 5);
pub const CPU_SUBTYPE_PENT: u32 = (0 * 0x10 + 5);
pub const CPU_SUBTYPE_PENTPRO: u32 = (1 * 0x10 + 6);
pub const CPU_SUBTYPE_PENTII_M3: u32 = (3 * 0x10 + 6);
pub const CPU_SUBTYPE_PENTII_M5: u32 = (5 * 0x10 + 6);
pub const CPU_SUBTYPE_CELERON: u32 = (6 * 0x10 + 7);
pub const CPU_SUBTYPE_CELERON_MOBILE: u32 = (7 * 0x10 + 7);
pub const CPU_SUBTYPE_PENTIUM_3: u32 = (0 * 0x10 + 8);
pub const CPU_SUBTYPE_PENTIUM_3_M: u32 = (1 * 0x10 + 8);
pub const CPU_SUBTYPE_PENTIUM_3_XEON: u32 = (2 * 0x10 + 8);
pub const CPU_SUBTYPE_PENTIUM_M: u32 = (0 * 0x10 + 9);
pub const CPU_SUBTYPE_PENTIUM_4: u32 = (0 * 0x10 + 10);
pub const CPU_SUBTYPE_PENTIUM_4_M: u32 = (1 * 0x10 + 10);
pub const CPU_SUBTYPE_ITANIUM: u32 = (0 * 0x10 + 11);
pub const CPU_SUBTYPE_ITANIUM_2: u32 = (1 * 0x10 + 11);
pub const CPU_SUBTYPE_XEON: u32 = (0 * 0x10 + 12);
pub const CPU_SUBTYPE_XEON_MP: u32 = (1 * 0x10 + 12);
pub const CPU_SUBTYPE_LITTLE_ENDIAN: u32 = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: u32 = 1;
pub const CPU_THREADTYPE_NONE: u32 = 0;
pub const CPU_SUBTYPE_VAX_ALL: u32 = 0;
pub const CPU_SUBTYPE_VAX780: u32 = 1;
pub const CPU_SUBTYPE_VAX785: u32 = 2;
pub const CPU_SUBTYPE_VAX750: u32 = 3;
pub const CPU_SUBTYPE_VAX730: u32 = 4;
pub const CPU_SUBTYPE_UVAXI: u32 = 5;
pub const CPU_SUBTYPE_UVAXII: u32 = 6;
pub const CPU_SUBTYPE_VAX8200: u32 = 7;
pub const CPU_SUBTYPE_VAX8500: u32 = 8;
pub const CPU_SUBTYPE_VAX8600: u32 = 9;
pub const CPU_SUBTYPE_VAX8650: u32 = 10;
pub const CPU_SUBTYPE_VAX8800: u32 = 11;
pub const CPU_SUBTYPE_UVAXIII: u32 = 12;
pub const CPU_SUBTYPE_MC680x0_ALL: u32 = 1;
pub const CPU_SUBTYPE_MC68030: u32 = 1;
pub const CPU_SUBTYPE_MC68040: u32 = 2;
pub const CPU_SUBTYPE_MC68030_ONLY: u32 = 3;
pub const CPU_THREADTYPE_INTEL_HTT: u32 = 1;
pub const CPU_SUBTYPE_MIPS_ALL: u32 = 0;
pub const CPU_SUBTYPE_MIPS_R2300: u32 = 1;
pub const CPU_SUBTYPE_MIPS_R2600: u32 = 2;
pub const CPU_SUBTYPE_MIPS_R2800: u32 = 3;
pub const CPU_SUBTYPE_MIPS_R2000a: u32 = 4;
pub const CPU_SUBTYPE_MIPS_R2000: u32 = 5;
pub const CPU_SUBTYPE_MIPS_R3000a: u32 = 6;
pub const CPU_SUBTYPE_MIPS_R3000: u32 = 7;
pub const CPU_SUBTYPE_MC98000_ALL: u32 = 0;
pub const CPU_SUBTYPE_MC98601: u32 = 1;
pub const CPU_SUBTYPE_HPPA_ALL: u32 = 0;
pub const CPU_SUBTYPE_HPPA_7100: u32 = 0;
pub const CPU_SUBTYPE_HPPA_7100LC: u32 = 1;
pub const CPU_SUBTYPE_MC88000_ALL: u32 = 0;
pub const CPU_SUBTYPE_MC88100: u32 = 1;
pub const CPU_SUBTYPE_MC88110: u32 = 2;
pub const CPU_SUBTYPE_SPARC_ALL: u32 = 0;
pub const CPU_SUBTYPE_I860_ALL: u32 = 0;
pub const CPU_SUBTYPE_I860_860: u32 = 1;
pub const CPU_SUBTYPE_POWERPC_ALL: u32 = 0;
pub const CPU_SUBTYPE_POWERPC_601: u32 = 1;
pub const CPU_SUBTYPE_POWERPC_602: u32 = 2;
pub const CPU_SUBTYPE_POWERPC_603: u32 = 3;
pub const CPU_SUBTYPE_POWERPC_603e: u32 = 4;
pub const CPU_SUBTYPE_POWERPC_603ev: u32 = 5;
pub const CPU_SUBTYPE_POWERPC_604: u32 = 6;
pub const CPU_SUBTYPE_POWERPC_604e: u32 = 7;
pub const CPU_SUBTYPE_POWERPC_620: u32 = 8;
pub const CPU_SUBTYPE_POWERPC_750: u32 = 9;
pub const CPU_SUBTYPE_POWERPC_7400: u32 = 10;
pub const CPU_SUBTYPE_POWERPC_7450: u32 = 11;
pub const CPU_SUBTYPE_POWERPC_970: u32 = 100;
pub const CPU_SUBTYPE_ARM_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM_V4T: u32 = 5;
pub const CPU_SUBTYPE_ARM_V6: u32 = 6;
pub const CPU_SUBTYPE_ARM_V5TEJ: u32 = 7;
pub const CPU_SUBTYPE_ARM_XSCALE: u32 = 8;
pub const CPU_SUBTYPE_ARM_V7: u32 = 9;
pub const CPU_SUBTYPE_ARM_V7F: u32 = 10;
pub const CPU_SUBTYPE_ARM_V7S: u32 = 11;
pub const CPU_SUBTYPE_ARM_V7K: u32 = 12;
pub const CPU_SUBTYPE_ARM_V6M: u32 = 14;
pub const CPU_SUBTYPE_ARM_V7M: u32 = 15;
pub const CPU_SUBTYPE_ARM_V7EM: u32 = 16;
pub const CPU_SUBTYPE_ARM_V8: u32 = 13;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;

// dont bother with the unions
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct x_nlist {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: i16,
    pub n_value: u32,
}
impl Swap for x_nlist {
    fn bswap(&mut self) {
        self.n_strx.bswap();
        self.n_type.bswap();
        self.n_sect.bswap();
        self.n_desc.bswap();
        self.n_value.bswap();
    }
}
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct x_nlist_64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}
impl Swap for x_nlist_64 {
    fn bswap(&mut self) {
        self.n_strx.bswap();
        self.n_type.bswap();
        self.n_sect.bswap();
        self.n_desc.bswap();
        self.n_value.bswap();
    }
}

pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u32 = 2;

pub fn u32_to_prot(ip: u32) -> exec::Prot {
    exec::Prot {
        r: (ip & VM_PROT_READ) != 0,
        w: (ip & VM_PROT_WRITE) != 0,
        x: (ip & VM_PROT_EXECUTE) != 0,
    }
}

#[inline(always)]
// probably 100% counterproductive optimization
pub fn copy_nlist_from_slice(slice: &[u8], end: Endian) -> x_nlist_64 {
    let len = slice.len();
    let is64 = if len == size_of::<x_nlist_64>() { true }
          else if len == size_of::<x_nlist>() { false }
          else { panic!() };
    unsafe {
        let ptr = slice.as_ptr();
        let source32: *const x_nlist = std::mem::transmute(ptr);
        let source64: *const x_nlist_64 = std::mem::transmute(ptr);
        let (mut strx, mut typ, mut sect, mut desc) =
            ((*source64).n_strx, (*source64).n_type,
             (*source64).n_sect, (*source64).n_desc);
        let value;
        if end.needs_swap() {
            strx.bswap(); typ.bswap(); sect.bswap(); desc.bswap();
            value = if is64 {
                let mut v = (*source64).n_value; v.bswap(); v
            } else {
                let mut v = (*source32).n_value; v.bswap(); v as u64
            }
        } else {
            value = if is64 { (*source64).n_value } else { (*source32).n_value as u64 }
        }
        x_nlist_64 {
            n_strx: strx,
            n_type: typ,
            n_sect: sect,
            n_desc: desc,
            n_value: value,
        }
    }
}

pub fn copy_nlist_to_vec(vec: &mut Vec<u8>, nl: &x_nlist_64, end: Endian, is64: bool) {
    if is64 {
        util::copy_to_vec(vec, nl, end);
    } else {
        let nl32 = x_nlist {
            n_strx: nl.n_strx,
            n_type: nl.n_type,
            n_sect: nl.n_sect,
            n_desc: nl.n_desc as i16,
            n_value: nl.n_value.narrow().unwrap(),
        };
        util::copy_to_vec(vec, &nl32, end);
    }
}


pub fn exec_sym_to_nlist_64(sym: &Symbol, strx: u32, ind_strx: Option<u32>, arch: arch::Arch, is_text: &mut FnMut() -> bool, for_obj: bool) -> Result<x_nlist_64, String> {
    // some stuff is missing, like common symbols
    let mut res: x_nlist_64 = Default::default();
    if sym.is_weak {
        res.n_type |= if let SymbolValue::Undefined(..) = sym.val { N_WEAK_REF } else { N_WEAK_DEF } as u8
    }
    if sym.is_public {
        res.n_type |= N_EXT as u8;
    }
    match &sym.val {
        &SymbolValue::Addr(vma) | &SymbolValue::ThreadLocal(vma) => {
            res.n_value = vma.0;
        },
        &SymbolValue::Abs(vma) => {
            res.n_value = vma.0;
            res.n_type |= N_ABS as u8;
        },
        &SymbolValue::Undefined(source) | &SymbolValue::ReExport(_, source) => {
            if let &SymbolValue::Undefined(..) = &sym.val {
                res.n_value = 0;
                res.n_type |= N_UNDF as u8;
            } else {
                res.n_value = ind_strx.unwrap().ext();
                res.n_type |= N_INDR as u8;
            }
            let ord = match source {
                SourceLib::None => 0,
                SourceLib::Flat => {
                    res.n_desc |= N_REF_TO_WEAK as u16;
                    DYNAMIC_LOOKUP_ORDINAL
                },
                SourceLib::Self_ => SELF_LIBRARY_ORDINAL,
                SourceLib::MainExecutable => EXECUTABLE_ORDINAL,
                SourceLib::Ordinal(xord) => xord + 1,
            };
            res.n_desc |= (ord << 8) as u16;
        },
        &SymbolValue::Resolver(vma, _) => {
            res.n_value = vma.0;
            // N_SYMBOL_RESOLVER is new, so it only needs to support ld linking against it from an
            // object file, not dyld from a dylib/etc.  In fact, the flag overlaps with the library
            // ordinal field for non-MH_OBJECTs (probably doesn't matter), and there's no way to specify the address of the
            // stub, because ld creates that so it doesn't exist in objects.
            if !for_obj {
                res.n_desc |= N_SYMBOL_RESOLVER as u16;
            }
        },
    }
    if res.n_value & 1 != 0 && arch == arch::ARM && is_text() {
        res.n_value -= 1;
        res.n_desc |= N_ARM_THUMB_DEF as u16;
    }
    res.n_strx = strx;
    Ok(res)
}

fn file_array(buf: &Mem<u8>, name: &str, off: u32, count: u32, elm_size: usize) -> Mem<u8> {
    file_array_64(buf, name, off as u64, count as u64, elm_size)
}
fn file_array_64(buf: &Mem<u8>, name: &str, mut off: u64, mut count: u64, elm_size: usize) -> Mem<u8> {
    let elm_size = elm_size as u64;
    let buf_len = buf.len() as u64;
    if off > buf_len {
        if name.len() != 0 {
            errln!("warning: {} (offset {}, {} * {}b-sized elements) starts past end of file ({}))", name, off, count, elm_size, buf_len);
        }
        off = 0;
        count = 0;
    } else if count > (buf_len - off) / elm_size {
        if name.len() != 0 {
            errln!("warning: {} (offset {}, {} * {}b-sized elements) extends past end of file ({})); truncating", name, off, count, elm_size, buf_len);
        }
        count = (buf_len - off) / elm_size;
    }
    buf.slice(off as usize, (off + count * elm_size) as usize).unwrap()
}


#[derive(Clone)]
pub struct DscTabs {
    pub symtab: Mem<u8>,
    pub strtab: Mem<u8>,
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadDylibKind {
    Normal = LC_LOAD_DYLIB as isize,
    Weak = LC_LOAD_WEAK_DYLIB as isize,
    Reexport = LC_REEXPORT_DYLIB as isize,
    Upward = LC_LOAD_UPWARD_DYLIB as isize,
}

#[derive(Clone)]
pub struct LoadDylib {
    pub path: ByteString,
    pub kind: LoadDylibKind,
    pub timestamp: u32,
    pub current_version: PackedVersion,
    pub compatibility_version: PackedVersion,
}

#[derive(Clone, Copy)]
pub struct PackedVersion(pub u32);
impl std::fmt::Display for PackedVersion {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}.{}.{}", self.0 >> 16, (self.0 >> 8) & 255, self.0 & 255)
    }
}

#[derive(Clone)]
pub struct SectPrivate {
    pub idx_in_seg: usize,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Default, Clone)]
pub struct MachO {
    pub eb: exec::ExecBase,
    pub is64: bool,
    pub mh: mach_header,
    pub load_commands: Vec<Mem<u8>>,
    pub load_dylib: Vec<LoadDylib>,
    pub dyld_base: Option<VMA>,
    pub sect_private: Vec<SectPrivate>,

    // old-style symbol table:
    pub nlist_size: usize,
    pub symtab: Mem<u8>,
    pub localsym: Mem<u8>,
    pub extdefsym: Mem<u8>,
    pub undefsym: Mem<u8>,
    pub strtab: Mem<u8>,
    pub dsc_tabs: Option<DscTabs>,
    pub toc: Mem<u8>,
    pub modtab: Mem<u8>,
    pub extrefsym: Mem<u8>,
    pub indirectsym: Mem<u8>,
    pub extrel: Mem<u8>,
    pub locrel: Mem<u8>,
    // new-style
    pub dyld_info_is_only: bool,
    pub dyld_rebase: Mem<u8>,
    pub dyld_bind: Mem<u8>,
    pub dyld_weak_bind: Mem<u8>,
    pub dyld_lazy_bind: Mem<u8>,
    pub dyld_export: Mem<u8>,
    // linkedit_data_commands
    pub segment_split_info: Mem<u8>,
    pub function_starts: Mem<u8>,
    pub data_in_code: Mem<u8>,
    pub linker_optimization_hint: Mem<u8>,
    pub dylib_code_sign_drs: Mem<u8>,
    pub code_signature: Mem<u8>,

    _linkedit_bits: Option<[LinkeditBit; 22]>,

    // from dyld cache
    pub dc_info: MachODCInfo,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum WhichBind {
    Bind = 0,
    WeakBind = 1,
    LazyBind = 2
}

#[derive(Clone, Copy)]
struct LinkeditBit {
    name: &'static str,
    self_field: FieldLens<MachO, Mem<u8>>,
    cmd_id: u32,
    cmd_off_field_off: usize,
    cmd_count_field_off: usize,
    elm_size: usize,
    is_symtab: bool,
}

macro_rules! lbit {
    ($self_field:ident, $cmd_id:ident, $cmd_type:ty, $off_field:ident, $size_field:ident, $divi:expr, $is_symtab:expr) => {
        LinkeditBit {
            name: stringify!($self_field),
            self_field: field_lens!(MachO, $self_field),
            cmd_id: $cmd_id,
            cmd_off_field_off: offset_of!($cmd_type, $off_field),
            cmd_count_field_off: offset_of!($cmd_type, $size_field),
            elm_size: $divi,
            is_symtab: $is_symtab,
        }
    };
    ($self_field:ident, $cmd_id:ident, $cmd_type:ty, $off_field:ident, $size_field:ident, $divi:expr) => { lbit!($self_field, $cmd_id, $cmd_type, $off_field, $size_field, $divi, false) }
}

fn make_linkedit_bits(is64: bool) -> [LinkeditBit; 22] {
    let nlist_size = if is64 { size_of::<nlist_64>() } else { size_of::<nlist>() };
    [
        // section relocations here?
        lbit!(dyld_rebase, LC_DYLD_INFO, dyld_info_command, rebase_off, rebase_size, 1),
        lbit!(dyld_bind, LC_DYLD_INFO, dyld_info_command, bind_off, bind_size, 1),
        lbit!(dyld_weak_bind, LC_DYLD_INFO, dyld_info_command, weak_bind_off, weak_bind_size, 1),
        lbit!(dyld_lazy_bind, LC_DYLD_INFO, dyld_info_command, lazy_bind_off, lazy_bind_size, 1),
        lbit!(dyld_export, LC_DYLD_INFO, dyld_info_command, export_off, export_size, 1),

        lbit!(locrel, LC_DYSYMTAB, dysymtab_command, locreloff, nlocrel, size_of::<relocation_info>()),
        lbit!(segment_split_info, LC_SEGMENT_SPLIT_INFO, linkedit_data_command, dataoff, datasize, 1),
        lbit!(function_starts, LC_FUNCTION_STARTS, linkedit_data_command, dataoff, datasize, 1),
        lbit!(data_in_code, LC_DATA_IN_CODE, linkedit_data_command, dataoff, datasize, 1),

        lbit!(linker_optimization_hint, LC_LINKER_OPTIMIZATION_HINT, linkedit_data_command, dataoff, datasize, 1),
        lbit!(dylib_code_sign_drs, LC_DYLIB_CODE_SIGN_DRS, linkedit_data_command, dataoff, datasize, 1),

        lbit!(symtab, LC_SYMTAB, symtab_command, symoff, nsyms, nlist_size), // ...not first anymore?
        lbit!(extrel, LC_DYSYMTAB, dysymtab_command, extreloff, nextrel, size_of::<relocation_info>()),
        lbit!(indirectsym, LC_DYSYMTAB, dysymtab_command, indirectsymoff, nindirectsyms, 4),
        lbit!(strtab, LC_SYMTAB, symtab_command, stroff, strsize, 1),


        // ld doesn't actually generate these anymore, so can't tell where it should go
        lbit!(modtab, LC_DYSYMTAB, dysymtab_command, modtaboff, nmodtab,
              if is64 { size_of::<dylib_module_64>() } else { size_of::<dylib_module>() }),
        lbit!(toc, LC_DYSYMTAB, dysymtab_command, tocoff, ntoc, size_of::<dylib_table_of_contents>()),
        lbit!(extrefsym, LC_DYSYMTAB, dysymtab_command, extrefsymoff, nextrefsyms, size_of::<dylib_reference>()),

        // added at the end by codesign
        lbit!(code_signature, LC_CODE_SIGNATURE, linkedit_data_command, dataoff, datasize, 1),

        // order of these compared to the rest doesn't affect anything
        lbit!(localsym, LC_DYSYMTAB, dysymtab_command, ilocalsym, nlocalsym, nlist_size, /* is_symtab */ true),
        lbit!(extdefsym, LC_DYSYMTAB, dysymtab_command, iextdefsym, nextdefsym, nlist_size, /* is_symtab */ true),
        lbit!(undefsym, LC_DYSYMTAB, dysymtab_command, iundefsym, nundefsym, nlist_size, /* is_symtab */ true),
    ]
}

// herp derp this is unsafe because of Any not liking non-'static
pub struct MachOLookupExportOptions {
    // for LC_REEXPORT_DYLIB
    pub using_image_cache: Option<&'static ImageCache>,
}

impl exec::Exec for MachO {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }

    fn get_symbol_list<'a>(&'a self, source: SymbolSource, specific: Option<&Any>) -> Vec<Symbol<'a>> {
        let _sw = stopwatch("get_symbol_list");
        assert!(specific.is_none());
        match source {
            SymbolSource::All => {
                let mut out = Vec::new();
                let mut skip_redacted = false;
                if let Some(DscTabs { ref symtab, ref strtab, start, count }) = self.dsc_tabs {
                    self.push_nlist_symbols(symtab.get(), strtab.get(), start as usize, count as usize, false, &mut out);
                    skip_redacted = true;
                }
                self.push_nlist_symbols(self.symtab.get(), self.strtab.get(), 0, self.symtab.len() / self.nlist_size, skip_redacted, &mut out);
                out
            },
            SymbolSource::Imported => {
                let mut out = Vec::new();
                self.parse_each_dyld_bind(&mut |state: &ParseDyldBindState<'a>| {
                    if state.already_bound_this_symbol { return true; }
                    out.push(Symbol {
                        name: some_or!(state.symbol, { return true; }).into(),
                        is_public: true,
                        // XXX what about BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION?
                        is_weak: state.which == WhichBind::WeakBind ||
                                 state.flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0,
                        val: SymbolValue::Undefined(state.source_dylib),
                        size: None,
                        private: 0,
                    });
                    true
                });
                out
            },
            SymbolSource::Exported => self.get_exported_symbol_list(None),
        }
    }
    fn lookup_export(&self, name: &ByteStr, specific: Option<&Any>) -> Vec<Symbol> {
        let mut res = self.get_exported_symbol_list(Some(name));
        if let Some(opts) = specific {
            let opts: &MachOLookupExportOptions = opts.downcast_ref().unwrap();
            if res.len() != 0 { return res; }
            if let Some(ic) = opts.using_image_cache {
                // todo cache?
                for ld in &self.load_dylib {
                    if ld.kind != LoadDylibKind::Reexport { continue; }
                    // yuck yuck yuck slow
                    if let Some(ice) = ic.lookup_path(&ld.path) {
                        if let Ok(ref mo) = ice.mo {
                            // TODO this can loop
                            for new in mo.lookup_export(name, specific) { res.push(new); }
                        } else {
                            errln!("warning: lookup_export: found bad image for LC_REEXPORT_DYLIB entry {}", ld.path);
                        }
                    } else {
                        errln!("warning: lookup_export: couldn't lookup path for LC_REEXPORT_DYLIB entry {}", ld.path);
                    }
                }
            }
        }
        res
    }

    fn get_dep_libs(&self) -> Cow<[DepLib]> {
        let dls = self.load_dylib.iter().enumerate().map(|(i, ld)| DepLib {
            path: (&*ld.path).into(),
            private: i,
        }).collect::<Vec<_>>();
        dls.into()
    }
    fn describe_dep_lib(&self, dl: &DepLib) -> String {
        let ld = &self.load_dylib[dl.private];
        format!("{}{} timestamp={} cur={} compat={}",
                ld.path,
                match ld.kind {
                    LoadDylibKind::Normal   => "",
                    LoadDylibKind::Weak     => " [weak]",
                    LoadDylibKind::Reexport => " [reexport]",
                    LoadDylibKind::Upward   => " [upward]",
                },
                ld.timestamp,
                ld.current_version,
                ld.compatibility_version)
    }

    fn as_any(&self) -> &std::any::Any { self as &std::any::Any }
}

fn mach_arch_desc(cputype: i32, cpusubtype: i32) -> Option<&'static str> {
    let cputype = cputype as u32;
    let cpusubtype = cpusubtype as u32;
    Some(match (cputype, cpusubtype & !0x80000000) {
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

fn fixup_segment_overflow(seg: &mut exec::Segment, sixtyfour: bool) {
    if sixtyfour {
        if seg.vmsize > exec::VMA(u64::MAX) - seg.vmaddr {
            errln!("warning: vmaddr+vmsize overflow: {}+0x{:x}; truncating", seg.vmaddr, seg.vmsize);
            seg.vmsize = exec::VMA(u64::MAX) - seg.vmaddr;
        }
        if seg.filesize > u64::MAX - seg.fileoff {
            errln!("warning: fileoff+filesize overflow: 0x{:x}+0x{:x}; truncating", seg.fileoff, seg.filesize);
            seg.filesize = u64::MAX - seg.fileoff;
        }
    } else {
        if seg.vmsize > exec::VMA(u32::MAX as u64) - seg.vmaddr {
            errln!("warning: vmaddr+vmsize 32-bit overflow: {}+0x{:x}; we're ok though", seg.vmaddr, seg.vmsize);
        }
        if seg.filesize > u32::MAX as u64 - seg.fileoff {
            errln!("warning: fileoff+filesize 32-bit overflow: 0x{:x}+0x{:x}; we're ok though", seg.fileoff, seg.filesize);
        }

    }
}

fn seg_name_to_macho(seg: &exec::Segment, error_pfx: &str) -> [libc::c_char; 16] {
    let mut name: &ByteStr = if let Some(ref name) = seg.name { &**name } else { ByteStr::from_str("") };
    if name.len() > 16 {
        errln!("warning: {} name '{}' is too long, truncating", error_pfx, name);
        name = &name[..16];
    }
    let mut segname: [libc::c_char; 16] = [0; 16];
    for (i, b) in name.iter().enumerate() { segname[i] = *b as i8; }
    segname
}

trait OKOrTruncated<T> { fn ok_or_truncated(self) -> exec::ExecResult<T>; }
impl<T> OKOrTruncated<T> for Option<T> {
    fn ok_or_truncated(self) -> exec::ExecResult<T> {
        if let Some(a) = self { Ok(a) } else { err(ErrorKind::BadData, "truncated") }
    }
}

pub struct ParseDyldBindState<'s> {
    pub source_dylib: SourceLib,
    pub seg: Option<&'s exec::Segment>,
    pub seg_idx: usize,
    pub seg_off: Option<u64>,
    pub seg_size: u64,
    pub addend: i64,
    pub typ: u8,
    pub symbol: Option<&'s ByteStr>,
    pub already_bound_this_symbol: bool,
    pub flags: u32,
    pub which: WhichBind,
}
struct ParseDyldExportState<'a> {
    name: &'a ByteStr,
    addr: VMA,
    flags: u32,
    resolver: Option<VMA>,
    reexport: Option<(u64, &'a ByteStr)>,
    offset: usize,
}

pub enum GuessBrokenCacheSlideResult {
    Guess(u64),
    Inconsistent,
    BlownAway,
    GotNoBindSelf,
}

// info about the dyld cache containing this macho
#[derive(Default, Copy, Clone, Debug)]
pub struct MachODCInfo {
    hdr_offset: usize,
    have_images_text_offset: bool,
}

impl MachO {
    pub fn new(mc: Mem<u8>, do_lcs: bool, dc_info: Option<MachODCInfo>) -> exec::ExecResult<MachO> {
        let mut me: MachO = Default::default();
        let dc_info = dc_info.unwrap_or(Default::default());
        me.dc_info = dc_info;
        let hdr_offset = dc_info.hdr_offset;
        let mut lc_off = try!(hdr_offset.checked_add(size_of::<mach_header>()).ok_or_truncated());
        {
            let buf = mc.get();
            if buf.len() < lc_off { return err(ErrorKind::BadData, "truncated"); }
            let magic: u32 = util::copy_from_slice(&buf[hdr_offset..hdr_offset+4], util::BigEndian);
            let is64; let end;
            match magic {
                0xfeedface => { end = util::BigEndian; is64 = false; }
                0xfeedfacf => { end = util::BigEndian; is64 = true; }
                0xcefaedfe => { end = util::LittleEndian; is64 = false; }
                0xcffaedfe => { end = util::LittleEndian; is64 = true; }
                _ => return err(ErrorKind::BadData, "bad magic")
            }
            me.eb.endian = end;
            me.is64 = is64;
            me.mh = util::copy_from_slice(&buf[hdr_offset..lc_off], end);
            // useless 'reserved' field
            if is64 { lc_off += 4; }
            me.eb.pointer_size = if me.is64 { 8 } else { 4 };
        }
        me._linkedit_bits = Some(make_linkedit_bits(me.is64)); /* :( */
        me.parse_header();
        me.eb.whole_buf = Some(mc.clone());
        if do_lcs {
            me.parse_load_commands(lc_off, &mc);
        }
        Ok(me)
    }

    pub fn subtype_desc(&self) -> Option<&'static str> {
        mach_arch_desc(self.mh.cputype, self.mh.cpusubtype)
    }

    pub fn desc(&self) -> String {
        let ft_desc = match self.mh.filetype {
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
        let st_desc: Cow<str> = match self.subtype_desc() {
            Some(d) => d.into(),
            None => format!("<unknown cpu {}/{}>", self.mh.cputype, self.mh.cpusubtype).into()
        };
        format!("Mach-O {}/{}", ft_desc, st_desc)
    }

    fn linkedit_bits(&self) -> &[LinkeditBit] {
        self._linkedit_bits.as_ref().unwrap()
    }

    fn parse_header(&mut self) {
        self.eb.arch = match self.mh.cputype as u32 {
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

    fn parse_load_commands(&mut self, mut lc_off: usize, mc: &Mem<u8>) {
        let self_ = self as *mut _;
        self.nlist_size = if self.is64 { size_of::<nlist_64>() } else { size_of::<nlist>() };
        let end = self.eb.endian;
        let hdr_offset = self.dc_info.hdr_offset as u64;
        let whole = mc.get();
        let mut segi: usize = 0;
        for lci in 0..self.mh.ncmds {
            let lc_data = some_or!(whole.slice_opt(lc_off, lc_off + 8),
                                   { errln!("warning: load commands truncated (couldn't read LC header)"); return; });
            let lc: load_command = util::copy_from_slice(lc_data, end);
            let lc_mc = some_or!(mc.slice(lc_off, lc_off + lc.cmdsize as usize),
                                 { errln!("warning: load commands truncated (cmdsize {} too high?)", lc.cmdsize); return; });
            let lc_buf = lc_mc.get();
            let mut do_segment = |is64: bool, segs: &mut Vec<exec::Segment>, sects: &mut Vec<exec::Segment>, sect_private: &mut Vec<SectPrivate>| {
                branch!(if (is64) {
                    type segment_command_x = segment_command_64;
                    type section_x = section_64;
                } else {
                    type segment_command_x = segment_command;
                    type section_x = section;
                } then {
                    let mut off = size_of::<segment_command_x>();
                    let sc_data = some_or!(lc_buf.slice_opt(0, off),
                                           { errln!("warning: segment command too small; skipping"); return; });
                    let sc: segment_command_x = util::copy_from_slice(sc_data, end);
                    let segprot = u32_to_prot(sc.initprot as u32);
                    let mut fileoff = sc.fileoff as u64;
                    let name = util::from_cstr(&sc.segname as &[i8]).to_owned();
                    let is_cache_text = hdr_offset != 0 && &name == "__TEXT";
                    if is_cache_text {
                        // u_d_s_c just keeps this from the original file.  Somehow, for the arm64
                        // cache, the offset isn't even consistent between __TEXT's fileoff and
                        // __text's.  So just do it based on the address.
                        fileoff = hdr_offset;
                    }
                    //let was_0 = sc.fileoff == 0;
                    //let fileoff = if was_0 { hdr_offset as u64 } else { sc.fileoff as u64 };
                    let data: Option<Mem<u8>> = mc.slice(fileoff as usize, (fileoff + (sc.filesize as u64)) as usize);
                    let mut seg = exec::Segment {
                        vmaddr: VMA(sc.vmaddr as u64),
                        vmsize: sc.vmsize as u64,
                        fileoff: fileoff,
                        filesize: sc.filesize as u64,
                        name: Some(name),
                        prot: segprot,
                        data: data,
                        seg_idx: None,
                        private: lci.ext(),
                    };
                    fixup_segment_overflow(&mut seg, is64);
                    segs.push(seg);
                    for secti in 0..sc.nsects {
                        let s: section_x = util::copy_from_slice(&lc_buf[off..off + size_of::<section_x>()], end);
                        let mut fileoff = s.offset as u64;
                        if is_cache_text {
                            fileoff = some_or!((s.addr as u64).check_sub(sc.vmaddr as u64).check_add(hdr_offset), {
                                errln!("warning: integer overflow in shared cache library __TEXT offset recalculation");
                                fileoff
                            });
                        }
                        let mut seg = exec::Segment {
                            vmaddr: VMA(s.addr as u64),
                            vmsize: s.size as u64,
                            fileoff: fileoff,
                            filesize: if s.offset != 0 { s.size as u64 } else { 0 },
                            name: Some(util::from_cstr(&s.sectname as &[i8]).to_owned()),
                            prot: segprot,
                            data: None,
                            seg_idx: Some(segi),
                            private: sect_private.len(),
                        };
                        //if was_0 { seg.fileoff += hdr_offset; }
                        fixup_segment_overflow(&mut seg, is64);
                        sects.push(seg);
                        sect_private.push(SectPrivate {
                            idx_in_seg: secti.ext(),
                            flags: s.flags,
                            reserved1: s.reserved1,
                            reserved2: s.reserved2,
                        });
                        off += size_of::<section_x>();
                    }
                });
                segi += 1;
            };
            match lc.cmd {
                LC_SEGMENT => do_segment(false, &mut self.eb.segments, &mut self.eb.sections, &mut self.sect_private),
                LC_SEGMENT_64 => do_segment(true, &mut self.eb.segments, &mut self.eb.sections, &mut self.sect_private),
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY | LC_SYMTAB | LC_DYSYMTAB |
                LC_FUNCTION_STARTS | LC_DATA_IN_CODE | LC_DYLIB_CODE_SIGN_DRS |
                LC_SEGMENT_SPLIT_INFO | LC_LINKER_OPTIMIZATION_HINT | LC_CODE_SIGNATURE => {
                    for fb in self.linkedit_bits() {
                        if lc.cmd == fb.cmd_id || (lc.cmd == LC_DYLD_INFO_ONLY && fb.cmd_id == LC_DYLD_INFO) {
                            let mcref: &mut Mem<u8> = unsafe { fb.self_field.get_mut_unsafe(self_) };
                            let (off_data, count_data) =
                                some_or!(         lc_buf.slice_opt(fb.cmd_off_field_off, fb.cmd_off_field_off+4)
                                         .and_tup(lc_buf.slice_opt(fb.cmd_count_field_off, fb.cmd_count_field_off+4)),
                                         { errln!("warning: load command too small for offset/size of {}", fb.name); continue; });
                            let mut off: u32 = util::copy_from_slice(off_data, end);
                            let count: u32 = util::copy_from_slice(count_data, end);
                            let buf = if fb.is_symtab {
                                off *= fb.elm_size as u32;
                                &self.symtab
                            } else {
                                self.eb.whole_buf.as_ref().unwrap()
                            };
                            let mut ignore = false;
                            if self.dc_info.hdr_offset != 0 && !self.dc_info.have_images_text_offset {
                                // update_dsc is supposed to drop the others but... doesn't on iOS?
                                // newer versions (approximated as those with imagesTextOffset) don't
                                // have this bug
                                match lc.cmd {
                                    LC_SYMTAB |
                                    LC_DYSYMTAB |
                                    LC_DYLD_INFO | LC_DYLD_INFO_ONLY |
                                    LC_FUNCTION_STARTS | LC_DATA_IN_CODE => (),
                                    _ => ignore = true,
                                }
                            }
                            if !ignore {
                                *mcref = file_array(buf, fb.name, off, count, fb.elm_size);
                            }
                        }
                    }
                },
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    if (lc.cmdsize as usize) < size_of::<dylib_command>() {
                        errln!("warning: LC_LOAD_DYLIB command too small");
                    } else {
                        let dc: dylib_command = util::copy_from_slice(&lc_buf[..size_of::<dylib_command>()], end);
                        let offset: u32 = unsafe { transmute(dc.dylib.name) };
                        let offset = offset as usize;
                        let name = if offset <= lc_buf.len() {
                            let rest = &lc_buf[offset..];
                            let n = util::from_cstr(rest);
                            if n.len() == rest.len() {
                                errln!("warning: LC_LOAD_DYLIB name runs off end");
                            }
                            n
                        } else {
                            errln!("warning: LC_LOAD_DYLIB invalid offset");
                            ByteStr::from_str("<err>")
                        };
                        self.load_dylib.push(LoadDylib {
                            path: ByteString::new(name),
                            kind: unsafe { transmute(lc.cmd) },
                            timestamp: dc.dylib.timestamp,
                            current_version: PackedVersion(dc.dylib.current_version),
                            compatibility_version: PackedVersion(dc.dylib.compatibility_version),
                        });
                    }
                },
                _ => ()
            }
            lc_off += lc.cmdsize as usize;
            self.load_commands.push(lc_mc.clone()); // unnecessary clone
        }
        self.update_dyld_base();
    }

    pub fn update_dyld_base(&mut self) {
        let text_fileoff = self.text_fileoff();
        for seg in &self.eb.segments {
            if seg.fileoff == text_fileoff && seg.filesize != 0 {
                self.dyld_base = Some(seg.vmaddr);
                break;
            }
        }
    }
    pub fn text_fileoff(&self) -> u64 {
        self.dc_info.hdr_offset.ext()
    }

    fn push_nlist_symbols<'a>(&self, symtab: &[u8], strtab: &'a [u8], start: usize, count: usize, skip_redacted: bool, out: &mut Vec<Symbol<'a>>) {
        let mut off = start * self.nlist_size;
        for _ in start..start+count {
            let slice = &symtab[off..off + self.nlist_size];
            let nl = copy_nlist_from_slice(slice, self.eb.endian);

            let _n_pext = (nl.n_type as u32 & N_PEXT) != 0;
            let _n_stab = (nl.n_type as u32 & N_STAB) >> 5;
            let n_type = nl.n_type as u32 & N_TYPE;
            let weak = (nl.n_desc as u32 & (N_WEAK_REF | N_WEAK_DEF)) != 0;
            let public = (nl.n_type as u32 & N_EXT) != 0;
            let name = if nl.n_strx == 0 { ByteStr::from_str("") }
                                    else { util::from_cstr(&strtab[nl.n_strx as usize..]) };
            let vma = VMA(nl.n_value as u64);
            let vma = if nl.n_desc as u32 & N_ARM_THUMB_DEF != 0 { vma | 1 } else { vma };
            let is_obj = self.mh.filetype == MH_OBJECT;
            let ord = (nl.n_desc >> 8) as u32;
            let source_lib = if is_obj || (n_type != N_UNDF && n_type != N_INDR) {
                SourceLib::None
            } else if (nl.n_desc as u32 & N_REF_TO_WEAK != 0) ||
                      (self.load_dylib.len() < 254 && ord == DYNAMIC_LOOKUP_ORDINAL) {
                SourceLib::Flat
            } else if ord == SELF_LIBRARY_ORDINAL {
                SourceLib::Self_
            } else if ord == EXECUTABLE_ORDINAL {
                SourceLib::MainExecutable
            } else {
                SourceLib::Ordinal((ord - 1) as u32)
            };
            let val =
                if nl.n_desc as u32 & N_SYMBOL_RESOLVER != 0 && is_obj {
                    SymbolValue::Resolver(vma, None)
                } else if n_type == N_UNDF {
                    SymbolValue::Undefined(source_lib)
                } else if n_type == N_INDR {
                    assert!(nl.n_value <= 0xfffffffe); // XXX why?
                    let indr_name = util::from_cstr(&strtab[nl.n_value as usize..]);
                    // is the source_lib right?
                    SymbolValue::ReExport(into_cow(indr_name), source_lib)
                } else if n_type == N_ABS {
                    SymbolValue::Abs(vma)
                } else {
                    let mut vma = vma;
                    let mut val = SymbolValue::Addr(vma);
                    if nl.n_sect as u32 != NO_SECT {
                        let secti = nl.n_sect as usize;
                        if let Some(sect) = self.eb.sections.get(secti) {
                            if is_obj {
                                vma = vma.wrapping_add(sect.vmaddr.0);
                            }
                            let sect_flags = if sect.private == !0 {
                                0
                            } else {
                                self.sect_private[sect.private].flags
                            };
                            if sect_flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES {
                                val = SymbolValue::ThreadLocal(vma);
                            }
                        } else {
                            errln!("warning: invalid section index {} for symbol named {}", secti, name);
                        }
                    }
                    val
                };
            if !(skip_redacted && name == ByteStr::from_bytes(b"<redacted>")) {
                out.push(Symbol {
                    name: into_cow(name),
                    is_public: public,
                    is_weak: weak,
                    val: val,
                    size: None,
                    private: off,
                })
            }
            off += self.nlist_size;
        }
    }

    pub fn page_size(&self) -> u64 {
        if self.eb.arch == arch::AArch64 { 0x4000 } else { 0x1000 }
    }

    pub fn rewhole(&mut self) {
        let _sw = stopwatch("rewhole");
        let new_size = self.eb.segments.iter().map(|seg| seg.fileoff + seg.filesize).max().unwrap_or(0);
        let mut mm = Mem::with_vec(vec![0; new_size as usize]);
        {
            let buf = mm.get_mut().unwrap();
            for seg in &self.eb.segments {
                let data = seg.get_data();
                assert_eq!(seg.filesize, data.len() as u64);
                copy_memory(data, &mut buf[seg.fileoff as usize..seg.fileoff as usize + seg.filesize as usize]);
            }
        }
        self.eb.whole_buf = Some(mm);
    }

    pub fn reallocate(&mut self) -> exec::ExecResult<()> {
        let _sw = stopwatch("reallocate");
        self.code_signature = Mem::<u8>::default();
        self.xsym_to_symtab();
        let page_size = self.page_size();

        let (linkedit, linkedit_allocs) = self.reallocate_linkedit();

        let mut linkedit_idx: Option<usize> = None;
        let mut text_idx: Option<usize> = None;
        let text_fileoff = self.text_fileoff();
        for (i, seg) in self.eb.segments.iter_mut().enumerate() {
            if seg.name.as_ref().map(|s| &s[..]) == Some(ByteStr::from_str("__LINKEDIT")) {
                linkedit_idx = Some(i);
                seg.vmsize = (linkedit.len() as u64).align_to(page_size);
                seg.filesize = linkedit.len() as u64;
                seg.data = Some(Mem::<u8>::with_data(&linkedit[..]));
            } else if seg.fileoff == text_fileoff && seg.filesize > 0 {
                text_idx = Some(i);
            }
        }
        let text_idx = some_or!(text_idx, {
            return err(ErrorKind::BadData, "no text segment?");
        });
        if linkedit_idx.is_none() && linkedit.len() > 0 {
            return err(ErrorKind::Other, "allocating new segments in VM space not supported yet");
        }

        let initial_cmds = self.update_cmds(0, &linkedit_allocs);
        let cmds_len: usize = initial_cmds.iter().map(Vec::len).sum();
        let (text_fileoff, text_filesize) = {
            let text_seg = &self.eb.segments[text_idx];
            (text_seg.fileoff, text_seg.filesize)
        };
        // do we have enough space for the LCs?
        let header_size = if self.is64 { size_of::<mach_header_64>() } else { size_of::<mach_header>() };
        let cmds_space_end = max((header_size as u32).check_add(self.mh.sizeofcmds)
                                            .unwrap_or_else(|| {
                                                errln!("warning: sizeofcmds way too big");
                                                0
                                            }) as usize,
                                 self.eb.sections.iter_mut()
                                                 .filter(|sect| sect.filesize != 0 &&
                                                                sect.seg_idx == Some(text_idx))
                                                 .map(|sect| sect.fileoff - text_fileoff )
                                                 .min().unwrap_or(0).narrow().unwrap());
        if cmds_space_end as u64 > text_filesize {
            return err(ErrorKind::BadData, "load commands go past __TEXT");
        }
        let cmds_space = some_or!(cmds_space_end.check_sub(header_size),
                                  return err(ErrorKind::BadData,
                                             "sizeofcmds too small"));
        let cmds_push = cmds_len.check_sub(cmds_space).unwrap_or(0);
        if cmds_push > 0 {
            return err(ErrorKind::Other, "need to slide in this case; not supported yet");
        }
        self.eb.segments[0].filesize += cmds_push as u64;

        self.reallocate_seg_offsets();

        let cmds = self.update_cmds(if let Some(li) = linkedit_idx { self.eb.segments[li].fileoff as usize } else { 0 }, &linkedit_allocs);
        assert_eq!(cmds_len, cmds.iter().map(Vec::len).sum());

        self.mh.ncmds = cmds.len() as u32;
        self.mh.sizeofcmds = cmds_len as u32;

        // update text/LC segment
        {
            let seg = &mut self.eb.segments[text_idx];
            let mut sbuf = Vec::new();
            sbuf.resize(seg.filesize as usize, 0);
            copy_memory(&seg.get_data()[cmds_space..], &mut sbuf[cmds_space + cmds_push..]);
            util::copy_to_slice(&mut sbuf[..size_of::<mach_header>()], &self.mh, self.eb.endian);
            let mut off = header_size;
            for cmd in &cmds {
                copy_memory(&cmd[..], &mut sbuf[off..off+cmd.len()]);
                off += cmd.len();
            }
            let smc = Mem::<u8>::with_data(&sbuf[..]);
            seg.data = Some(smc.clone());
            // update self.load_commands
            off = 0;
            self.load_commands.clear();
            for cmd in &cmds {
                self.load_commands.push(smc.slice(off, off+cmd.len()).unwrap());
                off += cmd.len();
            }
        }
        Ok(())
    }

    fn reallocate_linkedit(&self) -> (Vec<u8>, Vec<(usize, usize)>) {
        let mut linkedit: Vec<u8> = Vec::new();
        let mut allocs: Vec<(usize, usize)> = Vec::new();
        for fb in self.linkedit_bits() {
            let mcref: &Mem<u8> = fb.self_field.get(self);
            let buf = mcref.get();
            if fb.is_symtab {
                if mcref.len() == 0 {
                    allocs.push((0, 0));
                } else {
                    allocs.push((mcref.offset_in(&self.symtab).unwrap(), buf.len()));
                }
            } else {
                allocs.push((linkedit.len(), buf.len()));
                linkedit.extend_slice(buf);
            }
        }
        (linkedit, allocs)
    }

    fn reallocate_seg_offsets(&mut self) {
        let page_size = self.page_size();
        for sect in &mut self.eb.sections {
            if sect.filesize != 0 {
                sect.fileoff -= self.eb.segments[sect.seg_idx.expect("sect not belonging to seg?")].fileoff;
            }
        }
        let mut off: u64 = 0;
        for seg in &mut self.eb.segments {
            seg.fileoff = off;
            off += seg.filesize.align_to(page_size);
        }
        for sect in &mut self.eb.sections {
            if sect.filesize == 0 {
                sect.fileoff = 0;
            } else {
                sect.fileoff += self.eb.segments[sect.seg_idx.unwrap()].fileoff;
            }
        }
        self.dc_info.hdr_offset = 0;
    }


    pub fn xsym_to_symtab(&mut self) {
        let mut new_vec = self.localsym.get().to_owned();
        new_vec.extend_slice(self.extdefsym.get());
        new_vec.extend_slice(self.undefsym.get());
        let mc = Mem::<u8>::with_data(&new_vec[..]);
        self.symtab = mc;
        let parts = [
            (0, self.localsym.len()),
            (self.localsym.len(), self.extdefsym.len()),
            (self.localsym.len() + self.extdefsym.len(), self.undefsym.len()),
        ];
        self.symtab_to_xsym(&parts);
    }

    fn symtab_to_xsym(&mut self, parts: &[(usize, usize); 3]) {
        let mc = &self.symtab;
        self.localsym = mc.slice(parts[0].0, parts[0].0+parts[0].1).unwrap();
        self.extdefsym = mc.slice(parts[1].0, parts[1].0+parts[1].1).unwrap();
        self.undefsym = mc.slice(parts[2].0, parts[2].0+parts[2].1).unwrap();
    }

    fn update_cmds(&self, linkedit_off: usize, linkedit_allocs: &[(usize, usize)]) -> Vec<Vec<u8>> {
        let mut cmds: Vec<Vec<u8>> = Vec::new();
        let (mut existing_segs, extra_segs) = self.update_seg_cmds();
        let mut insert_extra_segs_idx: Option<usize> = None;
        let end = self.eb.endian;

        let mut dyld_info_cmd_id = LC_DYLD_INFO_ONLY;
        for cmd in &self.load_commands {
            let cmd = cmd.get();
            let cmd_id: u32 = util::copy_from_slice(&cmd[..4], self.eb.endian);
            if cmd_id == LC_DYLD_INFO {
                dyld_info_cmd_id = cmd_id;
            }
        }

        let mut bit_cmds = [
            (LC_DYLD_INFO, size_of::<dyld_info_command>()),
            (LC_SYMTAB, size_of::<symtab_command>()),
            (LC_DYSYMTAB, size_of::<dysymtab_command>()),
            (LC_DYLIB_CODE_SIGN_DRS, size_of::<linkedit_data_command>()),
            (LC_SEGMENT_SPLIT_INFO, size_of::<linkedit_data_command>()),
            (LC_FUNCTION_STARTS, size_of::<linkedit_data_command>()),
            (LC_DATA_IN_CODE, size_of::<linkedit_data_command>()),
            (LC_LINKER_OPTIMIZATION_HINT, size_of::<linkedit_data_command>()),
            // for consistency, code_signature is here, but reallocate() nukes it
            (LC_CODE_SIGNATURE, size_of::<linkedit_data_command>()),
        ].iter().map(|&(cmd, cmdsize)| {
            let mut buf: Vec<u8> = Vec::new();
            buf.resize(cmdsize, 0);
            util::copy_to_slice(&mut buf[0..8], &load_command {
                cmd: if cmd == LC_DYLD_INFO { dyld_info_cmd_id } else { cmd },
                cmdsize: cmdsize as u32,
            }, end);
            let mut got_any = false;
            for (fb, &(mut off, len)) in self.linkedit_bits().iter().zip(linkedit_allocs) {
                if cmd == fb.cmd_id {
                    if len == 0 {
                        off = 0;
                    } else if fb.is_symtab {
                        off /= fb.elm_size;
                    } else {
                        off += linkedit_off;
                    }
                    util::copy_to_slice(&mut buf[fb.cmd_off_field_off..fb.cmd_off_field_off+4], &(off as u32), end);
                    util::copy_to_slice(&mut buf[fb.cmd_count_field_off..fb.cmd_count_field_off+4], &((len / fb.elm_size) as u32), end);
                    if len > 0 {
                        got_any = true;
                    }
                }
            }
            if got_any { Some(buf) } else { None }
        }).collect::<Vec<_>>();


        for (lci, cmd) in self.load_commands.iter().enumerate() {
            let cmd = cmd.get();
            let cmd_id: u32 = util::copy_from_slice(&cmd[..4], self.eb.endian);
            if cmd_id != LC_SEGMENT && cmd_id != LC_SEGMENT_64 && insert_extra_segs_idx == None {
                insert_extra_segs_idx = Some(cmds.len());
            }
            match cmd_id {
                LC_SEGMENT | LC_SEGMENT_64 => {
                    if let Some(new_cmd) = existing_segs.remove(lci) {
                        cmds.push(new_cmd);
                    }
                },
                _ => {
                    if let Some(idx) = match cmd_id {
                        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => Some(0),
                        LC_SYMTAB => Some(1),
                        LC_DYSYMTAB => Some(2),
                        LC_DYLIB_CODE_SIGN_DRS => Some(3),
                        LC_SEGMENT_SPLIT_INFO => Some(4),
                        LC_FUNCTION_STARTS => Some(5),
                        LC_DATA_IN_CODE => Some(6),
                        LC_LINKER_OPTIMIZATION_HINT => Some(7),
                        LC_CODE_SIGNATURE => Some(8),
                        _ => None
                    } {
                        if let Some(new_cmd) = bit_cmds[idx].take() {
                            cmds.push(new_cmd);
                        }
                        continue;
                    }
                    cmds.push(cmd.to_owned());
                },
            }
        }
        for cmd in bit_cmds {
            if let Some(cmd) = cmd { cmds.push(cmd); }
        }
        let mut insert_extra_segs_idx = insert_extra_segs_idx.unwrap_or(cmds.len());
        for (_, new_cmd) in existing_segs.into_iter() {
            cmds.insert(insert_extra_segs_idx, new_cmd);
            insert_extra_segs_idx += 1;
        }
        for new_cmd in extra_segs.into_iter() {
            cmds.insert(insert_extra_segs_idx, new_cmd);
            insert_extra_segs_idx += 1;
        }
        cmds
    }

    fn update_seg_cmds(&self) -> (VecMap<Vec<u8>>, Vec<Vec<u8>>) {
        let mut existing_segs = VecMap::new();
        let mut extra_segs = Vec::new();
        for (segi, seg) in self.eb.segments.iter().enumerate() {
            let lci = seg.private;
            let cmd = if self.is64 { LC_SEGMENT_64 } else { LC_SEGMENT };
            let segname = seg_name_to_macho(&seg, "update_seg_cmds: segment");
            let mut new_cmd = Vec::<u8>::new();
            let olcbuf = if lci != usize::MAX { Some(self.load_commands[lci].get()) } else { None };
            branch!(if (self.is64) {
                type segment_command_x = segment_command_64;
                type section_x = section_64;
                type size_x = u64;
            } else {
                type segment_command_x = segment_command;
                type section_x = section;
                type size_x = u32;
            } then {
                let mut sc: segment_command_x = if let Some(ref lcbuf) = olcbuf {
                    util::copy_from_slice(&lcbuf[..size_of::<segment_command_x>()], self.eb.endian)
                } else {
                    segment_command_x {
                        maxprot: 7,
                        ..Default::default()
                    }
                };
                sc.cmd = cmd;
                sc.segname = segname;
                assert!(seg.vmaddr.0 <= !0 as size_x as u64);
                sc.vmaddr = seg.vmaddr.0 as size_x;
                sc.vmsize = seg.vmsize as size_x;
                sc.fileoff = seg.fileoff as size_x;
                sc.filesize = seg.filesize as size_x;
                sc.initprot = 0;
                if seg.prot.r { sc.initprot |= VM_PROT_READ as i32; }
                if seg.prot.w { sc.initprot |= VM_PROT_WRITE as i32; }
                if seg.prot.x { sc.initprot |= VM_PROT_EXECUTE as i32; }

                util::copy_to_vec(&mut new_cmd, &sc, self.eb.endian);

                let mut nsects: usize = 0;
                for sect in self.eb.sections.iter().filter(|sect| sect.seg_idx == Some(segi)) {
                    let mut snc: section_x = if sect.private != !0 {
                        let idx_in_seg = self.sect_private[sect.private].idx_in_seg;
                        let off = size_of::<segment_command_x>() + idx_in_seg * size_of::<section_x>();
                        util::copy_from_slice(&olcbuf.unwrap()[off..off+size_of::<section_x>()], self.eb.endian)
                    } else {
                        Default::default()
                    };
                    snc.segname = segname;
                    snc.sectname = seg_name_to_macho(&sect, "update_seg_cmds: section");
                    snc.addr = sect.vmaddr.0 as size_x;
                    snc.size = sect.vmsize as size_x;
                    if sect.filesize != sect.vmsize && sect.filesize != 0 {
                        errln!("warning: update_seg_cmds: section {} filesize != vmsize, using vmsize", sect.pretty_name());
                    }
                    snc.offset = sect.fileoff as u32;
                    util::copy_to_vec(&mut new_cmd, &snc, self.eb.endian);
                    nsects += 1;
                }
                sc.cmdsize = (size_of::<segment_command_x>() + nsects * size_of::<section_x>()) as u32;
                sc.nsects = nsects.narrow().unwrap();
            });
            if lci == usize::MAX {
                extra_segs.push(new_cmd);
            } else {
                existing_segs.insert(lci, new_cmd);
            }
        }
        (existing_segs, extra_segs)
    }

    pub fn parse_each_dyld_bind<'a>(&'a self, cb: &mut FnMut(&ParseDyldBindState<'a>) -> bool) {
        self.parse_dyld_bind(self.dyld_bind.get(), WhichBind::Bind, cb);
        self.parse_dyld_bind(self.dyld_weak_bind.get(), WhichBind::WeakBind, cb);
        self.parse_dyld_bind(self.dyld_lazy_bind.get(), WhichBind::LazyBind, cb);
    }

    fn parse_dyld_bind<'a>(&'a self, mut slice: &'a [u8], which: WhichBind, cb: &mut FnMut(&ParseDyldBindState<'a>) -> bool) {
        let pointer_size = self.eb.pointer_size as u64;
        let leb = |slice_: &mut &[u8], signed| -> Option<u64> {
            let mut it = ByteSliceIterator(slice_);
            exec::read_leb128_inner_noisy(&mut it, signed, "parse_dyld_bind")
        };
        macro_rules! leb { ($signed:expr) => {
            if let Some(num) = leb(&mut slice, $signed) { num } else { return }
        } }
        let advance = |state: &mut ParseDyldBindState, amount: u64| {
            if let Some(off) = state.seg_off {
                // This seems to be a bug in whatever is generating these files - we get 'negative'
                // values which are actually high ulebs, not real negative slebs
                let new = off.wrapping_add(amount);
                //println!("amount={:x} now={:x} name={:?}", amount, state.seg.unwrap().vmaddr.0.wrapping_add(new), state.symbol);
                if new > state.seg_size {
                    errln!("warning: parse_dyld_bind: going out of range of segment (off={:x}, size={:x}, adv={:x}), addr={}",
                           off, state.seg_size, amount, state.seg.unwrap().vmaddr);
                    state.seg_off = None;
                } else {
                    state.seg_off = Some(new);
                }
            }
        };
        let mut bind_advance = |state: &mut ParseDyldBindState<'a>, amount: u64| -> bool {
            if let Some(off) = state.seg_off {
                let bind_size = if state.typ == (BIND_TYPE_TEXT_ABSOLUTE32 as u8) ||
                                   state.typ == (BIND_TYPE_TEXT_PCREL32 as u8)
                                   { 4 } else { pointer_size as u64 };
                if state.seg_size - off < bind_size {
                    errln!("warning: parse_dyld_bind: bind reaches off end");
                    state.seg_off = None;
                }
            }
            if !cb(state) { return false; }
            state.already_bound_this_symbol = true;
            advance(state, amount);
            true
        };
        let mut state = ParseDyldBindState {
            source_dylib: SourceLib::None,
            seg: None,
            seg_idx: 0,
            seg_off: None,
            seg_size: 0,
            addend: 0,
            typ: if which == WhichBind::LazyBind { BIND_TYPE_POINTER as u8 } else { 0 },
            symbol: None,
            already_bound_this_symbol: false,
            which: which,
            flags: 0,
        };
        let set_dylib_ordinal = |state: &mut ParseDyldBindState, ord: u64| {
            let count = self.load_dylib.len().ext();
            state.source_dylib = if ord == 0 || ord > count {
                errln!("parse_dyld_bind: dylib ordinal out of range (ord={}, count={})", ord, count);
                SourceLib::None
            } else {
                SourceLib::Ordinal((ord - 1).narrow().unwrap())
            };
        };
        while !slice.is_empty() {
            let byte = slice[0];
            slice = &slice[1..];
            let immediate = byte & (BIND_IMMEDIATE_MASK as u8);
            let opcode = byte & (BIND_OPCODE_MASK as u8);
            match opcode as u32 {
                BIND_OPCODE_DONE => (),
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => set_dylib_ordinal(&mut state, immediate as u64),
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => set_dylib_ordinal(&mut state, leb!(false)),
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => state.source_dylib = match immediate {
                    0x0 => SourceLib::Self_,
                    0xf => SourceLib::MainExecutable,
                    0xe => SourceLib::Flat,
                    _ => {
                        errln!("warning: parse_dyld_bind: unknown special source dylib -{}", 0x10 - immediate);
                        SourceLib::None
                    },
                },
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    let name = some_or!(util::from_cstr_strict(slice), {
                        errln!("parse_dyld_bind: BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: bad string");
                        break;
                    });
                    state.symbol = Some(name);
                    state.already_bound_this_symbol = false;
                    slice = &slice[name.len()+1..];
                    state.flags = immediate.ext();
                },
                BIND_OPCODE_SET_TYPE_IMM => {
                    state.typ = immediate;
                    if immediate < 1 || immediate > 3 {
                        errln!("warning: parse_dyld_bind: unknown BIND_OPCODE_SET_TYPE_IMM type {}", immediate);
                    }
                },
                BIND_OPCODE_SET_ADDEND_SLEB => state.addend = leb!(true) as i64,
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    let offset = leb!(false);
                    let seg = some_or!(self.eb.segments.get(immediate as usize), {
                        errln!("parse_dyld_bind: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: bad segment index {}", immediate);
                        continue;
                    });
                    state.seg = Some(seg);
                    state.seg_idx = immediate.ext();
                    state.seg_off = Some(0);
                    state.seg_size = seg.vmsize;
                    advance(&mut state, offset);
                },
                BIND_OPCODE_ADD_ADDR_ULEB => advance(&mut state, leb!(false)),
                BIND_OPCODE_DO_BIND => if !bind_advance(&mut state, pointer_size) { return },
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    let add = leb!(false);
                    if !bind_advance(&mut state, add.wrapping_add(pointer_size)) /* ??? */ { return }
                },
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED =>
                    if !bind_advance(&mut state, (immediate as u64) * pointer_size + pointer_size) { return },
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = leb!(false);
                    let skip = leb!(false) + pointer_size;
                    for _ in 0..count {
                        if !bind_advance(&mut state, skip) { return }
                    }
                },
                _ => {
                    errln!("parse_dyld_bind: unknown bind opcode (byte=0x{:x})", byte);
                    break;
                }
            }
        }
    }
    fn parse_dyld_export<'a>(&'a self, dyld_export: &'a [u8], search_for: Option<&'a ByteStr>, cb: &mut for<'b> FnMut(&'b ParseDyldExportState<'b>) -> bool) {
        if dyld_export.is_empty() { return; }
        enum State<'x> {
            Search { search_for: &'x ByteStr, sf_offset: usize, offset: usize, count: usize },
            Exhaustive { seen: HashSet<usize, TrivialState>, todo: Vec<(usize, ByteString)> },
        }
        let mut state: State = if let Some(search_for) = search_for {
            State::Search { search_for: search_for, sf_offset: 0, offset: 0, count: 0 }
        } else {
            State::Exhaustive {
                seen: HashSet::with_hasher(TrivialState),
                todo: vec![(0usize, ByteString::from_str(""))],
            }
        };
        let base_addr = some_or!(self.dyld_base, {
            errln!("warning: parse_dyld_export: no load command segment, lol");
            return;
        });
        loop {
            let (offset, prefix): (usize, Cow<ByteStr>)
            = match state {
                State::Search { ref mut search_for, sf_offset, ref mut offset, count } => {
                    if *offset == !0 { break; }
                    if count > dyld_export.len() {
                        errln!("warning: parse_dyld_export: loop detected");
                        break;
                    }
                    let r = (*offset, (*search_for)[..sf_offset].into());
                    *offset = !0;
                    r
                },
                State::Exhaustive { seen: _, ref mut todo } => {
                    if let Some((offset, prefix)) = todo.pop() {
                        (offset, prefix.into())
                    } else { break }
                },
            };
            let mut slice = &dyld_export[offset..];
            let mut it = ByteSliceIterator(&mut slice);
            macro_rules! leb { ($it:expr) => {
                some_or!(exec::read_leb128_inner_noisy(&mut $it, false, "parse_dyld_export"),
                         continue)
            } }
            let terminal_size = leb!(it);
            if terminal_size > it.0.len() as u64 {
                errln!("warning: parse_dyld_export: terminal_size too big");
                continue;
            }
            let mut following = &it.0[terminal_size as usize..];
            *it.0 = &it.0[..terminal_size as usize];
            if !it.0.is_empty() && match state {
                State::Exhaustive { .. } => true,
                State::Search { search_for, sf_offset, .. } => sf_offset == search_for.len(),
            } {
                let flags = leb!(it);
                if flags > std::u32::MAX as u64 {
                    errln!("warning: parse_dyld_export: way too many flags");
                    continue;
                }
                let flags = flags as u32;
                let kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
                if kind == 3 {
                    errln!("warning: parse_dyld_export: unexpected symbol kind 3");
                }
                if flags > 0x1f {
                    errln!("warning: parse_dyld_export: unknown flags (flags=0x{:x})", flags);
                }
                let (reexport, addr) = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
                    let ord = leb!(it);
                    if ord == 0 || ord > self.load_dylib.len().ext() {
                        errln!("warning: parse_dyld_export: invalid reexport ordinal {} (count={})", ord, self.load_dylib.len());
                        continue;
                    }
                    let name;
                    if it.0.len() == 0 {
                        name = ByteStr::from_str("");
                    } else {
                        name = some_or!(util::from_cstr_strict(*it.0), {
                            errln!("warning: parse_dyld_export: invalid reexport name");
                            continue;
                        });
                        *it.0 = &it.0[name.len()+1..];
                    };
                    // export same?
                    let name = if name.len() == 0 { &prefix[..] } else { name };
                    (Some((ord - 1, name)), VMA(0))
                } else {
                    let read_addr = leb!(it);
                    //println!("{} {:x}", base_addr, read_addr);
                    let addr = (if kind == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE { VMA(0) } else { base_addr })
                               .wrapping_add(read_addr);
                    (None, addr)
                };
                let resolver = if reexport.is_none() && flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                    Some(base_addr + leb!(it))
                } else { None };
                if !cb(&ParseDyldExportState {
                    name: &prefix, addr: addr, flags: flags,
                    resolver: resolver, reexport: reexport, offset: offset,
                }) { return; }
                if !it.0.is_empty() {
                    errln!("warning: parse_dyld_export: excess terminal data");
                }
            }
            let mut it = ByteSliceIterator(&mut following);
            let edge_count = some_or!(it.next(), {
                errln!("warning: parse_dyld_export: ran into end before edge count");
                continue;
            });
            for _ in 0..edge_count {
                let this_prefix = some_or!(util::from_cstr_strict(*it.0), {
                    errln!("warning: parse_dyld_export: invalid prefix");
                    continue;
                });
                *it.0 = &it.0[this_prefix.len()+1..];
                let offset = leb!(it);
                if offset > dyld_export.len() as u64 {
                    errln!("warning: parse_dyld_export: invalid limb offset {}", offset);
                    continue;
                }
                let offset = offset as usize;
                match state {
                    State::Search { ref mut search_for, ref mut sf_offset, offset: ref mut offsetp, ref mut count } => {
                        // there can be multiple; need to pick the first that matches
                        if (&search_for[*sf_offset..]).starts_with(this_prefix) {
                            *sf_offset += this_prefix.len();
                            *offsetp = offset;
                            *count += 1;
                            break;
                        }
                    },
                    State::Exhaustive { ref mut seen, ref mut todo } => {
                        if !seen.insert(offset) {
                            errln!("warning: parse_dyld_export: offset {} already seen, whoa, might loop", offset);
                        } else {
                            todo.push((offset, prefix.clone().into_owned() + this_prefix));
                        }
                    },
                }
            }
        }
    }

    pub fn guess_broken_cache_slide(&self, dc: &DyldCache) -> GuessBrokenCacheSlideResult {
        let mut result = GuessBrokenCacheSlideResult::GotNoBindSelf;
        let dyld_export = self.dyld_export.get();
        self.parse_dyld_bind(self.dyld_lazy_bind.get(), WhichBind::LazyBind, &mut |bind_state: &ParseDyldBindState| {
            if bind_state.source_dylib == SourceLib::Self_ {
                let symbol = some_or!(bind_state.symbol.as_ref(), return true);
                let mut got_one = false;
                self.parse_dyld_export(dyld_export, Some(symbol), &mut |export_state: &ParseDyldExportState| -> bool {
                    debug_assert_eq!(&export_state.name, symbol);
                    let true_addr = export_state.addr;
                    let seg_data = some_or!(bind_state.seg, return true).get_data();
                    let seg_off = some_or!(bind_state.seg_off, return true) as usize;
                    let broken_addr = VMA(dc.eb.ptr_from_slice(
                        &seg_data[seg_off..seg_off + (dc.eb.pointer_size as usize)]));
                    let this_guess = match dc.slide_info {
                        None | Some(SlideInfo::V1(_)) => broken_addr.wrapping_sub(true_addr),
                        Some(SlideInfo::V2(ref v2)) => {
                            let delta_mask = v2.delta_mask;
                            if broken_addr.0.wrapping_add(v2.value_add) & !delta_mask == true_addr.0 & !delta_mask {
                                0
                            } else if broken_addr & !delta_mask == true_addr & !delta_mask {
                                result = GuessBrokenCacheSlideResult::BlownAway;
                                return false;
                            } else {
                                result = GuessBrokenCacheSlideResult::Inconsistent;
                                return false;
                            }
                        }
                    };
                    match result {
                        GuessBrokenCacheSlideResult::GotNoBindSelf => result = GuessBrokenCacheSlideResult::Guess(this_guess),
                        GuessBrokenCacheSlideResult::Guess(old_guess) => {
                            if this_guess != old_guess {
                                errln!("guess_broken_cache_slide: got inconsistent results:");
                                errln!("   old_guess={:x} this_guess={:x}", old_guess, this_guess);
                                result = GuessBrokenCacheSlideResult::Inconsistent;
                                return false;
                            }
                        },
                        _ => unreachable!(),
                    }
                    got_one = true;
                    true
                });
                if !got_one {
                    errln!("guess_broken_cache_slide: self-bind named '{}' not found in exports", symbol);
                }
            }
            true
        });
        result
    }
    pub fn get_exported_symbol_list(&self, search_for: Option<&ByteStr>) -> Vec<Symbol<'static>> {
        let mut out = Vec::new();
        self.parse_dyld_export(self.dyld_export.get(), search_for, &mut |state: &ParseDyldExportState| {
            out.push(Symbol {
                name: state.name.to_owned().into(),
                is_public: true,
                is_weak: state.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0,
                val: if let Some((ord, ref name)) = state.reexport {
                    let ord: u32 = ord.narrow().unwrap();
                    SymbolValue::ReExport((*name).to_owned().into(), SourceLib::Ordinal(ord))
                } else if let Some(resolver) = state.resolver {
                    SymbolValue::Resolver(resolver, Some(state.addr))
                } else { match state.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
                    EXPORT_SYMBOL_FLAGS_KIND_REGULAR | 3 => SymbolValue::Addr(state.addr),
                    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => SymbolValue::ThreadLocal(state.addr),
                    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => SymbolValue::Abs(state.addr),
                    _ => panic!("muri")
                } },
                size: None,
                private: state.offset,
            });
            true
        });
        out
    }
}

pub struct MachOProber;

impl exec::ExecProber for MachOProber {
    fn name(&self) -> &str {
        "macho"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, buf: Mem<u8>) -> Vec<exec::ProbeResult> {
        if let Ok(m) = MachO::new(buf, false, None) {
            vec!(exec::ProbeResult {
                desc: m.desc(),
                arch: m.eb.arch,
                likely: true,
                cmd: vec!["macho".to_string()],
            })
        } else {
            vec!()
        }
    }
   fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: Mem<u8>, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, "macho ...", 0, std::usize::MAX, &mut vec!(
            // ...
        ))));
        let mo: MachO = try!(MachO::new(buf, true, None));
        Ok((Box::new(mo) as Box<exec::Exec>, m.free))
    }
}

pub struct FatMachOProber;

impl FatMachOProber {
    fn probe_cb(&self, mc: &Mem<u8>, cb: &mut FnMut(u64, fat_arch)) -> bool {
        let buf = mc.get();
        if buf.len() < 8 { return false }
        let fh: fat_header = util::copy_from_slice(&buf[..8], util::BigEndian);
        if fh.magic != FAT_MAGIC as u32 { return false }
        let nfat = fh.nfat_arch as u64;
        let mut off: usize = 8;
        if (buf.len() as u64) < (off as u64) + (nfat * size_of::<fat_arch>() as u64) {
            errln!("fatmacho: no room for {} fat archs", nfat);
            return false;
        }
        for i in 0..nfat {
            let fa: fat_arch = util::copy_from_slice(&buf[off..off + size_of::<fat_arch>()], util::BigEndian);
            if (fa.offset as u64) + (fa.size as u64) > (buf.len() as u64) {
                errln!("fatmacho: bad arch cputype={},{} offset={} size={} (truncated?)",
                       fa.cputype, fa.cpusubtype, fa.offset, fa.size);
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
    fn probe(&self, eps: &Vec<exec::ExecProberRef>, mc: Mem<u8>) -> Vec<exec::ProbeResult> {
        let mut result = Vec::new();
        let ok = self.probe_cb(&mc, &mut |i, fa| {
            let arch = match mach_arch_desc(fa.cputype, fa.cpusubtype) {
                Some(desc) => desc.to_string(),
                None => format!("{}", i),
            };
            let off = fa.offset as usize;
            let size = fa.size as usize;
            for pr in exec::probe_all(eps, mc.slice(off, off + size).unwrap()).into_iter() {
                let npr = exec::ProbeResult {
                    desc: format!("(slice #{}) {}", i, pr.desc),
                    arch: pr.arch,
                    likely: pr.likely,
                    cmd: { let mut s = vec!("fat", "--arch", &*arch).strings(); s.extend_from_slice(&*pr.cmd); s },
                };
                result.push(npr);
            }
        });
        if !ok { return vec!()}
        result
    }

    fn create(&self, eps: &Vec<exec::ExecProberRef>, mc: Mem<u8>, args: Vec<String>) -> exec::ExecResult<(Box<exec::Exec>, Vec<String>)> {
        let top = "fat (--arch ARCH | -s SLICE)";
        let mut optgrps = vec!(
            getopts::optopt("", "arch", "choose by arch (OS X standard names)", "arch"),
            getopts::optopt("s", "slice", "choose by slice number", ""),
        );
        let mut m = try!(exec::usage_to_invalid_args(util::do_getopts_or_usage(&*args, top, 0, std::usize::MAX, &mut optgrps)));
        let slice_num = m.opt_str("slice");
        let arch = m.opt_str("arch");
        if slice_num.is_some() == arch.is_some() {
            return exec::usage_to_invalid_args(Err(util::usage(top, &mut optgrps)));
        }
        let slice_i = slice_num.map_or(0u64, |s| FromStr::from_str(&*s).unwrap());
        let mut result = None;
        let ok = self.probe_cb(&mc, &mut |i, fa| {
            if if let (&None, &Some(ref arch_)) = (&result, &arch) {
                mach_arch_desc(fa.cputype, fa.cpusubtype).map_or(false, |d| d == &**arch_)
            } else {
                i == slice_i
            }
            {
                let off = fa.offset as usize;
                let size = fa.size as usize;
                result = Some(exec::create(eps, mc.slice(off, off + size).unwrap(), replace(&mut m.free, vec!())));
            }
        });
        if !ok {
            return err(ErrorKind::BadData, "invalid fat mach-o");
        }
        match result {
            Some(e) => e,
            None => err(ErrorKind::Other, "no fat arch matched the arguments specified")
        }
    }
}
