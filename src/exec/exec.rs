#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate macros;
extern crate util;
extern crate bsdlike_getopts as getopts;
use arch::Arch;
use std::borrow::Cow;
use std::vec::Vec;
use std::fmt;
use std::mem::{replace, transmute, swap};
use std::str::FromStr;
use std::cmp::min;
use std::any::Any;
use std::cell::Cell;
use std::hash::{Hash, Hasher};
use util::{ByteString, ByteStr, Mem, ReadCell, Narrow, CheckAdd, CheckSub, Signedness, Endian, SignExtend, Signed, slice_find_byte};

pub mod arch;
mod reloc;
pub use reloc::{RelocKind, RelocContext};

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidArgs,
    BadData,
    Other
}

#[derive(Clone, Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: Cow<'static, str>,
}
display_as_debug!(Error);

impl std::error::Error for Error {
    fn description(&self) -> &str { &*self.message }
}

pub type ExecResult<T> = Result<T, Box<Error>>;
pub fn err<T, S: Into<Cow<'static, str>>>(kind: ErrorKind, s: S) -> ExecResult<T> {
    Err(Box::new(Error { kind: kind, message: s.into() }))
}
pub fn err_only<S: Into<Cow<'static, str>>>(kind: ErrorKind, s: S) -> Box<Error> {
    Box::new(Error { kind: kind, message: s.into() })
}

pub fn usage_to_invalid_args<T>(o: Result<T, String>) -> ExecResult<T> {
    o.map_err(|msg| Box::new(Error { kind: ErrorKind::InvalidArgs, message: msg.into() }))
}

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VMA(pub u64);

impl fmt::Debug for VMA {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.pad(&format!("0x{:x}", self.0))
    }
}
display_as_debug!(VMA);

delegate_arith!(VMA, Sub, sub, u64);
delegate_arith!(VMA, Add, add, u64);
delegate_arith!(VMA, BitOr, bitor, u64);
delegate_arith!(VMA, BitAnd, bitand, u64);

impl VMA {
    #[inline]
    pub fn offset_from(self, other: VMA) -> Option<u64> {
        if self.0 >= other.0 { Some(self.0 - other.0) } else { None }
    }
    #[inline]
    pub fn full_range_midpoint() -> VMA {
        VMA(1u64 << 63)
    }
    #[inline]
    pub fn midpoint(VMA(lo): VMA, VMA(hi): VMA) -> VMA {
        assert!(lo <= hi);
        VMA(lo + (hi - lo) / 2)
    }
    #[inline]
    pub fn wrapping_add(self, addend: u64) -> VMA {
        VMA(self.0.wrapping_add(addend))
    }
    #[inline]
    pub fn wrapping_sub(self, other: VMA) -> u64 {
        self.0.wrapping_sub(other.0)
    }
    #[inline]
    pub fn saturating_add(self, addend: u64) -> VMA {
        VMA(self.0.saturating_add(addend))
    }
    #[inline]
    pub fn trunc32(self) -> VMA {
        VMA(self.0 & 0xffffffff)
    }
    #[inline]
    pub fn align_down_to(self, size: u64) -> VMA {
        let mask = size - 1;
        self & !mask
    }
    #[inline]
    pub fn align_up_to(self, size: u64) -> VMA {
        let mask = size - 1;
        (self + mask) & !mask
    }
    #[inline]
    pub fn wrapping_align_up_to(self, size: u64) -> VMA {
        let mask = size - 1;
        self.wrapping_add(mask) & !mask
    }
}
// TODO - should this be signed or something?
impl std::ops::Sub<VMA> for VMA {
    type Output = u64;
    #[inline]
    fn sub(self, VMA(rhs): VMA) -> u64 {
        let lhs = self.0;
        lhs - rhs
    }
}
impl util::CheckAdd<u64, VMA> for VMA {
    type Output = VMA;
    #[inline]
    fn check_add(self, other: u64) -> Option<Self::Output> {
        self.0.checked_add(other).map(VMA)
    }
}
impl util::CheckSub<u64, VMA> for VMA {
    type Output = VMA;
    #[inline]
    fn check_sub(self, other: u64) -> Option<Self::Output> {
        self.0.checked_sub(other).map(VMA)
    }
}
impl util::CheckSub<VMA, VMA> for VMA {
    type Output = u64;
    #[inline]
    fn check_sub(self, other: VMA) -> Option<Self::Output> {
        if self >= other {
            Some(self - other)
        } else {
            None
        }
    }

}
impl_check_x_option!(CheckAdd, check_add, VMA, u64);
impl_check_x_option!(CheckSub, check_sub, VMA, u64);
impl_check_x_option!(CheckSub, check_sub, VMA, VMA);

impl Hash for VMA {
    fn hash<H>(&self, state: &mut H) where H: Hasher { self.0.hash(state) }
    fn hash_slice<H>(data: &[Self], state: &mut H) where H: Hasher {
        let data: &[u64] = unsafe { transmute(data) };
        u64::hash_slice(data, state)
    }
}

pub fn dynsized_integer_from_slice<S: ?Sized + util::ROSlicePtr<u8>>(slice: &S, signedness: Signedness, endian: Endian) -> u64 {
    let unextended: u64 = match slice.len() {
        1 => { let q: u8 = util::copy_from_slice(slice, endian); q as u64 },
        2 => { let q: u16 = util::copy_from_slice(slice, endian); q as u64 },
        4 => { let q: u32 = util::copy_from_slice(slice, endian); q as u64 },
        8 => { let q: u64 = util::copy_from_slice(slice, endian); q as u64 },
        _ => panic!("dynsized_integer_from_slice: bad slice len"),
    };
    if signedness == Signed {
        unextended.sign_extend((slice.len() * 8) as u8)
    } else {
        unextended
    }
}


#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl fmt::Display for Prot {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}{}{}",
            if self.r { 'r' } else { '-' },
            if self.w { 'w' } else { '-' },
            if self.x { 'x' } else { '-' })
    }
}

pub static prot_all : Prot = Prot { r: true, w: true, x: true };

// This struct is used for both segments and sections, because the file
// formats often have redundant fields.  (e.g. ELF sections have protection
// and alignment, Mach-O segments have names)

#[derive(Default, Debug, Clone)]
pub struct Segment {
    pub vmaddr: VMA,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub name: Option<ByteString>,
    pub prot: Prot,
    pub data: Option<util::Mem<u8>>,
    pub seg_idx: Option<usize>, // for sections, which seg it belongs to
    pub private: usize,
}

impl Segment {
    pub fn pretty_name<'a>(&'a self) -> Cow<'a, str> {
        self.name.as_ref().map_or("<unnamed>".into(), |a| a.lossy())
    }
    pub fn get_data(&self) -> &[ReadCell<u8>] {
        self.data.as_ref().unwrap().get()
    }
    pub fn steal_data(&mut self) -> Mem<u8> {
        replace(&mut self.data, None).unwrap()
    }
}

#[derive(Default, Clone)]
pub struct ExecBase {
    pub arch: Arch,
    pub pointer_size: usize,
    pub endian: util::Endian,
    pub segments: Vec<Segment>,
    pub sections: Vec<Segment>,
    pub whole_buf: Option<Mem<u8>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SymbolValue<'a> {
    Addr(VMA),
    Abs(VMA),
    ThreadLocal(VMA),
    Undefined(SourceLib),
    Resolver(VMA, /* stub */ Option<VMA>),
    ReExport(Cow<'a, ByteStr>, SourceLib),
}

impl<'a> SymbolValue<'a> {
    pub fn some_vma(&self) -> Option<VMA> {
        match self {
            &SymbolValue::Addr(vma) |
            &SymbolValue::Abs(vma) |
            &SymbolValue::ThreadLocal(vma) |
            &SymbolValue::Resolver(vma, _) => Some(vma),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SourceLib {
    None,
    Ordinal(u32), // starting from 0
    Self_,
    MainExecutable,
    Flat,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: Cow<'a, ByteStr>,
    pub is_public: bool,
    pub is_weak: bool,
    pub val: SymbolValue<'a>,
    pub size: Option<u64>,
    pub private: usize,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SymbolSource {
    All,
    Imported,
    Exported,
}


#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Reloc<'a> {
    pub address: VMA,
    pub kind: RelocKind,
    pub base: Option<VMA>, // None if 'rel'
    pub target: RelocTarget<'a>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RelocTarget<'a> {
    ThisImageSlide,
    ThisSegmentSlide,
    Import(&'a Symbol<'a>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DepLib<'a> {
    pub path: Cow<'a, ByteStr>,
    pub private: usize,
}

pub trait Exec : 'static {
    fn get_exec_base(&self) -> &ExecBase;

    // Todo: add a monomorphizable iterator version of this
    fn get_symbol_list(&self, _source: SymbolSource, specific: Option<&Any>) -> Vec<Symbol> {
        assert!(specific.is_none());
        vec!()
    }

    fn lookup_export(&self, _name: &ByteStr, specific: Option<&Any>) -> Vec<Symbol> {
        assert!(specific.is_none());
        vec!()
    }

    fn get_reloc_list<'a>(&'a self, specific: Option<&'a Any>) -> Vec<Reloc<'a>> {
        assert!(specific.is_none());
        vec!()
    }

    fn get_dep_libs(&self) -> Cow<[DepLib]> {
        static NONE: [DepLib<'static>; 0] = [];
        (&NONE as &[DepLib]).into()
    }
    fn describe_dep_lib(&self, _dl: &DepLib) -> String {
        panic!("describe_dep_lib must be implemented if get_dep_libs is")
    }

    fn as_any(&self) -> &std::any::Any;// { self as &std::any::Any }
    #[allow(mutable_transmutes)]
    fn as_any_mut(&mut self) -> &mut std::any::Any { unsafe { transmute(self.as_any()) } }
}

// Prober:

pub trait ExecProber {
    fn name(&self) -> &str;
    fn probe(&self, eps: &Vec<ExecProberRef>, buf: Mem<u8>) -> Vec<ProbeResult>;
    // May fail.
    fn create(&self, eps: &Vec<ExecProberRef>, buf: Mem<u8>, args: Vec<String>) -> ExecResult<(Box<Exec>, Vec<String>)>;
}

pub type ExecProberRef = &'static (ExecProber+'static);

pub struct ProbeResult {
    pub desc: String,
    pub arch: Arch,
    pub likely: bool,
    pub cmd: Vec<String>,
}

pub fn probe_all(eps: &Vec<ExecProberRef>, buf: Mem<u8>) -> Vec<ProbeResult> {
    let mut result = vec!();
    for epp in eps.iter() {
        result.extend(epp.probe(eps, buf.clone()).into_iter());
    }
    result
}

pub fn create(eps: &Vec<ExecProberRef>, buf: Mem<u8>, mut args: Vec<String>) -> ExecResult<(Box<Exec+'static>, Vec<String>)> {
    if args.len() == 0 {
        return err(ErrorKind::InvalidArgs, "empty argument list passed to exec::create");
    }
    let prober_name = args.remove(0);
    if prober_name == "auto" {
        return create_auto(eps, buf, args);
    }
    for epp in eps.iter() {
        if epp.name() == prober_name {
            return epp.create(eps, buf, args);
        }
    }
    err(ErrorKind::InvalidArgs, format!("no format named {}", prober_name))
}

fn create_auto(eps: &Vec<ExecProberRef>, buf: Mem<u8>, args: Vec<String>) -> ExecResult<(Box<Exec+'static>, Vec<String>)> {
    // TODO: error conversion
    let m = try!(usage_to_invalid_args(util::do_getopts_or_usage(&*args, "auto [--arch arch]", 0, std::usize::MAX, &mut vec![
        getopts::optopt("", "arch", "Architecture bias", "arch"),
    ])));
    let mut results = probe_all(eps, buf.clone());
    if let Some(arch_str) = m.opt_str("arch") {
        let arch: Arch = FromStr::from_str(&*arch_str).unwrap();
        for pr in results.iter_mut() {
            if pr.likely && pr.arch == arch {
                return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
            }
        }
    }
    for pr in results.iter_mut() {
        if pr.likely {
            return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
        }
    }
    for pr in results.iter_mut() {
        return Ok((try!(create(eps, buf, replace(&mut pr.cmd, vec!()))).0, m.free))
    }
    panic!("create_auto: no formats, not even raw_binary??");

}

pub fn addr_to_off(segs: &[Segment], addr: VMA, len: u64) -> Option<u64> {
    for seg in segs {
        if addr >= seg.vmaddr && addr - seg.vmaddr < seg.vmsize && seg.vmsize - (addr - seg.vmaddr) >= len {
            return Some(seg.fileoff + (addr - seg.vmaddr));
        }
    }
    None
}

pub fn off_to_addr(segs: &[Segment], off: u64, len: u64) -> Option<VMA> {
    for seg in segs {
        if off >= seg.fileoff && off - seg.fileoff < seg.filesize && seg.filesize - (off - seg.fileoff) >= len {
            return Some(seg.vmaddr + (off - seg.fileoff));
        }
    }
    None
}

pub fn addr_to_seg_off_range(segs: &[Segment], addr: VMA) -> Option<(&Segment, u64, u64)> {
    for seg in segs {
        if addr >= seg.vmaddr && addr - seg.vmaddr < seg.vmsize {
            return Some((seg, addr - seg.vmaddr, seg.vmsize - (addr - seg.vmaddr)));
        }
    }
    None
}

pub trait ReadVMA {
    fn read<'a>(&'a self, addr: VMA, size: u64) -> Mem<u8>;
}

impl ReadVMA for ExecBase {
    fn read<'a>(&'a self, addr: VMA, mut size: u64) -> Mem<u8> {
        let (seg, off, avail) = some_or!(addr_to_seg_off_range(&self.segments, addr),
            { return Mem::<u8>::empty() });
        if size <= avail {
            let data = some_or!(seg.data.as_ref(), { return Mem::<u8>::empty() });
            if off > std::usize::MAX as u64 { return Mem::<u8>::empty(); }
            return data.slice(off as usize, min(off + size, data.len() as u64) as usize).unwrap();
        }
        let mut res = Vec::new();
        while size > 0 {
            let (seg, off, avail) = some_or!(addr_to_seg_off_range(&self.segments, addr),
                { break });
            if off > std::usize::MAX as u64 { break; }
            let data = some_or!(seg.data.as_ref(), { return Mem::<u8>::empty() });
            let data = data.get();
            let desired = min(avail, size);
            let end = min(off + desired, data.len() as u64);
            let sl = &data[off as usize..end as usize];
            res.extend_from_slice(sl);
            if sl.len() as u64 != desired { break; }
            size -= desired;
        }
        Mem::<u8>::with_data(&res[..]) // xxx
    }
}

pub fn read_leb128_inner<It: Iterator<Item=u8>>(it: &mut It, signed: bool) -> Option<(u64, bool /* overflow */ )> {
    let mut shift = 0;
    let mut result: u64 = 0;
    let mut overflow = false;
    loop {
        let byte = some_or!(it.next(), { return None; });
        let (k, cont) = (byte & 0x7f, byte & 0x80 != 0);
        if shift < 63 {
            result |= (k as u64) << shift;
            shift += 7;
        } else if shift == 63 {
            result |= ((k & 1) as u64) << shift;
            if cont || (k > 1 && (!signed || k < 0x7f)) { overflow = true; }
            shift = 64;
        }
        if !cont {
            if signed && byte & 0x40 != 0 && shift != 64 {
                result |= !0u64 << shift;
            }
            return Some((result, overflow));
        }
    }
}

#[inline]
pub fn read_leb128_inner_noisy<It: Iterator<Item=u8>>(it: &mut It, signed: bool, func_name: &str) -> Option<u64> {
    if let Some((num, ovf)) = read_leb128_inner(it, signed) {
        if ovf {
            errln!("warning: {}: {}leb128 too big, continuing with truncated value", func_name, if signed { 's' } else { 'u' });
        }
        Some(num)
    } else {
        errln!("{}: {}leb128 runs off end", func_name, if signed { 's' } else { 'u' });
        None
    }
}

pub struct UlebWriter<'a> {
    pub out: &'a mut Vec<u8>
}

impl<'a> UlebWriter<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self { UlebWriter { out: out } }
    #[inline]
    pub fn write_u8(&mut self, byte: u8) {
        self.out.push(byte);
    }
    pub fn write_uleb(&mut self, mut val: u64) {
        loop {
            let cont = val >= 0x80;
            self.write_u8((val & 0x7f) as u8 | if cont { 0x80 } else { 0 });
            if !cont { break; }
            val >>= 7;
        }
    }
    // add sleb if necessary
}

pub struct ByteSliceIterator<'a, 'b: 'a>(pub &'a mut &'b [ReadCell<u8>]);
impl<'a, 'b> Iterator for ByteSliceIterator<'a, 'b> {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> {
        if self.0.is_empty() {
            None
        } else {
            let res = self.0[0].get();
            *self.0 = &(*self.0)[1..];
            Some(res)
        }
    }
}

impl ExecBase {
    // exact size, in one segment
    pub fn get_sane(&self, addr: VMA, size: u64) -> Option<&[Cell<u8>]> {
        let (seg, off, avail) =
            some_or!(addr_to_seg_off_range(&self.segments, addr),
                     { return None; });
        if size > avail { return None; }
        let data = some_or!(seg.data.as_ref(), { return None; });
        Some(&data.get_mut()[off as usize .. min(off + size, data.len() as u64) as usize])
    }
    pub fn ptr_from_slice<S: ?Sized + util::ROSlicePtr<u8>>(&self, slice: &S) -> u64 {
        match self.pointer_size {
            8 => util::copy_from_slice::<u64, _>(slice, self.endian),
            4 => util::copy_from_slice::<u32, _>(slice, self.endian) as u64,
            _ => panic!("pointer_size")
        }
    }
    pub fn ptr_to_slice<'a, S: util::RWSlicePtr<'a, u8>>(&'a self, slice: S, ptr: u64) {
        match self.pointer_size {
            8 => util::copy_to_slice::<'a, u64, _>(slice, &ptr, self.endian),
            4 => util::copy_to_slice::<'a, u32, _>(slice, &ptr.narrow().unwrap(), self.endian),
            _ => panic!("pointer_size")
        }
    }
    pub fn read_cstr_sane(&self, addr: VMA) -> Option<&ByteStr> {
        let (seg, off, _) =
            some_or!(addr_to_seg_off_range(&self.segments, addr),
                     { return None; });
        let data = some_or!(seg.data.as_ref(), { return None; });
        let data = &data.get()[off as usize..];
        util::from_cstr_strict(data)
    }
}

pub fn read_cstr<'a>(reader: &ReadVMA, offset: VMA) -> Option<ByteString> {
    let mut size = 32;
    loop {
        let res = reader.read(offset, size);
        let res = res.get();
        if let Some(o) = slice_find_byte(res, b'\0') {
            return Some(ByteString::from_bytes(&res[..o]));
        }
        if (res.len() as u64) < size { return None; }
        size *= 2;
    }
}

pub struct SegmentWriter {
    contents: Vec<(VMA, u64, SWContents)>,
}
enum SWContents {
    RO(Mem<u8>),
    RW(Vec<Cell<u8>>),
    Fail,
}
#[derive(Debug)]
pub enum SWGetSaneError {
    NotWritable,
    Unmapped,
}

impl SegmentWriter {
    pub fn new(segs: &mut [Segment]) -> Self {
        SegmentWriter {
            contents: segs.iter_mut()
                .map(|seg| (seg.vmaddr, seg.filesize,
                            SWContents::RO(seg.steal_data())))
                .collect(),
        }
    }
    pub fn access_ro(&self, idx: usize) -> &[ReadCell<u8>] {
        match &self.contents[idx].2 {
            &SWContents::RO(ref mcref) => unsafe { transmute(mcref.get()) },
            &SWContents::RW(ref vec) => unsafe { transmute(&vec[..]) },
            &SWContents::Fail => panic!(),
        }
    }
    pub fn access_rw(&self, idx: usize) -> Option<&[Cell<u8>]> {
        match &self.contents[idx].2 {
            &SWContents::RO(_) => None,
            &SWContents::RW(ref vec) => Some(&vec[..]),
            &SWContents::Fail => panic!(),
        }
    }
    pub fn make_seg_rw(&mut self, idx: usize) {
        let cp = &mut self.contents[idx].2;
        match replace(cp, SWContents::Fail) {
            SWContents::RO(mcref) => {
                let orig: Vec<u8> = mcref.into_vec();
                let rw: Vec<Cell<u8>> = unsafe { transmute(orig) };
                *cp = SWContents::RW(rw);
            },
            SWContents::RW(vec) => *cp = SWContents::RW(vec),
            _ => panic!(),
        }
    }
    pub fn get_sane_ro(&self, addr: VMA, size: u64) -> Option<&[ReadCell<u8>]> {
        if size == 0 { return Some(util::empty_slice()) }
        let end = addr + size;
        for &(seg_addr, seg_size, ref data) in &self.contents {
            let offset = addr.wrapping_sub(seg_addr);
            if offset <= seg_size &&
               size >= end - addr {
                let base: &[ReadCell<u8>] = match data {
                    &SWContents::RO(ref mcref) => unsafe { transmute(mcref.get()) },
                    &SWContents::RW(ref vec) => unsafe { transmute(&vec[..]) },
                    &SWContents::Fail => panic!(),
                };
                return Some(&base[offset as usize..(offset+size) as usize]);
            }
        }
        None
    }
    pub fn get_sane_rw(&self, addr: VMA, size: u64) -> Result<&[Cell<u8>], SWGetSaneError> {
        if size == 0 { return Ok(util::empty_slice()) }
        let end = addr + size;
        for &(seg_addr, seg_size, ref data) in &self.contents {
            let offset = addr.wrapping_sub(seg_addr);
            if offset <= seg_size &&
               size >= end - addr {
                let base: &[Cell<u8>] = match data {
                    &SWContents::RO(_) => return Err(SWGetSaneError::NotWritable),
                    &SWContents::RW(ref vec) => unsafe { transmute(&vec[..]) },
                    &SWContents::Fail => panic!(),
                };
                return Ok(&base[offset as usize..(offset+size) as usize]);
            }
        }
        Err(SWGetSaneError::Unmapped)
    }
    pub fn finish(mut self, segs: &mut [Segment]) {
        assert_eq!(segs.len(), self.contents.len());
        for (segp, (_, _, ovec)) in segs.iter_mut().zip(self.contents.drain(..)) {
            segp.data = Some(match ovec {
                SWContents::RO(mcref) => mcref,
                SWContents::RW(vec) => {
                    let orig: Vec<u8> = unsafe { transmute(vec) };
                    Mem::<u8>::with_vec(orig)
                },
                SWContents::Fail => panic!(),
            });
        }
    }
}
impl Drop for SegmentWriter {
    fn drop(&mut self) {
        if self.contents.len() != 0 {
            panic!("SegmentWriter should be finish()d");
        }
    }
}

pub fn intersect_start_size(mut a: (VMA, u64), mut b: (VMA, u64)) -> (VMA, u64) {
    if a.0 > b.0 {
        swap(&mut a, &mut b);
    }
    if let Some(diff) = b.0.check_sub(a.0) {
        a.1 = a.1.saturating_sub(diff);
        //a.0 = b.0;
    }
    (b.0, min(a.1, b.1))
}
/*
pub fn align_start_size(a: (VMA, u64), align: u64) -> (VMA, u64) {
    let start = a.align_down_to(align);
    let end = a.0.wrapping_add(a.1).wrapping_align_up_to(align);
    (start, end.wrapping_sub(start))
}
*/
