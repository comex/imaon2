#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(improper_ctypes)] // bug?
#[macro_use]
extern crate macros;
extern crate util;
use util::Swap;

impl Swap for lc_str {
    fn bswap(&mut self) { unsafe { self.offset.bswap(); } }
}
impl Swap for nlist__bindgen_ty_1 {
    fn bswap(&mut self) { unsafe { self.n_strx.bswap(); } }
}
impl Swap for nlist_64__bindgen_ty_1 {
    fn bswap(&mut self) { unsafe { self.n_strx.bswap(); } }
}
impl Swap for __BindgenBitfieldUnit<[u8; 4], u32> {
    fn bswap(&mut self) {
        unsafe { (*(self as *mut _ as *mut u32)).bswap(); }
    }

}

include!(concat!(env!("OUT_DIR"), "/out.rs"));

