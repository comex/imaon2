#![allow(improper_ctypes)]
extern crate build_run_gen;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Operand {
    pub name: &'static str,
    pub val: u32,
}
pub const MAX_OPS: usize = 8;

pub type DebugDisFn = unsafe extern "C" fn(op: u32, name: &mut &'static str, ops: &mut [Operand; MAX_OPS]);
macro_rules! variant { ($name:ident) => {
    extern "C" {
        pub fn $name(op: u32, name: &mut &'static str, ops: &mut [Operand; MAX_OPS]);
    }
} }
variant!(debug_dis_ARM);
variant!(debug_dis_Thumb);
variant!(debug_dis_Thumb2);
variant!(debug_dis_AArch64);
