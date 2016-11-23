extern crate build_run_gen;
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct JumpDisCtx {
    pub is_unidentified: bool,
    pub is_tail: bool,
    pub have_target_addr: bool,
    pub target_addr_is_data: bool,
    pub base_addr: u64,
    pub target_addr: u64,
}

pub type JumpDisFn = unsafe extern "C" fn(ctx: &mut JumpDisCtx, op: u32);
macro_rules! variant { ($name:ident) => {
    extern "C" {
        pub fn $name(ctx: &mut JumpDisCtx, op: u32);
    }
} }
variant!(jump_dis_AArch64);


