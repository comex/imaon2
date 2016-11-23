extern crate build_run_gen;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ctx {
    is_tail: bool,
    have_target_addr: bool,
    target_addr_is_data: bool,
    base_addr: u64,
    target_addr: u64,
}

pub type JumpDisFn = unsafe extern "C" fn(ctx: &mut Ctx, op: u32);
macro_rules! variant { ($name:ident) => {
    extern "C" {
        pub fn $name(ctx: &mut Ctx, op: u32);
    }
} }
variant!(jump_dis_AArch64);


