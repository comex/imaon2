fn unreachable() { unreachable!() }
pub fn foo(op: u32) {
    include!("../out-common/jump-dis-arm.inc.rs");
}
