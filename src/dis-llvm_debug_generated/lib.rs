extern crate build_run_gen;
pub type Callback<'a> = &'a mut FnMut(&'static str, &[Operand]);
pub struct Operand(pub &'static str, pub u32);

#[allow(unused_variables)]
#[allow(non_snake_case)]
pub mod d {
    pub mod arm {
        include!(concat!(env!("OUT_DIR"), "/dd/debug-dis-ARM.rs"));
    }
    pub mod thumb {
        include!(concat!(env!("OUT_DIR"), "/dd/debug-dis-ARM.rs"));
    }
    pub mod thumb2 {
        include!(concat!(env!("OUT_DIR"), "/dd/debug-dis-Thumb2.rs"));
    }
}
