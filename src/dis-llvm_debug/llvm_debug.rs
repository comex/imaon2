#![allow(non_snake_case)]

extern crate dis;
extern crate exec;
extern crate util;

use std::mem::transmute;
use std::ffi::CStr;
use std::os::raw::c_char;

use exec::arch::{ArchAndOptions, ARMMode};
use dis::{Disassembler, DisassemblerStatics, DisassemblerInput};
use util::{Endian, copy_from_slice};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
struct struct_operand { name: *const c_char, val: u32 }

#[allow(non_camel_case_types)]
type cb_t = extern "C" fn(*const u8, *const c_char, *const struct_operand, u32);

extern "C" fn cb_wrapper<F: FnMut(*const c_char, *const struct_operand, u32)>
    (ctx: *const u8, name: *const c_char, ops: *const struct_operand, op_count: u32) {
    let f: *mut F = unsafe { transmute(ctx) };
    unsafe { (*f)(name, ops, op_count); }
}
fn wrap_call<F: FnMut(*const c_char, *const struct_operand, u32)>
    (func: unsafe extern "C" fn(u32, cb_t, *const u8), op: u32, f: &mut F) {
    let ctx: *const u8 = unsafe { transmute(f) };
    unsafe { func(op, cb_wrapper::<F>, ctx); }
}

#[link(name = "llvm-debug-dis-c")]
extern {
    fn decode_arm(op: u32, cb: cb_t, ctx: *const u8);
    fn decode_thumb(op: u32, cb: cb_t, ctx: *const u8);
    fn decode_thumb2(op: u32, cb: cb_t, ctx: *const u8);
}

pub struct LLVMDebugDisassembler { arch: ArchAndOptions }

impl Disassembler for LLVMDebugDisassembler {
    fn arch(&self) -> &ArchAndOptions { &self.arch }
    fn can_disassemble_to_str(&self) -> bool { true }
    fn disassemble_insn_to_str(&self, input: DisassemblerInput) -> Option<(Option<String>, u32)> {
        match (self.arch, input.mode) {
            (ArchAndOptions::ARM(opts), ARMMode { thumb }) => go_arm(input, thumb, opts.endian),
            _ => panic!("unsupported arch"),
        }
    }

}

impl dis::DisassemblerStatics for LLVMDebugDisassembler {
    fn new_with_args(arch: ArchAndOptions, args: &[String]) -> Result<Self, dis::CreateDisError> {
        if args.len() > 0 {
            return Err(dis::CreateDisError::InvalidArgs("llvm-debug: no supported args".to_owned()));
        }

        Ok(LLVMDebugDisassembler { arch: arch })
    }
    fn name() -> &'static str { "llvm-debug" }
}

fn go_arm(input: DisassemblerInput, thumb: bool, endian: Endian) -> Option<(Option<String>, u32)> {
    let mut res: String = String::new();
    let len = {
        let mut cb = |name: *const c_char, ops: *const struct_operand, op_count: u32| {
            unsafe {
                res.push_str(&CStr::from_ptr(name).to_string_lossy());
                for i in 0..op_count {
                    let op = *ops.offset(i as isize);
                    res.push_str(&format!(" {}=0x{:x}", CStr::from_ptr(op.name).to_string_lossy(), op.val));
                }
            }
        };
        if thumb {
            if input.data.len() < 2 { return None; }
            let x: u16 = copy_from_slice(&input.data[..2], endian);
            let is32 =  (x >> 13 & 7) == 7 && (x >> 11 & 3) != 0;
            if is32 {
                if input.data.len() < 4 { return None; }
                let y: u32 = copy_from_slice(&input.data[..4], endian);
                wrap_call(decode_thumb2, y, &mut cb);
                4
            } else {
                wrap_call(decode_thumb, x as u32, &mut cb);
                2
            }
        } else {
            if input.data.len() < 4 { return None; }
            let x: u32 = copy_from_slice(&input.data[..4], endian);
            wrap_call(decode_arm, x, &mut cb);
            4
        }
    };
    Some((Some(res), len))
}
