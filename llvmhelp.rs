// imaon2 note: Adapted from rustc's middle/trans/{builder,common,type_}.rs (presently from revision 871e5708106c5ee3ad8d2bd6ec68fca60428b77e).

// Copyright 2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate rustc;
extern crate collections;


use rustc::lib;
use rustc::lib::llvm::llvm;
use rustc::lib::llvm::{CallConv, AtomicBinOp, AtomicOrdering, AsmDialect};
use rustc::lib::llvm::{ContextRef, ValueRef, BasicBlockRef, BuilderRef, ModuleRef, TypeRef};
use rustc::lib::llvm::{Opcode, IntPredicate, RealPredicate, True, False, Bool, TypeKind};

use std::libc::{c_uint, c_longlong, c_ulonglong, c_char};
use std::vec_ng::Vec;

trait ValueTr {
    fn ty(self) -> TypeRef;
}

impl ValueTr for ValueRef {
    fn ty(self) -> TypeRef {
        unsafe {
            llvm::LLVMTypeOf(self)
        }
    }
}

// TODO: UFCS would allow this to be bundled into the trait
pub struct Type;
impl Type {
    pub fn void(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMVoidTypeInContext(ctx) }
    }

    pub fn metadata(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMMetadataTypeInContext(ctx) }
    }

    pub fn i1(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMInt1TypeInContext(ctx) }
    }

    pub fn i8(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMInt8TypeInContext(ctx) }
    }

    pub fn i16(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMInt16TypeInContext(ctx) }
    }

    pub fn i32(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMInt32TypeInContext(ctx) }
    }

    pub fn i64(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMInt64TypeInContext(ctx) }
    }

    pub fn f32(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMFloatTypeInContext(ctx) }
    }

    pub fn f64(ctx: ContextRef) -> TypeRef {
        unsafe { llvm::LLVMDoubleTypeInContext(ctx) }
    }

    pub fn func(args: &[TypeRef], ret: TypeRef) -> TypeRef {
        unsafe { llvm::LLVMFunctionType(ret, args.as_ptr(),
                                   args.len() as c_uint, False) }
    }

    pub fn variadic_func(args: &[TypeRef], ret: TypeRef) -> TypeRef {
        unsafe { llvm::LLVMFunctionType(ret, args.as_ptr(),
                                   args.len() as c_uint, True) }
    }

    pub fn struct_(ctx: ContextRef, els: &[TypeRef], packed: bool) -> TypeRef {
        unsafe { llvm::LLVMStructTypeInContext(ctx, els.as_ptr(),
                                          els.len() as c_uint,
                                          packed as Bool) }
    }

    pub fn named_struct(ctx: ContextRef, name: &str) -> TypeRef {
        unsafe { name.with_c_str(|s| llvm::LLVMStructCreateNamed(ctx, s)) }
    }

    pub fn empty_struct(ctx: ContextRef) -> TypeRef {
        Type::struct_(ctx, [], false)
    }
}

trait TypeTr {
    fn array(self, len: u64) -> TypeRef;
    fn vector(self, len: u64) -> TypeRef;
    fn kind(self) -> TypeKind;
    fn set_struct_body(self, els: &[TypeRef], packed: bool);
    fn ptr_to(self) -> TypeRef;
    fn get_field(self, idx: uint) -> TypeRef;
    fn is_packed(self) -> bool;
    fn element_type(self) -> TypeRef;
    fn array_length(self) -> uint;
    fn field_types(self) -> Vec<TypeRef>;
    fn return_type(self) -> TypeRef;
    fn func_params(self) -> Vec<TypeRef>;
}


impl TypeTr for TypeRef {
    fn array(self, len: u64) -> TypeRef {
        unsafe { llvm::LLVMArrayType(self, len as c_uint) }
    }

    fn vector(self, len: u64) -> TypeRef {
        unsafe { llvm::LLVMVectorType(self, len as c_uint) }
    }

    fn kind(self) -> TypeKind {
        unsafe {
            llvm::LLVMGetTypeKind(self)
        }
    }

    fn set_struct_body(self, els: &[TypeRef], packed: bool) {
        unsafe {
            llvm::LLVMStructSetBody(self, els.as_ptr(),
                                    els.len() as c_uint, packed as Bool)
        }
    }

    fn ptr_to(self) -> TypeRef {
        unsafe { llvm::LLVMPointerType(self, 0) }
    }

    fn get_field(self, idx: uint) -> TypeRef {
        unsafe {
            let num_fields = llvm::LLVMCountStructElementTypes(self) as uint;
            let mut elems = Vec::from_elem(num_fields, 0 as TypeRef);

            llvm::LLVMGetStructElementTypes(self, elems.as_mut_ptr());

            *elems.get(idx)
        }
    }

    fn is_packed(self) -> bool {
        unsafe {
            llvm::LLVMIsPackedStruct(self) == True
        }
    }

    fn element_type(self) -> TypeRef {
        unsafe {
            llvm::LLVMGetElementType(self)
        }
    }

    fn array_length(self) -> uint {
        unsafe {
            llvm::LLVMGetArrayLength(self) as uint
        }
    }

    fn field_types(self) -> Vec<TypeRef> {
        unsafe {
            let n_elts = llvm::LLVMCountStructElementTypes(self) as uint;
            if n_elts == 0 {
                return Vec::new();
            }
            let mut elts = Vec::from_elem(n_elts, 0 as TypeRef);
            llvm::LLVMGetStructElementTypes(self, elts.get_mut(0));
            elts
        }
    }

    fn return_type(self) -> TypeRef {
        unsafe { llvm::LLVMGetReturnType(self) }
    }

    fn func_params(self) -> Vec<TypeRef> {
        unsafe {
            let n_args = llvm::LLVMCountParamTypes(self) as uint;
            let args = Vec::from_elem(n_args, 0 as TypeRef);
            llvm::LLVMGetParamTypes(self, args.as_ptr());
            args
        }
    }
}

// LLVM constant constructors.
pub fn C_null(t: TypeRef) -> ValueRef {
    unsafe {
        llvm::LLVMConstNull(t)
    }
}

pub fn C_undef(t: TypeRef) -> ValueRef {
    unsafe {
        llvm::LLVMGetUndef(t)
    }
}

pub fn C_integral(t: TypeRef, u: u64, sign_extend: bool) -> ValueRef {
    unsafe {
        llvm::LLVMConstInt(t, u, sign_extend as Bool)
    }
}

pub fn C_floating(s: &str, t: TypeRef) -> ValueRef {
    unsafe {
        s.with_c_str(|buf| llvm::LLVMConstRealOfString(t, buf))
    }
}

pub fn C_nil(ctx: ContextRef) -> ValueRef {
    C_struct(ctx, [], false)
}

pub fn C_i1(ctx: ContextRef, val: bool) -> ValueRef {
    C_integral(Type::i1(ctx), val as u64, false)
}

pub fn C_i32(ctx: ContextRef, i: i32) -> ValueRef {
    C_integral(Type::i32(ctx), i as u64, true)
}

pub fn C_i64(ctx: ContextRef, i: i64) -> ValueRef {
    C_integral(Type::i64(ctx), i as u64, true)
}

pub fn C_u64(ctx: ContextRef, i: u64) -> ValueRef {
    C_integral(Type::i64(ctx), i, false)
}

pub fn C_u8(ctx: ContextRef, i: uint) -> ValueRef {
    C_integral(Type::i8(ctx), i as u64, false)
}

pub fn C_struct(ctx: ContextRef, elts: &[ValueRef], packed: bool) -> ValueRef {
    unsafe {
        llvm::LLVMConstStructInContext(ctx,
                                       elts.as_ptr(), elts.len() as c_uint,
                                       packed as Bool)
    }
}

pub fn C_named_struct(t: TypeRef, elts: &[ValueRef]) -> ValueRef {
    unsafe {
        llvm::LLVMConstNamedStruct(t, elts.as_ptr(), elts.len() as c_uint)
    }
}

pub fn C_array(ty: TypeRef, elts: &[ValueRef]) -> ValueRef {
    unsafe {
        return llvm::LLVMConstArray(ty, elts.as_ptr(), elts.len() as c_uint);
    }
}

pub fn C_bytes(ctx: ContextRef, bytes: &[u8]) -> ValueRef {
    unsafe {
        let ptr = bytes.as_ptr() as *c_char;
        return llvm::LLVMConstStringInContext(ctx, ptr, bytes.len() as c_uint, True);
    }
}

pub fn get_param(fndecl: ValueRef, param: uint) -> ValueRef {
    unsafe {
        llvm::LLVMGetParam(fndecl, param as c_uint)
    }
}

pub fn const_get_elt(v: ValueRef, us: &[c_uint])
                  -> ValueRef {
    unsafe {
        llvm::LLVMConstExtractValue(v, us.as_ptr(), us.len() as c_uint)
    }
}

pub fn is_const(v: ValueRef) -> bool {
    unsafe {
        llvm::LLVMIsConstant(v) == True
    }
}

pub fn const_to_int(v: ValueRef) -> c_longlong {
    unsafe {
        llvm::LLVMConstIntGetSExtValue(v)
    }
}

pub fn const_to_uint(v: ValueRef) -> c_ulonglong {
    unsafe {
        llvm::LLVMConstIntGetZExtValue(v)
    }
}

pub fn is_undef(val: ValueRef) -> bool {
    unsafe {
        llvm::LLVMIsUndef(val) != False
    }
}

pub fn is_null(val: ValueRef) -> bool {
    unsafe {
        llvm::LLVMIsNull(val) != False
    }
}

pub struct Builder<'a> {
    ctx: &'a ContextRef,
    llbuilder: BuilderRef,
}

// This is a really awful way to get a zero-length c-string, but better (and a
// lot more efficient) than doing str::as_c_str("", ...) every time.
pub fn noname() -> *c_char {
    static cnull: c_char = 0;
    &cnull as *c_char
}

impl<'a> Builder<'a> {
    pub fn new(ctx: &'a ContextRef) -> Builder<'a> {
        Builder {
            ctx: ctx,
            llbuilder: unsafe {
                llvm::LLVMCreateBuilderInContext(*ctx)
            },
        }
    }

    pub fn position_before(&self, insn: ValueRef) {
        unsafe {
            llvm::LLVMPositionBuilderBefore(self.llbuilder, insn);
        }
    }

    pub fn position_at_end(&self, llbb: BasicBlockRef) {
        unsafe {
            llvm::LLVMPositionBuilderAtEnd(self.llbuilder, llbb);
        }
    }

    pub fn ret_void(&self) {
        unsafe {
            llvm::LLVMBuildRetVoid(self.llbuilder);
        }
    }

    pub fn ret(&self, v: ValueRef) {
        unsafe {
            llvm::LLVMBuildRet(self.llbuilder, v);
        }
    }

    pub fn aggregate_ret(&self, ret_vals: &[ValueRef]) {
        unsafe {
            llvm::LLVMBuildAggregateRet(self.llbuilder,
                                        ret_vals.as_ptr(),
                                        ret_vals.len() as c_uint);
        }
    }

    pub fn br(&self, dest: BasicBlockRef) {
        unsafe {
            llvm::LLVMBuildBr(self.llbuilder, dest);
        }
    }

    pub fn cond_br(&self, cond: ValueRef, then_llbb: BasicBlockRef, else_llbb: BasicBlockRef) {
        unsafe {
            llvm::LLVMBuildCondBr(self.llbuilder, cond, then_llbb, else_llbb);
        }
    }

    pub fn switch(&self, v: ValueRef, else_llbb: BasicBlockRef, num_cases: uint) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSwitch(self.llbuilder, v, else_llbb, num_cases as c_uint)
        }
    }

    pub fn indirect_br(&self, addr: ValueRef, num_dests: uint) {
        unsafe {
            llvm::LLVMBuildIndirectBr(self.llbuilder, addr, num_dests as c_uint);
        }
    }

    pub fn invoke(&self,
                  llfn: ValueRef,
                  args: &[ValueRef],
                  then: BasicBlockRef,
                  catch: BasicBlockRef,
                  attributes: &[(uint, lib::llvm::Attribute)])
                  -> ValueRef {
        unsafe {
            let v = llvm::LLVMBuildInvoke(self.llbuilder,
                                          llfn,
                                          args.as_ptr(),
                                          args.len() as c_uint,
                                          then,
                                          catch,
                                          noname());
            for &(idx, attr) in attributes.iter() {
                llvm::LLVMAddInstrAttribute(v, idx as c_uint, attr as c_uint);
            }
            v
        }
    }

    pub fn unreachable(&self) {
        unsafe {
            llvm::LLVMBuildUnreachable(self.llbuilder);
        }
    }

    /* Arithmetic */
    pub fn add(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildAdd(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nswadd(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNSWAdd(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nuwadd(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNUWAdd(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn fadd(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFAdd(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn sub(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSub(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nswsub(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNSWSub(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nuwsub(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNUWSub(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn fsub(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFSub(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn mul(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildMul(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nswmul(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNSWMul(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn nuwmul(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNUWMul(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn fmul(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFMul(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn udiv(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildUDiv(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn sdiv(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSDiv(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn exactsdiv(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildExactSDiv(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn fdiv(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFDiv(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn urem(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildURem(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn srem(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSRem(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn frem(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFRem(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn shl(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildShl(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn lshr(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildLShr(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn ashr(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildAShr(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn and(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildAnd(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn or(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildOr(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn xor(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildXor(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn binop(&self, op: Opcode, lhs: ValueRef, rhs: ValueRef)
              -> ValueRef {
        unsafe {
            llvm::LLVMBuildBinOp(self.llbuilder, op, lhs, rhs, noname())
        }
    }

    pub fn neg(&self, v: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNeg(self.llbuilder, v, noname())
        }
    }

    pub fn nswneg(&self, v: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNSWNeg(self.llbuilder, v, noname())
        }
    }

    pub fn nuwneg(&self, v: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNUWNeg(self.llbuilder, v, noname())
        }
    }
    pub fn fneg(&self, v: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFNeg(self.llbuilder, v, noname())
        }
    }

    pub fn not(&self, v: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildNot(self.llbuilder, v, noname())
        }
    }

    /* Memory */
    pub fn malloc(&self, ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildMalloc(self.llbuilder, ty, noname())
        }
    }

    pub fn array_malloc(&self, ty: TypeRef, val: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildArrayMalloc(self.llbuilder, ty, val, noname())
        }
    }

    pub fn alloca(&self, ty: TypeRef, name: &str) -> ValueRef {
        unsafe {
            if name.is_empty() {
                llvm::LLVMBuildAlloca(self.llbuilder, ty, noname())
            } else {
                name.with_c_str(|c| {
                    llvm::LLVMBuildAlloca(self.llbuilder, ty, c)
                })
            }
        }
    }

    pub fn array_alloca(&self, ty: TypeRef, val: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildArrayAlloca(self.llbuilder, ty, val, noname())
        }
    }

    pub fn free(&self, ptr: ValueRef) {
        unsafe {
            llvm::LLVMBuildFree(self.llbuilder, ptr);
        }
    }

    pub fn load(&self, ptr: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildLoad(self.llbuilder, ptr, noname())
        }
    }

    pub fn volatile_load(&self, ptr: ValueRef) -> ValueRef {
        unsafe {
            let insn = llvm::LLVMBuildLoad(self.llbuilder, ptr, noname());
            llvm::LLVMSetVolatile(insn, lib::llvm::True);
            insn
        }
    }

    pub fn load_range_assert(&self, ptr: ValueRef, lo: c_ulonglong,
                           hi: c_ulonglong, signed: lib::llvm::Bool) -> ValueRef {
        let value = self.load(ptr);

        unsafe {
            let t = llvm::LLVMGetElementType(llvm::LLVMTypeOf(ptr));
            let min = llvm::LLVMConstInt(t, lo, signed);
            let max = llvm::LLVMConstInt(t, hi, signed);

            let v = [min, max];

            llvm::LLVMSetMetadata(value, lib::llvm::MD_range as c_uint,
                                  llvm::LLVMMDNodeInContext(*self.ctx,
                                                            v.as_ptr(), v.len() as c_uint));
        }

        value
    }

    pub fn store(&self, val: ValueRef, ptr: ValueRef) {
        assert!(self.llbuilder.is_not_null());
        unsafe {
            llvm::LLVMBuildStore(self.llbuilder, val, ptr);
        }
    }

    pub fn volatile_store(&self, val: ValueRef, ptr: ValueRef) {
        assert!(self.llbuilder.is_not_null());
        unsafe {
            let insn = llvm::LLVMBuildStore(self.llbuilder, val, ptr);
            llvm::LLVMSetVolatile(insn, lib::llvm::True);
        }
    }

    pub fn gep(&self, ptr: ValueRef, indices: &[ValueRef]) -> ValueRef {
        unsafe {
            llvm::LLVMBuildGEP(self.llbuilder, ptr, indices.as_ptr(),
                               indices.len() as c_uint, noname())
        }
    }

    // Simple wrapper around GEP that takes an array of ints and wraps them
    // in C_i32()
    #[inline]
    pub fn gepi(&self, base: ValueRef, ixs: &[uint]) -> ValueRef {
        // Small vector optimization. This should catch 100% of the cases that
        // we care about.
        if ixs.len() < 16 {
            let mut small_vec = [ C_i32(*self.ctx, 0), ..16 ];
            for (small_vec_e, &ix) in small_vec.mut_iter().zip(ixs.iter()) {
                *small_vec_e = C_i32(*self.ctx, ix as i32);
            }
            self.inbounds_gep(base, small_vec.slice(0, ixs.len()))
        } else {
            let v = ixs.iter().map(|i| C_i32(*self.ctx, *i as i32)).collect::<Vec<ValueRef>>();
            self.inbounds_gep(base, v.as_slice())
        }
    }

    pub fn inbounds_gep(&self, ptr: ValueRef, indices: &[ValueRef]) -> ValueRef {
        unsafe {
            llvm::LLVMBuildInBoundsGEP(
                self.llbuilder, ptr, indices.as_ptr(), indices.len() as c_uint, noname())
        }
    }

    pub fn struct_gep(&self, ptr: ValueRef, idx: uint) -> ValueRef {
        unsafe {
            llvm::LLVMBuildStructGEP(self.llbuilder, ptr, idx as c_uint, noname())
        }
    }

    pub fn global_string(&self, _str: *c_char) -> ValueRef {
        unsafe {
            llvm::LLVMBuildGlobalString(self.llbuilder, _str, noname())
        }
    }

    pub fn global_string_ptr(&self, _str: *c_char) -> ValueRef {
        unsafe {
            llvm::LLVMBuildGlobalStringPtr(self.llbuilder, _str, noname())
        }
    }

    /* Casts */
    pub fn trunc(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildTrunc(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn zext(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildZExt(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn sext(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSExt(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn fptoui(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFPToUI(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn fptosi(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFPToSI(self.llbuilder, val, dest_ty,noname())
        }
    }

    pub fn uitofp(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildUIToFP(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn sitofp(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSIToFP(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn fptrunc(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFPTrunc(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn fpext(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFPExt(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn ptrtoint(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildPtrToInt(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn inttoptr(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildIntToPtr(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn bitcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildBitCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn zext_or_bitcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildZExtOrBitCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn sext_or_bitcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSExtOrBitCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn trunc_or_bitcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildTruncOrBitCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn cast(&self, op: Opcode, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildCast(self.llbuilder, op, val, dest_ty, noname())
        }
    }

    pub fn pointercast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildPointerCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn intcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildIntCast(self.llbuilder, val, dest_ty, noname())
        }
    }

    pub fn fpcast(&self, val: ValueRef, dest_ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFPCast(self.llbuilder, val, dest_ty, noname())
        }
    }


    /* Comparisons */
    pub fn icmp(&self, op: IntPredicate, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildICmp(self.llbuilder, op as c_uint, lhs, rhs, noname())
        }
    }

    pub fn fcmp(&self, op: RealPredicate, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildFCmp(self.llbuilder, op as c_uint, lhs, rhs, noname())
        }
    }

    /* Miscellaneous instructions */
    pub fn empty_phi(&self, ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildPhi(self.llbuilder, ty, noname())
        }
    }

    pub fn phi(&self, ty: TypeRef, vals: &[ValueRef], bbs: &[BasicBlockRef]) -> ValueRef {
        assert_eq!(vals.len(), bbs.len());
        let phi = self.empty_phi(ty);
        unsafe {
            llvm::LLVMAddIncoming(phi, vals.as_ptr(),
                                  bbs.as_ptr(),
                                  vals.len() as c_uint);
            phi
        }
    }

    pub fn inline_asm_call(&self, asm: *c_char, cons: *c_char,
                         inputs: &[ValueRef], output: TypeRef,
                         volatile: bool, alignstack: bool,
                         dia: AsmDialect) -> ValueRef {

        let volatile = if volatile { lib::llvm::True }
                       else        { lib::llvm::False };
        let alignstack = if alignstack { lib::llvm::True }
                         else          { lib::llvm::False };

        let argtys = inputs.map(|v| v.ty());

        let fty = Type::func(argtys, output);
        unsafe {
            let v = llvm::LLVMInlineAsm(
                fty, asm, cons, volatile, alignstack, dia as c_uint);
            self.call(v, inputs, [])
        }
    }

    pub fn call(&self, llfn: ValueRef, args: &[ValueRef],
                attributes: &[(uint, lib::llvm::Attribute)]) -> ValueRef {

        unsafe {
            let v = llvm::LLVMBuildCall(self.llbuilder, llfn, args.as_ptr(),
                                        args.len() as c_uint, noname());
            for &(idx, attr) in attributes.iter() {
                llvm::LLVMAddInstrAttribute(v, idx as c_uint, attr as c_uint);
            }
            v
        }
    }

    pub fn call_with_conv(&self, llfn: ValueRef, args: &[ValueRef],
                          conv: CallConv, attributes: &[(uint, lib::llvm::Attribute)]) -> ValueRef {
        let v = self.call(llfn, args, attributes);
        lib::llvm::SetInstructionCallConv(v, conv);
        v
    }

    pub fn select(&self, cond: ValueRef, then_val: ValueRef, else_val: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildSelect(self.llbuilder, cond, then_val, else_val, noname())
        }
    }

    pub fn va_arg(&self, list: ValueRef, ty: TypeRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildVAArg(self.llbuilder, list, ty, noname())
        }
    }

    pub fn extract_element(&self, vec: ValueRef, idx: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildExtractElement(self.llbuilder, vec, idx, noname())
        }
    }

    pub fn insert_element(&self, vec: ValueRef, elt: ValueRef, idx: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildInsertElement(self.llbuilder, vec, elt, idx, noname())
        }
    }

    pub fn shuffle_vector(&self, v1: ValueRef, v2: ValueRef, mask: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildShuffleVector(self.llbuilder, v1, v2, mask, noname())
        }
    }

    pub fn vector_splat(&self, num_elts: uint, elt: ValueRef) -> ValueRef {
        unsafe {
            let elt_ty = elt.ty();
            let undef = llvm::LLVMGetUndef(elt_ty.vector(num_elts as u64));
            let vec = self.insert_element(undef, elt, C_i32(*self.ctx, 0));
            let vec_i32_ty = Type::i32(*self.ctx).vector(num_elts as u64);
            self.shuffle_vector(vec, undef, C_null(vec_i32_ty))
        }
    }

    pub fn extract_value(&self, agg_val: ValueRef, idx: uint) -> ValueRef {
        unsafe {
            llvm::LLVMBuildExtractValue(self.llbuilder, agg_val, idx as c_uint, noname())
        }
    }

    pub fn insert_value(&self, agg_val: ValueRef, elt: ValueRef,
                       idx: uint) -> ValueRef {
        unsafe {
            llvm::LLVMBuildInsertValue(self.llbuilder, agg_val, elt, idx as c_uint,
                                       noname())
        }
    }

    pub fn is_null(&self, val: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildIsNull(self.llbuilder, val, noname())
        }
    }

    pub fn is_not_null(&self, val: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildIsNotNull(self.llbuilder, val, noname())
        }
    }

    pub fn ptrdiff(&self, lhs: ValueRef, rhs: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildPtrDiff(self.llbuilder, lhs, rhs, noname())
        }
    }

    pub fn trap(&self) {
        unsafe {
            let bb: BasicBlockRef = llvm::LLVMGetInsertBlock(self.llbuilder);
            let fn_: ValueRef = llvm::LLVMGetBasicBlockParent(bb);
            let m: ModuleRef = llvm::LLVMGetGlobalParent(fn_);
            let t: ValueRef = "llvm.trap".with_c_str(|buf| {
                llvm::LLVMGetNamedFunction(m, buf)
            });
            assert!((t as int != 0));
            let args: &[ValueRef] = [];
            llvm::LLVMBuildCall(
                self.llbuilder, t, args.as_ptr(), args.len() as c_uint, noname());
        }
    }

    pub fn landing_pad(&self, ty: TypeRef, pers_fn: ValueRef, num_clauses: uint) -> ValueRef {
        unsafe {
            llvm::LLVMBuildLandingPad(
                self.llbuilder, ty, pers_fn, num_clauses as c_uint, noname())
        }
    }

    pub fn set_cleanup(&self, landing_pad: ValueRef) {
        unsafe {
            llvm::LLVMSetCleanup(landing_pad, lib::llvm::True);
        }
    }

    pub fn resume(&self, exn: ValueRef) -> ValueRef {
        unsafe {
            llvm::LLVMBuildResume(self.llbuilder, exn)
        }
    }

    // Atomic Operations
    pub fn atomic_cmpxchg(&self, dst: ValueRef,
                         cmp: ValueRef, src: ValueRef,
                         order: AtomicOrdering) -> ValueRef {
        unsafe {
            llvm::LLVMBuildAtomicCmpXchg(self.llbuilder, dst, cmp, src, order)
        }
    }
    pub fn atomic_rmw(&self, op: AtomicBinOp,
                     dst: ValueRef, src: ValueRef,
                     order: AtomicOrdering) -> ValueRef {
        unsafe {
            llvm::LLVMBuildAtomicRMW(self.llbuilder, op, dst, src, order, False)
        }
    }

    pub fn atomic_fence(&self, order: AtomicOrdering) {
        unsafe {
            llvm::LLVMBuildAtomicFence(self.llbuilder, order);
        }
    }
}
