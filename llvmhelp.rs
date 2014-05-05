// imaon2 note: Adapted from rustc's middle/trans/{builder,common,type_}.rs (presently from revision 871e5708106c5ee3ad8d2bd6ec68fca60428b77e).
#![feature(struct_variant, macro_rules)]

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
extern crate libc;
extern crate collections;
extern crate llvmshim;

use rustc::lib;
use rustc::lib::llvm::llvm;
use rustc::lib::llvm::{CallConv, AtomicOrdering, AsmDialect};
use rustc::lib::llvm::{ContextRef, ValueRef, BasicBlockRef, BuilderRef, ModuleRef, TypeRef, UseRef};
use rustc::lib::llvm::{Opcode, IntPredicate, RealPredicate, True, False, Bool, TypeKind};

use libc::{c_uint, c_longlong, c_ulonglong, c_char};
use std::vec::Vec;
use std::cast;
use std::kinds::marker;
//use std::mem;

macro_rules! wrapper(($cls:ident, $clsref:ident) => (
    pub struct $cls<'f> {
        r: $clsref,
        marker: marker::ContravariantLifetime<'f>
    }

    impl<'o> Deref<$clsref> for $cls<'o> {
        fn deref<'a>(&'a self) -> &'a $clsref { &'a self.r }
    }

    impl<'f> $cls<'f> {
        pub unsafe fn new(r: $clsref) -> $cls {
            assert_eq!(std::mem::size_of::<$cls>(), std::mem::size_of::<$clsref>());
            $cls { r: r, marker: marker::ContravariantLifetime }
        }
    }
))

wrapper!(Use, UseRef)

impl<'f> Use<'f> {
    pub fn user(self) -> Value<'f> {
        unsafe { Value::new(llvm::LLVMGetUser(*self)) }
    }
    pub fn used(self) -> Value<'f> {
        //unsafe { llvm::LLVMGetUsedValue(self) }
        unsafe { Value::new(*cast::transmute::<UseRef, *ValueRef>(*self)) }
    }
    pub fn set_used(self, repl: Value<'f>) {
        unsafe { llvmshim::LLVMShimReplaceUse(*self, *repl) }
    }
}

pub struct UseList {
    use_: UseRef
}

impl Iterator<UseRef> for UseList {
    fn next(&mut self) -> Option<UseRef> {
        let use_ = self.use_;
        if use_.is_null() {
            None
        } else {
            self.use_ = unsafe { llvm::LLVMGetNextUse(use_) };
            Some(use_)
        }
    }
}

// Note: get() should be reasonably cheap, so not bundling things like switch cases in the enum for now.

#[deriving(Show, Eq, FromPrimitive)]
enum BinOpType { Add, FAdd, Sub, FSub, Mul, FMul, UDiv, SDiv, FDiv, URem, SRem, FRem, Shl, LShr, AShr, And, Or, Xor }

#[deriving(Show, Eq, FromPrimitive)]
enum CastType { Trunc, ZExt, SExt, FPToUI, FPToSI, UIToFP, SIToFP, FPTrunc, FPExt, PtrToInt, IntToPtr, BitCast }

#[deriving(Show, Eq)]
pub struct LoadStoreInfo {
    subclass: uint
}

impl LoadStoreInfo {
    pub fn volatile(&self) -> bool { (self.subclass & 1) != 0 }
    // huh?
    pub fn alignment(&self) -> uint { (1 << ((self.subclass >> 1) & 31)) >> 1 }
    pub fn ordering(&self) -> llvmshim::AtomicOrdering { FromPrimitive::from_uint((self.subclass >> 7) & 7).unwrap() }
    pub fn synch_scope(&self) -> uint { (self.subclass >> 6) & 1 }
    pub fn atomic(&self) -> bool { self.ordering() != llvmshim::AtomicOrderingNotAtomic }
}


#[deriving(Show, Eq)]
enum ValueEn {
    VRet(Option<ValueRef>),
    VBr { if_true: ValueRef, if_false: Option<ValueRef>, cond: Option<ValueRef> },
    VSwitch { value: ValueRef, default: ValueRef },
    VIndirectBr(ValueRef),
    VInvoke { fun: ValueRef, if_normal: ValueRef, if_exc: ValueRef },
    VCall(ValueRef),
    VUnreachable,
    VBinOp(BinOpType, ValueRef, ValueRef),
    VAlloca { ty: TypeRef, cnt: ValueRef },
    VLoad { addr: ValueRef, lsi: LoadStoreInfo },
    VStore { val: ValueRef, addr: ValueRef, lsi: LoadStoreInfo },
    VGEP(ValueRef),
    // We include a handy type even though it's available separately.
    VCast(CastType, TypeRef, ValueRef),

}

/*
#[inline(always)]
pub fn op_use(ops: &mut [Use_opaque], n: uint) -> UseRef {
    unsafe { cast::transmute(&ops[n]) }
}

#[inline(always)]
pub fn op(ops: &[Use_opaque], n: uint) -> ValueRef {
    op_use(unsafe { cast::transmute(ops) }, n).used()
}
*/

wrapper!(Value, ValueRef)

impl<'f> Value<'f> {
    pub fn ty(self) -> Type {
        unsafe {
            Type::new(llvm::LLVMTypeOf(*self))
        }
    }
    pub fn uses(self) -> UseList {
        UseList { use_: unsafe { llvm::LLVMGetFirstUse(*self) } }
    }
    /*
    pub fn operands(self) -> &mut [Use_opaque] {
        unsafe { llvmshim::LLVMShimGetOperandList(*self) }
    }
    */
    pub fn opcode(self) -> llvmshim::Opcode {
        FromPrimitive::from_u32(unsafe { llvmshim::LLVMShimGetValueID(*self) }).unwrap()
    }
    pub fn subclass_data(self) -> uint {
        (unsafe { llvmshim::LLVMShimGetSubclassData(*self) }) as uint
    }
    pub fn subclass_optional_data(self) -> uint {
        (unsafe { llvmshim::LLVMShimGetSubclassOptionalData(*self) }) as uint
    }
    /*
    pub fn get(self) -> ValueEn {
        let ops = self.operands();
        let opcode = self.opcode();
        match opcode {
            llvmshim::Ret if ops.len() == 1 => VRet(Some(op(ops, 0))),
            llvmshim::Ret => VRet(None),
            llvmshim::Br if ops.len() == 1 => VBr { if_true: op(ops, 1), if_false: None, cond: None },
            llvmshim::Br => VBr { if_true: op(ops, 0), if_false: Some(op(ops, 1)), cond: Some(op(ops, 2)) },
            llvmshim::Switch => VSwitch { value: op(ops, 0), default: op(ops, 1) },
            llvmshim::IndirectBr => VIndirectBr(op(ops, 0)),
            llvmshim::Invoke => VInvoke { fun: op(ops, ops.len() - 3), if_normal: op(ops, ops.len() - 2), if_exc: op(ops, ops.len() - 1) },
            llvmshim::Unreachable => VUnreachable,

            llvmshim::Add | llvmshim::FAdd | llvmshim::Sub | llvmshim::FSub | llvmshim::Mul | llvmshim::FMul | llvmshim::UDiv | llvmshim::SDiv | llvmshim::FDiv | llvmshim::URem | llvmshim::SRem | llvmshim::FRem | llvmshim::Shl | llvmshim::LShr | llvmshim::AShr | llvmshim::And | llvmshim::Or | llvmshim::Xor => VBinOp(
                FromPrimitive::from_int((self.opcode() as int) - (llvmshim::Add as int)).unwrap(),
                op(ops, 0),
                op(ops, 1)
            ),

            llvmshim::Alloca => VAlloca { ty: self.ty(), cnt: op(ops, 0) },
            llvmshim::Load => VLoad { addr: op(ops, 0), lsi: LoadStoreInfo { subclass: self.subclass_data() } },
            llvmshim::Store => VStore { val: op(ops, 0), addr: op(ops, 1), lsi: LoadStoreInfo { subclass: self.subclass_data() } },
            // For now, don't bother with inbounds...
            llvmshim::GetElementPtr => VGEP(op(ops, 0)),

            llvmshim::Call => VCall(op(ops, ops.len() - 1)),

            llvmshim::Trunc | llvmshim::ZExt | llvmshim::SExt | llvmshim::FPToUI | llvmshim::FPToSI | llvmshim::UIToFP | llvmshim::SIToFP | llvmshim::FPTrunc | llvmshim::FPExt | llvmshim::PtrToInt | llvmshim::IntToPtr | llvmshim::BitCast => VCast(
                FromPrimitive::from_int((self.opcode() as int) - (llvmshim::Trunc as int)).unwrap(),
                self.ty(),
                op(ops, 0)
            ),

            _ => fail!("unknown")
        }
    }
    */
}

wrapper!(Type, TypeRef)

impl<'a> Type<'a> {
    pub fn void(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMVoidTypeInContext(*ctx)) }
    }

    pub fn metadata(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMMetadataTypeInContext(*ctx)) }
    }

    pub fn i1(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMInt1TypeInContext(*ctx)) }
    }

    pub fn i8(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMInt8TypeInContext(*ctx)) }
    }

    pub fn i16(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMInt16TypeInContext(*ctx)) }
    }

    pub fn i32(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMInt32TypeInContext(*ctx)) }
    }

    pub fn i64(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMInt64TypeInContext(*ctx)) }
    }

    pub fn f32(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMFloatTypeInContext(*ctx)) }
    }

    pub fn f64(ctx: &'a ContextRef) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMDoubleTypeInContext(*ctx)) }
    }

    pub fn func(args: &[Type<'a>], ret: Type<'a>) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMFunctionType(*ret, cast::transmute(args.as_ptr()),
                           args.len() as c_uint, False)) }
    }

    pub fn variadic_func(args: &[Type<'a>], ret: Type<'a>) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMFunctionType(*ret, cast::transmute(args.as_ptr()),
                                                  args.len() as c_uint, True)) }
    }

    pub fn struct_(ctx: &'a ContextRef, els: &[Type<'a>], packed: bool) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMStructTypeInContext(*ctx, cast::transmute(els.as_ptr()),
                                                         els.len() as c_uint,
                                                         packed as Bool)) }
    }

    pub fn named_struct(ctx: &'a ContextRef, name: &str) -> Type<'a> {
        unsafe { Type::new(name.with_c_str(|s| llvm::LLVMStructCreateNamed(*ctx, s))) }
    }

    pub fn empty_struct(ctx: &'a ContextRef) -> Type<'a> {
        Type::struct_(ctx, [], false)
    }

    pub fn array(self, len: u64) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMArrayType(*self, len as c_uint)) }
    }

    pub fn vector(self, len: u64) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMVectorType(*self, len as c_uint)) }
    }

    pub fn kind(self) -> TypeKind {
        unsafe {
            llvm::LLVMGetTypeKind(*self)
        }
    }

    pub fn set_struct_body(self, els: &[Type<'a>], packed: bool) {
        unsafe {
            llvm::LLVMStructSetBody(*self, cast::transmute(els.as_ptr()),
                                    els.len() as c_uint, packed as Bool)
        }
    }

    pub fn ptr_to(self) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMPointerType(*self, 0)) }
    }

    pub fn get_field(self, idx: uint) -> Type<'a> {
        unsafe {
            let num_fields = llvm::LLVMCountStructElementTypes(*self) as uint;
            let mut elems = Vec::from_elem(num_fields, 0 as TypeRef);

            llvm::LLVMGetStructElementTypes(*self, elems.as_mut_ptr());

            Type::new(*elems.get(idx))
        }
    }

    pub fn is_packed(self) -> bool {
        unsafe {
            llvm::LLVMIsPackedStruct(*self) == True
        }
    }

    pub fn element_type(self) -> Type<'a> {
        unsafe {
            Type::new(llvm::LLVMGetElementType(*self))
        }
    }

    pub fn array_length(self) -> uint {
        unsafe {
            llvm::LLVMGetArrayLength(*self) as uint
        }
    }

    pub fn field_types(self) -> Vec<Type<'a>> {
        unsafe {
            let n_elts = llvm::LLVMCountStructElementTypes(*self) as uint;
            if n_elts == 0 {
                return Vec::new();
            }
            let mut elts = Vec::from_elem(n_elts, 0 as TypeRef);
            llvm::LLVMGetStructElementTypes(*self, elts.get_mut(0));
            cast::transmute(elts)
        }
    }

    pub fn return_type(self) -> Type<'a> {
        unsafe { Type::new(llvm::LLVMGetReturnType(*self)) }
    }

    pub fn func_params(self) -> Vec<Type<'a>> {
        unsafe {
            let n_args = llvm::LLVMCountParamTypes(*self) as uint;
            let args = Vec::from_elem(n_args, 0 as TypeRef);
            llvm::LLVMGetParamTypes(*self, args.as_ptr());
            cast::transmute(args)
        }
    }
}

// LLVM constant constructors.
pub fn C_null<'a>(t: Type<'a>) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstNull(*t))
    }
}

pub fn C_undef<'a>(t: Type<'a>) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMGetUndef(*t))
    }
}

pub fn C_integral<'a>(t: Type<'a>, u: u64, sign_extend: bool) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstInt(*t, u, sign_extend as Bool))
    }
}

pub fn C_floating<'a>(s: &str, t: Type<'a>) -> Value<'a> {
    unsafe {
        Value::new(s.with_c_str(|buf| llvm::LLVMConstRealOfString(*t, buf)))
    }
}

pub fn C_nil<'a>(ctx: &'a ContextRef) -> Value<'a> {
    C_struct(ctx, [], false)
}

pub fn C_i1<'a>(ctx: &'a ContextRef, val: bool) -> Value<'a> {
    C_integral(Type::i1(ctx), val as u64, false)
}

pub fn C_i32<'a>(ctx: &'a ContextRef, i: i32) -> Value<'a> {
    C_integral(Type::i32(ctx), i as u64, true)
}

pub fn C_i64<'a>(ctx: &'a ContextRef, i: i64) -> Value<'a> {
    C_integral(Type::i64(ctx), i as u64, true)
}

pub fn C_u64<'a>(ctx: &'a ContextRef, i: u64) -> Value<'a> {
    C_integral(Type::i64(ctx), i, false)
}

pub fn C_u8<'a>(ctx: &'a ContextRef, i: uint) -> Value<'a> {
    C_integral(Type::i8(ctx), i as u64, false)
}

pub fn C_struct<'a>(ctx: &'a ContextRef, elts: &[Value<'a>], packed: bool) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstStructInContext(*ctx,
                    cast::transmute(elts.as_ptr()), elts.len() as c_uint,
                    packed as Bool))
    }
}

pub fn C_named_struct<'a>(t: Type<'a>, elts: &[Value<'a>]) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstNamedStruct(*t, cast::transmute(elts.as_ptr()), elts.len() as c_uint))
    }
}

pub fn C_array<'a>(ty: Type<'a>, elts: &[Value<'a>]) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstArray(*ty, cast::transmute(elts.as_ptr()), elts.len() as c_uint))
    }
}

pub fn C_bytes<'a>(ctx: &'a ContextRef, bytes: &[u8]) -> Value<'a> {
    unsafe {
        let ptr = bytes.as_ptr() as *c_char;
        Value::new(llvm::LLVMConstStringInContext(*ctx, ptr, bytes.len() as c_uint, True))
    }
}

pub fn get_param<'a>(fndecl: Value<'a>, param: uint) -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMGetParam(*fndecl, param as c_uint))
    }
}

pub fn const_get_elt<'a>(v: Value<'a>, us: &[c_uint])
                  -> Value<'a> {
    unsafe {
        Value::new(llvm::LLVMConstExtractValue(*v, us.as_ptr(), us.len() as c_uint))
    }
}

pub fn is_const<'a>(v: Value) -> bool {
    unsafe {
        llvm::LLVMIsConstant(*v) == True
    }
}

pub fn const_to_int(v: Value) -> c_longlong {
    unsafe {
        llvm::LLVMConstIntGetSExtValue(*v)
    }
}

pub fn const_to_uint(v: Value) -> c_ulonglong {
    unsafe {
        llvm::LLVMConstIntGetZExtValue(*v)
    }
}

pub fn is_undef(val: Value) -> bool {
    unsafe {
        llvm::LLVMIsUndef(*val) != False
    }
}

pub fn is_null(val: Value) -> bool {
    unsafe {
        llvm::LLVMIsNull(*val) != False
    }
}

pub struct Builder<'f> {
    ctx: &'f ContextRef,
    llbuilder: BuilderRef,
    function: Value<'f>
}

// This is a really awful way to get a zero-length c-string, but better (and a
// lot more efficient) than doing str::as_c_str("", ...) every time.
pub fn noname() -> *c_char {
    static cnull: c_char = 0;
    &cnull as *c_char
}

impl<'f> Builder<'f> {
    pub fn new(ctx: &'f ContextRef, function: Value<'f>) -> Builder<'f> {
        Builder {
            ctx: ctx,
            llbuilder: unsafe {
                llvm::LLVMCreateBuilderInContext(*ctx)
            },
            function: function
        }
    }

    pub fn position_before(&self, insn: Value<'f>) {
        unsafe {
            llvm::LLVMPositionBuilderBefore(self.llbuilder, *insn);
        }
    }

    pub fn position_at_end(&self, llbb: BasicBlockRef) {
        // TODO verify function etc
        unsafe {
            llvm::LLVMPositionBuilderAtEnd(self.llbuilder, llbb);
        }
    }

    pub fn ret_void(&self) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildRetVoid(self.llbuilder))
        }
    }

    pub fn ret(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildRet(self.llbuilder, *v))
        }
    }

    pub fn aggregate_ret(&self, ret_vals: &[Value<'f>]) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildAggregateRet(self.llbuilder,
                                        cast::transmute(ret_vals.as_ptr()),
                                        ret_vals.len() as c_uint))
        }
    }

    pub fn br(&self, dest: BasicBlockRef) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildBr(self.llbuilder, dest))
        }
    }

    pub fn cond_br(&self, cond: Value<'f>, then_llbb: BasicBlockRef, else_llbb: BasicBlockRef) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildCondBr(self.llbuilder, *cond, then_llbb, else_llbb))
        }
    }

    pub fn switch(&self, v: Value<'f>, else_llbb: BasicBlockRef, num_cases: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSwitch(self.llbuilder, *v, else_llbb, num_cases as c_uint))
        }
    }

    pub fn indirect_br(&self, addr: Value<'f>, num_dests: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildIndirectBr(self.llbuilder, *addr, num_dests as c_uint))
        }
    }

    pub fn invoke(&self,
                  llfn: Value<'f>,
                  args: &[Value<'f>],
                  then: BasicBlockRef,
                  catch: BasicBlockRef,
                  attributes: &[(uint, lib::llvm::Attribute)])
                  -> Value<'f> {
        unsafe {
            let v = llvm::LLVMBuildInvoke(self.llbuilder,
                                          *llfn,
                                          cast::transmute(args.as_ptr()),
                                          args.len() as c_uint,
                                          then,
                                          catch,
                                          noname());
            for &(idx, attr) in attributes.iter() {
                llvm::LLVMAddInstrAttribute(v, idx as c_uint, attr as c_uint);
            }
            Value::new(v)
        }
    }

    pub fn unreachable(&self) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildUnreachable(self.llbuilder))
        }
    }

    /* Arithmetic */
    pub fn add(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildAdd(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nswadd(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNSWAdd(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nuwadd(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNUWAdd(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn fadd(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFAdd(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn sub(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSub(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nswsub(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNSWSub(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nuwsub(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNUWSub(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn fsub(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFSub(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn mul(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildMul(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nswmul(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNSWMul(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn nuwmul(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNUWMul(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn fmul(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFMul(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn udiv(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildUDiv(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn sdiv(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSDiv(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn exactsdiv(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildExactSDiv(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn fdiv(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFDiv(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn urem(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildURem(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn srem(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSRem(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn frem(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFRem(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn shl(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildShl(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn lshr(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildLShr(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn ashr(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildAShr(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn and(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildAnd(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn or(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildOr(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn xor(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildXor(self.llbuilder, *lhs, *rhs, noname()))
        }
    }

    pub fn binop(&self, op: Opcode, lhs: Value<'f>, rhs: Value<'f>)
              -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildBinOp(self.llbuilder, op, *lhs, *rhs, noname()))
        }
    }

    pub fn neg(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNeg(self.llbuilder, *v, noname()))
        }
    }

    pub fn nswneg(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNSWNeg(self.llbuilder, *v, noname()))
        }
    }

    pub fn nuwneg(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNUWNeg(self.llbuilder, *v, noname()))
        }
    }
    pub fn fneg(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFNeg(self.llbuilder, *v, noname()))
        }
    }

    pub fn not(&self, v: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildNot(self.llbuilder, *v, noname()))
        }
    }

    /* Memory */
    pub fn malloc(&self, ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildMalloc(self.llbuilder, *ty, noname()))
        }
    }

    pub fn array_malloc(&self, ty: Type<'f>, val: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildArrayMalloc(self.llbuilder, *ty, *val, noname()))
        }
    }

    pub fn alloca(&self, ty: Type<'f>, name: &str) -> Value<'f> {
        unsafe {
            if name.is_empty() {
                Value::new(llvm::LLVMBuildAlloca(self.llbuilder, *ty, noname()))
            } else {
                name.with_c_str(|c| {
                    Value::new(llvm::LLVMBuildAlloca(self.llbuilder, *ty, c))
                })
            }
        }
    }

    pub fn array_alloca(&self, ty: Type<'f>, val: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildArrayAlloca(self.llbuilder, *ty, *val, noname()))
        }
    }

    pub fn free(&self, ptr: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFree(self.llbuilder, *ptr))
        }
    }

    pub fn load(&self, ptr: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildLoad(self.llbuilder, *ptr, noname()))
        }
    }

    pub fn volatile_load(&self, ptr: Value<'f>) -> Value<'f> {
        unsafe {
            let insn = llvm::LLVMBuildLoad(self.llbuilder, *ptr, noname());
            llvm::LLVMSetVolatile(insn, lib::llvm::True);
            Value::new(insn)
        }
    }

    pub fn load_range_assert(&self, ptr: Value<'f>, lo: c_ulonglong,
                           hi: c_ulonglong, signed: lib::llvm::Bool) -> Value<'f> {
        let value = self.load(ptr);

        unsafe {
            let t = llvm::LLVMGetElementType(llvm::LLVMTypeOf(*ptr));
            let min = llvm::LLVMConstInt(t, lo, signed);
            let max = llvm::LLVMConstInt(t, hi, signed);

            let v = [min, max];

            llvm::LLVMSetMetadata(*value, lib::llvm::MD_range as c_uint,
                                  llvm::LLVMMDNodeInContext(*self.ctx,
                                                            v.as_ptr(), v.len() as c_uint));
        }

        value
    }

    pub fn store(&self, val: Value<'f>, ptr: Value<'f>) {
        assert!(self.llbuilder.is_not_null());
        unsafe {
            Value::new(llvm::LLVMBuildStore(self.llbuilder, *val, *ptr));
        }
    }

    pub fn volatile_store(&self, val: Value<'f>, ptr: Value<'f>) -> Value<'f> {
        assert!(self.llbuilder.is_not_null());
        unsafe {
            let insn = llvm::LLVMBuildStore(self.llbuilder, *val, *ptr);
            llvm::LLVMSetVolatile(insn, lib::llvm::True);
            Value::new(insn)
        }
    }

    pub fn gep(&self, ptr: Value<'f>, indices: &[Value<'f>]) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildGEP(self.llbuilder, *ptr, cast::transmute(indices.as_ptr()),
                               indices.len() as c_uint, noname()))
        }
    }

    // Simple wrapper around GEP that takes an array of ints and wraps them
    // in C_i32()
    #[inline]
    pub fn gepi(&self, base: Value<'f>, ixs: &[uint]) -> Value<'f> {
        // Small vector optimization. This should catch 100% of the cases that
        // we care about.
        if ixs.len() < 16 {
            let mut small_vec = [ C_i32(self.ctx, 0), ..16 ];
            for (small_vec_e, &ix) in small_vec.mut_iter().zip(ixs.iter()) {
                *small_vec_e = C_i32(self.ctx, ix as i32);
            }
            self.inbounds_gep(base, small_vec.slice(0, ixs.len()))
        } else {
            let v = ixs.iter().map(|i| C_i32(self.ctx, *i as i32)).collect::<Vec<Value<'f>>>();
            self.inbounds_gep(base, v.as_slice())
        }
    }

    pub fn inbounds_gep(&self, ptr: Value<'f>, indices: &[Value<'f>]) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildInBoundsGEP(
                self.llbuilder, *ptr, cast::transmute(indices.as_ptr()), indices.len() as c_uint, noname()))
        }
    }

    pub fn struct_gep(&self, ptr: Value<'f>, idx: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildStructGEP(self.llbuilder, *ptr, idx as c_uint, noname()))
        }
    }

    pub fn global_string(&self, _str: *c_char) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildGlobalString(self.llbuilder, _str, noname()))
        }
    }

    pub fn global_string_ptr(&self, _str: *c_char) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildGlobalStringPtr(self.llbuilder, _str, noname()))
        }
    }

    /* Casts */
    pub fn trunc(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildTrunc(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn zext(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildZExt(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn sext(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSExt(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn fptoui(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFPToUI(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn fptosi(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFPToSI(self.llbuilder, *val, *dest_ty,noname()))
        }
    }

    pub fn uitofp(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildUIToFP(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn sitofp(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSIToFP(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn fptrunc(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFPTrunc(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn fpext(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFPExt(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn ptrtoint(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildPtrToInt(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn inttoptr(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildIntToPtr(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn bitcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildBitCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn zext_or_bitcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildZExtOrBitCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn sext_or_bitcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSExtOrBitCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn trunc_or_bitcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildTruncOrBitCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn cast(&self, op: Opcode, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildCast(self.llbuilder, op, *val, *dest_ty, noname()))
        }
    }

    pub fn pointercast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildPointerCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn intcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildIntCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }

    pub fn fpcast(&self, val: Value<'f>, dest_ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFPCast(self.llbuilder, *val, *dest_ty, noname()))
        }
    }


    /* Comparisons */
    pub fn icmp(&self, op: IntPredicate, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildICmp(self.llbuilder, op as c_uint, *lhs, *rhs, noname()))
        }
    }

    pub fn fcmp(&self, op: RealPredicate, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildFCmp(self.llbuilder, op as c_uint, *lhs, *rhs, noname()))
        }
    }

    /* Miscellaneous instructions */
    pub fn empty_phi(&self, ty: TypeRef) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildPhi(self.llbuilder, ty, noname()))
        }
    }

    pub fn phi(&self, ty: TypeRef, vals: &[Value<'f>], bbs: &[BasicBlockRef]) -> Value<'f> {
        assert_eq!(vals.len(), bbs.len());
        let phi = self.empty_phi(ty);
        unsafe {
            llvm::LLVMAddIncoming(*phi, cast::transmute(vals.as_ptr()),
                                  bbs.as_ptr(),
                                  vals.len() as c_uint);
            phi
        }
    }

    pub fn inline_asm_call(&self, asm: *c_char, cons: *c_char,
                         inputs: &[Value<'f>], output: Type<'f>,
                         volatile: bool, alignstack: bool,
                         dia: AsmDialect) -> Value<'f> {

        let volatile = if volatile { lib::llvm::True }
                       else        { lib::llvm::False };
        let alignstack = if alignstack { lib::llvm::True }
                         else          { lib::llvm::False };

        let argtys: ~[_] = inputs.iter().map(|v| v.ty()).collect();

        let fty = Type::func(argtys, output);
        unsafe {
            let v = Value::new(llvm::LLVMInlineAsm(
                *fty, asm, cons, volatile, alignstack, dia as c_uint));
            self.call(v, inputs, [])
        }
    }

    pub fn call(&self, llfn: Value<'f>, args: &[Value<'f>],
                attributes: &[(uint, lib::llvm::Attribute)]) -> Value<'f> {

        unsafe {
            let v = llvm::LLVMBuildCall(self.llbuilder, *llfn, cast::transmute(args.as_ptr()),
                                        args.len() as c_uint, noname());
            for &(idx, attr) in attributes.iter() {
                llvm::LLVMAddInstrAttribute(v, idx as c_uint, attr as c_uint);
            }
            Value::new(v)
        }
    }

    pub fn call_with_conv(&self, llfn: Value<'f>, args: &[Value<'f>],
                          conv: CallConv, attributes: &[(uint, lib::llvm::Attribute)]) -> Value<'f> {
        let v = self.call(llfn, args, attributes);
        lib::llvm::SetInstructionCallConv(*v, conv);
        v
    }

    pub fn select(&self, cond: Value<'f>, then_val: Value<'f>, else_val: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildSelect(self.llbuilder, *cond, *then_val, *else_val, noname()))
        }
    }

    pub fn va_arg(&self, list: Value<'f>, ty: Type<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildVAArg(self.llbuilder, *list, *ty, noname()))
        }
    }

    pub fn extract_element(&self, vec: Value<'f>, idx: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildExtractElement(self.llbuilder, *vec, *idx, noname()))
        }
    }

    pub fn insert_element(&self, vec: Value<'f>, elt: Value<'f>, idx: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildInsertElement(self.llbuilder, *vec, *elt, *idx, noname()))
        }
    }

    pub fn shuffle_vector(&self, v1: Value<'f>, v2: Value<'f>, mask: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildShuffleVector(self.llbuilder, *v1, *v2, *mask, noname()))
        }
    }

    pub fn vector_splat(&self, num_elts: uint, elt: Value<'f>) -> Value<'f> {
        unsafe {
            let elt_ty = elt.ty();
            let undef = Value::new(llvm::LLVMGetUndef(*elt_ty.vector(num_elts as u64)));
            let vec = self.insert_element(undef, elt, C_i32(self.ctx, 0));
            let vec_i32_ty = Type::i32(self.ctx).vector(num_elts as u64);
            self.shuffle_vector(vec, undef, C_null(vec_i32_ty))
        }
    }

    pub fn extract_value(&self, agg_val: Value<'f>, idx: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildExtractValue(self.llbuilder, *agg_val, idx as c_uint, noname()))
        }
    }

    pub fn insert_value(&self, agg_val: Value<'f>, elt: Value<'f>,
                       idx: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildInsertValue(self.llbuilder, *agg_val, *elt, idx as c_uint,
                                       noname()))
        }
    }

    pub fn is_null(&self, val: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildIsNull(self.llbuilder, *val, noname()))
        }
    }

    pub fn is_not_null(&self, val: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildIsNotNull(self.llbuilder, *val, noname()))
        }
    }

    pub fn ptrdiff(&self, lhs: Value<'f>, rhs: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildPtrDiff(self.llbuilder, *lhs, *rhs, noname()))
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
            Value::new(llvm::LLVMBuildCall(
                self.llbuilder, t, args.as_ptr(), args.len() as c_uint, noname()));
        }
    }

    pub fn landing_pad(&self, ty: Type<'f>, pers_fn: Value<'f>, num_clauses: uint) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildLandingPad(
                self.llbuilder, *ty, *pers_fn, num_clauses as c_uint, noname()))
        }
    }

    pub fn set_cleanup(&self, landing_pad: Value<'f>) {
        unsafe {
            llvm::LLVMSetCleanup(*landing_pad, lib::llvm::True);
        }
    }

    pub fn resume(&self, exn: Value<'f>) -> Value<'f> {
        unsafe {
            Value::new(llvm::LLVMBuildResume(self.llbuilder, *exn))
        }
    }

}

#[cfg(test)]
fn dummy_bb(f: |&ContextRef, BasicBlockRef, Value|) {
    unsafe {
        let ctx = &llvm::LLVMContextCreate();
        assert!(!ctx.is_null());
        let mod_ = llvm::LLVMModuleCreateWithNameInContext(noname(), *ctx);
        assert!(!mod_.is_null());
        let func = llvm::LLVMAddFunction(mod_, noname(), *Type::func(&[], Type::void(ctx)));
        assert!(!func.is_null());
        let bb = llvm::LLVMAppendBasicBlockInContext(*ctx, func, noname());
        assert!(!bb.is_null());
        f(ctx, bb, Value::new(func));
        llvm::LLVMContextDispose(*ctx);
    }
}

#[test]
fn test_bb() {
    dummy_bb(|ctx, bb, func| {
        let b = Builder::new(ctx, func);
        b.position_at_end(bb);
        let rv = b.ret_void();
        //assert_eq!(rv.get(), VRet(None));
        let alloca = b.alloca(Type::i32(ctx).ptr_to(), "");
        let load = b.load(alloca);
        //match alloca.get() { VAlloca{..} => (), _ => assert!(false) }
        //match load.get() { VLoad{..} => (), _ => assert!(false) }

        unsafe { llvm::LLVMDumpValue(*func) };
    });
}
