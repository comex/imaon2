// This file is public domain.

extern crate rustc;
use rustc::lib::llvm::{UseRef, ValueRef, Use_opaque};
use std::libc::c_uint;

extern {
    pub fn LLVMShimReplaceUse(use_: UseRef, repl: ValueRef);
    pub fn LLVMShimGetOperandList(val: ValueRef) -> &mut [Use_opaque];
    // Might be nice to use something like bindgen to generate structure
    // offsets and let these be inlined... librustc should ship a LTO version
    // but using rustc's LLVM is a hack anyway.  Plus, LTO is slow.
    pub fn LLVMShimGetValueID(val: ValueRef) -> c_uint;
    pub fn LLVMShimGetSubclassData(val: ValueRef) -> c_uint;
    pub fn LLVMShimGetSubclassOptionalData(val: ValueRef) -> c_uint;
}

static InstructionVal: int = 22;

#[deriving(Show, Eq, FromPrimitive)]
pub enum Opcode {
    Argument,
    BasicBlock,
    Function,
    GlobalAlias,
    GlobalVariable,
    UndefValue,
    BlockAddress,
    ConstantExpr,
    ConstantAggregateZero,
    ConstantDataArray,
    ConstantDataVector,
    ConstantInt,
    ConstantFP,
    ConstantArray,
    ConstantStruct,
    ConstantVector,
    ConstantPointerNull,
    MDNode,
    MDString,
    InlineAsm,
    PseudoSourceValue,
    FixedStackPseudoSourceValue,

    Instruction,

    /* Terminator Instructions */
    Ret            = InstructionVal+1,
    Br             = InstructionVal+2,
    Switch         = InstructionVal+3,
    IndirectBr     = InstructionVal+4,
    Invoke         = InstructionVal+5,
    /* removed 6 due to API changes */
    Unreachable    = InstructionVal+7,

    /* Standard Binary Operators */
    Add            = InstructionVal+8,
    FAdd           = InstructionVal+9,
    Sub            = InstructionVal+10,
    FSub           = InstructionVal+11,
    Mul            = InstructionVal+12,
    FMul           = InstructionVal+13,
    UDiv           = InstructionVal+14,
    SDiv           = InstructionVal+15,
    FDiv           = InstructionVal+16,
    URem           = InstructionVal+17,
    SRem           = InstructionVal+18,
    FRem           = InstructionVal+19,

    /* Logical Operators */
    Shl            = InstructionVal+20,
    LShr           = InstructionVal+21,
    AShr           = InstructionVal+22,
    And            = InstructionVal+23,
    Or             = InstructionVal+24,
    Xor            = InstructionVal+25,

    /* Memory Operators */
    Alloca         = InstructionVal+26,
    Load           = InstructionVal+27,
    Store          = InstructionVal+28,
    GetElementPtr  = InstructionVal+29,

    /* Cast Operators */
    Trunc          = InstructionVal+30,
    ZExt           = InstructionVal+31,
    SExt           = InstructionVal+32,
    FPToUI         = InstructionVal+33,
    FPToSI         = InstructionVal+34,
    UIToFP         = InstructionVal+35,
    SIToFP         = InstructionVal+36,
    FPTrunc        = InstructionVal+37,
    FPExt          = InstructionVal+38,
    PtrToInt       = InstructionVal+39,
    IntToPtr       = InstructionVal+40,
    BitCast        = InstructionVal+41,

    /* Other Operators */
    ICmp           = InstructionVal+42,
    FCmp           = InstructionVal+43,
    PHI            = InstructionVal+44,
    Call           = InstructionVal+45,
    Select         = InstructionVal+46,
    UserOp1        = InstructionVal+47,
    UserOp2        = InstructionVal+48,
    VAArg          = InstructionVal+49,
    ExtractElement = InstructionVal+50,
    InsertElement  = InstructionVal+51,
    ShuffleVector  = InstructionVal+52,
    ExtractValue   = InstructionVal+53,
    InsertValue    = InstructionVal+54,

    /* Atomic operators */
    Fence          = InstructionVal+55,
    AtomicCmpXchg  = InstructionVal+56,
    AtomicRMW      = InstructionVal+57,

    /* Exception Handling Operators */
    Resume         = InstructionVal+58,
    LandingPad     = InstructionVal+59
}

#[deriving(Show, Eq, FromPrimitive)]
pub enum AtomicOrdering {
    AtomicOrderingNotAtomic = 0,
    AtomicOrderingUnordered = 1,
    AtomicOrderingMonotonic = 2,
    AtomicOrderingAcquire = 4,
    AtomicOrderingRelease = 5,
    AtomicOrderingAcquireRelease = 6,
    AtomicOrderingSequentiallyConsistent = 7
}
