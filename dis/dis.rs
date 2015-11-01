#![feature(box_syntax)]
extern crate exec;
#[macro_use]
extern crate macros;
use exec::arch;
use std::marker::PhantomData;

#[derive(Debug)]
pub enum CreateDisError {
    InvalidArgs(String),
    // there should be no need to use a box here, but rustc is borked, yay!
    Other(Box<std::error::Error>),
}
display_as_debug!(CreateDisError);
impl std::error::Error for CreateDisError {
    fn description(&self) -> &str {
        match self {
            &CreateDisError::InvalidArgs(ref s) => s,
            &CreateDisError::Other(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &CreateDisError::InvalidArgs(..) => None,
            &CreateDisError::Other(ref e) => Some(&**e),
        }
    }
}

pub struct DisassemblerInput<'a> {
    pub data: &'a [u8],
    pub pc: exec::VMA,
}

pub trait Disassembler : 'static {
    fn arch(&self) -> &arch::ArchAndOptions;
    fn can_disassemble_to_str(&self) -> bool { false }
    fn disassemble_insn_to_str(&self, _input: DisassemblerInput) -> Option<(String, u32)> { unimplemented!() }
    fn disassemble_multiple_to_str(&self, input: DisassemblerInput) -> Vec<(String, exec::VMA, u32)> {
        let mut result = Vec::new();
        let mut off = 0;
        let nia = self.arch().natural_insn_align();
        while off < input.data.len() {
            if let Some((dissed, length)) = self.disassemble_insn_to_str(DisassemblerInput { data: &input.data[off..], pc: input.pc + (off as u64)}) {
                result.push((dissed, input.pc + (off as u64), length));
                off += length as usize;
            } else {
                off += nia as usize;
            }
        }
        result
    }
    // todo - disassemble_all_to_str?
}
pub trait DisassemblerStatics : Disassembler {
    fn new_with_args(arch: arch::ArchAndOptions, args: &[String]) -> Result<Self, CreateDisError>;
    fn name() -> &'static str;
}

pub trait DisassemblerFamily : Sync + 'static {
    fn create_disassembler(&self, arch: arch::ArchAndOptions, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>>;
    fn name(&self) -> &str;
}

pub struct DisassemblerFamilyImpl<Dis: 'static>(pub PhantomData<fn()->Dis>);
impl<Dis: DisassemblerStatics> DisassemblerFamily for DisassemblerFamilyImpl<Dis> {
    fn create_disassembler(&self, arch: arch::ArchAndOptions, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
        Dis::new_with_args(arch, args).map(|dis| box dis as Box<Disassembler>).map_err(|err| box err)
    }
    fn name(&self) -> &str { Dis::name() }
}

pub fn create(dfs: &[&'static DisassemblerFamily], arch: arch::ArchAndOptions, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
    if args.len() == 0 {
        return Err(box CreateDisError::InvalidArgs("empty argument list passed to dis::create".to_owned()));
    }
    let name = &args[0];
    for df in dfs.iter() {
        if df.name() == name {
            return df.create_disassembler(arch, &args[1..]);
        }
    }
    Err(box CreateDisError::InvalidArgs(format!("no disassembler named {}", name)))
}
