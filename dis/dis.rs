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

pub trait Disassembler : 'static {
    fn can_disassemble_to_str(&self) -> bool { false }
    fn disassemble_to_str(&self, _bytes: &[u8]) -> String { unimplemented!() }
}
pub trait DisassemblerStatics : Disassembler {
    fn new_with_args(arch: arch::Arch, args: &[String]) -> Result<Self, CreateDisError>;
    fn name() -> &'static str;
}

pub trait DisassemblerFamily : Sync + 'static {
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>>;
    fn name(&self) -> &str;
}

pub struct DisassemblerFamilyImpl<Dis: 'static>(pub PhantomData<fn(Dis)>);
impl<Dis: DisassemblerStatics> DisassemblerFamily for DisassemblerFamilyImpl<Dis> {
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
        Dis::new_with_args(arch, args).map(|dis| box dis as Box<Disassembler>).map_err(|err| box err)
    }
    fn name(&self) -> &str { Dis::name() }
}

pub fn create(dfs: &[&'static DisassemblerFamily], arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
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
