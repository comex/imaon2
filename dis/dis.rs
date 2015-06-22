extern crate exec;
use exec::arch;

#[derive(Clone, Debug)]
pub enum Error {
    InvalidArgs(String),
    Other(Error),
}
display_as_debug!(Error);

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &InvalidArgs(ref s) => s,
            &Other(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option(&std::error::Error) {
        match self {
            &InvalidArgs(..) => None,
            &Other(ref e) => e,
        }
    }
}

pub trait Disassembler : 'static {
    fn can_disassemble_to_str(&self) -> bool { false }
    fn disassemble_to_str(&self, _bytes: &[u8]) -> String { unimplemented!() }
}
pub trait DisassemblerFamily {
    type Dis: Disassembler;
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Self::Dis>, Box<CreateDisError>>;

}
pub trait DisassemblerFamilyBoxy {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>>;
}
impl<T: DisassemblerFamily> DisassemblerFamilyBoxy for T {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
        self.create_disassembler(arch, args).map(|bd| bd as Box<Disassembler>)
    }
}
pub fn a() -> &'static DisassemblerFamilyBoxy { panic!() }

