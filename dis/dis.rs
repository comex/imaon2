extern crate exec;
#[macro_use]
extern crate macros;
use exec::arch;

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
pub trait DisassemblerFamily : 'static {
    type Dis: Disassembler;
    fn create_disassembler(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Self::Dis>, Box<CreateDisError>>;

}
pub trait DisassemblerFamilyBoxy : 'static {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>>;
}
impl<T: DisassemblerFamily> DisassemblerFamilyBoxy for T {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[String]) -> Result<Box<Disassembler>, Box<CreateDisError>> {
        self.create_disassembler(arch, args).map(|bd| bd as Box<Disassembler>)
    }
}
pub fn a() -> &'static DisassemblerFamilyBoxy { panic!() }

