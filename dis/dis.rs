extern crate exec;
use exec::arch;
use std::error::Error;

pub trait Disassembler : 'static {
    fn can_disassemble_to_str(&self) -> bool { false }
    fn disassemble_to_str(&self, _bytes: &[u8]) -> String { unimplemented!() }
}
pub trait DisassemblerFamily {
    type Dis: Disassembler;
    fn create_disassembler(&self, arch: arch::Arch, args: &[&str]) -> Result<Box<Self::Dis>, Box<Error>>;

}
pub trait DisassemblerFamilyBoxy {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[&str]) -> Result<Box<Disassembler>, Box<Error>>;
}
impl<T: DisassemblerFamily> DisassemblerFamilyBoxy for T {
    fn create_disassembler_box(&self, arch: arch::Arch, args: &[&str]) -> Result<Box<Disassembler>, Box<Error>> {
        self.create_disassembler(arch, args).map(|bd| bd as Box<Disassembler>)
    }
}
pub fn a() -> &'static DisassemblerFamilyBoxy { panic!() }

