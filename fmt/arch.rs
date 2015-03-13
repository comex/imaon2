use std::default::Default;
use std::str::FromStr;
pub use self::Arch::*;

#[derive(PartialEq, Eq, Debug, Copy)]
pub enum Arch {
    X86,
    X86_64,
    ARM,
    AArch64,
    Sparc,
    Mips,
    PowerPC,
    UnknownArch,
}

impl Default for Arch {
    fn default() -> Arch { UnknownArch }
}

impl FromStr for Arch {
    type Err = ();
    fn from_str(s: &str) -> Result<Arch, ()> {
        let s = s.replace("-", "_").to_lowercase();
        if s == "x86" || s == "i386" {
            Ok(X86)
        } else if s == "x86_64" || s == "amd64" {
            Ok(X86_64)
        } else if s == "arm" {
            Ok(ARM)
        } else if s == "arm64" || s == "aarch64" {
            Ok(AArch64)
        } else if s == "sparc" {
            Ok(Sparc)
        } else if s == "mips" {
            Ok(Mips)
        } else if s == "ppc" || s == "powerpc" {
            Ok(PowerPC)
        } else {
            Err(())
        }
    }
}
