use std::default::Default;
use std::str::FromStr;
pub use self::Arch::*;

#[deriving(PartialEq, Eq, Show, Copy)]
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
    fn from_str(s: &str) -> Option<Arch> {
        let s: String = s.replace("-", "_").chars().map(|c| c.to_lowercase()).collect();
        if s == "x86" || s == "i386" {
            Some(X86)
        } else if s == "x86_64" || s == "amd64" {
            Some(X86_64)
        } else if s == "arm" {
            Some(ARM)
        } else if s == "arm64" || s == "aarch64" {
            Some(AArch64)
        } else if s == "sparc" {
            Some(Sparc)
        } else if s == "mips" {
            Some(Mips)
        } else if s == "ppc" || s == "powerpc" {
            Some(PowerPC)
        } else {
            None
        }
    }
}
