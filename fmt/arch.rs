use ::{getopts, util};
use std::default::Default;
use std::str::FromStr;
pub use self::Arch::*;
pub use self::CodeMode::*;
use std;
use std::fmt;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
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
        if s == "x86" || s == "i386" || s == "i486" || s == "i586" || s == "i686" {
            Ok(X86)
        } else if s == "x86_64" || s == "x86-64" || s == "amd64" {
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

impl Arch {
    fn name(self) -> &'static str {
        match self {
            X86 => "x86",
            X86_64 => "x86_64",
            ARM => "arm",
            AArch64 => "aarch64",
            Sparc => "sparc",
            Mips => "mips",
            PowerPC => "powerpc",
            UnknownArch => "unknown",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name())
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct NoOptionsYet {
    pub please_use_default: (),
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ArchAndOptions {
    X86(NoOptionsYet),
    X86_64(NoOptionsYet),
    ARM(NoOptionsYet),
    AArch64(NoOptionsYet),
    Sparc(NoOptionsYet),
    Mips(NoOptionsYet),
    PowerPC(NoOptionsYet),
    UnknownArch(NoOptionsYet),
}

impl Default for ArchAndOptions {
    fn default() -> ArchAndOptions { ArchAndOptions::UnknownArch(Default::default()) }
}

impl ArchAndOptions {
    pub fn natural_insn_align(&self, mode: &CodeMode) -> u32 {
        match self {
            &ArchAndOptions::ARM(..) => match mode {
                &ARMMode { thumb } => if thumb { 2 } else { 4 },
                _ => panic!(),
            },
            &ArchAndOptions::AArch64(..) | &ArchAndOptions::PowerPC(..) => 4, // xxx others
            &ArchAndOptions::X86(..) | &ArchAndOptions::X86_64(..) => 1,
            _ => 1,
        }
    }
    pub fn new(args: Vec<String>) -> Result<(ArchAndOptions, Vec<String>), String> {
        if args.len() == 0 { return Err("empty args".to_owned()); }
        let arch = try!(Arch::from_str(&*args[0]).map_err(|()| "unknown arch"));
        match arch {
            _ => {
                let m = try!(util::do_getopts_or_usage(&args[1..], &*args[0], 0, std::usize::MAX, &mut vec![]));
                Ok((arch.into(), m.free))
            },
        }

    }
}

macro_rules! arch_into {
    ($($archs:ident),*) => {
        impl Into<ArchAndOptions> for Arch {
            fn into(self) -> ArchAndOptions {
                match self {
                    $($archs => ArchAndOptions::$archs(Default::default())),*,
                }
            }
        }
        impl Into<Arch> for ArchAndOptions {
            fn into(self) -> Arch {
                match self {
                    $(ArchAndOptions::$archs(..) => Arch::$archs),*,
                }
            }
        }
    }
}

arch_into!(X86, X86_64, ARM, AArch64, Sparc, Mips, PowerPC, UnknownArch);

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum CodeMode {
    ARMMode { thumb: bool },
    OtherMode,
}

impl CodeMode {
    pub fn new(arch: &ArchAndOptions, args: Vec<String>) -> Result<(CodeMode, Vec<String>), String> {
        match arch {
            &ArchAndOptions::ARM(..) => {
                let m = try!(util::do_getopts_or_usage(&args, "[--thumb]", 0, std::usize::MAX, &mut vec![
                    getopts::optflag("t", "thumb", "Thumb"),
                ]));
                Ok((CodeMode::ARMMode { thumb: m.opt_present("thumb") }, m.free))
            },
            _ => {
                let m = try!(util::do_getopts_or_usage(&args, "[no options]", 0, std::usize::MAX, &mut vec![]));
                Ok((CodeMode::OtherMode, m.free))
            },
        }
    }
}
