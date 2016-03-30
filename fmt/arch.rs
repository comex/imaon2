use ::{getopts, util};
use std::default::Default;
use std::str::FromStr;
use util::{Endian, LittleEndian, BigEndian};
pub use self::Arch::*;
pub use self::CodeMode::*;
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
        } else if s == "arm" || s == "armv7" || s == "armv6" {
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
    pub _please_use_default: (),
}

pub type ARMOptions = _EndianOptions;

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct _EndianOptions {
    pub endian: Endian,
    pub _please_use_default: (),
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ArchAndOptions {
    X86(NoOptionsYet),
    X86_64(NoOptionsYet),
    ARM(ARMOptions),
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
    pub fn new(args: &[String]) -> Result<ArchAndOptions, String> {
        if args.len() == 0 { return Err("empty args".to_owned()); }
        let arch = try!(Arch::from_str(&*args[0]).map_err(|()| "unknown arch"));
        match arch {
            ARM => {
                let m = try!(util::do_getopts_or_usage(&args[1..], &*args[0], 0,0, &mut vec![
                    getopts::optopt("E", "endian", "Endian", "little/big/L/B"),
                ]));
                let endian_str = m.opt_str("endian");
                let endian_str = if let Some(ref s) = endian_str { Some(&**s) } else { None }; // XXX wtf
                let endian = match endian_str {
                    Some("L") | Some("l") | Some("little") => LittleEndian,
                    Some("B") | Some("b") | Some("big") => BigEndian,
                    Some(x) => return Err(format!("bad endian spec {}", x)),
                    None => return Err("no endian specified".to_owned()),
                };
                Ok(ArchAndOptions::ARM(ARMOptions { endian: endian, ..ARMOptions::default() }))
            },
            _ => {
                if args.len() > 0 {
                    return Err(format!("arch {} accepts no args", arch));
                }
                Ok(ArchAndOptions::new_default(arch))
            },
        }

    }
}

macro_rules! arch_into {
    ($($archs:ident),*) => {
        impl ArchAndOptions {
            pub fn new_default(arch: Arch) -> Self {
                match arch {
                    $($archs => ArchAndOptions::$archs(Default::default())),*,
                }
            }
        }
        impl ArchAndOptions {
            pub fn arch(&self) -> Arch {
                match self {
                    $(&ArchAndOptions::$archs(..) => Arch::$archs),*,
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
    pub fn new(arch: &ArchAndOptions, args: &[String]) -> Result<CodeMode, String> {
        match arch {
            &ArchAndOptions::ARM(..) => {
                let m = try!(util::do_getopts_or_usage(&args, "[--thumb]", 0, 0, &mut vec![
                    getopts::optflag("t", "thumb", "Thumb"),
                ]));
                Ok(CodeMode::ARMMode { thumb: m.opt_present("thumb") })
            },
            _ => {
                let m = try!(util::do_getopts_or_usage(&args, "[no options]", 0, 0, &mut vec![]));
                Ok(CodeMode::OtherMode)
            },
        }
    }
}
