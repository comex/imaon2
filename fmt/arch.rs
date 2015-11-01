use ::{getopts, util};
use std::default::Default;
use std::str::FromStr;
pub use self::Arch::*;
use std;

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

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct ARMOptions {
    pub thumb: bool,
    pub please_use_default: (),
}

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct NoOptionsYet {
    pub please_use_default: (),
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

    UnknownArch,
}

impl Default for ArchAndOptions {
    fn default() -> ArchAndOptions { ArchAndOptions::UnknownArch }
}

impl ArchAndOptions {
    pub fn natural_insn_align(&self) -> u32 {
        match self {
            &ArchAndOptions::ARM(ARMOptions { thumb, .. }) => if thumb { 2 } else { 4 },
            &ArchAndOptions::AArch64(..) | &ArchAndOptions::PowerPC(..) => 4, // xxx others
            &ArchAndOptions::X86(..) | &ArchAndOptions::X86_64(..) => 1,
            _ => 1,
        }
    }
    pub fn new(args: Vec<String>) -> Result<(ArchAndOptions, Vec<String>), String> {
        if args.len() == 0 { return Err("empty args".to_owned()); }
        let arch = try!(Arch::from_str(&*args[0]).map_err(|()| "unknown arch"));
        match arch {
            ARM => {
                let m = try!(util::do_getopts_or_usage(&args[1..], "arm [--thumb]", 0, std::usize::MAX, &mut vec![
                    getopts::optflag("t", "thumb", "Thumb"),
                ]));
                Ok((ArchAndOptions::ARM(ARMOptions {
                    thumb: m.opt_present("thumb"),
                    ..Default::default()
                }), m.free))
            },
            _ => {
                let m = try!(util::do_getopts_or_usage(&args[1..], &*args[0], 0, std::usize::MAX, &mut vec![]));
                Ok((arch.into(), m.free))
            },
        }

    }
}

macro_rules! arch_into {
    ($this:expr, $($archs:ident),*) => {
        match $this {
            $($archs => ArchAndOptions::$archs(Default::default())),*,
            _ => ArchAndOptions::UnknownArch,
        }
    }
}

impl Into<ArchAndOptions> for Arch {
    fn into(self) -> ArchAndOptions {
        arch_into!(self, X86, X86_64, ARM, AArch64, Sparc, Mips, PowerPC)
    }

}

