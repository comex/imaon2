#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate "bsdlike_getopts" as getopts;
extern crate exec;
extern crate sync;
extern crate native;
extern crate debug;
extern crate macho;

use native::io;
use std::rt::rtio;
use std::any::{AnyRefExt};
mod execall;

fn macho_filedata_info(mo: &macho::MachO) {
    println!("File data:");
    let entry = |mc: &util::MCRef, name| {
        match mc.offset_in(&mo.eb.buf) {
            None => (),
            Some(offset) => {
                println!("{}: offset {:#x}, length {:#x}",
                    name, offset, mc.len());
            }
        }
    };
    entry(&mo.symtab,         "symtab");
    entry(&mo.strtab,         "strtab");
    entry(&mo.toc,            "toc");
    entry(&mo.modtab,         "modtab");
    entry(&mo.extrefsym,      "extrefsym");
    entry(&mo.indirectsym,    "indirectsym");
    entry(&mo.dyld_rebase,    "dyld rebase");
    entry(&mo.dyld_bind,      "dyld bind");
    entry(&mo.dyld_weak_bind, "dyld weak_bind");
    entry(&mo.dyld_lazy_bind, "dyld lazy_bind");
    entry(&mo.dyld_export,    "dyld export");
}

fn do_stuff(ex: Box<exec::Exec>, m: getopts::Matches) {
    let eb = ex.get_exec_base();
    let macho = ex.as_any().downcast_ref::<macho::MachO>();
    if m.opt_present("segs") {
        println!("All segments:");
        for seg in eb.segments.iter() {
            println!("{:<16} @ {:<#18x} sz {:<#12x}  off:{:<#8x} filesz {:<#8x} {}",
                match seg.name { Some(ref n) => n.as_slice(), None => "(unnamed)" },
                seg.vmaddr.0, seg.vmsize,
                seg.fileoff, seg.filesize,
                seg.prot,
            );
        }
    }
    if m.opt_present("sects") {
        println!("All sections:");
        for seg in eb.sections.iter() {
            println!("{}", seg);
        }
    }
    if m.opt_present("syms") {
        println!("All symbols:");
        for sym in ex.get_symbol_list(exec::AllSymbols).iter() {
            let s = String::from_utf8_lossy(sym.name);
            println!("{}", s);
        }
    }
    if m.opt_present("macho-filedata-info") {
        macho_filedata_info(macho.expect("macho-filedata-info: not mach-o"));
    }
}

fn main() {
    let top = "Usage: exectool <binary> [format...] [-- ops...]";
    let mut optgrps = vec!(
        getopts::optflag("v", "verbose", "Verbose mode"),
        getopts::optopt( "",  "arch",  "Architecture bias", "arch"),
        getopts::optflag("",  "segs",  "List segments"),
        getopts::optflag("",  "sects", "List sections"),
        getopts::optflag("",  "syms",  "List symbols"),
        // todo: option groups
        getopts::optflag("",  "macho-filedata-info", "List data areas within the file"),
    );
    let mut args = std::os::args();
    args.remove(0);
    if args[0].as_slice().starts_with("-") {
        util::usage(top, &mut optgrps);
    }
    let filename = args.remove(0).unwrap();
    let mut fp = io::file::open(&filename.to_c_str(), rtio::Open, rtio::Read).unwrap_or_else(|e| {
        util::errln(format!("open {} failed: {}", filename, util::rtio_err_msg(e)));
        util::exit();
    });
    let mm = util::safe_mmap(&mut fp);
    if args.len() > 0 {
        if args[0].as_slice().starts_with("-") {
            let m_ = util::do_getopts(args.as_slice(), top, 0, 0, &mut optgrps);
            args.insert(0, "--".to_string());
            match m_.opt_str("arch") {
                Some(arch) => { args.insert(0, arch); args.insert(0, "--arch".to_string()); }
                None => ()
            }
            args.insert(0, "auto".to_string());
        }
        let (ex, real_args) = exec::create(&execall::all_probers(), mm.clone(), args);
        let m = util::do_getopts(real_args.as_slice(), top, 0, 0, &mut optgrps);
        do_stuff(ex, m)
    } else {
        let results = exec::probe_all(&execall::all_probers(), mm.clone());
        // no format specified, give a list
        for pr in results.iter() {
            let name = util::shell_quote(pr.cmd.as_slice());
            println!("? [{}] {}{}",
                name,
                pr.desc,
                if pr.likely { "" } else { " (unlikely)" },
            );
        }
    }
}
