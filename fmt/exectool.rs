#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate "bsdlike_getopts" as getopts;
extern crate exec;
extern crate sync;
extern crate native;
extern crate debug;

use native::io;
use std::rt::rtio;
mod execall;

fn do_stuff(ex: Box<exec::Exec>, m: getopts::Matches) {
    let eb = ex.get_exec_base();
    if m.opt_present("list-segs") {
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
    if m.opt_present("list-sects") {
        println!("All sections:");
        for seg in eb.sections.iter() {
            println!("{}", seg);
        }
    }
}

fn main() {
    let top = "Usage: exectool <binary> [format...] [-- ops...]";
    let mut optgrps = vec!(
        getopts::optflag("v", "verbose", "Verbose mode"),
        getopts::optopt( "",  "arch", "Architecture bias", "arch"),
        getopts::optflag("",  "list-segs", "List segments"),
        getopts::optflag("",  "list-sects", "List sections"),
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
