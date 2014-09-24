#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate getopts;
extern crate exec;
extern crate sync;
extern crate native;

use native::io;
use std::rt::rtio;
mod execall;

fn main() {
    let mut args = std::os::args();
    args.remove(0);
    let mut m = util::do_getopts(args.as_slice(),
        "Usage: exectool <binary> [format...]", 1, std::uint::MAX, &mut vec!(
            getopts::optflag("v", "verbose", "Verbose mode"),
    ));
    let filename = m.free.remove(0).unwrap();
    let mut fp = io::file::open(&filename.to_c_str(), rtio::Open, rtio::Read).unwrap_or_else(|e| {
        util::errln(format!("open {} failed: {}", filename, util::rtio_err_msg(e)));
        util::exit();
    });
    let mm = util::safe_mmap(&mut fp);
    let results = exec::probe_all(&execall::all_probers(), mm.clone());
    if m.free.len() >= 1 {
        exec::create(&execall::all_probers(), mm.clone(), m.free);
    } else {
        // no format specified, give a list
        let likely: Vec<&(&'static exec::ExecProber, exec::ProbeResult)> = results.iter().filter(|&&(_, ref pr)| pr.likely).collect();
        if likely.len() == 0 {
            util::errln(format!("open {}: no formats were likely", filename));
            util::exit();
        }
        for &(_, ref pr) in results.iter() {
            let name = util::shell_quote(pr.cmd.as_slice());
            println!("? [{}] {}{}",
                name,
                pr.desc,
                if pr.likely { "" } else { " (unlikely)" },
            );
        }
    }
}
