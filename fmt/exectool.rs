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
    let m = util::do_getopts("Usage: exectool <binary>", 1, &[
        getopts::optflag("v", "verbose", "Verbose mode"),
        getopts::optflag("h", "help", "This help"),
    ]);
    let filename = m.free.get(0);
    let mut fp = io::file::open(&filename.to_c_str(), rtio::Open, rtio::Read).unwrap_or_else(|e| {
        util::errln(format!("open {} failed: {}", filename, util::rtio_err_msg(e)));
        util::exit();
    });
    let mm = sync::Arc::new(util::safe_mmap(&mut fp));
    let ap = execall::all_probers();
    let results = exec::probe_all(&ap, mm.clone());
    // if we specified one... else...
    let likely: Vec<&(&'static exec::ExecProber, exec::ProbeResult)> = results.iter().filter(|&&(_, ref pr)| pr.likely).collect();
    if likely.len() == 0 {
        util::errln(format!("open {}: no formats were likely", filename));
        util::exit();
    }
    for &(ref ep, ref pr) in results.iter() {
        let name = if pr.cmd.len() != 0 {
            format!("{} {}", ep.name(), util::shell_quote(pr.cmd.as_slice()))
        } else {
            ep.name().to_string()
        };
        println!("? [{}] {}{}",
            name,
            pr.desc,
            if pr.likely { "" } else { " (unlikely)" },
        ); 
    }
}
