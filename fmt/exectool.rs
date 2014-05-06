#![feature(macro_rules)]
#![allow(non_camel_case_types)]

extern crate util;
extern crate getopts;
extern crate exec;

use native::io;
mod execall;

fn main() {
    let m = util::do_getopts("Usage: exectool <binary>", 1, &[
        getopts::optflag("v", "verbose", "Verbose mode"),
        getopts::optflag("h", "help", "This help"),
    ]);
    let filename = m.free.get(0);
    let mut fp = io::file::open(&filename.to_c_str(), std::io::Open, std::io::Read).unwrap_or_handle(|e| {
        util::errln(format!("open {} failed: {}", filename, e.desc));
        util::exit();
    });
    let mm = util::SafeMMap::new(&mut fp);
    let ap = execall::all_probers();
    let results = exec::probe_all(&ap, mm.get());
    // if we specified one... else...
    let likely: Vec<&(&'static exec::ExecProber, exec::ProbeResult)> = results.iter().filter(|&&(_, ref pr)| pr.likely).collect();
    if likely.len() == 0 {
        util::errln(format!("open {}: no formats were likely", filename));
        util::exit();
    }
    // TODO: fuck this shit, PR should be stringly typed so that alternatives can be accessed from command line
    for &(ref ep, ref pr) in results.iter() {
        println!("? [{}] {}{}",
            ep.name(),
            pr.desc,
            if pr.likely { "" } else { " (unlikely)" },
        ); 
    }
}
