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
    let mut fp = io::file::open(&(*m.free.get(0)).to_c_str(), std::io::Open, std::io::Read).unwrap();
    let mm = util::SafeMMap::new(&mut fp);
    let ap = execall::all_probers();
    let results = exec::probe_all(&ap, mm.get());
    for &(_, ref pr) in results.iter() {
        println!("? {}", pr.desc); 
    }
}
