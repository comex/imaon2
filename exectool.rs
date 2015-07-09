#![allow(non_camel_case_types)]

extern crate util;
extern crate bsdlike_getopts as getopts;
extern crate exec;
extern crate macho;
extern crate dis;
#[macro_use]
extern crate macros;

use std::fs;
use std::path::Path;
use std::io::Write;
use std::cmp::min;
use std::str::FromStr;

use util::VecCopyExt;
use exec::{arch, SymbolValue};
#[path = "fmt/execall.rs"] mod execall;
#[path = "dis/disall.rs"] mod disall;

fn macho_filedata_info(_mo: &macho::MachO) {
    panic!();
    /* XXX
    println!("File data:");
    let entry = |mc: &util::MCRef, name| {
        if let Some(offset) = mc.offset_in(&mo.eb.whole_buf.unwrap()) {
            println!("{:<16}: offset {:<#8x}, length {:<#8x}",
                name, offset, mc.len());
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
    */
}

fn get_dump_from_spec(ex: &Box<exec::Exec>, dump_spec: String) -> Vec<u8> {
    let eb = ex.get_exec_base();
    let z;
    let is_addr_end: bool;
    if let Some(z_) = dump_spec.find('+') {
        z = z_; is_addr_end = false;
    } else if let Some(z_) = dump_spec.find('-') {
        z = z_; is_addr_end = true;
    } else {
        panic!();
    }
    let addr: u64 = util::stoi(&dump_spec[..z]).unwrap();
    let mut size: u64 = util::stoi(&dump_spec[z+1..]).unwrap();
    assert!(size <= (std::usize::MAX as u64));
    let mut ret = Vec::with_capacity(size as usize);
    if is_addr_end { size -= addr; }

    let (mut addr, mut size) = (exec::VMA(addr), size);
    while size != 0 {
        if let Some((seg, off, mut osize)) = exec::addr_to_seg_off_range(&eb.segments, addr) {
            osize = min(osize, size);
            let buf = seg.data.as_ref().unwrap().get();
            ret.extend_slice(&buf[off as usize..(off+osize) as usize]);
            addr = addr + osize;
            size -= osize;
        } else {
            panic!("unmapped: {}", addr);
        }
    }

    ret
}

fn do_stuff(ex: &Box<exec::Exec>, m: &getopts::Matches) {
    let eb = ex.get_exec_base();
    let macho = ex.as_any().downcast_ref::<macho::MachO>();
    if m.opt_present("segs") {
        println!("All segments:");
        for seg in eb.segments.iter() {
            println!("{:<16} @ {:<#18x} sz {:<#12x}  off:{:<#12x} filesz {:<#8x} {}",
                match seg.name { Some(ref n) => &**n, None => "(unnamed)" },
                seg.vmaddr.0, seg.vmsize,
                seg.fileoff, seg.filesize,
                seg.prot,
            );
        }
    }
    if m.opt_present("sects") {
        println!("All sections:");
        for seg in eb.sections.iter() {
            println!("{:?}", seg);
        }
    }
    if m.opt_present("syms") {
        println!("All symbols:");
        for sym in ex.get_symbol_list(exec::SymbolSource::All).iter() {
            let name = String::from_utf8_lossy(sym.name);
            match sym.val {
                SymbolValue::Addr(vma) =>     print!("{:<16}", vma),
                SymbolValue::Undefined =>     print!("[undef]           "),
                SymbolValue::Resolver(vma) => print!("{:<16} [resolver]", vma),
                SymbolValue::ReExport(..) =>  print!("[re-export]       "),
            }
            print!(" ");
            if sym.is_public { print!("[pub] ") }
            if sym.is_weak   { print!("[weak] ") }
            println!("{}", name);
        }
    }
    if m.opt_present("macho-filedata-info") {
        macho_filedata_info(macho.expect("macho-filedata-info: not mach-o"));
    }
    if let Some(off_str) = m.opt_str("o2a") {
        let off: u64 = util::stoi(&off_str).unwrap();
        if let Some(exec::VMA(vma)) = exec::off_to_addr(&eb.segments, off, 0) {
            println!("0x{:x}", vma);
        } else {
            println!("-");
        }
    }
    if let Some(addr_str) = m.opt_str("a2o") {
        let addr: u64 = util::stoi(&addr_str).unwrap();
        if let Some(off) = exec::addr_to_off(&eb.segments, exec::VMA(addr), 0) {
            println!("0x{:x}", off);
        } else {
            println!("-");
        }
    }
    if let Some(dump_spec) = m.opt_str("dump") {
        let dump_data = get_dump_from_spec(ex, dump_spec);
        std::io::stdout().write(&*dump_data).unwrap();
    }
    if let Some(dump_spec) = m.opt_str("dis-range") {
        let arch = match m.opt_str("arch") {
            Some(arch_s) => arch::Arch::from_str(&*arch_s).unwrap(),
            None => arch::Arch::UnknownArch,
        };
        let dis = dis::create(disall::all_families, arch, &[]).unwrap();
        let dump_data = get_dump_from_spec(ex, dump_spec);
        //std::io::stdout().write(&*dump_data);
    }
}

fn do_mut_stuff(mut ex: Box<exec::Exec>, m: &getopts::Matches) {
    if let Some(out_file) = m.opt_str("extract") {
        // TODO generic
        let macho = ex.as_any_mut().downcast_mut::<macho::MachO>().unwrap();
        macho.reallocate();
        macho.rewhole();
        let mut fp = fs::File::create(&Path::new(&out_file)).unwrap();
        fp.write_all(macho.eb.whole_buf.as_ref().unwrap().get()).unwrap();
    }
}

fn usage_panic<T>(s: String) -> T {
    errln!("{}", s);
    util::exit()
}

fn main() {
    let top = "Usage: exectool <binary> [format...] [-- ops...]";
    let mut optgrps = vec!(
        getopts::optflag("v", "verbose", "Verbose mode"),
        getopts::optopt( "",  "arch",  "Architecture bias", "arch"),
        getopts::optflag("",  "segs",  "List segments"),
        getopts::optflag("",  "sects", "List sections"),
        getopts::optflag("",  "syms",  "List symbols"),
        getopts::optopt( "",  "o2a",   "Offset to address", "off"),
        getopts::optopt( "",  "a2o",   "Address to offset", "addr"),
        getopts::optopt( "",  "dump",  "Dump address range", "addr+len"),
        getopts::optopt( "",  "dis-range",   "Disassemble address range", "addr+len"),
        getopts::optopt( "",  "dis",   "Disassembler name and options", "llvm/..."),
        getopts::optopt( "",  "extract", "Rewrite whole file", "outfile"),
        // todo: option groups
        getopts::optflag("",  "macho-filedata-info", "List data areas within the file"),
    );
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(0);
    if args[0].starts_with("-") {
        usage_panic::<()>(util::usage(top, &mut optgrps));
    }
    let filename = args.remove(0);
    let mut fp = fs::File::open(&Path::new(&filename)).unwrap_or_else(|e| {
        errln!("open {} failed: {}", filename, e);
        util::exit();
    });
    let mm = util::safe_mmap(&mut fp);
    if args.len() > 0 {
        if args[0].starts_with("-") {
            let m_ = util::do_getopts_or_usage(&*args, top, 0, 0, &mut optgrps).unwrap_or_else(usage_panic);
            args.insert(0, "--".to_string());
            if let Some(arch) = m_.opt_str("arch") {
                args.insert(0, arch);
                args.insert(0, "--arch".to_string());
            }
            args.insert(0, "auto".to_string());
        }
        let (ex, real_args) = exec::create(&execall::all_probers(), mm.clone(), args).unwrap_or_else(|e| {
            if e.kind == exec::ErrorKind::InvalidArgs {
                errln!("{}", e.message);
                util::exit();
            } else {
                panic!("error: {:?}", e);
            }
        });
        let m = util::do_getopts_or_usage(&*real_args, top, 0, 0, &mut optgrps).unwrap_or_else(usage_panic);
        do_stuff(&ex, &m);
        do_mut_stuff(ex, &m);
    } else {
        let results = exec::probe_all(&execall::all_probers(), mm.clone());
        // no format specified, give a list
        for pr in results.iter() {
            let name = util::shell_quote(&*pr.cmd);
            println!("? [{}] {}{}",
                name,
                pr.desc,
                if pr.likely { "" } else { " (unlikely)" },
            );
        }
    }
}
