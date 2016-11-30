#![allow(non_camel_case_types)]
#![feature(stmt_expr_attributes)] // disall
#![cfg_attr(opt, feature(alloc_system))]

#[cfg(opt)]
extern crate alloc_system;

extern crate util;
extern crate bsdlike_getopts as getopts;
extern crate exec;
extern crate fmt_macho as macho;
extern crate fmt_macho_dsc_extraction as macho_dsc_extraction;
extern crate fmt_elf as elf;
extern crate dis;
#[macro_use]
extern crate macros;
extern crate dis_all;
extern crate fmt_all;

use std::fs;
use std::path::Path;
use std::io::Write;
use std::cmp::min;
use std::str::FromStr;
use std::any::Any;

use util::{VecCopyExt, into_cow, Ext};
use exec::{arch, SymbolValue, VMA};
use exec::arch::{ArchAndOptions, CodeMode};

fn macho_filedata_info(mo: &macho::MachO) {
    println!("File data:");
    let entry = |mc: &util::Mem<u8>, name| {
        if let Some(offset) = mc.offset_in(&mo.eb.whole_buf.as_ref().unwrap()) {
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
}

fn elf_dynamic_raw(elf: &elf::Elf) {
    println!("raw .dynamic entries:");
    for dyn in &elf.dyns {
        println!("{}: 0x{:x}",
                  dyn.tag_name().map_or_else(
                    || panic!(),//into_cow(&*format!("<0x{:x}>", dyn.tag)),
                    |n| into_cow::<'static, str, &'static str>(n)),
                  dyn.val);

    }
}
fn elf_dynamic(elf: &mut elf::Elf) {
    elf.dynamic_info.dump(Some(elf));
}

fn get_dump_from_spec(ex: &Box<exec::Exec>, dump_spec: String) -> Result<Vec<u8>, String> {
    let eb = ex.get_exec_base();
    let z;
    let is_addr_end: bool;
    if let Some(z_) = dump_spec.find('+') {
        z = z_; is_addr_end = false;
    } else if let Some(z_) = dump_spec.find('-') {
        z = z_; is_addr_end = true;
    } else {
        return Err(format!("invalid dump spec '{}' - should be addr+len or addr1-addr2", dump_spec));
    }
    let addr: u64 = util::stoi(&dump_spec[..z]).unwrap();
    let mut size: u64 = util::stoi(&dump_spec[z+1..]).unwrap();
    assert!(size <= (std::usize::MAX as u64));
    let mut ret = Vec::with_capacity(size as usize);
    if is_addr_end {
        // 'size' is actually end
        if size < addr {
            return Err(format!("in dump spec '{}', end < start", dump_spec));
        }
        size -= addr;
    }

    let (mut addr, mut size) = (VMA(addr), size);
    while size != 0 {
        if let Some((seg, off, osize)) = exec::addr_to_seg_off_range(&eb.segments, addr) {
            let osize = min(osize, size);
            if osize > seg.filesize {
                return Err(format!("zerofill at: {} (in segment '{}')", addr + seg.filesize, seg.pretty_name()));
            }
            let buf = seg.data.as_ref().unwrap().get();
            ret.extend_slice(&buf[off as usize..(off+osize) as usize]);
            addr = addr + osize;
            size -= osize;
        } else {
            return Err(format!("unmapped at: {}", addr));
        }
    }

    Ok(ret)
}

fn print_segs(segs: &[exec::Segment]) {
    let pretty_names: Vec<_> = segs.iter().map(|s| s.pretty_name()).collect();
    let maxlen = pretty_names.iter().map(|pn| pn.len()).max().unwrap_or(0);
    let mut sorted: Vec<_> = segs.iter().collect();
    sorted.sort_by_key(|seg| (seg.vmaddr, !seg.vmsize));
    for seg in sorted.into_iter() {
        println!("{:<6$} @ {:<#18x} sz {:<#12x}  off {:<#12x} filesz {:<#8x} {}",
                 seg.pretty_name(),
                 seg.vmaddr.0, seg.vmsize,
                 seg.fileoff, seg.filesize,
                 seg.prot,
                 maxlen);
    }
}

fn do_stuff(ex: &Box<exec::Exec>, m: &getopts::Matches) {
    let eb = ex.get_exec_base();
    let macho = ex.as_any().downcast_ref::<macho::MachO>();
    let elf = ex.as_any().downcast_ref::<elf::Elf>();
    if m.opt_present("segs") {
        println!("All segments:");
        print_segs(&eb.segments);
    }
    if m.opt_present("sects") {
        println!("All sections:");
        print_segs(&eb.sections);
    }
    let mut elf_specific = elf::ElfGetSymbolListSpecific::default();
    if m.opt_present("elf-append-version") {
        assert!(elf.is_some());
        elf_specific.append_version = true;
    }
    const KINDS: &'static [(&'static str, &'static str, exec::SymbolSource)] = &[
        ("syms", "All symbols", exec::SymbolSource::All),
        ("imports", "Imported symbols", exec::SymbolSource::Imported),
        ("exports", "Exported symbols", exec::SymbolSource::Exported),
    ];
    for &(name, desc, kind) in KINDS {
        if !m.opt_present(name) { continue; }
        println!("{}:", desc);
        let opts = if elf.is_some() {
            Some(&elf_specific as &Any)
        } else { None };
        for sym in ex.get_symbol_list(kind, opts) {
            let name = sym.name.lossy();
            match sym.val {
                SymbolValue::Addr(vma) =>        print!("{:<16}", vma),
                SymbolValue::Abs(vma) =>         print!("{:<16}", vma),
                SymbolValue::Undefined(..) =>    print!("[undef]         "),
                SymbolValue::Resolver(vma, _) => print!("{:<16}", vma),
                SymbolValue::ReExport(_, _) =>   print!("[re-export]     "),
                SymbolValue::ThreadLocal(vma) => print!("{:<16}", vma),
            }
            print!(" {}", name);
            if sym.is_public { print!(" [pub]") }
            if sym.is_weak   { print!(" [weak]") }
            match sym.val {
                SymbolValue::Abs(_) =>                  print!(" [abs]"),
                SymbolValue::ThreadLocal(..) =>         print!(" [thread]"),
                SymbolValue::Resolver(_, None) =>       print!(" [resolver]"),
                SymbolValue::Resolver(_, Some(stub)) => print!(" [resolver stub={:<16}]", stub),
                SymbolValue::ReExport(ref name, sl) =>  print!(" => {} (source={:?})", name, sl),
                _ => ()
            }
            println!("");
        }
    }
    if m.opt_present("dep-libs") {
        println!("Library dependencies:");
        for dl in &*ex.get_dep_libs() {
            println!("{}", ex.describe_dep_lib(dl));
        }

    }
    if m.opt_present("relocs") {
        println!("Relocations:");
        for rel in ex.get_reloc_list(None) {
            println!("addr={} kind={:?}", rel.address, rel.kind);
            /*
            if let Some(add) = rel.addend {
                println!(" addend=0x{:x}", add);
            } else {
                println!("");
            }
            */
        }
    }
    if m.opt_present("macho-filedata-info") {
        macho_filedata_info(macho.expect("macho-filedata-info: not mach-o"));
    }
    if let Some(off_str) = m.opt_str("o2a") {
        let off: u64 = util::stoi(&off_str).unwrap();
        if let Some(VMA(vma)) = exec::off_to_addr(&eb.segments, off, 0) {
            println!("0x{:x}", vma);
        } else {
            println!("-");
        }
    }
    if let Some(addr_str) = m.opt_str("a2o") {
        let addr: u64 = util::stoi(&addr_str).unwrap();
        if let Some(off) = exec::addr_to_off(&eb.segments, VMA(addr), 0) {
            println!("0x{:x}", off);
        } else {
            println!("-");
        }
    }
    if let Some(dump_spec) = m.opt_str("dump") {
        match get_dump_from_spec(ex, dump_spec) {
            Ok(dump_data) => {std::io::stdout().write(&*dump_data).unwrap();},
            Err(msg) => errln!("dump error: {}", msg),
        };
    }
    let arch = match m.opt_str("arch") {
        Some(arch_s) => arch::Arch::from_str(&*arch_s).unwrap(),
        None => arch::Arch::UnknownArch,
    };
    // XXXXX
    let arch_opts: ArchAndOptions = ArchAndOptions::new_default(arch);
    // XXX should accept multiple copies of these
    let mut dis_opts = vec!["llvmdis".to_owned()];
    if let Some(name) = m.opt_str("dis") {
        // XXX I should probably support [ and ] - also depends on customizing getopts
        dis_opts = vec![name.to_owned()];
    }
    if let Some(dump_spec) = m.opt_str("dis-range") {
        let dis = dis::create(dis_all::ALL_FAMILIES, arch_opts, &dis_opts).unwrap();
        let dump_data = get_dump_from_spec(ex, dump_spec).unwrap();
        let base_pc = VMA(0);
        let results = dis.disassemble_multiple_to_str(dis::DisassemblerInput {
            data: &dump_data[..],
            pc: base_pc,
            mode: CodeMode::new(&arch_opts, &[]).unwrap(), // XXX
        });
        let mut last_end: VMA = base_pc;
        for (dissed, pc, length) in results {
            let diff = last_end - pc;
            if diff != 0 {
                println!("...skip {}", diff);
            }
            println!("-> {}: {}", pc,
                if let Some(ref s) = dissed { &s[..] } else { "<?>" });
            last_end = pc + length.ext();
        }
        let expected_end = base_pc + (dump_data.len() as u64);
        if last_end < expected_end {
            println!("...skip {}", expected_end - last_end);
        } else if last_end > expected_end {
            println!("...over-read by {}", last_end - expected_end);
        }
    }
}

fn do_mut_stuff(ex: &mut exec::Exec, m: &getopts::Matches) {
    fn get_elf<'a>(exe: &'a mut exec::Exec) -> &'a mut elf::Elf { exe.as_any_mut().downcast_mut::<elf::Elf>().expect("not elf") }
    fn get_macho<'a>(exe: &'a mut exec::Exec) -> &'a mut macho::MachO { exe.as_any_mut().downcast_mut::<macho::MachO>().expect("not macho") }
    if let Some(out_file) = m.opt_str("extract") {
        // TODO generic
        let macho = get_macho(ex);
        macho_dsc_extraction::extract_as_necessary(macho, None, None, /*minimal_processing*/ false).unwrap();
        let mut fp = fs::File::create(&Path::new(&out_file)).unwrap();
        fp.write_all(macho.eb.whole_buf.as_ref().unwrap().get()).unwrap();
    }
    if m.opt_present("elf-dynamic") {
        let elf = get_elf(ex);
        elf_dynamic(elf);
    }
    if m.opt_present("elf-dynamic-raw") {
        let elf = get_elf(ex);
        elf_dynamic_raw(elf);
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
        getopts::optflag("",  "exports","List exported symbols"),
        getopts::optflag("",  "imports","List imported symbols"),
        getopts::optflag("",  "dep-libs", "List library dependencies"),
        getopts::optflag("",  "relocs", "List relocs"),
        getopts::optopt( "",  "o2a",   "Offset to address", "off"),
        getopts::optopt( "",  "a2o",   "Address to offset", "addr"),
        getopts::optopt( "",  "dump",  "Dump address range", "addr+len"),
        getopts::optopt( "",  "dis-range",   "Disassemble address range", "addr+len"),
        getopts::optopt( "",  "dis",   "Disassembler name and options", "llvm/..."),
        getopts::optopt( "",  "extract", "Rewrite whole file", "outfile"),
        // todo: option groups
        getopts::optflag("",  "macho-filedata-info", "List data areas within the file"),
        getopts::optflag("",  "elf-dynamic", "List ELF .dynamic contents"),
        getopts::optflag("",  "elf-dynamic-raw", "List ELF .dynamic contents (raw)"),
        getopts::optflag("",  "elf-append-version", "When listing symbols, include @VERSION"),
    );
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1].starts_with("-") {
        usage_panic::<()>(util::usage(top, &mut optgrps));
    }
    args.remove(0);
    let filename = args.remove(0);
    let mut fp = fs::File::open(&Path::new(&filename)).unwrap_or_else(|e| {
        errln!("open {} failed: {}", filename, e);
        util::exit();
    });
    let mm = util::memmap(&fp).unwrap();
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
        let (mut ex, real_args) = exec::create(&fmt_all::all_probers(), mm.clone(), args).unwrap_or_else(|e| {
            if e.kind == exec::ErrorKind::InvalidArgs {
                errln!("{}", e.message);
                util::exit();
            } else {
                panic!("error: {:?}", e);
            }
        });
        let m = util::do_getopts_or_usage(&*real_args, top, 0, 0, &mut optgrps).unwrap_or_else(usage_panic);
        do_stuff(&ex, &m);
        do_mut_stuff(&mut *ex, &m);
    } else {
        let results = exec::probe_all(&fmt_all::all_probers(), mm.clone());
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
