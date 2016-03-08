#![cfg_attr(opt, feature(alloc_system))]
#[cfg(opt)]
extern crate alloc_system;

use std::os::unix::ffi::{OsStringExt, OsStrExt};
use std::ffi::{OsStr, OsString};
use std::path::{Path, Component};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::sync::mpsc::channel;

#[macro_use]
extern crate macros;
extern crate util;
extern crate macho;
extern crate deps;
use macho::dyldcache::{DyldCache, ImageInfo};
use util::{ByteString, ByteStr};

use deps::threadpool::ThreadPool;
use deps::num_cpus;


fn extract_one(dc: &DyldCache, ii: &ImageInfo, outpath: &Path) {
    let mut macho = match dc.load_single_image(ii) {
        Ok(m) => m,
        Err(e) => { errln!("for '{}', parse Mach-O fail: {}", ii.path, e); return },
    };
    match macho.extract_as_necessary(Some(dc)) {
        Ok(()) => (),
        Err(e) => { errln!("for '{}', extract fail: {}", ii.path, e); return },
    }
    let mut fp = File::create(outpath).unwrap();
    fp.write_all(macho.eb.whole_buf.as_ref().unwrap().get()).unwrap();
}

#[cfg(unix)]
fn bstr_to_path(a: &ByteStr) -> Result<&Path, std::str::Utf8Error> {
    Ok(Path::new(OsStr::from_bytes(a)))
}
#[cfg(not(unix))]
fn bstr_to_path(a: &ByteStr) -> Result<&Path, std::str::Utf8Error> {
    Ok(Path::new(try!(str::from_utf8(a))))
}

fn usage() -> ! {
    println!(
    "Yet Another Shared Cache Extractor
    Usage: yasce <cache> [basename | full path | --all | blank to list files] [-o dir/file] [-v]"
    );
    util::exit();
}


fn main() {
    let mut base_args = Vec::new();
    let mut args_it = std::env::args_os();
    let mut output_name = None;
    let mut verbose = false;
    let mut extract_all = false;
    let dash_o = OsStr::new("-o");
    let dash_v = OsStr::new("-v");
    let dash_dash_all = OsStr::new("--all");
    let dash_dash = OsStr::new("--");
    while let Some(arg) = args_it.next() {
        if arg == dash_o {
            if output_name.is_some() {
                errln!("multiple -o specified");
                usage();
            }
            output_name = Some(args_it.next().unwrap_or_else(|| usage()));
        } else if arg == dash_v {
            verbose = true;
        } else if arg == dash_dash_all {
            extract_all = true;
        } else if arg == dash_dash {
            while let Some(arg) = args_it.next() {
                base_args.push(arg);
            }
        } else {
            base_args.push(arg);
        }
    }
    let argc = base_args.len();
    if argc != 2 && argc != 3 { usage(); }
    let dc_path = &base_args[1];
    let filename = base_args.get(2);

    let mut fp = File::open(&Path::new(&dc_path)).unwrap_or_else(|e| {
        errln!("open {:?} failed: {}", dc_path, e);
        util::exit();
    });

    let dc_buf = util::safe_mmap(&mut fp);
    let dc = DyldCache::new(dc_buf, false).unwrap_or_else(|e| {
        errln!("parse dyld cache format fail: {}", e);
        util::exit();
    });

    if let Some(filename) = filename {
        fn get_output_path<'a>(ii: &'a ImageInfo, output_name: &'a Option<OsString>) -> &'a Path {
            if let &Some(ref name) = output_name {
                Path::new(name)
            } else {
                bstr_to_path(ii.path.unix_basename()).unwrap()
            }
        };
        let filename = ByteString::from_vec(filename.to_owned().into_vec());
        let mut which_extracted: Option<&ByteStr> = None;
        for ii in &dc.image_info {
            if ii.path == filename {
                if which_extracted.is_some() {
                    errln!("warning: only extracted the first of multiple files with path '{}'", ii.path);
                    return;
                }
                extract_one(&dc, ii, get_output_path(ii, &output_name));
                which_extracted = Some(&ii.path);
            }
        }
        if which_extracted.is_some() { return; }
        let mut warned = false;
        for ii in &dc.image_info {
            if ii.path.unix_basename() == &*filename {
                if let Some(other) = which_extracted {
                    if !warned {
                        errln!("warning: extracted '{}' but also saw:", other);
                        warned = true;
                    }
                    errln!("    {}", ii.path);
                    continue;
                }
                extract_one(&dc, ii, get_output_path(ii, &output_name));
                which_extracted = Some(&ii.path);
            }
        }

        if which_extracted.is_none() {
            errln!("no library in cache is named '{}'", filename);
            util::exit();
        }
    } else if extract_all {
        let output_base = if let Some(ref name) = output_name {
            let ob = Path::new(name);
            if let Some(parent) = ob.parent() {
                if !parent.exists() {
                    errln!("no such directory: {:?}", parent);
                    util::exit();
                }
            }
            ob
        } else {
            Path::new("extracted")
        };

        let xdc = Arc::new(dc);
        let stuff = if verbose { None } else {
            let threads = num_cpus::get();
            let pool = ThreadPool::new(threads);
            let (tx, rx) = channel();
            Some((pool, tx, rx))
        };
        for (i, ii) in xdc.image_info.iter().enumerate() {
            let mut output_path = output_base.to_owned();
            assert_eq!(ii.path[0], b'/');
            let ii_path = bstr_to_path(&ii.path[1..]).unwrap();
            if ii_path.has_root() ||
               ii_path.components().any(|comp| comp == Component::ParentDir) {
                   panic!("evil? filename {}", ii.path);
            }
            output_path.push(ii_path);
            if let Some(p) = output_path.parent() {
                std::fs::create_dir_all(p).unwrap();
            }
            if let Some((ref pool, ref tx, _)) = stuff {
                let xdc_ = xdc.clone();
                let tx_ = tx.clone();
                pool.execute(move || {
                    let ii = &xdc_.image_info[i];
                    extract_one(&xdc_, ii, &output_path);
                    tx_.send(()).unwrap();
                });
            } else {
                println!("-> {}", ii.path);
                extract_one(&xdc, ii, &output_path);
            }
        }
        if let Some((_, _, ref rx)) = stuff {
            let count = xdc.image_info.len();
            print!("{}", format!("0/{} ", count));
            for i in 0..count {
                rx.recv().unwrap();
                let text = format!("\x1b[1K\x1b[999D{}/{} ", i, count);
                print!("{}", text);
            }
            println!("");
        }
    } else {
        // just list
        for ii in &dc.image_info {
            println!("{} @ 0x{:x}", ii.path, ii.address);
        }
    }
}
