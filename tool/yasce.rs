#![feature(stmt_expr_attributes)]

#![cfg_attr(opt, feature(alloc_system))]
#[cfg(opt)]
extern crate alloc_system;

use std::os::unix::ffi::{OsStringExt, OsStrExt};
use std::os::unix::fs::symlink;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf, Component};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::sync::mpsc::channel;

#[macro_use]
extern crate macros;
extern crate util;
extern crate macho;
extern crate exec;
use macho::dyldcache::{DyldCache, ImageInfo, ImageCache};
use util::{ByteString, ByteStr};
use exec::arch;

extern crate deps;
use deps::threadpool::ThreadPool;
use deps::num_cpus;

fn extract_one(dc: &DyldCache, ii: &ImageInfo, outpath: &Path, image_cache: Option<&ImageCache>) {
    let mut macho = match dc.load_single_image(ii) {
        Ok(m) => m,
        Err(e) => { errln!("for '{}', parse Mach-O fail: {}", ii.path, e); return },
    };
    if let Some(ic) = image_cache {
        macho.fix_text_relocs_from_cache(ic, dc);
    }
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
    let dc = DyldCache::new(dc_buf, false, true).unwrap_or_else(|e| {
        errln!("parse dyld cache format fail: {}", e);
        util::exit();
    });
    let image_cache = Arc::new(if dc.eb.arch == arch::AArch64 {
        Some(ImageCache::new(&dc))
    } else { None });

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
                extract_one(&dc, ii, get_output_path(ii, &output_name),
                            (*image_cache).as_ref());
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
                extract_one(&dc, ii, get_output_path(ii, &output_name),
                            (*image_cache).as_ref());
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
        let canon = xdc.make_canonical_path_map();
        let mut wait_count = 0;
        let stuff = if verbose { None } else {
            let threads = num_cpus::get();
            let pool = ThreadPool::new(threads);
            let (tx, rx) = channel();
            Some((pool, tx, rx))
        };
        for (i, (ii, &canonical_idx)) in xdc.image_info.iter().zip(&canon).enumerate() {
            fn get_output_path(mut res: PathBuf, path_bstr: &ByteStr) -> (PathBuf, &Path) {
                assert!(path_bstr.len() > 0 && path_bstr[0] == b'/');
                let path = bstr_to_path(&path_bstr[1..]).unwrap();
                if path.has_root() ||
                   path.components().any(|comp| comp == Component::ParentDir) {
                       panic!("evil? filename {}", path_bstr);
                }
                res.push(path);
                (res, path)
            }
            let (output_path, output_rel) = get_output_path(output_base.to_owned(), &ii.path);
            if let Some(p) = output_path.parent() {
                std::fs::create_dir_all(p).unwrap();
            }
            if canonical_idx != i {
                let target = &xdc.image_info[canonical_idx].path;
                #[cfg(not(unix))]
                println!("* would symlink {} to {}, but not on Unix, to skipping"
                         &ii.path, target);
                #[cfg(unix)]
                {
                    let mut dot_dots = PathBuf::new();
                    for component in output_rel.parent().unwrap().components() {
                        if let Component::Normal(..) = component {
                            dot_dots.push("../");
                        }
                    }
                    let (target_path, _) = get_output_path(dot_dots, target);
                    let _ = std::fs::remove_file(&output_path);
                    symlink(&target_path, &output_path).unwrap();
                    continue;
                }
            }
            if let Some((ref pool, ref tx, _)) = stuff {
                let xdc_ = xdc.clone();
                let tx_ = tx.clone();
                let image_cache_ = image_cache.clone();
                wait_count += 1;
                pool.execute(move || {
                    let ii = &xdc_.image_info[i];
                    extract_one(&xdc_, ii, &output_path,
                                (*image_cache_).as_ref());
                    tx_.send(()).unwrap();
                });
            } else {
                println!("-> {}", ii.path);
                extract_one(&xdc, ii, &output_path,
                            (*image_cache).as_ref());
            }
        }
        if let Some((_, _, ref rx)) = stuff {
            print!("{}", format!("0/{} ", wait_count));
            for i in 0..wait_count {
                rx.recv().unwrap();
                let text = format!("\x1b[1K\x1b[999D{}/{} ", i, wait_count);
                print!("{}", text);
            }
            println!("");
        }
    } else {
        // just list
        let canon = dc.make_canonical_path_map();
        for (i, (ii, &canonical_idx)) in dc.image_info.iter().zip(&canon).enumerate() {
            print!("{} @ 0x{:x}", ii.path, ii.address);
            if canonical_idx != i {
                print!(" [-> {}]", dc.image_info[canonical_idx].path);
            }
            println!("");
        }
    }
}
