extern crate libbindgen;
use std::fs::File;
use std::io::{Read, Write};
use std::fmt::Write as FmtWrite;
#[macro_use]
extern crate macros;
extern crate regex;
#[macro_use]
extern crate lazy_static;
use std::path::{PathBuf, Path};
use std::process::{Command, Stdio};
use std::ffi::{OsStr, OsString};
pub fn do_bind(header_file_name: &str,
               include_components: &[&str]) {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = get_out_dir();
    let depfile = out_dir.join("deps.d");
    let header_file = manifest_dir.join(header_file_name);
    let mut include_path = manifest_dir.parent().unwrap()
                                       .parent().unwrap()
                                       .to_owned();
    for c in include_components { include_path.push(c); }
    let bindings = libbindgen::builder()
        .header(header_file.to_str().expect("invalid Unicode in path to header file"))
        .clang_arg(format!("-I{}", include_path.to_str().expect("invalid Unicode in include path")))
        .clang_arg("-MMD").clang_arg("-MF").clang_arg(depfile.to_str().expect("invalid Unicode in depfile path"))
        .no_unstable_rust()
        .generate()
        .unwrap()
        .to_string();
    let bindings = re!(r"(#\[repr\(C\)\]\n#\[derive\()([^\)]*)(\)\]\npub struct )([^ ]*)( \{(?:.|\n)*?\n\})").replace_all(&bindings, |m: &regex::Captures| {
        let mut x = m.at(0).unwrap().to_owned();
        let mut swap_decl = String::new();
        if !re!(r"\*(const|mut)").is_match(&x) {
            x = format!("{}Default, {}{}{}{}", m.at(1).unwrap(), m.at(2).unwrap(), m.at(3).unwrap(), m.at(4).unwrap(), m.at(5).unwrap());
            let struct_name = m.at(4).unwrap();
            swap_decl = format!("impl Swap for {} {{\nfn bswap(&mut self) {{\n", struct_name);
            for n in re!("pub ([^ ]*):").captures_iter(&x) {
                write!(&mut swap_decl, "self.{}.bswap();\n", n.at(1).unwrap()).unwrap();
            }
            write!(&mut swap_decl, "{}", "}\n}\n").unwrap();
        }
        format!("{}\n{}", x, swap_decl)
    });
    write!(File::create(out_dir.join("out.rs")).unwrap(), "{}", bindings).unwrap();

    // add dependencies based on what clang outputted
    let mut deps = String::new();
    File::open(depfile).unwrap().read_to_string(&mut deps).unwrap();
    let start = deps.find(':').expect("no : in depfile") + 1;
    let mut deps = &deps[start..];
    while !deps.is_empty() {
        if deps.starts_with("\\\n") {
            deps = &deps[2..];
            continue;
        }
        if deps.starts_with(' ') {
            deps = &deps[1..];
            continue;
        }
        let mut rest = deps;
        loop {
            if let Some(i) = rest.find(' ') {
                let bs = i != 0 && rest.as_bytes()[i-1] == b'\\';
                rest = &rest[i+1..];
                if bs { continue; }
            } else {
                rest = "";
            }
            break;
        }
        let x = deps.len() - rest.len();
        let filename = deps[..x-1].replace("\\ ", " ");
        println!("cargo:rerun-if-changed={}", filename);
        deps = &deps[x..];
    }
}

pub fn rel(path: &Path, components: &[&str]) -> PathBuf {
    let mut ret = path.to_owned();
    for component in components { ret.push(component); }
    ret
}

pub fn run(c: &mut Command) {
    c.stdin(Stdio::inherit());
    c.stderr(Stdio::inherit());
    println!("{:?}", c);
    let output = match c.output() {
        Ok(o) => o,
        Err(e) => panic!("failed to run: {:?} - error: {:?}", c, e)
    };
    if !output.status.success() {
        panic!("process returned failure: {:?}", c);
    }
}

pub fn run_node(js: &Path, args: &[&OsStr]) {
    let node_path = format!("{}/node_modules:{}",
        std::env::var("DEP_FAKE_BUILD_NPM_UPDATE_NODEPATH").unwrap(),
        std::env::var("NODE_PATH").unwrap_or(String::new()));
    println!("NODE_PATH={}", node_path);
    run(&mut Command::new(
        std::env::var_os("NODE").unwrap_or(OsString::from("node")))
        .arg("--harmony")
        .arg("--use-strict")
        .arg(js)
        .args(args)
        .env("NODE_PATH", node_path));
}

#[cfg(unix)]
pub fn prefix_osstr<P: AsRef<OsStr>, S: AsRef<OsStr>>(prefix: P, suffix: S) -> OsString {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut prefix = prefix.as_ref().as_bytes().to_owned();
    let suffix = suffix.as_ref().as_bytes();
    prefix.extend_from_slice(suffix);
    OsString::from_vec(prefix)
}

#[cfg(windows)]
pub fn prefix_osstr<P: AsRef<OsStr>, S: AsRef<OsStr>>(prefix: P, suffix: S) -> OsString {
    // XXX untested
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let vec: Vec<u16> = prefix.as_ref().encode_wide().chain(suffix.as_ref().encode_wide()).collect();
    OsString::from_wide(&vec)
}

pub fn get_out_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
}
pub fn get_root_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    manifest_dir.parent().unwrap().parent().unwrap().to_owned()
}
pub fn get_llvm_src() -> PathBuf {
    PathBuf::from(std::env::var_os("LLVM_SRC").expect("need LLVM_SRC environment variable"))
}
