// this is basically a copy of the macho one, xxx dedup
extern crate libbindgen;
use std::fs::File;
use std::io::Write;
#[macro_use]
extern crate macros;
extern crate regex;
#[macro_use]
extern crate lazy_static;
use std::path::PathBuf;
fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let elf_h = manifest_dir.parent().unwrap()
                            .parent().unwrap()
                            .join("externals").join("elf").join("elf.h");
    libbindgen::builder()
        .header(elf_h.to_str().expect("invalid Unicode in path to elf.h"))
        .no_unstable_rust()
        .generate()
        .unwrap()
        .to_string();
    let bindings = re!(r"#\[repr\(C\)\]\n#\[derive\([^\)]*\)\]\npub struct [^ ]* \{(?:.|\n)*?\n\}").replace_all(&bindings, "deriving_swap! {\n$0\n}");
    write!(File::create(out_dir.join("out.rs")).unwrap(), "{}", bindings).unwrap();
}
