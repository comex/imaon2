extern crate libbindgen;
use std::fs::File;
use std::io::Write;
use std::fmt::Write as FmtWrite;
#[macro_use]
extern crate macros;
extern crate regex;
#[macro_use]
extern crate lazy_static;
use std::path::PathBuf;
pub fn do_bind(header_file_name: &str,
               include_components: &[&str]) {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let header_file = manifest_dir.join(header_file_name);
    let mut include_path = manifest_dir.parent().unwrap()
                                       .parent().unwrap()
                                       .to_owned();
    for c in include_components { include_path.push(c); }
    let bindings = libbindgen::builder()
        .header(header_file.to_str().expect("invalid Unicode in path to header file"))
        .clang_arg(format!("-I{}", include_path.to_str().expect("invalid Unicode in include path")))
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
}

