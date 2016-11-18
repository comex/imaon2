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
fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let macho_bind_h = manifest_dir.join("macho_bind.h");
    let externals_macho = manifest_dir.parent().unwrap()
                                      .parent().unwrap()
                                      .join("externals").join("mach-o");
    let bindings = libbindgen::builder()
        .header(macho_bind_h.to_str().expect("invalid Unicode in path to macho_bind.h"))
        .clang_arg(format!("-I{}", externals_macho.to_str().expect("invalid Unicode in path to externals/mach-o")))
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
