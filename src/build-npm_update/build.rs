extern crate build_help;
use std::process::Command;
use std::ffi::OsString;
fn main() {
    build_help::run(&mut Command::new(
        std::env::var_os("NPM").unwrap_or(OsString::from("npm")))
        .arg("--prefix").arg(build_help::get_out_dir())
        .arg("install")
        .arg(build_help::get_root_dir().join("tables")));
    println!("cargo:nodepath={}", build_help::get_out_dir().to_str().unwrap());
}
