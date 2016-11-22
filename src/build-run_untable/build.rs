extern crate build_help;
use build_help::{prefix_osstr, rel};
use std::process::Command;
use std::ffi::{OsString};
fn main() {
    build_help::get_llvm_src(); // for panic
    let mut threads = Vec::new();
    for &(target_name, td_name) in &[
        ("X86", "X86.td"),
        ("ARM", "ARM.td"),
        ("Sparc", "Sparc.td"),
        ("Mips", "Mips.td"),
        ("AArch64", "AArch64.td"),
        ("PowerPC", "PPC.td"), // irregular
    ] {
        threads.push(std::thread::spawn(move || {
            let out_dir = build_help::get_out_dir();
            let out_td = rel(&out_dir, &[&format!("out-{}.td", target_name)]);
            let out_json = rel(&out_dir, &[&format!("out-{}.json", target_name)]);
            let llvm_src = build_help::get_llvm_src();
            build_help::run(&mut Command::new(
                std::env::var_os("LLVM_TBLGEN").unwrap_or(OsString::from("llvm-tblgen")))
                .arg(prefix_osstr("-I", &rel(&llvm_src, &["include"])))
                .arg(prefix_osstr("-I", &rel(&llvm_src, &["lib", "Target", target_name])))
                .arg(&rel(&llvm_src, &["lib", "Target", target_name, td_name]))
                .arg("-o")
                .arg(&out_td)
            );
            build_help::run_node("untable.js",
                                 &[out_td.as_ref(), out_json.as_ref()]);
        }));
    }
    for thread in threads { thread.join().unwrap(); }
    println!("cargo:outjsonpath={}", build_help::get_out_dir().to_str().unwrap());
}
