extern crate build_help;
use std::path::PathBuf;
use std::ffi::OsStr;
fn main() {
    let out_json_path = PathBuf::from(std::env::var_os("DEP_FAKE_BUILD_RUN_UNTABLE_OUTJSONPATH").unwrap());
    let mut threads = Vec::new();
    const X: &'static [(&'static str, &'static str, &'static [&'static str])] = &[
        ("ARM", "ARM", &["-n", "_arm"]),
        ("Thumb", "ARM", &["-n", "_thumb"]),
        ("Thumb2", "ARM", &["-n", "_thumb2"]),
        ("AArch64", "AArch64", &[]),
    ];
    for &(combo_name, arch_name, extra_args) in X {
        let out_json = out_json_path.join(format!("out-{}.json", arch_name));
        let my_out = build_help::get_out_dir();
        let debug_dis_c = my_out.join(format!("debug-dis-{}.c", combo_name));
        let jump_dis_c = my_out.join(format!("jump-dis-{}.c", combo_name));
        threads.push(std::thread::spawn(move || {
            let mut args: Vec<&OsStr> = vec![
                OsStr::new("-l"), OsStr::new("c"),
                OsStr::new("--gen-debug-disassembler"),
                debug_dis_c.as_os_str(),
                OsStr::new("--gen-jump-disassembler"),
                jump_dis_c.as_os_str(),
                out_json.as_os_str(),
            ];
            args.extend(extra_args.iter().map(OsStr::new));
            build_help::run_node("gen.js", &args);
        }));
    }
    for thread in threads { thread.join().expect("join"); }
    println!("cargo:ddpath={}", build_help::get_out_dir().to_str().unwrap());
}
