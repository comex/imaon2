extern crate gcc;
const VARIANTS: &'static [&'static str] =
    &["AArch64", "ARM", "Thumb", "Thumb2"];
fn main() {
    let ddpath = std::path::PathBuf::from(std::env::var_os("DEP_FAKE_BUILD_RUN_GEN_DDPATH").unwrap());
    let mut handles = Vec::new();
    for variant_name in VARIANTS {
        let ddpath = ddpath.clone();
        handles.push(std::thread::spawn(move || {
            gcc::Config::new()
                .file("boilerplate.c")
                .include(ddpath)
                .define("FUNC_NAME", Some(&format!("debug_dis_{}", variant_name)))
                .define("INCLUDE_PATH", Some(&format!("\"debug-dis-{}.c\"", variant_name)))
                .compile(&format!("lib{}.a", variant_name));
        }));
    }
    for handle in handles { handle.join().unwrap(); }
}
