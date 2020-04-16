extern crate build_help;
fn main() {
    let ddpath = std::path::PathBuf::from(std::env::var_os("DEP_FAKE_BUILD_RUN_GEN_DDPATH").unwrap());
    build_help::copydir(&ddpath, &build_help::get_out_dir());
}

