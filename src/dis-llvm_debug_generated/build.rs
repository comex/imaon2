extern crate build_help;
fn main() {
    build_help::copydir(std::path::Path::new(&std::env::var_os("DEP_FAKE_BUILD_RUN_GEN_DDPATH").unwrap()),
                        &build_help::get_out_dir().join("dd"));
}
