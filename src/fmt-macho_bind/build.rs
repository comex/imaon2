extern crate build_help;
fn main() {
    build_help::do_bind("macho_bind.h", &["externals", "mach-o"]);
}
