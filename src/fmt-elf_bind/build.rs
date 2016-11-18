extern crate build_help;
fn main() {
    build_help::do_bind("elf_bind.h", &["externals", "elf"]);
}

