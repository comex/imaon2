extern crate macho;
extern crate elf;
extern crate exec;
pub fn all_probers() -> Vec<~self::exec::ExecProber> {
    vec!(
        box self::macho::MachOProber(),
    )
}
