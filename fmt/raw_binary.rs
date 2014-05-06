extern crate exec;
extern crate util;
use exec::arch;

pub struct RawBinary {
    eb: exec::ExecBase,
    len: uint,
}

impl exec::Exec for RawBinary {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
}

impl RawBinary {
    pub fn new(len: uint, _args: &str) -> RawBinary {
        // todo: parse args
        let seg = exec::Segment {
            vmaddr: exec::VMA(0),
            vmsize: len as u64,
            fileoff: 0u64,
            filesize: len as u64,
            name: None,
            prot: exec::prot_all,
            private: 0,
        };
        RawBinary {
            len: len,
            eb: exec::ExecBase {
                arch: arch::UnknownArch,
                endian: util::BigEndian,
                segments: vec!(seg.clone()),
                sections: vec!(seg.clone()),
            }
        }
    }
}
pub struct RawProber;

impl exec::ExecProber for RawProber {
    fn name(&self) -> &str {
        "raw"
    }
    fn probe(&self, _: &[u8]) -> Vec<exec::ProbeResult> {
        vec!(exec::ProbeResult {
            desc: "raw".to_owned(),
            arch: arch::UnknownArch,
            likely: false,
            cmd: "".to_owned(),
        })
    }
    fn create(&self, buf: &[u8], pr: &exec::ProbeResult, args: &str) -> ~exec::Exec {
        let _ = pr; let _ = args;
        ~RawBinary::new(buf.len(), args) as ~exec::Exec
    }
}


