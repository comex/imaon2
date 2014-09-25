extern crate exec;
extern crate util;
use exec::arch;

pub struct RawBinary {
    eb: exec::ExecBase,
}

impl exec::Exec for RawBinary {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
}

impl RawBinary {
    pub fn new(buf: util::MCRef, _args: Vec<String>) -> RawBinary {
        let len = buf.get().len();
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
            eb: exec::ExecBase {
                arch: arch::UnknownArch,
                endian: util::BigEndian,
                segments: vec!(seg.clone()),
                sections: vec!(seg.clone()),
                buf: Some(buf),
            }
        }
    }
}
pub struct RawProber;

impl exec::ExecProber for RawProber {
    fn name(&self) -> &str {
        "raw"
    }
    fn probe(&self, _eps: &Vec<&'static exec::ExecProber>, _: util::MCRef) -> Vec<exec::ProbeResult> {
        vec!(exec::ProbeResult {
            desc: "raw".to_string(),
            arch: arch::UnknownArch,
            likely: false,
            cmd: vec!("raw".to_string()),
        })
    }
    fn create(&self, _eps: &Vec<&'static exec::ExecProber>, buf: util::MCRef, args: Vec<String>) -> (Box<exec::Exec>, Vec<String>) {
        (box RawBinary::new(buf, args) as Box<exec::Exec>, vec!())
    }
}

