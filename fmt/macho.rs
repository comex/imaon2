#![feature(phase)]
#![feature(globs)]
#[phase(link, syntax)]
extern crate util;
extern crate exec;
extern crate collections;
use std::default::Default;
use collections::HashMap;
use std::vec::Vec;
use std::mem::size_of;
use macho_bind::*;
use exec::arch;

mod macho_bind;

#[deriving(Default)]
pub struct MachO {
    eb: exec::ExecBase,
    mh: mach_header,
    seg_cmds: Vec<uint>,
    sect_cmds: Vec<uint>,
}

impl exec::Exec for MachO {
    fn get_exec_base<'a>(&'a self) -> &'a exec::ExecBase {
        &self.eb
    }
}

impl MachO {
    pub fn new(buf: &[u8], settings: &HashMap<&str, &str>) -> MachO {
        let mut me: MachO = Default::default();

        let _ = settings;
        let mut lc_off = size_of::<mach_header>();
        let magic: u32 = util::copy_from_slice(buf.slice_to(4), util::BigEndian);
        let is64; let end;
        match magic {
            0xfeedface => { end = util::BigEndian; is64 = false; }
            0xfeedfacf => { end = util::BigEndian; is64 = true; }
            0xcefaedfe => { end = util::LittleEndian; is64 = false; }
            0xcffaedfe => { end = util::LittleEndian; is64 = true; }
            _ => fail!("shouldn't happen due to probe")
        }
        me.eb.endian = end;
        me.mh = util::copy_from_slice(buf.slice(0, lc_off), end);
        // useless 'reserved' field
        if is64 { lc_off += 4; }

        me.parse_header();
        me.parse_load_commands(buf, lc_off);
        me
    }

    fn parse_header(&mut self) {
        self.eb.arch = match self.mh.cputype.to_uint().unwrap() {
            CPU_TYPE_X86 => arch::X86,
            CPU_TYPE_X86_64 => arch::X86_64,
            CPU_TYPE_ARM => arch::ARM,
            CPU_TYPE_ARM64 => arch::AArch64,
            CPU_TYPE_POWERPC => arch::PowerPC,
            CPU_TYPE_POWERPC64 => arch::PowerPC,
            // Even if we don't know the arch, we can at least do something.
            _ => arch::UnknownArch,
        }
        // we don't really care about cpusubtype but could fill it in
    }

    fn parse_load_commands(&mut self, buf: &[u8], mut lc_off: uint) {
        let end = self.me.endian;
        for i in range(0, self.mh.ncmds - 1) {
            let lc: load_command = util::copy_from_slice(buf.slice(lc_off, lc_off + 8), end);
            let data = buf.slice(lc_off, lc_off + lc.cmdsize);
            let do_segment = |is64: bool| {
                let segsize; let sectsize;
                let sc: segment_command_64;
                if is64 {
                    segsize = size_of::<segment_command_64>;
                    sectsize = size_of::<section_64>;
                } else {
                    segsize = size_of::<segment_command>;
                    sectsize = size_of::<section>;
                }
                /*
                let sc = sbranch!(data.slice_to(segsize), segment_command_64, segment_command, (cmd, cmdsize, segname, vmaddr, vmsize, 
                    sc = util::copy_from_slice(data.slice_to(segsize));
                } else {
                    let sc32 = util::copy_from_slice(data.slice_to(segsize));
                    sc = struct_conv!(segment_command_64, segment_command, 

                }
                    size_of::<segment_command>()), end);
                    
                */
            };
            match lc.cmd.to_uint().unwrap() {
                LC_SEGMENT => do_segment(false),
                LC_SEGMENT_64 => do_segment(true),


                _ => ()
            }
            lc_off += lc.cmdsize;
        }
    }
}


pub struct MachOProber();

impl exec::ExecProber for MachOProber {
    fn probe(&self, buf: &[u8]) -> bool {
        if buf.len() < 4 { return false; }
        let magic: u32 = util::copy_from_slice(buf.slice_to(4), util::BigEndian);
        match magic {
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe => true,
            _ => false
        }
    }
    fn create(&self, buf: &[u8], settings: &HashMap<&str, &str>) -> ~exec::Exec {
        ~MachO::new(buf, settings) as ~exec::Exec
    }
}

//#[test]

