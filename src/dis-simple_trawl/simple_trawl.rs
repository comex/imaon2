#[macro_use] extern crate macros;
extern crate dis_generated_jump_dis;
extern crate exec;
extern crate util;
extern crate arrayvec;

use self::dis_generated_jump_dis::{Reg, MAX_REGS, GenericHandler, TargetAddr, InsnInfo, InsnKind, Addrish, Size8};
use std::collections::VecDeque;
use self::exec::{VMA, Segment};
use util::{Narrow, Endian, Unsigned, ReadCell, BitSet32, Zeroable, Ext, ExtWrapper};
use std::mem::{replace, transmute};
use std::cmp::min;

use arrayvec::ArrayVec;

simple_bitflags! {
    BBFlags: u8 {
        valid/set_valid: bool << 0,
        rwkv_meaningful/set_rwkv_meaningful: bool << 1,
        have_next_block/set_have_next_block: bool << 2,
        queued/set_queued: bool << 3,
        switch_queued/set_switch_queued: bool << 4,
    }
}

const FLAGS_REG: Reg = Reg(31); // derp

struct BabyBlock {
    next_block: u32,
    flags: BBFlags,
    start_off: u8,
    end_off: u8, // inclusive
    // these refer to the beginning of the block
    regs_with_known_val: BitSet32,
    reg_vals_off: u32,
    notables_off: u32,
}
unsafe impl Zeroable for BabyBlock {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetKind {
    None,
    AddReg,
    Other,
    Whatever,
    Cmp,
}
impl Default for SetKind { fn default() -> Self { SetKind::None } }

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
struct RegVal {
    val: u64,
    have_val: bool,
    set_kind: SetKind,
    reg: Reg,
    set_off: u32,
}
unsafe impl Zeroable for RegVal {}
impl RegVal {
    fn intersect(&self, other: &RegVal) -> RegVal {
        debug_assert!(self.reg == other.reg);
        RegVal {
            have_val: self.have_val && other.have_val && self.val == other.val,
            val: self.val,
            set_kind: if self.set_kind == other.set_kind && self.set_off == other.set_off { self.set_kind } else { SetKind::None },
            reg: self.reg,
            set_off: self.set_off,
        }
    }
}


impl BabyBlock {
    #[inline]
    fn reg_val<'a>(&self, reg: Reg, reg_vals: &'a mut [RegVal]) -> Option<&'a mut RegVal> {
        let xreg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        if rwkv.has(xreg) {
            let position = (self.reg_vals_off.ext_usize()) + (rwkv.subset(0..xreg).count().ext_usize());
            debug_assert!(reg_vals[position].reg == reg);
            Some(&mut reg_vals[position])
        } else { None }
    }
    fn set_rwkv(&mut self, new_rwkv: BitSet32, my_vals: &[RegVal; MAX_REGS], reg_vals: &mut Vec<RegVal>) {
        self.regs_with_known_val = new_rwkv;
        self.flags.set_rwkv_meaningful(true);
        let new_off = reg_vals.len();
        for reg in new_rwkv.set_bits() {
            reg_vals.push(my_vals[reg.ext_usize()]);
        }
        self.reg_vals_off = new_off.narrow().unwrap();
    }
}

pub const CODEMAP_BB_GRAIN: usize = 32;

#[derive(Copy, Clone)]
pub struct Notable {
    pub valid: bool,
    pub off: u32,
    pub target_addr: VMA,
}

struct CodeMapBBData {
    bbs: Vec<BabyBlock>,
    extra_bbs: Vec<BabyBlock>,
}

pub struct CodeMap<'a> {
    region_start: VMA,
    region_size: usize,
    insn_data: &'a [ReadCell<u8>],
    bb_data: CodeMapBBData,
    reg_vals: Vec<RegVal>,
    queue: VecDeque<usize>,
    switch_queue: Vec<usize>,
    notables: Vec<Notable>,
    endian: Endian,
    lscache: Option<Box<LastSetterCache>>,
}

struct LastSetterCache {
    start_off: usize,
    end_off: usize,
    regs_with_known_val: BitSet32,
    reg_vals_off: u32,
    new_vals: ArrayVec<[(u8, RegVal); CODEMAP_BB_GRAIN]>,
    end_reg_vals: [RegVal; MAX_REGS],
    end_rwkv: BitSet32,

}

#[derive(Clone, Copy, Debug)]
pub enum GrokSwitchFail {
    GettingSetterOfBrAddr,
    GettingSetterOfAddR1,
    GettingSetterOfAddR2,
    ShiftMismatch,
    NeitherAddendLooksLikeTable,
    GettingTableAbaseValue,
    GettingTableAddrValue,
    FindingCmp,
    CmpWeirdInsn,
    //CmpIdxRegKilled,
    TableTooBig,
    TableReadError,
}

fn do_enqueue(bb: &mut BabyBlock, off: usize, queue: &mut VecDeque<usize>, notables: &mut Vec<Notable>) {
    if !bb.flags.queued() {
        queue.push_back(off);
        bb.flags.set_queued(true);
        if bb.notables_off != 0 {
            let end = off + (bb.end_off - bb.start_off).ext_usize();
            let mut idx = bb.notables_off.ext_usize();
            while let Some(n) = notables.get_mut(idx) {
                idx += 1;
                if n.valid && n.off.ext_usize() <= end {
                    n.valid = false;
                } else {
                    break;
                }
            }
        }
    }
}

impl CodeMapBBData {
    fn bb_for_off<'a>(&'a mut self, off: usize, queue: &mut VecDeque<usize>, notables: &mut Vec<Notable>) -> &'a mut BabyBlock {
        //println!("bb_for_off 0x{:x}", off);
        let slot = off / CODEMAP_BB_GRAIN;
        let slot_off = (off % CODEMAP_BB_GRAIN) as u8;
        let mut x = &mut self.bbs[slot];
        loop {
            if !x.flags.valid() {
                // initialize
                x.flags.set_valid(true);
                x.start_off = slot_off;
                x.end_off = (CODEMAP_BB_GRAIN - 1) as u8;
                //println!("case 0");
                return x;
            }
            let start_off = x.start_off;
            if slot_off == start_off {
                //println!("cae 1");
                return x;
            } else if slot_off < start_off {
                let idx: u32 = self.extra_bbs.len().narrow().unwrap();
                let mut new = BabyBlock::zeroed();
                new.flags.set_valid(true);
                new.flags.set_have_next_block(true);
                new.next_block = idx;
                new.start_off = slot_off;
                new.end_off = start_off - 1;
                let old = replace(x, new);
                self.extra_bbs.push(old);
                return x;
            } else { // slot_off > start_off
                let past_end = slot_off > x.end_off;
                if past_end && x.flags.have_next_block() {
                    let next_block = x.next_block.ext_usize();
                    drop(x);
                    // XXX with nonlexical lifetimes this shouldn't be necessary
                    // as self.extra_bbs should be definitely unborrowed after the drop() calls
                    let hack_extra_bbs: &'static mut Vec<BabyBlock> = unsafe { transmute(&mut self.extra_bbs) };
                    x = &mut hack_extra_bbs[next_block];
                    continue;
                } else {
                    //println!("cae 3 x.so={:x} eo={:x}", x.start_off, x.end_off);
                    let idx: u32 = self.extra_bbs.len().narrow().unwrap();
                    let next_block = x.next_block;
                    let have_next_block = x.flags.have_next_block();
                    x.next_block = idx;
                    x.flags.set_have_next_block(true);
                    if !past_end {
                        // truncate; need to rescan
                        x.end_off = slot_off - 1;
                        let off = slot * CODEMAP_BB_GRAIN + x.start_off.ext_usize();
                        do_enqueue(x, off, queue, notables);
                    }
                    drop(x);
                    let mut new = BabyBlock::zeroed();
                    new.flags.set_valid(true);
                    new.flags.set_have_next_block(have_next_block);
                    new.next_block = next_block;
                    new.start_off = slot_off;
                    new.end_off = if have_next_block {
                        self.extra_bbs[next_block.ext_usize()].start_off - 1
                    } else {
                        (CODEMAP_BB_GRAIN - 1) as u8
                    };
                    self.extra_bbs.push(new);
                    let x = self.extra_bbs.last_mut().unwrap();
                    return x;
                }
            }
        }
    }
}

impl<'a> CodeMap<'a> {
    pub fn new(region_start: VMA, insn_data: &'a [ReadCell<u8>], endian: Endian, _segs: &'a [Segment]) -> Self {
        let region_size = insn_data.len();
        let num_bbs = (region_size + CODEMAP_BB_GRAIN - 1) / CODEMAP_BB_GRAIN;
        CodeMap {
            region_start: region_start,
            region_size: region_size,
            insn_data: insn_data,
            bb_data: CodeMapBBData {
                bbs: util::zero_vec(num_bbs),
                extra_bbs: Vec::new(),
            },
            reg_vals: Vec::new(),
            queue: VecDeque::new(),
            switch_queue: Vec::new(),
            notables: Vec::new(),
            endian: endian,
            lscache: Some(Box::new(LastSetterCache {
                start_off: !0,
                end_off: 0,
                regs_with_known_val: BitSet32::empty(),
                reg_vals_off: 0,
                new_vals: ArrayVec::new(),
                end_reg_vals: [RegVal::zeroed(); MAX_REGS],
                end_rwkv: BitSet32::empty(),
            })),

            //segs: segs,
        }
    }
    pub fn go<'x>(&mut self, handler: &mut GenericHandler, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) {
        while !self.queue.is_empty() {
            self.go_round(handler);
            let offs = replace(&mut self.switch_queue, Vec::new());
            println!("switch offs = {:?}", offs);
            for off in offs {
                self.grok_switches(handler, off, read).unwrap(); // xxx
            }
        }
    }
    #[inline]
    pub fn addr_to_off(&self, addr: VMA) -> Option<usize> {
        let off = addr.wrapping_sub(self.region_start);
        if off < (self.region_size as u64) { Some(off as usize) } else { None }
    }
    #[inline]
    #[allow(dead_code)]
    pub fn off_to_addr(&self, off: usize) -> VMA {
        assert!(off <= self.region_size);
        self.region_start + (off as u64)
    }
    fn bb_containing_off_existing(&mut self, off: usize) -> Option<&mut BabyBlock> {
        //println!("bb_for_off 0x{:x}", off);
        let slot = off / CODEMAP_BB_GRAIN;
        let slot_off = (off % CODEMAP_BB_GRAIN) as u8;
        let mut x = &mut self.bb_data.bbs[slot];
        loop {
            if !x.flags.valid() { return None; }
            if slot_off < x.start_off {
                return None;
            } else if slot_off > x.end_off {
                if !x.flags.have_next_block() { return None; }
                let next_block = x.next_block.ext_usize();
                drop(x);
                let hack_extra_bbs: &'static mut Vec<BabyBlock> = unsafe { transmute(&mut self.bb_data.extra_bbs) };
                x = &mut hack_extra_bbs[next_block];
                continue;
            } else {
                return Some(x);
            }
        }
    }
    fn do_bb(&mut self, start_off: usize, reg_vals: &mut [RegVal; MAX_REGS], mut new_vals: Option<&mut ArrayVec<[(u8, RegVal); CODEMAP_BB_GRAIN]>>, handler: &mut GenericHandler) -> BitSet32 {
        'beginning: loop {
            let mut slot_off = (start_off % CODEMAP_BB_GRAIN) as u8;
            let base = start_off - slot_off.ext_usize();
            let mut regs_with_known_val: BitSet32;
            let mut end_off: u8;
            let mut switch_queued: bool;
            let reg_vals_off: usize;
            {
                let bb = self.bb_containing_off_existing(start_off).unwrap();
                debug_assert_eq!(bb.start_off, slot_off);
                regs_with_known_val = bb.regs_with_known_val;
                end_off = bb.end_off;
                switch_queued = bb.flags.switch_queued();
                reg_vals_off = bb.reg_vals_off.ext();
            }
            let mut notables_off: u32 = 0;
            println!("do_bb: start_off=0x{:x}/{} rwkv={}", start_off, self.off_to_addr(start_off), regs_with_known_val);
            {
                let mut off = reg_vals_off;
                for reg in regs_with_known_val.set_bits() {
                    let reg = reg.ext_usize();
                    reg_vals[reg] = self.reg_vals[off];
                    off += 1;
                }
            }
            loop {
                let this_off = base + slot_off.ext_usize();
                let (size, info) = self.decode(handler, this_off);
                println!(" {} rwkv={} size={} info={:?}", self.off_to_addr(this_off), regs_with_known_val, size, info);
                if size == 0 {
                    end_off = slot_off;
                    break;
                }
                let set: Option<(Reg, SetKind, bool, u64)> = match info.kind {
                    InsnKind::Set(reg, Addrish::Imm(val)) =>
                        Some((reg, SetKind::Other, true, val)),
                    InsnKind::Set(reg, Addrish::AddImm(base_reg, addend))
                        if regs_with_known_val.has(base_reg.0 as u8) =>
                            Some((reg, SetKind::Other, true, reg_vals[base_reg.idx()].val.wrapping_add(addend))),
                    InsnKind::Set(reg, Addrish::AddReg(base_reg, addend_reg, shift)) => {
                        if regs_with_known_val.has(base_reg.0 as u8) &&
                           regs_with_known_val.has(addend_reg.0 as u8) {
                            Some((reg, SetKind::AddReg, true, reg_vals[base_reg.idx()].val.wrapping_add(reg_vals[addend_reg.idx()].val << shift)))
                        } else {
                            Some((reg, SetKind::AddReg, false, 0))
                        }
                    },
                    InsnKind::Set(reg, _) | InsnKind::Load(reg, ..) =>
                        Some((reg, SetKind::Whatever, false, 0)),
                    InsnKind::CmpImm(..) =>
                        Some((FLAGS_REG, SetKind::Cmp, false, 0)),
                    _ => None,
                };
                // this has to be after the above checks
                for &kill in &info.kills_reg {
                    if kill != Reg::invalid() {
                        regs_with_known_val.remove(kill.0 as u8);
                    }
                }
                if let Some((reg, set_kind, have_val, val)) = set {
                    regs_with_known_val.add(reg.0 as u8);
                    let rv = RegVal { val: val, have_val: have_val, set_off: this_off.narrow().unwrap(), set_kind: set_kind, reg: reg, };
                    reg_vals[reg.idx()] = rv;
                    if let Some(ref mut new_vals) = new_vals {
                        new_vals.push((slot_off, rv));
                    }
                }

                match info.target_addr {
                    TargetAddr::Code(target_addr) | TargetAddr::Data(target_addr) => {
                        let target_off = self.addr_to_off(target_addr);
                        if let Some(target_off) = target_off {
                            if let TargetAddr::Code(_) = info.target_addr {
                                self.mark_flow(target_off, regs_with_known_val, reg_vals);
                                if target_off > start_off && target_off <= (base + end_off.ext_usize()) {
                                    let target_slot_off = (target_off % CODEMAP_BB_GRAIN) as u8;
                                    if target_slot_off > slot_off {
                                        end_off = target_slot_off - 1;
                                    } else {
                                        continue 'beginning;
                                    }
                                }
                            }
                        }
                        if target_off.is_none() {
                            if notables_off == 0 {
                                notables_off = self.notables.len().narrow().unwrap();
                            }
                            self.notables.push(Notable { valid: true, off: this_off.narrow().unwrap(), target_addr: target_addr });
                        }
                    },
                    TargetAddr::None => (),
                }

                if let InsnKind::Br(target) = info.kind {
                    if regs_with_known_val.has(target.0 as u8) &&
                       reg_vals[target.idx()].set_kind == SetKind::AddReg &&
                       !switch_queued {
                        switch_queued = true;
                        self.switch_queue.push(start_off);
                    }
                }

                let should_cont = match info.kind {
                    InsnKind::Tail | InsnKind::Unidentified | InsnKind::Br(_) => false,
                    _ => true,
                };
                let next_slot_off = slot_off + (size as u8);
                if !should_cont {
                    end_off = min(end_off, next_slot_off);
                    break;
                }
                if next_slot_off > end_off {
                    let next_off = base + next_slot_off.ext_usize();
                    if next_off < self.region_size {
                        self.mark_flow(next_off, regs_with_known_val, reg_vals);
                    }
                    break;
                }
                slot_off = next_slot_off;
            }
            {
                let bb = self.bb_containing_off_existing(start_off).unwrap();
                bb.end_off = end_off;
                bb.notables_off = notables_off;
                bb.flags.set_queued(false);
                bb.flags.set_switch_queued(switch_queued);
            }
            return regs_with_known_val;
        }
    }
    fn mark_flow(&mut self, to_off: usize, regs_with_known_val: BitSet32, reg_vals: &[RegVal; MAX_REGS]) {
        println!("  mark_flow -> {} rwkv={}", self.off_to_addr(to_off), regs_with_known_val);
        let bb = self.bb_data.bb_for_off(to_off, &mut self.queue, &mut self.notables);
        if !bb.flags.rwkv_meaningful() {
            bb.set_rwkv(regs_with_known_val, reg_vals, &mut self.reg_vals);
        } else {
            let new_rwkv = bb.regs_with_known_val & regs_with_known_val;
            let mut changed_vals = false;
            for regn in new_rwkv.set_bits() {
                let p = bb.reg_val(Reg(regn as i8), &mut self.reg_vals).unwrap();
                let new = &reg_vals[regn.ext_usize()];
                let intersected = p.intersect(new);
                if intersected != *p {
                    *p = intersected;
                    changed_vals = true;
                }
            }
            if !changed_vals {
                return;
            }
        }
        do_enqueue(bb, to_off, &mut self.queue, &mut self.notables);
    }
    pub fn mark_root(&mut self, off: usize) {
        let bb = self.bb_data.bb_for_off(off, &mut self.queue, &mut self.notables);
        do_enqueue(bb, off, &mut self.queue, &mut self.notables);
    }
    #[inline(always)]
    fn decode(&self, handler: &mut GenericHandler, off: usize) -> (usize, InsnInfo) {
        let data = &self.insn_data[off..];
        let addr = self.region_start + (off as u64);
        let (size, info) = handler.decode(addr, data);
        (size, *info)
    }
    fn go_round(&mut self, handler: &mut GenericHandler) {
        let mut reg_vals = [RegVal::default(); MAX_REGS];
        while let Some(off) = self.queue.pop_front() {
            self.do_bb(off, &mut reg_vals, None, handler);
        }

    }
    fn grok_switches<'x>(&mut self, handler: &mut GenericHandler, bb_off: usize, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) -> Result<(), GrokSwitchFail> {
        let mut offs: ArrayVec<[usize; CODEMAP_BB_GRAIN]> = ArrayVec::new();
        {
            let start; let end;
            {
                let bb = self.bb_containing_off_existing(bb_off).unwrap();
                if !bb.flags.switch_queued() { return Ok(()); }
                let base = bb_off - (bb_off % CODEMAP_BB_GRAIN);
                start = bb.start_off.ext_usize() + base;
                end = bb.end_off.ext_usize() + base;
            }
            let mut off = start;
            while off <= end {
                let (size, info) = self.decode(handler, off);
                if let InsnKind::Br(_) = info.kind {
                    offs.push(off);
                }
                off += size;
            }
        }
        for off in offs {
            try!(self.grok_switch(handler, off, read));
        }

        self.bb_containing_off_existing(bb_off).unwrap().flags.set_switch_queued(false);
        Ok(())
    }
    fn grok_switch<'x>(&mut self, handler: &mut GenericHandler, br_off: usize, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) -> Result<(), GrokSwitchFail> {
        println!("grok_switch: {}", self.off_to_addr(br_off));
        let br_reg = match self.decode(handler, br_off).1.kind {
            InsnKind::Br(r) => r, _ => panic!(),
        };
        let addr_setter = some_or!(self.last_setter_for_reg(handler, br_off, br_reg), {
            println!("no ls 1");
            return Ok(());
        });
        let (r1, r2) = match self.decode(handler, addr_setter.set_off.ext()).1.kind {
            InsnKind::Set(_, Addrish::AddReg(r1, r2, 0)) => (r1, r2),
            _ => {
                println!("no ls 2");
                return Ok(())
            },
        };
        let (r1rv, r2rv) = (
            try!(self.last_setter_for_reg(handler, addr_setter.set_off.ext(), r1).ok_or(GrokSwitchFail::GettingSetterOfAddR1)),
            try!(self.last_setter_for_reg(handler, addr_setter.set_off.ext(), r2).ok_or(GrokSwitchFail::GettingSetterOfAddR2)),
        );
        let rs = &[r1rv, r2rv];
        // find the table - would be nice to use loop-break-val for this
        let mut which_is_load: usize = 2;
        let mut table_addr_reg = Reg::invalid(); let mut table_idx_reg = Reg::invalid();
        let mut table_item_size = Size8; let mut table_item_signedness = Unsigned;
        for (i, rnrv) in rs.iter().enumerate() {
            let rnkind = self.decode(handler, rnrv.set_off.ext()).1.kind;
            match rnkind {
                InsnKind::Load(_, Addrish::AddReg(table_addr, table_idx, shift), size, signedness) => {
                    if size.log2_bytes() != shift {
                        return Err(GrokSwitchFail::ShiftMismatch);
                    }
                    table_addr_reg = table_addr; table_idx_reg = table_idx;
                    table_item_size = size; table_item_signedness = signedness;
                    which_is_load = i;
                    break;
                },
                _ => (),
            }
        }
        if which_is_load == 2 {
            return Err(GrokSwitchFail::NeitherAddendLooksLikeTable);
        }
        // the other should just be a static offset from PC
        let table_abase_rv = rs[1 - which_is_load];
        let table_abase = try!(self.value_for_reg(handler, table_abase_rv.set_off.ext_usize() + 1, table_abase_rv.reg).ok_or(GrokSwitchFail::GettingTableAbaseValue));
        let load_idx = rs[which_is_load].set_off.ext_usize();
        let table_addr = try!(self.value_for_reg(handler, load_idx, table_addr_reg).ok_or(GrokSwitchFail::GettingTableAddrValue));

        let table_addr = VMA(table_addr);
        let table_abase = VMA(table_abase);

        // one more thing: find the cmp to establish table size
        let cmp_rv = try!(self.last_setter_for_reg(handler, br_off, FLAGS_REG).ok_or(GrokSwitchFail::FindingCmp));
        println!("cmp@{}", self.off_to_addr(cmp_rv.set_off.ext()));
        let (_, info) = self.decode(handler, cmp_rv.set_off.ext());
        let table_len = match info.kind {
            InsnKind::CmpImm(r, u) if r == table_idx_reg => u,
            _ => return Err(GrokSwitchFail::CmpWeirdInsn),
        };
        // xxx - this doesn't check for killing idx in between
        if table_len > 100000 {
            return Err(GrokSwitchFail::TableTooBig);
        }

        // ok!
        println!("table_addr={} table_abase={} table_len={} item size={:?} sign={:?}", table_addr, table_abase, table_len, table_item_size, table_item_signedness);

        let bytes = table_item_size.bytes() as usize;
        let table_bytes = (table_len as usize) * bytes;
        let table: &[ReadCell<u8>] = some_or!(read(table_addr, table_bytes as u64), {
            return Err(GrokSwitchFail::TableReadError);
        });
        let lscache = replace(&mut self.lscache, None).unwrap();
        for (i, chunk) in table.chunks(bytes).enumerate() {
            let val = exec::dynsized_integer_from_slice(chunk, table_item_signedness, self.endian);
            let addr = table_abase.wrapping_add(val);
            if let Some(target_off) = self.addr_to_off(addr) {
                let end_rwkv = lscache.end_rwkv;
                self.mark_flow(target_off, end_rwkv, &lscache.end_reg_vals);
            } else {
                errln!("grok_switch: out-of-range(?) switch branch to {} from table {} element #{}", addr, table_addr, i);
            }
        }
        self.lscache = Some(lscache);
        Ok(())
    }
    fn value_for_reg(&mut self, handler: &mut GenericHandler, before_off: usize, reg: Reg) -> Option<u64> {
        if let Some(rv) = self.last_rv_for_reg(handler, before_off, reg) {
            if rv.have_val {
                return Some(rv.val);
            }
        }
        None
    }
    fn last_setter_for_reg(&mut self, handler: &mut GenericHandler, before_off: usize, reg: Reg) -> Option<RegVal> {
        if let Some(rv) = self.last_rv_for_reg(handler, before_off, reg) {
            println!("rv={:?}", rv);
            if rv.set_kind != SetKind::None {
                return Some(rv);
            }
        }
        None
    }
    fn last_rv_for_reg(&mut self, handler: &mut GenericHandler, before_off: usize, reg: Reg) -> Option<RegVal> {
        println!("last_rv_for_reg({:?} before {})", reg, self.off_to_addr(before_off));
        if !self.move_lscache_to(before_off, handler) { return None; }
        let lscache = self.lscache.as_ref().unwrap();
        let before_slot_off = before_off % CODEMAP_BB_GRAIN;
        for &(slot_off, ref val) in lscache.new_vals.iter().rev() {
            println!("newval: @0x{:x}(bo=0x{:x}) {:?}", slot_off, before_slot_off, val);
            if slot_off.ext_usize() >= before_slot_off {
                continue;
            }
            if val.reg == reg {
                return Some(*val);
            }
        }
        let rwkv = lscache.regs_with_known_val;
        println!("reached start rwkv={}", rwkv);
        if rwkv.has(reg.0 as u8) {
            let position = (lscache.reg_vals_off.ext_usize()) + (rwkv.subset(0..(reg.0 as u8)).count().ext_usize());
            return Some(self.reg_vals[position]);
        }
        return None;
    }
    fn move_lscache_to(&mut self, before_off: usize, handler: &mut GenericHandler) -> bool {
        let mut lscache = replace(&mut self.lscache, None).unwrap();
        println!("move_lscache_to: before {}/off=0x{:x} existing start_off=0x{:x} end_off=0x{:x}", self.off_to_addr(before_off), before_off, lscache.start_off, lscache.end_off);
        let ret;
        'lol: loop { // not actually a loop
            if before_off >= lscache.start_off && before_off <= lscache.end_off {
                println!("already there");
                ret = true;
                break 'lol;
            }
            let end_off;
            {
                let bb = some_or!(self.bb_containing_off_existing(before_off), {
                    println!("fail");
                    ret = false;
                    break 'lol;
                });
                let base = before_off - (before_off % CODEMAP_BB_GRAIN);
                lscache.start_off = base + bb.start_off.ext_usize();
                lscache.end_off = base + bb.end_off.ext_usize();
                assert!(bb.flags.rwkv_meaningful());
                lscache.regs_with_known_val = bb.regs_with_known_val;
                lscache.reg_vals_off = bb.reg_vals_off;
                end_off = bb.end_off;
            }
            let rwkv = {
                let lscache = &mut *lscache; // needed for multi-field borrowing, lol
                lscache.new_vals.clear();
                self.do_bb(lscache.start_off, &mut lscache.end_reg_vals, Some(&mut lscache.new_vals), handler)
            };
            lscache.end_rwkv = rwkv;
            debug_assert!(self.bb_containing_off_existing(before_off).unwrap().end_off == end_off);
            ret = true;
            break 'lol;
        }
        self.lscache = Some(lscache);
        return ret;
    }
}
