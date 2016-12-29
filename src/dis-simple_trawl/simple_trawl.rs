#[macro_use] extern crate macros;
extern crate dis_generated_jump_dis;
extern crate exec;
extern crate util;

use self::dis_generated_jump_dis::{Reg, MAX_REGS, GenericHandler, TargetAddr, InsnInfo, InsnKind, Addrish, Size8};
use std::collections::VecDeque;
use self::exec::{VMA, Segment};
use util::{Narrow, Endian, Unsigned, ReadCell, BitSet32, Zeroable, Ext, ExtWrapper, unlikely};
use std::mem::{replace, transmute};

simple_bitflags! {
    BBFlags: u8 {
        valid/set_valid: bool << 0,
        have_next_block/set_have_next_block: bool << 1,
        queued/set_queued: bool << 2,
        switch_queued/set_switch_queued: bool << 4,
    }
}

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

/*
#[derive(Clone, Copy, PartialEq)]
enum SetKind {
    None,
    AddReg,
    Other,
}
impl Default for SetKind { fn default() -> Self { SetKind::None } }
*/

#[derive(Clone, Copy, PartialEq, Default)]
struct RegVal {
    val: u64,
}


type PrevVals = [Option<(Reg, RegVal)>; CODEMAP_BB_GRAIN];
impl BabyBlock {
    #[inline]
    fn reg_val<'a>(&self, reg: Reg, reg_vals: &'a mut [RegVal]) -> Option<&'a mut RegVal> {
        let reg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        if rwkv.has(reg) {
            let position = (self.reg_vals_off.ext_usize()) + (rwkv.subset(0..reg).count().ext_usize());
            Some(&mut reg_vals[position])
        } else { None }
    }
    fn set_rwkv(&mut self, new_rwkv: BitSet32, my_vals: &[RegVal; MAX_REGS], reg_vals: &mut Vec<RegVal>) {
        self.regs_with_known_val = new_rwkv;
        let new_off = reg_vals.len();
        for reg in new_rwkv.set_bits() {
            reg_vals.push(my_vals[reg.ext_usize()]);
        }
        self.reg_vals_off = new_off.narrow().unwrap();

    }
    fn reduce_rwkv(&mut self, new_rwkv: BitSet32, reg_vals: &mut Vec<RegVal>) {
        let old_rwkv = self.regs_with_known_val;
        let removed_bits = old_rwkv & !new_rwkv;
        if removed_bits.is_empty() { return; }
        self.regs_with_known_val = new_rwkv;
        if new_rwkv.is_empty() ||
           removed_bits.lowest_set_bit().unwrap() > new_rwkv.highest_set_bit().unwrap() {
           return;
        }
        let mut off: usize = self.reg_vals_off.ext();
        let new_off = reg_vals.len();
        for oreg in old_rwkv.set_bits() {
            if new_rwkv.has(oreg) {
                let val = reg_vals[off];
                reg_vals.push(val);
            }
            off += 1;
        }
        self.reg_vals_off = new_off.narrow().unwrap();
    }
}

pub const CODEMAP_BB_GRAIN: usize = 32;

struct Notable {
    valid: bool,
    off: u32,
    target_addr: VMA,
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

    segs: &'a [Segment],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastSetterFail {
    DifferentValues,
    StackOverflow,
    Loop,
    FoundRoot,
    VFROverflow,
    VFRUnknownSetter,
}

#[derive(Clone, Copy, Debug)]
pub enum GrokSwitchFail {
    GettingSetterOfBrAddr(LastSetterFail),
    GettingSetterOfAddR1(LastSetterFail),
    GettingSetterOfAddR2(LastSetterFail),
    ShiftMismatch,
    NeitherAddendLooksLikeTable,
    GettingTableAbaseValue(LastSetterFail),
    GettingTableAddrValue(LastSetterFail),
    CmpTooFar,
    CmpNoSolePred,
    CmpIdxRegKilled,
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
            loop {
                if let Some(n) = notables.get_mut(idx) {
                    if n.valid && n.off.ext_usize() <= end {
                        n.valid = false;
                        continue;
                    }
                }
                break;
            }
        }
    }
}

impl CodeMapBBData {
    fn bb_for_off<'a>(&'a mut self, off: usize, queue: &mut VecDeque<usize>, notables: &mut Vec<Notable>) -> (&'a mut BabyBlock, bool /*is_new*/) {
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
                return (x, true);
            }
            let start_off = x.start_off;
            if slot_off == start_off {
                //println!("cae 1");
                return (x, false);
            } else if slot_off < start_off {
                let idx: u32 = self.extra_bbs.len().narrow().unwrap();
                let mut new = BabyBlock::zeroed();
                new.flags.set_valid(true);
                new.flags.set_have_next_block(true);
                new.next_block = idx;
                new.start_off = slot_off;
                new.end_off = start_off - 1;
                let old = replace(x, new);
                drop(x);

                self.extra_bbs.push(old);
                let x = self.extra_bbs.last_mut().unwrap();
                //println!("cae 2");
                return (x, true);
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
                    return (x, true);
                }
            }
        }
    }
}

impl<'a> CodeMap<'a> {
    pub fn new(region_start: VMA, insn_data: &'a [ReadCell<u8>], endian: Endian, segs: &'a [Segment]) -> Self {
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
            segs: segs,
        }
    }
    pub fn go<'x>(&mut self, handler: &mut GenericHandler, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) {
        while !self.queue.is_empty() {
            self.go_round(handler);
            /*
            let idxs = replace(&mut self.switchlike_br_idxs, Vec::new());
            //println!("switch idxs = {:?}", idxs);
            for idx in idxs {
                self.grok_switch(handler, idx, read).unwrap(); // xxx
            }
            */
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
        self.region_start + (off as u64)
    }
    fn bb_for_off_existing(&mut self, off: usize) -> &mut BabyBlock {
        //println!("bb_for_off 0x{:x}", off);
        let slot = off / CODEMAP_BB_GRAIN;
        let slot_off = (off % CODEMAP_BB_GRAIN) as u8;
        let mut x = &mut self.bb_data.bbs[slot];
        loop {
            assert!(x.flags.valid());
            let start_off = x.start_off;
            if slot_off == start_off {
                return x;
            } else if slot_off > start_off {
                assert!(x.flags.have_next_block());
                let next_block = x.next_block.ext_usize();
                drop(x);
                let hack_extra_bbs: &'static mut Vec<BabyBlock> = unsafe { transmute(&mut self.bb_data.extra_bbs) };
                x = &mut hack_extra_bbs[next_block];
                continue;
            } else {
                panic!();
            }
        }
    }
    fn do_bb(&mut self, start_off: usize, reg_vals: &mut [RegVal; MAX_REGS], prev_vals: &mut PrevVals, handler: &mut GenericHandler, switch_mode: bool) {
        'beginning: loop {
            let mut slot_off = (start_off % CODEMAP_BB_GRAIN) as u8;
            let base = start_off - slot_off.ext_usize();
            let mut regs_with_known_val: BitSet32;
            let mut end_off: u8;
            let mut switch_queued: bool;
            let reg_vals_off: usize;
            {
                let bb = self.bb_for_off_existing(start_off);
                regs_with_known_val = bb.regs_with_known_val;
                end_off = bb.end_off;
                switch_queued = bb.flags.switch_queued();
                reg_vals_off = bb.reg_vals_off.ext();
            }
            let mut notables_off: u32 = 0;
            let mut last_addreg_target = Reg::invalid();
            println!("do_bb: start_off=0x{:x}/{} rwkv=0x{:x}", start_off, self.off_to_addr(start_off), regs_with_known_val.bits);
            {
                let mut off = reg_vals_off;
                for reg in regs_with_known_val.set_bits() {
                    let reg = reg.ext_usize();
                    reg_vals[reg] = self.reg_vals[off];
                    off += 1;
                }
            }
            loop {
                let (size, info) = self.decode(handler, base + slot_off.ext_usize());
                if size == 0 {
                    end_off = slot_off;
                    break;
                }
                let set: Option<(Reg, u64)> = match info.kind {
                    InsnKind::Set(reg, Addrish::Imm(val)) =>
                        Some((reg, val)),
                    InsnKind::Set(reg, Addrish::AddImm(base_reg, addend))
                        if regs_with_known_val.has(base_reg.0 as u8) =>
                            Some((reg, reg_vals[base_reg.idx()].val.wrapping_add(addend))),
                    InsnKind::Set(reg, Addrish::AddReg(base_reg, addend_reg, shift))
                        if regs_with_known_val.has(base_reg.0 as u8) &&
                           regs_with_known_val.has(addend_reg.0 as u8) =>
                            Some((reg, reg_vals[base_reg.idx()].val.wrapping_add(reg_vals[addend_reg.idx()].val << shift))),
                    _ => None,
                };
                // this has to be after the above checks
                for &kill in &info.kills_reg {
                    if kill != Reg::invalid() {
                        regs_with_known_val.remove(kill.0 as u8);
                        if last_addreg_target == kill { last_addreg_target = Reg::invalid(); }
                    }
                }
                if let InsnKind::Set(reg, Addrish::AddReg(..)) = info.kind {
                    last_addreg_target = reg;
                }
                let this_off = base + slot_off.ext_usize();
                let mut prev = None;
                if let Some((reg, val)) = set {
                    regs_with_known_val.add(reg.0 as u8);
                    let rv = RegVal { val: val };
                    prev = Some((reg, reg_vals[reg.idx()]));
                    reg_vals[reg.idx()] = rv;
                }
                prev_vals[slot_off.ext_usize()] = prev;

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
                    if target == last_addreg_target && !switch_mode && !switch_queued {
                        switch_queued = true;
                        self.switch_queue.push(start_off);
                    }
                }

                let should_cont = match info.kind {
                    InsnKind::Tail | InsnKind::Unidentified | InsnKind::Br(_) => false,
                    _ => true,
                };

                if !should_cont { break; }
                let next_slot_off = slot_off + (size as u8);
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
                let bb = self.bb_for_off_existing(start_off);
                bb.end_off = end_off;
                bb.notables_off = notables_off;
                bb.flags.set_queued(false);
                bb.flags.set_switch_queued(switch_queued);
            }
            return;
        }
    }
    fn mark_flow(&mut self, to_off: usize, regs_with_known_val: BitSet32, reg_vals: &[RegVal; MAX_REGS]) {
        let (bb, is_new) = self.bb_data.bb_for_off(to_off, &mut self.queue, &mut self.notables);
        if is_new {
            bb.set_rwkv(regs_with_known_val, reg_vals, &mut self.reg_vals);
        } else {
            let mut new_rwkv = bb.regs_with_known_val & regs_with_known_val;
            let mut changed_vals = false;
            for regn in new_rwkv.set_bits() {
                let old = bb.reg_val(Reg(regn as i8), &mut self.reg_vals).unwrap();
                let new = reg_vals[regn.ext_usize()];
                if old.val != new.val {
                    new_rwkv.remove(regn);
                }/* else if old.set_kind != SetKind::None && (new.set_kind == SetKind::None || old.set_off != new.set_off) {
                    old.set_kind = SetKind::None;
                    changed_vals = true;
                }*/
            }
            if new_rwkv != bb.regs_with_known_val {
                bb.reduce_rwkv(new_rwkv, &mut self.reg_vals);
            } else if !changed_vals {
                return;
            }
        }
        do_enqueue(bb, to_off, &mut self.queue, &mut self.notables);
    }
    pub fn mark_root(&mut self, off: usize) {
        let (bb, _) = self.bb_data.bb_for_off(off, &mut self.queue, &mut self.notables);
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
        let mut prev_vals = [None; CODEMAP_BB_GRAIN]; // only useful for switch mode
        while let Some(off) = self.queue.pop_front() {
            self.do_bb(off, &mut reg_vals, &mut prev_vals, handler, false);
        }

    }

}
