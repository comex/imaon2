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
        once_completed/set_once_completed: bool << 3,
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
}
unsafe impl Zeroable for BabyBlock {}

impl BabyBlock {
    #[inline]
    fn reg_val(&self, reg: Reg, reg_vals: &[u64]) -> Option<u64> {
        let reg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        if rwkv.has(reg) {
            let position = (self.reg_vals_off.ext_usize()) + (rwkv.subset(0..reg).count().ext_usize());
            Some(reg_vals[position])
        } else { None }
    }
    fn set_rwkv(&mut self, new_rwkv: BitSet32, my_vals: &[u64; MAX_REGS], reg_vals: &mut Vec<u64>) {
        self.regs_with_known_val = new_rwkv;
        let new_off = reg_vals.len();
        for reg in new_rwkv.set_bits() {
            reg_vals.push(my_vals[reg.ext_usize()]);
        }
        self.reg_vals_off = new_off.narrow().unwrap();

    }
    fn reduce_rwkv(&mut self, new_rwkv: BitSet32, reg_vals: &mut Vec<u64>) {
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

pub struct CodeMapBBData {
    bbs: Vec<BabyBlock>,
    extra_bbs: Vec<BabyBlock>,
}

pub struct CodeMap<'a> {
    region_start: VMA,
    region_size: usize,
    insn_data: &'a [ReadCell<u8>],
    bb_data: CodeMapBBData,
    reg_vals: Vec<u64>,
    queue: VecDeque<usize>,
    //switchlike_br_idxs: Vec<InsnIdx>,
    endian: Endian,

    segs: &'a [Segment],
    pub potentially_out_of_range_offs: Vec<usize>,

    /*
    // last_setter state
    ls_generation: usize,
    ls_result_idx: Option<InsnIdx>,
    ls_result_kind: InsnKind,
    */
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

impl CodeMapBBData {
    fn bb_for_off(&mut self, off: usize, queue: &mut VecDeque<usize>) -> (&mut BabyBlock, bool /*is_new*/) {
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
                //println!("cae 0");
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
                    // XXX with nonlexical lifetimes this shouldn't be necessary
                    // as self.extra_bbs should be definitely unborrowed after the drop() calls
                    let hack_extra_bbs: &'static mut Vec<BabyBlock> = unsafe { transmute(&mut self.extra_bbs) };
                    x = &mut hack_extra_bbs[x.next_block.ext_usize()];
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
                        if !x.flags.queued() {
                            queue.push_back(slot * CODEMAP_BB_GRAIN + x.start_off.ext_usize());
                            x.flags.set_queued(true);
                        }
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
            //switchlike_br_idxs: Vec::new(),
            endian: endian,
            segs: segs,
            potentially_out_of_range_offs: Vec::new(),
            /*
            ls_generation: 0,
            ls_result_idx: None,
            ls_result_kind: InsnKind::Other,
            */
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
        let (bb, new) = self.bb_data.bb_for_off(off, &mut self.queue);
        assert!(!new);
        bb
    }
    fn do_bb(&mut self, start_off: usize, reg_vals: &mut [u64; MAX_REGS], handler: &mut GenericHandler) {
        'beginning: loop {
            let mut slot_off = (start_off % CODEMAP_BB_GRAIN) as u8;
            let base = start_off - slot_off.ext_usize();
            let mut regs_with_known_val: BitSet32;
            let mut end_off: u8;
            let reg_vals_off: usize;
            let once_completed: bool;
            {
                let bb = self.bb_for_off_existing(start_off);
                regs_with_known_val = bb.regs_with_known_val;
                end_off = bb.end_off;
                once_completed = bb.flags.once_completed();
                reg_vals_off = bb.reg_vals_off.ext();
            }
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
                            Some((reg, reg_vals[base_reg.idx()].wrapping_add(addend))),
                    InsnKind::Set(reg, Addrish::AddReg(base_reg, addend_reg, shift))
                        if regs_with_known_val.has(base_reg.0 as u8) &&
                           regs_with_known_val.has(addend_reg.0 as u8) =>
                            Some((reg, reg_vals[base_reg.idx()].wrapping_add(reg_vals[addend_reg.idx()] << shift))),
                    _ => None,
                };
                // this has to be after the above checks
                for &kill in &info.kills_reg {
                    if kill != Reg::invalid() {
                        regs_with_known_val.remove(kill.0 as u8);
                    }
                }
                if let Some((reg, val)) = set {
                    regs_with_known_val.add(reg.0 as u8);
                    reg_vals[reg.idx()] = val;
                }

                let mut potentially_oor = false;
                match info.target_addr {
                    TargetAddr::Code(target_addr) => {
                        if let Some(target_off) = self.addr_to_off(target_addr) {
                            self.mark_flow(target_off, regs_with_known_val, reg_vals);
                            if target_off > start_off && target_off <= (base + end_off.ext_usize()) {
                                let target_slot_off = (target_off % CODEMAP_BB_GRAIN) as u8;
                                if target_slot_off > slot_off {
                                    end_off = target_slot_off - 1;
                                } else {
                                    continue 'beginning;
                                }
                            }
                        } else {
                            potentially_oor = true;
                        }
                    },
                    TargetAddr::Data(target_addr) => {
                        if self.addr_to_off(target_addr).is_none() { potentially_oor = true; }
                    },
                    _ => (),
                }
                if potentially_oor && !once_completed {
                    // this can have dupes because of splitting, but not too many
                    self.potentially_out_of_range_offs.push(base + slot_off.ext_usize());
                }

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
                bb.flags.set_queued(false);
                bb.flags.set_once_completed(true);
            }
            return;
        }
    }
    fn mark_flow(&mut self, to_off: usize, regs_with_known_val: BitSet32, reg_vals: &[u64; MAX_REGS]) {
        let (bb, is_new) = self.bb_data.bb_for_off(to_off, &mut self.queue);
        if is_new {
            bb.set_rwkv(regs_with_known_val, reg_vals, &mut self.reg_vals);
        } else {
            let mut new_rwkv = bb.regs_with_known_val & regs_with_known_val;
            for regn in new_rwkv.set_bits() {
                if bb.reg_val(Reg(regn as i8), &self.reg_vals).unwrap() != reg_vals[regn.ext_usize()] {
                    new_rwkv.remove(regn);
                }
            }
            if new_rwkv == bb.regs_with_known_val {
                return;
            }
            bb.reduce_rwkv(new_rwkv, &mut self.reg_vals);
        }
        if !bb.flags.queued() {
            bb.flags.set_queued(true);
            self.queue.push_back(to_off);
        }
    }
    pub fn mark_root(&mut self, off: usize) {
        let (bb, _) = self.bb_data.bb_for_off(off, &mut self.queue);
        if !bb.flags.queued() {
            self.queue.push_back(off);
            bb.flags.set_queued(true);
        }
    }
    #[inline(always)]
    fn decode(&self, handler: &mut GenericHandler, off: usize) -> (usize, InsnInfo) {
        let data = &self.insn_data[off..];
        let addr = self.region_start + (off as u64);
        let (size, info) = handler.decode(addr, data);
        (size, *info)
    }
    fn go_round(&mut self, handler: &mut GenericHandler) {
        let mut reg_vals = [0; MAX_REGS];
        while let Some(off) = self.queue.pop_front() {
            self.do_bb(off, &mut reg_vals, handler);
        }

    }

    /*
    fn grok_switch<'x>(&mut self, handler: &mut GenericHandler, br_idx: InsnIdx, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) -> Result<(), GrokSwitchFail> {
        //println!("grok_switch: {}", self.idx_to_addr(br_idx));
        let br_reg = match self.decode(handler, br_idx).1.kind {
            InsnKind::Br(r) => r, _ => panic!(),
        };
        let (addr_setter_idx, addr_setter_kind) = try!(self.last_setter(handler, br_idx, false, br_reg).map_err(GrokSwitchFail::GettingSetterOfBrAddr));
        let (r1, r2) = match addr_setter_kind {
            InsnKind::Set(_, Addrish::AddReg(r1, r2, 0)) => (r1, r2), _ => panic!(),
        };
        let ((r1idx, r1kind), (r2idx, r2kind)) = (
            try!(self.last_setter(handler, addr_setter_idx, false, r1).map_err(GrokSwitchFail::GettingSetterOfAddR1)),
            try!(self.last_setter(handler, addr_setter_idx, false, r2).map_err(GrokSwitchFail::GettingSetterOfAddR2)),
        );
        //println!("addends: {}, {} [from {}]", self.idx_to_addr(r1idx), self.idx_to_addr(r2idx), self.idx_to_addr(addr_setter_idx));
        let rs = &[(r1, r1idx, r1kind), (r2, r2idx, r2kind)];
        // find the table - would be nice to use loop-break-val for this
        let mut which_is_load: usize = 2;
        let mut table_addr_reg = Reg::invalid(); let mut table_idx_reg = Reg::invalid();
        let mut table_item_size = Size8; let mut table_item_signedness = Unsigned;
        for (i, &(_, _, rnkind)) in rs.iter().enumerate() {
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
        let (table_abase_reg, table_abase_idx, _) = rs[1 - which_is_load];
        let table_abase = try!(self.value_for_reg(handler, table_abase_idx, true, table_abase_reg).map_err(GrokSwitchFail::GettingTableAbaseValue));
        let (_, load_idx, _) = rs[which_is_load];
        let table_addr = try!(self.value_for_reg(handler, load_idx, false, table_addr_reg).map_err(GrokSwitchFail::GettingTableAddrValue));

        let table_addr = VMA(table_addr);
        let table_abase = VMA(table_abase);

        // one more thing: find the cmp to establish table size
        let table_len: u64;
        {
            let mut idx = load_idx;
            let mut i = 0;
            loop {
                i += 1;
                if i >= 20 {
                    return Err(GrokSwitchFail::CmpTooFar);
                }
                idx = some_or!(self.sole_pred(idx), {
                    return Err(GrokSwitchFail::CmpNoSolePred);
                });
                let (_, info) = self.decode(handler, idx);
                match info.kind {
                    InsnKind::CmpImm(r, u) if r == table_idx_reg => {
                        table_len = u;
                        break;
                    },
                    _ => if info.kills_reg(table_idx_reg) {
                        return Err(GrokSwitchFail::CmpIdxRegKilled);
                    },
                }
            }
        }
        if table_len > 100000 {
            return Err(GrokSwitchFail::TableTooBig);
        }

        // ok!
        //println!("table_addr={} table_abase={} table_len={} item size={:?} sign={:?}", table_addr, table_abase, table_len, table_item_size, table_item_signedness);

        let bytes = table_item_size.bytes().ext_usize();
        let table_bytes = (table_len.ext_usize()) * bytes;
        let table: &[ReadCell<u8>] = some_or!(read(table_addr, table_bytes as u64), {
            return Err(GrokSwitchFail::TableReadError);
        });
        for (i, chunk) in table.chunks(bytes).enumerate() {
            let val = exec::dynsized_integer_from_slice(chunk, table_item_signedness, self.endian);
            let addr = table_abase.wrapping_add(val);
            if let Some(target_idx) = self.addr_to_idx(addr) {
                self.mark_flow(br_idx, target_idx, false);
            } else {
                errln!("grok_switch: out-of-range(?) switch branch to {} from table {} element #{}", addr, table_addr, i);
            }
        }
        Ok(())
    }

    fn value_for_reg(&mut self, handler: &mut GenericHandler, mut before_idx: InsnIdx, mut can_be_at: bool, mut reg: Reg) -> Result<u64, LastSetterFail> {
        let mut i = 0;
        let mut addend: u64 = 0;
        loop {
            let (setter_idx, setter_kind) = try!(self.last_setter(handler, before_idx, can_be_at, reg));
            match setter_kind {
                InsnKind::Set(_, Addrish::Imm(val)) =>
                    return Ok(val.wrapping_add(addend)),
                InsnKind::Set(_, Addrish::AddImm(other_reg, xaddend)) => {
                    addend = addend.wrapping_add(xaddend);
                    reg = other_reg;
                    before_idx = setter_idx;
                    can_be_at = false;
                },
                _ => return Err(LastSetterFail::VFRUnknownSetter),
            }
            i += 1;
            if i >= 5 { return Err(LastSetterFail::VFROverflow); }
        }
    }

    fn last_setter(&mut self, handler: &mut GenericHandler, before_idx: InsnIdx, can_be_at: bool, reg: Reg) -> Result<(InsnIdx, InsnKind), LastSetterFail> {
        self.ls_generation += 1;
        self.ls_result_idx = None;
        try!(self.last_setter_inner(handler, before_idx, can_be_at, reg, 0));
        Ok((self.ls_result_idx.unwrap(), self.ls_result_kind))
    }

    #[inline]
    fn last_setter_rec(&mut self, handler: &mut GenericHandler, at_or_before_idx: InsnIdx, reg: Reg, depth: usize) -> Result<(), LastSetterFail> {
        //println!("last_setter_rec: {:?} @ {}/{}", reg, at_or_before_idx, self.idx_to_addr(at_or_before_idx));
        if depth > 20 {
            return Err(LastSetterFail::StackOverflow);
        }
        {
            let ls_generation = self.ls_generation;
            let iso = self.get_or_make_insn_state_other(at_or_before_idx);
            if iso.is_root {
                return Err(LastSetterFail::FoundRoot);
            }
            if iso.ls_generation == ls_generation {
                if iso.ls_finished {
                    // cached result
                    //println!("-> cached");
                    return Ok(());
                } else {
                    return Err(LastSetterFail::Loop);
                }
            } else {
                iso.ls_generation = ls_generation;
                iso.ls_finished = false;
            }
        }
        try!(self.last_setter_inner(handler, at_or_before_idx, /*can_be_at*/ true, reg, depth));
        {
            let iso = &mut self.insn_state_other[self.insn_state[at_or_before_idx].ext_usize()];
            iso.ls_finished = true;
        }
        //println!("-> got it");
        Ok(())
    }

    fn last_setter_inner(&mut self, handler: &mut GenericHandler, at_or_before_idx: InsnIdx, can_be_at: bool, reg: Reg, depth: usize) -> Result<(), LastSetterFail> {
        let mut idx = at_or_before_idx;
        loop {
            if can_be_at || idx != at_or_before_idx {
                if self.ls_result_idx == Some(idx) {
                    return Ok(());
                }
                let (_, info) = self.decode(handler, idx);
                if info.kills_reg(reg) {
                    // idx is a possible value
                    if self.ls_result_idx.is_some() {
                        return Err(LastSetterFail::DifferentValues);
                    }
                    self.ls_result_idx = Some(idx);
                    self.ls_result_kind = info.kind;
                    return Ok(());
                }
            }
            let state_word = self.insn_state[idx];
            //println!("idx={} state_word={}", idx, state_word);
            if state_word < 0 {
                idx = idx.wrapping_add(state_word.ext_usize());
            } else if state_word > 0 {
                let mut ok = false;
                let mut i = 0;
                //println!("flows_from({})={:?}", self.idx_to_addr(idx), self.insn_state_other[state_word.ext_usize()].flows_from);
                loop {
                    let from_idx = {
                        let flows_from = &self.insn_state_other[state_word.ext_usize()].flows_from;
                        *some_or!(flows_from.get(i), { break; })
                    };
                    i += 1;
                    let res = self.last_setter_rec(handler, from_idx, reg, depth + 1);
                    if res == Err(LastSetterFail::Loop) {
                        // this path is a loop but others may not be
                        continue;
                    }
                    // but other failures are fatal
                    try!(res);
                    ok = true;
                }
                if !ok { return Err(LastSetterFail::Loop); }
                return Ok(());
            } else {
                panic!("last_setter_inner: unseen?");
            }
        }
    }
    fn sole_pred(&mut self, idx: InsnIdx) -> Option<InsnIdx> {
        let state_word = self.insn_state[idx];
        if state_word < 0 {
            Some(idx.wrapping_add(state_word.ext_usize()))
        } else if state_word > 0 {
            let flows_from = &self.insn_state_other[state_word.ext_usize()].flows_from;
            if flows_from.len() != 1 { return None; }
            Some(flows_from[0])
        } else {
            None
        }
    }
    */
}
