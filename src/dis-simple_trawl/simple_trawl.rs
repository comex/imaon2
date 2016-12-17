#[macro_use] extern crate bitflags;
#[macro_use] extern crate macros;
extern crate dis_generated_jump_dis;
extern crate exec;
extern crate util;

use self::dis_generated_jump_dis::{Reg, GenericHandler, TargetAddr, InsnInfo, InsnKind, Addrish, Size8};
use std::collections::VecDeque;
use self::exec::{VMA, Segment};
use util::{Narrow, Endian, Unsigned, ReadCell, BitSet32, Zeroable};
use std::mem::{replace, transmute};
use std::ptr;

type InsnIdx = usize;

struct InsnStateOther {
    flows_from: Vec<InsnIdx>,
    is_root: bool,
    ls_finished: bool,
    ls_generation: usize,
}

impl InsnStateOther {
    fn new(flows_from: Vec<InsnIdx>) -> Self {
        InsnStateOther {
            flows_from: flows_from,
            is_root: false,
            ls_finished: false,
            ls_generation: 0,
        }
    }
}

bitflags! {
    flags BBFlags: u8 {
        const BBF_VALID = 1,
        const BBF_OOL_REG_VALS = 2,
        const BBF_HAVE_NEXT = 4,
    }
}

const BB_NUM_INLINE_REG_VALS: usize = 2;

struct BabyBlock {
    next_block: u32,
    flags: BBFlags,
    start_off: u8,
    end_off: u8, // inclusive
    rwkv_count: u8, // lol popcount
    regs_with_known_val: BitSet32,
    // 4 bytes wasted here
    reg_vals: [u64; BB_NUM_INLINE_REG_VALS], // either inline or actually a Box<[u64]>
}
unsafe impl Zeroable for BabyBlock {}

impl BabyBlock {
    #[inline]
    unsafe fn ool_reg_vals(&mut self) -> *mut Box<[u64]> {
        unsafe { transmute(&mut self.reg_vals) }
    }
    fn reg_vals<'a>(&'a self) -> &'a [u64] {
        #[allow(mutable_transmutes)]
        unsafe { transmute::<&'a BabyBlock, &'a mut BabyBlock>(self).reg_vals_mut() }
    }
    fn reg_vals_mut(&mut self) -> &mut [u64] {
        if self.flags.contains(BBF_OOL_REG_VALS) {
            unsafe { &mut (*self.ool_reg_vals())[..] }
        } else {
            &mut self.reg_vals[..]
        }
    }
    fn reg_val(&self, reg: Reg) -> Option<u64> {
        let reg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        if rwkv.has(reg) {
            let position = rwkv.subset(0..reg).count() as usize;
            Some(self.reg_vals()[position])
        } else { None }
    }
    fn add_reg_val(&mut self, reg: Reg, val: u64) {
        let reg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        let vals = self.reg_vals_mut() as *mut [u64];
        if rwkv.has(reg) {
            let position = rwkv.subset(0..reg).count() as usize;
            unsafe { (*vals)[position] = val; }
            return;
        }
        let new_count = (self.rwkv_count + 1) as usize;
        let old_cap = unsafe { (*vals).len() };
        if new_count > old_cap {
            let new_cap = 4 * old_cap;
            let mut new = util::zero_vec(new_cap).into_boxed_slice();
            new[..old_cap].copy_from_slice(unsafe { &(*vals)[..] });
            // XXX we'd like to drop here
            if self.flags.contains(BBF_OOL_REG_VALS) {
                let _ = unsafe { ptr::read(self.ool_reg_vals()) };
            }
            unsafe { ptr::write(self.ool_reg_vals(), new); }
        }
        let vals = self.reg_vals_mut();
        let position = rwkv.subset(0..reg).count() as usize;
        let move_count = rwkv.subset(reg..32).count() as usize;
        let new_rwkv = rwkv.adding(reg);
        for i in position..position+move_count {
            vals[i+1] = vals[i];
        }
        vals[position] = val;
    }
    fn remove_reg_val(&mut self, reg: Reg) {
        let reg = reg.0 as u8;
        let rwkv = self.regs_with_known_val;
        if rwkv.has(reg) {
            let position = rwkv.subset(0..reg).count() as usize;
            let move_count = rwkv.subset(reg+1..32).count() as usize;
            let vals = self.reg_vals_mut();
            for i in position..position+move_count {
                vals[i] = vals[i+1];
            }
        }

    }
}

impl Drop for BabyBlock {
    fn drop(&mut self) {
        if self.flags.contains(BBF_OOL_REG_VALS) {
            let _ = unsafe { ptr::read(self.ool_reg_vals()) };
        }
    }
}

pub const CODEMAP_BB_GRAIN: usize = 32;

pub struct CodeMap<'a> {
    region_start: VMA,
    region_size: usize,
    insn_data: &'a [ReadCell<u8>],
    bbs: Vec<BabyBlock>,
    extra_bbs: Vec<BabyBlock>,
    todo: VecDeque<InsnIdx>,
    switchlike_br_idxs: Vec<InsnIdx>,
    endian: Endian,

    segs: &'a [Segment],
    pub out_of_range_idxs: Vec<InsnIdx>,

    // last_setter state
    ls_generation: usize,
    ls_result_idx: Option<InsnIdx>,
    ls_result_kind: InsnKind,
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

impl<'a> CodeMap<'a> {
    pub fn new(region_start: VMA, insn_data: &'a [ReadCell<u8>], endian: Endian, segs: &'a [Segment]) -> Self {
        let region_size = insn_data.len();
        let num_bbs = region_size / CODEMAP_BB_GRAIN;
        CodeMap {
            region_start: region_start,
            region_size: region_size,
            insn_data: insn_data,
            bbs: util::zero_vec(num_bbs),
            // start with dummy 0 entry
            extra_bbs: vec![BabyBlock::zeroed()],
            todo: VecDeque::new(),
            switchlike_br_idxs: Vec::new(),
            endian: endian,
            segs: segs,
            out_of_range_idxs: Vec::new(),
            ls_generation: 0,
            ls_result_idx: None,
            ls_result_kind: InsnKind::Other,
        }
    }
    pub fn go<'x>(&mut self, handler: &mut GenericHandler, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) {
        unimplemented!()
        /*
        while !self.todo.is_empty() {
            self.go_round(handler);
            let idxs = replace(&mut self.switchlike_br_idxs, Vec::new());
            //println!("switch idxs = {:?}", idxs);
            for idx in idxs {
                self.grok_switch(handler, idx, read).unwrap(); // xxx
            }
        }
        */
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
    fn bb_for_off(&mut self, off: usize) -> (&mut BabyBlock, bool /*is_new */) {
        let slot = off / CODEMAP_BB_GRAIN;
        let slot_off = (off % CODEMAP_BB_GRAIN) as u8;
        let mut x = &mut self.bbs[slot];
        loop {
            if !x.flags.contains(BBF_VALID) {
                // initialize
                x.flags |= BBF_VALID;
                x.start_off = slot_off;
                x.end_off = 255; // should update later
                return (x, true);
            }
            let start_off = x.start_off;
            if start_off > slot_off {
                let idx: u32 = self.extra_bbs.len().narrow().unwrap();
                let mut new = BabyBlock::zeroed();
                new.flags |= BBF_VALID | BBF_HAVE_NEXT;
                new.next_block = idx;
                new.start_off = slot_off;
                new.end_off = start_off - 1;
                let old = replace(x, new);
                drop(x);

                self.extra_bbs.push(old);
                let x = self.extra_bbs.last_mut().unwrap();
                return (x, true);
            }
            if slot_off > x.end_off {
                if x.flags.contains(BBF_HAVE_NEXT) {
                    // XXX with nonlexical lifetimes this shouldn't be necessary
                    // as self.extra_bbs should be definitely unborrowed after the drop() calls
                    let hack_extra_bbs: &'static mut Vec<BabyBlock> = unsafe { transmute(&mut self.extra_bbs) };
                    x = &mut hack_extra_bbs[x.next_block as usize];
                    continue;
                } else {
                    let idx: u32 = self.extra_bbs.len().narrow().unwrap();
                    x.next_block = idx;
                    drop(x);
                    let mut new = BabyBlock::zeroed();
                    new.flags |= BBF_VALID;
                    new.start_off = slot_off;
                    new.end_off = 255;
                    self.extra_bbs.push(new);
                    let x = self.extra_bbs.last_mut().unwrap();
                    return (x, true);
                }
            }
            return (x, false);
        }

    }
    /*
    // returns whether we should proceed
    fn mark_flow(&mut self, from: InsnIdx, to: InsnIdx, is_flow: bool) -> bool {
        //print!("mark_flow from {}/{} to {}/{} ", from, self.idx_to_addr(from), to, self.idx_to_addr(to));
        let state = &mut self.insn_state[to];
        let old = *state;
        //println!("is_flow={} old={:x}", is_flow, old);
        if old > 0 {
            let ff = &mut self.insn_state_other[old as usize].flows_from;
            // quadratic yay
            if !ff.contains(&from) {
                ff.push(from);
            }
            false
        } else if old == 0 && is_flow {
            *state = -((to - from) as i32);
            //println!("now *state = {}", *state);
            true
        } else {
            *state = self.insn_state_other.len().narrow().unwrap();
            let mut vec = vec![from];
            if old == 0 {
                self.todo.push_back(to);
            } else {
                let old_from = to.wrapping_add(old as usize);
                if old_from != from { vec.push(old_from); }
            }
            self.insn_state_other.push(InsnStateOther::new(vec));
            false
        }
    }
    fn get_or_make_insn_state_other(&mut self, idx: InsnIdx) -> &mut InsnStateOther {
        let state = &mut self.insn_state[idx];
        let mut val = *state;
        if val <= 0 {
            let newval = self.insn_state_other.len().narrow().unwrap();
            *state = newval;
            let vec = if val == 0 { Vec::new() } else {
                let old_from = idx.wrapping_add(val as usize);
                vec![old_from]
            };
            self.insn_state_other.push(InsnStateOther::new(vec));
            val = newval;
        }
        &mut self.insn_state_other[val as usize]
    }
    pub fn mark_root(&mut self, idx: InsnIdx) {
        // this should only happen at the beginning
        assert!(self.insn_state[idx] == 0);
        self.get_or_make_insn_state_other(idx).is_root = true;
        self.todo.push_back(idx);
        //println!("mark_root {}/{}", idx, self.idx_to_addr(idx));
    }
    fn go_round(&mut self, handler: &mut GenericHandler) {
        let grain_shift = self.grain_shift;
        let segs = self.segs;
        while let Some(start_idx) = self.todo.pop_front() {
            let mut last_add_target_reg = Reg::invalid();
            let mut idx = start_idx;
            loop {
                let (size, info) = self.decode(handler, idx);
                println!("go_round: {}/{} => {:?} size={}", idx, self.idx_to_addr(idx), info, size);
                let next_idx = idx + (size >> grain_shift);
                if let TargetAddr::Code(addr) = info.target_addr {
                    if let Some(target_idx) = self.addr_to_idx(addr) {
                        self.mark_flow(idx, target_idx, false);
                    }
                }
                match info.target_addr {
                    TargetAddr::Code(addr) | TargetAddr::Data(addr) => {
                        if !segs.iter().any(|seg| addr.wrapping_sub(seg.vmaddr) < seg.vmsize) {
                            self.out_of_range_idxs.push(idx);
                        }
                    },
                    _ => ()
                }
                let should_cont = match info.kind {
                    InsnKind::Tail | InsnKind::Unidentified => false,
                    InsnKind::Br(target) => {
                        if target == last_add_target_reg {
                            self.switchlike_br_idxs.push(idx);
                        }
                        false
                    },
                    _ => self.mark_flow(idx, next_idx, true),
                };
                if !should_cont { break; }
                match info.kind {
                    InsnKind::Set(target, Addrish::AddReg(..)) => {
                        last_add_target_reg = target;
                    },
                    _ => if info.kills_reg(last_add_target_reg) {
                        last_add_target_reg = Reg::invalid();
                    },
                };
                idx = next_idx;
            }

        }
    }
    #[inline(always)]
    fn decode(&self, handler: &mut GenericHandler, idx: InsnIdx) -> (usize, InsnInfo) {
        let offset = idx << self.grain_shift;
        let data = &self.insn_data[offset..];
        let addr = self.region_start + (offset as u64);
        let (size, info) = handler.decode(addr, data);
        (size, *info)
    }

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

        let bytes = table_item_size.bytes() as usize;
        let table_bytes = (table_len as usize) * bytes;
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
            let iso = &mut self.insn_state_other[self.insn_state[at_or_before_idx] as usize];
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
                idx = idx.wrapping_add(state_word as usize);
            } else if state_word > 0 {
                let mut ok = false;
                let mut i = 0;
                //println!("flows_from({})={:?}", self.idx_to_addr(idx), self.insn_state_other[state_word as usize].flows_from);
                loop {
                    let from_idx = {
                        let flows_from = &self.insn_state_other[state_word as usize].flows_from;
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
            Some(idx.wrapping_add(state_word as usize))
        } else if state_word > 0 {
            let flows_from = &self.insn_state_other[state_word as usize].flows_from;
            if flows_from.len() != 1 { return None; }
            Some(flows_from[0])
        } else {
            None
        }
    }
    */
}
