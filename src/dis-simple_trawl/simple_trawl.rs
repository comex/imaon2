extern crate dis_generated_jump_dis;
extern crate util;
extern crate exec;
#[macro_use]
extern crate macros;

use self::dis_generated_jump_dis::{Reg, GenericHandler, TargetAddr, InsnInfo, InsnKind, Addrish, Size8, CC};
use std::collections::VecDeque;
use self::exec::{VMA, Segment};
use util::{Narrow, Endian, Unsigned, ReadCell, BitSet32, Fnv};
use std::mem::replace;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

type InsnIdx = usize;

struct InsnStateOther {
    flows_from: Vec<InsnIdx>,
    is_root: bool,
}

impl InsnStateOther {
    fn new(flows_from: Vec<InsnIdx>) -> Self {
        InsnStateOther {
            flows_from: flows_from,
            is_root: false,
        }
    }
}

pub struct CodeMap<'a> {
    region_start: VMA,
    region_size: u64,
    grain_shift: u8,
    insn_data: &'a [ReadCell<u8>],
    // 0 => unseen
    // -x => distance to previous instruction, which flows to this one
    // +x => index into insn_state_other
    insn_state: Vec<i32>,
    insn_state_other: Vec<InsnStateOther>,
    todo: VecDeque<InsnIdx>,
    switchlike_br_idxs: Vec<InsnIdx>,
    endian: Endian,

    segs: &'a [Segment],
    pub out_of_range_idxs: Vec<InsnIdx>,

    noreturn_addrs: Vec<VMA>,

    // key is at_or_before - can_be_at must be true
    value_info_cache: HashMap<ValueInfoKey, Option<ValueInfo>, Fnv>,
}

#[derive(Copy, Clone, Hash, PartialEq, Eq)]
struct ValueInfoKey {
    at_or_before_idx: InsnIdx,
    reg: Reg,
}

#[derive(Default, Copy, Clone, Debug)]
struct ValueInfo {
    setter_idx: Option<InsnIdx>,
    value: Option<u64>,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueInfoFail {
    DifferentValues,
    StackOverflow,
    Loop,
    LoopWithAddend,
    FoundRoot,
}

#[derive(Clone, Copy, Debug)]
pub enum GrokSwitchFail {
    GettingBrAddrValueInfo(ValueInfoFail),
    GettingBrAddrSetter,
    GettingR1ValueInfo(ValueInfoFail),
    GettingR2ValueInfo(ValueInfoFail),
    ShiftMismatch,
    NeitherAddendLooksLikeTable,
    GettingTableAbaseValue,
    GettingTableAddrValueInfo(ValueInfoFail),
    GettingTableAddrValue,
    CmpTooFar,
    CmpNoSolePred,
    UnknownCC,
    TableTooBig,
    TableReadError,
}

impl<'a> CodeMap<'a> {
    pub fn new(region_start: VMA, grain_shift: u8, insn_data: &'a [ReadCell<u8>], endian: Endian, segs: &'a [Segment]) -> Self {
        let region_size = insn_data.len() as u64;
        let num_insns: usize = ((region_size + ((1 << grain_shift) - 1)) >> grain_shift).narrow().unwrap();
        CodeMap {
            region_start: region_start,
            region_size: region_size,
            grain_shift: grain_shift,
            insn_data: insn_data,
            insn_state: util::zero_vec(num_insns),
            // start with dummy 0 entry
            insn_state_other: vec![InsnStateOther::new(Vec::new())],
            todo: VecDeque::new(),
            switchlike_br_idxs: Vec::new(),
            endian: endian,
            segs: segs,
            out_of_range_idxs: Vec::new(),
            noreturn_addrs: Vec::new(),
            value_info_cache: util::new_fnv_hashmap(),
        }
    }
    pub fn go<'x>(&mut self, handler: &mut GenericHandler, read: &'x mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) {
        while !self.todo.is_empty() {
            self.go_round(handler);
            let idxs = replace(&mut self.switchlike_br_idxs, Vec::new());
            //println!("switch idxs = {:?}", idxs);
            for idx in idxs {
                self.grok_switch(handler, idx, read).unwrap(); // xxx
                self.value_info_cache.clear();
            }
        }
    }
    pub fn addr_to_idx(&self, addr: VMA) -> Option<InsnIdx> {
        let offset = addr.wrapping_sub(self.region_start);
        if offset < self.region_size &&
           offset & ((1 << self.grain_shift) - 1) == 0 {
            Some((offset >> self.grain_shift) as usize)
        } else {
            None
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub fn idx_to_addr(&self, addr: InsnIdx) -> VMA {
        self.region_start + (addr << self.grain_shift) as u64
    }
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
    fn get_insn_state_other(&mut self, idx: InsnIdx) -> Option<&mut InsnStateOther> {
        let state = &mut self.insn_state[idx];
        let val = *state;
        if val > 0 {
            Some(&mut self.insn_state_other[val as usize])
        } else { None }
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
    pub fn mark_noreturn_addr(&mut self, addr: VMA) {
        self.noreturn_addrs.push(addr);
    }
    pub fn mark_root(&mut self, idx: InsnIdx) {
        // this should only happen at the beginning
        {
        let state = self.get_or_make_insn_state_other(idx);
        if state.is_root { return; }
        state.is_root = true;
        }
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
                //println!("go_round: {}/{} => {:?} size={}", idx, self.idx_to_addr(idx), info, size);
                let next_idx = idx + (size >> grain_shift);
                if let TargetAddr::Code(addr) = info.target_addr {
                    if let Some(target_idx) = self.addr_to_idx(addr) {
                        self.mark_flow(idx, target_idx, false);
                    }
                }
                match info.target_addr {
                    TargetAddr::Code(addr) => {
                        if self.noreturn_addrs.contains(&addr) {
                            break;
                        }
                        if !segs.iter().any(|seg| addr.wrapping_sub(seg.vmaddr) < seg.vmsize) {
                            self.out_of_range_idxs.push(idx);
                        }
                    },
                    _ => ()
                }
                let should_cont = match info.kind {
                    InsnKind::Tail => false,
                    InsnKind::Unidentified => {
                        errln!("go_round: stopping at unidentified instruction at {}", self.idx_to_addr(idx));
                        false
                    },
                    InsnKind::Br(target) => {
                        if target == last_add_target_reg {
                            self.switchlike_br_idxs.push(idx);
                        }
                        false
                    },
                    _ => {
                        if next_idx != self.insn_state.len() {
                            self.mark_flow(idx, next_idx, true)
                        } else {
                            false
                        }
                    },
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

    fn grok_switch<'x>(&mut self, handler: &mut GenericHandler, br_idx: InsnIdx, read: &mut FnMut(VMA, u64) -> Option<&'x [ReadCell<u8>]>) -> Result<(), GrokSwitchFail> {
        //println!("grok_switch: {}", self.idx_to_addr(br_idx));
        let br_reg = match self.decode(handler, br_idx).1.kind {
            InsnKind::Br(r) => r, _ => panic!(),
        };
        let addr_setter_vi = try!(self.value_info(handler, br_idx, br_reg).map_err(GrokSwitchFail::GettingBrAddrValueInfo));
        let addr_setter_idx = try!(addr_setter_vi.setter_idx.ok_or(GrokSwitchFail::GettingBrAddrSetter));
        let (r1, r2) = match self.decode(handler, addr_setter_idx).1.kind {
            InsnKind::Set(_, Addrish::AddReg(r1, r2, 0)) => (r1, r2), _ => panic!(),
        };
        let (r1vi, r2vi) = (
            try!(self.value_info(handler, addr_setter_idx, r1).map_err(GrokSwitchFail::GettingR1ValueInfo)),
            try!(self.value_info(handler, addr_setter_idx, r2).map_err(GrokSwitchFail::GettingR2ValueInfo)),
        );
        //println!("addends: {}, {} [from {}]", self.idx_to_addr(r1idx), self.idx_to_addr(r2idx), self.idx_to_addr(addr_setter_idx));
        let rs = &[(r1, r1vi), (r2, r2vi)];
        // find the table - would be nice to use loop-break-val for this
        let mut which_is_load: usize = 2;
        let mut table_addr_reg = Reg::invalid(); let mut table_idx_reg = Reg::invalid();
        let mut table_item_size = Size8; let mut table_item_signedness = Unsigned;
        let mut load_idx = 0;
        for (i, &(_, rnvi)) in rs.iter().enumerate() {
            let rnidx = some_or!(rnvi.setter_idx, { continue; });
            match self.decode(handler, rnidx).1.kind {
                InsnKind::Load(_, Addrish::AddReg(table_addr, table_idx, shift), size, signedness) => {
                    if size.log2_bytes() != shift {
                        return Err(GrokSwitchFail::ShiftMismatch);
                    }
                    table_addr_reg = table_addr; table_idx_reg = table_idx;
                    table_item_size = size; table_item_signedness = signedness;
                    which_is_load = i; load_idx = rnidx;
                    break;
                },
                _ => (),
            }
        }
        if which_is_load == 2 {
            return Err(GrokSwitchFail::NeitherAddendLooksLikeTable);
        }
        // the other should just be a static offset from PC
        let (_, ref table_abase_vi) = rs[1 - which_is_load];
        let table_abase = VMA(try!(table_abase_vi.value.ok_or(GrokSwitchFail::GettingTableAbaseValue)));
        let table_addr_vi = try!(self.value_info(handler, load_idx, table_addr_reg).map_err(GrokSwitchFail::GettingTableAddrValueInfo));
        let table_addr = VMA(try!(table_addr_vi.value.ok_or(GrokSwitchFail::GettingTableAddrValue)));

        // one more thing: find the cmp to establish table size
        let mut table_len: u64 = 0;
        {
            let mut idx = load_idx;
            let mut i = 0;
            let mut cmp_reg = Reg::invalid();
            let mut table_idx_regs = BitSet32::empty();
            let mut cc: Option<CC> = None;
            table_idx_regs.add(table_idx_reg.0 as u8);
            loop {
                i += 1;
                if i >= 20 {
                    return Err(GrokSwitchFail::CmpTooFar);
                }
                idx = some_or!(self.sole_pred(idx), {
                    return Err(GrokSwitchFail::CmpNoSolePred);
                });
                let (_, info) = self.decode(handler, idx);
                //println!("ti={} => {:?}", table_idx_regs, info.kind);
                match info.kind {
                    InsnKind::Bcc(cc_) if cc.is_none() => cc = Some(cc_),
                    InsnKind::CmpImm(r, u) if cc.is_some() && cmp_reg == Reg::invalid() => {
                        cmp_reg = r;
                        table_len = match cc.unwrap() {
                            CC::Geu | CC::Ltu => u,
                            CC::Gtu | CC::Leu => u + 1,
                            CC::Other => return Err(GrokSwitchFail::UnknownCC),
                        };
                    },
                    InsnKind::Set(dst, Addrish::AddImm(src, 0))
                        if table_idx_regs.has(dst.0 as u8) =>
                        table_idx_regs.add(src.0 as u8),
                    _ => {
                        for &reg in &info.kills_reg {
                            if reg != Reg::invalid() {
                                table_idx_regs.remove(reg.0 as u8);
                            }
                        }
                    },
                }
                if cmp_reg != Reg::invalid() && table_idx_regs.has(cmp_reg.0 as u8) {
                    // OK, it's reasonable
                    break;
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

    #[inline]
    fn value_info(&mut self, handler: &mut GenericHandler, before_idx: InsnIdx, reg: Reg) -> Result<ValueInfo, ValueInfoFail> {
        //println!("value_info({:?} before {})", reg, self.idx_to_addr(before_idx));
        self.value_info_inner(handler, before_idx, false, reg, 0)
    }

    #[inline]
    fn value_info_rec(&mut self, handler: &mut GenericHandler, at_or_before_idx: InsnIdx, reg: Reg, depth: usize) -> Result<ValueInfo, ValueInfoFail> {
        //println!("value_info_rec: {:?} @ {}/{}", reg, at_or_before_idx, self.idx_to_addr(at_or_before_idx));
        if depth > 40 {
            return Err(ValueInfoFail::StackOverflow);
        }
        if let Some(iso) = self.get_insn_state_other(at_or_before_idx) {
            if iso.is_root {
                return Err(ValueInfoFail::FoundRoot);
            }
        }
        let key = ValueInfoKey { at_or_before_idx: at_or_before_idx, reg: reg, };
        match self.value_info_cache.entry(key) {
            Entry::Occupied(optres) => {
                return optres.get().ok_or(ValueInfoFail::Loop);
            },
            Entry::Vacant(slot) => {
                slot.insert(None);
            }
        }
        let res = try!(self.value_info_inner(handler, at_or_before_idx, /*can_be_at*/ true, reg, depth));
        *self.value_info_cache.get_mut(&key).unwrap() = Some(res);
        Ok(res)
    }

    fn value_info_inner(&mut self, handler: &mut GenericHandler, at_or_before_idx: InsnIdx, can_be_at: bool, mut reg: Reg, depth: usize) -> Result<ValueInfo, ValueInfoFail> {
        let mut idx = at_or_before_idx;
        let mut addend: u64 = 0;
        loop {
            if can_be_at || idx != at_or_before_idx {
                let (_, info) = self.decode(handler, idx);
                match info.kind {
                    InsnKind::Set(dst, Addrish::AddImm(src, imm)) if dst == reg => {
                        reg = src;
                        addend = addend.wrapping_add(imm);
                    },
                    InsnKind::Set(dst, Addrish::Imm(imm)) if dst == reg => {
                        return Ok(ValueInfo {
                            setter_idx: Some(idx),
                            value: Some(imm.wrapping_add(addend)),
                        });
                    },
                    _ if info.kills_reg(reg) => {
                        return Ok(ValueInfo {
                            setter_idx: Some(idx),
                            value: None,
                        });
                    },
                    _ => (),
                }
            }
            let state_word = self.insn_state[idx];
            //println!("idx={} state_word={}", idx, state_word);
            if state_word < 0 {
                idx = idx.wrapping_add(state_word as usize);
            } else if state_word > 0 {
                let mut i = 0;
                //println!("flows_from({})={:?}", self.idx_to_addr(idx), self.insn_state_other[state_word as usize].flows_from);
                let mut existing: Option<ValueInfo> = None;
                loop {
                    let from_idx = {
                        let flows_from = &self.insn_state_other[state_word as usize].flows_from;
                        *some_or!(flows_from.get(i), { break; })
                    };
                    i += 1;
                    let res = self.value_info_rec(handler, from_idx, reg, depth + 1);
                    if let Err(ValueInfoFail::Loop) = res {
                        if addend != 0 { return Err(ValueInfoFail::LoopWithAddend); }
                        // this path is a loop but others may not be
                        continue;
                    }
                    // but other failures are fatal
                    let res = try!(res);
                    if let Some(ref mut existing) = existing {
                        //println!("existing={:?} res={:?}", existing, res);
                        if existing.setter_idx != res.setter_idx { existing.setter_idx = None; }
                        if existing.value != res.value { existing.value = None; }
                        if existing.setter_idx.is_none() && existing.value.is_none() {
                            return Err(ValueInfoFail::DifferentValues);
                        }
                    } else {
                        existing = Some(res);
                    }
                }
                return existing.ok_or(ValueInfoFail::Loop);
            } else {
                panic!("value_info_inner: unseen?");
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
}
