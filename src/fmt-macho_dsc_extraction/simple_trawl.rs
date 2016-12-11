extern crate dis_generated_jump_dis;
extern crate exec;

use self::dis_generated_jump_dis::{Reg, AArch64Handler, GenericHandler, TargetAddr, InsnKind, Size, CC};
use std::collections::VecDeque;
use self::exec::VMA;
use std::cell::Cell;
use util;
use util::Narrow;

type InsnIdx = usize;

struct InsnStateOther {
    flows_from: Vec<InsnIdx>,
    is_root: bool,
    vfr_req: ValueForRegReq,
    vfr_state: ValueForRegState,
}

struct ValueForRegReq {
    generation: usize,
    reg: Reg,
    addend: u64,
}

enum ValueForRegState {
    None,
    InProgress,
    Finished(Result<u64, ValueForRegFail>),
}

impl InsnStateOther {
    fn new(flows_from: Vec<InsnIdx>) -> Self {
        InsnStateOther {
            flows_from: flows_from,
            is_root: false,
            vfr_req: ValueForRegReq { generation: 0, reg: Reg::invalid(), addend: 0 },
            vfr_state: ValueForRegState::None,
        }
    }
}

struct CodeMap<'a> {
    region_start: VMA,
    region_size: u64,
    grain_shift: u8,
    insn_data: &'a [Cell<u8>],
    // 0 => unseen
    // -x => distance to previous instruction, which flows to this one
    // +x => index into insn_state_other
    insn_state: Vec<i32>,
    insn_state_other: Vec<InsnStateOther>,
    todo: VecDeque<InsnIdx>,
    switch_info: Vec<SwitchInfo>,
    endian: Endian,
}

#[derive(Debug)]
enum SwitchInfo {
    LoadShiftedBr { load_shifted_idx: InsnIdx, branch_idx: InsnIdx, pc_base: VMA },
}

#[derive(Clone, Copy, Debug)]
enum ValueForRegFail {
    DifferentValues,
    StackOverflow,
    SetWithUnknownInsn,
    Loop,
    Weird,
    FoundRoot,
}

impl<'a> CodeMap<'a> {
    fn new(region_start: VMA, grain_shift: u8, insn_data: &'a [Cell<u8>]) -> Self {
        let region_size = (insn_data.len() >> grain_shift) as u64;
        let num_insns: usize = (region_size >> grain_shift).narrow().unwrap();
        CodeMap {
            region_start: region_start,
            region_size: region_size,
            grain_shift: grain_shift,
            insn_data: insn_data,
            insn_state: util::zero_vec(num_insns),
            // start with dummy 0 entry
            insn_state_other: vec![InsnStateOther::new(Vec::new())],
            todo: VecDeque::new(),
            switch_branches: Vec::new(),
        }
    }
    fn addr_to_idx(&self, addr: VMA) -> Option<InsnIdx> {
        let offset = addr.wrapping_sub(self.region_start);
        if offset < self.region_size &&
           offset & ((1 << self.grain_shift) - 1) == 0 {
            Some((offset >> self.grain_shift) as usize)
        } else {
            None
        }
    }
    #[inline]
    fn idx_to_addr(&self, addr: InsnIdx) -> VMA {
        self.region_start + (addr << self.grain_shift) as u64
    }
    // returns whether we should proceed
    fn mark_flow(&mut self, from: InsnIdx, to: InsnIdx, is_flow: bool) -> bool {
        println!("mark_flow from {} to {}", from, to);
        let state = &mut self.insn_state[to];
        let old = *state;
        if old > 0 {
            self.insn_state_other[old as usize].flows_from.push(from);
            false;
        } else if old == 0 && is_flow {
            *state = -((to - from) as i32);
            true
        } else {
            *state = self.insn_state_other.len().narrow().unwrap();
            let vec = if old == 0 {
                self.todo.push_back(to);
                vec![from]
            } else {
                let old_from = to.wrapping_add(old as usize);
                vec![old_from, from]
            };
            self.insn_state_other.push(InsnStateOther::new(vec));
            false
        }
    }
    fn get_or_make_insn_state_other(&mut self, idx: InsnIdx) -> &mut InsnStateOther {
        let state = &mut self.insn_state[to];
        let mut val = *state;
        if val <= 0 {
            val = self.insn_state_other.len().narrow().unwrap();
            *state = val;
            let vec = if val == 0 { Vec::new() } else {
                let old_from = to.wrapping_add(val as usize);
                vec![old_from]
            };
            self.insn_state_other.push(InsnStateOther::new(vec));
        }
        &mut self.insn_state_other[val as usize]
    }
    fn mark_root(&mut self, idx: InsnIdx) {
        // this should only happen at the beginning
        assert!(self.insn_state[idx] == 0);
        self.get_or_make_insn_state_other(idx).is_root = true;
        self.todo.push_back(idx);
        println!("mark_root {}", idx);
    }
    fn go<H: GenericHandler>(&mut self, handler: &mut H) {
        let grain_shift = self.grain_shift;
        while let Some(mut start_idx) = self.todo.pop_front() {
            let mut last_load_shifted_target_reg = Reg::invalid();
            let mut last_load_shifted_idx: InsnIdx = 0;
            let mut idx = start_idx;
            loop {
                let (size, info) = self.decode(handler, idx);
                let next_idx = idx + (size >> grain_shift);
                if let TargetAddr::Code(addr) = info.target_addr {
                    if let Some(target_idx) = self.addr_to_idx(addr) {
                        self.mark_flow(idx, target_idx, false);
                    }
                }
                let should_cont = match info.kind {
                    InsnKind::Tail | InsnKind::Unidentified => false,
                    InsnKind::Br(target) => {
                        if target == last_load_shifted_target_reg {
                            self.switch_info.push(SwitchInfo::LoadShiftedBr { load_shifted_idx: last_load_shifted_idx });
                        }
                        false
                    },
                    _ => self.mark_flow(idx, next_idx, true),
                };
                if !should_cont { break; }
                match info.kind {
                    InsnKind::LoadShifted(target, ..) => {
                        last_load_shifted_target_reg = target;
                        last_load_shifted_idx = idx;
                    },
                    _ => if info.kills_reg(last_load_shifted_target_reg) {
                        last_load_shifted_target_reg = Reg::invalid();
                    },
                };
                idx = next_idx;
            }

        }
    }
    #[inline]
    fn decode(&mut self, handler: &'a mut GenericHandler, idx: InsnIdx) -> (usize, &'a InsnInfo) {
        let offset = idx << grain_shift;
        let data = &self.insn_data[offset..];
        let addr = self.region_start + (offset as u64);
        handler.decode(addr, data)
    }

    fn grok_switch(&mut self, handler: &mut GenericHandler, switch_info: &SwitchInfo, read: &mut FnMut(VMA, usize) -> Option<&[Cell<u8>]>) -> bool {
        // TODO I forgot the add-pc which comes after load-shifted
        match *switch_info {
            SwitchInfo::LoadShiftedBr { load_shifted_idx, branch_idx, pc_base } => {
                let (base_reg, index_reg, shift, size, signedness) = {
                    let (_, info) = handler.decode(load_shifted_idx);
                    match info.kind {
                        InsnKind::LoadShifted(_, base_reg, index_reg, shift, size, signedness) => (base_reg, index_reg, shift, size, signedness),
                        _ => unreachable!(),
                    }
                };
                let table_addr = match self.value_for_reg(handler, load_shifted_idx, base_reg, 0, 0) {
                    Ok(a) => a,
                    Err(e) => {
                        errln!("grok_switch: value_for_reg({:?} @ {}) -> {:?}", base_reg, self.idx_to_addr(load_shifted_idx), e);
                        return false;
                    },
                };
                let table_len: u64;
                {
                    let mut idx = load_shifted_idx;
                    let mut i = 0;
                    loop {
                        i += 1;
                        if i >= 5 {
                            errln!("grok_switch: too far away (at {}) when trying to find cmp", self.idx_to_addr(idx));
                            return false;
                        }
                        idx = some_or!(self.sole_pred(idx), {
                            errln!("grok_switch: no sole pred for {} when trying to find cmp", self.idx_to_addr(idx));
                            return false;
                        });
                        let (_, info) = handler.decode(load_shifted_idx);
                        match info.kind {
                            InsnKind::CmpImm(r, u) if r == index_reg => {
                                table_len = u;
                                break;
                            },
                            _ => if info.kills_reg(index_reg) {
                                errln!("grok_switch: index reg {:?} killed at {} when trying to find cmp", index_reg, self.idx_to_addr(idx));
                                return false;
                            },
                        }
                    }
                }
                if table_len > 100000 {
                    errln!("grok_switch: table length {} is /probably/ absurd (ls at {})", table_len, self.idx_to_addr(load_shifted_idx));
                }
                // I guess we got it
                let bytes = size.bits() / 8;
                let table_bytes = table_len * bytes;
                let table = some_or!(read(table_addr, table_bytes), {
                    errln!("grok_switch: failed to read table at {} size {}", table_addr, table_bytes);
                    return false;
                });
                for (i, chunk) in table.chunks(bytes).enumerate() {
                    let val = exec::dynsized_integer_from_slice(chunk, signedness, self.endian);
                    let addr = pc_base.wrapping_add(val);
                    if let Some(target_idx) = self.addr_to_idx(addr) {
                        targets.add(target_idx);
                        // TODO TODO TODO duplicates
                        self.mark_flow(branch_idx, target_idx, false);
                    } else {
                        errln!("grok_switch: out-of-range(?) switch branch to {} from table element at {}", addr, table_addr + i * bytes);
                    }
                }

            },
            // ^ most of that code should apply to other types too
        }
    }
    fn value_for_reg<H: GenericHandler>(&mut self, handler: &mut GenericHandler, idx: InsnIdx, reg: Reg, mut addend: u64, depth: usize) -> Result<u64, ValueForRegFail> {
        if depth > 20 {
            return Err(ValueForRegFail::StackOverflow);
        }
        {
            let iso = self.get_or_make_insn_state_other(idx);
            if iso.is_root {
                return Err(ValueForRegFail::FoundRoot);
            }
            let is_match = iso.vfr_req.reg == reg && iso.vfr_req.addend == addend;
            if !is_match && iso.vfr_req.generation != self.generation {
                iso.vfr_state = ValueForRegState::None;
            }
            match iso.vfr_state {
                ValueForRegState::None => {
                    iso.vfr_req.reg = reg;
                    iso.vfr_req.addend = addend;
                    iso.vfr_state = ValueForRegState::InProgress;
                },
                ValueForRegState::InProgress => {
                    if is_match {
                        return Err(ValueForRegFail::Loop);
                    } else {
                        return Err(ValueForRegFail::Weird);
                    }
                },
                ValueForRegState::Finished(res) => {
                    if is_match {
                        return res;
                    } else {
                        return Err(ValueForRegFail::Weird);
                    }
                }
            }
        }
        let res = self.value_for_reg_inner(handler, idx, reg, depth);
        {
            let iso = &mut self.insn_state_other[self.insn_state[idx] as usize];
            iso.vfr_state = ValueForRegState::Finished(res);
        }
        res
    }

    fn value_for_reg_inner(&mut self, handler: &mut GenericHandler, idx: InsnIdx, mut reg: Reg, depth: usize) -> Result<u64, ValueForRegFail> {
        let mut addend = 0u64;
        loop {
            let (_, info) = handler.decode(idx);
            match info.kind {
                InsnKind::SetImm(r, val) if r == reg =>
                    return Ok(val.wrapping_add(addend)),
                InsnKind::AddImm(r, r2, val) if r == reg => {
                    addend = addend.wrapping_add(val);
                    reg = r2;
                },
                _ => if info.kills_reg(reg) {
                    return Err(ValueForRegFail::SetWithUnknownInsn);
                },
            }
            let state_word = self.insn_state[idx];
            if state_word < 0 {
                idx = idx.wrapping_add(state_word as usize);
            } else if state_word > 0 {
                let mut val: Option<u64> = None;
                let mut i = 0;
                loop {
                    let from_idx = {
                        let flows_from = &self.insn_state_other[state_word as usize].flows_from;
                        some_or!(flows_from.get(i), { break; })
                    };
                    i += 1;
                    let res = self.value_for_reg_inner(handler, idx, reg, depth + 1);
                    if res == Err(ValueForRegFail::Loop) {
                        // this path is a loop but others may not be
                        continue;
                    }
                    // but other failures are fatal
                    let this_val = try!(res);
                    if let Some(val) = val {
                        if this_val != val {
                            return Err(ValueForRegFail::DifferentValues);
                        }
                    } else {
                        val = Some(this_val);
                    }
                }
                let val = some_or!(val, { return Err(ValueForRegFail::Loop); });
                return Ok(val);
            } else {
                panic!("value_for_reg: unseen?");
            }
        }
    }
}
