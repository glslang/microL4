//! Kernel invocations: `Call`s on Untyped, CNode and TCB capabilities with
//! their labels (`docs/abi.md`, "Untyped invocations", "CNode invocations"
//! and "TCB invocations").
//!
//! [`invoke`] lays a message out as the kernel reads it: MR0 to MR3 in
//! registers, MR4 and up and the extra capability pointers in the calling
//! thread's IPC buffer. Only a thread with a buffer can send those, so the
//! wrappers that may need one take the caller's [`Ipc`]; the others take
//! none and work in a thread without a buffer. A reply with a non-zero
//! label is an [`Error`].

use l4core::bootinfo::CAP_INIT_CNODE;
use l4core::cap::{ObjectType, Rights};
use l4core::invoke::label as cnode_label;
use l4core::ipc::{MSG_MAX_EXTRA_CAPS, MSG_MAX_LENGTH, MSG_REG_COUNT, MessageInfo, word};
use l4core::regs::{USER_REGS, UserReg};
use l4core::tcb::label as tcb_label;

use crate::error::{Error, MAX_DETAIL_WORDS};
use crate::syscall::{CPtr, Ipc, Message, call};

/// `TCB_ReadRegisters` flag: suspend the target first.
pub const READ_SUSPEND_SOURCE: u64 = 1 << 0;
/// `TCB_WriteRegisters` flag: resume the target afterwards.
pub const WRITE_RESUME_TARGET: u64 = 1 << 0;

/// The successful reply to an invocation: label 0 and `length` result
/// words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub info: MessageInfo,
    /// MR0 to MR3.
    pub mr: [u64; MSG_REG_COUNT],
    ipc: Option<Ipc>,
}

impl Reply {
    /// Result words received.
    pub fn length(&self) -> usize {
        self.info.length() as usize
    }

    /// Result word `i`: MR0 to MR3 from registers, the rest from the
    /// caller's IPC buffer. Panics past `length` or without a buffer.
    pub fn word(&self, i: usize) -> u64 {
        assert!(i < self.length(), "result word {i} of {}", self.length());
        match self.mr.get(i) {
            Some(&w) => w,
            None => self.ipc.expect("results past MR3 need an IPC buffer").mr(i),
        }
    }
}

/// Performs invocation `label` on `cap` by `Call`, with `args` as MR0 and
/// up and `caps` as the extra capabilities. `ipc` is the calling thread's
/// IPC buffer; it may be `None` only for at most four `args` and no `caps`
/// (panics otherwise).
pub fn invoke(
    ipc: Option<Ipc>,
    cap: CPtr,
    label: u64,
    args: &[u64],
    caps: &[CPtr],
) -> Result<Reply, Error> {
    assert!(
        args.len() <= MSG_MAX_LENGTH,
        "{} message registers",
        args.len()
    );
    assert!(
        caps.len() <= MSG_MAX_EXTRA_CAPS,
        "{} extra caps",
        caps.len()
    );
    let buffer = || ipc.expect("this invocation needs the caller's IPC buffer");
    let mut mr = [0; MSG_REG_COUNT];
    for (i, &a) in args.iter().enumerate() {
        match mr.get_mut(i) {
            Some(r) => *r = a,
            None => buffer().set_mr(i, a),
        }
    }
    for (i, &c) in caps.iter().enumerate() {
        buffer().set_word(word::CAPS_OR_BADGES + i, c);
    }
    let info = MessageInfo::new(label, 0, caps.len() as u64, args.len() as u64);
    let reply = call(cap, &Message::new(info, mr));
    if reply.info.label() == 0 {
        return Ok(Reply {
            info: reply.info,
            mr: reply.mr,
            ipc,
        });
    }
    let mut words = [0; MAX_DETAIL_WORDS];
    let n = (reply.info.length() as usize).min(MAX_DETAIL_WORDS);
    for (i, w) in words.iter_mut().enumerate().take(n) {
        *w = match reply.mr.get(i) {
            Some(&r) => r,
            // A thread without a buffer received only MR0 to MR3, and
            // `length` says so.
            None => ipc.map_or(0, |b| b.mr(i)),
        };
    }
    Err(Error::decode(reply.info, &words))
}

/// A slot argument (`docs/abi.md`, "Capability lookup"): exactly the low
/// `depth` bits of `index`, resolved from the CNode capability `root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub root: CPtr,
    pub index: u64,
    pub depth: u64,
}

impl Slot {
    pub const fn new(root: CPtr, index: u64, depth: u64) -> Slot {
        Slot { root, index, depth }
    }

    /// Slot `n` of the root task's CNode: its guard covers the 52 bits
    /// above the 12-bit index, so `depth` is 64.
    pub const fn root_cnode(n: u64) -> Slot {
        Slot::new(CAP_INIT_CNODE, n, 64)
    }

    /// The CNode `root` itself, as `Untyped_Retype`'s destination
    /// (`node_depth` 0).
    pub const fn cnode_itself(root: CPtr) -> Slot {
        Slot::new(root, 0, 0)
    }
}

/// `Untyped_Retype`: `num_objects` objects of type `ty` (`size_bits` for an
/// Untyped or a CNode, ignored otherwise) in the CNode `node` names,
/// from slot `node_offset` on.
pub fn untyped_retype(
    ipc: Ipc,
    untyped: CPtr,
    ty: ObjectType,
    size_bits: u64,
    node: Slot,
    node_offset: u64,
    num_objects: u64,
) -> Result<(), Error> {
    let args = [
        ty as u64,
        size_bits,
        node.index,
        node.depth,
        node_offset,
        num_objects,
    ];
    invoke(
        Some(ipc),
        untyped,
        cnode_label::UNTYPED_RETYPE,
        &args,
        &[node.root],
    )?;
    Ok(())
}

/// `CNode_Revoke`: deletes every capability derived from the one in
/// `slot`; `slot.root` is the invoked CNode.
pub fn cnode_revoke(slot: Slot) -> Result<(), Error> {
    let args = [slot.index, slot.depth];
    invoke(None, slot.root, cnode_label::CNODE_REVOKE, &args, &[])?;
    Ok(())
}

/// `CNode_Delete`: deletes the capability in `slot`; `slot.root` is the
/// invoked CNode.
pub fn cnode_delete(slot: Slot) -> Result<(), Error> {
    let args = [slot.index, slot.depth];
    invoke(None, slot.root, cnode_label::CNODE_DELETE, &args, &[])?;
    Ok(())
}

/// `CNode_Copy`: copies `src` to `dest` with its rights ANDed with
/// `rights`; `dest.root` is the invoked CNode.
pub fn cnode_copy(ipc: Ipc, dest: Slot, src: Slot, rights: Rights) -> Result<(), Error> {
    let args = [
        dest.index,
        dest.depth,
        src.index,
        src.depth,
        rights.0.into(),
    ];
    invoke(
        Some(ipc),
        dest.root,
        cnode_label::CNODE_COPY,
        &args,
        &[src.root],
    )?;
    Ok(())
}

/// `CNode_Mint`: as [`cnode_copy`], and applies `data`: an endpoint's
/// badge or a CNode's guard (`docs/abi.md`, "Capability data").
pub fn cnode_mint(ipc: Ipc, dest: Slot, src: Slot, rights: Rights, data: u64) -> Result<(), Error> {
    let args = [
        dest.index,
        dest.depth,
        src.index,
        src.depth,
        rights.0.into(),
        data,
    ];
    invoke(
        Some(ipc),
        dest.root,
        cnode_label::CNODE_MINT,
        &args,
        &[src.root],
    )?;
    Ok(())
}

/// `CNode_Move`: moves the capability in `src` to `dest`.
pub fn cnode_move(ipc: Ipc, dest: Slot, src: Slot) -> Result<(), Error> {
    let args = [dest.index, dest.depth, src.index, src.depth];
    invoke(
        Some(ipc),
        dest.root,
        cnode_label::CNODE_MOVE,
        &args,
        &[src.root],
    )?;
    Ok(())
}

/// `CNode_Mutate`: moves the capability in `src` to `dest` and applies
/// `data` to it.
pub fn cnode_mutate(ipc: Ipc, dest: Slot, src: Slot, data: u64) -> Result<(), Error> {
    let args = [dest.index, dest.depth, src.index, src.depth, data];
    invoke(
        Some(ipc),
        dest.root,
        cnode_label::CNODE_MUTATE,
        &args,
        &[src.root],
    )?;
    Ok(())
}

/// `CNode_Rotate`: moves `pivot` to `dest` with `dest_data` applied, and
/// `src` to `pivot` with `pivot_data`.
pub fn cnode_rotate(
    ipc: Ipc,
    dest: Slot,
    dest_data: u64,
    pivot: Slot,
    pivot_data: u64,
    src: Slot,
) -> Result<(), Error> {
    let args = [
        dest.index,
        dest.depth,
        dest_data,
        pivot.index,
        pivot.depth,
        pivot_data,
        src.index,
        src.depth,
    ];
    invoke(
        Some(ipc),
        dest.root,
        cnode_label::CNODE_ROTATE,
        &args,
        &[pivot.root, src.root],
    )?;
    Ok(())
}

/// A thread's IPC buffer for `TCB_Configure` and `TCB_SetIPCBuffer`: its
/// user address, a multiple of 1024, and the non-device frame that holds
/// it. The kernel reaches the buffer through the frame, at the address
/// modulo the frame size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcBufferFrame {
    pub addr: u64,
    pub frame: CPtr,
}

/// `TCB_Configure`: the fault endpoint (a `CPtr` the kernel looks up in
/// the thread's CSpace when it faults; 0 for none), the CSpace root with
/// `cspace_root_data` applied (0 keeps its guard), the VSpace root and the
/// IPC buffer.
pub fn tcb_configure(
    ipc: Ipc,
    tcb: CPtr,
    fault_ep: CPtr,
    cspace_root: CPtr,
    cspace_root_data: u64,
    vspace_root: CPtr,
    buffer: Option<IpcBufferFrame>,
) -> Result<(), Error> {
    let args = [fault_ep, cspace_root_data, buffer.map_or(0, |b| b.addr)];
    let caps = [cspace_root, vspace_root, buffer.map_or(0, |b| b.frame)];
    // The frame only with a buffer.
    let caps = &caps[..2 + usize::from(buffer.is_some())];
    invoke(Some(ipc), tcb, tcb_label::CONFIGURE, &args, caps)?;
    Ok(())
}

/// `TCB_SetPriority`, bounded by the MCP of the TCB `authority`.
pub fn tcb_set_priority(ipc: Ipc, tcb: CPtr, authority: CPtr, priority: u64) -> Result<(), Error> {
    invoke(
        Some(ipc),
        tcb,
        tcb_label::SET_PRIORITY,
        &[priority],
        &[authority],
    )?;
    Ok(())
}

/// `TCB_SetSchedParams`: the MCP and the priority, both bounded by the MCP
/// of the TCB `authority`.
pub fn tcb_set_sched_params(
    ipc: Ipc,
    tcb: CPtr,
    authority: CPtr,
    mcp: u64,
    priority: u64,
) -> Result<(), Error> {
    invoke(
        Some(ipc),
        tcb,
        tcb_label::SET_SCHED_PARAMS,
        &[mcp, priority],
        &[authority],
    )?;
    Ok(())
}

/// `TCB_SetIPCBuffer`: the thread's IPC buffer, or none.
pub fn tcb_set_ipc_buffer(
    ipc: Ipc,
    tcb: CPtr,
    buffer: Option<IpcBufferFrame>,
) -> Result<(), Error> {
    let args = [buffer.map_or(0, |b| b.addr)];
    let frame = buffer.map(|b| b.frame);
    invoke(
        Some(ipc),
        tcb,
        tcb_label::SET_IPC_BUFFER,
        &args,
        frame.as_slice(),
    )?;
    Ok(())
}

/// `TCB_Suspend`: the thread becomes `Inactive`, and any IPC it is
/// blocked in, a pending fault included, is cancelled.
pub fn tcb_suspend(tcb: CPtr) -> Result<(), Error> {
    invoke(None, tcb, tcb_label::SUSPEND, &[], &[])?;
    Ok(())
}

/// `TCB_Resume`: an `Inactive` or blocked thread restarts at its `rip`.
pub fn tcb_resume(tcb: CPtr) -> Result<(), Error> {
    invoke(None, tcb, tcb_label::RESUME, &[], &[])?;
    Ok(())
}

/// The user register set in `docs/abi.md`'s order ("User register set"),
/// which `TCB_ReadRegisters` and `TCB_WriteRegisters` use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Registers(pub [u64; USER_REGS]);

impl Registers {
    pub const ZERO: Registers = Registers([0; USER_REGS]);

    pub fn get(&self, r: UserReg) -> u64 {
        self.0[r.index()]
    }

    pub fn set(&mut self, r: UserReg, value: u64) {
        self.0[r.index()] = value;
    }

    /// Itself with `r` set to `value`.
    pub fn with(mut self, r: UserReg, value: u64) -> Registers {
        self.set(r, value);
        self
    }
}

/// `TCB_WriteRegisters`: writes the first `count` words of `regs`, which
/// the kernel sanitises, then resumes the thread if `resume`.
pub fn tcb_write_registers(
    ipc: Ipc,
    tcb: CPtr,
    resume: bool,
    regs: &Registers,
    count: usize,
) -> Result<(), Error> {
    assert!(count <= USER_REGS, "{count} registers");
    let flags = if resume { WRITE_RESUME_TARGET } else { 0 };
    let mut args = [0; 2 + USER_REGS];
    args[0] = flags;
    args[1] = count as u64;
    args[2..2 + count].copy_from_slice(&regs.0[..count]);
    invoke(
        Some(ipc),
        tcb,
        tcb_label::WRITE_REGISTERS,
        &args[..2 + count],
        &[],
    )?;
    Ok(())
}

/// `TCB_ReadRegisters`: the first `count` words of the thread's registers,
/// suspending it first if `suspend`. Without an IPC buffer the caller gets
/// at most four; the words not received read as 0.
pub fn tcb_read_registers(
    ipc: Option<Ipc>,
    tcb: CPtr,
    suspend: bool,
    count: usize,
) -> Result<Registers, Error> {
    let flags = if suspend { READ_SUSPEND_SOURCE } else { 0 };
    let reply = invoke(
        ipc,
        tcb,
        tcb_label::READ_REGISTERS,
        &[flags, count as u64],
        &[],
    )?;
    let mut regs = Registers::ZERO;
    for i in 0..reply.length().min(USER_REGS) {
        regs.0[i] = reply.word(i);
    }
    Ok(regs)
}
