//! `test=redteam-tlb` and `test=redteam-selfdelete`.
//!
//! **TLB.** The root task maps frames into its own VSpace at
//! [`WINDOW`], writes a marker through each mapping so its translation is
//! in the TLB, then takes the access away one way or another: unmap,
//! remap read-only, delete or revoke the frame capability, unmap or delete
//! the page table, page directory or PDPT above it, revoke and reuse the
//! untyped the frame came from, and the same for a 2 MiB frame. A prober
//! thread in the same VSpace, so the switch to it writes no CR3, then
//! touches the address ([`rt_touch`]): it must fault, and a read the
//! mapping still allows must see the marker. A stale TLB entry would let
//! the access through.
//!
//! **Self-deletion.** A thread whose TCB, IPC buffer frame and VSpace (a
//! PML4 of its own with copies of the root task's image frames) all come
//! from one untyped U, and whose TCB holds the last capability to that
//! PML4, deletes the last capability to its own TCB with one `Call`, with
//! its FS base set and a marker in XMM0. The kernel must finish the call,
//! leave CR3 off the dead PML4, never run the thread again and not reply.
//! Then the root task revokes U and retypes a new TCB at the same address:
//! it must start with FS base 0 and the initial FP state, not the dead
//! thread's. A second thread then revokes the untyped its own TCB,
//! VSpace and IPC buffer come from, in one call.

use core::arch::global_asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use libsys::bootinfo::{CAP_INIT_CNODE, CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::invoke::{
    Slot, cnode_copy, cnode_delete, cnode_revoke, invoke, tcb_configure, tcb_read_registers,
    tcb_set_priority, tcb_suspend, untyped_retype,
};
use libsys::{
    BootInfo, CPtr, Ipc, IpcBufferFrame, MessageInfo, ObjectAlloc, ObjectType, Rights, UserReg,
    println, recv,
};

use super::{FAULT_BADGE, USER_EXCEPTION, USER_REGS, VM_FAULT, prober, start};
use crate::fail;
use crate::spawn::STACKS;

/// Labels (`docs/abi.md`, "Invocation labels", "TCB invocations").
const PDPT_MAP: u64 = 0x40;
const PDPT_UNMAP: u64 = 0x41;
const PD_MAP: u64 = 0x42;
const PD_UNMAP: u64 = 0x43;
const PT_MAP: u64 = 0x44;
const PT_UNMAP: u64 = 0x45;
const FRAME_MAP: u64 = 0x50;
const FRAME_UNMAP: u64 = 0x51;
const FRAME_REMAP: u64 = 0x52;
const CNODE_DELETE: u64 = 0x11;
const CNODE_REVOKE: u64 = 0x10;
const TCB_SET_TLS_BASE: u64 = 0x2D;
/// Rights words.
const RW: u64 = Rights::READ.0 as u64 | Rights::WRITE.0 as u64;
const RO: u64 = Rights::READ.0 as u64;
/// Attributes: write-back, and write-back executable.
const WB: u64 = 0;
const WB_X: u64 = 1 << 3;

/// A 1 GiB-aligned window nothing else in the root task's VSpace uses:
/// PML4 entry 1.
const WINDOW: u64 = 0x80_0000_0000;
/// Where the 2 MiB frame goes in the window.
const WINDOW_2M: u64 = WINDOW + 0x40_0000;

// The prober's code. `rt_touch(addr, op, value)`: op 0 reads the word at
// `addr`, op 1 writes `value` there; either way, if the access worked, the
// thread then runs `ud2` with the word in `rax`. `rt_selfdel(cnode, info,
// index)`: puts a marker in XMM0, then makes the `Call` `CNode_Delete` of
// slot `index` (depth 64) in `cnode` with `info`; past it, which it must
// never get, it sets `RT_WENT_ON` and runs `ud2`. `rt_state`: puts XMM0's
// low half in `r14` and reads FS:[0x10], which faults.
global_asm!(
    ".pushsection .text.rt_vm, \"ax\", @progbits",
    ".global rt_touch, rt_selfdel, rt_state",
    "rt_touch:",
    "    test rsi, rsi",
    "    jnz 1f",
    "    mov rax, qword ptr [rdi]",
    "    ud2",
    "1:",
    "    mov qword ptr [rdi], rdx",
    "    mov rax, rdx",
    "    ud2",
    "rt_selfdel:",
    "    movabs rax, 0x5e1fde1e7e5e1f00",
    "    movq xmm0, rax",
    "    mov r10, rdx",
    "    mov r8d, 64",
    "    mov edx, 1",
    "    syscall",
    "    lea rax, [rip + {went_on}]",
    "    mov qword ptr [rax], 1",
    "    ud2",
    "rt_state:",
    "    movq rax, xmm0",
    "    mov r14, rax",
    "    mov rax, qword ptr fs:[0x10]",
    "    ud2",
    ".popsection",
    went_on = sym RT_WENT_ON,
);

/// Set by a self-deleting thread that ran past its `Call`.
static RT_WENT_ON: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn rt_touch();
    fn rt_selfdel();
    fn rt_state();
}

fn addr(f: unsafe extern "C" fn()) -> u64 {
    f as *const () as u64
}

/// An invocation that must succeed.
fn must(ipc: Ipc, what: &str, cap: CPtr, label: u64, args: &[u64], caps: &[CPtr]) {
    if let Err(e) = invoke(Some(ipc), cap, label, args, caps) {
        fail!("{what}: {e}");
    }
}

fn map_frame(ipc: Ipc, frame: CPtr, vaddr: u64, rights: u64, attrs: u64, vspace: CPtr) {
    must(
        ipc,
        "Frame_Map",
        frame,
        FRAME_MAP,
        &[vaddr, rights, attrs],
        &[vspace],
    );
}

fn map_table(ipc: Ipc, table: CPtr, label: u64, vaddr: u64, vspace: CPtr) {
    must(
        ipc,
        "a paging structure's Map",
        table,
        label,
        &[vaddr],
        &[vspace],
    );
}

/// What a probe of an address found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touch {
    /// The access worked; a read saw this word.
    Done(u64),
    /// A VMFault at this address with this error code.
    Fault { addr: u64, fsr: u64 },
}

/// Runs `rt_touch` in the prober and reports what happened.
fn touch(ipc: Ipc, tcb: CPtr, ep: CPtr, at: u64, write: bool, value: u64) -> Touch {
    start(
        ipc,
        tcb,
        addr(rt_touch),
        STACKS[0].top() - 8,
        [at, u64::from(write), value],
    );
    let r = recv(ep);
    if r.badge != FAULT_BADGE {
        fail!("badge {:#x} on the fault endpoint", r.badge);
    }
    let regs = tcb_read_registers(Some(ipc), tcb, true, USER_REGS)
        .unwrap_or_else(|e| fail!("reading the prober: {e}"));
    match (r.msg.info.label(), r.msg.mr[3]) {
        (USER_EXCEPTION, 6) => Touch::Done(regs.get(UserReg::Rax)),
        (VM_FAULT, fsr) => Touch::Fault {
            addr: r.msg.mr[1],
            fsr,
        },
        (label, w) => fail!(
            "the prober raised fault {label} ({w:#x}) at {:#x}",
            r.msg.mr[0]
        ),
    }
}

fn root_write(at: u64, v: u64) {
    // SAFETY: the caller has just mapped a frame RW at `at`, which nothing
    // in this program refers to.
    unsafe { ptr::write_volatile(at as *mut u64, v) };
}

fn root_read(at: u64) -> u64 {
    // SAFETY: as in `root_write`, mapped readable.
    unsafe { ptr::read_volatile(at as *const u64) }
}

/// Checks that the prober's access to `at` faults now, after `what`, which
/// took away the mapping (or its write right) the root task just used.
fn must_fault(ipc: Ipc, tcb: CPtr, ep: CPtr, what: &str, at: u64, write: bool) {
    match touch(ipc, tcb, ep, at, write, 0xBAD) {
        Touch::Fault { addr, fsr } if addr == at => {
            println!(
                "redteam: tlb: after {what}, a {} of {at:#x} faults (fsr {fsr:#x})",
                if write { "write" } else { "read" }
            );
        }
        other => fail!(
            "redteam: tlb: after {what}, a {} of {at:#x} gave {other:x?}: a stale translation",
            if write { "write" } else { "read" }
        ),
    }
}

/// `test=redteam-tlb`.
pub fn tlb(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let ep = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the endpoint: {e}"));
    let tcb = prober(ipc, &mut objects, ep);
    let retype = |objects: &mut ObjectAlloc<'_>, ty: ObjectType, size: u64, n: u64| {
        objects
            .retype(ipc, ty, size, n)
            .unwrap_or_else(|e| fail!("retyping {n} {ty:?}: {e}"))
    };
    let pdpt = retype(&mut objects, ObjectType::Pdpt, 0, 1);
    let pd = retype(&mut objects, ObjectType::PageDirectory, 0, 1);
    let pts = retype(&mut objects, ObjectType::PageTable, 0, 2);
    let frames = retype(&mut objects, ObjectType::Frame4K, 0, 2);
    let big = retype(&mut objects, ObjectType::Frame2M, 0, 1);
    let copies = objects
        .slots
        .alloc(2)
        .unwrap_or_else(|| fail!("no slots for frame copies"));
    let vs = CAP_INIT_VSPACE;
    map_table(ipc, pdpt, PDPT_MAP, WINDOW, vs);
    map_table(ipc, pd, PD_MAP, WINDOW, vs);
    map_table(ipc, pts, PT_MAP, WINDOW, vs);
    let (f, v) = (frames, WINDOW + 0x1000);
    let mut marker = 0x7EB0_0000_0000_0000u64;
    // Maps `frame` at `at` RW and writes a fresh marker through it, which
    // puts the translation in the TLB.
    let mut prime = |frame: CPtr, at: u64| -> u64 {
        map_frame(ipc, frame, at, RW, WB, vs);
        marker += 1;
        root_write(at, marker);
        if root_read(at) != marker {
            fail!("the root task read back {:#x} at {at:#x}", root_read(at));
        }
        marker
    };

    // 1. Frame_Unmap.
    prime(f, v);
    must(ipc, "Frame_Unmap", f, FRAME_UNMAP, &[], &[]);
    must_fault(ipc, tcb, ep, "Frame_Unmap", v, false);

    // 2. Frame_Remap read-only: a write faults, a read sees the marker.
    let m = prime(f, v);
    must(ipc, "Frame_Remap", f, FRAME_REMAP, &[RO, WB], &[]);
    must_fault(ipc, tcb, ep, "Frame_Remap to read-only", v, true);
    match touch(ipc, tcb, ep, v, false, 0) {
        Touch::Done(w) if w == m => {}
        other => fail!("a read after Frame_Remap to read-only gave {other:x?}, want {m:#x}"),
    }
    must(ipc, "Frame_Unmap", f, FRAME_UNMAP, &[], &[]);

    // 3. CNode_Delete of a mapped copy.
    cnode_copy(
        ipc,
        Slot::root_cnode(copies),
        Slot::root_cnode(f),
        Rights::ALL,
    )
    .unwrap_or_else(|e| fail!("copying the frame: {e}"));
    prime(copies, v);
    cnode_delete(Slot::root_cnode(copies)).unwrap_or_else(|e| fail!("deleting the copy: {e}"));
    must_fault(ipc, tcb, ep, "CNode_Delete of the mapped copy", v, false);

    // 4. CNode_Revoke of the original deletes a mapped copy.
    cnode_copy(
        ipc,
        Slot::root_cnode(copies),
        Slot::root_cnode(f),
        Rights::ALL,
    )
    .unwrap_or_else(|e| fail!("copying the frame: {e}"));
    prime(copies, v);
    cnode_revoke(Slot::root_cnode(f)).unwrap_or_else(|e| fail!("revoking the frame: {e}"));
    must_fault(ipc, tcb, ep, "CNode_Revoke of the frame", v, false);

    // 5. PageTable_Unmap.
    prime(f, v);
    must(ipc, "PageTable_Unmap", pts, PT_UNMAP, &[], &[]);
    must_fault(ipc, tcb, ep, "PageTable_Unmap", v, false);
    map_table(ipc, pts, PT_MAP, WINDOW, vs);

    // 6. PageDirectory_Unmap: the page table keeps its entry, but nothing
    //    reaches it.
    prime(f, v);
    must(ipc, "PageDirectory_Unmap", pd, PD_UNMAP, &[], &[]);
    must_fault(ipc, tcb, ep, "PageDirectory_Unmap", v, false);
    must(ipc, "PageTable_Unmap", pts, PT_UNMAP, &[], &[]);
    map_table(ipc, pd, PD_MAP, WINDOW, vs);
    map_table(ipc, pts, PT_MAP, WINDOW, vs);

    // 7. PDPT_Unmap.
    prime(f, v);
    must(ipc, "PDPT_Unmap", pdpt, PDPT_UNMAP, &[], &[]);
    must_fault(ipc, tcb, ep, "PDPT_Unmap", v, false);
    must(ipc, "PageDirectory_Unmap", pd, PD_UNMAP, &[], &[]);
    must(ipc, "PageTable_Unmap", pts, PT_UNMAP, &[], &[]);
    map_table(ipc, pdpt, PDPT_MAP, WINDOW, vs);
    map_table(ipc, pd, PD_MAP, WINDOW, vs);
    map_table(ipc, pts, PT_MAP, WINDOW, vs);

    // 8. CNode_Delete of the page table.
    prime(f, v);
    cnode_delete(Slot::root_cnode(pts)).unwrap_or_else(|e| fail!("deleting the PT: {e}"));
    must_fault(ipc, tcb, ep, "CNode_Delete of the page table", v, false);
    map_table(ipc, pts + 1, PT_MAP, WINDOW, vs);

    // 9. Revoke the untyped a mapped frame came from, retype it again (the
    //    reset zeroes the page) and write through a new mapping elsewhere:
    //    the old address must fault, not show the new marker.
    let ut = retype(&mut objects, ObjectType::Untyped, 12, 1);
    let uf = objects
        .slots
        .alloc(2)
        .unwrap_or_else(|| fail!("no slots for the untyped's frames"));
    let new_frame = |slot: CPtr| {
        untyped_retype(
            ipc,
            ut,
            ObjectType::Frame4K,
            0,
            Slot::cnode_itself(CAP_INIT_CNODE),
            slot,
            1,
        )
        .unwrap_or_else(|e| fail!("retyping a frame from the small untyped: {e}"))
    };
    new_frame(uf);
    let v3 = WINDOW + 0x3000;
    prime(uf, v3);
    cnode_revoke(Slot::root_cnode(ut)).unwrap_or_else(|e| fail!("revoking the untyped: {e}"));
    new_frame(uf + 1);
    let v4 = WINDOW + 0x4000;
    let m4 = prime(uf + 1, v4);
    must_fault(ipc, tcb, ep, "a revoke and reuse of its untyped", v3, false);
    if root_read(v4) != m4 {
        fail!("the reused page reads {:#x}, want {m4:#x}", root_read(v4));
    }

    // 10. A 2 MiB frame: unmap, then remap read-only.
    let w = WINDOW_2M + 0x1000;
    map_frame(ipc, big, WINDOW_2M, RW, WB, vs);
    root_write(w, 0x2B);
    must(ipc, "Frame_Unmap (2 MiB)", big, FRAME_UNMAP, &[], &[]);
    must_fault(ipc, tcb, ep, "Frame_Unmap of a 2 MiB frame", w, false);
    map_frame(ipc, big, WINDOW_2M, RW, WB, vs);
    root_write(w + 0x1000, 0x2C);
    must(ipc, "Frame_Remap (2 MiB)", big, FRAME_REMAP, &[RO, WB], &[]);
    must_fault(
        ipc,
        tcb,
        ep,
        "Frame_Remap of a 2 MiB frame to read-only",
        w + 0x1000,
        true,
    );

    // 11. Map at USER_TOP and across the kernel half: refused.
    for (at, what) in [
        (0x7FFF_FFFF_F000u64, "USER_TOP"),
        (0xFFFF_8000_0000_0000, "the direct map"),
        (0xFFFF_FFFF_8000_0000, "kernel text"),
        (0x0000_8000_0000_0000, "2^47"),
        (0, "page 0"),
    ] {
        if invoke(Some(ipc), f, FRAME_MAP, &[at, RW, WB], &[vs]).is_ok() {
            fail!("Frame_Map at {at:#x} ({what}) succeeded");
        }
    }
    println!("redteam: tlb: Frame_Map at USER_TOP, 2^47, page 0 and in the kernel half: refused");
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// An address space of its own for a thread: a new PML4 with copies of the
/// root task's image frames at their addresses, all from untyped `ut`
/// through `next` (slots). Returns the PML4's slot.
fn own_vspace(ipc: Ipc, bi: &BootInfo, ut: CPtr, next: &mut CPtr) -> CPtr {
    let alloc = |next: &mut CPtr, ty: ObjectType| -> CPtr {
        let slot = *next;
        *next += 1;
        untyped_retype(ipc, ut, ty, 0, Slot::cnode_itself(CAP_INIT_CNODE), slot, 1)
            .unwrap_or_else(|e| fail!("retyping {ty:?} from U: {e}"));
        slot
    };
    let pml4 = alloc(next, ObjectType::Pml4);
    let first = bi.user_image_start;
    let pdpt = alloc(next, ObjectType::Pdpt);
    map_table(ipc, pdpt, PDPT_MAP, first, pml4);
    let pd = alloc(next, ObjectType::PageDirectory);
    map_table(ipc, pd, PD_MAP, first, pml4);
    let mut pt_base = u64::MAX;
    let frames = bi.user_image_frames;
    // Every page is covered but the guard page below the 64 KiB libsys
    // stack (`user/link.ld`); the thread needs only the pages below it.
    let pages = (bi.user_image_end - first) / 0x1000;
    if pages != frames.len() + 1 || pages < 17 {
        fail!(
            "{pages} image pages and {} frames: not one guard page",
            frames.len()
        );
    }
    for (i, frame) in (frames.start..frames.start + pages - 17).enumerate() {
        let at = first + 0x1000 * i as u64;
        if at >> 21 != pt_base {
            let pt = alloc(next, ObjectType::PageTable);
            map_table(ipc, pt, PT_MAP, at, pml4);
            pt_base = at >> 21;
        }
        let copy = *next;
        *next += 1;
        cnode_copy(
            ipc,
            Slot::root_cnode(copy),
            Slot::root_cnode(frame),
            Rights::ALL,
        )
        .unwrap_or_else(|e| fail!("copying image frame {frame}: {e}"));
        map_frame(ipc, copy, at, RW, WB_X, pml4);
    }
    pml4
}

/// `test=redteam-selfdelete`.
pub fn self_delete(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let ep = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the endpoint: {e}"));
    let observer = prober(ipc, &mut objects, ep);
    // U: 1 MiB, enough for a TCB, a buffer frame and an address space.
    let ut = objects
        .retype(ipc, ObjectType::Untyped, 20, 1)
        .unwrap_or_else(|e| fail!("retyping U: {e}"));
    let base = objects.slots.alloc(1).unwrap_or_else(|| fail!("no slots"));
    // The rest of the slot region is ours from here on.
    let mut next = base;

    for round in 0..2 {
        // The TCB first, at U's start, so the next round's lands on it.
        let tcb = next;
        next += 1;
        untyped_retype(
            ipc,
            ut,
            ObjectType::Tcb,
            0,
            Slot::cnode_itself(CAP_INIT_CNODE),
            tcb,
            1,
        )
        .unwrap_or_else(|e| fail!("retyping the TCB from U: {e}"));
        let buffer = next;
        next += 1;
        untyped_retype(
            ipc,
            ut,
            ObjectType::Frame4K,
            0,
            Slot::cnode_itself(CAP_INIT_CNODE),
            buffer,
            1,
        )
        .unwrap_or_else(|e| fail!("retyping the buffer frame from U: {e}"));
        let pml4 = own_vspace(ipc, bi, ut, &mut next);
        // The buffer frame, mapped in the thread's space past the image.
        let buffer_at = (bi.user_image_end + 0x10_0000) & !0xFFF;
        map_frame(ipc, buffer, buffer_at, RW, WB, pml4);
        let ep_copy = next;
        next += 1;
        super::mint_fault_ep(ipc, ep, ep_copy);
        tcb_configure(
            ipc,
            tcb,
            ep_copy,
            CAP_INIT_CNODE,
            0,
            pml4,
            Some(IpcBufferFrame {
                addr: buffer_at,
                frame: buffer,
            }),
        )
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, 100))
        .unwrap_or_else(|e| fail!("configuring the thread: {e}"));
        // The TCB's slot now holds the only capability to its PML4.
        cnode_delete(Slot::root_cnode(pml4)).unwrap_or_else(|e| fail!("deleting the PML4: {e}"));
        must(
            ipc,
            "TCB_SetTLSBase",
            tcb,
            TCB_SET_TLS_BASE,
            &[0x5E1F_0000],
            &[],
        );

        let (what, cptr, label) = if round == 0 {
            (
                "deletes the last capability to its own TCB",
                tcb,
                CNODE_DELETE,
            )
        } else {
            (
                "revokes U, which holds its TCB, VSpace and IPC buffer",
                ut,
                CNODE_REVOKE,
            )
        };
        println!("redteam: selfdelete: round {round}: thread {tcb} {what}");
        let info = MessageInfo::new(label, 0, 0, 2).word();
        // A Call on the root CNode: index `cptr`, depth 64.
        super::start(
            ipc,
            tcb,
            addr(rt_selfdel),
            STACKS[1].top() - 8,
            [CAP_INIT_CNODE, info, cptr],
        );
        // Below the thread, so it runs now; back up once it is gone.
        tcb_set_priority(ipc, CAP_INIT_TCB, CAP_INIT_TCB, 50)
            .and_then(|()| tcb_set_priority(ipc, CAP_INIT_TCB, CAP_INIT_TCB, 255))
            .unwrap_or_else(|e| fail!("the root task's priority: {e}"));
        if RT_WENT_ON.load(Ordering::Relaxed) != 0 {
            fail!("round {round}: the thread ran past the call that deleted it");
        }
        // Its TCB is gone, by its own call: the slot is empty.
        if tcb_suspend(tcb).is_ok() {
            fail!("round {round}: slot {tcb} still holds a TCB");
        }
        if round == 1 {
            break;
        }
        // Revoke U and make a TCB at the same address, which must start
        // clean.
        cnode_revoke(Slot::root_cnode(ut)).unwrap_or_else(|e| fail!("revoking U: {e}"));
        let fresh = next;
        next += 1;
        untyped_retype(
            ipc,
            ut,
            ObjectType::Tcb,
            0,
            Slot::cnode_itself(CAP_INIT_CNODE),
            fresh,
            1,
        )
        .unwrap_or_else(|e| fail!("retyping the new TCB from U: {e}"));
        let fresh_ep = next;
        next += 1;
        super::mint_fault_ep(ipc, ep, fresh_ep);
        tcb_configure(
            ipc,
            fresh,
            fresh_ep,
            CAP_INIT_CNODE,
            0,
            CAP_INIT_VSPACE,
            None,
        )
        .and_then(|()| tcb_set_priority(ipc, fresh, CAP_INIT_TCB, 100))
        .unwrap_or_else(|e| fail!("configuring the new thread: {e}"));
        start(ipc, fresh, addr(rt_state), STACKS[1].top() - 8, [0; 3]);
        let r = recv(ep);
        let regs = tcb_read_registers(Some(ipc), fresh, true, USER_REGS)
            .unwrap_or_else(|e| fail!("reading the new thread: {e}"));
        let (label, fault_addr) = (r.msg.info.label(), r.msg.mr[1]);
        let xmm0 = regs.get(UserReg::R14);
        println!(
            "redteam: selfdelete: a new TCB at the dead one's address: FS:[0x10] faults at {fault_addr:#x} (label {label}), XMM0 {xmm0:#x}"
        );
        if label != VM_FAULT || fault_addr != 0x10 || xmm0 != 0 {
            fail!("the new TCB started with the dead thread's FS base or FP state");
        }
        cnode_delete(Slot::root_cnode(fresh)).unwrap_or_else(|e| fail!("deleting it: {e}"));
        cnode_revoke(Slot::root_cnode(ut)).unwrap_or_else(|e| fail!("revoking U: {e}"));
    }
    // The observer still runs, in the root task's space.
    match touch(ipc, observer, ep, bi.user_image_start, false, 0) {
        Touch::Done(_) => {}
        other => fail!("the observer could not read the image: {other:x?}"),
    }
    println!("redteam: selfdelete: the kernel survived both, and nothing ran on");
    println!("TEST PASS");
    libsys::debug_halt(0)
}
