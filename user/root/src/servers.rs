//! Starting `watch`, `uart` and `console` (`docs/design.md`, "Where the
//! servers run", "Capabilities" and "Failures"), and from M8 `term` and
//! `tui` ("Framebuffer, terminal and TUI", "Where it runs"): each server
//! in a CSpace of its own, a 16-slot CNode filled from its crate's slot
//! table only, and a VSpace built from the root task's image frames by
//! `root::process::Plan`; `watch` in the root task's own spaces, receiving
//! the servers' faults on endpoint F. term's VSpace also maps its state
//! window and the framebuffer's frames, write-combining, from `fb::Plan`.
//! Nothing here prints, so a test on a kernel without `debug` can start
//! the servers before it has a console.

use core::fmt::Write;

use libsys::bootinfo::{CAP_INIT_TCB, CAP_INIT_VSPACE, CAP_IO_PORT_CONTROL, CAP_IRQ_CONTROL};
use libsys::device::{
    IsaIrq, ioport_control_issue, irq_control_get_isa, irq_handler_set_notification,
};
use libsys::invoke::{
    cnode_copy, cnode_mint, tcb_bind_notification, tcb_configure, tcb_resume, tcb_set_sched_params,
    tcb_write_registers,
};
use libsys::output::{EXIT_FAILURE, EXIT_PORT_NUMBER, IoPort, Polled};
use libsys::proto::{IRQ, KEYS, RX_READY, TERM_CLIENT};
use libsys::vspace::{self, EXECUTE, READ, READ_WRITE, Table, WRITE_BACK, WRITE_COMBINING};
use libsys::{
    BootInfo, CPtr, Ipc, IpcBufferFrame, ObjectAlloc, ObjectType, Registers, Rights, Slot, UserReg,
    recv,
};
use root::process::{FaultLine, Image, PAGE, PT_SPAN, Plan, Role, fault_badge};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// Priorities and MCPs (`docs/design.md`, "Server priorities").
pub const WATCH_PRIORITY: u64 = 255;
pub const UART_PRIORITY: u64 = 200;
pub const CONSOLE_PRIORITY: u64 = 150;
pub const CLIENT_PRIORITY: u64 = 100;
/// From M8: term above its client tui, below console, whose client it is.
pub const TERM_PRIORITY: u64 = 125;
pub const TUI_PRIORITY: u64 = 100;

/// The badge of root's own capability to term's endpoint T: `Stats` only.
pub const TERM_STATS_BADGE: u64 = 2;
/// tui's badge on endpoint C, as console's client 5, and on endpoint D.
pub const TUI_BADGE: u64 = 5;

// Every server's CNode has the same shape, which `fill` relies on.
const _: () = assert!(
    uart::slot::RADIX == console::slot::RADIX
        && uart::slot::RADIX == term::slot::RADIX
        && uart::slot::RADIX == tui::slot::RADIX
        && uart::slot::CNODE == term::slot::CNODE
        && uart::slot::CNODE == tui::slot::CNODE
);
// console's raw client is term.
const _: () = assert!(libsys::proto::CONSOLE_RAW_CLIENT == 4);

/// COM1's ports.
pub const COM1_FIRST: u16 = 0x3F8;
pub const COM1_LAST: u16 = 0x3FF;
/// The badge of root's own capability to uart's endpoint: `Stats` only.
pub const STATS_BADGE: u64 = 2;
/// A CNode's guard word for a 16-slot CNode named with 64 bits: guard 0
/// of size 60 (`docs/abi.md`, "Capability data").
const SERVER_GUARD: u64 = uart::slot::GUARD_BITS;
/// RFLAGS of a new thread: bit 1 and IF.
const RFLAGS: u64 = 0x202;

/// What the root task keeps once the servers run.
#[derive(Clone, Copy, Debug)]
pub struct Servers {
    /// Endpoint C's original, and the root task's client capability, with
    /// badge 1.
    pub console_ep: CPtr,
    pub client: CPtr,
    /// Endpoint U with badge 2, for `Stats`.
    pub uart_stats: CPtr,
    /// The original COM1 IOPort and IRQ 4 handler.
    pub com1: CPtr,
    pub irq: CPtr,
    pub irq_info: IsaIrq,
    pub uart_tcb: CPtr,
    pub console_tcb: CPtr,
    pub watch_tcb: CPtr,
    /// Root slots each server's VSpace and CNode took.
    pub slots_each: u64,
    /// Endpoint F's original, which `watch` receives on.
    pub fault_ep: CPtr,
    /// Notification NT's original, term's, which console's slot 5 signals
    /// with `KEYS`.
    pub nt: CPtr,
}

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

fn retype(ipc: Ipc, objects: &mut ObjectAlloc, ty: ObjectType, bits: u64, n: u64) -> CPtr {
    objects
        .retype(ipc, ty, bits, n)
        .unwrap_or_else(|e| fail!("servers: retyping {n} {ty:?}: {e}"))
}

fn slots(objects: &mut ObjectAlloc, n: u64) -> CPtr {
    objects
        .slots
        .alloc(n)
        .unwrap_or_else(|| fail!("servers: no free slots"))
}

/// The root task's image, as `user/link.ld` and BootInfo describe it.
pub fn image(bi: &BootInfo) -> Image {
    let seg = libsys::image::segments();
    let mut thread_stacks = [(0, 0); 6];
    for (s, stack) in thread_stacks.iter_mut().zip(STACKS) {
        let top = stack.top();
        *s = (top - spawn::STACK_BYTES as u64, top);
    }
    Image {
        start: bi.user_image_start,
        end: bi.user_image_end,
        rodata_start: seg.rodata_start,
        data_start: seg.data_start,
        data_end: seg.data_end,
        libsys_stack_start: seg.libsys_stack_start,
        thread_stacks,
    }
}

/// Issues the COM1 range into a fresh slot.
fn issue(ipc: Ipc, objects: &mut ObjectAlloc, first: u16, last: u16) -> CPtr {
    let port = slots(objects, 1);
    ioport_control_issue(ipc, CAP_IO_PORT_CONTROL, first, last, root_slot(port))
        .unwrap_or_else(|e| fail!("servers: IOPortControl_Issue {first:#x}-{last:#x}: {e}"));
    port
}

/// An IOPort capability for `isa-debug-exit`'s `0xF4` to `0xF7`, under
/// QEMU only.
pub fn exit_port(ipc: Ipc, objects: &mut ObjectAlloc, bi: &BootInfo) -> Option<CPtr> {
    use libsys::bootinfo::{HYPERVISOR_QEMU_KVM, HYPERVISOR_QEMU_TCG};
    matches!(
        bi.hypervisor_vendor,
        HYPERVISOR_QEMU_TCG | HYPERVISOR_QEMU_KVM
    )
    .then(|| issue(ipc, objects, EXIT_PORT_NUMBER, EXIT_PORT_NUMBER + 3))
}

/// Starts `watch`, then `uart` and `console`, with the capabilities
/// `docs/design.md`'s tables give them. `exit_port` is what `watch` ends a
/// failed run through; `None` for `DebugHalt`.
pub fn start(
    bi: &BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc,
    exit_port: Option<CPtr>,
) -> Servers {
    let plan = Plan::new(image(bi), bi.user_image_frames)
        .unwrap_or_else(|e| fail!("servers: the root task's image: {e}"));
    let scratch = plan
        .scratch()
        .unwrap_or_else(|| fail!("servers: no free page under the root task's page tables"));
    let com1 = issue(ipc, objects, COM1_FIRST, COM1_LAST);
    let eps = retype(ipc, objects, ObjectType::Endpoint, 0, 3);
    let (uart_ep, console_ep, fault_ep) = (eps, eps + 1, eps + 2);
    // NT, term's, from M8: console's slot 5 signals it whether or not
    // term runs; a signal with no thread bound waits in it.
    let ntfns = retype(ipc, objects, ObjectType::Notification, 0, 3);
    let (nu, nc, nt) = (ntfns, ntfns + 1, ntfns + 2);
    let tcbs = retype(ipc, objects, ObjectType::Tcb, 0, 3);
    let (watch_tcb, uart_tcb, console_tcb) = (tcbs, tcbs + 1, tcbs + 2);
    let cnodes = retype(ipc, objects, ObjectType::CNode, uart::slot::RADIX, 2);
    let (uart_cnode, console_cnode) = (cnodes, cnodes + 1);
    // Root's own badged copies: the IRQ's signal, its client capability,
    // its Stats capability and the servers' fault endpoints.
    let mine = slots(objects, 6);
    let (nu_irq, client, uart_stats, f_uart, f_console, nc_rx) =
        (mine, mine + 1, mine + 2, mine + 3, mine + 4, mine + 5);
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    for (what, dest, src, rights, badge) in [
        ("NU badged IRQ", nu_irq, nu, Rights::WRITE, IRQ),
        ("root's client capability", client, console_ep, w_gr, 1),
        (
            "root's Stats capability",
            uart_stats,
            uart_ep,
            w_gr,
            STATS_BADGE,
        ),
        ("F for uart", f_uart, fault_ep, w_gr, fault_badge::UART),
        (
            "F for console",
            f_console,
            fault_ep,
            w_gr,
            fault_badge::CONSOLE,
        ),
        ("NC badged RX_READY", nc_rx, nc, Rights::WRITE, RX_READY),
    ] {
        cnode_mint(ipc, root_slot(dest), root_slot(src), rights, badge)
            .unwrap_or_else(|e| fail!("servers: minting {what}: {e}"));
    }

    // watch first, so a server's fault always finds it.
    let t = Thread {
        tcb: watch_tcb,
        fault_ep: 0,
        stack: STACKS[0],
        entry: watch,
        args: [fault_ep, com1, exit_port.unwrap_or(0), 0],
    };
    spawn::prepare(ipc, &t)
        .and_then(|()| {
            tcb_set_sched_params(ipc, watch_tcb, CAP_INIT_TCB, WATCH_PRIORITY, WATCH_PRIORITY)
        })
        .and_then(|()| tcb_resume(watch_tcb))
        .unwrap_or_else(|e| fail!("servers: starting watch: {e}"));

    // IRQ 4, bound to NU before uart gets it.
    let irq = slots(objects, 1);
    let irq_info = irq_control_get_isa(ipc, CAP_IRQ_CONTROL, 4, root_slot(irq))
        .unwrap_or_else(|e| fail!("servers: IRQControl_GetISA(4): {e}"));
    if irq_info.level || irq_info.active_low {
        fail!(
            "servers: IRQ 4 is GSI {}, level {}, active low {}; uart's loop is right only for an edge-triggered, active-high pin",
            irq_info.gsi,
            irq_info.level,
            irq_info.active_low
        );
    }
    irq_handler_set_notification(ipc, irq, nu_irq)
        .unwrap_or_else(|e| fail!("servers: IRQHandler_SetNotification: {e}"));

    let before = objects.slots.remaining();
    // uart: its CNode, VSpace and thread.
    let s = |n| Slot::new(uart_cnode, n, uart::slot::RADIX);
    fill(
        ipc,
        uart_cnode,
        "uart",
        &[
            (
                "U with Read",
                s(uart::slot::ENDPOINT),
                uart_ep,
                Rights::READ,
                None,
            ),
            (
                "the COM1 IOPort",
                s(uart::slot::IOPORT),
                com1,
                Rights::ALL,
                None,
            ),
            (
                "the IRQ 4 handler",
                s(uart::slot::IRQ),
                irq,
                Rights::ALL,
                None,
            ),
            (
                "NC badged RX_READY",
                s(uart::slot::CONSOLE_NTFN),
                nc_rx,
                Rights::WRITE,
                None,
            ),
            ("F badged UART", s(uart::slot::FAULT), f_uart, w_gr, None),
        ],
    );
    let uart_space = vspace(ipc, objects, &plan, scratch);
    let slots_each = before - objects.slots.remaining() + 2;
    spawn_server(
        ipc,
        &plan,
        Server {
            tcb: uart_tcb,
            cnode: uart_cnode,
            space: uart_space,
            fault_ep: uart::slot::FAULT,
            ntfn: Some(nu),
            priority: UART_PRIORITY,
            entry: uart_main,
            args: [0; 3],
        },
    );

    // console.
    let s = |n| Slot::new(console_cnode, n, console::slot::RADIX);
    fill(
        ipc,
        console_cnode,
        "console",
        &[
            (
                "C with Read",
                s(console::slot::ENDPOINT),
                console_ep,
                Rights::READ,
                None,
            ),
            (
                "U badged 1",
                s(console::slot::UART),
                uart_ep,
                w_gr,
                Some(uart::CONSOLE_BADGE),
            ),
            (
                "F badged CONSOLE",
                s(console::slot::FAULT),
                f_console,
                w_gr,
                None,
            ),
            (
                "NT badged KEYS",
                s(console::slot::KEYS),
                nt,
                Rights::WRITE,
                Some(KEYS),
            ),
        ],
    );
    let console_space = vspace(ipc, objects, &plan, scratch);
    spawn_server(
        ipc,
        &plan,
        Server {
            tcb: console_tcb,
            cnode: console_cnode,
            space: console_space,
            fault_ep: console::slot::FAULT,
            ntfn: Some(nc),
            priority: CONSOLE_PRIORITY,
            entry: console_main,
            args: [0; 3],
        },
    );

    Servers {
        console_ep,
        client,
        uart_stats,
        com1,
        irq,
        irq_info,
        uart_tcb,
        console_tcb,
        watch_tcb,
        slots_each,
        fault_ep,
        nt,
    }
}

/// The framebuffer's frames and the page tables of its window, each kind
/// in consecutive root slots in the order `fb::Plan` gives them: frame
/// `i` of `Plan::frames` is `first_frame + i`, the table for the `j`th
/// address of `Plan::page_tables` is `first_table + j`. The root task
/// keeps them all; term holds none.
#[derive(Clone, Copy, Debug)]
pub struct FbObjects {
    pub first_frame: CPtr,
    pub frames: u64,
    pub first_table: CPtr,
    pub tables: u64,
}

/// Retypes `plan`'s frames from the framebuffer's device untyped,
/// `framebuffer_untyped`'s descriptor `r.untyped` for each retype `r`,
/// and the window's page tables from RAM.
pub fn framebuffer_objects(
    bi: &BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc,
    plan: &fb::Plan<'_>,
) -> FbObjects {
    let mut first_frame = None;
    let mut frames = 0;
    for r in plan.retypes() {
        let ty = if r.huge() {
            ObjectType::Frame2M
        } else {
            ObjectType::Frame4K
        };
        let untyped = bi.framebuffer_untyped.start + r.untyped as u64;
        let first = objects
            .retype_from(ipc, untyped, ty, 0, r.count as u64)
            .unwrap_or_else(|e| {
                fail!(
                    "servers: retyping {} {ty:?} at {:#x} from framebuffer untyped {untyped}: {e}",
                    r.count,
                    r.paddr
                )
            });
        let at = *first_frame.get_or_insert(first);
        if first != at + frames {
            fail!("servers: the framebuffer's frames are not in consecutive slots");
        }
        frames += r.count as u64;
    }
    let tables = plan.page_tables().count() as u64;
    let first_table = if tables == 0 {
        0
    } else {
        retype(ipc, objects, ObjectType::PageTable, 0, tables)
    };
    FbObjects {
        first_frame: first_frame.unwrap_or(0),
        frames,
        first_table,
        tables,
    }
}

impl FbObjects {
    /// Maps the window's page tables in `vspace`, whose page directory
    /// for the first GiB exists (the root image's).
    pub fn map_tables(&self, ipc: Ipc, plan: &fb::Plan<'_>, vspace: CPtr) {
        for (j, base) in plan.page_tables().enumerate() {
            vspace::map_table(
                ipc,
                self.first_table + j as u64,
                Table::PageTable,
                base,
                vspace,
            )
            .unwrap_or_else(|e| {
                fail!("servers: mapping the framebuffer's page table at {base:#x}: {e}")
            });
        }
    }

    /// Unmaps the window's page tables, leaving them unmapped and empty,
    /// so they can be mapped in another VSpace.
    pub fn unmap_tables(&self) {
        for j in 0..self.tables {
            vspace::unmap_table(self.first_table + j, Table::PageTable)
                .unwrap_or_else(|e| fail!("servers: unmapping a framebuffer page table: {e}"));
        }
    }

    /// Maps every frame at its window address in `vspace`, read-write,
    /// no-execute, with the attributes word `cache` (`UNCACHED` or
    /// `WRITE_COMBINING`).
    pub fn map_frames(&self, ipc: Ipc, plan: &fb::Plan<'_>, vspace: CPtr, cache: u64) {
        for (i, f) in plan.frames().enumerate() {
            vspace::frame_map(
                ipc,
                self.first_frame + i as u64,
                f.vaddr,
                READ_WRITE,
                cache,
                vspace,
            )
            .unwrap_or_else(|e| {
                fail!(
                    "servers: mapping the framebuffer's frame at {:#x} at {:#x}: {e}",
                    f.paddr,
                    f.vaddr
                )
            });
        }
    }

    /// Unmaps every frame.
    pub fn unmap_frames(&self) {
        for i in 0..self.frames {
            vspace::frame_unmap(self.first_frame + i)
                .unwrap_or_else(|e| fail!("servers: unmapping a framebuffer frame: {e}"));
        }
    }
}

/// What the root task keeps of term and tui.
#[derive(Clone, Copy, Debug)]
pub struct Terminal {
    /// Endpoint T with badge 2, for term's `Stats`.
    pub stats: CPtr,
}

/// Starts `term` and `tui` (`docs/design.md`, "Where it runs" and
/// "Capabilities" under "Framebuffer, terminal and TUI"): term in a CSpace
/// of its own with T, console's raw client capability and F, and a VSpace
/// with its state window and the framebuffer's frames mapped
/// write-combining, bound to NT before it starts, with the geometry's
/// three words in `rdi`, `rsi` and `rdx`; then tui, with T as term's
/// client, console as client 5 and D, its report and fault endpoint. The
/// framebuffer's frames and tables must be unmapped and empty.
pub fn start_terminal(
    bi: &BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc,
    s: &Servers,
    plan: &fb::Plan<'_>,
    fbo: &FbObjects,
    d: CPtr,
) -> Terminal {
    let image = Plan::new(image(bi), bi.user_image_frames)
        .unwrap_or_else(|e| fail!("servers: the root task's image: {e}"));
    let scratch = image
        .scratch()
        .unwrap_or_else(|| fail!("servers: no free page under the root task's page tables"));
    let t_ep = retype(ipc, objects, ObjectType::Endpoint, 0, 1);
    let tcbs = retype(ipc, objects, ObjectType::Tcb, 0, 2);
    let (term_tcb, tui_tcb) = (tcbs, tcbs + 1);
    let cnodes = retype(ipc, objects, ObjectType::CNode, term::slot::RADIX, 2);
    let (term_cnode, tui_cnode) = (cnodes, cnodes + 1);
    let stats = slots(objects, 1);
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    cnode_mint(
        ipc,
        root_slot(stats),
        root_slot(t_ep),
        w_gr,
        TERM_STATS_BADGE,
    )
    .unwrap_or_else(|e| fail!("servers: minting root's Stats capability to T: {e}"));

    // term.
    let s_term = |n| Slot::new(term_cnode, n, term::slot::RADIX);
    fill(
        ipc,
        term_cnode,
        "term",
        &[
            (
                "T with Read",
                s_term(term::slot::ENDPOINT),
                t_ep,
                Rights::READ,
                None,
            ),
            (
                "C badged 4",
                s_term(term::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(libsys::proto::CONSOLE_RAW_CLIENT),
            ),
            (
                "F badged TERM",
                s_term(term::slot::FAULT),
                s.fault_ep,
                w_gr,
                Some(fault_badge::TERM),
            ),
        ],
    );
    let space = vspace(ipc, objects, &image, scratch);
    // The state window: fresh frames, zeroed by the retype, under a page
    // table of their own.
    let table = retype(ipc, objects, ObjectType::PageTable, 0, 1);
    vspace::map_table(
        ipc,
        table,
        Table::PageTable,
        term::layout::STATE,
        space.pml4,
    )
    .unwrap_or_else(|e| fail!("servers: mapping term's state window's page table: {e}"));
    let state = retype(
        ipc,
        objects,
        ObjectType::Frame4K,
        0,
        term::layout::STATE_PAGES,
    );
    for i in 0..term::layout::STATE_PAGES {
        let addr = term::layout::STATE + i * PAGE;
        vspace::frame_map(ipc, state + i, addr, READ_WRITE, WRITE_BACK, space.pml4)
            .unwrap_or_else(|e| fail!("servers: mapping term's state at {addr:#x}: {e}"));
    }
    // The framebuffer, write-combining, in term's VSpace alone.
    fbo.map_tables(ipc, plan, space.pml4);
    fbo.map_frames(ipc, plan, space.pml4, WRITE_COMBINING);
    let [rdi, rsi, rdx] = plan.geometry().to_words();
    spawn_server(
        ipc,
        &image,
        Server {
            tcb: term_tcb,
            cnode: term_cnode,
            space,
            fault_ep: term::slot::FAULT,
            ntfn: Some(s.nt),
            priority: TERM_PRIORITY,
            entry: term_main,
            args: [rdi, rsi, rdx],
        },
    );

    // tui.
    let s_tui = |n| Slot::new(tui_cnode, n, tui::slot::RADIX);
    fill(
        ipc,
        tui_cnode,
        "tui",
        &[
            (
                "T badged 1",
                s_tui(tui::slot::TERM),
                t_ep,
                w_gr,
                Some(TERM_CLIENT),
            ),
            (
                "C badged 5",
                s_tui(tui::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(TUI_BADGE),
            ),
            (
                "D badged 5",
                s_tui(tui::slot::REPORT),
                d,
                w_gr,
                Some(TUI_BADGE),
            ),
        ],
    );
    let space = vspace(ipc, objects, &image, scratch);
    spawn_server(
        ipc,
        &image,
        Server {
            tcb: tui_tcb,
            cnode: tui_cnode,
            space,
            fault_ep: tui::slot::REPORT,
            ntfn: None,
            priority: TUI_PRIORITY,
            entry: tui_main,
            args: [0; 3],
        },
    );
    Terminal { stats }
}

type Fill<'a> = (&'a str, Slot, CPtr, Rights, Option<u64>);

/// A server's CNode: slot 1 the CNode itself with the guard that makes
/// `CNode_SaveCaller` take depth 64, then each entry, copied or minted
/// from the root task's slot.
fn fill(ipc: Ipc, cnode: CPtr, server: &str, entries: &[Fill<'_>]) {
    let own = Slot::new(cnode, uart::slot::CNODE, uart::slot::RADIX);
    cnode_mint(ipc, own, root_slot(cnode), Rights::ALL, SERVER_GUARD)
        .unwrap_or_else(|e| fail!("servers: {server}'s CNode in its slot 1: {e}"));
    for &(what, dest, src, rights, badge) in entries {
        let r = match badge {
            Some(b) => cnode_mint(ipc, dest, root_slot(src), rights, b),
            None => cnode_copy(ipc, dest, root_slot(src), rights),
        };
        r.unwrap_or_else(|e| fail!("servers: {server}'s {what}: {e}"));
    }
}

/// A server's VSpace and IPC buffer frame.
struct Space {
    pml4: CPtr,
    buffer: CPtr,
}

/// Builds a VSpace from the root task's image (`docs/design.md`, "Where
/// the servers run"): text and read-only pages map copies of the root
/// task's frame capabilities with Read only; `.data` and `.bss` get fresh
/// frames, each filled with the root task's page through `scratch` in the
/// root task's VSpace; the stack and the IPC buffer fresh zeroed frames;
/// the thread stacks and guards nothing.
fn vspace(ipc: Ipc, objects: &mut ObjectAlloc, plan: &Plan, scratch: u64) -> Space {
    let pml4 = retype(ipc, objects, ObjectType::Pml4, 0, 1);
    for (span, ty, level) in [
        (1u64 << 39, ObjectType::Pdpt, Table::Pdpt),
        (1 << 30, ObjectType::PageDirectory, Table::PageDirectory),
        (PT_SPAN, ObjectType::PageTable, Table::PageTable),
    ] {
        for base in plan.bases(span) {
            let t = retype(ipc, objects, ty, 0, 1);
            vspace::map_table(ipc, t, level, base, pml4)
                .unwrap_or_else(|e| fail!("servers: mapping a {ty:?} at {base:#x}: {e}"));
        }
    }
    let fresh = plan.pages().filter(|p| p.role.fresh()).count() as u64;
    let mut next_fresh = retype(ipc, objects, ObjectType::Frame4K, 0, fresh);
    let copies = plan
        .pages()
        .filter(|p| matches!(p.role, Role::Text | Role::ReadOnly))
        .count() as u64;
    let mut next_copy = slots(objects, copies);
    let mut buffer = 0;
    let map = |frame, addr, rights, attrs| {
        vspace::frame_map(ipc, frame, addr, rights, attrs, pml4)
            .unwrap_or_else(|e| fail!("servers: mapping a frame at {addr:#x}: {e}"));
    };
    for page in plan.pages() {
        match page.role {
            Role::Text | Role::ReadOnly => {
                let Some(frame) = page.frame else {
                    fail!("servers: image page {:#x} has no frame", page.addr)
                };
                let copy = next_copy;
                next_copy += 1;
                cnode_copy(ipc, root_slot(copy), root_slot(frame), Rights::READ)
                    .unwrap_or_else(|e| fail!("servers: copying image frame {frame}: {e}"));
                let attrs = if page.role == Role::Text {
                    WRITE_BACK | EXECUTE
                } else {
                    WRITE_BACK
                };
                map(copy, page.addr, READ, attrs);
            }
            Role::Data | Role::Stack | Role::IpcBuffer => {
                let frame = next_fresh;
                next_fresh += 1;
                if page.role == Role::Data {
                    fill_page(ipc, frame, page.addr, scratch);
                }
                if page.role == Role::IpcBuffer {
                    buffer = frame;
                }
                map(frame, page.addr, READ_WRITE, WRITE_BACK);
            }
            Role::ThreadStack | Role::Guard => {}
        }
    }
    Space { pml4, buffer }
}

/// Copies the root task's page at `addr` into `frame`, through a mapping
/// at `scratch` that is gone again before the frame is mapped in the
/// server: a frame capability maps once.
fn fill_page(ipc: Ipc, frame: CPtr, addr: u64, scratch: u64) {
    vspace::frame_map(ipc, frame, scratch, READ_WRITE, WRITE_BACK, CAP_INIT_VSPACE)
        .unwrap_or_else(|e| fail!("servers: mapping a data frame at {scratch:#x}: {e}"));
    // SAFETY: `addr` is a page of the root task's own `.data` and `.bss`,
    // mapped readable in this VSpace, and no thread writes it while the
    // servers are built: watch, the one other thread in this VSpace yet,
    // waits in its first Recv on F, which writes nothing but its
    // registers, and uart and console run in VSpaces of their own.
    // `scratch` is a page nothing else maps, where the fresh frame was
    // just mapped read-write. The pages do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(addr as *const u8, scratch as *mut u8, PAGE as usize);
    }
    vspace::frame_unmap(frame)
        .unwrap_or_else(|e| fail!("servers: unmapping a data frame at {scratch:#x}: {e}"));
}

/// A server to start.
struct Server {
    tcb: CPtr,
    /// Its CNode, which gets the guard.
    cnode: CPtr,
    space: Space,
    /// Its fault endpoint, a `CPtr` in its own CSpace.
    fault_ep: CPtr,
    /// The notification it is bound to, if any.
    ntfn: Option<CPtr>,
    priority: u64,
    entry: spawn::Entry,
    /// Its arguments, in `rdi`, `rsi` and `rdx`: term's geometry; 0 for
    /// the others.
    args: [u64; 3],
}

/// Configures and starts a server: its CSpace with the guard, its VSpace
/// and IPC buffer, its fault endpoint, priority and MCP, bound to its
/// notification if it has one, at its entry on its own stack at the top of
/// the `_start` stack's range, with its arguments.
fn spawn_server(ipc: Ipc, plan: &Plan, s: Server) {
    let Server {
        tcb,
        cnode,
        space,
        fault_ep,
        ntfn,
        priority,
        entry,
        args: [a0, a1, a2],
    } = s;
    let end = plan.image().end;
    let buffer = IpcBufferFrame {
        addr: end,
        frame: space.buffer,
    };
    let regs = Registers::ZERO
        .with(UserReg::Rip, entry as usize as u64)
        .with(UserReg::Rsp, end - 8)
        .with(UserReg::Rflags, RFLAGS)
        .with(UserReg::Rdi, a0)
        .with(UserReg::Rsi, a1)
        .with(UserReg::Rdx, a2);
    tcb_configure(
        ipc,
        tcb,
        fault_ep,
        cnode,
        SERVER_GUARD,
        space.pml4,
        Some(buffer),
    )
    .and_then(|()| tcb_set_sched_params(ipc, tcb, CAP_INIT_TCB, priority, priority))
    .and_then(|()| ntfn.map_or(Ok(()), |n| tcb_bind_notification(ipc, tcb, n)))
    // Words 0 to 8: rip to rdi, so rdx and rsi too.
    .and_then(|()| tcb_write_registers(ipc, tcb, false, &regs, UserReg::Rdi.index() + 1))
    .and_then(|()| tcb_resume(tcb))
    .unwrap_or_else(|e| fail!("servers: starting the thread in TCB slot {tcb}: {e}"));
}

extern "C" fn uart_main(_: u64, _: u64, _: u64, _: u64) -> ! {
    uart::run()
}

extern "C" fn console_main(_: u64, _: u64, _: u64, _: u64) -> ! {
    console::run()
}

/// term's entry: checks the geometry root passed again, then makes its
/// pixel and state slices over the windows root mapped and runs it.
extern "C" fn term_main(size: u64, format: u64, offset: u64, _: u64) -> ! {
    // Before anything can panic: the statics are a copy of the root
    // task's, whose print! may name a console capability of its CSpace.
    libsys::output::reset();
    let Some(g) = fb::Geometry::from_words([size, format, offset]) else {
        panic!("term: a geometry fb refuses: {size:#x} {format:#x} {offset:#x}")
    };
    // SAFETY: `start_terminal` mapped `fb::Plan`'s frames, which cover the
    // visible bytes `[base, base + 4 x stride x height)`, read-write at
    // `fb::WINDOW` + (their address - `base` rounded down to 2 MiB), in
    // this VSpace and no other; `offset` is `base` mod 2 MiB, so the
    // `stride x height` pixels from `fb::WINDOW + offset` are the visible
    // bytes, 4-byte aligned since `base` is (`from_words` checked both).
    // Nothing else in this VSpace names them, and this is the only slice
    // made of them. Every bit pattern is a valid `u32`.
    let pixels = unsafe {
        core::slice::from_raw_parts_mut((fb::WINDOW + g.offset()) as *mut u32, g.pixels())
    };
    // SAFETY: `start_terminal` mapped `term::layout::STATE_PAGES` fresh
    // frames read-write at `term::layout::STATE` in this VSpace and no
    // other, page-aligned and covering `term::STATE_WORDS` words; this is
    // the only slice made of them. Every bit pattern is a valid `u64`.
    let state = unsafe {
        core::slice::from_raw_parts_mut(term::layout::STATE as *mut u64, term::STATE_WORDS)
    };
    term::run(g, pixels, state)
}

extern "C" fn tui_main(_: u64, _: u64, _: u64, _: u64) -> ! {
    tui::run()
}

/// `watch`: receives the servers' faults on F and ends the run with
/// failure at the first, after a `TEST FAIL` line through COM1 directly.
/// It never replies, so the server stays stopped. It has no IPC buffer,
/// so a fault arrives as MR0 to MR3. It never uses `print!`, which may
/// name a console in the root task's statics.
extern "C" fn watch(fault_ep: CPtr, com1: CPtr, exit_port: CPtr, _: u64) -> ! {
    let r = recv(fault_ep);
    let line = FaultLine {
        badge: r.badge,
        label: r.msg.info.label(),
        mr: r.msg.mr,
    };
    let _ = writeln!(Polled::com1(IoPort(com1)), "{line}");
    if exit_port != 0 {
        let _ = libsys::device::ioport_out32(exit_port, EXIT_PORT_NUMBER, EXIT_FAILURE);
    }
    libsys::debug_halt(1)
}
