//! Starting `watch`, `uart` and `console` (`docs/design.md`, "Where the
//! servers run", "Capabilities" and "Failures"), and from M8 `term` and
//! `tui` ("Framebuffer, terminal and TUI", "Where it runs"): each server
//! in a CSpace of its own, a 16-slot CNode filled from its crate's slot
//! table only, and a VSpace built from the root task's image frames by
//! `root::process::Plan`; `watch` in the root task's own spaces, receiving
//! the servers' faults on endpoint F. term's VSpace also maps its state
//! window and the framebuffer's frames, write-combining, from `fb::Plan`.
//! From M9, `start_network` starts the network servers ("Networking",
//! "Where the network servers run"): on QEMU `virtio-net` and `net`, the
//! driver's VSpace with its DMA frame, its device regions' pages,
//! uncached, and the frame queues' frame, `net`'s with a copy of it; on
//! Hyper-V `vmbus`, with the SynIC frames, `netvsc`, with its channel
//! frame, the frame queues' frame and with `netvsc.mnf=1` the monitor
//! window, and `net`. Nothing here prints but `start_network`'s `pci:`
//! and `servers: Hyper-V:` lines, so a test on a kernel without `debug`
//! can start the other servers before it has a console.

use core::fmt::Write;

use ::pci::{Config as _, Segment};
use libsys::bootinfo::{
    CAP_HYPERVISOR, CAP_INIT_TCB, CAP_INIT_VSPACE, CAP_IO_PORT_CONTROL, CAP_IRQ_CONTROL,
};
use libsys::device::{
    IsaIrq, ioport_control_issue, irq_control_get_isa, irq_control_get_sint,
    irq_handler_set_notification,
};
use libsys::frames;
use libsys::invoke::{
    cnode_copy, cnode_mint, tcb_bind_notification, tcb_configure, tcb_resume, tcb_set_sched_params,
    tcb_write_registers,
};
use libsys::mem::{Mmio, Shared};
use libsys::objects::Carver;
use libsys::output::{EXIT_FAILURE, EXIT_PORT_NUMBER, IoPort, Polled};
use libsys::proto::{CHANNEL, FRAMES, IRQ, KEYS, RX_READY, SINT, TERM_CLIENT, VMBUS_CLIENT};
use libsys::vspace::{
    self, EXECUTE, HUGE_PAGE, READ, READ_WRITE, Table, UNCACHED, WRITE_BACK, WRITE_COMBINING,
};
use libsys::{
    BootInfo, CPtr, Ipc, IpcBufferFrame, ObjectAlloc, ObjectType, Registers, Rights, Slot, UserReg,
    println, recv,
};
use root::network::{
    DRIVER_CLIENT, DRIVER_PRIORITY, HyperVLine, MNF_FRAMES, MONITOR_FRAMES, NET_CLIENT,
    NET_PRIORITY, NETVSC_CLIENT, NETVSC_WINDOWS, Platform, QUEUES, STATS_BADGE as NET_STATS_BADGE,
    SYNIC_FRAMES, VIRTIO_NET_WINDOWS, VMBUS_PRIORITY, VMBUS_SINT, VMBUS_WINDOWS, Window,
    check_windows, net_words, netvsc_start, virtio_net_start, vmbus_start,
};
use root::process::{FaultLine, Image, PAGE, PT_SPAN, Plan, Role, UartBurst, fault_badge};
use virtio_net::{Regions, Which};

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
pub use root::check::tui::TUI_BADGE;

// Every server's CNode has the same shape, which `fill` relies on.
const _: () = assert!(
    uart::slot::RADIX == console::slot::RADIX
        && uart::slot::RADIX == term::slot::RADIX
        && uart::slot::RADIX == tui::slot::RADIX
        && uart::slot::CNODE == term::slot::CNODE
        && uart::slot::CNODE == tui::slot::CNODE
        && uart::slot::RADIX == virtio_net::slot::RADIX
        && uart::slot::RADIX == net::slot::RADIX
        && uart::slot::CNODE == virtio_net::slot::CNODE
        && uart::slot::CNODE == net::slot::CNODE
        && uart::slot::GUARD_BITS == virtio_net::slot::GUARD_BITS
        && uart::slot::GUARD_BITS == net::slot::GUARD_BITS
        && uart::slot::RADIX == vmbus::slot::RADIX
        && uart::slot::RADIX == netvsc::slot::RADIX
        && uart::slot::CNODE == vmbus::slot::CNODE
        && uart::slot::CNODE == netvsc::slot::CNODE
        && uart::slot::GUARD_BITS == vmbus::slot::GUARD_BITS
        && uart::slot::GUARD_BITS == netvsc::slot::GUARD_BITS
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
/// `docs/design.md`'s tables give them, and uart with the cap on its
/// burst that the command line's `uart.burst=<n>` asks for (M9).
/// `exit_port` is what `watch` ends a failed run through; `None` for
/// `DebugHalt`.
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
            // From M9: the command line's cap on its burst, 0 for none.
            args: [UartBurst::parse(bi.cmdline()).cap().to_word(), 0, 0, 0],
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
            args: [0; 4],
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
    /// Their TCBs, which `test=term_fault` and `test=tui_fault` make
    /// fault, and whose MCPs `test=tui` reads back.
    pub term_tcb: CPtr,
    pub tui_tcb: CPtr,
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
            args: [rdi, rsi, rdx, 0],
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
            args: [0; 4],
        },
    );
    Terminal {
        stats,
        term_tcb,
        tui_tcb,
    }
}

/// What runs beside the network driver: `net`, with its configuration,
/// or, for `test=virtio_net`, root's probe thread, for which root maps
/// the frame queues' copy in its own VSpace instead of `net`'s.
#[derive(Clone, Copy, Debug)]
pub enum Peer {
    Net(net::Config),
    Probe,
}

/// What the root task keeps of the network servers (`docs/design.md`,
/// "Capabilities" under "Networking", "`root` keeps"): every capability
/// stays in its CNode; these are the ones its tests use.
#[derive(Clone, Copy, Debug)]
pub struct Network {
    /// The driver's TCB, which `test=virtio_net_fault` makes fault:
    /// virtio-net's, or on Hyper-V netvsc's.
    pub driver_tcb: CPtr,
    /// Endpoint VN with badge 2, for virtio-net's `Stats`; on Hyper-V
    /// endpoint NS with badge 2, for netvsc's.
    pub driver_stats: CPtr,
    /// On Hyper-V, endpoint VB with badge 2, for vmbus's `Stats`; 0 on
    /// QEMU.
    pub bus_stats: CPtr,
    /// The MSI's IRQ; root keeps its handler, bound to NV with `IRQ`. On
    /// Hyper-V SINT 2's, whose handler root keeps bound to NB with
    /// `SINT`.
    pub irq: u8,
    /// net's TCB and endpoint NE with badge 2, for its `Stats`; 0 with
    /// the probe.
    pub net_tcb: CPtr,
    pub net_stats: CPtr,
    /// For the probe: notification NN's original, which the driver
    /// signals with `FRAMES`, and a copy of NV with Write and `FRAMES`, to
    /// signal the driver; 0 with `net`.
    pub nn: CPtr,
    pub nv_frames: CPtr,
}

/// The platform whose network servers root starts
/// (`root::network::Platform::choose`): Hyper-V with a Hypervisor
/// capability in slot 12, else QEMU with an ECAM range; neither fails the
/// test. Decide it before `net::Config::parse`, whose defaults are the
/// platform's (`root::network::default_config`).
pub fn platform(bi: &BootInfo) -> Platform {
    // An invocation on slot 12 tells a Hypervisor capability from the
    // null capability QEMU's root task has there: VpIndex changes nothing.
    let hypervisor = libsys::hyperv::vp_index(CAP_HYPERVISOR).is_ok();
    Platform::choose(hypervisor, bi.interrupts.ecam_count.into()).unwrap_or_else(|e| fail!("{e}"))
}

/// Starts the network servers on `platform` (`docs/design.md`, "Where
/// the network servers run"): on QEMU `virtio-net` (140) over the
/// virtio-net function root sets up with the crate `pci`, and `net` (130)
/// or the probe beside it; on Hyper-V `vmbus` (145), `netvsc` (140) and
/// `net` (130). It prints `pci:` lines, or on Hyper-V one `servers:
/// Hyper-V:` line, so it needs console or a debug kernel.
pub fn start_network<'a>(
    bi: &'a BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc<'a>,
    s: &Servers,
    platform: Platform,
    peer: Peer,
) -> Network {
    match (platform, peer) {
        (Platform::Qemu, _) => start_qemu(bi, ipc, objects, s, peer),
        (Platform::HyperV, Peer::Net(config)) => start_hyperv(bi, ipc, objects, s, config),
        (Platform::HyperV, Peer::Probe) => {
            fail!("servers: test=virtio_net's probe runs beside virtio-net, on QEMU only")
        }
    }
}

/// QEMU's half of [`start_network`] (`docs/design.md`, "PCI on QEMU"):
/// finds and checks the virtio-net function, binds its MSI to NV and
/// programs MSI-X entry 0, builds the driver's VSpace (the DMA frame, the
/// frame queues' original and its regions' pages, uncached), turns bus
/// mastering on, unmaps configuration space, and starts `net` or maps the
/// probe's copy, then the driver.
fn start_qemu<'a>(
    bi: &'a BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc<'a>,
    s: &Servers,
    peer: Peer,
) -> Network {
    let image = Plan::new(image(bi), bi.user_image_frames)
        .unwrap_or_else(|e| fail!("servers: the root task's image: {e}"));
    let scratch = image
        .scratch()
        .unwrap_or_else(|| fail!("servers: no free page under the root task's page tables"));
    // Every window against the image's end, in each VSpace that maps one:
    // the driver's, net's, and with the probe root's, beside its ECAM and
    // MSI-X windows.
    let end = bi.user_image_end;
    let roots = [
        QUEUES,
        Window {
            name: "ECAM",
            start: crate::pci::WINDOW,
            bytes: crate::pci::ECAM_FRAMES as u64 * HUGE_PAGE,
            huge: true,
        },
        Window {
            name: "the MSI-X table",
            start: crate::pci::MSIX_WINDOW,
            bytes: PAGE,
            huge: false,
        },
    ];
    let windows: &[Window] = match peer {
        Peer::Net(_) => &[QUEUES],
        Peer::Probe => &roots,
    };
    check_windows(end, &VIRTIO_NET_WINDOWS)
        .and_then(|()| check_windows(end, windows))
        .unwrap_or_else(|e| fail!("servers: {e}"));

    let range = crate::pci::ecam_range(bi);
    let mut carver = Carver::new(bi, &objects.untyped);
    // A page table for root's MSI-X window.
    let msix_table = retype(ipc, objects, ObjectType::PageTable, 0, 1);
    vspace::map_table(
        ipc,
        msix_table,
        Table::PageTable,
        crate::pci::MSIX_WINDOW,
        CAP_INIT_VSPACE,
    )
    .unwrap_or_else(|e| fail!("servers: mapping root's MSI-X window's page table: {e}"));

    let mut ecam = crate::pci::Ecam::new(ipc, objects, &mut carver, &range);
    let f = crate::pci::find_virtio_net(&mut ecam);
    let plan = crate::pci::plan(&ecam, &f);
    let pages = crate::pci::carve_pages(&mut ecam, &plan);
    let (handler, msi) = crate::pci::get_msi(ipc, ecam.objects);

    // The driver's objects: VN, NV, NN, its TCB and CNode, the DMA frame,
    // the frame queues' frame and its copy, and its regions' page table.
    let o = &mut *ecam.objects;
    let vn = retype(ipc, o, ObjectType::Endpoint, 0, 1);
    let ntfns = retype(ipc, o, ObjectType::Notification, 0, 2);
    let (nv, nn) = (ntfns, ntfns + 1);
    let driver_tcb = retype(ipc, o, ObjectType::Tcb, 0, 1);
    let driver_cnode = retype(ipc, o, ObjectType::CNode, virtio_net::slot::RADIX, 1);
    let dma = retype(ipc, o, ObjectType::Frame2M, 0, 1);
    let queues = retype(ipc, o, ObjectType::Frame2M, 0, 1);
    let regions_table = retype(ipc, o, ObjectType::PageTable, 0, 1);
    let mine = slots(o, 5);
    let (copy, nv_irq, nv_frames, driver_stats, f_driver) =
        (mine, mine + 1, mine + 2, mine + 3, mine + 4);
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    cnode_copy(ipc, root_slot(copy), root_slot(queues), Rights::ALL)
        .unwrap_or_else(|e| fail!("servers: copying the frame queues' frame: {e}"));
    for (what, dest, src, rights, badge) in [
        ("NV badged IRQ", nv_irq, nv, Rights::WRITE, IRQ),
        ("NV badged FRAMES", nv_frames, nv, Rights::WRITE, FRAMES),
        (
            "root's Stats capability to VN",
            driver_stats,
            vn,
            w_gr,
            NET_STATS_BADGE,
        ),
        (
            "F for virtio-net",
            f_driver,
            s.fault_ep,
            w_gr,
            fault_badge::VIRTIO_NET,
        ),
    ] {
        cnode_mint(ipc, root_slot(dest), root_slot(src), rights, badge)
            .unwrap_or_else(|e| fail!("servers: minting {what}: {e}"));
    }

    // The MSI, bound to NV before the driver gets anything; root keeps
    // the handler. Then MSI-X entry 0, with memory decode on and bus
    // mastering still off: the table answers, the device sends nothing.
    irq_handler_set_notification(ipc, handler, nv_irq)
        .unwrap_or_else(|e| fail!("servers: binding the MSI handler to NV: {e}"));
    {
        let cfg = ecam.function(f.address);
        ::pci::enable_memory(&cfg, false);
        crate::pci::program_msix(ipc, &cfg, &plan, &pages, &msi);
    }

    // virtio-net's CNode and VSpace: the image, the DMA frame, the frame
    // queues' original and its regions' pages, uncached.
    let sv = |n| Slot::new(driver_cnode, n, virtio_net::slot::RADIX);
    fill(
        ipc,
        driver_cnode,
        "virtio-net",
        &[
            (
                "VN with Read",
                sv(virtio_net::slot::ENDPOINT),
                vn,
                Rights::READ,
                None,
            ),
            (
                "NN badged FRAMES",
                sv(virtio_net::slot::NET),
                nn,
                Rights::WRITE,
                Some(FRAMES),
            ),
            (
                "F badged VIRTIO_NET",
                sv(virtio_net::slot::FAULT),
                f_driver,
                w_gr,
                None,
            ),
            (
                "C badged 6",
                sv(virtio_net::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(DRIVER_CLIENT),
            ),
        ],
    );
    let space = vspace(ipc, ecam.objects, &image, scratch);
    let map = |frame, addr, attrs, what: &str| {
        vspace::frame_map(ipc, frame, addr, READ_WRITE, attrs, space.pml4)
            .unwrap_or_else(|e| fail!("servers: mapping virtio-net's {what} at {addr:#x}: {e}"));
    };
    map(dma, virtio_net::layout::DMA, WRITE_BACK, "DMA frame");
    map(queues, frames::WINDOW, WRITE_BACK, "frame queues");
    vspace::map_table(
        ipc,
        regions_table,
        Table::PageTable,
        virtio_net::layout::REGIONS,
        space.pml4,
    )
    .unwrap_or_else(|e| fail!("servers: mapping virtio-net's regions' page table: {e}"));
    for (p, &frame) in plan.pages().zip(&pages.regions[..pages.count]) {
        map(
            frame,
            virtio_net::layout::REGIONS + p.offset,
            UNCACHED,
            p.kind.name(),
        );
    }
    let dma_base = vspace::frame_get_address(dma)
        .unwrap_or_else(|e| fail!("servers: Frame_GetAddress of the DMA frame: {e}"));
    let start = virtio_net_start(&plan, dma_base)
        .unwrap_or_else(|e| fail!("servers: virtio-net's arguments: {e}"));

    // Bus mastering, now that every frame the device may reach is mapped
    // in the driver's VSpace; then configuration space goes away.
    {
        let cfg = ecam.function(f.address);
        ::pci::enable_memory(&cfg, true);
        let command = cfg.read16(::pci::reg::COMMAND);
        let want = ::pci::command::MEMORY | ::pci::command::BUS_MASTER;
        if command & (want | ::pci::command::IO) != want {
            fail!("pci: virtio-net: the command register reads back {command:#x}");
        }
    }
    ecam.unmap();
    println!(
        "pci: virtio-net: MSI-X entry 0 sends IRQ {} (address {:#x}, data {:#x}); bus mastering on; configuration space and the MSI-X table unmapped",
        msi.irq, msi.address, msi.data
    );

    let mut network = Network {
        driver_tcb,
        driver_stats,
        bus_stats: 0,
        irq: msi.irq,
        net_tcb: 0,
        net_stats: 0,
        nn: 0,
        nv_frames: 0,
    };
    match peer {
        Peer::Net(config) => {
            // net first: it waits for the driver's first signal.
            let net = Net {
                config,
                queues: copy,
                driver: (nv, "NV badged FRAMES"),
                nn,
            };
            (network.net_tcb, network.net_stats) = start_net(ipc, objects, s, &image, scratch, net);
        }
        Peer::Probe => {
            vspace::frame_map(
                ipc,
                copy,
                frames::WINDOW,
                READ_WRITE,
                WRITE_BACK,
                CAP_INIT_VSPACE,
            )
            .unwrap_or_else(|e| fail!("servers: mapping the frame queues in root's VSpace: {e}"));
            network.nn = nn;
            network.nv_frames = nv_frames;
        }
    }

    spawn_server(
        ipc,
        &image,
        Server {
            tcb: driver_tcb,
            cnode: driver_cnode,
            space,
            fault_ep: virtio_net::slot::FAULT,
            ntfn: Some(nv),
            priority: DRIVER_PRIORITY,
            entry: virtio_net_main,
            args: start.to_words(),
        },
    );
    network
}

/// What `net` runs over: its configuration, the frame queues' copy, its
/// driver's notification (NV or NH) with its name for a failure's line,
/// and its own notification NN, made with the driver's objects.
struct Net {
    config: net::Config,
    queues: CPtr,
    driver: (CPtr, &'static str),
    nn: CPtr,
}

/// Starts `net` (130) beside either driver (`docs/design.md`, "Where the
/// network servers run"): NE, its TCB and CNode, root's `Stats`
/// capability to NE and F badged `NET`; its CNode from `net::slot`, its
/// VSpace with one window, the frame queues' copy; bound to NN before it
/// starts, with its configuration's words. Returns its TCB and root's
/// `Stats` capability.
fn start_net(
    ipc: Ipc,
    objects: &mut ObjectAlloc,
    s: &Servers,
    image: &Plan,
    scratch: u64,
    n: Net,
) -> (CPtr, CPtr) {
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    let ne = retype(ipc, objects, ObjectType::Endpoint, 0, 1);
    let net_tcb = retype(ipc, objects, ObjectType::Tcb, 0, 1);
    let net_cnode = retype(ipc, objects, ObjectType::CNode, net::slot::RADIX, 1);
    let mine = slots(objects, 2);
    let (net_stats, f_net) = (mine, mine + 1);
    for (what, dest, src, badge) in [
        (
            "root's Stats capability to NE",
            net_stats,
            ne,
            NET_STATS_BADGE,
        ),
        ("F for net", f_net, s.fault_ep, fault_badge::NET),
    ] {
        cnode_mint(ipc, root_slot(dest), root_slot(src), w_gr, badge)
            .unwrap_or_else(|e| fail!("servers: minting {what}: {e}"));
    }
    let sn = |i| Slot::new(net_cnode, i, net::slot::RADIX);
    let (driver, driver_name) = n.driver;
    fill(
        ipc,
        net_cnode,
        "net",
        &[
            (
                "NE with Read",
                sn(net::slot::ENDPOINT),
                ne,
                Rights::READ,
                None,
            ),
            (
                driver_name,
                sn(net::slot::DRIVER),
                driver,
                Rights::WRITE,
                Some(FRAMES),
            ),
            ("F badged NET", sn(net::slot::FAULT), f_net, w_gr, None),
            (
                "C badged 8",
                sn(net::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(NET_CLIENT),
            ),
        ],
    );
    // Its one window: the frame queues' copy.
    let net_space = vspace(ipc, objects, image, scratch);
    vspace::frame_map(
        ipc,
        n.queues,
        frames::WINDOW,
        READ_WRITE,
        WRITE_BACK,
        net_space.pml4,
    )
    .unwrap_or_else(|e| fail!("servers: mapping net's frame queues: {e}"));
    spawn_server(
        ipc,
        image,
        Server {
            tcb: net_tcb,
            cnode: net_cnode,
            space: net_space,
            fault_ep: net::slot::FAULT,
            ntfn: Some(n.nn),
            priority: NET_PRIORITY,
            entry: net_main,
            args: net_words(&n.config),
        },
    );
    (net_tcb, net_stats)
}

/// Hyper-V's half of [`start_network`] (`docs/design.md`, "Where the
/// network servers run", "`vmbus`" and "`netvsc`"), with a Hypervisor
/// capability in slot 12: SINT 2's handler from `IRQControl_GetSint`,
/// bound to NB before anything starts, root keeping it; the channel frame
/// and the frame queues' frame, fresh 2 MiB frames, and the monitor pages
/// and the event-flags page, three fresh 4 KiB frames from one
/// `Untyped_Retype`, each located with `Frame_GetAddress` and checked
/// (`root::network::vmbus_start`, `netvsc_start`); `vmbus`'s VSpace with
/// the SynIC frames, its CNode with slot 12's copy; `netvsc`'s VSpace with
/// the channel frame, the frame queues' original and, with
/// `netvsc.mnf=1`, the monitor window; then `net`, `netvsc` and `vmbus`,
/// each bound to its notification before it starts. Every decision is in
/// `root::network`, host-tested: QEMU's TCG has no SynIC, so this runs
/// first on the owner's machine.
fn start_hyperv<'a>(
    bi: &'a BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc<'a>,
    s: &Servers,
    config: net::Config,
) -> Network {
    let mnf = root::network::mnf(bi.cmdline()).unwrap_or_else(|e| fail!("{e}"));
    let image = Plan::new(image(bi), bi.user_image_frames)
        .unwrap_or_else(|e| fail!("servers: the root task's image: {e}"));
    let scratch = image
        .scratch()
        .unwrap_or_else(|| fail!("servers: no free page under the root task's page tables"));
    // Every window against the image's end, in each VSpace that maps one.
    let end = bi.user_image_end;
    check_windows(end, &VMBUS_WINDOWS)
        .and_then(|()| check_windows(end, &NETVSC_WINDOWS))
        .and_then(|()| check_windows(end, &[QUEUES]))
        .unwrap_or_else(|e| fail!("servers: {e}"));

    // SINT 2: unmasked now, its handler kept in root's CSpace and bound to
    // NB below, before vmbus starts; vmbus looks at its slot and flags
    // once when it starts, for what came before the binding.
    let sint = slots(objects, 1);
    let irq = irq_control_get_sint(ipc, CAP_IRQ_CONTROL, VMBUS_SINT, root_slot(sint))
        .unwrap_or_else(|e| fail!("servers: IRQControl_GetSint({VMBUS_SINT}): {e}"));

    // The objects: VB, NS; NB, NH, NN; vmbus's and netvsc's TCBs and
    // CNodes; the channel frame, the frame queues' frame and the monitor
    // pages; the page tables of vmbus's SynIC window and netvsc's monitor
    // window.
    let eps = retype(ipc, objects, ObjectType::Endpoint, 0, 2);
    let (vb, ns) = (eps, eps + 1);
    let ntfns = retype(ipc, objects, ObjectType::Notification, 0, 3);
    let (nb, nh, nn) = (ntfns, ntfns + 1, ntfns + 2);
    let tcbs = retype(ipc, objects, ObjectType::Tcb, 0, 2);
    let (vmbus_tcb, netvsc_tcb) = (tcbs, tcbs + 1);
    let cnodes = retype(ipc, objects, ObjectType::CNode, vmbus::slot::RADIX, 2);
    let (vmbus_cnode, netvsc_cnode) = (cnodes, cnodes + 1);
    let channel = retype(ipc, objects, ObjectType::Frame2M, 0, 1);
    let queues = retype(ipc, objects, ObjectType::Frame2M, 0, 1);
    // One Untyped_Retype: consecutive pages, as vmbus's CONNECT names
    // them.
    let monitor = retype(ipc, objects, ObjectType::Frame4K, 0, MONITOR_FRAMES);
    let synic_table = retype(ipc, objects, ObjectType::PageTable, 0, 1);
    let mnf_table = mnf.then(|| retype(ipc, objects, ObjectType::PageTable, 0, 1));
    let mine = slots(objects, 4);
    let (copy, nb_sint, bus_stats, driver_stats) = (mine, mine + 1, mine + 2, mine + 3);
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    cnode_copy(ipc, root_slot(copy), root_slot(queues), Rights::ALL)
        .unwrap_or_else(|e| fail!("servers: copying the frame queues' frame: {e}"));
    for (what, dest, src, rights, badge) in [
        ("NB badged SINT", nb_sint, nb, Rights::WRITE, SINT),
        (
            "root's Stats capability to VB",
            bus_stats,
            vb,
            w_gr,
            NET_STATS_BADGE,
        ),
        (
            "root's Stats capability to NS",
            driver_stats,
            ns,
            w_gr,
            NET_STATS_BADGE,
        ),
    ] {
        cnode_mint(ipc, root_slot(dest), root_slot(src), rights, badge)
            .unwrap_or_else(|e| fail!("servers: minting {what}: {e}"));
    }

    // The physical pages vmbus names to the host, checked as vmbus's and
    // netvsc's entry stubs check them.
    let address = |frame, what: &str| {
        vspace::frame_get_address(frame)
            .unwrap_or_else(|e| fail!("servers: Frame_GetAddress of {what}: {e}"))
    };
    let channel_base = address(channel, "the channel frame");
    let pages: [u64; MONITOR_FRAMES as usize] =
        core::array::from_fn(|i| address(monitor + i as u64, "a monitor page"));
    let bus_start =
        vmbus_start(channel_base, pages, bi.tsc_hz).unwrap_or_else(|e| fail!("servers: {e}"));
    let nic_start = netvsc_start(channel_base, mnf).unwrap_or_else(|e| fail!("servers: {e}"));

    // SINT 2, bound to NB before vmbus gets anything.
    irq_handler_set_notification(ipc, sint, nb_sint)
        .unwrap_or_else(|e| fail!("servers: binding SINT 2's handler to NB: {e}"));

    // vmbus's CNode and VSpace: the image and the SynIC frames, root's
    // slots 13 and 14 themselves.
    let sb = |n| Slot::new(vmbus_cnode, n, vmbus::slot::RADIX);
    fill(
        ipc,
        vmbus_cnode,
        "vmbus",
        &[
            (
                "VB with Read and Grant",
                sb(vmbus::slot::ENDPOINT),
                vb,
                Rights(Rights::READ.0 | Rights::GRANT.0),
                None,
            ),
            (
                "the Hypervisor capability",
                sb(vmbus::slot::HYPERVISOR),
                CAP_HYPERVISOR,
                Rights::ALL,
                None,
            ),
            (
                "NH badged CHANNEL",
                sb(vmbus::slot::NETVSC_NTFN),
                nh,
                Rights::WRITE,
                Some(CHANNEL),
            ),
            (
                "F badged VMBUS",
                sb(vmbus::slot::FAULT),
                s.fault_ep,
                w_gr,
                Some(fault_badge::VMBUS),
            ),
            (
                "C badged 6",
                sb(vmbus::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(DRIVER_CLIENT),
            ),
        ],
    );
    let bus_space = vspace(ipc, objects, &image, scratch);
    vspace::map_table(
        ipc,
        synic_table,
        Table::PageTable,
        vmbus::layout::SYNIC,
        bus_space.pml4,
    )
    .unwrap_or_else(|e| fail!("servers: mapping vmbus's SynIC window's page table: {e}"));
    for (frame, addr) in SYNIC_FRAMES {
        vspace::frame_map(ipc, frame, addr, READ_WRITE, WRITE_BACK, bus_space.pml4)
            .unwrap_or_else(|e| fail!("servers: mapping SynIC frame {frame} at {addr:#x}: {e}"));
    }

    // netvsc's CNode and VSpace: the image, the channel frame, the frame
    // queues' original and, with netvsc.mnf=1, monitor page 2 and the
    // event-flags page.
    let sn = |n| Slot::new(netvsc_cnode, n, netvsc::slot::RADIX);
    fill(
        ipc,
        netvsc_cnode,
        "netvsc",
        &[
            (
                "NS with Read",
                sn(netvsc::slot::ENDPOINT),
                ns,
                Rights::READ,
                None,
            ),
            (
                "VB badged 1",
                sn(netvsc::slot::VMBUS),
                vb,
                w_gr,
                Some(VMBUS_CLIENT),
            ),
            (
                "NN badged FRAMES",
                sn(netvsc::slot::NET_NTFN),
                nn,
                Rights::WRITE,
                Some(FRAMES),
            ),
            (
                "F badged NETVSC",
                sn(netvsc::slot::FAULT),
                s.fault_ep,
                w_gr,
                Some(fault_badge::NETVSC),
            ),
            (
                "C badged 7",
                sn(netvsc::slot::CONSOLE),
                s.console_ep,
                w_gr,
                Some(NETVSC_CLIENT),
            ),
        ],
    );
    let nic_space = vspace(ipc, objects, &image, scratch);
    let map = |frame, addr, what: &str| {
        vspace::frame_map(ipc, frame, addr, READ_WRITE, WRITE_BACK, nic_space.pml4)
            .unwrap_or_else(|e| fail!("servers: mapping netvsc's {what} at {addr:#x}: {e}"));
    };
    map(channel, netvsc::layout::CHANNEL, "channel frame");
    map(queues, frames::WINDOW, "frame queues");
    if let Some(table) = mnf_table {
        vspace::map_table(
            ipc,
            table,
            Table::PageTable,
            netvsc::layout::MNF,
            nic_space.pml4,
        )
        .unwrap_or_else(|e| fail!("servers: mapping netvsc's monitor window's page table: {e}"));
        for (i, addr) in MNF_FRAMES {
            map(monitor + i, addr, "monitor window");
        }
    }

    println!(
        "{}",
        HyperVLine {
            irq,
            vmbus: bus_start,
            mnf
        }
    );

    // net first, then netvsc, which calls vmbus's Attach, then vmbus: all
    // below root, so none runs before root waits.
    let net = Net {
        config,
        queues: copy,
        driver: (nh, "NH badged FRAMES"),
        nn,
    };
    let (net_tcb, net_stats) = start_net(ipc, objects, s, &image, scratch, net);
    spawn_server(
        ipc,
        &image,
        Server {
            tcb: netvsc_tcb,
            cnode: netvsc_cnode,
            space: nic_space,
            fault_ep: netvsc::slot::FAULT,
            ntfn: Some(nh),
            priority: DRIVER_PRIORITY,
            entry: netvsc_main,
            args: nic_start.to_words(),
        },
    );
    spawn_server(
        ipc,
        &image,
        Server {
            tcb: vmbus_tcb,
            cnode: vmbus_cnode,
            space: bus_space,
            fault_ep: vmbus::slot::FAULT,
            ntfn: Some(nb),
            priority: VMBUS_PRIORITY,
            entry: vmbus_main,
            args: bus_start.to_words(),
        },
    );
    Network {
        driver_tcb: netvsc_tcb,
        driver_stats,
        bus_stats,
        irq,
        net_tcb,
        net_stats,
        nn: 0,
        nv_frames: 0,
    }
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
    // registers, and the servers, uart, console, from M8 term and tui and
    // from M9 the network servers, run in VSpaces of their own (M9's
    // probe, in this VSpace, starts only after the last server's VSpace
    // is built). `scratch` is a page nothing else maps,
    // where the fresh frame was just mapped read-write. The pages do not
    // overlap.
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
    /// Its arguments, in `rdi`, `rsi`, `rdx` and `rcx`: term's geometry,
    /// uart's cap on its burst in `rdi` (M9), and from M9 the network
    /// servers' words from their crates' `to_words`; 0 for the others.
    args: [u64; 4],
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
        args: [a0, a1, a2, a3],
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
        .with(UserReg::Rdx, a2)
        .with(UserReg::Rcx, a3);
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
    // Words 0 to 8: rip to rdi, so rcx, rdx and rsi too.
    .and_then(|()| tcb_write_registers(ipc, tcb, false, &regs, UserReg::Rdi.index() + 1))
    .and_then(|()| tcb_resume(tcb))
    .unwrap_or_else(|e| fail!("servers: starting the thread in TCB slot {tcb}: {e}"));
}

/// uart's entry: the cap on its burst, from the command line's
/// `uart.burst=<n>`, is in `rdi`.
extern "C" fn uart_main(cap: u64, _: u64, _: u64, _: u64) -> ! {
    uart::run(uart::Cap::from_word(cap))
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

/// virtio-net's entry: checks the words root passed again
/// (`virtio_net::Start::from_words`), then makes its windows over what
/// `start_qemu` mapped and runs it.
extern "C" fn virtio_net_main(rdi: u64, rsi: u64, rdx: u64, rcx: u64) -> ! {
    // Before anything can panic: the statics are a copy of the root
    // task's, whose print! may name a console capability of its CSpace.
    libsys::output::reset();
    let start = virtio_net::Start::from_words([rdi, rsi, rdx, rcx]).unwrap_or_else(|e| {
        panic!("virtio-net: words it refuses: {rdi:#x} {rsi:#x} {rdx:#x} {rcx:#x}: {e}")
    });
    let window = |which: Which| {
        let (addr, len) = start.window(which);
        // SAFETY: `start_qemu` mapped every page of region `which`
        // read-write and uncached at `virtio_net::layout::REGIONS` + its
        // window's offset + the page's, in this VSpace alone, from the
        // device frames it carved for the region (`pci::Plan::pages`);
        // `from_words` checked that the region starts in its window's
        // first page and ends inside the window, and root passed its
        // offset in its page and its length, so these `len` bytes from
        // `addr` are mapped device registers. They stay mapped for the
        // thread's life, and nothing holds a reference into them: they
        // are reached only through `Mmio`.
        unsafe { Mmio::new(addr as *mut u8, len) }
    };
    let regions = Regions {
        common: window(Which::Common),
        notify: window(Which::Notify),
        device: window(Which::Device),
    };
    // SAFETY: `start_qemu` mapped the DMA frame, a fresh 2 MiB RAM frame,
    // read-write and write-back at `virtio_net::layout::DMA` in this
    // VSpace and no other; it stays mapped for the thread's life. The
    // device writes it behind the compiler's back, so nothing holds a
    // reference into it: it is reached only through `Shared`.
    let dma = unsafe {
        Shared::new(
            virtio_net::layout::DMA as *mut u8,
            virtio_net::layout::DMA_SIZE,
        )
    };
    // SAFETY: `start_qemu` mapped the frame queues' frame, a fresh 2 MiB
    // RAM frame zeroed by its retype, read-write and write-back at
    // `libsys::frames::WINDOW` here, and its one copy in net's VSpace (or
    // root's, for test=virtio_net's probe); it stays mapped for the
    // thread's life. The other side writes it behind the compiler's back,
    // so nothing holds a reference into it: it is reached only through
    // `Shared`.
    let queues = unsafe { Shared::new(frames::WINDOW as *mut u8, frames::SIZE) };
    virtio_net::run(start, regions, dma, frames::Driver::new(queues))
}

/// net's entry: checks the words root passed again
/// (`net::Config::from_words`), then makes its window on the frame queues'
/// copy and runs it.
extern "C" fn net_main(rdi: u64, rsi: u64, rdx: u64, rcx: u64) -> ! {
    // Before anything can panic, as for virtio-net.
    libsys::output::reset();
    let Some(config) = net::Config::from_words([rdi, rsi, rdx, rcx]) else {
        panic!("net: words it refuses: {rdi:#x} {rsi:#x} {rdx:#x} {rcx:#x}")
    };
    // SAFETY: `start_net`, from `start_qemu` or `start_hyperv`, mapped a
    // copy of the frame queues' frame, the one the driver maps,
    // read-write and write-back at
    // `libsys::frames::WINDOW` in this VSpace, its only mapping here; it
    // stays mapped for the thread's life. The driver writes it behind the
    // compiler's back, so nothing holds a reference into it: it is
    // reached only through `Shared`.
    let queues = unsafe { Shared::new(frames::WINDOW as *mut u8, frames::SIZE) };
    net::run(config, frames::Net::new(queues))
}

/// vmbus's entry: checks the words root passed again
/// (`vmbus::Start::from_words`), then makes its windows on the SynIC
/// frames `start_hyperv` mapped and runs it.
extern "C" fn vmbus_main(rdi: u64, rsi: u64, rdx: u64, rcx: u64) -> ! {
    // Before anything can panic, as for virtio-net.
    libsys::output::reset();
    let Some(start) = vmbus::Start::from_words([rdi, rsi, rdx, rcx]) else {
        panic!("vmbus: words it refuses: {rdi:#x} {rsi:#x} {rdx:#x} {rcx:#x}")
    };
    let page = vmbus::layout::PAGE as usize;
    // SAFETY: `start_hyperv` mapped the SynIC message frame, root's slot
    // 13, a 4 KiB RAM frame outside every untyped, read-write and
    // write-back at `vmbus::layout::SIM` in this VSpace, its only mapping
    // anywhere; it stays mapped for the thread's life. The hypervisor
    // writes it behind the compiler's back, so nothing holds a reference
    // into it: it is reached only through `Shared`.
    let sim = unsafe { Shared::new(vmbus::layout::SIM as *mut u8, page) };
    // SAFETY: the same for the SynIC event-flag frame, root's slot 14, at
    // `vmbus::layout::SIEF`, the page above the message frame's.
    let sief = unsafe { Shared::new(vmbus::layout::SIEF as *mut u8, page) };
    vmbus::run(start, sim, sief)
}

/// netvsc's entry: checks the words root passed again
/// (`netvsc::Start::from_words`), then makes its windows on the channel
/// frame, the frame queues' original and, with `netvsc.mnf=1`, the
/// monitor window, which `start_hyperv` mapped, and runs it.
extern "C" fn netvsc_main(rdi: u64, rsi: u64, rdx: u64, rcx: u64) -> ! {
    // Before anything can panic, as for virtio-net.
    libsys::output::reset();
    let Some(start) = netvsc::Start::from_words([rdi, rsi, rdx, rcx]) else {
        panic!("netvsc: words it refuses: {rdi:#x} {rsi:#x} {rdx:#x} {rcx:#x}")
    };
    // SAFETY: `start_hyperv` mapped the channel frame, a fresh 2 MiB RAM
    // frame zeroed by its retype, read-write and write-back at
    // `netvsc::layout::CHANNEL` in this VSpace and no other; it stays
    // mapped for the thread's life. The host writes it behind the
    // compiler's back, so nothing holds a reference into it: it is reached
    // only through `Shared`.
    let channel = unsafe {
        Shared::new(
            netvsc::layout::CHANNEL as *mut u8,
            netvsc::layout::CHANNEL_SIZE,
        )
    };
    let mnf = if start.mnf {
        // SAFETY: with `netvsc.mnf=1`, the one case root passes `rsi` 1,
        // `start_hyperv` mapped monitor page 2 and the event-flags page,
        // fresh 4 KiB RAM frames, read-write and write-back at
        // `netvsc::layout::MNF` and the page above it in this VSpace and no
        // other; they stay mapped for the thread's life. The host reads
        // and writes them behind the compiler's back, so nothing holds a
        // reference into them: they are reached only through `Shared`.
        Some(unsafe { Shared::new(netvsc::layout::MNF as *mut u8, netvsc::layout::MNF_SIZE) })
    } else {
        None
    };
    // SAFETY: `start_hyperv` mapped the frame queues' frame, a fresh 2 MiB
    // RAM frame zeroed by its retype, read-write and write-back at
    // `libsys::frames::WINDOW` here, and its one copy in net's VSpace; it
    // stays mapped for the thread's life. net writes it behind the
    // compiler's back, so nothing holds a reference into it: it is reached
    // only through `Shared`.
    let queues = unsafe { Shared::new(frames::WINDOW as *mut u8, frames::SIZE) };
    netvsc::run(start, channel, mnf, frames::Driver::new(queues))
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
