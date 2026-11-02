//! `test=rootimage`: what boot step 8 made of the root image
//! (`docs/design.md`, "Root-task image and address space", "Root-task
//! entry state").
//!
//! `cargo xtask build` built `user/root`, stripped and checked it, and the
//! kernel embedded it in `.rootimage`; boot step 8 copied it into the root
//! task's frames, mapped its VSpace and made its TCB, then unmapped
//! `.rootimage`. The test checks that `.rootimage` is gone from the kernel
//! window and covered by RAM untyped; that BootInfo names the image; that
//! the root VSpace maps every image page to a frame holding what the ELF
//! says, with the segment's permissions (a hash step 8 computed from the
//! ELF before unmapping it, against the frames read through a walk of the
//! root PML4), and the IPC buffer and BootInfo after it, RW and NX, and
//! nothing just outside; and that the root TCB is ready to run as
//! `docs/abi.md` says.

use core::fmt;

use l4core::bootinfo::{BootInfo, CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER, CAP_INIT_VSPACE};
use l4core::cap::{CapType, TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_VSPACE};
use l4core::handoff::KERNEL_VIRT_BASE;
use l4core::regs::Exit;
use l4core::slot::SlotMemory;
use l4core::tcb::{Tcbs, ThreadState};
use l4core::vspace::{self, CacheType, PAGE_4K, USER_MIN};

use crate::arch::{self, Objects};
use crate::boot::{BootState, FNV_BASIS, RootSpace, page_hash};

fn fail(why: fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: rootimage: {why}");
    arch::exit(arch::ExitCode::Failure)
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            fail(format_args!($($arg)*))
        }
    };
}

fn perms(write: bool, execute: bool) -> &'static str {
    match (write, execute) {
        (false, true) => "RX",
        (false, false) => "R",
        (true, false) => "RW, NX",
        (true, true) => "RWX",
    }
}

/// Consecutive mapped pages with consecutive frames and the same
/// permissions, printed as one line.
struct Run {
    virt: (u64, u64),
    phys: u64,
    write: bool,
    execute: bool,
}

impl Run {
    fn print(&self) {
        let n = (self.virt.1 - self.virt.0) / PAGE_4K;
        kprintln!(
            "rootimage: {:#x}-{:#x} maps {n} frame{} from {:#x}, {}",
            self.virt.0,
            self.virt.1,
            if n == 1 { "" } else { "s" },
            self.phys,
            perms(self.write, self.execute)
        );
    }
}

/// `test=rootimage`.
pub fn test(boot: &BootState, root: &RootSpace, bi: &BootInfo) -> ! {
    // `.rootimage`: gone from the kernel window, covered by RAM untyped.
    let ri = root.rootimage;
    let virt = ri.start - boot.handoff.kernel_phys_base + KERNEL_VIRT_BASE;
    kprintln!(
        "rootimage: .rootimage was {virt:#x}-{:#x}, {} KiB, at physical {:#x}-{:#x}",
        virt + (ri.end - ri.start),
        (ri.end - ri.start) >> 10,
        ri.start,
        ri.end
    );
    for v in (virt..virt + (ri.end - ri.start)).step_by(PAGE_4K as usize) {
        ensure!(
            arch::kernel_translation(boot, v..v + PAGE_4K).is_none(),
            "{v:#x} is still mapped"
        );
    }
    let (count, bytes) = bi
        .untyped()
        .iter()
        .filter(|d| !d.device() && d.paddr >= ri.start && d.end() <= ri.end)
        .fold((0, 0), |(n, b), d| (n + 1, b + d.size()));
    ensure!(
        bytes == ri.end - ri.start,
        "RAM untyped cover {bytes:#x} of its {:#x} bytes",
        ri.end - ri.start
    );
    kprintln!(
        "rootimage: unmapped from the kernel window; {count} RAM untyped cover its {} KiB",
        bytes >> 10
    );
    // A reset of those untyped writes them through the direct map, which
    // must map them writable: a write would fault in ring 0 otherwise.
    Objects::begin().fill(ri.start, ri.end - ri.start, 0);
    kprintln!("rootimage: its direct-map alias is writable: zeroed through it");

    // BootInfo names the image, the IPC buffer and itself after it.
    let image = root.user_image;
    let after = |i: u64| image.end + i * PAGE_4K;
    ensure!(
        (bi.user_image_start, bi.user_image_end, bi.ipc_buffer)
            == (image.start, image.end, after(0)),
        "BootInfo's image {:#x}-{:#x} and IPC buffer {:#x}",
        bi.user_image_start,
        bi.user_image_end,
        bi.ipc_buffer
    );
    kprintln!(
        "rootimage: the root ELF's image {:#x}-{:#x}, entry {:#x}; IPC buffer at {:#x}, BootInfo at {:#x}",
        image.start,
        image.end,
        root.entry,
        after(0),
        after(1)
    );

    // The root VSpace, walked from its PML4.
    let k = Objects::begin();
    let l = &root.plan.layout;
    let pml4 = l.pml4.unwrap_or_else(|| fail(format_args!("no root PML4")));
    let frames = l.image_frame(0)..l.image_frame(root.image_pages);
    let (mut hash, mut pages) = (FNV_BASIS, 0);
    let mut run: Option<Run> = None;
    for v in (image.start..image.end).step_by(PAGE_4K as usize) {
        let Some(t) = vspace::translate(&k, pml4, v) else {
            continue;
        };
        ensure!(
            t.user
                && !t.global
                && t.page_size == PAGE_4K
                && t.cache == CacheType::WriteBack
                && frames.contains(&t.phys),
            "{v:#x} maps {t:x?}"
        );
        hash = page_hash(hash, v, t.write, t.execute, |w| {
            k.buffer_word(t.phys + 8 * w as u64)
        });
        pages += 1;
        match &mut run {
            Some(r)
                if r.virt.1 == v
                    && r.phys + (r.virt.1 - r.virt.0) == t.phys
                    && (r.write, r.execute) == (t.write, t.execute) =>
            {
                r.virt.1 += PAGE_4K;
            }
            _ => {
                if let Some(done) = run.take() {
                    done.print();
                }
                run = Some(Run {
                    virt: (v, v + PAGE_4K),
                    phys: t.phys,
                    write: t.write,
                    execute: t.execute,
                });
            }
        }
    }
    if let Some(done) = run {
        done.print();
    }
    ensure!(
        (hash, pages) == (root.image_hash, root.image_pages),
        "{pages} image pages hash to {hash:#x}; step 8 mapped {} to {:#x}",
        root.image_pages,
        root.image_hash
    );
    kprintln!(
        "rootimage: its {pages} image pages hold what the ELF says, with its segments' permissions"
    );
    for (v, phys, what) in [
        (after(0), l.ipc_buffer, "the IPC buffer"),
        (after(1), l.bootinfo, "BootInfo"),
        (after(2), l.bootinfo + PAGE_4K, "BootInfo's second page"),
    ] {
        match vspace::translate(&k, pml4, v) {
            Some(t) if t.phys == phys && t.write && !t.execute && t.user => {}
            other => fail(format_args!("{what} at {v:#x} maps {other:x?}")),
        }
    }
    kprintln!(
        "rootimage: {:#x}-{:#x} maps the IPC buffer and BootInfo's two frames, RW, NX",
        after(0),
        after(3)
    );
    let outside = [image.start - PAGE_4K, after(3)];
    for v in outside.into_iter().filter(|&v| v >= USER_MIN) {
        ensure!(
            vspace::translate(&k, pml4, v).is_none(),
            "{v:#x}, outside the image, maps"
        );
    }

    // The root TCB.
    let t = root.tcb;
    let regs = k.regs(t);
    ensure!(
        k.state(t) == ThreadState::Running && k.priority(t) == 255 && k.mcp(t) == 255,
        "the root TCB is {:?} at priority {} and MCP {}",
        k.state(t),
        k.priority(t),
        k.mcp(t)
    );
    ensure!(
        regs.next_ip == root.entry
            && regs.rdi == after(1)
            && regs.rflags == 0x202
            && regs.rsp == 0
            && regs.exit() == Exit::Iret
            && (regs.rax, regs.rbx, regs.rsi, regs.r15) == (0, 0, 0, 0),
        "the root TCB's registers {regs:x?}"
    );
    for (n, root_slot, ty) in [
        (TCB_SLOT_CSPACE, CAP_INIT_CNODE, CapType::CNode),
        (TCB_SLOT_VSPACE, CAP_INIT_VSPACE, CapType::Pml4),
        (TCB_SLOT_IPC_BUFFER, CAP_INIT_IPC_BUFFER, CapType::Frame),
    ] {
        let slot = k.load(t.slot(n));
        let src = l.slot(root_slot);
        ensure!(
            slot.cap.cap_type() == ty
                && slot.cap.same_object(&k.load(src).cap)
                && slot.node.prev() == Some(src),
            "TCB slot {n} holds {:x?}",
            slot.cap
        );
    }
    ensure!(
        k.ipc_buffer(t) == after(0),
        "the root TCB's IPC buffer is {:#x}",
        k.ipc_buffer(t)
    );
    kprintln!(
        "rootimage: the root TCB at {:#x} is Running at {:#x} with rdi {:#x}, RFLAGS 0x202, priority and MCP 255, its IPC buffer at {:#x}; its slots hold copies of root slots 2, 3 and 10",
        t.get(),
        regs.next_ip,
        regs.rdi,
        after(0)
    );
    kprintln!("TEST PASS");
    arch::exit(arch::ExitCode::Success)
}
