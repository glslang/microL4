//! `test=rootimage`: the root image pipeline, before the kernel boots the
//! root task (`docs/design.md`, "Root-task image and address space").
//!
//! `cargo xtask build` built `user/root`, stripped and checked it, and the
//! kernel embeds it in `.rootimage`. The test finds the section through the
//! linker's symbols and checks that it holds exactly the file, page-aligned,
//! at the end of what the kernel maps read-only, where the live tables put
//! it at the physical pages the boot plan will reclaim. Then it runs
//! `l4core::boot::image`'s checks on the file, makes the boot plan the root
//! task's needs give on this machine, and prints the VSpace boot step 8
//! would build from it, slot by slot, each slot checked against the
//! capability `root_cap` would put there.

use core::fmt;

use l4core::boot::check::check_plan;
use l4core::boot::image::{RootImage, RootMapping, root_mappings};
use l4core::boot::{self as l4boot, root_cap};
use l4core::cap::{CapType, FRAME_4K_BITS, PAGING_STRUCTURE_BITS};
use l4core::vspace::UserAccess;

use crate::arch;
use crate::boot::{BootState, RootSpace};

const PAGE: u64 = 4096;

fn fail(why: fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: {why}");
    arch::exit(arch::ExitCode::Failure)
}

fn perms(a: UserAccess) -> &'static str {
    match (a.write, a.execute) {
        (false, true) => "RX",
        (false, false) => "R",
        (true, false) => "RW, NX",
        (true, true) => "RWX",
    }
}

/// Consecutive frames with consecutive slots, addresses and pages and the
/// same permissions, printed as one line.
struct Run {
    slots: (u64, u64),
    paddr: u64,
    virt: (u64, u64),
    access: UserAccess,
    file_bytes: usize,
}

impl Run {
    fn print(&self) {
        let n = (self.virt.1 - self.virt.0) / PAGE;
        kprintln!(
            "rootimage: slots {}-{}: {n} frame{} at {:#x} map {:#x}-{:#x} {}, {} file bytes",
            self.slots.0,
            self.slots.1,
            if n == 1 { "" } else { "s" },
            self.paddr,
            self.virt.0,
            self.virt.1,
            perms(self.access),
            self.file_bytes
        );
    }
}

/// `test=rootimage`.
pub fn test(boot: &BootState, root: &RootSpace) -> ! {
    let section = arch::take_rootimage();
    let v = section.virt();
    let (file, bytes) = (section.file(), section.bytes());
    kprintln!(
        "rootimage: .rootimage {:#x}-{:#x}, {} KiB, holds the {}-byte root ELF",
        v.start,
        v.end,
        (v.end - v.start) >> 10,
        file.len()
    );
    if !v.start.is_multiple_of(PAGE) || !v.end.is_multiple_of(PAGE) {
        fail(format_args!(".rootimage is not page-aligned"));
    }
    // The static's address, hidden from the optimiser, which could take
    // it and the linker's symbol for distinct objects.
    let file_at = core::hint::black_box(file.as_ptr()) as u64;
    if file_at != v.start || v.end != (v.start + file.len() as u64).next_multiple_of(PAGE) {
        fail(format_args!("the linker's symbols do not bound the file"));
    }
    if bytes[..file.len()] != *file || bytes[file.len()..].iter().any(|&b| b != 0) {
        fail(format_args!(".rootimage holds more than the file"));
    }
    let rodata = section.rodata();
    if rodata.start > v.start || rodata.end != v.end {
        fail(format_args!(
            ".rootimage does not end rodata {:#x}-{:#x}",
            rodata.start, rodata.end
        ));
    }
    let phys = section.phys(boot.handoff.kernel_phys_base);
    match section.translated(boot) {
        Some(t) if t == (phys.start..phys.end) => {}
        other => fail(format_args!(
            "the kernel's tables map .rootimage at {other:x?}, not {:#x}-{:#x}",
            phys.start, phys.end
        )),
    }
    kprintln!(
        "rootimage: at physical {:#x}-{:#x}, at the end of the kernel's read-only data",
        phys.start,
        phys.end
    );

    let image = match RootImage::check(bytes) {
        Ok(image) => image,
        Err(e) => fail(format_args!("the boot checks refuse the root image: {e}")),
    };
    let span = image.image();
    kprintln!(
        "rootimage: the root ELF passes the boot checks: entry {:#x}, image {:#x}-{:#x}",
        image.entry(),
        span.start,
        span.end
    );
    let regs = image.entry_regs();
    kprintln!(
        "rootimage: IPC buffer at {:#x}, BootInfo at {:#x}; root enters at {:#x} with rdi {:#x}, RFLAGS {:#x}",
        image.ipc_buffer(),
        image.bootinfo(),
        regs.next_ip,
        regs.rdi,
        regs.rflags
    );
    let needs = image.needs();
    kprintln!(
        "rootimage: needs a TCB, a PML4, {} PDPT, {} PD, {} PT and {} image frames",
        needs.pdpts,
        needs.pds,
        needs.pts,
        needs.image_frames
    );

    // The plan boot makes once it loads the root task: M4's input with
    // these needs and `.rootimage` reclaimed.
    let mut input = root.plan.input;
    input.root = needs;
    input.rootimage = Some(phys);
    let plan = match l4boot::plan(input) {
        Ok(plan) => plan,
        Err(e) => fail(format_args!("boot plan: {e}")),
    };
    if let Err(e) = check_plan(&plan) {
        fail(format_args!("check_plan: {e}"));
    }
    let slots = match l4boot::slot_plan(&needs, &root.untyped) {
        Ok(slots) => slots,
        Err(e) => fail(format_args!("slot plan: {e}")),
    };
    let l = &plan.layout;
    let r = l.region;
    kprintln!(
        "rootimage: boot region {:#x}-{:#x}, {} KiB: PML4 at {:#x}, TCB at {:#x}",
        r.start,
        r.end,
        (r.end - r.start) >> 10,
        l.pml4.unwrap_or(0),
        l.tcb.unwrap_or(0)
    );

    let mut run: Option<Run> = None;
    let mut frames = 0;
    for m in root_mappings(&image, l, &slots) {
        match m {
            RootMapping::Table {
                slot,
                ty,
                paddr,
                vaddr,
            } => {
                let cap = root_cap(&plan, &slots, &[], slot);
                if (cap.cap_type(), cap.object(), cap.size_bits())
                    != (ty, paddr, PAGING_STRUCTURE_BITS)
                {
                    fail(format_args!(
                        "slot {slot} holds {cap:?}, not {ty:?} at {paddr:#x}"
                    ));
                }
                kprintln!("rootimage: slot {slot}: {ty:?} at {paddr:#x} maps from {vaddr:#x}");
            }
            RootMapping::Frame {
                slot,
                paddr,
                vaddr,
                access,
                offset,
                bytes,
            } => {
                let cap = root_cap(&plan, &slots, &[], slot);
                if (cap.cap_type(), cap.object(), cap.size_bits())
                    != (CapType::Frame, paddr, FRAME_4K_BITS)
                    || offset + bytes.len() > PAGE as usize
                {
                    fail(format_args!(
                        "slot {slot} holds {cap:?}, not a frame at {paddr:#x}"
                    ));
                }
                frames += 1;
                match &mut run {
                    Some(r)
                        if r.slots.1 + 1 == slot
                            && r.virt.1 == vaddr
                            && r.paddr + (r.virt.1 - r.virt.0) == paddr
                            && r.access == access =>
                    {
                        r.slots.1 = slot;
                        r.virt.1 += PAGE;
                        r.file_bytes += bytes.len();
                    }
                    _ => {
                        if let Some(done) = run.take() {
                            done.print();
                        }
                        run = Some(Run {
                            slots: (slot, slot),
                            paddr,
                            virt: (vaddr, vaddr + PAGE),
                            access,
                            file_bytes: bytes.len(),
                        });
                    }
                }
            }
        }
    }
    if let Some(done) = run {
        done.print();
    }
    if frames != needs.image_frames + 3 {
        fail(format_args!(
            "{frames} frames mapped, not {} image frames, the IPC buffer and BootInfo",
            needs.image_frames
        ));
    }
    kprintln!("rootimage: every slot holds the capability boot step 8 maps");
    kprintln!("TEST PASS");
    arch::exit(arch::ExitCode::Success)
}
