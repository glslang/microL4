//! Building a server's address space from the root task's image
//! (`docs/design.md`, "Where the servers run"): which role each image page
//! has, which of the root task's image frames covers it, the paging
//! structures the server's VSpace needs, the scratch page the root task
//! fills fresh frames through, and the line `watch` prints when a server
//! faults. The root task's `servers.rs` does the invocations.

use core::fmt;

use libsys::bootinfo::SlotRegion;
use libsys::fault_label;

/// Bytes in a page.
pub const PAGE: u64 = 0x1000;
/// Bytes one page table translates.
pub const PT_SPAN: u64 = 1 << 21;

/// The image's layout: BootInfo's bounds, `user/link.ld`'s symbols and the
/// thread stacks' addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    /// The first page; text starts here.
    pub start: u64,
    /// One past the top of the `_start` stack; the IPC buffer's page.
    pub end: u64,
    pub rodata_start: u64,
    pub data_start: u64,
    /// The end of `.bss`, rounded up to a page.
    pub data_end: u64,
    /// The 64 KiB `_start` stack, up to `end`.
    pub libsys_stack_start: u64,
    /// Each thread stack's pages, `[start, end)`.
    pub thread_stacks: [(u64, u64); 6],
}

/// What an image page becomes in a server's VSpace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A copy of the root task's frame capability with Read only, mapped
    /// RX.
    Text,
    /// The same, mapped R and NX.
    ReadOnly,
    /// A fresh frame holding a copy of the root task's page at spawn,
    /// mapped RW and NX.
    Data,
    /// A root-task thread stack: unmapped.
    ThreadStack,
    /// A fresh zeroed frame of the server's stack, RW and NX.
    Stack,
    /// The server's IPC buffer, a fresh frame at the root task's address,
    /// RW and NX.
    IpcBuffer,
    /// A guard page: no frame, unmapped.
    Guard,
}

impl Role {
    /// Whether the server's VSpace maps the page.
    pub const fn mapped(self) -> bool {
        !matches!(self, Role::ThreadStack | Role::Guard)
    }

    /// Whether the page gets a fresh frame rather than a copy of the root
    /// task's capability.
    pub const fn fresh(self) -> bool {
        matches!(self, Role::Data | Role::Stack | Role::IpcBuffer)
    }
}

/// One page of the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub addr: u64,
    pub role: Role,
    /// The root task's image frame capability for the page, if a segment
    /// covers it.
    pub frame: Option<u64>,
}

/// Why an image cannot be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// A bound is not page-aligned, or the bounds are out of order.
    Layout,
    /// The pages segments cover are not as many as BootInfo's image
    /// frames.
    Frames { covered: u64, frames: u64 },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Layout => f.write_str("the image's segment bounds are out of order"),
            PlanError::Frames { covered, frames } => write!(
                f,
                "segments cover {covered} pages but BootInfo lists {frames} image frames"
            ),
        }
    }
}

/// The plan of a server's VSpace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    image: Image,
    frames: SlotRegion,
}

/// The paging structures a range needs, by level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tables {
    pub pdpts: u64,
    pub pds: u64,
    pub pts: u64,
}

impl Tables {
    pub const fn total(&self) -> u64 {
        self.pdpts + self.pds + self.pts
    }
}

impl Plan {
    /// Checks `image` against BootInfo's `user_image_frames`, one frame per
    /// covered page in address order.
    pub fn new(image: Image, frames: SlotRegion) -> Result<Plan, PlanError> {
        let i = &image;
        let aligned = [
            i.start,
            i.end,
            i.rodata_start,
            i.data_start,
            i.data_end,
            i.libsys_stack_start,
        ]
        .iter()
        .chain(i.thread_stacks.iter().flat_map(|(s, e)| [s, e]))
        .all(|a| a % PAGE == 0);
        let ordered = i.start <= i.rodata_start
            && i.rodata_start <= i.data_start
            && i.data_start <= i.data_end
            && i.data_end <= i.libsys_stack_start
            && i.libsys_stack_start <= i.end
            && i.thread_stacks.iter().all(|&(s, e)| {
                s <= e && (s == e || (i.data_end <= s && e <= i.libsys_stack_start))
            });
        if !aligned || !ordered {
            return Err(PlanError::Layout);
        }
        let plan = Plan { image, frames };
        let covered = plan.pages().filter(|p| p.frame.is_some()).count() as u64;
        // `pages` stops numbering frames past the region, so count roles.
        let covered_roles = plan
            .pages()
            .filter(|p| !matches!(p.role, Role::Guard | Role::IpcBuffer))
            .count() as u64;
        if covered_roles != frames.len() || covered != frames.len() {
            return Err(PlanError::Frames {
                covered: covered_roles,
                frames: frames.len(),
            });
        }
        Ok(plan)
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    fn role(&self, addr: u64) -> Role {
        let i = &self.image;
        if addr == i.end {
            Role::IpcBuffer
        } else if addr < i.rodata_start {
            Role::Text
        } else if addr < i.data_start {
            Role::ReadOnly
        } else if addr < i.data_end {
            Role::Data
        } else if addr >= i.libsys_stack_start {
            Role::Stack
        } else if i.thread_stacks.iter().any(|&(s, e)| (s..e).contains(&addr)) {
            Role::ThreadStack
        } else {
            Role::Guard
        }
    }

    /// Every page from the image's start to its IPC buffer, in address
    /// order, with its role and the root task's frame for it.
    pub fn pages(&self) -> impl Iterator<Item = Page> + '_ {
        let mut next_frame = self.frames.start;
        (self.image.start..=self.image.end)
            .step_by(PAGE as usize)
            .map(move |addr| {
                let role = self.role(addr);
                let frame = (!matches!(role, Role::Guard | Role::IpcBuffer)).then(|| {
                    let f = next_frame;
                    next_frame += 1;
                    f
                });
                Page {
                    addr,
                    role,
                    frame: frame.filter(|&f| f < self.frames.end),
                }
            })
    }

    /// The range the server's paging structures translate: the image and
    /// its IPC buffer.
    pub fn range(&self) -> (u64, u64) {
        (self.image.start, self.image.end + PAGE)
    }

    /// The base of each structure of `span` bytes the range touches.
    pub fn bases(&self, span: u64) -> impl Iterator<Item = u64> {
        let (start, end) = self.range();
        let first = start / span;
        let last = (end - 1) / span;
        (first..=last).map(move |n| n * span)
    }

    /// How many PDPTs, PDs and PTs the server's VSpace needs.
    pub fn tables(&self) -> Tables {
        Tables {
            pdpts: self.bases(1 << 39).count() as u64,
            pds: self.bases(1 << 30).count() as u64,
            pts: self.bases(PT_SPAN).count() as u64,
        }
    }

    /// Root slots a server costs: a copy per text and read-only page, a
    /// fresh frame per data, stack and IPC buffer page, its PML4 and paging
    /// structures, its TCB and its CNode.
    pub fn slots(&self) -> u64 {
        let frames = self.pages().filter(|p| p.role.mapped()).count() as u64;
        frames + 1 + self.tables().total() + 2
    }

    /// A page under the root task's own page tables that nothing maps: the
    /// last page of the 2 MiB that holds the end of what the kernel mapped
    /// (the image, the IPC buffer and BootInfo's two pages), if that is
    /// free.
    pub fn scratch(&self) -> Option<u64> {
        let mapped_end = self.image.end + 3 * PAGE;
        let last = ((mapped_end - 1) | (PT_SPAN - 1)) & !(PAGE - 1);
        (last >= mapped_end).then_some(last)
    }
}

/// Badges of endpoint F, the servers' fault endpoint, which `watch`
/// receives on: each names the server.
pub mod fault_badge {
    pub const UART: u64 = 1;
    pub const CONSOLE: u64 = 2;

    /// The server a badge names.
    pub const fn name(badge: u64) -> &'static str {
        match badge {
            UART => "uart",
            CONSOLE => "console",
            _ => "an unknown server",
        }
    }
}

/// The line `watch` prints for a fault message on F: `TEST FAIL: <server>
/// fault <label>, MR0 to MR3 <words>`.
pub struct FaultLine {
    pub badge: u64,
    pub label: u64,
    pub mr: [u64; 4],
}

impl fmt::Display for FaultLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.label {
            fault_label::CAP_FAULT => " (CapFault)",
            fault_label::UNKNOWN_SYSCALL => " (UnknownSyscall)",
            fault_label::USER_EXCEPTION => " (UserException)",
            fault_label::VM_FAULT => " (VMFault)",
            _ => "",
        };
        let [a, b, c, d] = self.mr;
        write!(
            f,
            "TEST FAIL: {} fault {}{kind}, MR0 to MR3 {a:#x} {b:#x} {c:#x} {d:#x}",
            fault_badge::name(self.badge),
            self.label
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::vec::Vec;

    /// M6's image as `user/link.ld` lays it out: text, rodata and data,
    /// six 16 KiB thread stacks each above a guard page, and the 64 KiB
    /// `_start` stack above one; 96 pages, 89 frames.
    fn m6() -> Image {
        let start = 0x40_0000;
        let rodata_start = start + 34 * PAGE;
        let data_start = rodata_start + 11 * PAGE;
        let data_end = data_start + 4 * PAGE;
        let mut stacks = [(0, 0); 6];
        let mut at = data_end;
        for s in stacks.iter_mut() {
            at += PAGE;
            *s = (at, at + 4 * PAGE);
            at += 4 * PAGE;
        }
        let libsys_stack_start = at + PAGE;
        Image {
            start,
            end: libsys_stack_start + 16 * PAGE,
            rodata_start,
            data_start,
            data_end,
            libsys_stack_start,
            thread_stacks: stacks,
        }
    }

    fn region(start: u64, len: u64) -> SlotRegion {
        SlotRegion {
            start,
            end: start + len,
        }
    }

    #[test]
    fn m6s_image() {
        let img = m6();
        assert_eq!(img.end, 0x46_0000);
        let plan = Plan::new(img, region(20, 89)).unwrap();
        let pages: Vec<Page> = plan.pages().collect();
        assert_eq!(pages.len(), 97, "96 image pages and the IPC buffer");
        let count = |r| pages.iter().filter(|p| p.role == r).count();
        assert_eq!(count(Role::Text), 34);
        assert_eq!(count(Role::ReadOnly), 11);
        assert_eq!(count(Role::Data), 4);
        assert_eq!(count(Role::ThreadStack), 24);
        assert_eq!(count(Role::Guard), 7);
        assert_eq!(count(Role::Stack), 16);
        assert_eq!(count(Role::IpcBuffer), 1);
        // Frames in address order over the covered pages only.
        let frames: Vec<u64> = pages.iter().filter_map(|p| p.frame).collect();
        assert_eq!(frames, (20..109).collect::<Vec<_>>());
        assert_eq!(
            pages[0],
            Page {
                addr: 0x40_0000,
                role: Role::Text,
                frame: Some(20)
            }
        );
        assert_eq!(pages[49].role, Role::Guard);
        assert_eq!(pages[49].frame, None);
        assert_eq!(pages[50].frame, Some(69));
        let last = pages[96];
        assert_eq!(
            (last.addr, last.role, last.frame),
            (0x46_0000, Role::IpcBuffer, None)
        );
        // One PDPT, PD and PT; with the PML4, the TCB and the CNode, and
        // 34 + 11 + 4 + 16 + 1 frames: 72 slots, "about 70".
        assert_eq!(
            plan.tables(),
            Tables {
                pdpts: 1,
                pds: 1,
                pts: 1
            }
        );
        assert_eq!(plan.slots(), 66 + 1 + 3 + 2);
        assert_eq!(plan.scratch(), Some(0x5F_F000));
        // Nothing the plan maps is writable in two VSpaces: text and
        // read-only pages are copies, everything writable is fresh.
        for p in &pages {
            match p.role {
                Role::Text | Role::ReadOnly => assert!(!p.role.fresh() && p.frame.is_some()),
                Role::Data | Role::Stack | Role::IpcBuffer => assert!(p.role.fresh()),
                Role::ThreadStack | Role::Guard => assert!(!p.role.mapped()),
            }
        }
    }

    #[test]
    fn an_image_across_a_2_mib_boundary() {
        let mut img = m6();
        // Shift everything up so the image straddles 0x60_0000.
        let shift = 0x5E_0000 - img.start;
        img.start += shift;
        img.end += shift;
        img.rodata_start += shift;
        img.data_start += shift;
        img.data_end += shift;
        img.libsys_stack_start += shift;
        for s in img.thread_stacks.iter_mut() {
            s.0 += shift;
            s.1 += shift;
        }
        let plan = Plan::new(img, region(30, 89)).unwrap();
        assert_eq!(plan.tables().pts, 2);
        assert_eq!(
            plan.bases(PT_SPAN).collect::<Vec<_>>(),
            [0x40_0000, 0x60_0000]
        );
        assert_eq!(plan.slots(), 66 + 1 + 4 + 2);
        // The IPC buffer page alone in a new 2 MiB still needs its table.
        let mut img = m6();
        let d = 0x60_0000 - img.end;
        img.end += d;
        img.libsys_stack_start += d;
        let plan = Plan::new(img, region(0, 89)).unwrap();
        assert_eq!(plan.tables().pts, 2);
        assert_eq!(plan.range(), (0x40_0000, 0x60_1000));
        // ... while the root task's BootInfo pages make it map past it.
        assert_eq!(plan.scratch(), Some(0x7F_F000));
    }

    #[test]
    fn segments_with_gaps() {
        let mut img = m6();
        // No .data at all, and the thread stacks two guard pages apart.
        img.data_end = img.data_start;
        let mut at = img.data_end;
        for s in img.thread_stacks.iter_mut() {
            at += 2 * PAGE;
            *s = (at, at + 4 * PAGE);
            at += 4 * PAGE;
        }
        img.libsys_stack_start = at + PAGE;
        img.end = img.libsys_stack_start + 16 * PAGE;
        let frames = 34 + 11 + 24 + 16;
        let plan = Plan::new(img, region(16, frames)).unwrap();
        let pages: Vec<Page> = plan.pages().collect();
        assert_eq!(pages.iter().filter(|p| p.role == Role::Guard).count(), 13);
        assert_eq!(pages.iter().filter(|p| p.role == Role::Data).count(), 0);
        // A frame count that disagrees is refused.
        assert_eq!(
            Plan::new(img, region(16, frames + 1)),
            Err(PlanError::Frames {
                covered: frames,
                frames: frames + 1
            })
        );
        // Bounds out of order, or not page-aligned.
        let mut bad = img;
        bad.data_start = bad.rodata_start - PAGE;
        assert_eq!(Plan::new(bad, region(16, frames)), Err(PlanError::Layout));
        let mut bad = img;
        bad.data_end += 8;
        assert_eq!(Plan::new(bad, region(16, frames)), Err(PlanError::Layout));
        // Empty thread stacks, as in a program without them.
        let mut img = m6();
        img.thread_stacks = [(0, 0); 6];
        assert!(matches!(
            Plan::new(img, region(0, 89)),
            Err(PlanError::Frames { .. })
        ));
    }

    #[test]
    fn no_scratch_page_when_the_mapping_ends_on_a_2_mib_boundary() {
        let mut img = m6();
        let d = 0x60_0000 - 3 * PAGE - img.end;
        img.end += d;
        img.libsys_stack_start += d;
        let plan = Plan::new(img, region(0, 89)).unwrap();
        assert_eq!(plan.scratch(), None);
    }

    #[test]
    fn watchs_line_for_each_fault() {
        let line = |badge, label| {
            format!(
                "{}",
                FaultLine {
                    badge,
                    label,
                    mr: [0x40_1234, 0xdead, 0, 6]
                }
            )
        };
        assert_eq!(
            line(1, 5),
            "TEST FAIL: uart fault 5 (VMFault), MR0 to MR3 0x401234 0xdead 0x0 0x6"
        );
        assert_eq!(
            line(2, 1),
            "TEST FAIL: console fault 1 (CapFault), MR0 to MR3 0x401234 0xdead 0x0 0x6"
        );
        assert_eq!(
            line(1, 2),
            "TEST FAIL: uart fault 2 (UnknownSyscall), MR0 to MR3 0x401234 0xdead 0x0 0x6"
        );
        assert_eq!(
            line(2, 3),
            "TEST FAIL: console fault 3 (UserException), MR0 to MR3 0x401234 0xdead 0x0 0x6"
        );
        assert_eq!(
            line(7, 0x130),
            "TEST FAIL: an unknown server fault 304, MR0 to MR3 0x401234 0xdead 0x0 0x6"
        );
    }
}
