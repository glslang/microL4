//! The initial 4-level page tables the kernel is entered on.
//!
//! - `[0, phys_map_size)` 1:1 with 2 MiB pages, writable and executable,
//!   because the loader is still running there when it loads CR3.
//! - `[0, phys_map_size)` again at `PHYS_MAP_BASE`, writable and no-execute.
//! - The kernel image at `KERNEL_VIRT_BASE` with 4 KiB pages and the
//!   permissions of its ELF segments.
//!
//! The kernel replaces these tables with its own in M3.

use core::ptr;

use l4core::elf::{PAGE_SIZE, Segment};
use l4core::handoff::{KERNEL_VIRT_BASE, PHYS_MAP_BASE};

use crate::uefi::BootServices;
use crate::{Error, alloc_pages};

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const ENTRIES: u64 = 512;
const SIZE_2M: u64 = 2 << 20;
const SIZE_1G: u64 = 1 << 30;
const SIZE_512G: u64 = 512 << 30;

/// Upper bound on the table pages [`PageTables`] needs for these mappings.
pub fn tables_needed(phys_map_size: u64, kernel_size: u64) -> usize {
    // One PML4. For each of the 1:1 map and the direct map: a PDPT per
    // 512 GiB and a PD per GiB. For the kernel: one PDPT, up to two PDs (in
    // case the image crosses a 1 GiB boundary), and one PT per 2 MiB plus one
    // for a crossing.
    let pdpts = phys_map_size.div_ceil(SIZE_512G);
    let pds = phys_map_size.div_ceil(SIZE_1G);
    let kernel = 1 + 2 + kernel_size.div_ceil(SIZE_2M) + 1;
    (1 + 2 * (pdpts + pds) + kernel) as usize
}

pub struct PageTables {
    /// Physical address of a pool of zeroed pages; the first is the PML4.
    pool: u64,
    capacity: usize,
    used: usize,
    nx: bool,
}

impl PageTables {
    /// Allocates a pool of `pages` table pages. With `nx` false the
    /// no-execute bit is never set, for CPUs without it.
    pub fn alloc(bs: &BootServices, pages: usize, nx: bool) -> Result<Self, Error> {
        let pool = alloc_pages(bs, pages)?;
        Ok(Self {
            pool,
            capacity: pages,
            used: 1,
            nx,
        })
    }

    /// Physical address of the PML4, for CR3.
    pub fn root(&self) -> u64 {
        self.pool
    }

    /// Table pages used so far.
    pub fn used(&self) -> usize {
        self.used
    }

    pub fn map_identity(&mut self, size: u64) -> Result<(), Error> {
        self.map_range_2m(0, size, WRITABLE)
    }

    pub fn map_direct(&mut self, size: u64) -> Result<(), Error> {
        let nx = self.nx_bit();
        self.map_range_2m(PHYS_MAP_BASE, size, WRITABLE | nx)
    }

    /// Maps `seg` to the matching offset in the kernel's physical
    /// allocation, which starts at `kernel_phys` for `KERNEL_VIRT_BASE`.
    pub fn map_kernel_segment(&mut self, seg: &Segment, kernel_phys: u64) -> Result<(), Error> {
        let mut flags = 0;
        if seg.writable() {
            flags |= WRITABLE;
        }
        if !seg.executable() {
            flags |= self.nx_bit();
        }
        let first = seg.vaddr & !(PAGE_SIZE - 1);
        let mut virt = first;
        while virt < seg.vend() {
            self.map_4k(virt, kernel_phys + (virt - KERNEL_VIRT_BASE), flags)?;
            virt += PAGE_SIZE;
        }
        Ok(())
    }

    fn nx_bit(&self) -> u64 {
        if self.nx { NO_EXECUTE } else { 0 }
    }

    fn map_range_2m(&mut self, virt: u64, size: u64, flags: u64) -> Result<(), Error> {
        let mut off = 0;
        while off < size {
            let pd = self.walk(virt + off, 2)?;
            let slot = pd + index(virt + off, 1) * 8;
            if entry(slot) & PRESENT != 0 {
                return Err(Error::Unsupported("overlapping 2 MiB mappings"));
            }
            set_entry(slot, off | PRESENT | HUGE | flags);
            off += SIZE_2M;
        }
        Ok(())
    }

    fn map_4k(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), Error> {
        let pt = self.walk(virt, 3)?;
        let slot = pt + index(virt, 0) * 8;
        if entry(slot) & PRESENT != 0 {
            return Err(Error::Unsupported("overlapping kernel pages"));
        }
        set_entry(slot, phys | PRESENT | flags);
        Ok(())
    }

    /// Walks down `depth` levels from the PML4 towards `virt`, creating
    /// tables as needed, and returns the physical address of the table
    /// reached: depth 2 gives the PD, depth 3 the PT.
    fn walk(&mut self, virt: u64, depth: u32) -> Result<u64, Error> {
        let mut table = self.pool;
        for level in (4 - depth..4).rev() {
            let slot = table + index(virt, level) * 8;
            let e = entry(slot);
            table = if e & PRESENT == 0 {
                let new = self.alloc_table()?;
                // Intermediate entries grant everything; leaves restrict.
                set_entry(slot, new | PRESENT | WRITABLE);
                new
            } else if e & HUGE != 0 {
                return Err(Error::Unsupported("4 KiB mapping inside a huge page"));
            } else {
                e & ADDR_MASK
            };
        }
        Ok(table)
    }

    fn alloc_table(&mut self) -> Result<u64, Error> {
        if self.used == self.capacity {
            return Err(Error::Unsupported("page-table pool exhausted"));
        }
        let page = self.pool + self.used as u64 * PAGE_SIZE;
        self.used += 1;
        Ok(page)
    }
}

/// Index into the table at `level` (0 = PT, 3 = PML4) for `virt`.
fn index(virt: u64, level: u32) -> u64 {
    (virt >> (12 + 9 * level)) & (ENTRIES - 1)
}

fn entry(slot: u64) -> u64 {
    // SAFETY: `slot` is an 8-byte-aligned entry in a page of the pool, which
    // the firmware's page tables map 1:1.
    unsafe { ptr::read(slot as *const u64) }
}

fn set_entry(slot: u64, value: u64) {
    // SAFETY: as for `entry`. The new tables are not live yet, so no TLB
    // maintenance is needed.
    unsafe { ptr::write(slot as *mut u64, value) }
}
