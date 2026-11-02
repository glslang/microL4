//! Paging: the kernel's own page tables (`docs/design.md`, "The kernel
//! half"), step 4 of the M3 boot sequence; and from M5 the machine side of
//! address spaces ("Where the code lives"): `l4core::vspace`'s
//! [`PagingStore`] over the direct map, [`apply`], which holds the only
//! `invlpg` and the only CR3 reload, and [`set_vm_root`], the only other
//! CR3 write after boot. With `selftest`, the `test=paging`, `test=lowmem`
//! and `test=vspace` hooks.
//!
//! `l4core::vspace` decides every entry; this file finds the image's
//! sections from the linker script, owns the static tables in `.bss`,
//! reads and writes paging structures through the direct map, and writes
//! the MSR and control registers.
//!
//! What the rest of the kernel calls, from `arch::Objects`'s hooks, boot
//! step 8 and the exit path:
//!
//! - [`init_object`], for a new PML4's kernel half;
//! - [`finalise`] and [`moved`], for Frame and paging-structure
//!   capabilities: they call `l4core::vspace` and apply its flush;
//! - [`set_vm_root`], on every exit to a thread, with the capability in its
//!   VSpace slot;
//! - [`unmap_rootimage`], at the end of boot step 8, which takes
//!   `.rootimage` out of the kernel window and lets paging structures lie
//!   in its reclaimed pages.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use l4core::cap::{Cap, CapType};
use l4core::cpu::Feature;
use l4core::handoff::Handoff;
use l4core::slot::{SlotAddr, SlotMemory};
use l4core::vspace::{
    self, ADDR_4K, BACKREFS, BuildInput, ENTRIES, Flush, KERNEL_HALF, KernelLayout, KernelTables,
    PML4, PagingStore, STRUCTURE_LIMIT, Table,
};
use l4core::window::DeviceWindow;

use super::{Objects, cpu, phys_to_virt};
use crate::boot::BootState;

#[cfg(feature = "selftest")]
pub use self::selftest::{direct_map_page, tables_virt, test_lowmem, test_paging, translate};
#[cfg(feature = "selftest")]
pub use self::vspace_test::test_vspace;

const CR0_WP: u64 = 1 << 16;
const CR4_PGE: u64 = 1 << 7;
const CR4_UMIP: u64 = 1 << 11;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_PCIDE: u64 = 1 << 17;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const EFER_NXE: u64 = 1 << 11;
/// `IA32_APIC_BASE` bit 10: the local APIC is in x2APIC mode, and its MMIO
/// page reads nothing useful.
#[cfg(feature = "selftest")]
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// The address of linker-script symbol `$sym`. Read with `lea` rather than
/// `&raw const` of an extern static: the compiler assumes distinct statics
/// have distinct addresses, but `__data_end` and `__kernel_end` share one.
macro_rules! linker_addr {
    ($sym:literal) => {{
        let addr: u64;
        // SAFETY: `lea` only computes the address the linker gave `$sym`;
        // nothing is read.
        unsafe {
            asm!(
                concat!("lea {}, [rip + ", $sym, "]"),
                out(reg) addr,
                options(pure, nomem, nostack, preserves_flags)
            )
        };
        addr
    }};
}

/// The kernel's page tables: 87 page-aligned pages of `.bss`.
struct Tables(UnsafeCell<KernelTables>);

// SAFETY: the tables are written only through the one `&mut` that
// `take_tables` hands out, during boot on the one core, and then only by
// `unmap_rootimage`, once, in boot step 8, while no reference `built` gave
// out is live; otherwise they are only read.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(UnsafeCell::new(KernelTables::new()));
static TAKEN: AtomicBool = AtomicBool::new(false);
/// The kernel PML4's physical address once CR3 holds it, else 0.
static PML4_PHYS: AtomicU64 = AtomicU64::new(0);
/// The direct map's end and the kernel image's physical bounds, for the
/// checks of [`PagingStore`] over the direct map; set by `init`.
static DIRECT_MAP_END: AtomicU64 = AtomicU64::new(0);
static IMAGE_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_END: AtomicU64 = AtomicU64::new(0);
/// `.rootimage`'s physical pages once [`unmap_rootimage`] reclaimed them:
/// paging structures may lie there although it is inside the image.
static RECLAIMED_START: AtomicU64 = AtomicU64::new(0);
static RECLAIMED_END: AtomicU64 = AtomicU64::new(0);

/// The tables and the PML4's physical address, once `init` has loaded
/// them.
fn built() -> Option<(&'static KernelTables, u64)> {
    let pml4 = PML4_PHYS.load(Ordering::Acquire);
    // SAFETY: PML4_PHYS is set only after `init` finished writing the
    // tables through the reference `take_tables` gave it. The CPU never
    // writes them, since every kernel entry has Accessed, and every
    // writable leaf Dirty, already set; the kernel writes them once more,
    // in `unmap_rootimage`, which no caller of this function can overlap:
    // each uses the reference within one call and keeps none.
    (pml4 != 0).then(|| (unsafe { &*TABLES.0.get() }, pml4))
}

/// The kernel PML4: its physical address and its entries, which every
/// PML4's entries 256 to 511 copy. Panics before `init` has loaded it.
fn kernel_pml4() -> (u64, &'static Table) {
    let (tables, pml4) = built().expect("the kernel's page tables are not loaded");
    (pml4, &tables.tables[PML4])
}

/// The one mutable reference to the tables. Panics if called twice.
fn take_tables() -> &'static mut KernelTables {
    assert!(
        !TAKEN.swap(true, Ordering::AcqRel),
        "kernel page tables taken twice"
    );
    // SAFETY: the swap above lets exactly one caller past, so this is the
    // only reference to TABLES until `built` hands out shared ones, which it
    // does only after `init` has stopped using this one.
    unsafe { &mut *TABLES.0.get() }
}

/// The image's layout from the linker script's symbols and the handoff.
fn kernel_layout(h: &Handoff) -> KernelLayout {
    let data_end = linker_addr!("__data_end");
    assert_eq!(
        linker_addr!("__kernel_end"),
        data_end,
        "the data segment must end the image"
    );
    KernelLayout {
        phys_base: h.kernel_phys_base,
        size: h.kernel_size,
        text_start: linker_addr!("__text_start"),
        text_end: linker_addr!("__text_end"),
        rodata_start: linker_addr!("__rodata_start"),
        rodata_end: linker_addr!("__rodata_end"),
        rootimage_start: linker_addr!("__rootimage_start"),
        rootimage_end: linker_addr!("__rootimage_end"),
        data_start: linker_addr!("__data_start"),
        data_end,
        guards: [
            linker_addr!("__kernel_stack_guard"),
            linker_addr!("__ist1_guard"),
            linker_addr!("__ist2_guard"),
            linker_addr!("__ist3_guard"),
            linker_addr!("__ist4_guard"),
        ],
    }
}

/// Reads CR3: the loaded PML4's physical address in bits 12 to 51, PWT and
/// PCD in bits 3 and 4 (0 here), and nothing else, since PCID is off.
fn read_cr3() -> u64 {
    let v;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Loads CR3.
///
/// # Safety
///
/// `pml4` must be the physical address of a PML4 that maps the running
/// code, its stack and everything the kernel goes on to use, as the code
/// expects them.
unsafe fn write_cr3(pml4: u64) {
    // SAFETY: the caller vouches for the tables. The write changes every
    // translation, so it is not `nomem`.
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags)) };
}

/// Step 4 of the M3 boot sequence, after the descriptor tables: checks
/// EFER.NXE and CR0.WP, programs `IA32_PAT`, builds the kernel's tables in
/// `.bss`, sets CR4.SMEP, SMAP, PGE and (if present) UMIP, loads CR3 and
/// toggles CR4.PGE, which drops every translation the loader left, global
/// ones included [H4]. Afterwards the lower half is empty and the device
/// registers are reachable only through `window`.
pub fn init(boot: &'static BootState, window: &DeviceWindow) {
    let h = &boot.handoff;
    assert!(
        cpu::read_msr(cpu::IA32_EFER) & EFER_NXE != 0,
        "EFER.NXE is clear; the loader sets it"
    );
    assert!(
        cpu::read_cr0() & CR0_WP != 0,
        "CR0.WP is clear; the loader sets it"
    );

    let old_pat = cpu::read_msr(vspace::IA32_PAT);
    // SAFETY: the CPU has PAT (`check_cpu`). The loader's tables use only
    // PAT index 0, which is WB before and after, so no live mapping changes
    // type.
    unsafe { cpu::write_msr(vspace::IA32_PAT, vspace::PAT_MSR) };
    kprintln!(
        "paging: IA32_PAT {old_pat:#018x}, now {:#018x}",
        vspace::PAT_MSR
    );

    let layout = kernel_layout(h);
    let tables = take_tables();
    let tables_phys = layout.virt_to_phys(&raw const *tables as u64);
    let input = BuildInput {
        layout: &layout,
        regions: boot.memory_map(),
        direct_map_end: h.direct_map_end(),
        window,
    };
    let summary = match vspace::build(tables, tables_phys, &input) {
        Ok(s) => s,
        Err(e) => panic!("kernel page tables: {e}"),
    };
    let pml4 = KernelTables::table_phys(tables_phys, PML4);

    // PCID stays off and the kernel switches FS and GS bases itself
    // (`docs/design.md`, CPU features; ADR 0015), whatever the firmware left.
    let mut cr4 = (cpu::read_cr4() | CR4_SMEP | CR4_SMAP | CR4_PGE) & !(CR4_PCIDE | CR4_FSGSBASE);
    if cpu::cpuid_features().has(Feature::Umip) {
        cr4 |= CR4_UMIP;
    }
    // SAFETY: `check_cpu` found SMEP, SMAP and PGE, and UMIP is set only
    // when CPUID reports it. No page the kernel uses is user-accessible in
    // the loader's tables or in its own, so SMEP and SMAP stop nothing it
    // does; PGE only lets the new tables' global bits take effect. Clearing
    // PCIDE is allowed at any time, and the CR3 load below then uses no
    // PCID; nothing in the kernel uses the FS or GS base instructions.
    unsafe { cpu::write_cr4(cr4) };
    // SAFETY: `build` mapped the image at KERNEL_VIRT_BASE with this code,
    // the stack (minus its guard pages) and BootState, and the direct map
    // the kernel's `phys_to_virt` relies on; the host tests check both.
    // Nothing the kernel uses after this point is in the lower half.
    unsafe { write_cr3(pml4) };
    // SAFETY: clearing and setting PGE only flushes the TLB [H4]; the
    // tables just loaded hold every translation the kernel needs.
    unsafe {
        cpu::write_cr4(cr4 & !CR4_PGE);
        cpu::write_cr4(cr4);
    }
    let image = layout.phys();
    DIRECT_MAP_END.store(h.direct_map_end(), Ordering::Relaxed);
    IMAGE_START.store(image.start, Ordering::Relaxed);
    IMAGE_END.store(image.end, Ordering::Relaxed);
    PML4_PHYS.store(pml4, Ordering::Release);

    kprintln!(
        "paging: kernel PML4 at {pml4:#x}; image {} KiB; device window pages: {}",
        layout.size >> 10,
        summary.window_pages
    );
    kprintln!(
        "paging: direct map {} GiB; 2 MiB pages: {} WB, {} UC, {} split into 4 KiB pages",
        h.direct_map_end() >> 30,
        summary.direct_wb,
        summary.direct_uc,
        summary.alias_pts
    );
}

/// The direct-map address of word `i` of the paging structure at physical
/// `table` (words 512 to 1023 are its back-references). Panics unless `i`
/// is below 1024 and `table` is 8 KiB-aligned; debug builds also check
/// that the structure lies above 1 MiB, below the direct map's end and
/// outside the kernel image, as every paging structure does: they are
/// retyped from RAM untyped only.
fn structure_word(table: u64, i: usize) -> *mut u64 {
    assert!(
        i < 2 * ENTRIES && table.is_multiple_of(1 << 13),
        "word {i} of paging structure {table:#x}"
    );
    debug_assert!(
        (1 << 20..STRUCTURE_LIMIT).contains(&table)
            && table + (1 << 13) <= DIRECT_MAP_END.load(Ordering::Relaxed)
            && (table + (1 << 13) <= IMAGE_START.load(Ordering::Relaxed)
                || table >= IMAGE_END.load(Ordering::Relaxed)
                || (table >= RECLAIMED_START.load(Ordering::Relaxed)
                    && table + (1 << 13) <= RECLAIMED_END.load(Ordering::Relaxed))),
        "{table:#x} is not where a paging structure can be"
    );
    phys_to_virt(table + 8 * i as u64) as *mut u64
}

/// Word `i` of the paging structure at `table`.
fn read_structure(table: u64, i: usize) -> u64 {
    let at = structure_word(table, i);
    // SAFETY: `l4core::vspace` names only live paging structures, which its
    // invariants keep in RAM retyped from untyped below the direct map's
    // end, 8 KiB-aligned, and `structure_word` keeps the word inside the
    // structure. The direct map maps that RAM RW and write-back (no RAM
    // untyped lies in a 2 MiB page it maps uncached), and no Rust reference
    // into object memory exists. The CPU's page walker reads entries and
    // sets their Accessed and Dirty bits at any time; an aligned 8-byte
    // volatile access is one access, so neither side sees a torn word.
    unsafe { ptr::read_volatile(at) }
}

/// Overwrites word `i` of the paging structure at `table`.
fn write_structure(table: u64, i: usize, word: u64) {
    let at = structure_word(table, i);
    // SAFETY: as in `read_structure`. The write changes only paging
    // structure memory, never kernel code, static data or a slot; what it
    // changes for the CPU's translations is `l4core::vspace`'s to decide,
    // and the flush it returns follows the write.
    unsafe { ptr::write_volatile(at, word) };
}

/// `l4core::vspace`'s view of paging structures, through the direct map.
impl PagingStore for Objects {
    fn entry(&self, table: u64, i: usize) -> u64 {
        read_structure(table, i)
    }

    fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
        write_structure(table, i, entry)
    }

    fn backref(&self, table: u64, i: usize) -> u64 {
        read_structure(table, i + BACKREFS as usize / 8)
    }

    fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
        write_structure(table, i + BACKREFS as usize / 8, backref)
    }

    fn flush(&mut self, flush: Flush) {
        apply(flush)
    }
}

/// Applies a flush `l4core::vspace` returned, after the writes it covers
/// ("TLB maintenance"): `invlpg` for a page [H5], a CR3 reload for
/// everything not global [H4]. The kernel's only `invlpg` and only CR3
/// reload. Flushes do not depend on which VSpace is loaded: an `invlpg` of
/// another VSpace's page drops at worst one unrelated translation.
pub fn apply(flush: Flush) {
    match flush {
        Flush::None => {}
        Flush::Page(vaddr) => {
            // SAFETY: `invlpg` only drops the translations of the page
            // holding `vaddr` and the paging-structure caches; it reads no
            // memory. It is not `nomem`, so the entry writes before it
            // stay before it.
            unsafe { asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
        }
        Flush::All => {
            // SAFETY: loading CR3 with the PML4 it holds changes no mapping
            // and drops every non-global translation [H4]; the kernel's
            // own are global, and in every PML4 anyway.
            unsafe { write_cr3(read_cr3()) };
        }
    }
}

/// Loads the VSpace `vspace` names (`docs/design.md`, "TLB maintenance"):
/// the PML4 of a PML4 capability, or the kernel PML4 for anything else, a
/// thread without a valid VSpace. Writes CR3 only when the PML4 changes;
/// with PCID off the write drops every user translation [H4]. The only CR3
/// write after boot besides [`apply`]'s reload: the exit path calls it with
/// the capability in the next thread's VSpace slot, and [`finalise`] when
/// the loaded PML4 dies. `vspace` must be a capability read from a slot,
/// so that a PML4 capability names a live PML4; one without the kernel's
/// half panics.
pub fn set_vm_root(vspace: Cap) {
    let (kernel, kernel_entries) = kernel_pml4();
    let pml4 = match vspace.cap_type() {
        CapType::Pml4 => vspace.object(),
        _ => kernel,
    };
    if read_cr3() & ADDR_4K == pml4 {
        return;
    }
    // A PML4 that a capability names is live, and retype gave it the
    // kernel's half (`init_object`), which no invocation writes. Entries
    // 256 and 511 are the ones the kernel uses; debug builds check all.
    let check = |i: usize| read_structure(pml4, i) == kernel_entries[i];
    let half_ok = pml4 == kernel
        || if cfg!(debug_assertions) {
            KERNEL_HALF.clone().all(check)
        } else {
            check(256) && check(511)
        };
    assert!(half_ok, "PML4 {pml4:#x} does not hold the kernel's half");
    // SAFETY: `pml4` is the kernel PML4, or a live PML4 whose entries 256
    // to 511 equal the kernel PML4's (checked above), so the kernel's code,
    // stacks, data, direct map and device window translate as before; the
    // lower half holds only user mappings, which the kernel never uses.
    unsafe { write_cr3(pml4) };
}

/// Boot step 8's end (`docs/design.md`, "Boot sequence", "The kernel
/// half"): clears the PTEs that map `.rootimage`, the image pages `virt`
/// at `KERNEL_VIRT_BASE`, then toggles CR4.PGE, which drops their global
/// translations [H4]. Its direct-map alias, `phys`, stays mapped
/// read-write, as M3 built it, and paging structures may lie there from
/// now on. Called once, by `RootImageSection::unmap`, which consumes the
/// section so no borrow of its bytes outlives this.
pub fn unmap_rootimage(virt: core::ops::Range<u64>, phys: core::ops::Range<u64>) {
    use l4core::handoff::KERNEL_VIRT_BASE;
    use l4core::vspace::{IMAGE_PTS, PAGE_4K};

    assert!(
        RECLAIMED_END.load(Ordering::Relaxed) == 0,
        ".rootimage reclaimed twice"
    );
    assert!(
        virt.start.is_multiple_of(PAGE_4K)
            && virt.end.is_multiple_of(PAGE_4K)
            && virt.start >= KERNEL_VIRT_BASE
            && phys.end - phys.start == virt.end - virt.start,
        "bad .rootimage range"
    );
    let tables = TABLES.0.get();
    for v in (virt.start..virt.end).step_by(PAGE_4K as usize) {
        let k = ((v - KERNEL_VIRT_BASE) / PAGE_4K) as usize;
        let (pt, i) = (IMAGE_PTS + k / ENTRIES, k % ENTRIES);
        // SAFETY: `init` built the tables and loaded them; this is boot
        // step 8, between kernel operations, so no reference `built` gave
        // out is live, and `take_tables`' was dropped at the end of `init`.
        // Clearing the leaf for an image page of `.rootimage` unmaps only
        // that page, which nothing but `RootImageSection` reads, and the
        // caller consumed it; the code, stacks and data stay mapped. The
        // place is reached through the raw pointer, not a reference, and
        // written with one aligned store, which the page walker sees whole.
        unsafe { ptr::write_volatile(&raw mut (*tables).tables[pt][i], 0) };
    }
    let cr4 = cpu::read_cr4();
    // SAFETY: clearing and setting PGE only flushes the TLB, global
    // entries included [H4]; every translation the kernel still uses is in
    // the tables.
    unsafe {
        cpu::write_cr4(cr4 & !CR4_PGE);
        cpu::write_cr4(cr4);
    }
    RECLAIMED_START.store(phys.start, Ordering::Relaxed);
    RECLAIMED_END.store(phys.end, Ordering::Relaxed);
}

/// The `init_object` hook's part for paging: a new PML4 gets the kernel's
/// half. Retype zeroed it, and every other new paging structure or frame
/// is all zeros already.
pub fn init_object<K: PagingStore + ?Sized>(k: &mut K, cap: Cap) {
    if cap.cap_type() == CapType::Pml4 {
        vspace::init_pml4(k, cap.object(), kernel_pml4().1);
    }
}

/// The `finalise` hook's part for Frame and paging-structure capabilities
/// (`docs/design.md`, "Deletion"): if the last capability to the loaded
/// PML4 goes, the kernel PML4 is loaded first; then `l4core::vspace`
/// unmaps what the capability maps, and its flush is applied. Nothing
/// for other capabilities.
pub fn finalise<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, cap: Cap, last: bool) {
    if cap.cap_type() == CapType::Pml4 && last && read_cr3() & ADDR_4K == cap.object() {
        set_vm_root(Cap::NULL);
    }
    apply(vspace::finalise(k, cap, last));
}

/// The `moved` hook's part: a mapped Frame or paging structure's
/// back-reference follows its capability from `from` to `to`.
pub fn moved<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    cap: Cap,
    from: SlotAddr,
    to: SlotAddr,
) {
    apply(vspace::moved(k, cap, from, to));
}

/// `test=paging` and `test=lowmem` (M3), with `selftest` only.
#[cfg(feature = "selftest")]
mod selftest {
    use core::arch::asm;
    use core::sync::atomic::{AtomicU64, Ordering};

    use l4core::handoff::{KERNEL_VIRT_BASE, PHYS_MAP_BASE};
    use l4core::vspace::{self, CacheType, KernelTables};
    use l4core::window::{DeviceWindow, LAPIC_PAGE};

    use super::super::{ExitCode, cpu, exit, phys_to_virt};
    use super::{APIC_BASE_X2APIC, CR4_PGE, CR4_SMAP, CR4_SMEP, TABLES, built, kernel_layout};
    use crate::boot::BootState;

    /// The physical range the live kernel tables map the virtual range
    /// `virt` to, for `test=bootinfo`; `None` if a page of it is unmapped.
    /// Panics if it is not physically contiguous.
    pub fn translate(
        boot: &BootState,
        virt: core::ops::Range<u64>,
    ) -> Option<core::ops::Range<u64>> {
        let Some((tables, _)) = built() else {
            panic!("the kernel's tables are not loaded");
        };
        let tables_phys = kernel_layout(&boot.handoff).virt_to_phys(&raw const *tables as u64);
        let phys = |v: u64| match tables.walk(tables_phys, v) {
            Ok(t) => t.map(|t| t.phys),
            Err(e) => panic!("{v:#x} does not translate: {e:?}"),
        };
        let mut v = virt.start;
        let start = phys(v)?;
        while v < virt.end {
            assert_eq!(
                phys(v)?,
                start + (v - virt.start),
                "{v:#x} breaks contiguity"
            );
            v = (v | 0xFFF) + 1;
        }
        Some(start..start + (virt.end - virt.start))
    }

    /// The kernel's page tables, as a virtual range.
    pub fn tables_virt() -> core::ops::Range<u64> {
        let start = TABLES.0.get() as u64;
        start..start + size_of::<KernelTables>() as u64
    }

    /// How the live kernel tables map physical `phys` in the direct map:
    /// the cache type and the size of the page holding it, or `None` if
    /// no page does. For `test=bootinfo`.
    pub fn direct_map_page(boot: &BootState, phys: u64) -> Option<(CacheType, u64)> {
        let Some((tables, _)) = built() else {
            panic!("the kernel's tables are not loaded");
        };
        let tables_phys = kernel_layout(&boot.handoff).virt_to_phys(&raw const *tables as u64);
        match tables.walk(tables_phys, PHYS_MAP_BASE + phys) {
            Ok(t) => t.map(|t| (t.cache, t.page_size)),
            Err(e) => panic!("{phys:#x} does not translate in the direct map: {e:?}"),
        }
    }

    /// Records one check of `test=paging`; returns whether it held.
    fn check(ok: bool, what: &str) -> bool {
        kprintln!("paging: {} {what}", if ok { "ok  " } else { "FAIL" });
        ok
    }

    /// `test=paging`: the kernel runs on its own tables. CR3 holds the kernel
    /// PML4 and CR4 the required bits; the software walk of the live tables
    /// agrees with the design; a write through the direct map's alias of `.bss`
    /// is seen at `KERNEL_VIRT_BASE`; the direct map's alias of `.text` reads
    /// the same bytes; and the local APIC answers through the device window.
    pub fn test_paging(boot: &BootState) -> ! {
        let Some((tables, pml4)) = built() else {
            panic!("test=paging: the kernel's tables are not loaded");
        };
        let layout = kernel_layout(&boot.handoff);
        let tables_phys = layout.virt_to_phys(&raw const *tables as u64);
        let cr3 = cpu::read_cr3();
        let cr4 = cpu::read_cr4();
        kprintln!("paging: CR3 {cr3:#x}, CR4 {cr4:#x}");
        let mut ok = check(cr3 & vspace::ADDR_4K == pml4, "CR3 holds the kernel PML4");
        let required = CR4_SMEP | CR4_SMAP | CR4_PGE;
        ok &= check(cr4 & required == required, "CR4.SMEP, SMAP and PGE are set");

        let walk = |virt| tables.walk(tables_phys, virt).ok().flatten();
        ok &= check(
            walk(0x20_0000).is_none() && walk(boot.handoff.kernel_phys_base).is_none(),
            "the lower half maps nothing",
        );
        ok &= check(
            layout.guards.iter().all(|&g| walk(g).is_none()),
            "the five guard pages are unmapped",
        );
        ok &= check(
            walk(KERNEL_VIRT_BASE).is_some_and(|t| t.execute && !t.write && t.global && !t.user),
            "KERNEL_VIRT_BASE is RX, global and supervisor-only",
        );
        let text_alias = PHYS_MAP_BASE + boot.handoff.kernel_phys_base;
        ok &= check(
            walk(text_alias).is_some_and(|t| !t.execute && !t.write),
            "the direct map's alias of .text is read-only and NX",
        );

        // A write through the direct map's alias of `.data` lands where the
        // image mapping reads.
        static PROBE: AtomicU64 = AtomicU64::new(0);
        let probe_alias = phys_to_virt(layout.virt_to_phys(&raw const PROBE as u64));
        // SAFETY: `probe_alias` is PROBE's own physical page through the direct
        // map, RW in the kernel's tables, and an AtomicU64 tolerates the alias.
        unsafe { (*(probe_alias as *const AtomicU64)).store(0x5EED_CAFE, Ordering::SeqCst) };
        ok &= check(
            PROBE.load(Ordering::SeqCst) == 0x5EED_CAFE,
            "a write through the direct map reaches .bss",
        );
        // SAFETY: both addresses map the image's first page of text, readable
        // in the kernel's tables; reading code bytes as data is harmless.
        let (a, b) = unsafe {
            (
                core::ptr::read_volatile(KERNEL_VIRT_BASE as *const u64),
                core::ptr::read_volatile(text_alias as *const u64),
            )
        };
        ok &= check(
            a == b,
            "the direct map's alias of .text reads the same bytes",
        );

        let lapic = DeviceWindow::virt(LAPIC_PAGE);
        ok &= check(
            walk(lapic).is_some_and(|t| t.cache == CacheType::Uncached && !t.execute && t.write),
            "the local APIC's window page is UC, RW and NX",
        );
        if cpu::read_msr(cpu::IA32_APIC_BASE) & APIC_BASE_X2APIC != 0 {
            kprintln!("paging: the local APIC is in x2APIC mode; skipping its MMIO read");
        } else {
            // SAFETY: the window maps the local APIC's page UC; offset 0x30 is
            // its read-only version register, and reading it has no side effect.
            let version = unsafe { core::ptr::read_volatile((lapic + 0x30) as *const u32) };
            kprintln!("paging: local APIC version register {version:#x}");
            ok &= check(
                (0x10..=0x1F).contains(&(version & 0xFF)),
                "the local APIC answers through the device window",
            );
        }

        if ok {
            kprintln!("TEST PASS");
            exit(ExitCode::Success)
        } else {
            kprintln!("TEST FAIL");
            exit(ExitCode::Failure)
        }
    }

    /// `test=lowmem`: the loader's 1:1 map is gone. Physical `LOW` is RAM and
    /// reads through the direct map, but virtual `LOW`, which the loader mapped
    /// 1:1, must fault. With the kernel's fault report the run ends in a
    /// `KERNEL PANIC` naming CR2 = `LOW`; without it, in a triple fault.
    pub fn test_lowmem() -> ! {
        const LOW: u64 = 0x20_0000;
        // SAFETY: physical 2 MiB is RAM on QEMU and Hyper-V and lies inside the
        // direct map; reading it changes nothing.
        let v = unsafe { core::ptr::read_volatile(phys_to_virt(LOW) as *const u64) };
        kprintln!("lowmem: physical {LOW:#x} reads {v:#x} through the direct map");
        kprintln!("lowmem: reading virtual {LOW:#x}, which the loader mapped 1:1; this must fault");
        let w: u64;
        // SAFETY: a read of a lower-half address, which the kernel's tables
        // leave unmapped: it touches no memory Rust knows about, and its page
        // fault ends the run.
        unsafe {
            asm!("mov {}, qword ptr [{}]", out(reg) w, in(reg) LOW, options(nostack, readonly));
        }
        kprintln!("TEST FAIL: virtual {LOW:#x} read {w:#x}; the 1:1 map is still there");
        exit(ExitCode::Failure)
    }
}

/// `test=vspace` (M5), with `selftest` only: address spaces on the machine.
///
/// Paging structures and frames are retyped from a RAM untyped `U` through
/// `l4core::invoke`, with CPtrs into the root CNode, as the root task will
/// make them, and mapped at the top of the user range in a fresh PML4,
/// which [`set_vm_root`] loads. The kernel never touches a user address
/// (SMAP; `docs/design.md`, "Kernel execution model"), so each mapping is
/// checked by walking the tables CR3 holds, and the frame behind a user
/// address is written and read through the direct map at the address the
/// walk gives. Then a remap, a move, an unmap and deletions, each checked
/// the same way; the last capability to the loaded PML4 is deleted, which
/// loads the kernel PML4; and `U` is revoked.
///
/// The kernel's `Objects` hooks call this file's [`finalise`], [`moved`] and
/// [`init_object`]; the test wraps `Objects` in `Wired`, which never
/// preempts.
#[cfg(feature = "selftest")]
mod vspace_test {
    use core::fmt;
    use core::ptr;

    use l4core::bootinfo::CAP_INIT_CNODE;
    use l4core::cap::{Cap, ObjectType, Rights};
    use l4core::cspace;
    use l4core::error::{LookupFailure, SyscallError};
    use l4core::invoke::{self, ExtraCap, InvokeError, Message, Reply};
    use l4core::kernel::{Kernel, Preempted};
    use l4core::slot::{Slot, SlotAddr, SlotMemory};
    use l4core::vspace::{
        Attributes, CacheType, Flush, PAGE_2M, PAGE_4K, PagingStore, Translation, USER_TOP, label,
        translate,
    };

    use super::super::{ExitCode, Objects, exit, phys_to_virt};
    use l4core::sched::{Scheduler, Scheduling};
    use l4core::tcb::{TcbRef, Tcbs, Threads};

    use super::{ADDR_4K, ENTRIES, kernel_pml4, read_cr3, set_vm_root};
    use crate::boot::RootSpace;

    /// `Objects`, whose hooks call this file's paging hooks, without
    /// preemption: the test's calls run to the end.
    struct Wired(Objects);

    impl SlotMemory for Wired {
        fn load(&self, at: SlotAddr) -> Slot {
            self.0.load(at)
        }

        fn store(&mut self, at: SlotAddr, slot: Slot) {
            self.0.store(at, slot)
        }
    }

    impl PagingStore for Wired {
        fn entry(&self, table: u64, i: usize) -> u64 {
            self.0.entry(table, i)
        }

        fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
            self.0.set_entry(table, i, entry)
        }

        fn backref(&self, table: u64, i: usize) -> u64 {
            self.0.backref(table, i)
        }

        fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
            self.0.set_backref(table, i, backref)
        }

        fn flush(&mut self, flush: Flush) {
            self.0.flush(flush)
        }
    }

    impl Kernel for Wired {
        fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
            self.0.finalise(cap, last)
        }

        fn after_delete(&mut self, cleanup: Cap) {
            self.0.after_delete(cleanup)
        }

        fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
            self.0.moved(cap, from, to)
        }

        fn zero(&mut self, paddr: u64, len: u64) {
            self.0.zero(paddr, len)
        }

        fn init_object(&mut self, cap: Cap) {
            self.0.init_object(cap)
        }

        fn preempt(&mut self) -> Result<(), Preempted> {
            Ok(())
        }
    }

    impl Tcbs for Wired {
        fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
            self.0.tcb_word(t, offset)
        }

        fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
            self.0.set_tcb_word(t, offset, value)
        }
    }

    impl Scheduling for Wired {
        fn scheduler(&self) -> &Scheduler {
            self.0.scheduler()
        }

        fn scheduler_mut(&mut self) -> &mut Scheduler {
            self.0.scheduler_mut()
        }
    }

    impl Threads for Wired {
        fn cancel_ipc(&mut self, t: TcbRef) {
            self.0.cancel_ipc(t)
        }

        fn invoked_by_call(&self) -> bool {
            self.0.invoked_by_call()
        }

        fn synic_pages(&self) -> [u64; 2] {
            self.0.synic_pages()
        }

        fn set_current_fs_base(&mut self, value: u64) {
            self.0.set_current_fs_base(value)
        }

        fn write_buffer_word(&mut self, paddr: u64, value: u64) {
            self.0.write_buffer_word(paddr, value)
        }
    }

    fn wired() -> Wired {
        Wired(Objects::begin())
    }

    fn fail(why: fmt::Arguments<'_>) -> ! {
        kprintln!("TEST FAIL: vspace: {why}");
        exit(ExitCode::Failure)
    }

    fn check(ok: bool, what: &str) {
        if !ok {
            fail(format_args!("{what}: no"))
        }
        kprintln!("vspace: ok   {what}");
    }

    const ROOT: u64 = CAP_INIT_CNODE;
    const RW: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;
    const R: u64 = Rights::READ.0 as u64;
    const WB: u64 = 0;
    const X: u64 = Attributes::EXECUTE;
    /// The highest page table: PML4 entry 255, PDPT entry 511, page
    /// directory entry 511. The highest 4 KiB page, its entry 510; its
    /// first page; and the highest 2 MiB page, page directory entry 510.
    const TOP_PT: u64 = 0x0000_7FFF_FFE0_0000;
    const F1_VA: u64 = USER_TOP - PAGE_4K;
    const F2_VA: u64 = TOP_PT;
    const G_VA: u64 = TOP_PT - PAGE_2M;
    /// The least size of `U`: a 2 MiB frame and the rest.
    const MIN_U_BITS: u8 = 22;

    /// The root CNode's capability, and the root CNode slots the test
    /// uses: `U`'s, then from the first empty one.
    struct Slots {
        root: Cap,
        u: u64,
        g: u64,
        pml4: u64,
        pdpt: u64,
        pd: u64,
        pt: u64,
        f1: u64,
        f2: u64,
        pml4_copy: u64,
        f1_moved: u64,
    }

    impl Slots {
        /// One invocation: the capability `invoked` names, with `mrs` and
        /// the capabilities `extra` names, every CPtr resolved from the
        /// root CNode.
        fn call(
            &self,
            invoked: u64,
            l: u64,
            mrs: &[u64],
            extra: &[u64],
        ) -> Result<Reply, InvokeError> {
            let mut k = wired();
            let slot = self.lookup(&k, invoked);
            let mut caps = [ExtraCap {
                cap: Cap::NULL,
                slot,
            }; 2];
            for (c, &cptr) in caps.iter_mut().zip(extra) {
                *c = ExtraCap::load(&k, self.lookup(&k, cptr));
            }
            let msg = Message {
                label: l,
                mrs,
                extra_caps: &caps[..extra.len()],
            };
            invoke::invoke(&mut k, slot, &msg)
        }

        fn lookup(&self, k: &Wired, cptr: u64) -> SlotAddr {
            match cspace::lookup_cap(k, self.root, cptr) {
                Ok(slot) => slot,
                Err(f) => fail(format_args!("CPtr {cptr:#x} does not resolve: {f:?}")),
            }
        }

        /// An invocation that must succeed.
        fn ok(&self, what: &str, invoked: u64, l: u64, mrs: &[u64], extra: &[u64]) {
            match self.call(invoked, l, mrs, extra) {
                Ok(_) => kprintln!("vspace: ok   {what}"),
                Err(e) => fail(format_args!("{what}: {e:?}")),
            }
        }

        /// An invocation that must fail with `e`.
        fn fails(
            &self,
            what: &str,
            invoked: u64,
            l: u64,
            mrs: &[u64],
            extra: &[u64],
            e: SyscallError,
        ) {
            match self.call(invoked, l, mrs, extra) {
                Err(InvokeError::Error(got)) if got == e => {
                    kprintln!("vspace: ok   {what}: {e:?}")
                }
                other => fail(format_args!("{what}: {other:?}, not {e:?}")),
            }
        }

        /// The capability in root slot `slot`.
        fn cap(&self, slot: u64) -> Cap {
            let k = wired();
            k.load(self.lookup(&k, slot)).cap
        }
    }

    /// What the tables CR3 holds translate `vaddr` to.
    fn walk(vaddr: u64) -> Option<Translation> {
        translate(&wired(), read_cr3() & ADDR_4K, vaddr)
    }

    /// A word of a frame the test holds a capability to.
    fn read_phys(paddr: u64) -> u64 {
        // SAFETY: the callers pass an 8-byte-aligned address inside a frame
        // retyped from a RAM untyped below the direct map's end, which the
        // direct map maps RW and write-back; no Rust reference to it exists.
        unsafe { ptr::read_volatile(phys_to_virt(paddr) as *const u64) }
    }

    /// Overwrites a word of a frame the test holds a capability to.
    fn write_phys(paddr: u64, word: u64) {
        // SAFETY: as in `read_phys`; the frame holds no kernel object.
        unsafe { ptr::write_volatile(phys_to_virt(paddr) as *mut u64, word) };
    }

    pub fn test_vspace(root: &RootSpace, bi: &l4core::bootinfo::BootInfo) -> ! {
        // The smallest RAM untyped that holds a 2 MiB frame and the rest.
        let Some((i, d)) = bi
            .untyped()
            .iter()
            .enumerate()
            .filter(|(_, d)| !d.device() && d.size_bits >= MIN_U_BITS)
            .min_by_key(|(_, d)| d.size_bits)
        else {
            fail(format_args!("no RAM untyped of 2^{MIN_U_BITS} bytes"))
        };
        let e = bi.empty.start;
        let s = Slots {
            root: wired().load(root.plan.layout.slot(ROOT)).cap,
            u: bi.untyped.start + i as u64,
            g: e,
            pml4: e + 1,
            pdpt: e + 2,
            pd: e + 3,
            pt: e + 4,
            f1: e + 5,
            f2: e + 6,
            pml4_copy: e + 7,
            f1_moved: e + 8,
        };
        kprintln!(
            "vspace: U is root slot {}: {} MiB of RAM at {:#x}; the test's slots start at {e}",
            s.u,
            d.size() >> 20,
            d.paddr
        );

        // Retype, through `invoke`, as the root task will.
        let retype = |what, ty: ObjectType, at: u64, n: u64| {
            let mrs = [ty as u64, 0, 0, 0, at, n];
            s.ok(what, s.u, invoke::label::UNTYPED_RETYPE, &mrs, &[ROOT]);
        };
        retype("U into a 2 MiB frame", ObjectType::Frame2M, s.g, 1);
        retype("U into a PML4", ObjectType::Pml4, s.pml4, 1);
        retype("U into a PDPT", ObjectType::Pdpt, s.pdpt, 1);
        retype(
            "U into a page directory",
            ObjectType::PageDirectory,
            s.pd,
            1,
        );
        retype("U into a page table", ObjectType::PageTable, s.pt, 1);
        retype("U into two 4 KiB frames", ObjectType::Frame4K, s.f1, 2);

        let pml4 = s.cap(s.pml4).object();
        let (kernel, kernel_entries) = kernel_pml4();
        let k = wired();
        let want = |i: usize| if i < 256 { 0 } else { kernel_entries[i] };
        check(
            (0..ENTRIES).all(|i| k.entry(pml4, i) == want(i) && k.backref(pml4, i) == 0),
            "the new PML4's entries 256 to 511 are the kernel PML4's, the rest zero",
        );

        // Map, at the top of the user range.
        let map = label::FRAME_MAP;
        let pml4_slot = [s.pml4];
        s.ok(
            "PDPT_Map at PML4 entry 255",
            s.pdpt,
            label::PDPT_MAP,
            &[F1_VA],
            &pml4_slot,
        );
        s.ok(
            "PageDirectory_Map",
            s.pd,
            label::PAGE_DIRECTORY_MAP,
            &[F1_VA],
            &pml4_slot,
        );
        s.ok(
            "PageTable_Map",
            s.pt,
            label::PAGE_TABLE_MAP,
            &[F1_VA],
            &pml4_slot,
        );
        s.ok(
            "Frame_Map of the highest 4 KiB page, read-write",
            s.f1,
            map,
            &[F1_VA, RW, WB],
            &pml4_slot,
        );
        s.fails(
            "Frame_Map of the page below the hole",
            s.f2,
            map,
            &[USER_TOP, RW, WB],
            &pml4_slot,
            SyscallError::InvalidArgument(0),
        );
        s.fails(
            "Frame_Map over a mapped page",
            s.f2,
            map,
            &[F1_VA, RW, WB],
            &pml4_slot,
            SyscallError::DeleteFirst,
        );
        let missing = SyscallError::FailedLookup {
            source: false,
            failure: LookupFailure::MissingCapability { bits_left: 39 },
        };
        s.fails(
            "Frame_Map with no PDPT",
            s.f2,
            map,
            &[0x1000, RW, WB],
            &pml4_slot,
            missing,
        );
        s.fails(
            "PageTable_Map of a mapped page table",
            s.pt,
            label::PAGE_TABLE_MAP,
            &[F1_VA],
            &pml4_slot,
            SyscallError::InvalidCapability(0),
        );
        s.ok(
            "Frame_Map of the page table's first page, read and execute",
            s.f2,
            map,
            &[F2_VA, R, X],
            &pml4_slot,
        );
        s.ok(
            "Frame_Map of the highest 2 MiB page",
            s.g,
            map,
            &[G_VA, RW, WB],
            &pml4_slot,
        );

        // Load it, and walk the tables CR3 holds.
        set_vm_root(s.cap(s.pml4));
        check(
            read_cr3() & ADDR_4K == pml4,
            "set_vm_root loaded the new PML4, and the kernel runs on its kernel half",
        );
        let (f1, f2, g) = (
            s.cap(s.f1).object(),
            s.cap(s.f2).object(),
            s.cap(s.g).object(),
        );
        let t1 = walk(F1_VA + 0x18);
        kprintln!("vspace: {F1_VA:#x} + 0x18 translates to {t1:x?}");
        check(
            t1.is_some_and(|t| {
                t.phys == f1 + 0x18
                    && t.page_size == PAGE_4K
                    && t.write
                    && t.user
                    && !t.execute
                    && !t.global
                    && t.cache == CacheType::WriteBack
            }),
            "the highest 4 KiB page maps its frame read-write, NX, user, not global, write-back",
        );
        check(
            walk(F2_VA).is_some_and(|t| t.phys == f2 && !t.write && t.execute && t.user),
            "the page table's first page maps its frame read-only and executable",
        );
        check(
            walk(G_VA + 0x12_3450).is_some_and(|t| {
                t.phys == g + 0x12_3450 && t.page_size == PAGE_2M && t.write && !t.execute
            }),
            "the highest 2 MiB page maps its frame with a 2 MiB leaf",
        );
        check(
            walk(F1_VA - PAGE_4K).is_none()
                && walk(0x1000).is_none()
                && walk(G_VA - PAGE_2M).is_none(),
            "nothing else in the lower half translates",
        );
        // The frame behind the user address, through the direct map.
        let p = t1.map_or(f1, |t| t.phys);
        write_phys(p, 0x5EED_0000_CAFE_F00D);
        check(
            read_phys(f1 + 0x18) == 0x5EED_0000_CAFE_F00D,
            "a write at the physical address the walk gives lands in the frame",
        );

        // Remap read-only; the `invlpg` runs.
        s.ok(
            "Frame_Remap read-only",
            s.f1,
            label::FRAME_REMAP,
            &[R, WB],
            &[],
        );
        check(
            walk(F1_VA).is_some_and(|t| !t.write && t.phys == f1),
            "the remapped page is read-only",
        );

        // Move the mapped capability; its back-reference follows.
        s.ok(
            "CNode_Move of the mapped 4 KiB frame",
            ROOT,
            invoke::label::CNODE_MOVE,
            &[s.f1_moved, 64, s.f1, 64],
            &[ROOT],
        );
        check(
            walk(F1_VA).is_some(),
            "the moved capability's page still translates",
        );
        s.ok(
            "Frame_Unmap through the moved capability",
            s.f1_moved,
            label::FRAME_UNMAP,
            &[],
            &[],
        );
        check(
            walk(F1_VA).is_none() && walk(F2_VA).is_some() && s.cap(s.f1_moved).data == 0,
            "the unmapped page no longer translates; the page table's first page does",
        );

        // Delete the page table: detach, empty, reload CR3.
        s.ok(
            "CNode_Delete of the mapped page table",
            ROOT,
            invoke::label::CNODE_DELETE,
            &[s.pt, 64],
            &[],
        );
        check(
            walk(F2_VA).is_none() && s.cap(s.f2).data == 0 && walk(G_VA).is_some(),
            "its frame is unmapped and no longer translates; the 2 MiB page still does",
        );

        // The PML4: a copy's deletion changes nothing; the last one's loads
        // the kernel PML4 first.
        s.ok(
            "CNode_Copy of the PML4",
            ROOT,
            invoke::label::CNODE_COPY,
            &[s.pml4_copy, 64, s.pml4, 64, RW],
            &[ROOT],
        );
        s.ok(
            "CNode_Delete of a PML4 capability, not the last",
            ROOT,
            invoke::label::CNODE_DELETE,
            &[s.pml4, 64],
            &[],
        );
        check(
            read_cr3() & ADDR_4K == pml4 && walk(G_VA).is_some(),
            "CR3 still holds the PML4, which still maps the 2 MiB page",
        );
        s.ok(
            "CNode_Delete of the loaded PML4's last capability",
            ROOT,
            invoke::label::CNODE_DELETE,
            &[s.pml4_copy, 64],
            &[],
        );
        check(
            read_cr3() & ADDR_4K == kernel && s.cap(s.pdpt).data == 0 && s.cap(s.pd).data != 0,
            "CR3 holds the kernel PML4; the PDPT is unmapped, the page directory keeps its entry",
        );
        set_vm_root(Cap::NULL);
        check(
            read_cr3() & ADDR_4K == kernel,
            "set_vm_root of no VSpace keeps the kernel PML4",
        );

        // Revoke U: every mapped capability left unmaps as it goes.
        s.ok(
            "CNode_Revoke of U",
            ROOT,
            invoke::label::CNODE_REVOKE,
            &[s.u, 64],
            &[],
        );
        let k = wired();
        check(
            (s.g..=s.f1_moved).all(|slot| k.load(root.plan.layout.slot(slot)).cap.is_null()),
            "every slot the test filled is empty",
        );
        kprintln!("TEST PASS");
        exit(ExitCode::Success)
    }
}
