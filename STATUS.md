# Status
Current milestone: M3 · Paging and interrupts, complete: the done-when test passed on QEMU and on the owner's Hyper-V host (2026-10-30), and the fresh reviewer signed off. Next: M4 · Kernel objects and BootInfo.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 · Paging and interrupts (PR #4), the boot sequence of `docs/design.md`, "Boot":
  - **CPU check:** `l4core::cpu`, `arch::check_cpu`. The kernel refuses to boot without NX, PGE, PAT, SMEP, SMAP and XSAVE, with one `CPU lacks` line (`cpu_refuse` boots `-cpu qemu64`). The boot summary prints the features, CR0, CR4, EFER, `IA32_APIC_BASE` and the Meltdown line.
  - **`BootState`:** the handoff and memory map are copied out of loader memory after the ADR 0006 bounds check. The loader allocates below 64 GiB.
  - **Descriptor tables and traps:** `l4core::trap`, `arch::{gdt,idt,trap,irq}`.
    - The GDT, TSS, IDT and a null LDT; one stub per vector, each running `clac` and `cld` first; IST stacks for #DF, NMI, #MC and #DB.
    - Ring-0 faults panic with a decoded report: vector, error code, CR2, RIP, RSP, every register, and which stack the frame is on.
    - The idle loop takes interrupts.
    - #DF's report uses 1,872 of the 8,192 bytes on IST1.
  - **Page tables:** `l4core::vspace`, `arch::paging`.
    - A direct map of at most 64 GiB in 2 MiB pages: write-back over RAM, uncached elsewhere and over kernel device pages.
    - The image in 4 KiB pages, never writable and executable at once through any alias.
    - The uncached device window; PAT, SMEP, SMAP, PGE and UMIP on, PCIDE and FSGSBASE off.
    - A guard page under every stack; the loader's 1:1 map is gone.
  - **ACPI:** `l4core::acpi` parses and validates the RSDP, XSDT, MADT, HPET and MCFG.
    - Tested on QEMU's dumped tables, corrupted copies, edge cases and random bytes, under Miri too.
    - The loader dumps the tables on `acpidump`, and `cargo xtask acpidump` turns a boot or a COM1 log into a test file.
  - **Interrupt controllers and the timer:** `l4core::{hyperv,apic,hpet,timer,calibration}`, `arch::{hyperv,apic,pic,ioapic,hpet,timer}`.
    - Hyper-V detection and its firmware leftovers turned off.
    - The 8259 remapped and masked, the local APIC set up, every I/O APIC pin masked, the HPET cleaned up.
    - Calibration against the Hyper-V reference counter or the HPET: QEMU's APIC clock comes out within about 30 ppm of 1 GHz.
    - The LAPIC timer runs at 100 Hz on vector `0xFD`: ten ticks take 100 ms within 0.02% on QEMU.
  - **Scenarios:** 22, covering the boot summary, eleven traps, page and double faults, overflows of the kernel, NMI and #DF stacks, the empty lower half, ACPI and its dump, ten ticks, and `hpet=off`.
  - **Source check:** `cargo xtask test` fails if the kernel source contains `stac`.
- [x] A fresh M3 reviewer found no kernel bug. It asked for the Hyper-V check image, a null LDT, PCIDE cleared, and a correction to the #DF-stack overflow text. All of these are done, and it signed off.
- [x] The M3 Hyper-V check passed on the owner's host (2026-10-30, CI's `microl4-vhdx-m3-check`): ten ticks at 100.002 Hz against the reference counter and `TEST PASS`; the results are under "Hyper-V checks".
  - Its ACPI tables are host-tested as `core/tests/acpi/hyperv-gen2.dump`, without the 123 KB DSDT the parser never reads. The test checks no HPET, no MCFG, one I/O APIC with ID 1, only the IRQ 9 override, COM1 on GSI 4, and ISA IRQ 0 on GSI 0, unlike q35. The corrupted-copy test covers these tables too.
- [x] An M2 bug found during M3, fixed in PR #4: a revoke whose own slot its work destroyed ended differently depending on where preemption fell. The first shape seen was two CNodes holding each other's only capability. See "Decisions" below.

## Next
- [ ] M4 · Kernel objects and BootInfo:
  - wire `l4core` into the kernel through `SlotMemory` and `Kernel` in `arch`;
  - make the BootInfo untyped from the memory map, keeping out `kernel_reserved`: the device-window pages, the MSI window, and `hyperv::Info.locked_hypercall_page`;
  - decode the CNode and Untyped invocations;
  - call `apic::interrupt_pending()` at preemption points;
  - put the stored calibration's `tsc_hz` in BootInfo;
  - add the retype, revoke and retype self-test.

## Open issues
- **Never run anywhere:** the x2APIC-to-xAPIC handover. Both firmwares hand over in xAPIC mode, so only a host test covers it.
- **From memory, never exercised:** the VP assist page's privilege gate (`AccessIntrCtrlRegs`, as KVM does) and the time-unhalted timer's enable bit 8. Both read as off on Hyper-V, so they were never written.
- **Hyper-V's I/O APIC is version `0x11`, with no EOI register.** M7's plan for a stale Remote IRR (write the old vector to the EOI register) does not work there; see `docs/design.md`, Open questions.
- **Toolchain drift:** CI runs Rust stable (1.99), and this session's default toolchain was 1.97. Run `cargo +1.99 xtask clippy` or newer before pushing, or pin the toolchain (ADR 0001 is the place to decide). On 1.99 a non-`.global` asm label read from Rust failed to link; every label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8, H11 (UMIP) in M5.
- A revoke that destroys the CNode holding its own slot stops after that step, whether or not it is preempted. Under a boot untyped, a Zombie left in the CNode's own slot 0 is never finished; that region is dead anyway (`docs/design.md`, Slot operations).
- The model harness covers user operations on a Zombie only through hand-written tests.
- `Kernel::finalise` runs with `last = true` for every deletion of an Untyped, IRQControl, IOPortControl or Hypervisor capability; the kernel's hook must ignore those (M4).
- The optional `cargo-fuzz` target over the M2 sequences is not built.
- Accepted risks, recorded for the M10 red team:
  - Meltdown on a vulnerable host CPU (no skim window; ADR 0004);
  - IPC queue-cancel loops are not preemptible, as in seL4;
  - `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020).
- PLAN.md, exported from the plan doc, still shows pre-M1 proposals where ADRs supersede them: ADRs 0010, 0011, 0016 and 0023. Re-export it when the doc is next edited.

## Decisions this milestone
- No new ADR: M3 follows `docs/design.md` and ADRs 0004 to 0008, 0014, 0019 and 0020, and `docs/abi.md` is unchanged.
- **A revoke that destroys its own slot stops after that step, preempted or not; this departs from seL4.** seL4 goes on with the deletion unless preempted. A restart cannot find the rest of that work, so seL4's outcome depends on where the interrupt falls.
  - In microL4 the half-cleared container's Zombie stays where its last capability was, or in its own slot 0, and Delete or a revoke of its untyped's parent finishes it. Delete itself is unchanged from seL4.
  - The model's random test found two shapes of this bug in turn: the cycle, then a CNode holding a copy of itself.
  - The fix replaces the first, cycle-only special case with one general rule, checked over 1.6 million random cases (`docs/design.md`, Slot operations, Deletion and finalisation, and its seL4 table).
- **The boot-sequence order** is now written in `docs/design.md`:
  - EFER.NXE and CR0.WP are checked before the PAT is written;
  - Hyper-V's leftovers come first in step 5, since its time-unhalted timer can raise an NMI;
  - LINT0 is masked before the PIC is reprogrammed;
  - in-service vectors the firmware left are acknowledged.
- **Calibration:** each reference read is bracketed by LAPIC and TSC reads. The ten-tick test dates each tick by the timer's reload, so the host's delivery delay under TCG does not count.
- **The kernel enforces CPU state itself** where the design states it, rather than trusting the firmware: a null LDT, and CR4.PCIDE and FSGSBASE cleared.
- **ACPI duplicates:** two MADT or HPET tables at different addresses are a panic; the same address listed twice is a warning. Unusable entries are skipped with warnings, as `docs/design.md` lists.
- **Limits:** at most 24 HPET comparators and 120 I/O APIC pins.
- **Kernel leaves have Accessed and Dirty set in advance**, so the CPU never writes the kernel's page tables.
- **CI uploads a second VHDX for the M3 Hyper-V check.** It boots `acpidump test=ticks`, so the owner needs no Linux machine to dump the tables.

## Hyper-V checks
- **M0 VHDX** (7c4609f, 2026-10-29): boots with Secure Boot off; hello and `TEST PASS` on COM1 through the named pipe.
  - CPUID signature `Microsoft Hv`.
  - GOP framebuffer 1024x768 BGR at `0xF8000000`, stride 1024.
  - RSDP at `0x1FFFA014`.
  - 10 memory regions, 509 MiB usable of 512 MiB; RAM ends at `0x20000000`, so the direct map is the 4 GiB minimum; no MMIO ranges in the map.
- **M3 VHDX** (`microl4-vhdx-m3-check`, 2026-10-30): boots to `TEST PASS`; ten ticks reload over 99,998 µs, 100.002 Hz, against the reference counter.
  - `cpu: meltdown: not vulnerable`. SMEP, SMAP and XSAVE are passed through: the boot got past `check_cpu`.
  - `IA32_APIC_BASE` `0xfee00900`: xAPIC at handover, though CPUID offers x2APIC. LAPIC version `0x50014`, 6 LVTs.
  - TLFS `Hv#1`, highest leaf `0x4000000b`; privileges EAX `0xae7f`, EBX `0x3b8030`; features EDX `0xe0bed7b2`.
  - Firmware leftovers: only SCONTROL was on (`0x1`), now off. Everything else was off, no SINT was unmasked, and the hypercall MSR read `0x0`, so it was not locked.
  - Calibration: LAPIC 200,001,000 Hz, 5 ppm from the APIC frequency MSR (200 MHz); TSC 2,112,120,929 Hz, 57 ppm from its MSR.
  - ACPI: RSDP revision 2 at `0x1fffa014`, XSDT; tables FACP, OEM0, WAET, APIC, SRAT and BGRT; no HPET and no MCFG. MADT flags 0, so no `PCAT_COMPAT` and the 8259s are left alone. One I/O APIC, ID 1 at `0xfec00000`, version `0x11`, 24 pins. Only override: IRQ 9 to GSI 9, level, active high. COM1 on GSI 4, edge, active high.
  - Paging: the direct map covers 4 GiB, 256 WB and 1792 UC 2 MiB pages; the device window holds 2 pages (no HPET).
  - `Test-L4Vhdx.ps1` reported FAIL only because the owner ran it with its defaults, which then expected `cmdline: "test=hello"`. The defaults now hold only the lines every image prints.

## Last session
2026-10-30: M3.
- **Setup:** the lead laid a skeleton first: the CPU check, `BootState`, the linker layout and guard pages, `qemu_args:`, the 64 GiB loader bound and the device-window layout.
- **Builders:** three worked in parallel worktrees on ACPI, page tables and traps, then a fourth on the interrupt controllers, HPET, Hyper-V and the timer. The lead merged them, added the stack-overflow scenario and the `stac` check, and applied every builder's design corrections through a docs agent.
- **Problems found along the way:**
  - The M2 model's random test found the preempted-revoke cycle bug; it is fixed.
  - CI's newer Rust exposed a non-global asm label and a new clippy lint; both are fixed.
  - Codex caught the ACPI reader stopping at 64 GiB instead of `phys_map_size`; it is fixed.
- **Review:** the fresh reviewer's one blocking item was the missing Hyper-V tick check, now CI's `microl4-vhdx-m3-check`. It signed off after the fixes.
- **Hyper-V:** the owner ran the M3 check that evening and it passed. Its results are recorded above and in `docs/design.md`'s answered open questions. One new problem for M7: Hyper-V's I/O APIC has no EOI register.
- **Next:** the Hyper-V ACPI dump from the full log, then M4.
