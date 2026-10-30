# Status
Current milestone: M3 · Paging and interrupts. The code is built and passes on QEMU, and the fresh reviewer signed off on 2026-10-30. The done-when test's Hyper-V half, the timer rate on the owner's host, waits for the M3 Hyper-V check: boot CI's `microl4-vhdx-m3-check` artifact (`tools/hyperv/README.md`, "At the M3 check"). Tick M3 when that log passes. Next: M4 · Kernel objects and BootInfo, which needs M2 and M3.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 code (PR #4), the boot sequence of `docs/design.md`, "Boot":
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
- [x] An M2 bug found during M3, fixed in PR #4: a preempted revoke through two CNodes that held each other's only capability ended differently than an uninterrupted one. See "Decisions" below.

## Next
- [ ] The owner's M3 Hyper-V check: boot `microl4-vhdx-m3-check` with the README's command, and paste `m3-check.log` into PR #4. It must show:
  - SMEP, SMAP and XSAVE in `cpu: features`;
  - the `hyperv:` lines;
  - calibration against the reference counter;
  - `ticks: ... within 1%`.
  Record the `cpu: meltdown:` line below.
- [ ] From that log:
  - `cargo xtask acpidump --from-log m3-check.log --out core/tests/acpi/hyperv-gen2.dump`, plus a host test that COM1 is GSI 4 and there is no HPET;
  - close the Hyper-V open questions in `docs/design.md`: SMEP/SMAP/XSAVE, x2APIC handover, `PCAT_COMPAT`, PIC, PIT and HPET, the firmware leftovers, and the frequency MSRs;
  - fix anything the Hyper-V paths got wrong. They have never run: TCG ignores `hv-*` flags and never offers x2APIC.
- [ ] Tick M3, then start M4 · Kernel objects and BootInfo:
  - wire `l4core` into the kernel through `SlotMemory` and `Kernel` in `arch`;
  - make the BootInfo untyped from the memory map, keeping out `kernel_reserved`: the device-window pages, the MSI window, and `hyperv::Info.locked_hypercall_page`;
  - decode the CNode and Untyped invocations;
  - call `apic::interrupt_pending()` at preemption points;
  - put the stored calibration's `tsc_hz` in BootInfo;
  - add the retype, revoke and retype self-test.

## Open issues
- **Untested paths:** the Hyper-V and x2APIC-handover paths have never run, and the M3 Hyper-V check is their first test. From memory and still unchecked:
  - the VP assist page is gated on `AccessIntrCtrlRegs`, as KVM does;
  - the time-unhalted timer's enable bit is bit 8.
- **Toolchain drift:** CI runs Rust stable (1.99), and this session's default toolchain was 1.97. Run `cargo +1.99 xtask clippy` or newer before pushing, or pin the toolchain (ADR 0001 is the place to decide). On 1.99 a non-`.global` asm label read from Rust failed to link; every label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8, H11 (UMIP) in M5.
- A revoke that destroys the CNode holding its own slot stops part way, as seL4's does (M2; `docs/design.md`, Slot operations).
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
- **The M2 cycle fix departs from seL4 in one case.** Two CNodes C and D each hold the other's only capability. A deletion of C reaches D's capability and swaps D's Zombie into D's slot 0. seL4 goes on to clear D in the same call, which a restarted revoke could not resume. microL4 stops there and leaves D detached until a revoke of its untyped reaches it. The outcome is now the same whether or not the revoke is preempted (`docs/design.md`, Deletion and finalisation, and its seL4 table).
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
- **M3:** pending. The README lists the lines to record. The QEMU equivalents for comparison:
  - `cpu: meltdown: unknown`, since TCG reports no `IA32_ARCH_CAPABILITIES`;
  - xAPIC at handover (`0xfee00900`);
  - `PCAT_COMPAT` set, HPET present.

## Last session
2026-10-30: M3.
- **Setup:** the lead laid a skeleton first: the CPU check, `BootState`, the linker layout and guard pages, `qemu_args:`, the 64 GiB loader bound and the device-window layout.
- **Builders:** three worked in parallel worktrees on ACPI, page tables and traps, then a fourth on the interrupt controllers, HPET, Hyper-V and the timer. The lead merged them, added the stack-overflow scenario and the `stac` check, and applied every builder's design corrections through a docs agent.
- **Problems found along the way:**
  - The M2 model's random test found the preempted-revoke cycle bug; it is fixed.
  - CI's newer Rust exposed a non-global asm label and a new clippy lint; both are fixed.
  - Codex caught the ACPI reader stopping at 64 GiB instead of `phys_map_size`; it is fixed.
- **Review:** the fresh reviewer's one blocking item was the missing Hyper-V tick check, now CI's `microl4-vhdx-m3-check`. It signed off after the fixes.
- **Next:** the owner's Hyper-V check, then M4.
