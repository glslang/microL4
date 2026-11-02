# Status
Current milestone: M4 · Kernel objects and BootInfo, complete: the done-when test passes on QEMU, the fresh reviewer signed off, and the M4 red-team pass found nothing. Next: M5 · Threads, address spaces and the root task.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 · Paging and interrupts (PR #4, merged 2026-11-02): the kernel's own GDT, TSS, IDT and page tables, decoded ring-0 faults, the ACPI parser with QEMU and Hyper-V table dumps, the local APIC, PIC, I/O APIC and HPET set up, and a 100 Hz timer calibrated against the HPET or Hyper-V's reference counter. A fresh reviewer signed off.
- [x] The M3 Hyper-V check passed on the owner's host (2026-10-30): ten ticks at 100.002 Hz against the reference counter; the results are under "Hyper-V checks".
- [x] M4 · Kernel objects and BootInfo (PR #5): boot steps 6, 7 and 9 of `docs/design.md`, "Boot", and the first invocations.
  - **`l4core::bootinfo`:** the BootInfo ABI types of `docs/abi.md`, with an offset assert per field, the slot constants and `InterruptInfo::from_platform`.
  - **`l4core::boot`:** the boot region plan, the untyped computation and the slot plan, the BootInfo and root-CNode writers, and `boot::check`, the M4 invariants written apart from the planner.
    - Host tests on the recorded QEMU and Hyper-V maps (`core/tests/boot/`): 106 to 148 and 73 to 115 untyped of 448 for physical address widths 36 to 52, each plan compared descriptor by descriptor with a second implementation.
    - Proptest over generated maps, framebuffers, device pages and a reserved page where the boot region would go.
  - **`l4core::invoke`:** decodes and performs `Untyped_Retype` and the CNode methods Revoke, Delete, Copy, Mint, Move, Mutate and Rotate, with errors in `docs/abi.md`'s order.
    - Tests cover every error row, the depth limit through each path, restarts after preemption at every point, and random messages.
    - The M4 red-team pass (`core/src/invoke/redteam.rs`) checks every slot of fake memory after each call against the guarantees. 10,000 sequences of 150 calls from depth 0, and 10,000 from depth 4092, broke nothing.
  - **`l4core::objmem`:** the memory kernel objects may occupy, for the kernel's debug assertions.
  - **Kernel:**
    - the `debug` and `selftest` features, with every `test=` arm behind `selftest`;
    - `arch::Objects`, which implements `SlotMemory` and `Kernel` over the direct map, its hooks inert until M5;
    - the preemption poll on the IRR;
    - a preempted call restarted from the idle path through a resume hook, which M5's `schedule()` replaces;
    - steps 6, 7 and 9 on every boot, with the BootInfo summary in the boot log.
  - **Scenarios:**
    - `bootinfo` runs `boot::check` and checks every untyped against kernel memory found from the CPU's own tables, and against the cache types of the loaded direct map.
    - `retype` is the done-when test:
      - 27 invocations through `l4core::invoke` per run: U, the largest RAM untyped, retyped into every object type, then the CNode methods, a retyped child untyped, copies of root slots 9 and 2 in the new CNode, and three calls that must fail;
      - then a revoke of U, and the same 25 calls again;
      - both runs give the same slots, and the objects filled after the first run read zero after the second;
      - capabilities that do not come from U, placed in the test CNode, are deleted only by its Zombie;
      - after each revoke, every boot capability is a root without links and `cdt::check_slot` holds for every slot recorded;
      - calls are preempted by the timer (the test waits until it is pending, so the first reset's first poll always is) and by injected preemptions, and restarted from the idle path.
  - **Measured on QEMU TCG:** the steady-state stretch between preemption polls is under about 50 µs (mean 4.5 µs) with 4 KiB reset chunks. The first reset of never-touched RAM has stretches of up to about 60 ms, every 2 MiB: the host faulting guest RAM in on first touch.
- [x] The fresh M4 reviewer found no bug and signed off. It asked for:
  - a `retype` test that a broken Zombie would fail;
  - cache types checked against the live tables;
  - an ADR for the wider `framebuffer_untyped` rule.

  All three are done.
- [x] The M4 red-team pass found nothing; its tests stay as regression tests.

## Next
- [ ] M5 · Threads, address spaces and the root task:
  - steps 8 and 10:
    - `RootNeeds` with the TCB, PML4, paging structures and image frames;
    - the mapping records of the frame and paging capabilities `write_root_cnode` leaves unmapped;
    - `.rootimage` reclaimed;
  - keep BootInfo's physical address instead of `RootSpace`'s `&'static BootInfo` before the root task can write those frames;
  - fill the `arch::Objects` hooks: `finalise` for TCBs, Endpoints, Reply capabilities, Frames and paging structures; `init_object` for a PML4's kernel half and a TCB; `moved` for back-references;
  - replace the idle path's resume hook with `schedule()`, and decode `syscall` into `l4core::invoke` with capability lookups from the TCB's CSpace root;
  - let a `test=` name the kernel does not know go to the root task instead of failing;
  - the Hyper-V check at the end of M5.

## Open issues
- **Never run anywhere:** the x2APIC-to-xAPIC handover. Both firmwares hand over in xAPIC mode, so only a host test covers it.
- **From memory, never exercised:** the VP assist page's privilege gate (`AccessIntrCtrlRegs`, as KVM does) and the time-unhalted timer's enable bit 8. Both read as off on Hyper-V, so they were never written.
- **Hyper-V's I/O APIC is version `0x11`, with no EOI register.** M7's plan for a stale Remote IRR (write the old vector to the EOI register) does not work there; see `docs/design.md`, Open questions.
- **Toolchain drift:** CI runs Rust stable (1.99), and this session's default toolchain was 1.97. Run `cargo +1.99 xtask clippy` or newer before pushing, or pin the toolchain (ADR 0001 is the place to decide). On 1.99 a non-`.global` asm label read from Rust failed to link; every label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8, H11 (UMIP) in M5.
- A partial revoke, one whose work destroys a CNode on its slot's lookup path, ends where preemption falls, as in seL4: the restart fails its lookup and the work left stays undone. Delete finishes a Zombie it leaves in a slot the user can name, and a revoke of an ancestor untyped the rest; under a boot untyped that region is dead (`docs/design.md`, Slot operations). A Delete named through a path that runs through its own slot can be cut short the same way. The harness checks that a revoke cut short left a safe state, then runs the same revoke unpreempted from the same start: the leftover's memory and back-references must equal that run's at one of its preemption points, and its hook calls must be that run's up to there. Later steps go on from the unpreempted run's end.
- The model harness covers user operations on a Zombie only through hand-written tests. It no longer deletes the Zombies a revoke cut short leaves, so no random sequence does; `l4core`'s `a_revoke_restarted_by_looking_its_slot_up_again_is_cut_short` checks that such a Delete finishes the work.
- **Is 4 KiB the right reset chunk?** Answered on QEMU; Hyper-V is unmeasured. CI's `microl4-vhdx-m4-check` boots `test=retype`, which prints the longest stretch between polls.
- **Until M6:** `CNode_CancelBadgedSends` (`0x12`) and `CNode_SaveCaller` (`0x18`) return `IllegalOperation`.
- **A kernel without features** is only linted, never built into an image or booted; M7 adds that build and its scenario.
- **The kernel's `SlotAddr` debug check** tests only that a slot lies in object memory (`l4core::objmem`), which is weaker than core's invariant; M7 must add the IRQ node's static range to it.
- **No differential check against `model/`** of decoded invocation sequences; `l4core::invoke`'s own tests and the red-team harness cover them.
- **M5's boot region** rounds to whole pages, so the 2 KiB after the TCB is lost; seL4 turns such slack into small untyped.
- The optional `cargo-fuzz` target over the M2 sequences is not built.
- Accepted risks, recorded for the M10 red team:
  - Meltdown on a vulnerable host CPU (no skim window; ADR 0004);
  - IPC queue-cancel loops are not preemptible, as in seL4;
  - `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020).
- PLAN.md, exported from the plan doc, still shows pre-M1 proposals where ADRs supersede them: ADRs 0010, 0011, 0016 and 0023. Re-export it when the doc is next edited.

## Decisions this milestone
- **ADR 0024:** `framebuffer_untyped` is empty for any framebuffer the kernel cannot hand out whole: a write-back 2 MiB page, below 1 MiB or past `2^phys_addr_bits`, or overlapping memory no untyped may cover. `framebuffer` keeps the handoff's values. The layout is unchanged.
- **M4 has no root task.** The boot region holds the root CNode, the IPC buffer and BootInfo; slots 1, 3 and 12 to 14 are null, and the image fields and `ipc_buffer` are 0 (`docs/design.md`, Boot sequence).
- **Self-tests restart preempted calls as M5 will:**
  - the preemption point polls the IRR and never enables interrupts;
  - a preempted call goes back to the idle loop, which takes the interrupt;
  - a resume hook after `irq::handle` then decodes the call again from its unchanged arguments.
- **`debug` and `selftest`:** all test code builds only with `selftest`, which implies `debug`. xtask always enables `selftest` and lints the kernel both with it and with no features. `debug` gates nothing new until M7.
- **Decoder orders the ABI leaves open:**
  1. An empty or Zombie invoked slot is `InvalidCapability(0)` whatever the label.
  2. The label is checked before the length.
  3. `node_depth` 0 with a non-CNode root is `InvalidRoot`; seL4 gives `MissingCapability`.
  4. The source depth's `RangeError` comes after the destination's `DeleteFirst`.
  5. Rotate looks up the destination, then the source, then the pivot.

  All are in `docs/design.md`, System-call dispatch.
- **ISA routes in `InterruptInfo`:** an IRQ with a route keeps its `gsi` and `flags` even when no I/O APIC serves the GSI, and `routed` is then 0; all three are 0 when its GSI is another IRQ's override target.
- **Boot panics** on a memory map that is unsorted, overlapping or not 4 KiB granular, on `phys_addr_bits` outside 32 to 52, and on more than 448 untyped or 4096 slots, rather than drop memory.

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
- **M4:** no check is required. CI's `microl4-vhdx-m4-check` boots `test=retype`. Its log would show three things: the BootInfo summary (expected boot region `0x1ff00000-0x1ff23000` and 73 to 115 untyped), the retype record, and the longest stretch between preemption polls, which answers the 4 KiB question on Hyper-V.

## Last session
2026-11-02: M4.
- **Builders:** three worked in parallel worktrees:
  - BootInfo and the boot plan in `l4core`;
  - the invocation decoder;
  - the kernel plumbing: features, `arch::Objects`, the preemption restart, the boot facts.

  The kernel builder then wired steps 6, 7 and 9 and the two self-tests on top of the merge.
- **Docs:** a docs agent wrote the builders' notes into `docs/design.md`, `CLAUDE.md` and ADR 0003's status. The lead wrote ADR 0024 for the one change the notes made to `docs/abi.md`.
- **Review:** the fresh reviewer signed off with no must-fix finding. Its experiment showed that `retype` passed with CNode Zombies disabled; the test now fails that way. A red-team pass on the decoder found nothing.
- **Problems:** the red-team tests first failed Rust 1.99's clippy (`needless_late_init`), and the lead pushed before seeing it. It is fixed; check each command's exit status before pushing.
- **Next:** merge PR #5, then M5.
