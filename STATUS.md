# Status
Current milestone: M5 · Threads, address spaces and the root task. Its done-when test passes on QEMU, and both fresh reviewers signed off. The owner's Hyper-V check is still to run (`tools/hyperv/README.md`, "At the M5 check"). Next: M6 · IPC and notifications.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 · Paging and interrupts (PR #4, merged 2026-11-02): the kernel's own GDT, TSS, IDT and page tables, decoded ring-0 faults, the ACPI parser with QEMU and Hyper-V table dumps, the local APIC, PIC, I/O APIC and HPET set up, and a 100 Hz timer calibrated against the HPET or Hyper-V's reference counter. A fresh reviewer signed off.
- [x] The M3 Hyper-V check passed on the owner's host (2026-10-30): ten ticks at 100.002 Hz against the reference counter; the results are under "Hyper-V checks".
- [x] M4 · Kernel objects and BootInfo (PR #5, merged 2026-11-02): the boot plan, the untyped and BootInfo in `l4core::{bootinfo, boot}`, the Untyped and CNode decoder `l4core::invoke`, boot steps 6, 7 and 9, and the `bootinfo` and `retype` self-tests. A fresh reviewer signed off and a red-team pass on the decoder found nothing.
- [ ] M5 · Threads, address spaces and the root task (PR #6). QEMU done; the Hyper-V check remains.
  - **Threads** (`l4core::{tcb, regs, sched}`):
    - TCBs with the design's layout and states;
    - every TCB invocation, with errors in `docs/abi.md`'s order;
    - the user register set and `sanitise`;
    - fault messages and replies;
    - 256 ready queues, with round-robin and whole-tick charging.
    - A proptest checks the scheduler against 256 `VecDeque`s.
  - **Address spaces** (`l4core::vspace`):
    - paging objects with back-references checked both ways;
    - the map, unmap and remap invocations;
    - every change returns a `Flush`, which `arch::paging::apply` turns into `invlpg` or a CR3 reload.
    - A proptest with a TLB model catches every flush left out.
  - **Entry and exit** (`l4core::{abi, entry, fpu}`, `arch::{entry, fpu, thread}`):
    - `syscall` in, `sysretq` or `iretq` out, with `swapgs`;
    - `iretq` whenever registers were written or `next_ip` is at or above 2^47;
    - eager XSAVE64 and XRSTOR64 into each TCB;
    - XCR0 `0x3` and a 576-byte area;
    - `IA32_TSC_AUX` set to 0.
  - **IPC** (`l4core::{ipc, syscall}`):
    - endpoints with `Send`, `NBSend`, `Call`, `Recv`, `NBRecv`, `Reply` and `ReplyRecv`, without capability transfer (M6, ADR 0023);
    - reply capabilities;
    - fault delivery and replies;
    - `cancel_ipc` and `cancel_all_ipc`;
    - the system-call dispatch as one host-tested function per entry.
  - **The root task:**
    - `user/libsys` (system calls, invocations, allocators) and `user/root`;
    - xtask builds, strips and checks the root ELF and embeds it in `.rootimage`;
    - boot runs steps 6, 9, 7, 8 and 10: step 8 maps the root VSpace, copies the image, and reclaims `.rootimage` as untyped;
    - a `test=` name the kernel does not know goes to the root task.
  - **Scenarios** (36 in all):
    - `threads` and `fault`, the done-when;
    - `root`, `rootimage`, `vspace` and `ring3`, the paths in isolation;
    - `tlb`, which proves the flushes on the machine and fails without `invlpg` or the CR3 reload;
    - `isolation`, two preempted threads keeping their own FP state, bases, registers, DF and AC;
    - four red-team scenarios.
  - **`threads`:** A and B at priority 100 were each preempted 16 times by the 100 Hz timer with the other running in between.
  - **`fault`:**
    - F reads `0xdeadbee8`, and handler H receives the `VMFault` (ip, address, fsr `0x4`);
    - `DebugDumpScheduler` shows F `BlockedOnReply`;
    - H kills F with `TCB_Suspend`, and F stays stopped.
  - **ADR 0025:** user code may read the TSC; `IA32_TSC_AUX` reads 0.
  - **CI:** Miri runs in two shards. `microl4-vhdx-m5-check` holds six Hyper-V images.
- [x] Both fresh M5 reviewers signed off; reviewer K re-checked the fix round at 8cc6c74 and signed off again.
  - Reviewer C (core logic and ABI) and reviewer K (kernel and machine) each had one must-fix: `threads.scenario` expected A's first line before B's, which failed about half the runs; it no longer expects an order.
  - Their should-fixes are done:
    - `test=tlb`, after both found the flushes untested on the machine;
    - `test=isolation`;
    - scenario disk images deleted after a pass;
    - `IA32_TSC_AUX` set to 0;
    - exit warnings printed once per boot.
- [x] The M5 red-team pass found one probable denial of service: with TF set, `mov ss; int3` defers the single step into ring 0 at the `#BP` stub's first instruction (the CVE-2018-8897 mechanism), and the kernel panicked.
  - The kernel now returns from that `#DB` as it does at `syscall_entry` (`docs/redteam/m5-movss-db.md`).
  - QEMU raises the `#DB` in ring 3, so the finding and the fix are proven only on Hyper-V, by `redteam-movss`.
  - Everything else held: 80 exception probes from ring 3, every unmap path then a stale read, and threads deleting their own TCB or the memory under them.

## Next
- [ ] The M5 Hyper-V check: boot the six images of CI's `microl4-vhdx-m5-check` (`tools/hyperv/README.md`, "At the M5 check") and paste the logs into PR #6.
  - `threads` and `fault` are the done-when.
  - `ring3` shows TF at `syscall_entry`, `#XM` and UMIP.
  - `tlb` and `isolation` exercise a real TLB and XSAVE.
  - `redteam-movss` proves the deferred `#DB` fix: probe 1 should read `0x3/0x0`; a panic on probe 2 or 3 means the `int n` or `int1` variants are real after all.
- [ ] M6 · IPC and notifications:
  - capability transfer;
  - notifications and binding;
  - `CNode_SaveCaller` and `CNode_CancelBadgedSends`;
  - the IPC state-machine proptest against `model/`, which also covers M5's paths;
  - 1,000 ping-pong round trips timed with the TSC.

## Open issues
- **Never run anywhere:** the x2APIC-to-xAPIC handover. Both firmwares hand over in xAPIC mode, so only a host test covers it.
- **From memory, never exercised:** the VP assist page's privilege gate (`AccessIntrCtrlRegs`, as KVM does) and the time-unhalted timer's enable bit 8. Both read as off on Hyper-V, so they were never written.
- **Hyper-V's I/O APIC is version `0x11`, with no EOI register.** M7's plan for a stale Remote IRR (write the old vector to the EOI register) does not work there; see `docs/design.md`, Open questions.
- **Toolchain drift:** CI runs Rust stable (1.99), and this session's default toolchain was 1.97. Run `cargo +1.99 xtask clippy` or newer before pushing, or pin the toolchain (ADR 0001 is the place to decide). On 1.99 a non-`.global` asm label read from Rust failed to link; every label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8. UMIP (H11) was confirmed on QEMU in M5; Hyper-V's answer comes from `ring3` at the M5 check.
- A partial revoke, one whose work destroys a CNode on its slot's lookup path, ends where preemption falls, as in seL4: the restart fails its lookup and the work left stays undone. Delete finishes a Zombie it leaves in a slot the user can name, and a revoke of an ancestor untyped the rest; under a boot untyped that region is dead (`docs/design.md`, Slot operations). A Delete named through a path that runs through its own slot can be cut short the same way. The harness checks that a revoke cut short left a safe state, then runs the same revoke unpreempted from the same start: the leftover's memory and back-references must equal that run's at one of its preemption points, and its hook calls must be that run's up to there. Later steps go on from the unpreempted run's end.
- The model harness covers user operations on a Zombie only through hand-written tests. It no longer deletes the Zombies a revoke cut short leaves, so no random sequence does; `l4core`'s `a_revoke_restarted_by_looking_its_slot_up_again_is_cut_short` checks that such a Delete finishes the work.
- **Is 4 KiB the right reset chunk?** Answered on QEMU; Hyper-V is unmeasured. Build `cargo xtask image --cmdline "test=retype"` and boot it (`tools/hyperv/README.md`, the optional M4 check).
- **Until M6:**
  - `CNode_CancelBadgedSends` (`0x12`) and `CNode_SaveCaller` (`0x18`) return `IllegalOperation`;
  - `TCB_BindNotification` and `TCB_UnbindNotification` do too;
  - a Notification capability takes no invocation, and a receive on one is a capability fault.
- **A kernel without features** is only linted, never built into an image or booted; M7 adds that build and its scenario.
- **The kernel's `SlotAddr` debug check** tests only that a slot lies in object memory (`l4core::objmem`), which is weaker than core's invariant; M7 must add the IRQ node's static range to it.
- **No differential check against `model/`** of decoded invocation sequences; `l4core::invoke`'s own tests and the red-team harness cover them.
- **The boot region** rounds to whole pages, so the 2 KiB after the root TCB is lost; seL4 turns such slack into small untyped.
- **QEMU cannot show:**
  - the deferred `#DB` (`redteam-movss`);
  - `#XM` (QEMU TCG never raises it);
  - `int1` in ring 3 gives `#UD` on QEMU;
  - 11 of the `retfq`/`iretq` red-team probes stop at a SMAP `#PF` (error code 1) before the selector check, which looks like a QEMU bug.

  Hyper-V runs of `ring3` and `redteam-exceptions` settle these.
- **The scheduler state is a static** that kernel code reaches through one `arch::Objects` at a time; a second live `Objects` calling the scheduler would be unsound. Reviewer K checked that today's code holds to this; keep it so.
- **`Kernel::finalise` gets no slot:** a paging capability's slot is found through its back-reference and checked to hold exactly that capability, slightly weaker than the design's two-way check. Passing the slot is a small API change for later.
- **Debug kernels:** `DebugDumpScheduler` walks every TCB with no preemption point. Accepted, since debug kernels make no security claim (ADR 0021).
- **`test=redteam-tlb`** and `test=tlb` overlap; both stay, since they remove mappings in different orders.
- **Miri time:** CI's two shards take about 4 and 5 minutes against a 20-minute limit; add a shard before either nears it.
- The optional `cargo-fuzz` target over the M2 sequences is not built.
- Accepted risks, recorded for the M10 red team:
  - Meltdown on a vulnerable host CPU (no skim window; ADR 0004);
  - IPC queue-cancel loops are not preemptible, as in seL4;
  - `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020).
- PLAN.md, exported from the plan doc, still shows pre-M1 proposals where ADRs supersede them: ADRs 0010, 0011, 0016 and 0023. Re-export it when the doc is next edited.

## Decisions this milestone
- **ADR 0025:** user code may read the TSC with `rdtsc` and `rdtscp`. The kernel keeps CR4.TSD clear and sets `IA32_TSC_AUX` to 0.
- **Boot order is steps 6, 9, 7, 8, 10:**
  - the untyped are computed before step 8 reclaims `.rootimage`;
  - no untyped can be used before the root task runs, so this is safe;
  - the kernel keeps BootInfo's physical address, not a reference.
- **The root task:**
  - linked at `0x40_0000`;
  - its stack and thread stacks are separate segments with unmapped guard pages;
  - xtask strips it and runs the kernel's own image checks on it, so an image the kernel would refuse fails the build.
- **Restart after preemption:**
  - a preempted call leaves its caller `Restart` only if it is still `Running`, so a call that finalised its own caller is never restarted;
  - the pending interrupt is taken on the way back to ring 3.
- **The single-step `#DB`:** a ring-0 `#DB` is accepted only at `syscall_entry` and at the `#BP` stub's first instruction; any other panics.
- **`IpcEnv` extends `Threads`:** ADR 0018's "no method touches priorities" is now checked by host tests, not by the type.
- **Whole-tick charging, as seL4 (ADR 0013):** a tick that falls due while a thread is dispatched charges it a whole slice, so scenarios do not assume which equal-priority thread prints first.
- **Exits use `iretq`** when `next_ip` is at or above 2^47, as well as when registers were written.
- **CI:**
  - Miri on `l4core` runs in two shards;
  - the user crates' host tests and lints run in `cargo xtask test` and `cargo xtask clippy`;
  - a passing scenario's disk image is deleted.

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
- **M4:** no check was required. CI's `microl4-vhdx-m4-check` boots `test=retype`. Its log would show three things: the BootInfo summary (expected boot region `0x1ff00000-0x1ff23000` and 73 to 115 untyped), the retype record, and the longest stretch between preemption polls, which answers the 4 KiB question on Hyper-V.
- **M5:** not yet run. CI's `microl4-vhdx-m5-check` holds six images:
  - `threads` and `fault` (the done-when);
  - `ring3`, `tlb`, `isolation` and `redteam-movss`.

  `tools/hyperv/README.md`, "At the M5 check", has the loop and what each log must show.

## Last session
2026-11-02: M5.
- **Skeleton:** the lead wrote the TCB's register frame and layout offsets first.
- **Phase 1**, four builders in parallel worktrees:
  - threads, registers and the scheduler;
  - address spaces;
  - entry, exit and FP;
  - the user side and the root image.
- **Phase 2:**
  - builder I wrote endpoint IPC, fault delivery and the dispatch in `l4core`;
  - builder E integrated the kernel, and the root task booted in ring 3;
  - builder R wrote the done-when tests in `user/root`;
  - builder I then plugged its dispatch in and ran both done-when scenarios five times each.
- **Docs:** a docs agent wrote the builders' notes into `docs/design.md`, `CLAUDE.md`, `docs/boot.md` and ADR 0018's status.
- **Review and red team:** two fresh reviewers (kernel and core) and a red teamer found the issues above, and a fix round closed them.
- **Problems:**
  - the skeleton's `Exit` made a zeroed TCB leave by `sysretq` (fixed: `Iret` is 0);
  - Codex caught the temporary dispatch restarting a self-deleted caller (gone with the real dispatch, and host-tested);
  - the shared disk filled twice, from builders' `target/` directories and kept scenario images;
  - Miri approached CI's 20-minute limit (now two shards).
- **Next:** the owner's M5 Hyper-V check, then merge PR #6, then M6.
