# Status
Current milestone: M7 · User-level drivers and console, complete: the done-when scenarios pass on QEMU, both fresh reviewers signed off and a third re-checked the fix round, and the red team's two low findings are fixed. M7 has no Hyper-V check. Next: M8 · Framebuffer, terminal emulator and TUI.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 · Paging and interrupts (PR #4, merged 2026-11-02): the kernel's own GDT, TSS, IDT and page tables, decoded ring-0 faults, the ACPI parser with QEMU and Hyper-V table dumps, the local APIC, PIC, I/O APIC and HPET set up, and a 100 Hz timer calibrated against the HPET or Hyper-V's reference counter. A fresh reviewer signed off.
- [x] The M3 Hyper-V check passed on the owner's host (2026-10-30): ten ticks at 100.002 Hz against the reference counter; the results are under "Hyper-V checks".
- [x] M4 · Kernel objects and BootInfo (PR #5, merged 2026-11-02): the boot plan, the untyped and BootInfo in `l4core::{bootinfo, boot}`, the Untyped and CNode decoder `l4core::invoke`, boot steps 6, 7 and 9, and the `bootinfo` and `retype` self-tests. A fresh reviewer signed off and a red-team pass on the decoder found nothing.
- [x] M5 · Threads, address spaces and the root task (PR #6, merged 2026-11-22): TCBs and every TCB invocation, the scheduler, the paging objects with their flushes, `syscall`/`sysretq`/`iretq` entry and exit with eager XSAVE, endpoint IPC with reply capabilities and fault delivery, the system-call dispatch in `l4core`, and the root task (`user/libsys`, `user/root`) in ring 3. The done-when passed on QEMU and on Hyper-V; two fresh reviewers signed off; the red team's `mov ss` deferred-`#DB` denial of service is fixed and confirmed on Hyper-V (`docs/redteam/m5-movss-db.md`). `docs/design.md` has the details.
- [x] M6 · IPC and notifications (PR #7, merged 2026-11-22): notifications and binding, capability transfer, `CNode_SaveCaller` and `CNode_CancelBadgedSends` in `l4core::ipc`, the IPC reference model in `model/` (20,000 random cases, 70 scenarios), and the `pingpong`, `captransfer`, `badge` and `ipcntfn` scenarios. Two fresh reviewers signed off, a third re-checked the fix round, and the red team found nothing; `docs/design.md` has the details.
- [x] M7 · User-level drivers and console (PR #8). Done on QEMU.
  - **Spec check first:** a fresh agent checked the interrupt, I/O port and release-kernel design against seL4 (ADR 0027), and a designer wrote "User-level drivers and console", checked by a second fresh agent (ADR 0028).
  - **Kernel** (`l4core::{irq, ioport}`, `arch::{ioapic, irq, io}`): IRQControl (`GetISA`, `GetIOAPIC`), IRQHandler (`Ack`, `SetNotification`, `Clear`) and interrupt delivery through `ipc::signal`, with the level and edge masking rules; IOPortControl and IOPort with ranges, reserved ports and `In`/`Out` of 8, 16 and 32 bits; deletion of each; the stale Remote IRR cleared on issue on I/O APIC versions `0x20` (EOI register) and `0x11` (trigger toggle).
  - **The release kernel:** built without `debug`, no UART code; `cargo xtask test` disassembles it and fails on any `in` or `out` outside `io.rs`, a COM1 port loaded or passed, an `io.rs` function called from anywhere but its three callers, the IOPort executor called from anywhere but `invoke_port::<Objects>`, either's address used other than as a branch target, or a `serial` symbol; `PortAccess` makes the executor uncallable from other kernel code at compile time.
  - **User side:** `uart` (16550, interrupt-driven both ways, wait, Ack, service) and `console` (several clients, whole lines, line editing, focus by Ctrl-T and a digit, control bytes shown, not sent) in their own CSpaces and VSpaces; `watch` ends a run with a failure line if a server faults; libsys's protocols, clients and output sinks.
  - **Harness:** `send:`, `kernel: release`, `forbid:`, `next:`, `exit: timeout`; `send:` input is capped at 4 KiB.
  - **Scenarios** (49): `console` (two clients' interleaved lines, typed input reaching the right client, type-ahead, a drain proving nothing else reached any client), `release` (the release kernel prints nothing; all output from `uart`; exits through `isa-debug-exit`), `release_fault`, `ioport`, `irq`, `irq_stale` on versions `0x20` and `0x11`, and the red team's `redteam-irq`.
- [x] Both fresh M7 reviewers signed off with no must-fix finding: reviewer C (core and kernel) caught all 16 compiling mutations of `l4core::{irq, ioport}` with the host tests; reviewer U (user side, harness, done-when) added the type-ahead step and `release_fault`. Two fix rounds closed their should-fixes and the red team's findings, and a fresh reviewer re-checked both and signed off. Its first look found the IOPort executor callable from anywhere in the kernel; it now takes a `PortAccess` token only `l4core::ioport::invoke_port` can build, and the disassembly check allows calls to it only from `invoke_port::<Objects>`.
- [x] The M7 red-team pass found nothing in the kernel (an 18.6 kHz PIT storm, pin stealing, 300 issue and delete cycles, revoked and nested deletions held, `test=redteam-irq`) and two low findings, both fixed: `console` passed clients' escape sequences to the terminal (`docs/redteam/m7-console-escapes.md`), and the disassembly check missed a computed COM1 port (`docs/redteam/m7-disasm-computed-port.md`).
- [x] Codex found a real `console` bug (a Read answered from type-ahead could have its reply overwritten by queued output; fixed in 266fa62 and covered by `test=console`) and a failure path that could hang (answered by `watch`).

## Next
- [ ] M8 · Framebuffer, terminal emulator and TUI (PLAN.md), with a Hyper-V check. `console`'s raw mode (`0x125`) is reserved for the terminal; M8's Hyper-V check also covers the 16550 there (FIFOs, character timeout, no client on the pipe).

## Open issues
- **Never run anywhere:** the x2APIC-to-xAPIC handover. Both firmwares hand over in xAPIC mode, so only a host test covers it.
- **From memory, never exercised:** the VP assist page's privilege gate (`AccessIntrCtrlRegs`, as KVM does) and the time-unhalted timer's enable bit 8. Both read as off on Hyper-V, so they were never written.
- **Hyper-V's I/O APIC is version `0x11`, with no EOI register:** ADR 0027 clears a stale Remote IRR there by toggling the entry to edge and back while masked; `irq_stale_0x11` runs that path on QEMU (`ioapic.version=0x11`), but no driver uses a level pin on Hyper-V yet, so it is unchecked there.
- **Toolchain drift:** CI runs Rust stable, 1.100 on 2026-11-22, while this container's default is 1.97. Each new stable has brought clippy lints the older ones miss: 1.99 `chunks_exact_to_as_chunks` and `needless_late_init`, 1.100 `needless_range_loop` on four range loops. Install the current stable (`rustup toolchain install <version> --profile minimal -c clippy`) and run `cargo +<version> xtask clippy` before pushing, or pin the toolchain (ADR 0001 is the place to decide). Every asm label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8. UMIP (H11) is confirmed on QEMU and on Hyper-V.
- A partial revoke, one whose work destroys a CNode on its slot's lookup path, ends where preemption falls, as in seL4: the restart fails its lookup and the work left stays undone. Delete finishes a Zombie it leaves in a slot the user can name, and a revoke of an ancestor untyped the rest; under a boot untyped that region is dead (`docs/design.md`, Slot operations). A Delete named through a path that runs through its own slot can be cut short the same way. The harness checks that a revoke cut short left a safe state, then runs the same revoke unpreempted from the same start: the leftover's memory and back-references must equal that run's at one of its preemption points, and its hook calls must be that run's up to there. Later steps go on from the unpreempted run's end.
- The model harness covers user operations on a Zombie only through hand-written tests. It no longer deletes the Zombies a revoke cut short leaves, so no random sequence does; `l4core`'s `a_revoke_restarted_by_looking_its_slot_up_again_is_cut_short` checks that such a Delete finishes the work.
- **Is 4 KiB the right reset chunk?** Answered on QEMU; Hyper-V is unmeasured. Build `cargo xtask image --cmdline "test=retype"` and boot it (`tools/hyperv/README.md`, the optional M4 check).
- **No differential check against `model/`** of decoded invocation sequences; `l4core::invoke`'s own tests and the red-team harness cover them.
- **The boot region** rounds to whole pages, so the 2 KiB after the root TCB is lost; seL4 turns such slack into small untyped.
- **Still unchecked on hardware:** 11 of the `retfq`/`iretq` red-team probes stop at a SMAP `#PF` (error code 1) on QEMU before the selector check, which looks like a QEMU bug; booting `test=redteam-exceptions` on Hyper-V would settle it. `int1` in ring 0 gives `#UD` on QEMU (M10 brief 5).
- **The scheduler state is a static** that kernel code reaches through one `arch::Objects` at a time; a second live `Objects` calling the scheduler would be unsound. Reviewer K checked that today's code holds to this; keep it so.
- **`Kernel::finalise` gets no slot:** a paging capability's slot is found through its back-reference and checked to hold exactly that capability, slightly weaker than the design's two-way check. Passing the slot is a small API change for later.
- **Debug kernels:** `DebugDumpScheduler` walks every TCB with no preemption point. Accepted, since debug kernels make no security claim (ADR 0021).
- **`test=redteam-tlb`** and `test=tlb` overlap; both stay, since they remove mappings in different orders.
- **Miri time:** M6 added about 2 minutes to the `ipc:: syscall:: tcb:: sched:: regs:: vspace::` shard; CI's whole run, both shards included, took about 6.5 minutes on 2026-11-22 against a 20-minute limit per job. Add a shard before either nears it. The model's tests and the red team's fuzzer are skipped under Miri.
- The optional `cargo-fuzz` target over the M2 sequences is not built.
- Accepted risks, recorded for the M10 red team:
  - Meltdown on a vulnerable host CPU (no skim window; ADR 0004);
  - IPC queue-cancel loops are not preemptible, as in seL4;
  - `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020).
- PLAN.md, exported from the plan doc, still shows pre-M1 proposals where ADRs supersede them: ADRs 0010, 0011, 0016 and 0023. Re-export it when the doc is next edited.
- **The IPC model's limits:** it never sends an untyped (so `derive` refusing an untyped with children is uncovered there), and it does not model derivation depth or revoke; `l4core`'s host tests and `test=captransfer` cover those. Only some random worlds give threads a second CSpace root; that CNode holds no TCB capability, and neither CNode's own capability (slot 1) is ever deleted.
- **Released threads' order differs from seL4:** `cancel_all_ipc`, `cancel_all_signals` and `cancel_badged_sends` make released threads runnable in queue order, so the first to wait runs first; seL4 enqueues each at the head of its ready queue (`docs/design.md`, IPC and Notifications, "Compared with seL4").
- **Bind-time delivery** of a pending signal differs from seL4 and is justified only in `docs/design.md`'s comparison table; it was in `docs/abi.md` from M1, so no ADR.
- **No "is this slot empty" query:** the ABI has no non-destructive way to ask; `test=captransfer` moves a slot onto itself (`DeleteFirst` if full, `FailedLookup` if empty), relying on the documented error order.
- **`ipc::signal` calls `ipc::cancel_ipc` directly,** while binding goes through the `Threads::cancel_ipc` hook; M7's interrupt delivery kept it on `IpcEnv`. Small.
- **Two M6 invariant rows rest on the code's structure only:** the queue-cancel loops have no preemption point, and every IPC call finishes in one kernel entry; M10 briefs 6 and 9 test them.
- **QEMU 8.2 drops an edge that arrives on a masked I/O APIC pin** (`test=irq`); ADR 0028's wait, Ack, service loop loses nothing either way.
- **`uart` on Hyper-V is unchecked:** its 16550 (FIFOs, character timeout, a pipe with no client) is left to the M8 Hyper-V check. On QEMU `uart` never holds a `Write` (QEMU transmits at once), so held writes are tested only on the host.
- **Each server costs 101 of root's slots** and about 107 KiB with the 118-frame root image; it grows with the image.
- **The disassembly check's allowed callers** are matched by exact demangled names (`port_in`, `port_out`, `pic::init`, `arch::exit`); a rename or an LLVM clone under a new name fails the check loudly.
- **A `console` client can print a plain line that looks like a status line;** it can no longer erase or overwrite the real one.
- **Ports from memory:** QEMU's `fw_cfg` (`0x510`-`0x51B`, DMA at `0x514` can write any memory) is flagged like `0xCF8`, not reserved; ICH chipsets alias the PIC at `0x24`-`0x3D` and `0xA4`-`0xBD` (not on QEMU or Hyper-V). The PIT is not kernel-reserved.
- **Kernel code that forges a capability in a real slot** (for example with the safe `SlotMemory::store`) could still reach COM1 through `invoke_port` and pass the disassembly check; `next:` catches it if it prints at boot. Accepted: such a forgery breaks every capability guarantee at once (`docs/redteam/m7-disasm-computed-port.md`).
- **Miri in CI runs on `l4core` only;** the user crates' host tests ran under Miri locally in M7.

## Decisions this milestone
- **ADR 0027:** issuing an I/O APIC pin masks it and clears a stale Remote IRR (EOI register from version `0x20`, a trigger toggle below), or fails with `RevokeFirst`.
- **ADR 0028:** a driver of an edge pin loops wait, Ack, service; a level pin's driver wait, service, Ack. The kernel did not change.
- **`uart` and `console` run in their own CSpaces and VSpaces** (text and read-only data shared read-only from root's image), as host-tested library crates linked into `root`; priorities root 255, `watch` 255, `uart` 200, `console` 150, clients 100.
- **`console`:** whole lines up to 512 bytes per client; focus by Ctrl-T and a digit; a client's control bytes are shown (`^[`, `\xNN`), never sent; raw mode `0x125` reserved for M8.
- **`watch`** is the servers' fault handler and ends a run through COM1 polling and the exit port, so a server fault never hangs a scenario.
- **The release kernel** is detected by root from its `test=` name, not a BootInfo bit; it ends QEMU runs through `isa-debug-exit` (`0xF4`).
- **The disassembly check** uses rustup's `llvm-objdump` (`llvm-tools`), and checks callers and address uses, not only port values; the IOPort executor takes a `PortAccess` token only `l4core::ioport` builds.
- **Harness directives:** `send:` (4 KiB cap), `kernel: release`, `forbid:`, `next:`, `exit: timeout`; `qemu_args:` gives QEMU options.
- **History stays linear:** builders' branches were cherry-picked or rebased, never merged.

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
- **M5** (CI's `microl4-vhdx-m5-check`, 2026-11-22): all six images reached `TEST PASS`, with no panic.
  - Boot: `cpu: features NX PGE PAT SMEP SMAP XSAVE UMIP`; physical address width 46 bits; 83 untyped (521,416 KiB of RAM), inside the 73 to 115 the host tests predicted; boot region `0x1fee0000-0x1ff40000`; the framebuffer as one device untyped.
  - Entry and FP: the same `IA32_STAR` and `IA32_FMASK` as on QEMU; `IA32_TSC_AUX 0x0`; XCR0 `0x3` of `0x7` supported, a 576-byte XSAVE area; CR4 `0x340ee8`, EFER `0xd01`.
  - `threads`: A and B each preempted 16 times with the other running in between; lines ABABABABABABABAB.
  - `fault`: the `VMFault` at `0xdeadbee8` (ip `0x400010`, fsr `0x4`) reached handler H; F was blocked, H killed it with `TCB_Suspend`, and F stayed stopped.
  - `ring3`: `#XM` raised (step 9) and MXCSR `0x1d84` with ZE set (step 10); a `syscall` with TF set took no ring-0 `#DB` (step 12); `sgdt` under UMIP took `#GP` (step 22).
  - `tlb`: every phase faulted after `Frame_Remap`, `Frame_Unmap` and `PageTable_Unmap`, and restarted once mapped again.
  - `isolation`: check 0 for both threads and the root task.
  - `redteam-movss`: probe 1 `0x3/0x0` (the deferred step reached ring 0 and the kernel returned), probe 2 `0xd/0x402`, probe 3 `0x1/0x0`.

## Last session
2026-11-22: M7, in the same session as M6 (PR #7 merged by rebase as 22 linear commits).
- **Design:** a spec check of the interrupt and I/O port design against seL4 (ADR 0027) and a designer's note for `uart` and `console`, itself checked by a fresh agent (ADR 0028, the `watch` thread).
- **Builders**, in parallel worktrees: K (IRQ and I/O port objects and delivery), R (harness directives, the release kernel and its disassembly check), U (`uart`, `console`, libsys and the done-when scenarios).
- **Review and red team:** two fresh reviewers signed off; the red team found two low gaps; two fix rounds closed everything, the second after a fresh re-check found the IOPort executor reachable from any kernel code, and the re-check then signed off.
- **Interruptions:** the owner's usage limit stopped four agents mid-task for about 40 minutes; each resumed where it stopped.
- **Next:** merge PR #8, then M8.
