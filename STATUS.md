# Status
Current milestone: M6 · IPC and notifications, complete: the done-when scenarios pass on QEMU, both fresh reviewers signed off, and the red-team pass found nothing. M6 has no Hyper-V check. Next: M7 · User-level drivers and console.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023
- [x] M2 · Capability core and model (PR #3, merged 2026-10-30): the capability core in `l4core`, a reference model in `model/` with a 10,000-case differential proptest, and Miri clean. A fresh reviewer failed to break an invariant.
- [x] M3 · Paging and interrupts (PR #4, merged 2026-11-02): the kernel's own GDT, TSS, IDT and page tables, decoded ring-0 faults, the ACPI parser with QEMU and Hyper-V table dumps, the local APIC, PIC, I/O APIC and HPET set up, and a 100 Hz timer calibrated against the HPET or Hyper-V's reference counter. A fresh reviewer signed off.
- [x] The M3 Hyper-V check passed on the owner's host (2026-10-30): ten ticks at 100.002 Hz against the reference counter; the results are under "Hyper-V checks".
- [x] M4 · Kernel objects and BootInfo (PR #5, merged 2026-11-02): the boot plan, the untyped and BootInfo in `l4core::{bootinfo, boot}`, the Untyped and CNode decoder `l4core::invoke`, boot steps 6, 7 and 9, and the `bootinfo` and `retype` self-tests. A fresh reviewer signed off and a red-team pass on the decoder found nothing.
- [x] M5 · Threads, address spaces and the root task (PR #6, merged 2026-11-22): TCBs and every TCB invocation, the scheduler, the paging objects with their flushes, `syscall`/`sysretq`/`iretq` entry and exit with eager XSAVE, endpoint IPC with reply capabilities and fault delivery, the system-call dispatch in `l4core`, and the root task (`user/libsys`, `user/root`) in ring 3. The done-when passed on QEMU and on Hyper-V; two fresh reviewers signed off; the red team's `mov ss` deferred-`#DB` denial of service is fixed and confirmed on Hyper-V (`docs/redteam/m5-movss-db.md`). `docs/design.md` has the details.
- [x] M6 · IPC and notifications (PR #7). Done on QEMU.
  - **Spec check first:** a fresh agent checked the design's capability-transfer, badge, notification, binding, `CNode_SaveCaller` and `CNode_CancelBadgedSends` rules against seL4's sources; 14 clarifications, no mistakes, and ADR 0026.
  - **Notifications** (`l4core::ipc::notification`): Signal (`Send`, `NBSend`, `Call`), Wait (`Recv`, the receive phase of `ReplyRecv`) and Poll (`NBRecv`); `TCB_BindNotification` and `TCB_UnbindNotification`; an endpoint receive takes a pending bound signal first, and a signal wakes a bound thread blocked in one; deleting a notification unbinds it and restarts its waiters; `tcb::finalise` unbinds, then suspends.
  - **Capability transfer** (`l4core::ipc::transfer`): Grant and both IPC buffers gate it; every pointer is looked up again at transfer, all or nothing; the receive slot is found once (depth 1 to 64); capabilities to the carrying endpoint unwrap to badges, whatever their rights, never in a reply; at most one copy per message, placed as `CNode_Copy` places it; replies carry capabilities through the reply capability's Grant.
  - **`CNode_SaveCaller`** and **`CNode_CancelBadgedSends`** (`l4core::ipc::badge`), with errors in `docs/abi.md`'s order.
  - **The IPC reference model** (`model/src/ipc.rs`, `ipc_harness.rs`): written from the design, run beside `l4core`'s `IpcTestKernel` and compared after every step. `ipc_random` runs 20,000 random cases by default, `ipc_scenarios` 70 hand-written ones. It covers M5's paths (calls, replies, faults, cancellation, deletion) and M6's. Builder M planted 25 bugs; each was caught.
  - **Scenarios** (41 in all): `pingpong` (1,016 checked round trips each of 1-, 0- and 120-word messages, the last 1,000 timed with the TSC; the fastest 1-word round trip under TCG is about 170,000 to 185,000 cycles, 80 to 90 µs), `captransfer`, `badge`, `ipcntfn` (one server bound to a notification takes calls and signals in one receive loop), and the red team's `redteam-ipc`.
  - **Kernel:** the notification words over the direct map and the Notification and TCB arms of `Objects::finalise`; nothing else changed.
- [x] Both fresh M6 reviewers signed off with no must-fix finding. Reviewer C (core logic and ABI) planted 48 bugs in `l4core`, 42 caught and the other 6 unobservable; reviewer K (kernel, user side, model and done-when) planted 12. A fix round closed their should-fixes: the model gives some threads a second CSpace, so a lookup in the wrong thread's CSpace is caught; `pingpong`'s 120-word run checks every word both ways; a host test pins an empty poll's `rsi`; `ipcntfn` exercises bind-time delivery and `badge` a refused re-mint; and the design records seL4's release order. A fresh reviewer re-checked the fix round and signed off: each planted bug the reviewers named now fails a test, and `l4core` changed only in doc comments.
- [x] The M6 red-team pass found nothing: a host fuzzer of system calls, transfers, SaveCaller, CancelBadgedSends, binding and capability operations by six threads (`core/src/ipc/redteam.rs`, 3,000 cases, 100,000 once) checks every invariant and every reply capability after each step, and `test=redteam-ipc` checks saved replies and bound-thread and notification deletion from ring 3.

## Next
- [ ] M7 · User-level drivers and console (PLAN.md): IRQHandler and IOPort invocations, interrupt delivery through notifications (`ipc::signal` is the entry M7 calls), a COM1 driver in user space, and the kernel-without-features build and scenario.

## Open issues
- **Never run anywhere:** the x2APIC-to-xAPIC handover. Both firmwares hand over in xAPIC mode, so only a host test covers it.
- **From memory, never exercised:** the VP assist page's privilege gate (`AccessIntrCtrlRegs`, as KVM does) and the time-unhalted timer's enable bit 8. Both read as off on Hyper-V, so they were never written.
- **Hyper-V's I/O APIC is version `0x11`, with no EOI register.** M7's plan for a stale Remote IRR (write the old vector to the EOI register) does not work there; see `docs/design.md`, Open questions.
- **Toolchain drift:** CI runs Rust stable, 1.100 on 2026-11-22, while this container's default is 1.97. Each new stable has brought clippy lints the older ones miss: 1.99 `chunks_exact_to_as_chunks` and `needless_late_init`, 1.100 `needless_range_loop` on four range loops. Install the current stable (`rustup toolchain install <version> --profile minimal -c clippy`) and run `cargo +<version> xtask clippy` before pushing, or pin the toolchain (ADR 0001 is the place to decide). Every asm label Rust names through `extern` must be `.global`.
- **#DF stack overflow:** it re-enters the #DF handler over its own frames, so the first report may be cut short (`df_stack`). Accepted: nothing runs on.
- **`int1` (`0xF1`):** in ring 0 it raises #UD on QEMU 8.2 TCG, not #DB. Recheck the design's `int1` claims on real hardware or Hyper-V in M10, brief 5.
- **HPET above MAXPHYADDR:** an HPET base under 2^52 but above the CPU's MAXPHYADDR would fault when mapped instead of counting as no HPET. No known firmware does this.
- **Unchecked hardware facts:** H10 (MTRR and PAT combination) is checked in M8. UMIP (H11) is confirmed on QEMU and on Hyper-V.
- A partial revoke, one whose work destroys a CNode on its slot's lookup path, ends where preemption falls, as in seL4: the restart fails its lookup and the work left stays undone. Delete finishes a Zombie it leaves in a slot the user can name, and a revoke of an ancestor untyped the rest; under a boot untyped that region is dead (`docs/design.md`, Slot operations). A Delete named through a path that runs through its own slot can be cut short the same way. The harness checks that a revoke cut short left a safe state, then runs the same revoke unpreempted from the same start: the leftover's memory and back-references must equal that run's at one of its preemption points, and its hook calls must be that run's up to there. Later steps go on from the unpreempted run's end.
- The model harness covers user operations on a Zombie only through hand-written tests. It no longer deletes the Zombies a revoke cut short leaves, so no random sequence does; `l4core`'s `a_revoke_restarted_by_looking_its_slot_up_again_is_cut_short` checks that such a Delete finishes the work.
- **Is 4 KiB the right reset chunk?** Answered on QEMU; Hyper-V is unmeasured. Build `cargo xtask image --cmdline "test=retype"` and boot it (`tools/hyperv/README.md`, the optional M4 check).
- **A kernel without features** is only linted, never built into an image or booted; M7 adds that build and its scenario.
- **The kernel's `SlotAddr` debug check** tests only that a slot lies in object memory (`l4core::objmem`), which is weaker than core's invariant; M7 must add the IRQ node's static range to it.
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
- **`ipc::signal` calls `ipc::cancel_ipc` directly,** while binding goes through the `Threads::cancel_ipc` hook; through the hook `signal` could drop its `IpcEnv` bound. Small; decide when M7 wires interrupts to `signal`.
- **Two M6 invariant rows rest on the code's structure only:** the queue-cancel loops have no preemption point, and every IPC call finishes in one kernel entry; M10 briefs 6 and 9 test them.

## Decisions this milestone
- **ADR 0026:** a receive phase that resolves its capability pointer but cannot use the slot (empty, wrong type, no Read, or a notification bound to another thread) is a capability fault with `MissingCapability` and 0 bits left.
- **Notification words and `cancel_badged_sends` are `Threads` hooks,** because `invoke` and `tcb::invocation` are generic over `Threads`, not `IpcEnv`.
- **`Call` on a notification signals it and gets an empty reply.**
- **Capability transfer** looks every pointer up again at transfer and moves nothing if one fails; it copies at most one capability per message; unwrapping ignores rights; a transferred untyped fills its source's watermark, as `CNode_Copy` does.
- **`CNode_CancelBadgedSends`** checks all four rights before the badge-0 case, is not preemptible (as seL4), and releases senders in queue order; `CNode_SaveCaller` with no invoking thread (self-tests only) is `IllegalOperation`.
- **A `receive_depth` of 0 or above 64 names no slot** (seL4's `lookupTargetSlot`), a clarification in `docs/abi.md`.
- **The IPC model** is plain data written from the design, not a second implementation of `l4core`'s traits; `l4core` runs over `IpcTestKernel` beside it.
- **The root task** has six guarded 16 KiB thread stacks; its image spans `0x40_0000` to `0x46_0000`.

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
2026-11-22: M6, in one session after merging M5 (PR #6).
- **Spec check:** a fresh agent checked the M6 design against seL4 before any code; its 14 clarifications and ADR 0026 went in first.
- **Phase 1**, four builders in parallel worktrees: notifications and binding (N); capability transfer, `CNode_SaveCaller` and `CNode_CancelBadgedSends` (X); the IPC reference model over M5's paths (M); libsys and the four done-when tests (U).
- **Phase 2:** the lead merged N and X (six trivial conflicts), U and M; builder M extended the model to M6's rules; a docs agent wrote the builders' notes into `docs/design.md` and `CLAUDE.md`.
- **Review and red team:** two fresh reviewers (core; kernel, user side and model) signed off with should-fixes only; the red team found nothing and left a fuzzer and a scenario. A fix round closed the should-fixes.
- **Also this session:** PR #6 could not be rebase-merged because its 12 merge commits replayed with conflicts; with the owner's go-ahead the branch was rebuilt as 28 linear commits with an identical tree, and merged.
- **Next:** merge PR #7, then M7.
