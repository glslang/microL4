# Status
Current milestone: M1 · Design and ABI, complete: the done-when test passed and the fresh reviewers signed off on 2026-10-29. Next: M2 · Capability core and model and M3 · Paging and interrupts, which can run in parallel.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] Shared ABI decisions fixed first, so six areas could be designed in parallel: seL4's x86_64 registers, `MessageInfo` and IPC buffer, with microL4's own system call numbers, object type numbers and invocation labels (ADR 0022)
- [x] `docs/design.md`: one section per row of PLAN.md's architecture table, plus TCBs, faults, address spaces, I/O ports, ACPI and the timer. Each section has its invariants, each naming its milestone, and a comparison with seL4 listing every divergence with its reason
- [x] Six designer subagents wrote the areas (capabilities, IPC, threads, address spaces, interrupts and I/O, boot and ABI); a fresh spec checker per area compared each with the seL4 manual's source and kernel code (commit `7a852638f502`), made 143 fixes in place and raised 24 must-fix items, all settled
- [x] `docs/abi.md` v0: system calls and registers, `MessageInfo`, IPC buffer, capability pointers and lookup, errors and detail words, object types and sizes, every invocation's label, arguments, results and errors, fault messages, BootInfo, the initial CSpace, root-task entry state, debug calls, and the boot handoff moved from `docs/boot.md`
- [x] ADRs 0004 to 0023 and a list of open questions, each with its default and the milestone that answers it (`docs/design.md`, Open questions)
- [x] Fresh review against the done-when test by three reviewers, one per group of areas. They found 7 blocking contradictions, 18 should-fix items and 39 nits; all were fixed, and each reviewer re-checked its items and signed off. The link check passes, and all 189 invariants name their milestone

## Next
- [ ] Merge the M1 PR, then start M2 and M3 (two sessions can run them in parallel)
- [ ] M2 · Capability core and model, from `docs/design.md` Kernel objects to Derivation tracking: the 32-byte slot, the depth-and-`low` derivation list (ADR 0012), copy, mint, move, mutate, rotate, delete, revoke, Zombies, untyped retype, the `moved` hook for paging back-references
- [ ] M3 · Paging and interrupts. First, before any feature that needs them: xtask passes `-cpu max,la57=off` and scenarios gain a `qemu_args:` key; the loader allocates below 64 GiB (ADR 0006); `tools/hyperv/New-L4Vm.ps1` turns processor compatibility mode off; the CPU feature check covers XSAVE too and prints one `CPU lacks` line naming every missing feature; the boot summary prints the CPUID features the kernel requires, `IA32_APIC_BASE` and the Meltdown line (XCR0 and the XSAVE size from M5)

## Open issues
- QEMU's default CPU model (`qemu64`), which xtask uses today, lacks SMEP, SMAP and XSAVE (from memory). The kernel checks for all three from M3 (ADRs 0004 and 0014), so M3 must change xtask first.
- The loader's 1:1 map of low memory is still live in the kernel; M3 drops it (`docs/design.md`, Privilege levels).
- `kprintln!` has no lock. Fine while interrupts are off, and the kernel never enables them outside the idle loop (`docs/design.md`, Kernel execution model).
- The firmware's IDT and stack sit in `USABLE` memory; M3 loads the kernel's own before M4 reuses any (`docs/design.md`, Boot).
- No guard page under the boot stack; M3 puts one under the kernel stack and each IST stack.
- Accepted risks, recorded for the M10 red team: Meltdown on a vulnerable host CPU (no skim window; ADR 0004); IPC queue-cancel loops are not preemptible, as in seL4 (`docs/design.md`, IPC); `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020, `docs/design.md`, Interrupts).
- PLAN.md (exported from the plan doc) still shows the pre-M1 proposals where ADRs supersede them: M2's "an untyped with children cannot be retyped" (ADR 0010), "at most two levels" of CNodes (ADR 0011), the reply capability's place (ADR 0016), and IPC entirely in M6 (ADR 0023). `docs/design.md` and the ADRs win; re-export PLAN.md when the doc is next edited.
- `rustup target add` worked again this session; the `build-std` fallback is kept (ADR 0001).

## Decisions this milestone
- ADR 0004: the kernel requires NX, PGE, PAT, SMEP, SMAP and XSAVE, and maps itself from static tables shared by every address space
- ADR 0005: paging structures keep back-references to the capabilities mapped in them, instead of ASIDs; PCID is off
- ADR 0006: the direct map covers at most 64 GiB, and the loader allocates below it (amends ADR 0002)
- ADR 0007: the root task's objects come from a boot region outside every untyped, and a two-page BootInfo describes the rest
- ADR 0008: kernel entry builds one trap frame on the kernel stack; IST stacks serve only fatal and debug vectors; `sysretq` returns only below 2^47
- ADR 0009: a capability is a header word and a data word; CNodes and TCBs are destroyed through Zombie capabilities
- ADR 0010: retype allocates at the watermark while an untyped has children, and resets it only when it has none
- ADR 0011: CSpaces are seL4's guarded radix trees, with no limit on levels
- ADR 0012: the derivation list stores a depth and a low-water depth in every slot
- ADR 0013: fixed-priority round-robin with MCP, one 10 ms tick per slice, woken threads at the queue tail
- ADR 0014: eager XSAVE of x87 and SSE state only, with XSAVE required
- ADR 0015: CR4.FSGSBASE stays off; the kernel sets and switches user FS and GS bases
- ADR 0016: the reply capability is a one-shot capability in the receiver's TCB, made from a master in the caller's TCB
- ADR 0017: IPC names up to three capabilities, copies at most one, and unwraps capabilities to the sending endpoint
- ADR 0018: IPC does no priority inheritance; endpoint and notification queues are FIFO
- ADR 0019: IRQControl names interrupt sources; the kernel allocates vectors, applies MADT overrides, bounds every pin to three interrupts per Ack, and runs the local APIC in xAPIC mode
- ADR 0020: the Hypervisor capability exposes two hypercalls; SINTs are IRQ handlers; the SynIC pages are boot frames the kernel never touches
- ADR 0021: all UART code and the debug system calls exist only with the `debug` feature
- ADR 0022: the ABI keeps seL4's x86_64 registers and layouts, with its own numbers
- ADR 0023: M5 builds the IPC that fault delivery needs (endpoints, reply capabilities, fault delivery, cancellation); M6 keeps the rest

## Hyper-V checks
- M0 VHDX (7c4609f, 2026-10-29): boots with Secure Boot off; hello and `TEST PASS` on COM1 through the named pipe. It confirms the plan's Hyper-V column for M0:
  - CPUID signature is `Microsoft Hv`.
  - The GOP framebuffer is 1024x768 BGR at `0xF8000000`, stride 1024.
  - The ACPI RSDP is at `0x1FFFA014`.
  - The memory map has 10 regions, 509 MiB usable of 512 MiB; the highest RAM ends at `0x20000000`, so the direct map is the 4 GiB minimum.
  - Unlike QEMU, the map lists no MMIO or high reserved ranges.
- M1 is documents only; the next Hyper-V check is at the end of M3.

## Last session
2026-10-29: M1 written. The shared ABI decisions came first; six designer subagents then wrote the areas in parallel, a fresh spec checker per area compared each with seL4's manual source, and the lead settled the cross-area questions (39 decisions, now in the documents and ADRs). `sel4.systems` is blocked by the proxy, so the manual was read from its LaTeX source in the seL4 repository. Three fresh reviewers then checked both documents; their blocking findings were contradictions between sections (the M3 boot order, XSAVE milestones, the root TCB's reply master, the M5/M6 split), all fixed. M1 signed off. The next session starts M2 or M3 from the playbook prompt, once the M1 PR is merged.
