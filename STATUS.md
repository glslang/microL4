# Status
Current milestone: M2 · Capability core and model. The done-when test passed on 2026-10-30; the fresh reviewer is re-checking the fixes to its four points before signing off. Next: M3 · Paging and interrupts (it can run in parallel with M2), then M4 · Kernel objects and BootInfo, which needs both.

## Done
- [x] M0 · Bootstrap and tooling (PR #1, merged 2026-10-29)
- [x] M1 · Design and ABI (PR #2, merged 2026-10-30): `docs/design.md`, `docs/abi.md` v0 and ADRs 0004 to 0023, checked against seL4 by a spec checker per area and signed off by three fresh reviewers
- [x] M2 capability core in `l4core` (PR #3), all safe `no_std` code:
  - `cap`: the 16-byte capability, object types and sizes, rights.
  - `slot`: the 32-byte slot and `SlotMemory`.
  - `cdt`: the depth-and-`low` derivation list of ADR 0012, with a `check_slot` invariant check.
  - `cspace`: guarded radix lookup.
  - `cnode`: derive, Copy, Mint, Move, Mutate, Rotate, Delete and Revoke, with seL4's Zombie deletion ported to loops with preemption points.
  - `untyped`: retype with the watermark rules and a preemptible top-down reset.
  - `kernel`: the hooks the kernel implements.
  - `testing` (a feature): fake memory and a recording kernel for tests.
- [x] `model/` (`l4model`): a reference model of plain maps and an ordered derivation forest. A test writer built it from the specification, reading only the core's public API. A proptest harness runs each random sequence on both. After every step, and at every injected preemption, it compares results, every slot, parents, finality, children and hooks, and checks the invariants. Six self-tests show it catches deliberate corruption. `cargo test` runs 10,000 cases in about 16 s; a 100,000-case soak also passed. It found no bug in the core.
- [x] Miri clean on `l4core`. Under Miri it skips the 4,095-deep chain test and the reviewer's checker tests, which scan all memory after every call, to save time.
- [x] A fresh reviewer failed to hand-write a sequence that breaks an invariant. Its checking kernel follows every capability through every slot write and hook against a plain parent map. Before it was trusted, it caught six bugs planted one at a time. Eleven targeted attacks held, each with preemption at every point and other calls before the restart, as did about 7,000 seeds of a random explorer and a lookup fuzzer. It raised four disagreements between code and specification, all settled below.

## Next
- [ ] M3 · Paging and interrupts. First, before any feature that needs them: xtask passes `-cpu max,la57=off` and scenarios gain a `qemu_args:` key; the loader allocates below 64 GiB (ADR 0006); `tools/hyperv/New-L4Vm.ps1` turns processor compatibility mode off; the CPU feature check covers XSAVE too and prints one `CPU lacks` line naming every missing feature; the boot summary prints the CPUID features the kernel requires, `IA32_APIC_BASE` and the Meltdown line (XCR0 and the XSAVE size from M5)
- [ ] M4 · Kernel objects and BootInfo: implement `SlotMemory` and `Kernel` in `kernel/src/arch/` over the direct map; decode the CNode and Untyped invocations around `l4core` (slot lookup, including `Untyped_Retype`'s `node_depth` 0); the self-test that retypes, revokes and retypes again

## Open issues
- A revoke that destroys the CNode holding its own slot deletes the revoked capability and stops, so its later descendants survive. If it is preempted inside that destruction, the CNode's Zombie is left, partly cleared, in a slot the user can name, until Delete or a revoke of its untyped finishes it. seL4 does the same; accepted (`docs/design.md`, Slot operations). The M10 red team should know it.
- The model harness finishes such a Zombie with a Delete before comparing. Otherwise random sequences never leave a Zombie the user can name, so user operations on Zombies are covered only by the hand-written tests in `core/src/tests.rs` and `core/src/review_tests.rs`.
- `Kernel::finalise` runs with `last = true` on every deletion of an Untyped, IRQControl, IOPortControl or Hypervisor capability, because `same_object` is false for them, as in seL4's `isFinalCapability`. The kernel's hook must ignore those (M4).
- The `capCyclicZombie` return in `finalise_slot` is unreachable without overlapping objects; it is kept as seL4 has it.
- The optional `cargo-fuzz` target over the same sequences is not built.
- QEMU's default CPU model (`qemu64`), which xtask uses today, lacks SMEP, SMAP and XSAVE (from memory). The kernel checks for all three from M3 (ADRs 0004 and 0014), so M3 must change xtask first.
- The loader's 1:1 map of low memory is still live in the kernel; M3 drops it (`docs/design.md`, Privilege levels).
- `kprintln!` has no lock. Fine while interrupts are off, and the kernel never enables them outside the idle loop (`docs/design.md`, Kernel execution model).
- The firmware's IDT and stack sit in `USABLE` memory; M3 loads the kernel's own before M4 reuses any (`docs/design.md`, Boot).
- No guard page under the boot stack; M3 puts one under the kernel stack and each IST stack.
- Accepted risks, recorded for the M10 red team: Meltdown on a vulnerable host CPU (no skim window; ADR 0004); IPC queue-cancel loops are not preemptible, as in seL4 (`docs/design.md`, IPC); `vmbus` can name any guest page in a GPADL, and an MSI-capable driver can send any vector (ADR 0020, `docs/design.md`, Interrupts).
- PLAN.md (exported from the plan doc) still shows the pre-M1 proposals where ADRs supersede them: M2's "an untyped with children cannot be retyped" (ADR 0010), "at most two levels" of CNodes (ADR 0011), the reply capability's place (ADR 0016), and IPC entirely in M6 (ADR 0023). `docs/design.md` and the ADRs win; re-export PLAN.md when the doc is next edited.
- `rustup target add` worked again this session; the `build-std` fallback is kept (ADR 0001).

## Decisions this milestone
- No new ADR: the core follows `docs/design.md` and ADRs 0009 to 0012, and `docs/abi.md` is unchanged.
- The `Kernel` trait has no `derive` hook; every derivation rule lives in `l4core::cnode::derive`.
- A TCB's `finalise` hook returns no cleanup, as seL4's thread finalisation does. The trait's doc says so and `core/` asserts it.
- `l4core`'s `testing` feature gives `model/` the fake memory and recording kernel; the kernel never enables it.
- Proptest's failure files are git-ignored; minimal cases worth keeping become named tests in `model/tests/scenarios.rs`.
- `docs/design.md` now states the partial revoke in Slot operations and in three invariants, and corrects the list note on plain copies, which ignored deleted slots.
- The test writer settled these specification gaps from seL4, and the core already agreed:
  - Each object a retype makes becomes the untyped's first child, in creation order.
  - `init_object` runs for every new object.
  - The reply master carries Grant.
  - A swap calls `moved` only for non-empty slots, naming the capability as it lands.

## Hyper-V checks
- M0 VHDX (7c4609f, 2026-10-29): boots with Secure Boot off; hello and `TEST PASS` on COM1 through the named pipe. It confirms the plan's Hyper-V column for M0:
  - CPUID signature is `Microsoft Hv`.
  - The GOP framebuffer is 1024x768 BGR at `0xF8000000`, stride 1024.
  - The ACPI RSDP is at `0x1FFFA014`.
  - The memory map has 10 regions, 509 MiB usable of 512 MiB; the highest RAM ends at `0x20000000`, so the direct map is the 4 GiB minimum.
  - Unlike QEMU, the map lists no MMIO or high reserved ranges.
- M1 was documents only and M2 is host code only; the next Hyper-V check is at the end of M3.

## Last session
2026-10-30: M2. The lead wrote the capability core in `l4core` and its scenario tests, porting seL4's deletion onto the ADR 0012 list. Two agents then worked in parallel, each in its own worktree. A test writer built `model/` and the differential proptest from the specification alone. A fresh reviewer tried to break the core with hand-written sequences and its own checking kernel. Neither found an implementation bug. Their findings were specification gaps: the partial revoke, and a TCB's cleanup contract. Both are now fixed in the docs and the core. The reviewer's sign-off on those fixes is pending.
