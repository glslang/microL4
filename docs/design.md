# microL4 kernel design

Status: v0, M1 (2026-10-29). Every later milestone codes against this note and
`docs/abi.md`. A change to either needs an ADR in `docs/adr/`.

microL4 follows seL4's classic, non-MCS design on one x86_64 core. All
authority is a capability, the kernel allocates nothing after boot, and user
space owns every policy. The API is shaped like seL4's so that every choice
has a reference to compare against, but it is not seL4-compatible. This note
says how each part works and which invariants it keeps; `docs/abi.md` gives
the exact numbers, registers and layouts. Where they disagree, that is a bug
in one of them.

Each section ends with an invariants table, naming the milestone that
enforces each invariant, and a comparison with seL4 that lists every
divergence and its reason. seL4 references are to the reference manual's
source (`manual/parts/*.tex`) and kernel files in
[seL4's repository](https://github.com/seL4/seL4) at commit `7a852638f502`
(2026-10-29).

| Section | PLAN.md architecture row | Built in |
| --- | --- | --- |
| [Kernel execution model](#kernel-execution-model) | (all) | M3 to M6 |
| [Privilege levels](#privilege-levels) | Privilege levels | M3, M5 |
| [Address spaces](#address-spaces) | Kernel objects (paging) | M3, M5, M9 |
| [Boot](#boot) | Boot | M3 to M5 |
| [Kernel entry and exit](#kernel-entry-and-exit) | Syscall ABI | M3 to M5 |
| [Kernel objects](#kernel-objects) | Kernel objects | M2, M4 |
| [Memory and retype](#memory-and-retype) | Memory | M2, M4 |
| [Capability addressing](#capability-addressing) | Capability addressing | M2, M4 |
| [Derivation tracking](#derivation-tracking) | Derivation tracking | M2, M4 |
| [Threads and TCBs](#threads-and-tcbs) | (TCB) | M5, M6 |
| [Scheduling](#scheduling) | Scheduling | M3, M5 |
| [FP and SIMD](#fp-and-simd) | FP and SIMD | M5 |
| [Faults](#faults) | (faults) | M5, M6 |
| [IPC](#ipc) | IPC | M5, M6 |
| [Notifications](#notifications) | Notifications | M6 |
| [Interrupts](#interrupts) | Interrupts | M3, M7, M9 |
| [I/O ports](#io-ports) | Kernel objects (I/O ports) | M4, M7 |
| [ACPI and the timer](#acpi-and-the-timer) | Scheduling, Interrupts | M3 |
| [Hyper-V interface](#hyper-v-interface) | Hyper-V interface | M3, M9 |
| [Debug](#debug) | Debug | M3 to M5, M7 |
| [User-level drivers and console](#user-level-drivers-and-console) | (user-space servers: `uart`, `console`) | M7 |
| [Framebuffer, terminal and TUI](#framebuffer-terminal-and-tui) | (user-space servers: `fb`, `term`, `tui`) | M8 |
| [Open questions](#open-questions) | | |

## Kernel execution model

The kernel is event-driven on one core with one kernel stack. Every entry, a
system call, an exception or an interrupt, runs to completion with
interrupts disabled, then returns to whichever thread the scheduler picks.
The kernel never blocks and has no kernel threads.

- **Preemption points.** Long operations (revoking a capability, deleting a
  CNode, clearing a large untyped during retype) check for a pending
  interrupt at bounded intervals. If one is pending, the operation leaves its
  objects in a consistent intermediate state, the interrupt is handled, and
  the system call restarts later from the thread's saved registers. Progress
  is kept in the objects, so a restart continues rather than repeats. This is
  seL4's model.
- **No allocation after boot.** Every kernel object comes from untyped memory
  through retype. Static kernel memory (the kernel stack, IST stacks, the
  idle thread, the kernel's page tables and fixed tables) is reserved at boot
  and never grows.
- **No user pointers.** The kernel never dereferences a user virtual address.
  It reaches user memory (IPC buffers, BootInfo, the root-task image) only
  through physical frames it holds capabilities or references to, through
  the direct map. SMAP stays on, and the kernel never executes `stac`.
- **`unsafe` stays in `arch`.** Raw memory, registers and instructions are in
  `kernel/src/arch/`, each `unsafe` block with a `SAFETY:` comment. The logic
  that can run on a host (capability operations, derivation, retype rules,
  lookup, the IPC state machine, message decoding, ACPI parsing) lives in
  `core/`, which is `forbid(unsafe_code)` and is tested on Linux and under
  Miri.

| Constant | Value | Meaning |
| --- | --- | --- |
| `PHYS_MAP_BASE` | `0xFFFF_8000_0000_0000` | the direct map of physical memory, PML4 slot 256 |
| `KERNEL_VIRT_BASE` | `0xFFFF_FFFF_8000_0000` | the kernel image, PML4 slot 511 |
| user range | the lower half | exact bounds in [Address spaces](#address-spaces) |
| page sizes | 4 KiB and 2 MiB | 1 GiB pages are not offered to user space |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Kernel code runs with interrupts disabled, from entry to exit; only the idle thread's halt loop runs with `IF = 1` in ring 0 | `IA32_FMASK` clears IF; every IDT gate is an interrupt gate; no `sti` outside the idle loop (review, M10 brief 5); `test=ring3` reads RFLAGS at every entry from ring 3 and requires IF clear | M3, M5 |
| Every kernel operation whose length a ring-3 task can grow has a preemption point, except the IPC queue-cancel loops, which are bounded by the number of TCBs the task could retype ([IPC](#ipc)) | `core/` loops call the kernel's `preempt` hook after each unit of work; from M5 an invocation cut short leaves its caller `Restart` (`l4core::syscall`), and the paging loops touch at most 512 entries with no preemption point ([Deletion](#deletion)); the queue-cancel loops, `ipc::cancel_all_ipc` (M5), `ipc::cancel_badged_sends` and `ipc::cancel_all_signals` (M6), take one O(1) step per queued thread ([Deletion and cancellation](#deletion-and-cancellation)); M10 briefs 6 and 9 | M2, M4, M5, M6, M10 |
| A system call restarted after a preemption point continues its work and never repeats a completed step. Three exceptions, all as in seL4: a partial revoke, whose work destroyed a CNode on the lookup path that named its slot (a Delete can do this only through a path that runs through its own slot), so its restart fails the lookup and leaves the rest undone, with an outcome that depends on where preemption fell; a Delete or Revoke that finalises the caller's own TCB, which is never restarted; and one that deletes the caller's own VSpace or IPC buffer before its TCB, whose restarted caller faults before it can issue the call again ([Slot operations](#slot-operations)) | progress lives in the objects (untyped watermark, Zombie capabilities, the derivation list itself); proptest with preemption injected at random, restarting Delete and Revoke by looking their slots up again, and requiring a revoke cut short to stop exactly where the unpreempted revoke passed one of its preemption points, in memory and in the hook calls made so far | M2, M4 |
| The kernel allocates no memory after boot | the kernel links no allocator; every object comes from `Untyped_Retype` | M4 |
| The kernel never dereferences a user virtual address | user memory is reached only through frames, via the direct map: an IPC buffer word through `l4core::tcb::buffer_word`, which gives the physical address in the frame of the TCB's buffer slot, and `arch::Objects`' buffer accessors; the root image through `Objects::copy_into_frame` (boot step 8); SMAP on (M3); no `stac` anywhere (CI grep over `kernel/`) | M3, M5 |
| Every exception and interrupt entry clears RFLAGS.AC and DF before any Rust code runs | `clac` and `cld` in every entry stub ([Kernel entry and exit](#kernel-entry-and-exit)) | M3 |
| `unsafe` appears only in `kernel/src/arch/`, each block with a `SAFETY:` comment; `core/` has none | `#![deny(unsafe_code)]` outside `arch`, `clippy::undocumented_unsafe_blocks`, `#![forbid(unsafe_code)]` in `core/` | M0 |

### Compared with seL4

No divergence in the model itself. seL4's kernel is also event-based with
one kernel stack per core, runs with interrupts disabled, polls for a
pending interrupt at preemption points (`preemptionPoint` in
`src/model/preemption.c`, every `CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION`
units) and allocates nothing after boot. The differences are of method:
microL4 is written in Rust and tests its host-runnable logic in `core/`
with proptest and Miri, where seL4 relies on its proofs.

## Privilege levels

The kernel runs in ring 0 and user code in ring 3, with nothing in rings 1
and 2, and the kernel is mapped supervisor-only and global in PML4 slots 256
to 511 of every address space. The kernel refuses to boot without NX, PGE,
PAT, SMEP, SMAP and XSAVE, and turns UMIP on when the CPU has it
([ADR 0004](adr/0004-privilege-features.md)).

Hardware facts this document relies on are listed once, here. M1 wrote each
from memory of the Intel SDM or of QEMU and Hyper-V behaviour, not checked
against a source; the last column names the milestone that checks it, or says
how M3 or M5 checked it.

| Ref | Fact | Check |
| --- | --- | --- |
| H1 | QEMU's default TCG CPU model `qemu64`, which xtask used before M3, has NX, PGE and PAT but not SMEP, SMAP, XSAVE, UMIP, PCID or 1 GiB pages. `-cpu max` under TCG has SMEP, SMAP and UMIP, and LA57 unless `la57=off`. | Checked in M3: the `cpu_refuse` scenario boots `qemu64` and the kernel finds NX, PGE and PAT but not SMEP, SMAP or XSAVE; the `hello` boot log shows `-cpu max,la57=off` with SMEP, SMAP and UMIP. `qemu64`'s lack of UMIP, PCID and 1 GiB pages and `-cpu max`'s LA57 are from memory |
| H2 | Hyper-V passes SMEP and SMAP through to a Generation 2 guest when the host CPU has them and processor compatibility mode is off. | Checked at the M3 Hyper-V check: the kernel booted past `check_cpu` |
| H3 | Exception and interrupt delivery clears TF, NT and RF (and IF for interrupt gates) but not AC or DF; `syscall` clears the RFLAGS bits set in `IA32_FMASK`. | Checked in M3 for TF and IF only: the `trap_debug` handler, entered by a single step, runs to its report, and `idle_irq` finds IF = 0 in the interrupt path. Whether delivery leaves AC and DF set was not observed; every stub clears both regardless. `syscall`: checked in M5 on QEMU: `test=ring3` makes a `syscall` with DF, NT and AC set, finds them in the saved RFLAGS (`0x44646`) and clear in ring 0 |
| H4 | With CR4.PCIDE = 0, a CR3 write invalidates every non-global TLB entry and every paging-structure-cache entry. Clearing and setting CR4.PGE invalidates every entry, global ones included. | Checked in M3 only in part: after the CR3 load and the PGE toggle, `lowmem` faults on the loader's 1:1 map, but TCG flushes every translation on any CR3 write, so it cannot show that the toggle is needed. The rest is from memory |
| H5 | `invlpg a` invalidates the TLB entries for the page holding `a`, whatever its size, and all paging-structure-cache entries. | Not checked on a CPU in M5: TCG hides a missing flush ([TLB maintenance](#tlb-maintenance)), and the TLB model of `l4core::vspace`'s proptest is built on this fact. From memory |
| H6 | Changing an entry's P flag from 0 to 1 needs no invalidation: no TLB or paging-structure-cache entry is made from a not-present entry. Any other change to a present entry needs one. | As H5 |
| H7 | Effective R/W and U/S are the AND over the walk and XD the OR, so intermediate entries may grant everything and leaves restrict. | Checked in part in M5 on QEMU: `test=ring3` maps every user page under tables with R/W, U/S set and XD clear, runs its code page and takes #PF with error `0x7` writing to it, a read-only leaf. The XD OR and the U/S AND are from memory |
| H8 | PAT index = 4·PAT + 2·PCD + PWT; the PAT bit is bit 7 of a 4 KiB PTE and bit 12 of a 2 MiB PDE. Type encodings: UC `00h`, WC `01h`, WT `04h`, WB `06h`, UC- `07h`. A page mapped UC or WC must not also be mapped WB (SDM vol. 3, 11.12.4). | Checked in M3 against seL4's entry layouts (`structures.bf`) and `init_pat_msr`, and pinned by host tests in `l4core::vspace`; the aliasing rule is from memory |
| H9 | `sysretq` with a non-canonical RCX raises #GP in ring 0 on Intel CPUs, after the kernel has restored the user's RSP. | Not checked: `l4core::entry::exit_frame` never lets `sysretq` see such an RCX. `test=ring3` makes a `syscall` that returns to 2^47, and the kernel leaves by `iretq` to RIP 0 ([Exit](#exit)). From memory |
| H10 | An MTRR type of UC with a PAT type of WB gives UC; a PAT type of WC gives WC whatever the MTRR. Fixed-range MTRRs make the legacy hole at `0xA0000` UC. | The WC half in M8, when the framebuffer is first mapped WC: `test=tui` times a full clear of it mapped UC and then WC ([`fb`](#fb)); TCG has no cache model, so the M8 Hyper-V check gives the answer. The rest is from memory; M3 maps no page whose type depends on it |
| H11 | UMIP makes `sgdt`, `sidt`, `sldt`, `smsw` and `str` raise #GP at CPL 3. | Checked in M5 on QEMU for `sgdt`: under `-cpu max`, which has UMIP, `test=ring3` runs `sgdt` in ring 3 and takes #GP with error 0. The other four are from memory. M3 sets CR4.UMIP when CPUID reports it. Checked on Hyper-V at the M5 Hyper-V check (2026-11-22): `cpu: features` lists UMIP and `test=ring3` step 22 takes #GP with error 0 for `sgdt` in ring 3 |
| H12 | CPUID: leaf 1 EDX bit 13 PGE, bit 16 PAT; leaf `0x8000_0001` EDX bit 20 NX; leaf 7.0 EBX bit 7 SMEP, bit 20 SMAP; leaf 7.0 ECX bit 2 UMIP. | Checked in M3: `l4core::cpu` reads these bits, and the boots agree with H1 (`qemu64` lacks exactly SMEP, SMAP and XSAVE in `cpu_refuse`; `-cpu max,la57=off` has all seven in `hello`) |
| H13 | The CPU may fill TLB and paging-structure-cache entries at any time, in any ring, from any present entry reachable from CR3, including for speculative accesses that never retire (SDM vol. 3, 4.10.2.3). So a flush must follow the entry write it covers, never precede it. | As H5; `Flush` is returned by the operation that wrote the entry, so the order holds by construction |
| H14 | CPUID leaf 7.0 EDX bit 29 says `IA32_ARCH_CAPABILITIES` (MSR `0x10A`) exists; its bit 0, `RDCL_NO`, says the CPU is not open to Meltdown (rogue data cache load). | Checked in M3: TCG's `-cpu max` does not report the MSR, so QEMU boots print `unknown`; the owner's Hyper-V host reports it with `RDCL_NO` set, `cpu: meltdown: not vulnerable` |

### Rings and segments

M3 loads this GDT; M5, which adds system calls, writes `IA32_STAR` =
`0x0013_0008_0000_0000` in the same boot step ([Descriptor tables and
MSRs](#descriptor-tables-and-msrs)).

| Index | Offset | Selector used | Descriptor |
| --- | --- | --- | --- |
| 0 | `0x00` | | null |
| 1 | `0x08` | `0x08` | kernel code, 64-bit, DPL 0 |
| 2 | `0x10` | `0x10` | kernel data, DPL 0 |
| 3 | `0x18` | `0x1B` | user data, DPL 3 |
| 4 | `0x20` | `0x23` | user code, 64-bit, DPL 3 |
| 5 and 6 | `0x28` | `0x28` | TSS, 16 bytes |

- `syscall` loads CS `STAR[47:32]` = `0x08` and SS `0x10`. `sysretq` loads
  CS from `STAR[63:48] + 16` and SS from `STAR[63:48] + 8`, each with RPL 3,
  so `STAR[63:48]` = `0x13` gives CS `0x23` and SS `0x1B`, entries 4 and 3,
  and an `iretq` with the same selectors reads matching descriptors.
- There is no 32-bit code descriptor and no LDT, so user code cannot enter
  compatibility mode. User CS and SS are always these selectors; no
  invocation takes them from user registers.
- Vector 3 (`#BP`) has DPL 3 and every other IDT gate DPL 0 ([Descriptor
  tables and MSRs](#descriptor-tables-and-msrs), [Vector map](#vector-map)),
  so `int n` from ring 3 cannot forge an exception or a device interrupt. seL4
  also opens the vectors from `int_trap_min`, above its IRQs
  (`init_idt_entry`).
- User RFLAGS always has IOPL 0 and the TSS denies every port, so ring 3 can
  reach ports only through IOPort invocations ([I/O ports](#io-ports)).
- Kernel RFLAGS: `IA32_FMASK` ([Descriptor tables and
  MSRs](#descriptor-tables-and-msrs)) clears at least IF, TF, DF, NT, IOPL and
  AC on `syscall`. Exceptions and interrupts do not clear AC or DF [H3], so
  every exception and interrupt entry runs `clac` and `cld` before any Rust
  code; `clac` is safe because SMAP is required. Without `clac`, a thread
  could set AC with `popf` and switch SMAP off for the kernel entry its next
  fault causes. The kernel never runs `stac`.

### CPU features

| Feature | Set by | If the CPU lacks it | Why |
| --- | --- | --- | --- |
| EFER.NXE | the loader; M3 checks it | refuse to boot | kernel data and the direct map are never executable; user execute control |
| CR0.WP | the loader; M3 checks it | (architectural) | ring 0 honours read-only kernel pages |
| CR4.PGE | M3 | refuse to boot | kernel translations survive CR3 writes |
| PAT | M3 | refuse to boot | write-combining for the framebuffer; seL4 also refuses (`init_pat_msr`) |
| CR4.SMEP | M3 | refuse to boot | ring 0 cannot execute user pages |
| CR4.SMAP | M3 | refuse to boot | ring 0 cannot touch user pages; `clac` needs it |
| CR4.UMIP | M3 | run without it | it hides the GDT, IDT and TSS addresses [H11], which are fixed and public in microL4 (no KASLR), so it protects nothing; on when present as hygiene |
| CR4.PCIDE | never set | | PCID is off in v0 ([Address spaces](#address-spaces)) |
| CR4.LA57 | never set | the loader refuses (`docs/boot.md`) | 4-level paging only |
| XSAVE (CPUID.1:ECX bit 26) | M3 checks it; M5 sets CR4.OSXSAVE and XCR0 in boot step 3 (`fpu::init`) | refuse to boot | eager FP switching ([FP and SIMD](#fp-and-simd)) |

"Refuse to boot" means that M3 checks CPUID [H12] before it changes any
state and panics with one line, `CPU lacks <features>`, naming every missing
feature, which reaches COM1 as a `KERNEL PANIC` line. XSAVE, which M5 first
uses, is checked from M3 with the rest. Hardening that is silently missing on one target is
hardening the M10 red team never tested. QEMU's default model lacks SMEP,
SMAP and XSAVE [H1], so from M3 xtask's `base_command()` passes
`-cpu max,la57=off`, and a scenario key `qemu_args:` appends arguments, so the
`cpu_refuse` scenario boots `-cpu qemu64`. `tools/hyperv/New-L4Vm.ps1` turns
processor compatibility mode off, and the M3 Hyper-V check confirms SMEP and
SMAP [H2]. The M3 boot summary prints the CPUID features the kernel requires and
the Meltdown line below. From M5 its `cpu:` line reads `CR0 0x80010033 CR4
0x340ee8 EFER 0xd01` on QEMU: M3's CR4 with OSFXSR, OSXMMEXCPT and OSXSAVE
added, and EFER with SCE ([FP and SIMD](#fp-and-simd), [Descriptor tables and
MSRs](#descriptor-tables-and-msrs)).

### The kernel half

| PML4 slot | Virtual range | Maps | Pages | Attributes |
| --- | --- | --- | --- | --- |
| 0 to 255 | `[0, 0x0000_8000_0000_0000)` | user mappings; empty in the kernel PML4 | | |
| 256 | `PHYS_MAP_BASE` + `[0, min(phys_map_size, 64 GiB))` | the direct map | 2 MiB; 4 KiB over the kernel image | RW, NX, global; WB or UC by the rules below; the image's `.text` and `.rodata` read-only |
| 257 to 510 | | nothing | | |
| 511 | `KERNEL_VIRT_BASE` to `__kernel_end` | the kernel image | 4 KiB | `.text` and `.hvcall` RX, `.rodata` R, `.rootimage` R NX until boot step 8 unmaps it, `.data` and `.bss` RW NX; global, WB; a hole under each stack |
| 511 | `KERNEL_DEVICE_BASE` = `0xFFFF_FFFF_FFE0_0000` to the top | the kernel device window | 4 KiB | RW, NX, global, UC (PAT index 3) |

- **Direct-map cache types.** A 2 MiB page is WB if it overlaps a RAM-like
  region (`USABLE`, `LOADER`, `ACPI_RECLAIMABLE`, `ACPI_NVS`, `FIRMWARE`)
  and holds no kernel device page; every other 2 MiB page (gaps, `MMIO`,
  `RESERVED`, `BAD`, and any page holding a kernel device page) is UC. So no
  device register is ever reached write-back through the direct map, whatever
  the MTRRs say, and M4 makes no RAM untyped from a 2 MiB page holding a
  kernel device page. A 2 MiB page that mixes RAM with a hole (the
  legacy hole at `0xA0000`) is WB and relies on the fixed-range MTRRs [H10];
  M4 makes no device untyped from such a page.
- **Kernel device window.** One static page table of 4 KiB UC pages,
  reached through a static page directory in the image PDPT's entry 511. The
  kernel touches device registers only here, never through the direct map:

  | Page | Offset | Maps the 4 KiB page holding |
  | --- | --- | --- |
  | 0 | `0x0000` | the local APIC (`IA32_APIC_BASE`) |
  | 1 to 4 | `0x1000` to `0x4000` | I/O APIC 0 to 3, in MADT order |
  | 5 | `0x5000` | the HPET (ACPI `HPET` table) |
  | 6 to 511 | | nothing |

  The kernel adds each register block's offset within its page. A user
  device frame never covers these pages: M4 makes them no untyped
  ([Untyped](#untyped)).
- **No writable alias of kernel text.** The direct map maps the 2 MiB
  regions that cover `[kernel_phys_base, kernel_phys_base + kernel_size)`
  with 4 KiB pages: the image's `.text`, `.hvcall` and `.rodata` read-only,
  `.rootimage` read-write, since M5 reclaims it as RAM untyped and nothing
  executes it, the rest of those regions as the 2 MiB rule says, everything
  NX. After M3
  no alias of the image is weaker than its mapping at `KERNEL_VIRT_BASE`,
  except `.rootimage`, which is writable and never executed there and becomes RAM untyped in M5.
- **Hypercall page.** `.hvcall` is a page-aligned 4 KiB section
  in the text segment, mapped RX at `KERNEL_VIRT_BASE`; M9 points
  `HV_X64_MSR_HYPERCALL` at it ([Hypercalls](#hypercalls-m9)).
- **Guard pages.** The kernel stack and the four IST stacks each have
  an unmapped 4 KiB page below them: the linker script reserves the holes
  and the M3 table builder skips them, both at `KERNEL_VIRT_BASE` and in the
  direct map's 4 KiB alias of the image. An overflow takes a page fault and
  then a double fault on IST1 (the `stack_overflow` and `nmi_stack`
  scenarios). An overflow of IST1 itself does not end in a triple fault:
  the page fault in IST1's guard page becomes another double fault, whose
  delivery reloads RSP from the TSS, the top of IST1, so the handler runs
  again over the first one's frames (the `df_stack` scenario). The second
  panic finds the first under way and exits without a report, so the first
  report may be cut short; nothing runs on. This closes the STATUS.md open
  issue.
- **From what memory.** The kernel's tables are static, in `.bss`: the
  kernel PML4; the direct-map PDPT, 64 page directories (256 KiB, enough for
  64 GiB of 2 MiB pages) and 9 page tables for the image's alias; the image
  PDPT, PD and 8 page tables; the device window's PD and page table: 87
  pages, 348 KiB, more than half of the 600 KiB debug image at the end of M3.
  Nothing comes from the memory map, so M4 reserves no pages for them beyond
  the image; the builder refuses tables outside the image's data. Every
  kernel entry has Accessed preset, and every writable kernel leaf Dirty, as
  Linux presets them, so the CPU never writes the kernel's tables and the
  kernel reads them after boot as plain shared data. The kernel itself
  writes them once after M3: boot step 8 clears the PTEs of `.rootimage`
  (`arch::paging::unmap_rootimage`).
- **Bounds.** The direct map covers at most 64 GiB: the loader allocates below
  64 GiB, M3 panics if the kernel image, the handoff or its memory map ends
  above the direct map, and RAM above it becomes no untyped
  ([ADR 0006](adr/0006-direct-map-bound.md)). The image, `.rootimage`
  included, is at most `KERNEL_IMAGE_MAX` = 16 MiB: `kernel/linker.ld` asserts
  it, and from M5 xtask strips `root` before embedding it and checks the
  kernel against the limit. M3 also panics if a 2 MiB page the image touches
  overlaps no RAM-like region, since the direct map would map the image UC,
  and unless `.text` (with `.hvcall`), `.rodata` and `.data` (with `.bss` and
  the stacks) tile `[KERNEL_VIRT_BASE, KERNEL_VIRT_BASE + kernel_size)` in
  that order with no gap: `l4core::vspace::KernelLayout` names those three
  ranges and, from M5, `.rootimage`'s, which `KernelLayout::check` requires
  to be whole pages of rodata. `kernel/linker.ld` puts it at the end of
  rodata, so `__rodata_end` equals `__rootimage_end`. The table builder maps
  it R at `KERNEL_VIRT_BASE` and RW in the direct map; without that field the
  direct map would map it read-only, and resetting the untyped that cover
  it after step 8 would fault in ring 0.
- **Sharing.** Kernel PML4 entries 256 and 511 point at the kernel's PDPTs
  with U/S = 0. Retyping a PML4 copies entries 256 to 511 from the kernel
  PML4, as seL4's `copyGlobalMappings` copies its kernel slots (511 only, or
  from the TLB-bitmap slot below it on SMP: `TLBBITMAP_PPTR`,
  `src/arch/x86/64/kernel/vspace.c`). The copy is the `init_object` hook's
  (`l4core::vspace::init_pml4`); boot step 8 calls the hook on the root
  PML4, which is not retyped. The kernel writes its PML4 only
  in the M3 boot sequence, before any PML4 can be retyped, and no invocation
  can write a slot above 255 ([user range](#user-address-range)), so every
  PML4's upper half stays equal to the kernel's. A later change to the kernel
  half (M5 reclaiming the embedded root-task image) happens below the PML4
  level, which every PML4 shares, and ends with a CR4.PGE toggle [H4].
- **Kernel-only address space.** The kernel PML4 is the address space of the
  idle thread and of any thread without a valid VSpace. Its lower half
  is empty after M3.

PAT, programmed by M3 before it switches CR3 (the loader's tables use only
index 0, whose type does not change):

| Index | PAT, PCD, PWT | Type | Used for |
| --- | --- | --- | --- |
| 0 | 0, 0, 0 | WB | the kernel image, RAM in the direct map, user RAM frames |
| 1 | 0, 0, 1 | WT | not used |
| 2 | 0, 1, 0 | UC- | not used |
| 3 | 0, 1, 1 | UC | the kernel device window; direct-map pages without RAM or with a kernel device page; user device frames mapped `Uncached` |
| 4 | 1, 0, 0 | WC | user device frames mapped `WriteCombining` (the framebuffer) |
| 5 to 7 | | WT, UC-, UC | not used |

`IA32_PAT` (MSR `0x277`) = `0x0007_0401_0007_0406` [H8]. Entries 0 to 4 are
what seL4 writes (`init_pat_msr`, `src/arch/x86/kernel/vspace.c`); seL4
leaves entries 5 to 7 as it finds them, and microL4 writes the power-on
values there, so the whole MSR is fixed. QEMU reads
`0x0007_0406_0007_0406` before the write, whose entries 5 to 7 match (the
`paging` scenario's boot log prints the value found; a host test in
`l4core::vspace` pins it).

M3 boot sequence, in this order:

1. Check CPUID; refuse to boot if a required feature is missing. Panic if
   the kernel image, the handoff or its memory map ends above 64 GiB.
2. Load the kernel's GDT, TSS and IDT
   ([Descriptor tables and MSRs](#descriptor-tables-and-msrs),
   [Vector map](#vector-map)).
3. Find the kernel device pages: the local APIC from `IA32_APIC_BASE`, the
   I/O APICs from the MADT and the HPET from its table, read by the ACPI
   parser ([ACPI and the timer](#acpi-and-the-timer)) through the loader's
   direct map. No device
   register is touched yet.
4. Check EFER.NXE and CR0.WP, then program `IA32_PAT`.
5. Build the tables in `.bss` from the handoff's `kernel_phys_base`,
   `kernel_size`, memory map and `phys_map_size` and the device pages, with
   the type of each direct-map page computed by `core`.
6. Set CR4.SMEP, CR4.SMAP, CR4.PGE, and CR4.UMIP if present.
7. Load CR3 with the kernel PML4, then clear and set CR4.PGE, which drops
   every translation the firmware or loader left, global ones included [H4].

After step 7 the lower half is empty and the loader's 1:1 map is gone; the
`LOADER` pages that held the loader's tables are free for M4.

**Meltdown is an accepted risk in v0.** The upper half is present,
supervisor-only, in every address space, so on a CPU open to rogue data
cache load a ring-3 task can read all RAM through the direct map. There is no
counterpart of seL4's skim window. M3 reads `RDCL_NO` when the MSR exists
[H14] and prints `cpu: meltdown: vulnerable`, `cpu: meltdown: not
vulnerable` or `cpu: meltdown: unknown`; the Hyper-V check records the line
in `STATUS.md`, and M10 lists the risk. TCG's `-cpu max` does not report
`IA32_ARCH_CAPABILITIES`, so QEMU boots print `unknown`.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| User code runs only in ring 3 and in 64-bit mode | the GDT has no DPL-3 32-bit code descriptor and there is no LDT; user CS and SS are fixed selectors, never taken from user registers: `l4core::entry::exit_frame` writes constants, and `test=ring3` finds them in every frame from ring 3 | M3, M5 |
| The kernel never runs without NX, PGE, PAT, SMEP, SMAP and XSAVE | `arch::check_cpu` before any other M3 step; the `cpu_refuse` scenario boots `qemu_args: -cpu qemu64` and expects one `CPU lacks` line naming SMEP, SMAP and XSAVE | M3 |
| CR0.WP, EFER.NXE, CR4.SMEP, CR4.SMAP and CR4.PGE are set before the first user instruction and never cleared | M3 init; the boot summary prints CR0, CR4 and EFER and a scenario matches the line | M3 |
| Every boot states its Meltdown exposure | M3 prints `cpu: meltdown: vulnerable`, `not vulnerable` or `unknown` from `RDCL_NO`; a scenario matches the line; the Hyper-V check records it in `STATUS.md`; M10 lists the accepted risk | M3, M10 |
| Kernel code always runs with RFLAGS.AC = 0 and DF = 0 | `IA32_FMASK` includes AC and DF; `clac` and `cld` at every exception and interrupt entry; review of `arch` entry code; `test=ring3` reads RFLAGS at every entry from ring 3, one of them a `syscall` with DF and AC set | M3, M5 |
| The kernel never executes `stac` | CI grep over `kernel/` | M3 |
| Ring 3 cannot use I/O ports directly | IOPL 0 in every user RFLAGS (`exit_frame` clears it at every exit, and `l4core::regs::sanitise` at every register write); the TSS denies every port | M3, M5 |
| Every upper-half translation is supervisor-only; no user-accessible translation is global | kernel PML4 entries 256 to 511 have U/S = 0; the `core` leaf encoder always sets U/S and never sets G; `test=vspace` walks a mapped user page and finds it user and not global | M3, M5 |
| Every PML4's entries 256 to 511 equal the kernel PML4's | the `init_object` hook copies them into every new PML4 and the root PML4 (host test `a_new_pml4_gets_the_kernel_half_and_nothing_else`, `test=vspace`); the kernel PML4 is written only in the M3 boot sequence, and step 8 changes only a page table below it; user mappings end below `USER_TOP`; `arch::paging::set_vm_root` checks entries 256 and 511, and every one in debug builds, before it loads a PML4 | M3, M5 |
| No address space contains the loader's 1:1 map | the kernel PML4's lower half is empty after M3's CR3 switch and PGE toggle; `init_pml4` copies only entries 256 to 511 | M3, M5 |
| The kernel reaches device registers only through the UC device window, and no 2 MiB direct-map page holding a kernel device page or no RAM is WB | the M3 table builder; `l4core::vspace::direct_map_type`, host tests on the QEMU and Hyper-V memory maps and MADTs; M4 makes no RAM untyped from a 2 MiB page holding a kernel device page | M3, M4 |
| The page below the kernel stack and below each of the four IST stacks is unmapped | linker-script holes; the M3 table builder skips them; a scenario overflows the kernel stack and expects the double-fault report | M3 |
| No mapping of kernel text or read-only data is writable, and no mapping of kernel data is executable; the one exception is the direct-map alias of `.rootimage`, which is writable and never executed | M3 image tables from the linker sections; the direct map's 4 KiB pages over the image; CR0.WP; NX required; a host test of the table builder over each alias | M3 |
| The kernel image, the handoff and its memory map lie inside the direct map | the loader allocates below 64 GiB; M3 panics otherwise | M3 |
| The kernel image, `.rootimage` included, is at most 16 MiB | `kernel/linker.ld` assertion (M3); xtask strips `root` before the kernel embeds it and checks the built kernel against `KERNEL_IMAGE_MAX` (`xtask/src/compile.rs`) | M3, M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| SMEP and SMAP are turned on only if CPUID reports them; SMAP stays off with `CONFIG_PRINTING`, and both stay off with `CONFIG_DANGEROUS_CODE_INJECTION` (`src/arch/x86/kernel/boot.c`, `init_cpu`) | both required; the kernel refuses to boot without them | hardening absent on one target goes untested; microL4's debug output never reads user memory |
| No `clac` anywhere in `src/` or `include/`. `traps.S` (`handle_interrupt`) says why: AC "is not relevant for seL4, the kernel does not access user pages outside debug configs and SMAP is turned off on debug" | `clac` in every exception and interrupt stub | microL4's kernel never touches user pages either ([Kernel execution model](#kernel-execution-model)), so this is defence in depth: delivery does not clear AC [H3], and without `clac` a thread could switch SMAP off for the kernel entry it triggers, removing the net under that rule |
| No NX: every `xd` field is 0, in the kernel window (`map_kernel_window`) and in user entries (`makeUserPTE`, `src/arch/x86/64/kernel/vspace.c`), and EFER.NXE is never set (`src/arch/x86/64/head.S` sets only LME and SCE) | NX required; kernel data, the direct map and user pages without the execute attribute are NX | W^X for the kernel costs nothing on both targets |
| The kernel image is reached through the kernel window's 2 MiB or 1 GiB pages, writable and executable, so kernel text is writable (`map_kernel_window`) | 4 KiB image pages from the ELF sections: `.text` RX, `.rodata` R, `.data` and `.bss` RW NX; the direct map's alias of the image uses 4 KiB pages with text and rodata read-only | W^X for the kernel across every alias: a kernel write bug cannot patch kernel code |
| One PML4 slot, 511, holds the physical-memory window, the kernel ELF and the device window (`include/plat/pc99/plat/64/plat_mode/machine/hardware.h`) | slot 256 holds the direct map, slot 511 the image | the constants in [Kernel execution model](#kernel-execution-model) |
| The kernel window maps `[0, PADDR_TOP)`, 510 GiB, all write-back, with 1 GiB pages under `CONFIG_HUGE_PAGE` (`map_kernel_window`) | 2 MiB pages, WB only where RAM is and no kernel device page lies, UC elsewhere, at most 64 GiB; the loader allocates below 64 GiB | no write-back mapping of device memory; `qemu64` may lack 1 GiB pages [H1]; the tables fit in 348 KiB of `.bss` |
| Kernel devices get their own uncached window at `KDEV_BASE` = `0xffffffffc0000000`: the local APIC, then the I/O APICs, then IOMMUs (`map_kernel_window_devices`, `src/arch/x86/kernel/vspace.c`; `hardware.h`) | the same idea at `KERNEL_DEVICE_BASE` = `0xFFFF_FFFF_FFE0_0000`: the local APIC, four I/O APIC pages, the HPET; no IOMMU | the last 2 MiB need one page table; the HPET calibrates the timer on QEMU ([The timer](#the-timer)) |
| Skim window against Meltdown, on by default on x86_64 (`KernelSkimWindow` in `src/arch/x86/config.cmake`; `map_skim_window`): user address spaces map only a small kernel window, and kernel mappings are then not global (`KERNEL_IS_GLOBAL`) | none; M3 prints whether the CPU is vulnerable | accepted risk in v0: a skim window needs separate kernel and user tables and non-global kernel pages; instead every boot says whether its CPU is exposed (TCG's `-cpu max` does not report `IA32_ARCH_CAPABILITIES`, so QEMU boots say `unknown`; the owner's Hyper-V host says `not vulnerable`) |
| GDT: TSS at index 3, user code and data at 5 and 6, FS and GS descriptors (`include/arch/x86/arch/64/mode/object/structures.h`); `IA32_STAR[63:48]` = `SEL_CS_3` = `0x2B` (`init_syscall_msrs`), so `sysretq` loads CS `0x3B`, the FS descriptor's slot, while `iretq` uses `0x2B` | user data 3, user code 4, TSS 5, no FS or GS descriptor; `IA32_STAR` = `0x0013_0008_0000_0000` | `sysretq` selector arithmetic lands on matching descriptors; FS and GS bases go through MSRs ([FS and GS base](#fs-and-gs-base)) |
| UMIP not used (no mention in `src/` or `include/`) | on when present | free; protects nothing secret here |

## Address spaces

microL4 has seL4's x86_64 paging objects (PML4 as the VSpace, PDPT,
PageDirectory, PageTable, 4 KiB and 2 MiB frames), mapped by invoking the
lower object with the VSpace as an argument, but no ASIDs: every paging
structure carries a back-reference array naming the capability that
installed each of its entries, and every mapped capability names its entry
([ADR 0005](adr/0005-paging-back-references.md)). PCID is off.

### Objects

| Type | Object | Size | Layout |
| --- | --- | --- | --- |
| 5 | Frame, 4 KiB | 2^12 | the page |
| 6 | Frame, 2 MiB | 2^21 | the page |
| 7 | PageTable | 2^13 | the 4 KiB hardware table, then 512 back-references |
| 8 | PageDirectory | 2^13 | as PageTable |
| 9 | PDPT | 2^13 | as PageTable |
| 10 | PML4 | 2^13 | as PageTable; back-references 256 to 511 stay zero |

A back-reference is a word: 0 for none, or the physical address of the
capability slot holding the capability that installed the entry, with bit 0
set. Retype zeroes the object, so a new paging structure has no entries and
no back-references; a new PML4 then gets entries 256 to 511 from the kernel
PML4. Device untyped retype only into frames and device untyped, and device frames are not
zeroed ([Retype](#retype)).

### Capabilities

| Capability | Fields |
| --- | --- |
| Frame | `base`: physical frame number, 40 bits (device frames may lie above the direct map); `size`, 1 bit; `device`, 1 bit; `read` and `write` rights ([Rights](abi.md#rights)); `mapped`, 1 bit; `table`: physical address of the table holding the entry, shifted right by 13, 23 bits; `vaddr` of the mapping shifted right by 12, 35 bits, whose bits 12 to 20 (4 KiB) or 21 to 29 (2 MiB) are the entry index |
| PDPT, PageDirectory, PageTable | `base`, 23 bits; `mapped`, 1 bit; parent `table`, 23 bits; `index`, 9 bits |
| PML4 | `base`, 23 bits |

The capability's header word ([Capability
representation](#capability-representation)) holds the type, the object
address, the size, the rights and the `device` bit; the mapping record
(`mapped`, `table`, and `vaddr` or `index`: at most 59 bits) is its one `data`
word. Paging structures and the tables they sit in are always RAM inside the
direct map, so 23 bits of an 8 KiB-aligned address suffice. The record is 0
when the capability is unmapped (`l4core::vspace::paging`, `FrameMapping`
and `TableMapping`):

| Bits | Frame | PDPT, PageDirectory, PageTable |
| --- | --- | --- |
| 0 | `mapped`, 1 | `mapped`, 1 |
| 1 to 23 | `table >> 13` | parent `table >> 13` |
| 24 to 58 | `vaddr >> 12` | `index`, bits 24 to 32 |

Recording a table at or above `STRUCTURE_LIMIT` = 2^36 (64 GiB, the direct
map's bound) panics, and so does reading a non-zero record without bit 0.
Derivation rules, which the capability core applies in M2:

- Copying or minting a frame capability gives an unmapped capability, as in
  seL4 (`Mode_deriveCap`). Each copy maps at most one page. Sharing memory
  means mapping two copies.
- PDPT, PageDirectory and PageTable capabilities fail `derive` with
  `IllegalOperation`: Copy and Mint fail, and IPC transfer stops at
  them without an error ([Capability transfer](#capability-transfer)). They
  can be moved. So
  each paging structure has exactly one capability, which holds its mapping
  state, and is mapped at most once.
- PML4 capabilities derive freely and carry no mapping state. A TCB names
  its VSpace with such a copy in a TCB slot ([TCB layout](#tcb-layout)), so
  a PML4 cannot be freed while a TCB names it.
- Moving a mapped frame or paging-structure capability rewrites the
  back-reference in its table to the new slot. The capability core's
  `Kernel` trait has `moved(cap, old_slot, new_slot)`, called after
  `CNode_Move`, `CNode_Mutate`, both halves of `CNode_Rotate`, the Rotate
  swap, every Zombie swap and `CNode_SaveCaller`. M2 defines and calls the
  hook; M5 fills it in (`arch::paging::moved`, over
  `l4core::vspace::moved`), which checks the link from the old slot and
  that the new slot holds the capability before it rewrites the
  back-reference.

### Back-references instead of ASIDs

A seL4 mapping capability records (ASID, virtual address), a name that cannot
dangle, and unmap looks the VSpace up by ASID, walks to the entry and checks
that it still points at the frame (`unmapPage`, `findVSpaceForASID` in
`src/arch/x86/kernel/vspace.c`). PLAN.md drops ASID pools, so microL4 keeps
the link exact in both directions instead. For entry `i` of a live paging
structure `T`, in the user half:

| Name | Link invariant |
| --- | --- |
| L1 | entry `i` is present exactly when `T.backref[i]` is not 0 |
| L2 | if `T.backref[i]` names slot `S`, then `S` holds a frame or paging-structure capability whose mapping is (`T`, `i`), and entry `i` points at that capability's object |
| L3 | if the capability in slot `S` has mapping (`T`, `i`), then `T` is a live paging structure one level above the capability's object and `T.backref[i]` names `S` |

Unmapping a frame clears one entry and one back-reference with no lookup;
deleting a structure visits its own 512 back-references and nothing else.
Nothing points at a dead structure or an empty slot, so there is no stale
state to validate and no ASID to exhaust or reuse. Structures and frames
detach before they die, so a walk from a live PML4 touches only live tables;
a structure is mapped at most once, into one reachable from a PML4, so the
structures under each PML4 form a tree. The price is 8 KiB structures,
uncopyable table capabilities, and one more write per slot move. A broken
link is a dangling pointer, so one `core` module makes every write to
entries, back-references and mapping fields, under a proptest model (M5).
[ADR 0005](adr/0005-paging-back-references.md) compares this with ASID
pools and a kernel-static ASID table.

Every use of a link checks it in both directions first, and panics on a
mismatch. Before writing through a capability's mapping (`T`, `i`), the
kernel checks that `T.backref[i]` names the capability's own slot; before
acting on `T.backref[i]` = `S`, it checks that `S` holds a capability whose
mapping is (`T`, `i`) and whose object entry `i` points at. One extra read
turns a broken link into a panic instead of a write into reused memory. Each
step of a table walk checks the link of the entry it follows. The kernel's
`finalise` hook is not told the deleted capability's slot, so for a mapped
Frame or paging structure the paging code takes the slot its
back-reference names, checks that the slot holds exactly that capability,
then checks the link both ways.
Whether a structure is empty, which Map requires, is a scan of its 512
back-references (L1); 8 KiB leaves no room for a counter.

### User address range

| Constant | Value | Meaning |
| --- | --- | --- |
| `USER_MIN` | `0x0000_0000_0000_1000` | lowest address a frame may map; page 0 never maps |
| `USER_TOP` | `0x0000_7FFF_FFFF_F000` | a frame mapping must end at or below it |

- A frame of size `s` maps at `vaddr` only if `vaddr` is `s`-aligned,
  `vaddr >= USER_MIN` and `vaddr <= USER_TOP - s` (no overflow). A paging
  structure maps at `vaddr` rounded down to the span it covers (512 GiB,
  1 GiB, 2 MiB), and that base must be below `USER_TOP`; as in seL4, the
  low bits are ignored.
- **The kernel half cannot be mapped.** `USER_TOP` is below 2^47, so no
  mapping reaches PML4 slot 256 or the non-canonical hole. The range check
  runs before any table walk.
- **The last page below the hole never maps.** A `syscall` in the last two
  bytes of that page would return to `0x0000_8000_0000_0000`, which is not
  canonical, and `sysretq` would raise #GP in ring 0 [H9]. With that page
  unmappable, user code reaches a non-canonical RIP only through register
  writes, which the exit path must check anyway
  ([The non-canonical RCX problem](#the-non-canonical-rcx-problem); seL4
  sanitises RIP in `Mode_sanitiseRegister`). seL4 gets the same bound from
  `USER_TOP` = `0x7FFFFFFFFFFF` and its `vtop > USER_TOP` check
  (`decodeX86FrameInvocation`), for this reason (the comment on `USER_TOP` in
  `include/plat/pc99/plat/64/plat_mode/machine/hardware.h`); libsel4's
  `seL4_UserTop` is `0x00007ffffffff000`, microL4's `USER_TOP`.
- **Page 0 never maps**, so a null pointer in user code always faults. It
  costs one comparison; no 2 MiB frame can map at 0.

### Mapping

Table maps (`PDPT_Map`, `PageDirectory_Map`, `PageTable_Map`) take the VSpace
capability and an address. As in seL4, decoding checks everything before
anything changes: the message and extra capability, that the extra capability
is a PML4, that the structure is unmapped and empty, the range, that the
walk from the PML4 finds present tables down to the level above, and that the
target entry is not present. Then the kernel writes the entry (P, R/W and U/S
set; XD, PWT and PCD clear [H7]), the back-reference and the capability's
mapping. No flush is needed [H6]. Errors are in
[`abi.md`](abi.md#pdpt_map-pagedirectory_map-pagetable_map).

`Frame_Map` takes the VSpace, an address, a rights word and an attributes
word:

- **Rights.** The mapping gets the requested rights masked by the
  capability's `read` and `write`, silently, as in seL4. A result without
  `read` is refused: x86 cannot express write-only, and seL4's answer, a
  supervisor-only entry in the user half (`maskVMRights` returning
  `VMKernelOnly`), would break "every user-half leaf is user-accessible".
- **Execute** is an attribute bit, off by default (NX), not a capability
  right. Whatever a task can read it can copy into a frame it can execute,
  so execute permission confers no authority; it is a mapping choice, as
  `seL4_ARM_ExecuteNever` is on Arm. A read-only frame capability maps
  read-only or read-execute, never writable.
- **Cache type**: `WriteBack` (PAT index 0), `Uncached` (3) or
  `WriteCombining` (4). A RAM frame maps only `WriteBack`; a device frame
  maps only `Uncached` or `WriteCombining`. The direct map is WB over RAM and
  UC over, or absent from, the pages device untyped come from, so no
  physical page is ever mapped both cacheable and uncacheable [H8]. A device
  frame mapped WC keeps a UC alias in the direct map. The SDM allows no
  mixed-type alias at all, so this is an accepted deviation: both types are
  uncacheable, and the kernel never touches that alias [H8].
- The capability must be unmapped, the address aligned and in range, the
  table at the mapping level present (a PageTable for 4 KiB, a PageDirectory
  for 2 MiB) and the target entry not present, whatever it holds. Then the
  kernel writes the entry, the back-reference and the capability's `table`
  and `vaddr`. No flush is needed [H6].

`Frame_Remap` changes the rights and attributes of the capability's existing
mapping, with the same checks, and flushes the page. An ELF loader maps a
segment writable, fills it, then remaps it read-execute. `Frame_Unmap`
removes the mapping and flushes the page; on an unmapped capability it does
nothing. `Frame_GetAddress` returns the physical address, for DMA; any
frame capability may ask, as in seL4. It is built in M9; until then its
label returns `IllegalOperation`. A table's `Unmap` detaches it and then
empties it: every child capability becomes unmapped and every entry and
back-reference is cleared; then CR3 is reloaded. On an unmapped, empty
structure it does nothing.

### Deletion

| Event | Kernel action | Flush |
| --- | --- | --- |
| A mapped frame capability (any copy) is deleted | as `Frame_Unmap` | `invlpg` |
| A PDPT, PageDirectory or PageTable capability is deleted (always the only one) | as its `Unmap`: detach, then empty; child structures keep their own entries | CR3 reload |
| A structure's parent is unmapped or deleted, which empties the parent | the structure becomes unmapped but keeps its own entries. It is unreachable, so no translation uses it; Map refuses it until its own `Unmap` empties it | the parent's |
| A PML4 capability that is not the last is deleted | nothing; if it was the running thread's VSpace slot, the exit path loads the kernel PML4 | CR3 write at exit |
| The last PML4 capability is deleted | if CR3 holds it, load the kernel PML4 first (`arch::paging::finalise`); then clear entries 0 to 255 and the mappings of the PDPT capabilities their back-references name (`l4core::vspace::finalise`, which returns `Flush::None`) | the CR3 write, if it was loaded; else none, since the TLB holds translations of the loaded PML4 only |
| A mapped capability is moved | rewrite its back-reference | none |
| An untyped is revoked | each descendant is deleted as above, with the revoke loop's preemption points between capabilities ([Slot operations](#slot-operations)) | as above |

Each step touches at most 512 entries and never recurses, so it needs no
preemption point; seL4's `flushTable` loop is the same size. A VSpace deleted
under a running thread behaves as in seL4, whose `setVMRoot` switches to the
global VSpace when the thread's root is invalid
(`src/arch/x86/64/kernel/vspace.c`): the thread resumes on the kernel PML4,
its next instruction fetch faults, and the fault goes to its fault endpoint
([Faults](#faults)).

### TLB maintenance

PCID is off: CR4.PCIDE is never set, and every CR3 write drops all non-global
translations [H4], so the TLB holds user translations only for the PML4 in
CR3. Stale translations can therefore arise only in the loaded VSpace, and
only when the kernel changes or removes a present entry.

| Change | Flush | Done by |
| --- | --- | --- |
| A user entry goes from not present to present (any Map) | none [H6] | |
| A user leaf is cleared, or its rights, cache type or execute bit change (`Frame_Unmap`, `Frame_Remap`, frame deletion) | `invlpg vaddr` [H5] | `Flush::Page` |
| A user non-leaf entry is cleared, or a structure is emptied (table `Unmap`, structure deletion) | CR3 reload | `Flush::All` |
| The next thread's VSpace differs from the loaded PML4 | CR3 write | exit path |
| The loaded PML4 is finalised | CR3 = kernel PML4 | PML4 finalisation |
| The kernel half changes (M3 boot, M5 root-image reclaim) | CR4.PGE toggle | boot code |

Flushes do not depend on which VSpace is loaded: an `invlpg` for an unloaded
VSpace drops at worst one unrelated translation of the loaded one, and a
spurious CR3 reload costs a refill. A reviewer checks one thing: every `core`
operation that clears or changes a present entry returns the flush the table
names, and `arch` applies it after `core` returns and before returning to user
mode. An invocation returns only a `Reply`, so `l4core::vspace::invoke` hands
its flush to `PagingStore::flush` inside the call, after the writes; the
kernel's `finalise` and `moved` hooks apply theirs themselves. Both end in
`arch::paging::apply`. The flush must follow the entry write: the CPU may
refill the TLB from a still-present entry at any moment, speculatively and in
ring 0 [H13], so a flush issued first could be undone before the write.
Returning `Flush` from the operation that wrote the entry gives that order by
construction. A missed flush lets a thread keep using a frame after unmap; if
the frame is then retyped into a kernel object, the thread can write that
object. A missed reload after a table detach lets the CPU keep walking, and
setting accessed and dirty bits in, a table whose memory may be retyped. TCG
hides both (PLAN.md), so the host model below checks them.

### Where the code lives

- `l4core::vspace` (`core/src/vspace.rs`): the constants; entry encoding; the
  type of each direct-map page and the kernel's tables (M3).
- `l4core::vspace::paging` (`core/src/vspace/paging.rs`, M5): the user half.
  The mapping records; range, rights and attribute checks; map, remap, unmap,
  table unmap, deletion (`finalise`) and the move hook (`moved`); a new PML4's
  kernel half (`init_pml4`); `translate`, a walk for tests; and boot step 8's
  helpers, `TableCounts::covering`, `map_boot_tables` and `map_boot_frame`. It
  is written against two traits: `PagingStore`, which reads and writes an
  entry or a back-reference of the structure at a physical address and applies
  a flush, and the capability core's slot store (M2). Every operation that can
  change a present entry returns a `#[must_use]` `Flush`: `None`,
  `Page(vaddr)` or `All`. It is the only code that writes user entries,
  back-references and mapping records.
- `l4core::vspace::decode` (M5): the PDPT, PageDirectory, PageTable and Frame
  labels, the label checked before the length and every later error in
  `docs/abi.md`'s order; `l4core::invoke` sends those capabilities here, and a
  PML4 capability has no invocations (`IllegalOperation`).
- Tests: `paging_tests.rs` covers the bounds at both ends and around 2^47,
  every error row, the record's extremes, each flush, and one test per broken
  link that expects the panic. `model_tests.rs` is the proptest: 512 random
  sequences of map, remap and unmap invocations through `l4core::invoke`, and
  of deletes, revokes preempted at random points and restarted, copies, moves,
  rotates and swaps through the capability core, with nested CNodes carrying
  mapped capabilities into Zombie swaps. A model of the mappings predicts each
  result and flush; after every step memory must equal the model, L1 to L3 and
  the tree shape must hold, and a TLB model, which cached every translation of
  the loaded PML4 before the step and before every hook, must agree with the
  tables once the step's flushes are applied. Planted in M5, a missing
  `invlpg`, a missing CR3 reload, a back-reference left unrewritten, a skipped
  unmap and a wrong index each failed it.
- `kernel/src/arch/x86_64/paging.rs`: `PagingStore` over the direct map;
  `apply(Flush)`, which holds the only `invlpg` and the only CR3 reload;
  `set_vm_root`, the only other CR3 write after boot (every exit to a thread,
  idling, and PML4 finalisation); the hooks `init_object`, `finalise` and
  `moved`; `unmap_rootimage` (boot step 8); the M3 table builder, the PAT and
  CR4 setup; and `test=vspace`. It reads the linker script's section bounds
  with `lea`, not as addresses of `extern` statics: the compiler assumes
  distinct statics have distinct addresses and folds
  `&__kernel_end == &__data_end` to false. `cpu.rs` checks the features.

| Part | Milestone |
| --- | --- |
| CPU features and the Meltdown line, PAT, kernel tables with the device window and the 4 KiB image alias, the five guard pages, dropping the 1:1 map, the loader's 64 GiB bound, xtask's CPU model and `qemu_args:` | M3 |
| Frame and table derivation rules, the `moved` hook and its calls | M2 |
| No device untyped from a write-back direct-map page; no RAM untyped from a 2 MiB page holding a kernel device page | M4 |
| Paging objects, all invocations but `Frame_GetAddress`, back-references and their two-way checks, flushes, CR3 switching; xtask's image-size check | M5 |
| `Frame_GetAddress` | M9 |
| Red-team briefs 4 (address spaces) and 5 (entry and exit) | M10 |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every frame mapping lies in `[USER_MIN, USER_TOP)`; no invocation writes a PML4 entry above 255 | the range checks of `l4core::vspace::paging::map_frame` and `map_table` run before any walk, and the table code asserts that no back-reference above 255 is used; host tests `frame_map_errors_in_abi_order` and `table_maps_ignore_the_low_bits_and_reach_the_top` at both bounds and around 2^47; `test=vspace` maps the highest page and is refused the page below the hole | M5 |
| L1, L2 and L3 hold after every operation | `l4core::vspace::paging` writes all entries, back-references and mapping fields; `moved(cap, old_slot, new_slot)` runs after every Move, Mutate, both halves of Rotate, the Rotate swap, every Zombie swap and `CNode_SaveCaller`; the M2 proptest covers nested CNode deletion with mapped capabilities in slot 0 and random preemption; M5's `model_tests.rs` proptest checks L1 to L3 against a model of the mappings after every step, through preempted revokes and Zombie swaps of mapped capabilities | M2, M5 |
| Every use of a back-reference or mapping field first checks the link in both directions, and a mismatch panics instead of writing | `l4core::vspace::paging` checks the link before each write through it and at each walk step, and `finalise` checks that the slot a back-reference names holds exactly the deleted capability; seven host tests each break a link and expect the panic | M5 |
| A present entry points at a live object of the right kind | frames and structures detach before they die: the `finalise` hook unmaps them while their slot still holds them (`arch::paging::finalise`); the link checks compare each entry with its capability's object and type; the `model_tests.rs` proptest | M5 |
| A paging structure is mapped at most once, only when empty, and only into a structure reachable from a PML4, so mappings form trees | derivation refuses table capabilities; `map_table` refuses a mapped or non-empty structure (`InvalidCapability` 0) and walks from the PML4; host test `table_map_errors_in_abi_order`; the proptest checks the tree shape; `test=vspace` | M2, M5 |
| A frame capability maps at most one page; its copies start unmapped | derivation clears the mapping; `map_frame` refuses a mapped capability (`InvalidCapability` 0; host test `frame_map_errors_in_abi_order`) | M2, M5 |
| A mapping's rights never exceed its capability's; every user-half leaf has U/S = 1 and G = 0 | the rights mask in `l4core::vspace::paging` and the leaf encoders `user_pte` and `user_pde_2m`; host test `frame_rights_and_attributes_reach_the_entry`; `test=vspace` | M5 |
| No physical page is mapped both cacheable and uncacheable | `Attributes::decode` allows a RAM frame only `WriteBack` and a device frame only `Uncached` or `WriteCombining`; M4 makes no device untyped from a WB direct-map page; host tests `the_attributes_word` and `frame_map_errors_in_abi_order` | M4, M5 |
| Paging structures are made only from RAM untyped | the retype rule ([Retype](#retype)) | M2, M4 |
| Every change to a present user entry is followed by its flush before the next user instruction | `Flush` returned by `core`, applied by `arch::paging::apply` inside the invocation (`PagingStore::flush`) or the hook; the TLB model in the proptest and `the_tlb_model_catches_a_missing_flush`; `test=vspace` remaps a page and deletes a mapped page table; review; red-team brief 4 | M5, M10 |
| The TLB holds user translations only for the PML4 in CR3 | CR4.PCIDE never set; `set_vm_root` writes CR3 at every exit whose thread's PML4 differs from the loaded one | M3, M5 |
| CR3 always holds the kernel PML4 or a live PML4 | `arch::paging::finalise` loads the kernel PML4 before the loaded PML4's last capability is finalised; every exit calls `set_vm_root` with the capability in the thread's VSpace slot, and the idle path with none; `test=vspace` deletes the loaded PML4's last capability | M5 |
| Unmapping or deleting any paging object touches at most 512 entries | one loop over a structure's entries in `l4core::vspace::paging` (256 for a PML4), no recursion | M5 |
| A thread without a valid VSpace runs no user code | `set_vm_root` loads the kernel PML4, whose lower half is empty, for anything in the VSpace slot but a PML4 capability | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| ASID Control and ASID Pool objects; a VSpace must be assigned an ASID before use (manual `vspace.tex`, ASID Control and ASID Pool) | neither object; a PML4 is usable once retyped | PLAN.md drops ASID pools; back-references replace them ([ADR 0005](adr/0005-paging-back-references.md)) |
| A mapped capability holds (ASID, vaddr); unmap re-finds the entry through `findVSpaceForASID` and a walk, and does nothing if it no longer matches (`unmapPage`, `unmapPageTable`) | the capability holds its table and index; the table holds the slot; both are kept exact | O(1) unmap, no stale state, no ASID reuse ([ADR 0005](adr/0005-paging-back-references.md)) |
| Paging structures are 4 KiB (`seL4_PageTableBits` to `seL4_PML4Bits` = 12) | 8 KiB | the back-reference array |
| A PDPT, PD or PT capability can be derived only while mapped, and a PML4 capability only once it has an ASID (`Arch_deriveCap`, `Mode_deriveCap`); Unmap needs the final capability, else `RevokeFirst` | PDPT, PD and PT capabilities are never derived, so always final, and cannot travel by IPC; PML4 capabilities derive freely; no `RevokeFirst` | mapping state lives in the one capability; a delegated table cannot be revoked except through its untyped; a PML4 needs no assignment step |
| Deleting the last capability to a mapped PDPT, PD or PT only detaches it (`Arch_finaliseCap`, `Mode_finaliseCap` call `unmapPDPT`, `unmapPageDirectory`, `unmapPageTable`); its entries stay until its memory is retyped, and capabilities mapped through it keep a stale (ASID, vaddr) | detach, then empty, marking every child capability unmapped | L3: a mapped capability must name a live table |
| Table Map takes VM attributes for the table entry (`makeUserPDEPageTable`) | no attributes | uncached paging structures are never wanted |
| Unmap of a table clears its memory (`clearMemory`); a table orphaned by its VSpace's deletion keeps a stale mapped capability until Unmap | the same user-visible protocol: an orphan keeps its entries and must be unmapped before it is mapped again | matches seL4 |
| 1 GiB frames (`seL4_HugePageBits`, `CONFIG_HUGE_PAGE`) | not offered | the page sizes in [Kernel execution model](#kernel-execution-model) |
| User entries are never NX (`makeUserPTE`, `makeUserPDELargePage`) | NX unless the execute attribute is set | user space chooses execute per mapping; the kernel still allows RWX, so W^X is the loader's policy, not a kernel rule |
| Mapping without read gives a supervisor-only entry in the user half (`maskVMRights`, `SuperUserFromVMRights`) | refused, `InvalidArgument` | every user-half leaf is user-accessible |
| Any cache attribute on any frame: WB, WT, UC-, UC, WC (`seL4_X86_VMAttributes`) | RAM frames WB only; device frames UC or WC only | no WB/UC alias of one page [H8] |
| Map at the same address updates rights and attributes (manual `vspace.tex`, Mapping Attributes); a mapped capability given another VSpace fails with `InvalidCapability` (cap 1) and another address with `InvalidArgument` (arg 0) (`decodeX86FrameInvocation`) | a separate `Frame_Remap` on the existing mapping; `Frame_Map` on any mapped capability fails with `InvalidCapability` (cap 0) | the back-reference names the mapping, so VSpace and address need not be restated |
| The 4 KiB and 2 MiB map paths do not check whether the target entry already maps a frame (`createSafeMappingEntries_PTE`, `createSafeMappingEntries_PDE`), though the API XML lists `DeleteFirst` | `DeleteFirst` if the entry is present | one capability per entry (L1 to L3) |
| Without PCID, Map ends with a paging-structure-cache flush only (`invalidateLocalPageStructureCacheASID` runs `invlpg 0`), also when it changes rights | no flush after a fresh map [H6]; `invlpg vaddr` after `Frame_Remap` | a rights reduction must reach the TLB |
| Unmapping a PageTable flushes each present entry if its VSpace is loaded (`flushTable`); unmapping a PageDirectory or PDPT flushes the whole ASID, which without PCID is a CR3 reload (`flushPD`, `flushPDPT`, `invalidateLocalPCID`) | CR3 reload for every level, unconditionally | one rule a reviewer can check |
| PCID on by default, ASID = PCID (`KernelSupportPCID`, `makeCR3`) | PCID off | no ASIDs to tag with; correctness first on one core ([ADR 0005](adr/0005-paging-back-references.md)) |
| Page 0 may be mapped (no lower bound in `decodeX86FrameInvocation`) | `USER_MIN` = `0x1000` | null pointers always fault |
| Deleting a VSpace invalidates its ASID and calls `setVMRoot` (`deleteASID`); the PML4's entries stay, and every capability mapped under it keeps its stale (ASID, vaddr) until it is unmapped or deleted | switches CR3 to the kernel PML4 directly if it is loaded, and marks the PDPT capabilities named by back-references 0 to 255 unmapped; lower levels keep their entries, as orphans | no ASIDs; L3 |
| IOMMU and VT-x mappings: `X86PageMapIO`, `X86PageMapEPT`, IO page tables and EPT structures (`CONFIG_IOMMU`, `CONFIG_VTX`; `object-api-arch.xml`) | none | no IOMMU or VT-x in v0 ([Kernel objects](#kernel-objects)); device DMA is unchecked, recorded for M10 brief 7 (PLAN.md) |

## Boot

After the M0 handoff the kernel copies what it needs out of loader memory,
moves onto its own descriptor tables and page tables (M3), carves one boot
region from the top of RAM for the root task's objects, hands every other
usable page out as untyped through a two-page BootInfo (M4,
[ADR 0007](adr/0007-boot-region-and-bootinfo.md)), and enters the root task,
loaded from an ELF image embedded in the kernel, in ring 3 (M5).

### Boot sequence

| Step | Built in | What happens |
| --- | --- | --- |
| 1 | M0 | `_start` zeroes BSS, switches to the kernel stack and calls `rust_entry`, which sets up COM1; from M7 only in debug kernels ([Debug](#debug)) |
| 2 | M3 | CPU feature check: refuse to boot if a required feature is missing ([CPU features](#cpu-features)). `Handoff::validate`; panic if the kernel image, the handoff or its memory map ends above the kernel's direct map, `min(phys_map_size, 64 GiB)`, which the loader's 64 GiB allocation bound prevents ([ADR 0006](adr/0006-direct-map-bound.md)); then the handoff and its memory map (at most 256 regions, else panic) are copied into the static `BootState` (the kernel's own `.bss`; no CPU or firmware state changes before the feature check). No code reads `LOADER` memory after this, except the kernel image |
| 3 | M3, M5 | GDT, TSS, IDT ([Privilege levels](#privilege-levels)) and CR4.MCE; `IA32_GS_BASE` = the per-CPU area; DR7 = `0x400`, its reset value, no breakpoint enabled. The firmware's GDT, IDT and stack are now dead. From M5, the syscall MSRs ([Descriptor tables and MSRs](#descriptor-tables-and-msrs), `entry::init`), then CR0, CR4 and XCR0 for x87 and SSE ([Control registers and XCR0 (M5)](#control-registers-and-xcr0-m5), `fpu::init`), so the entry is ready long before anything runs in ring 3 |
| 4 | M3 | ACPI is parsed through the loader's direct map: the kernel device pages (the local APIC, at most four I/O APICs, the HPET), the ISA overrides and the ECAM ranges ([ACPI and the timer](#acpi-and-the-timer)). Then the kernel's page tables are built in `.bss`, with the kernel device window at `KERNEL_DEVICE_BASE`, and replace the loader's in the order [The kernel half](#the-kernel-half) gives (EFER.NXE and CR0.WP checked, `IA32_PAT`, the tables, CR4.SMEP, SMAP, PGE and UMIP, then CR3); the 1:1 map is gone |
| 5 | M3, M7 | Hyper-V's leftovers go first, since a synthetic timer the firmware left armed can interrupt, and the time-unhalted timer can raise an NMI ([Firmware leftovers](#firmware-leftovers-m3)); M3 records a hypercall page the firmware locked. Then the local APIC, with LINT0 masked before the PIC is reprogrammed, the PIC, the I/O APICs and the HPET are set up, and the local APIC timer and the TSC are calibrated in the same windows, giving `tsc_hz` ([Local APIC, PIC and I/O APIC (M3)](#local-apic-pic-and-io-apic-m3), [The timer](#the-timer)). The kernel device pages, the MSI window and a locked Hyper-V hypercall page are what step 6's plan keeps in `BootPlan.kernel_reserved`. From M7 the step also records the interrupt routes, each I/O APIC's pin count and version with the ISA routes (`l4core::irq::Routing`, `objects::init_interrupts`), and at its end the IRQ node's physical address (`objects::init`). Only now are `USABLE`, `LOADER` and `ACPI_RECLAIMABLE` pages free |
| 6 | M4, M5 | `.rootimage`'s ELF is checked (`l4core::boot::image::RootImage::check`) and `l4core::boot::plan` sizes the boot region for its needs; the kernel allocates and zeroes it |
| 7 | M4 | The root CNode is made in the boot region and the fixed capabilities written |
| 8 | M5 | The root ELF is copied from `.rootimage` into image frames; its VSpace, IPC buffer and TCB are built. `.rootimage` is unmapped from the kernel window, ending with a CR4.PGE toggle ([The kernel half](#the-kernel-half)) |
| 9 | M4 | `l4core::boot::untyped` computes the untyped; caps go into the CNode, descriptors and the rest of BootInfo into its frames |
| 10 | M5 | The root TCB goes to the scheduler, and the kernel leaves for it as every kernel entry ends ([Exit](#exit)): its FS and GS bases (0), its PML4 and its FP state are loaded, and it leaves by `iretq` |

The steps run in the order 6, 9, 7, 8, 10. `boot::make_root_space`
(`kernel/src/boot.rs`) runs `RootImage::check` and `l4core::boot::plan`
with the image's `RootNeeds` (step 6), zeroes the region through
`arch::Objects`, then calls `write_bootinfo` (step 9's untyped, slot plan
and BootInfo fields, written straight into BootInfo's frames) and
`write_root_cnode`, which puts the capabilities of steps 7 and 9 in the root
CNode together. Step 9 makes untyped that cover `.rootimage` before step 8
has unmapped it, which is safe because no untyped can be used before the
root task runs. Step 8 then:

1. calls the `init_object` hook on the root PML4, which is not retyped, for
   its kernel half;
2. maps the paging structures, then each image frame, the IPC buffer and
   BootInfo's two frames, in the order `l4core::boot::image::root_mappings`
   gives (tables first), with `l4core::vspace::map_boot_tables` and
   `map_boot_frame`, which write the mapping records `write_root_cnode`
   leaves empty, and copies each image page's file bytes into its frame as
   it maps it (`Objects::copy_into_frame`), the rest staying zero;
3. unmaps `.rootimage` from the kernel window, clearing its PTEs and
   toggling CR4.PGE (`RootImageSection::unmap`,
   `arch::paging::unmap_rootimage`); from then on `arch::Objects`' debug
   checks count its pages as memory kernel objects may occupy;
4. makes the root TCB: the `init_object` hook (`tcb::init`, the FP template),
   `tcb::init_root` ([Root-task entry state](#root-task-entry-state)), its
   master reply capability inserted as a derivation root in its `reply` slot,
   as retype gives every other TCB one, copies of root slots 2, 3 and 10 in
   its slots 0 to 2, each its original's only child, and its IPC buffer
   address.

Step 10 is `boot::start_root_task`: `sched::make_runnable` on the root TCB,
then `thread::exit_to_scheduled`. A `test=` the kernel knows runs instead of
step 10 ([The `debug` feature](#the-debug-feature)). `RootSpace` keeps no
reference to BootInfo: `make_root_space` returns one for the boot summary
and the self-tests, and step 10 abandons it with the kernel stack, before
the root task can write those frames. Each `BootError`, and each refusal of
the root image, is a panic with its reason; among them, `plan` refuses a
memory map that is unsorted, overlapping or not 4 KiB granular, and a
physical address width outside 32 to 52 bits.

The boot region now holds the root task's objects too. At the end of M5,
with a root image of 39 pages, it is 332 KiB on QEMU,
`[0xfea0000, 0xfef3000)`: the 128 KiB root CNode, the PML4, one PDPT, one
page directory and one page table, the IPC buffer, BootInfo's two frames, the
image frames and the TCB's page. Slot 1 holds the root TCB and slot 3 its
PML4; slots 12, 13 and 14 are null until M9. The frames in slots 9, 10 and 16, the image
frames and the paging structures are mapped. Every capability boot puts in
the root CNode is an original derivation root. (M4, with no root task, had a
140 KiB region: `[0xfec0000, 0xfee3000)` on QEMU and
`[0x1ff00000, 0x1ff23000)` on the recorded Hyper-V map.)

### What each physical page becomes

The rules are applied in this order, by `l4core::boot::page_class`; a later
row overrides an earlier one.

| Physical range | Becomes | Why |
| --- | --- | --- |
| `USABLE`, `LOADER`, `ACPI_RECLAIMABLE` | RAM untyped | the loader, its tables, the handoff and the map are dead after steps 2 and 4; ACPI is parsed in step 4 |
| `RESERVED`, `MMIO`, ranges absent from the map, below `2^phys_addr_bits` | device untyped | PCI BARs, ECAM ([Memory map](abi.md#memory-map)) |
| `ACPI_NVS`, `FIRMWARE`, `BAD`, and any kind number the handoff does not define | nothing | firmware-owned, broken or unknown |
| the kernel image, except `.rootimage` | nothing | |
| `.rootimage` | RAM untyped (from the `LOADER` row) | reclaimed in step 8 |
| the GOP framebuffer, page-rounded | its own device untyped, listed first; none at all, and its pages nothing, if any 2 MiB page it touches is write-back in the direct map, if it reaches below 1 MiB or past `2^phys_addr_bits`, or if it overlaps the kernel image, the boot region, a `kernel_reserved` page, or `ACPI_NVS`, `FIRMWARE`, `BAD` or unknown memory (a debug kernel warns with the reason) | `fb` (M8) gets all of it or none of it, and no untyped may cover the ranges named ([ADR 0024](adr/0024-framebuffer-untyped-rejections.md)) |
| any 2 MiB page the direct map maps write-back | no device untyped | a device frame would alias a WB mapping ([The kernel half](#the-kernel-half), H8); above the direct map's end nothing is mapped, so the rule stops there |
| any 2 MiB page holding a kernel device page | no RAM untyped | the direct map maps it UC, so a RAM frame there would alias |
| `[0, 1 MiB)` | nothing | no kernel object at physical address 0; legacy areas; the AP trampoline of the multi-core stretch goal |
| the boot region | nothing | the root task's objects, outside every untyped as in seL4 |
| `BootPlan.kernel_reserved`: the pages the kernel device window maps (local APIC, I/O APICs, HPET), the MSI window `[0xFEE0_0000, 0xFEF0_0000)`, a locked Hyper-V hypercall page | nothing | a holder could reprogram the timer, route interrupts, send itself an NMI, or overwrite the hypercall page |
| RAM at or above the direct map's end, `min(phys_map_size, 64 GiB)` | nothing | the kernel cannot reach it; this row applies last |

ACPI tables are unreadable from user space after boot: their memory becomes
RAM untyped, zeroed on retype. User space gets the ACPI facts it needs (the
MCFG ECAM ranges for M9, interrupt routing) from BootInfo's `InterruptInfo`
block ([What user space gets, and kernel
devices](#what-user-space-gets-and-kernel-devices)); BootInfo's `rsdp` is for
information only.

### Static kernel memory and the boot region

Fixed-size state is in `.bss`: the 64 KiB kernel stack (M0's boot stack) and
four 8 KiB IST stacks, each above an unmapped 4 KiB guard page that the
linker script reserves and the M3 table builder skips; the GDT, TSS,
IDT and per-CPU area; the kernel's page tables, including the device window
([The kernel half](#the-kernel-half)); `BootState`; the idle thread,
scheduler and interrupt tables ([Scheduling](#scheduling),
[The IRQ table](#the-irq-table)). The fatal handlers format their panic
report on their 8 KiB IST stack. The `double_fault` scenario paints IST1
first and prints how much of it the report used: 1,872 bytes in the dev
profile and 1,904 in release at the end of M3, and 1,680 in the dev profile
at the end of M4, so 8 KiB is enough.

Everything sized at run time comes from one boot region, chosen like seL4's
rootserver region (`init_freemem`, `src/kernel/boot.c`): the top of the
highest `USABLE` range above 1 MiB, inside the direct map, that fits without
touching a `kernel_reserved` page or any 2 MiB page that holds one (the direct
map maps such a page UC, so a WB user frame there would alias it). M3 panics
if the kernel image shares a 2 MiB page with a kernel device page. It is aligned to the 128 KiB root CNode and
holds, in order of decreasing alignment as in seL4's
`create_rootserver_objects`, the root CNode, the 8 KiB PML4, PDPT, PD and
PTs, the IPC buffer, BootInfo, image frames, on Hyper-V the two SynIC frames
(the hypercall page is `.hvcall` in the kernel image), then the 2 KiB
TCB. Its end is rounded up to a page, so from M5 the 2 KiB after the TCB is
lost; seL4 leaves such slack in its free memory, which becomes small untyped.
It is zeroed when allocated, no untyped covers it, and it is never freed,
so the root task cannot revoke its own CNode. Boot-only kernel code (a few
KiB) is not reclaimed.

### Untyped

`l4core::boot::untyped(&BootPlan, &mut [UntypedDesc; 448])`, a pure function,
classifies every page below `2^phys_addr_bits` by the table above
(`page_class`, using `l4core::vspace::direct_map_type` for the write-back rule
and the device window's pages for the other 2 MiB rule, and subtracting the
fixed-size `kernel_reserved` list, which `plan` subtracts too), merges runs of
one class (`runs`), cuts each run into the largest naturally aligned
power-of-two chunks between 4 KiB and the maximum untyped size in [Object
sizes](abi.md#object-sizes) (`chunks`, seL4's `create_untypeds_for_region`),
and writes the framebuffer's chunks first, then the rest by ascending address,
straight into BootInfo's descriptor list. BootInfo holds 448 descriptors; if
more are needed, boot panics with the count rather than drop memory. The host
tests `q35_untyped_fit_at_every_width` and `hyperv_untyped_fit_at_every_width`
run it on the memory maps recorded from QEMU and Hyper-V
(`core/tests/boot/q35.memmap`, `hyperv-gen2.memmap`) at every physical address
width from 36 to 52 bits: QEMU's map gives 106 to 148 untyped, covering 248
MiB of RAM, with 6 for the framebuffer, and Hyper-V's 73 to 115, covering 509
MiB of RAM, with 2 for the framebuffer ([Open questions](#open-questions)).
Outside Miri, every host test also compares the list with a second
implementation that paints the table's rows over the address space one after
another.

### Root-task image and address space

`cargo xtask build` builds the user crates for `x86_64-unknown-none` in
their own target directory, `target/user`, with `-C relocation-model=static
-C code-model=small`, and links `user/root` as a static ELF at `0x40_0000`
with `user/link.ld`, which gives text, read-only data and writable data each
a `PT_LOAD` segment on pages of its own (`xtask/src/compile.rs`). It strips
the ELF to its ELF header, program headers and segment bytes, zeroing the
bytes between segments and dropping the section headers
(`xtask/src/rootimage.rs`), and runs on it the check boot step 8 makes, so an
image the kernel would refuse, among them one whose `PT_LOAD` segments span
more than 8 MiB (from the first segment's page to the end of the last), fails
the build. It writes the result to `target/xtask/rootimage/<profile>/root.elf`,
and the kernel embeds that file, named by `MICROL4_ROOT_IMAGE`, with
`include_bytes!` in `.rootimage`, its own read-only, NX `PT_LOAD` segment
between `__rootimage_start` and `__rootimage_end`, which starts and ends on a
page boundary so that no other kernel byte shares its pages. From M5 xtask
also checks the whole kernel image, `.rootimage` included, against
`KERNEL_IMAGE_MAX` = 16 MiB. Other servers travel inside root's image.
Step 8 checks the image with `l4core::boot::image::RootImage::check`:
`l4core::elf` checks ET_EXEC, x86_64, that no page is shared by two segments
and that the entry lies in an executable segment, and `RootImage::check`
that every segment lies inside `[USER_MIN, USER_TOP - 12 KiB)`, that none is
both writable and executable, and that the span is at most 8 MiB. Step 8
copies the file bytes, leaves the rest zero, and maps each page with its
segment's permissions. A page inside the span that no segment covers gets no
frame and no mapping.

The paging structures are those that translate `[image_start, image_end + 12
KiB)`: one PDPT per 512 GiB, one page directory per 1 GiB and one page table
per 2 MiB that the range touches, as seL4's `arch_get_n_paging` counts them
(`RootImage::needs`; `l4core::vspace::map_boot_tables` refuses any other
count). A 2 MiB region whose pages no segment covers still gets its page
table. `l4core::boot::image::root_mappings` lists the root VSpace in slot
order: every paging structure with the range it translates, then every frame
with its page, its permissions and, for an image page, the file bytes it
holds. Host tests check images across 2 MiB, 1 GiB and 512 GiB boundaries, the
largest and the highest image, a gap between segments, and random images
(`core/src/boot/image/tests.rs`).

| Root virtual range | Content | Mapping |
| --- | --- | --- |
| `[image_start, image_end)` | the pages the ELF's segments cover, 4 KiB frames | from segment flags; uncovered pages unmapped |
| `image_end` | IPC buffer, one frame | RW, NX |
| `image_end + 4 KiB` | BootInfo, two frames | RW, NX |

The kernel gives the root task no stack. As in seL4, root's `_start` in
`libsys` switches to a stack of its own: 64 KiB in `.libsys_stack`, which
`user/link.ld` makes a segment of its own one page above the segment below
it. No segment covers that page, so nothing maps it, and a stack overflow
faults instead of overwriting what lies below. Between `.bss` and it lie the
root task's six 16 KiB thread stacks (`.thread_stack.0` to `.5`,
`user/root/src/spawn.rs`), each a segment above a guard page in the same
way. M6 raised them from two to six: `test=ipcntfn` runs five threads
besides the root task. The image ends at the top of the libsys stack. With
M6's tests it spans `0x40_0000` to `0x46_0000`, 96 pages, of which the seven
guard pages get no frame, so boot maps 89 image frames (the boot summary of
`test=root`).

### Initial CSpace and BootInfo

The root CNode has radix 12 (4096 slots, 2^17 bytes) and guard 0 of size 52,
so CPtr `n` names slot `n` (seL4 `create_root_cnode`). Slots 0 to 15 are fixed
([Initial CSpace](abi.md#initial-cspace)): seL4's number where seL4 has the
same object, null where microL4 has none, and on Hyper-V the Hypervisor
capability in slot 12 and the SynIC message and event-flag frames in slots 13
and 14. All three are null elsewhere, before M9, when an M9 privilege is missing,
and when the firmware locked the hypercall MSR to a page outside `.hvcall`; the kernel then prints why. From
slot 16 come the second BootInfo frame, the paging structures, the image
frames and the untyped, then empty slots. An 8 MiB span plus the three pages
after it needs at most 2 PDPTs, 2 PDs and 6 PTs, and 16 + 1 + 10 + 2048 + 448
is under 4096, so a valid image cannot run out of slots. Every boot-made
capability is an original; the TCB's slots hold copies derived from slots 2, 3
and 10, and its `reply` slot holds its reply master, made by boot as a
derivation root, since the root TCB is never retyped (seL4 does the same in
`create_initial_thread`, `src/kernel/boot.c`).

`l4core::boot::write_root_cnode` writes the root CNode: `root_cap` gives
each slot's capability, and `cdt::insert_root` puts it in. Each is an
original with full rights, every untyped has its watermark at its size, and
every Frame and paging-structure capability is unmapped, so that step 8
writes the mapping records of those it maps. From M9 the Hypervisor capability
comes in through `RootNeeds::hypervisor`, and only then are the SynIC frames
laid out.

BootInfo is one 8 KiB `#[repr(C)]` struct in `l4core::bootinfo`, shared by the
kernel and `libsys` with compile-time offset asserts: a 1 KiB header and 448
untyped descriptors ([BootInfo](abi.md#bootinfo)). Beyond seL4's fields it
carries the framebuffer and the slot range of its untyped, the RSDP address
(for information), the command line
([ADR 0003](adr/0003-scenarios-select-tests-by-command-line.md)), the TSC
frequency measured in M3, the hypervisor vendor, the physical address width,
the image bounds, and the 256-byte `InterruptInfo` block, whose fields [What
user space gets, and kernel devices](#what-user-space-gets-and-kernel-devices)
lists. The module also holds `BootInfo::ZERO`, the slot constants,
`ROOT_CNODE_RADIX`, `MAX_UNTYPED`, the magic and version, the
`hypervisor_vendor` numbers, which `arch`'s `Hypervisor::vendor` returns, and
`InterruptInfo::from_platform(&Platform, pins)`. It fills an ISA route's
`gsi` and `flags` whenever the IRQ has a route, with `routed` 0 when no I/O
APIC serves that GSI; all three are 0 when the IRQ's GSI is another IRQ's
override target. When the framebuffer gets no untyped, BootInfo's
`framebuffer` keeps the handoff's values and only `framebuffer_untyped` is
empty.

### Root-task entry state

`rip` = ELF entry, `rdi` = BootInfo, `rsp` and other registers 0, RFLAGS
`0x202`, the FP template of [Initial state](#initial-state), priority and
MCP 255, no fault endpoint, `exit` = `Iret` so the first exit is an `iretq`
([Root-task entry state](abi.md#root-task-entry-state)). `tcb::init_root`
sets them on a TCB `tcb::init` prepared, and `test=rootimage` reads them
back.

### `core/` and `arch/`

| Part | Where | Built in |
| --- | --- | --- |
| Handoff copy into `BootState` (step 2) | `kernel/src/boot.rs`, reading through `arch::read_handoff` and `arch::read_memory_map` | M3 |
| Steps 3 to 5 | `arch::init` (`arch/x86_64/mod.rs`) over `l4core::{trap, acpi, vspace, window, hyperv, apic, hpet, calibration, timer}`; from M4 it returns `BootFacts`, what steps 6 to 9 need, and sets up `arch::Objects` | M3, M4 |
| BootInfo, `SlotRegion`, `UntypedDesc`, `InterruptInfo`, slot constants | `l4core::bootinfo`, compile-time asserts | M4 |
| Boot plan and `kernel_reserved`, page classes, untyped computation, slot plan, BootInfo fields, root capabilities | `l4core::boot` (`plan`, `page_class`, `runs`, `chunks`, `untyped`, `slot_plan`, `fill_bootinfo`, `write_bootinfo`, `root_cap`, `write_root_cnode`); host tests on the recorded maps and proptest | M4 |
| The root image's checks, `RootNeeds`, the root VSpace in slot order and the entry registers | `l4core::boot::image` (`RootImage::check`, `needs`, `root_mappings`), shared with xtask; host tests and proptest over random images | M5 |
| The invariants below as checks, written from the rules apart from the planner: `check_plan`, `check_untyped`, `check_bootinfo`, `check_root_cnode` | `l4core::boot::check`, run by every host test and by `test=bootinfo`. `check_root_cnode` applies only right after boot, before any retype, and allows the two marks step 8 leaves: the mapping records of the frames and paging structures it mapped, and the root TCB's copy as the only child of root slots 2, 3 and 10 (host test `root_cnode_check_allows_what_step_8_leaves`); `check_untyped` checks RAM coverage exactly, and device coverage is left to the comparison with the second implementation | M4, M5 |
| Steps 6 to 9: the region zeroed, BootInfo and the root CNode written, the root VSpace mapped, the image copied and the root TCB made | `boot::make_root_space` through `arch::Objects`, and `arch::bootinfo_frames(paddr)`, the one `unsafe` view of BootInfo's frames, a `&'static mut BootInfo` handed out once. `RootSpace` keeps no reference to BootInfo, which the root task can write | M4, M5 |
| Step 10 | `boot::start_root_task`, then `arch::exit_to_scheduled` | M5 |
| `test=bootinfo`: the four checks, then every descriptor against kernel memory found without the plan, from GDTR, IDTR, `IA32_GS_BASE`, CR3, the stack symbols and statics translated through the live page tables, and the device window's mapped pages; then the loaded direct map walked over every untyped: every RAM untyped mapped write-back and no device untyped in a write-back page | `kernel/src/selftest.rs`, `arch::kernel_memory` (`selftest` only) | M4 |
| `.rootimage` section, unmap and flush | `kernel/linker.ld`; `arch/x86_64/rootimage.rs` (`take_rootimage` hands the section out once, and `RootImageSection::unmap` consumes it, so no borrow of its bytes outlives the mapping); `arch::paging::unmap_rootimage` | M5 |
| `test=rootimage`: `.rootimage` gone from the kernel window and covered by RAM untyped, its direct-map alias writable; BootInfo naming the image; every image page mapped to a frame that holds what the ELF says with its segment's permissions (a hash step 8 made from the ELF, against the frames read through a walk of the root PML4); the IPC buffer and BootInfo after it; the root TCB as `docs/abi.md` says | `kernel/src/rootimage.rs` (`selftest` only) | M5 |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| No untyped covers the kernel image (except reclaimed `.rootimage`), the boot region, a `kernel_reserved` page, `[0, 1 MiB)`, `ACPI_NVS`, `FIRMWARE` or `BAD` memory; the boot region holds no `kernel_reserved` page and touches no 2 MiB page that holds one | `l4core::boot::plan` and `page_class` both subtract `kernel_reserved`; `check_plan` and `check_untyped` on the recorded maps and in proptest over generated maps (`random_machines` and `a_reserved_page_where_the_boot_region_would_go`); `test=bootinfo` checks every descriptor against kernel memory `arch` finds without the plan | M4 |
| No kernel object lies at physical address 0 | no untyped and no boot region below 1 MiB (`page_class`, `plan`; `check_untyped`, `check_plan` in host tests and `test=bootinfo`); `core/` handles are `NonZeroU64` | M2, M4 |
| Untyped are pairwise disjoint, each aligned to its size and at least 4 KiB | `l4core::boot::chunks` over disjoint runs; `check_untyped` in host tests, proptest and `test=bootinfo` | M4 |
| RAM untyped lie inside the direct map; no device untyped lies in a write-back direct-map page; no RAM untyped lies in a 2 MiB page holding a kernel device page | `l4core::boot::page_class` with `direct_map_type`; `check_untyped`; host tests on the QEMU and Hyper-V maps; `test=bootinfo` walks the loaded direct map over every untyped | M4 |
| The kernel image, the handoff and its memory map lie below the direct map's end | the loader's 64 GiB `AllocateMaxAddress` bound; M3 check, panic otherwise | M3 |
| The kernel image, `.rootimage` included, fits `KERNEL_IMAGE_MAX` = 16 MiB | `kernel/linker.ld` assert (M3); xtask strips `root` and checks the image (M5) | M3, M5 |
| The root task never holds a capability to kernel memory: kernel image, stacks, descriptor tables, kernel page tables, kernel device pages, or the boot-region pages that hold its CNode, TCB and paging structures (as frames or untyped) | the plan excludes them from every untyped and frame; `test=bootinfo` checks every BootInfo descriptor against the kernel image but `.rootimage`, which step 8 reclaimed, the stacks, descriptor tables, page tables and `BootState` in it, the device window's pages, the boot region, the MSI window and `[0, 1 MiB)` | M4, M5 |
| No `USABLE`, `LOADER` or `ACPI_RECLAIMABLE` page outside the kernel image is written or handed out before step 5 ends: the firmware's GDT, IDT and stack, the loader's tables, ACPI and any firmware-enabled Hyper-V overlay are dead by then | the step order in `kmain`; the boot plan (step 6) is the first allocator, and `arch::Objects` panics if used before `arch::init` ends; review | M3, M4 |
| Boot never drops memory silently: it panics if the untyped or slots do not fit | `BootError::TooManyUntyped` and `TooManySlots` from `l4core::boot`; `check_untyped` requires the RAM untyped to cover every byte the rules allow; host tests on the recorded maps and `more_untyped_than_bootinfo_holds` | M4 |
| BootInfo's layout is identical in the kernel and in `libsys` | one `l4core::bootinfo` type; compile-time offset and size asserts in each build | M4 |
| Slot `untyped.start + i` holds the untyped `untyped_list[i]` describes, for every `i` below `untyped.end - untyped.start`; every slot in `empty` is null | `slot_plan`, `root_cap` and `write_root_cnode`; `check_bootinfo` and `check_root_cnode` in host tests and `test=bootinfo` | M4 |
| After step 2 no code reads `LOADER` memory other than the kernel image | `BootState` copy; review | M3 |
| No page of `.rootimage` is mapped in the kernel window once anything can use the untyped that cover it | step 9 makes those untyped before step 8 unmaps `.rootimage`, but nothing can use an untyped before the root task runs; step 8 clears its PTEs and toggles CR4.PGE (`arch::paging::unmap_rootimage`) before step 10; `test=rootimage` finds it gone from the kernel window and covered by RAM untyped | M5 |
| The root image cannot map outside `[USER_MIN, USER_TOP)` or make writable text: a writable and executable segment is refused; a page no segment covers is not mapped | `l4core::boot::image::RootImage::check` with `l4core::elf`, run by xtask on every build and by step 8; host tests `segments_must_lie_inside_the_user_range`, `a_writable_and_executable_segment_is_refused`, `a_page_between_segments_gets_no_frame` and proptest `random_images_load_as_their_segments_say`; `test=rootimage` checks every image page's contents and permissions | M5 |
| The root task starts with the registers, priority and capabilities [`abi.md`](abi.md#boot-and-the-root-task) lists | `tcb::init_root` and step 8; `test=rootimage` reads the root TCB back (`Running` at the entry with `rdi` BootInfo, RFLAGS `0x202`, priority and MCP 255, its IPC buffer, copies of root slots 2, 3 and 10 and its master reply capability), and `test=root` prints BootInfo's slot regions from ring 3 | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Root task is Multiboot module 0, ELF-loaded right after the kernel image and reserved with it, apart from the rootserver objects (`load_boot_module`, `src/arch/x86/kernel/boot_sys.c`; `arch_init_freemem`, `src/arch/x86/kernel/boot.c`) | embedded in `.rootimage`, copied into boot-region frames, section reclaimed | the loader loads one file (`docs/boot.md`); one allocation, outside every untyped either way |
| Every initial-thread frame, image, IPC buffer and BootInfo alike, is mapped read-write and executable (`map_it_frame_cap`, `src/arch/x86/64/kernel/vspace.c`) | image pages from segment flags, NX unless executable; IPC buffer and BootInfo RW, NX | W^X from the first instruction; [CPU features](#cpu-features) requires NX |
| BootInfo is one page; framebuffer, a copy of the RSDP, the raw multiboot memory map, TSC frequency in MHz and VBE go in extra chunks with headers (`bootinfo_types.h`, `init_sys_state`) | two pages, one fixed struct; framebuffer, RSDP address and TSC frequency in Hz are fixed fields; no memory map or VBE | a handful of items, always present; a fixed struct is simpler to read; descriptors and `InterruptInfo` say what user space needs of the map and ACPI |
| BootInfo fields `extraLen`, `nodeID`, `numNodes`, `numIOPTLevels`, `sharedFrames`, `ioSpaceCaps`, `initThreadDomain`, MCS `schedcontrol` (manual `bootup.tex`, BootInfo Frame) | none; adds `magic`, `version`, `size`, `framebuffer_untyped`, image bounds, command line, `hypervisor_vendor`, `phys_addr_bits` and the `InterruptInfo` block | one core, no extra chunks, IOMMU, domains or MCS; the version lets `libsys` reject a mismatched kernel |
| Kernel command line from the Multiboot loader (`console_port`, `debug_port`, `disable_iommu`), not passed to the root task (manual `bootup.tex`, Boot Command-line Arguments) | `\cmdline.txt` through the handoff; the kernel reads `test=`; root gets the same bytes in BootInfo | COM1 is fixed and there is no IOMMU; user-space tests pick themselves the same way ([ADR 0003](adr/0003-scenarios-select-tests-by-command-line.md)) |
| Untyped that do not fit the list are left out with a message (`provide_untyped_cap`, `src/kernel/boot.c`) | boot panics | memory is never lost silently |
| Untyped in no particular order (manual `bootup.tex`) | framebuffer first, then ascending address | `fb` finds its untyped; deterministic tests |
| Initial thread's paging, frames and untyped in slot regions, from slot 16 in the order paging, extra BootInfo, image frames, untyped (`create_it_address_space`, `init_sys_state`); seL4 slot numbers 0 to 15 (`seL4_RootCNodeCapSlots`) | same regions, extra BootInfo frame first; same numbers; 5, 6, 8, 11, 15 null; 12 Hypervisor, 13 and 14 the SynIC frames, on Hyper-V only | BootInfo names every region, so their order carries nothing; no ASID pools, IOSpace, domains, SMMU, MCS or SMC; the Hypervisor capability and SynIC frames are new |
| Every page from the image's first to its last is mapped and has a frame (`create_frames_of_region`, `init_sys_state`) | pages no segment covers get neither | no frame or mapping the image did not ask for |
| Device untyped cover every gap up to `CONFIG_PADDR_USER_DEVICE_TOP` (2^47 on x86_64), including firmware-reserved and ACPI ranges and RAM below 1 MiB, which `HIGHMEM_PADDR` keeps out of RAM only (`create_untypeds`; `parse_mem_map`, `boot_sys.c`) | gaps below `2^phys_addr_bits`, minus WB direct-map pages; `ACPI_RECLAIMABLE` becomes RAM, `ACPI_NVS` and `FIRMWARE` nothing; nothing below 1 MiB | no WB/UC aliasing; UEFI's kinds say more than E820's; low memory keeps the AP trampoline |
| RAM above the kernel window (510 GiB) becomes device untyped (`add_mem_p_regs`) | RAM above the 64 GiB direct map becomes nothing; the loader allocates below 64 GiB | keeps one rule: RAM untyped hold kernel objects; our targets have far less RAM |
| Kernel device pages: one LAPIC page, I/O APICs, IOMMUs, mapped in a kernel device window and reserved (`map_kernel_window_devices`, `src/arch/x86/kernel/vspace.c`) | the same idea, with the LAPIC page, at most four I/O APICs and the HPET in the window at `KERNEL_DEVICE_BASE`; `kernel_reserved` also holds the 1 MiB MSI window and a locked hypercall page; no RAM untyped in a 2 MiB page holding a device page | no MSI-window frames for user space; the kernel uses the HPET; no WB alias of a UC direct-map page |
| Boot code reclaimed (`get_p_reg_kernel_img_boot`) | only `.rootimage` | simpler; loses a few KiB |
| The initial thread gets no stack, RSP 0 and the BootInfo address in `capRegister` (`Mode_initContext`, `create_initial_thread`); IPC buffer and BootInfo follow the image (`init_sys_state`) | the same | not a divergence; listed because `libsys` depends on it |

## Kernel entry and exit

Every entry from ring 3 runs `swapgs`, builds one trap frame at the top of the
single kernel stack and copies it into the current TCB; every exit rebuilds
the frame from the next thread's TCB and leaves by `sysretq` only if that
thread entered by `syscall` and returns below 2^47, else by `iretq`, with RIP
always below 2^47. NMI, #DF, #MC and #DB run on their own IST stacks and never
read GS.

### Descriptor tables and MSRs

The GDT is the one in [Rings and segments](#rings-and-segments): null, kernel
code `0x08`, kernel data `0x10`, user data `0x18` (selector `0x1B`), 64-bit
user code `0x20` (`0x23`), TSS `0x28`, no 32-bit code descriptor. `syscall`
loads CS = `STAR[47:32]`, SS = CS + 8; `sysretq` loads SS = `STAR[63:48]` + 8,
CS = `STAR[63:48]` + 16, with RPL 3 (checked in M5 on QEMU: after a `sysretq`
exit, `test=ring3`'s next exception frame, which the CPU pushed, holds CS
`0x23` and SS `0x1B`). That forces the order: kernel data right after kernel
code, then user data, then 64-bit user code. `STAR[63:48]` names index 2 with
RPL 3, `0x13`, which is right whether or not `sysretq` forces RPL 3. The
selectors are loaded with fixed hidden attributes, not read from the GDT; the
GDT entries matter for `iretq`. The GDT's limit is `0x37`, its seven entries
less one byte, not the size of the 16-byte-aligned static that holds them,
whose padding would make selector `0x38` look valid: a selector past the TSS
descriptor raises #GP, as the `trap_general_protection` scenario shows.

| Register | Value | Why |
| --- | --- | --- |
| `IA32_EFER` (`0xC000_0080`) | SCE set (M5); NXE from the loader | enables `syscall` |
| `IA32_STAR` (`0xC000_0081`) | `0x0013_0008_0000_0000`, as in [Rings and segments](#rings-and-segments) | entry CS `0x08`, SS `0x10`; exit SS `0x13 + 8 = 0x1B`, CS `0x13 + 16 = 0x23` |
| `IA32_LSTAR` (`0xC000_0082`) | `syscall_entry` | |
| `IA32_CSTAR` (`0xC000_0083`) | `compat_entry`: `swapgs`, load the kernel stack, panic | unreachable, since no compatibility-mode code segment exists; if reached, it never runs on the user stack |
| `IA32_FMASK` (`0xC000_0084`) | `0x0025_7FD5`: CF PF AF ZF SF TF IF DF OF IOPL NT RF AC ID, seL4's `FLAGS_SYSCALL_MASK` | IF: the kernel runs with interrupts off. DF: Rust assumes it clear for string operations. TF: no single-step trap inside the kernel. AC: with AC set SMAP is off in ring 0. NT: a later `iretq` with NT set would attempt a task return and fault (from memory). The rest gives a defined state. On QEMU a `syscall` with DF, NT and AC set enters with all three clear (`test=ring3`) |
| `IA32_SYSENTER_CS` (`0x174`), `_ESP`, `_EIP` | 0 | firmware may leave them set; with CS 0, `sysenter` faults in ring 3 on Intel and is #UD in long mode on AMD (from memory; no M5 test runs `sysenter`) |
| `IA32_GS_BASE` (`0xC000_0101`) | the per-CPU area while in ring 0 | |
| `IA32_KERNEL_GS_BASE` (`0xC000_0102`) | the current thread's GS base while in ring 0 | swapped in by the exit `swapgs`; written at a thread switch ([FS and GS base](#fs-and-gs-base)) |
| `IA32_TSC_AUX` (`0xC000_0103`) | 0, if CPUID reports `rdtscp` (`0x8000_0001` EDX bit 27) or `rdpid` (7 ECX bit 22) | both return it in ring 3 ([ADR 0025](adr/0025-user-tsc.md)), so the firmware's value must not reach a thread (`l4core::cpu::Cpuid::has_tsc_aux`) |

`entry::init` (`arch/x86_64/entry.rs`) writes `IA32_STAR`, `IA32_LSTAR`,
`IA32_CSTAR`, `IA32_FMASK`, the three SYSENTER MSRs and EFER.SCE in boot
step 3, right after the GDT is loaded, and prints `entry: syscall_entry at
<address>, IA32_STAR 0x13000800000000, IA32_FMASK 0x257fd5, EFER.SCE on,
IA32_SYSENTER_CS 0`. It then writes `IA32_TSC_AUX` and prints it read back,
`entry: IA32_TSC_AUX 0x0, which rdtscp and rdpid read in ring 3`
(`test=ring3` expects it on QEMU's `-cpu max`), or `entry: no rdtscp or
rdpid, so no IA32_TSC_AUX`.

TSS: RSP0 = the kernel stack top; IST1 #DF, IST2 NMI, IST3 #MC, IST4 #DB, each
8 KiB above an unmapped guard page; I/O map base past the limit, so ring 3 has
no port ([Rings and segments](#rings-and-segments)). IDT: 256 64-bit interrupt
gates on `0x08`, all DPL 0 except vector 3 (#BP), which is DPL 3 so that
`int3` raises UserException 3 with `rip` after it, as in seL4; vectors 1, 2, 8
and 18 use their IST, every other gate none. [Vector map](#vector-map) assigns
vectors 32 to 255.

### The per-CPU area and `swapgs`

`PerCpu` is a `#[repr(C)]` static in `arch/x86_64/gdt.rs`, set up in M3:
`this`, its own address (offset 0), `kernel_stack_top` (8), `user_rsp` (16).
`swapgs` runs once per entry from ring 3 and once per exit to it, so GS
points at `PerCpu` in ring 0 and at the user's GS base in ring 3.
Only the stubs use GS; Rust uses the static. seL4's uniprocessor build has no
`swapgs` (`MAYBE_SWAPGS`, `src/arch/x86/64/traps.S`); microL4 keeps it, as
PLAN.md asks, which readies the stubs for multi-core
([ADR 0008](adr/0008-kernel-entry-and-exit.md)). An IDT stub swaps when the
saved CS has RPL 3. That rule is wrong only from `syscall` to the entry
`swapgs` and from the exit `swapgs` to `sysretq` or `iretq`; interrupts are
off there and nothing there can fault, so only NMI, #MC or #DB can arrive, and
their handlers never read GS.

### Entry

The trap frame, 22 words at the top of the kernel stack, lowest address
first: `r15`, `r14`, `r13`, `r12`, `r11`, `r10`, `r9`, `r8`, `rbp`, `rdi`,
`rsi`, `rdx`, `rcx`, `rbx`, `rax`, `vector`, `error`, `rip`, `cs`, `rflags`,
`rsp`, `ss`. It is internal; the user-visible register order is in
[User register set](abi.md#user-register-set).

```
syscall_entry:                 ; IF DF AC TF NT = 0 by IA32_FMASK; RSP is the user's
    swapgs
    mov  gs:[user_rsp], rsp
    mov  rsp, gs:[kernel_stack_top]
    push 0x1B, gs:[user_rsp], r11, 0x23, rcx   ; ss, rsp, rflags, cs, rip
    push 0, 256                                ; error, vector (256 = syscall)
    push rax ... r15
    mov  rdi, rsp
    call syscall_from_user                     ; Rust, never returns

trap_vector_N:                 ; every vector; RSP0 from ring 3 unless IST
    push 0 (if the CPU pushed no error code), N
    clac
    cld
    jmp  trap_fatal_entry (NMI, #DF, #MC) or trap_common_entry (the rest)

trap_common_entry:
    test byte [rsp + 24], 3    ; saved CS
    jz   1f
    swapgs
1:  push rax ... r15
    mov  rdi, rsp
    call trap_from_kernel or trap_from_user, by the saved CS

trap_fatal_entry:              ; IST1, IST2 or IST3; no swapgs from either ring
    push rax ... r15
    mov  rdi, rsp
    call trap_fatal
```

Each stub pushes the vector, runs `clac` and `cld` and jumps to one of the
two shared entries, so the saved-CS test and `swapgs` live in one place, not
in 256 stubs. The CPU pushes an error code for vectors 8 and 10 to 14, as
seL4's `traps.S` has it and the M3 scenarios show: `trap_general_protection`,
`page_fault` and `double_fault` read their error codes from the frames QEMU
pushed. Vectors 17, 21, 29 and 30 also push one when raised as exceptions,
but none can be raised here (CR0.AM clear, no CET, no SEV), so they take the
no-error-code stub, which also reads an MSI injected on them correctly. They
and the vectors with no use here (9, 15, 20, 22 to 28, 31, from the SDM's
vector table as remembered; `trap_cannot_occur` raises 21 and checks the
report) panic from either ring. Every stub, IST ones included, runs
`clac` and `cld` before any Rust code.

The Rust handlers read CR2 first for #PF, then copy the frame into the current
TCB's `regs` ([Register frame and restart](#register-frame-and-restart)): for
`syscall`, `next_ip` = `rcx`, `fault_ip` = `rcx` − 2, `error` = 0, `exit` =
`Sysret`; otherwise `next_ip` = `fault_ip` = the pushed RIP, `error` = the
error code, `exit` = `Iret`. FS and GS base stay in their MSRs while the
thread runs. Then they dispatch, schedule and exit; nothing stays on the
kernel stack between entries. The kernel has no SSE code
(`kernel/src/main.rs`), so x87 and SSE state is untouched until a thread
switch swaps it ([Switching](#switching-m5)).

In code: `syscall_from_user` and `trap_from_user` make an
`l4core::entry::UserEntry` of the frame with `classify`: `Syscall`,
`Exception { vector, error, cr2 }` (CR2 kept for #PF only), `Interrupt` for a
vector of 32 or more, or `Fatal` for NMI, #DF, #MC, a vector that cannot
occur, or a frame not from ring 3, which panics. A #DB from ring 3 arrives on
IST4; its frame stays there, and its handling moves to the top of the kernel
stack first. `entry::from_user` hands the frame to one seam per kind of entry,
`user_syscall`, `user_exception` and `user_interrupt`. Each saves the frame
into the current thread's `regs` (`l4core::entry::save`), then hands the work
to `crate::dispatch` ([System-call dispatch](#system-call-dispatch)) or, for
an interrupt, to `irq::handle`, whose timer tick runs `sched::tick`, and ends
with `thread::exit_to_scheduled` ([Exit](#exit)).

### Exit

Every entry ends in `thread::exit_to_scheduled` (`arch/x86_64/thread.rs`):

1. `sched::schedule` picks the thread to run, or none for the idle thread;
   debug builds then check the scheduler with `sched::check_exit`.
2. `tcb::activate`: a `Restart` thread continues at `fault_ip` and becomes
   `Running`.
3. If the thread is not the one whose FS and GS bases are in the MSRs, that
   one's bases are read back into its TCB and the new one's written
   ([FS and GS base](#fs-and-gs-base)).
4. On every exit, `set_vm_root` with the capability in the thread's VSpace
   slot, since `TCB_Configure` or `TCB_SetSpace` on the caller changes it
   without a reschedule ([TLB maintenance](#tlb-maintenance)), and
   `fpu::switch_to` ([Switching](#switching-m5)).
5. `exit_to_user` with the thread's registers. With nothing runnable,
   `set_vm_root` loads the kernel PML4 and `trap::idle` resets RSP to the
   stack top and runs `idle_loop`: `sti; hlt` in a loop. The idle thread owns
   no FP state and no bases, so A, idle, A switches neither.

`exit_to_user(&regs)` writes the trap frame in its own stack frame from the
registers, through `l4core::entry::exit_frame`, a pure function, and jumps to
the exit stub with the frame as its stack:

- `rip` = `next_ip`, `rsp` = `rsp`, each replaced by 0 if at or above
  `0x0000_8000_0000_0000`, the sanitiser's rule
  ([User register set and sanitising](#user-register-set-and-sanitising)). A
  debug
  kernel prints a warning the first time each fires in a boot, not again,
  since a thread can make the `rsp` one fire on every system call. Without
  a kernel bug it fires only for an `rsp` the thread set itself, or for a
  `rip` restarted after a fault on an upper-half fetch; otherwise a writer
  forgot to sanitise.
- `rflags` = `(rflags & 0x0024_0DD5) | 0x0202`: CF PF AF ZF SF TF DF OF AC
  ID, which ring 3 can set itself with `popfq`, are kept; IF and bit 1 are
  forced on; IOPL, NT, RF, VM, VIF and VIP are forced off (ring 3 can set NT
  too, but it is never needed). The register-write sanitiser is stricter: a
  register write also clears TF, AC and ID, as seL4's `sanitiseRegister`
  does (`src/arch/x86/machine/registerset.c`). `exit_frame` applied after it
  changes nothing.
- `cs` = `0x23`, `ss` = `0x1B`, constants, never from the TCB.
- The path is `Sysret` only if `exit` is `Sysret` and `next_ip` is below
  2^47, else `Iret`. A `syscall` in the last bytes below 2^47, which
  `USER_TOP` keeps unmapped, returns to 2^47: the thread leaves by `iretq`
  to RIP 0, so RCX is never non-canonical at a `sysretq` even if a writer
  forgot to sanitise (`test=ring3` maps that page to show it).
- On the `Sysret` path the frame's `rcx` and `r11` are the RIP and RFLAGS
  `sysretq` loads into them, so the frame is the thread's state after the
  exit either way.

```
exit_sysret:                    exit_iret:
    mov  rsp, rdi                   mov  rsp, rdi
    pop  r15 ... rax (not rcx, r11) pop  r15 ... rax
    add  rsp, 16                    add  rsp, 16
    mov  rcx, [rsp]       ; rip     swapgs
    mov  r11, [rsp + 16]  ; rflags  iretq
    mov  rsp, [rsp + 24]  ; user rsp
    swapgs
    sysretq
```

`sysretq` overwrites `rcx` and `r11`, which a system call destroys
([System calls](abi.md#system-calls)), so it serves only a thread whose last
entry was `syscall` and whose registers nothing has written since. Every
register write sets `exit` = `Iret`
([Register frame and restart](#register-frame-and-restart)), as seL4's
`Mode_postModifyRegisters` forces its interrupt path
(`src/arch/x86/64/kernel/thread.c`). `Iret` is the zero value of `exit`, so a
newly retyped TCB leaves by `iretq`. A `sysretq` that restores TF traps at
the return address, before the next instruction runs (QEMU, `test=ring3`),
where an `iretq` that restores TF traps after one instruction (from memory).
On QEMU `test=ring3` leaves by both many times, and checks every frame and
register at the next entry.

### The non-canonical RCX problem

On Intel CPUs `sysretq` with a non-canonical RCX raises #GP in ring 0 after
the kernel has loaded the user's RSP, so the CPU would push the #GP frame to
an address the user chose ([User address range](#user-address-range), H9). The
check that prevents it is in `l4core::entry::exit_frame`: a RIP at or above
`0x0000_8000_0000_0000` becomes 0 before either exit instruction sees it, so
RCX is always a lower-half canonical address, whoever wrote the register. Two
earlier defences keep it from firing: `USER_TOP` = `0x0000_7FFF_FFFF_F000`, so
a `syscall` in the last mappable page returns below 2^47
([User address range](#user-address-range)), and every register write is
sanitised ([User register set and
sanitising](#user-register-set-and-sanitising)). With constant CS and SS,
canonical RIP and RSP and masked RFLAGS, `iretq` cannot fault in ring 0 either
(from memory; on QEMU none of `test=ring3`'s `iretq` exits faults in ring 0,
the one to RIP 0 included, whose fetch faults in ring 3).

### NMI, double fault, machine check and debug

| Vector | Stack | From ring 3 | From ring 0 |
| --- | --- | --- | --- |
| 1, #DB | IST4 | `swapgs`, save the frame into the TCB, continue on the kernel stack; UserException 1 (`int1`, TF; [Faults](#faults); QEMU 8.2's TCG raises #UD for `int1` in ring 0, so M10 brief 5 rechecks `int1` from ring 3) | if the saved RIP is exactly `syscall_entry` (a `syscall` executed with TF set, if the CPU traps there) or the first instruction of the #BP stub (`mov ss` with TF set, then `int3`; below), `iretq` at once with the saved state unchanged (`l4core::entry::single_step_into_syscall_entry`, `single_step_into_breakpoint_stub`, `entry::return_to_kernel`); otherwise panic, on the #DB stub's own first instruction too. QEMU takes no trap at either: `test=ring3` runs a `syscall` with TF set, counts no ring-0 #DB, and takes the single step in ring 3 at the return address, and `test=redteam-movss` sees every `mov ss` probe's single step in ring 3. On Hyper-V (the M5 Hyper-V check, 2026-11-22) a `syscall` with TF set still takes no ring-0 #DB (`test=ring3` step 12), but `mov ss; int3` with TF set does reach the #BP stub's first instruction, and the kernel returns from it (`test=redteam-movss` probe 1, `0x3/0x0`) |
| 2, NMI | IST2 | panic | panic |
| 8, #DF | IST1 | panic | panic |
| 18, #MC | IST3 | panic | panic |
| 9, 15, 17, 20 to 31 | none | panic | panic |

These handlers never read GS and never use the interrupted RSP, so an NMI or
#DB at the first instruction of `syscall_entry`, while RSP is still the
user's, is safe. The kernel sends no NMIs outside the `nmi_stack` test hook,
so one means a hardware error, a
host operator, or a bus-master device whose driver programmed an NMI (or a
vector-18) MSI, which is as strong as DMA
([MSI (M9) and the trust model](#msi-m9-and-the-trust-model)); as it is
fatal, no handler returns from IST2 and a nested NMI cannot overwrite a live
frame. Separate ISTs keep an NMI inside a #MC
handler off its stack. CR4.MCE is set so a machine check reaches the panic
report instead of shutting down (from memory: TCG cannot raise a real machine
check, and the `trap_machine_check` scenario enters the handler with
`int 18`). OVMF already sets it (CR4 is `0x668` at handover, read under GDB
in M3); the kernel sets it regardless. DR7 keeps its
reset value `0x400`, no breakpoint enabled ([Invocations](#invocations)), so
a ring-0 #DB can only be a thread's own single step that the CPU carried into
the kernel. A `syscall` with TF set may raise one at `syscall_entry`. A load
of SS (`mov ss` or `pop ss`) holds a pending single step until the next
instruction has finished, so with TF set, `mov ss` followed by an instruction
that enters the kernel delivers the #DB on the entry's first instruction, in
ring 0, with GS still the user's (CVE-2018-8897's mechanism, there with a data
breakpoint; [the M5 red-team finding](redteam/m5-movss-db.md)). Only two
instructions enter directly: `syscall`, at `syscall_entry`, and `int3`, at the
#BP stub, the only gate with DPL 3. The #DB at the #BP stub is taken on IST4
after the CPU pushed the #BP frame at the top of the kernel stack and cleared
TF; the handler `iretq`s to the stub, which then enters as for any `int3`, its
frame's ring-3 CS giving it its `swapgs`, and the thread gets UserException 3.
The single step itself is dropped, as at `syscall_entry`. Every other ring-0
#DB still panics. `int n` on a DPL-0 gate raises #GP, which drops the pending
single step (Linux's `tools/testing/selftests/x86/mov_ss_trap.c` notes); and
`mov ss; int1` raises a #DB from ring 3 into which, by the SDM's description of
pending debug exceptions, the CPU folds the pending single step. A second #DB
on the #DB stub's first instruction would have been delivered on IST4 over the
first one's frame, so the kernel must never return from it, and panics. The M5
Hyper-V check (2026-11-22) confirmed all three: `test=redteam-movss` probe 1
(`int3`) read `0x3/0x0`, so Hyper-V defers the single step past `int3` into
ring 0 and the kernel returned from it; probe 2 (`int 0x80`) read
`0xd/0x402`, a #GP that dropped the step; probe 3 (`int1`) read `0x1/0x0`,
one #DB from ring 3; and nothing panicked.

### Interrupts and exceptions taken in ring 0

IF is 0 everywhere in the kernel except `idle_loop`, and preemption points
poll the local APIC's IRR without ever opening an `sti` window, so there is no
nested-interrupt path like seL4's `nested_interrupt`. A vector of 32 or more
from ring 0 must have RIP inside `idle_loop`; its frame is discarded and the
interrupt path runs ([Idle thread](#idle-thread)). Any other ring-0 vector is
a kernel bug: panic with vector, error code, CR2, RIP, RSP and the decoded #PF
bits (M3's page-fault scenario), without reading GS. After the interrupt
path, `interrupt_from_idle` runs an M4 self-test's resume hook if one is
installed, and otherwise `thread::exit_to_scheduled`, so a thread the
interrupt woke, or one a preemption point cut short, runs on.

### System-call dispatch

`l4core::abi::Syscall::from_number(rdx, cfg!(feature = "debug"))` returns
the system call or none; none raises an `UnknownSyscall` fault
([Faults](#faults)), with `fault_ip` on the `syscall` instruction. Otherwise:

| System call | Kernel action |
| --- | --- |
| `Call`, `Send`, `NBSend` | look up `rdi` (up to 64 bits, stopping at the first slot that is not a CNode), then, if the caller has a readable IPC buffer, the `extra_caps` pointers in `caps_or_badges`, and dispatch on the type of the capability `rdi` names: Endpoint, Notification, Reply ([IPC](#ipc), [Notifications](#notifications)); any other object decodes `label` within its type's range ([Invocation label index](abi.md#invocation-label-index)), else `IllegalOperation`, with MR0 to MR3 from the registers and MR4 and up from the IPC buffer. `Call` gets the result or error as a kernel reply; `Send` and `NBSend` drop it ([Decoding a system call](#decoding-a-system-call)) |
| `Recv`, `NBRecv` | Endpoint or Notification receive ([Receive phase](#receive-phase), [Wait and poll](#wait-and-poll)) |
| `Reply` | the caller slot's reply capability ([Reply capabilities](#reply-capabilities)) |
| `ReplyRecv` | `Reply`, then `Recv` on `rdi` |
| `Yield` | the scheduler ([Scheduling](#scheduling)) |
| 16 to 18 | [Debug](#debug) |

What each lookup or rights failure produces is in the table [Errors, faults
and silent drops](abi.md#errors-faults-and-silent-drops). An operation that
reaches a preemption point leaves the thread `Restart`, so it re-executes
`syscall` from `fault_ip` with its argument registers unchanged.

All of this is `l4core::syscall`, as functions of the current thread and its
saved registers: `handle_syscall(e, debug)` and `handle_exception(e, vector,
error, cr2)` return an `Outcome`, and `kernel/src/dispatch.rs` does what only
the kernel can with it:

| `Outcome` | The kernel's part |
| --- | --- |
| `Done` | nothing |
| `Preempted` | counts the call, for the `dispatch:` line before `DEBUG HALT` ([Debug](#debug)) |
| `Debug(PutChar(b))`, `Debug(Halt(status))`, `Debug(DumpScheduler)` | performs the debug system call for the current thread, whose registers stay as they are |
| `Stopped(DoubleFault)` | a fault found no handler and the thread is `Inactive`; a debug kernel prints both faults and where the thread stopped |

- The kernel's reply: after a successful invocation the kernel writes the
  reply, `rsi` = `MessageInfo` with label 0 and the result length and
  `rdi` = 0, and after a failed one the error reply, only for a `Call` whose
  caller is still `Running`. ReadRegisters has already written its result
  words as MR0 and up; a self-Suspend by `Call` writes its own empty reply
  before it stops ([Suspend, Resume and
  deletion](#suspend-resume-and-deletion)).
- `invoked_by_call`: some TCB invocations act only for a `Call`:
  ReadRegisters writes its results and a self-Suspend its reply. They ask
  `Threads::invoked_by_call`, which is `l4core::syscall::invoked_by_call`:
  whether the current thread's saved `rdx` is `Call`'s number. Every system
  call preserves `rdx`, and no invocation writes its caller's, so the answer
  holds for the whole invocation. With no current thread, a self-test's
  invocation, it is false.
- Where a preempted call takes its interrupt: the preemption point only polls
  the IRR. The entry ends as every entry does: the scheduler picks a thread,
  usually the caller again, and the pending interrupt is taken as soon as a
  thread runs with IF = 1, which for the caller is at the `syscall`
  instruction it is about to run again, or in `idle_loop`. Its handler runs,
  the timer's tick included, and the caller re-executes its `syscall` when it
  next runs. `test=root` shows this on QEMU: its first `Untyped_Retype` clears
  the largest untyped and is preempted and restarted again and again.

The decoder for Untyped and CNode capabilities, from M4, is
`l4core::invoke::invoke(k, slot, &Message { label, mrs, extra_caps })`. The
caller has looked up the invoked capability's slot and each extra capability
(`ExtraCap { cap, slot }`), as `syscall` does. It returns a `Reply`, whose
`length` counts the result words (none before M5), or an `InvokeError`:
`Error`, which changed nothing, or `Preempted`, with the work so far kept.
It checks the label, then the message length, resolves every slot argument
and performs the call through `l4core::cnode` and `l4core::untyped`. Where
the error tables of [Untyped invocations](abi.md#untyped-invocations) and
[CNode invocations](abi.md#cnode-invocations) leave an order open, it
chooses:

- An empty or Zombie invoked slot is `InvalidCapability` 0, whatever the
  label.
- The label comes before `TruncatedMessage`. A reserved label is
  `IllegalOperation` at once, before any length check or lookup.
- `Untyped_Retype` checks `type` and `size_bits` (`untyped::check_object`)
  before the destination lookup. With `node_depth` 0, a `root` that is not a
  CNode is `FailedLookup` `InvalidRoot`.
- In Copy, Mint, Move and Mutate the source's `depth` is checked as part of
  the source lookup, after the destination's `DeleteFirst`.
- Rotate looks up the destination, then the source, then the pivot.
- `CNode_CancelBadgedSends` (M6) looks up its slot, then needs an Endpoint
  capability with all four rights (`IllegalOperation`), and only then does
  nothing for badge 0: seL4 checks `hasCancelSendRights` before
  `invokeCNodeCancelBadgedSends` looks at the badge.
- `CNode_SaveCaller` (M6) looks up its destination, then checks
  `DeleteFirst`, then the caller slot ([Reply
  capabilities](#reply-capabilities)). With no invoking thread, a
  self-test's invocation, it has nothing to save and is `IllegalOperation`.
- Neither M6 method is preemptible, as in seL4: one moves one capability,
  and the other's loop is bounded by the TCBs that exist ([Deletion and
  cancellation](#deletion-and-cancellation)).

Each is seL4's order except the `node_depth` 0 case
([Memory and retype](#memory-and-retype), Compared with seL4).

From M5 `invoke` takes a TCB capability to `l4core::tcb::invoke` and a Frame,
PDPT, PageDirectory or PageTable capability to `l4core::vspace::invoke`, and
needs `K: Kernel + PagingStore + Threads`; a Reply's `length` counts the
result words, MR0 and up. From M6 the CNode methods use `Threads` too:
`CNode_SaveCaller` takes the invoking thread from the scheduler's current
thread, as seL4 takes `ksCurThread`, and `CNode_CancelBadgedSends` reaches
IPC through the `Threads::cancel_badged_sends` hook, because `invoke` is
generic over `Threads`, not `IpcEnv` ([`core/` and
`arch/`](#core-and-arch-2)). Host tests in `core/src/invoke/ipc_tests.rs`
check both methods' effects, every error row in order, and that a failed
call changes nothing.

Before M5 nothing ran in ring 3, so only a self-test called `invoke`, and it
restarted a preempted call as a thread does. The preemption point polls the
IRR and never enables interrupts; the `Preempted` call returns to the idle
loop, which takes the interrupt, and after `irq::handle` the idle path calls
a resume hook the test installed (`arch::set_resume_hook`). The hook restarts
the call from its unchanged arguments, looking its slots up and decoding it
again. A preemption the test injected with nothing pending waits for the
next timer tick. M4's self-tests still restart their calls this way; without
a hook, the idle path ends in `thread::exit_to_scheduled`.

### `core/` and `arch/`

| Part | Where | Built in |
| --- | --- | --- |
| GDT, TSS, IDT, IST stacks, `PerCpu`, the stubs and their two shared entries, ring-0 exception decode, NMI, #DF, #MC handlers, idle loop and its interrupt path | `arch/x86_64/{gdt,idt,trap,irq}.rs` | M3 |
| Descriptor encodings, the vector map, error-code and fatal-vector masks for the stubs, the trap frame and the fatal report | `l4core::trap`, host tests | M3 |
| Syscall MSRs (`init`), `syscall_entry`, `compat_entry`, `exit_sysret`, `exit_iret`, the ring-0 #DB return at `syscall_entry` and the #BP stub; the seams `user_syscall`, `user_exception`, `user_interrupt`; `exit_to_user`, `load_user_bases`, `save_user_bases` | `arch/x86_64/entry.rs`; `trap_from_user` in `trap.rs` hands ring-3 traps to it | M5 |
| The end of every entry: `exit_to_scheduled`, the thread switch, idling on the kernel PML4 | `arch/x86_64/thread.rs` | M5 |
| `Syscall::from_number`; `STAR`, `FMASK`, the RFLAGS masks, `classify`, `save`, `exit_frame`, `single_step_into_syscall_entry`, `single_step_into_breakpoint_stub` | `l4core::abi`, `l4core::entry`; host tests at `2^47 - 1`, `2^47`, `2^64 - 2^47`, and proptest over all `u64` | M5 |
| Dispatch: `handle_syscall`, `handle_exception`, `Outcome`, `invoked_by_call`; from M6 signals, waits and polls on notifications | `l4core::syscall`; host tests of every system call over fake memory | M5, M6 |
| What only the kernel does with an `Outcome`: debug system calls, the report of a stopped thread, the count of preempted calls | `kernel/src/dispatch.rs` | M5 |
| `test=ring3`: the paths between ring 3 and the kernel, before any real thread exists, in 24 steps through a hook that takes every entry from ring 3 | `arch/x86_64/ring3.rs` (`selftest` only) | M5 |
| The Untyped and CNode decoder: `invoke`, `Message`, `ExtraCap`, `Reply`, `InvokeError`, the labels in `invoke::label`; from M6 `CNode_SaveCaller` and `CNode_CancelBadgedSends` | `l4core::invoke`; host tests of every error row and of errors that occur together, the depth limit, retype, revoke and delete preempted at every point and restarted by decoding again, and proptest over random messages; the M6 methods' tests in `core/src/invoke/ipc_tests.rs` | M4, M6 |
| The resume hook on the idle path, after `irq::handle`, which restarts an M4 self-test's preempted call; without one, the idle path ends in the scheduler | `arch/x86_64/trap.rs` (`interrupt_from_idle`, `set_resume_hook`), `selftest` only | M4 |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| `sysretq` never runs with RCX at or above 2^47 | `l4core::entry::exit_frame`, which takes `iretq` when `next_ip` is at or above 2^47; host tests and proptest; `test=ring3` makes a `syscall` that returns to 2^47 and leaves by `iretq`; M10 brief 5 scenario: `syscall` in the last mappable page, and WriteRegisters with a non-canonical RIP | M5, M10 |
| `sysretq`, `iretq` and the FS and GS base `wrmsr`s at a switch cannot fault in ring 0 | `exit_frame` (constant CS and SS, canonical RIP and RSP, masked RFLAGS); the FS and GS base sanitiser, and `entry::load_user_bases` writes only lower-half bases ([FS and GS base](#fs-and-gs-base)); `test=ring3`'s exits by both paths | M5 |
| User code always runs with IF = 1, IOPL = 0, NT = 0 and the user selectors | `exit_frame`; host test `exit_rflags_keep_only_what_ring_3_may_set` and proptest; `test=ring3` returns from a `syscall` made with NT set without it | M5 |
| Kernel code always runs with IF = 0 outside `idle_loop`, and with DF = AC = TF = NT = 0 | `IA32_FMASK`; `clac` and `cld` in every IDT stub, IST ones included; review; `test=ring3` reads RFLAGS at every entry from ring 3 | M3, M5 |
| `int n` from ring 3 reaches no handler but #BP's, which treats it as the `int3` trap it is | every gate DPL 0 but vector 3's | M3 |
| Vectors 9, 15, 17 and 20 to 31 never reach a fault handler or the interrupt path, and no injected vector makes the kernel misread a frame | no-error-code stubs for 17, 21, 29, 30; panic from either ring; red-team brief 7 | M3, M10 |
| NMI, #DF, #MC and #DB never run on the interrupted RSP and never read GS | IST1 to IST4; a #DB from ring 3 is handled on the kernel stack, its frame left on IST4 (`trap_from_user`), which `test=ring3` checks; review; M10 brief 5 | M3, M5 |
| GS points at `PerCpu` whenever a ring-0 path outside the IST handlers and the two windows reads it | `swapgs` exactly once per ring-3 entry and exit, keyed on saved CS; `test=ring3` reads `IA32_GS_BASE` at every entry from ring 3; review; M10 brief 5 | M5 |
| `sysenter`, compatibility-mode `syscall` and far transfers cannot enter ring 0 | `entry::init` writes `IA32_SYSENTER_CS` = 0, which the boot summary prints; no 32-bit code descriptor; the `IA32_CSTAR` stub, `compat_entry`, panics off the user's stack | M5 |
| A ring-0 interrupt is accepted only from `idle_loop`; every other ring-0 exception panics with a decoded report | `trap_from_kernel` RIP check; M3 page-fault scenario | M3 |
| An overflow of the kernel stack or of the NMI, #MC or #DB IST stack ends in a #DF report, and an overflow of the #DF stack in a second #DF over the first, which stops the machine with the first report possibly cut short; never in silent corruption | a guard page below each of the five stacks, reserved by the linker script and skipped by the M3 table builder; #DF on IST1; the panic path's re-entry guard; M3 scenarios overflow the #DF stack (`df_stack`), the kernel stack (`stack_overflow`) and, from a `test=` hook, the NMI stack after an NMI the kernel sends itself through the ICR (`nmi_stack`), naming its own APIC ID, since the self shorthand is valid only for fixed delivery | M3 |
| The kernel stack holds no state across entries | every entry starts at RSP0 or the stack top; `exit_to_user` rebuilds the frame from the TCB and abandons the stack; `test=ring3` checks that each entry's frame lies at the top of the stack its entry uses | M5 |
| An unknown or, without `debug`, a debug system call number reaches no handler and raises `UnknownSyscall` | `Syscall::from_number`; host tests for both builds; host test `a_number_that_names_no_system_call_is_an_unknown_syscall_fault` through `l4core::syscall` | M5 |
| A preempted system call restarts with the caller's arguments | `fault_ip`, `Restart` ([Register frame and restart](#register-frame-and-restart)), set by `l4core::syscall` and undone by `tcb::activate`; host test `a_preempted_invocation_restarts_its_syscall_and_finishes`; `test=root`'s `Untyped_Retype`, preempted and restarted from ring 3 | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Uniprocessor builds use no `swapgs` and find the thread through `ksCurThread` (`traps.S`, `MAYBE_SWAPGS`) | `swapgs` with a per-CPU area | PLAN.md's Syscall ABI row ([ADR 0008](adr/0008-kernel-entry-and-exit.md)); stubs ready for multi-core; costs one invariant |
| User context pushed straight into the TCB with RSP as the pointer (`handle_fastsyscall`, `LOAD_USER_CONTEXT`) | trap frame on the kernel stack, copied into the TCB in Rust | one frame layout for every entry, logic in Rust; costs a 22-word copy |
| Every IDT gate on IST1, a six-word IRQ stack (`init_tss`, `init_idt_entry` in `src/arch/x86/64/kernel/vspace.c`) | RSP0 for ring-3 entries; IST only for #DF, NMI, #MC, #DB | a nested exception cannot overwrite another's frame |
| `sysretq` after `xor rsp, rsp`; libsel4 keeps RSP in RBX across `syscall` (`restore_user_context`, `syscalls_syscall.h`) | the kernel saves and restores RSP; RBX preserved | the register table in [System calls](abi.md#system-calls) |
| `IA32_STAR[63:48]` = `SEL_CS_3` (`0x2B`), so `sysretq` loads CS selector `0x3B`, GDT_FS's slot, and SS `0x33`, while `iretq` uses CS `0x2B` from the TCB (`init_syscall_msrs`, `src/arch/x86/64/kernel/vspace.c`; `include/arch/x86/arch/64/mode/object/structures.h`; `Arch_initContext`; the SYSRET arithmetic checked on QEMU in M5, [Descriptor tables and MSRs](#descriptor-tables-and-msrs)) | `0x13`: selectors agree on both paths. Like seL4, the field holds an RPL-3 selector | one user CS value |
| System call numbers are negative: `Call` −1 to `NBRecv` −8, debug calls after them (`syscall.xml`; `SysCall == -1` is asserted in `include/arch/arm/arch/64/mode/fastpath/fastpath.h`) | positive: 1 to 8, debug 16 to 18 | [ADR 0022](adr/0022-abi-v0-numbering.md) |
| Optional `sysenter` entry (`CONFIG_SYSENTER`, `handle_syscall` in `traps.S`) | none: `IA32_SYSENTER_CS` = 0 | one entry instruction |
| TSS I/O map base inside the TSS, bitmap all ones (`init_tss`) | I/O map base past the limit | the same effect, no bitmap to keep |
| RIP sanitised at register writes only (`Mode_sanitiseRegister`), `USER_TOP` below the last page (`hardware.h`) | the same, plus the check in `exit_frame` | survives a missed writer; M10 brief 5 |
| Kernel-mode interrupts recorded and replayed (`nested_interrupt`, `c_nested_interrupt`) | none; IF = 0 outside idle | preemption points poll the IRR |
| Vectors below 32 from user mode, NMI included, become user exceptions (`c_handle_interrupt`) | NMI and #MC are fatal, and so are the vectors that cannot occur here (9, 15, 17, 20 to 31) | the thread did not cause them; only a misbehaving device or driver can raise them |
| DPL 3 gates for `int3` and, on one core, vectors 158 to 255; 158 to 254 become unknown system calls (`init_idt_entry`, `c_handle_interrupt`) | DPL 3 only for #BP; any other `int n` raises #GP | one entry instruction, `syscall` ([Rings and segments](#rings-and-segments)) |
| Optional skim window against Meltdown (`CONFIG_KERNEL_SKIM_WINDOW`) and IBRS or RSB flushing against Spectre v2 (`CONFIG_KERNEL_X86_IBRS_BASIC`, `c_traps.c`) | none | non-goal; loses that resistance on affected hosts |

## Kernel objects

Every kernel object is named by a 16-byte capability held in a 32-byte slot.
The object set is seL4's classic x86_64 set without ASID pools, domains,
IOMMU or VT-x objects, plus a Hypervisor capability; memory objects live in
untyped memory, are named by physical address, are aligned to their size and
are at least 16 bytes ([ADR 0009](adr/0009-capability-representation.md)).

### Object and capability types

The capability type tag is kernel-internal; user space names object types
only by the numbers in [Object types and sizes](abi.md#object-types-and-sizes),
in `Untyped_Retype`.

| Tag | Capability | Object type | Size | `data` word | Described in |
| --- | --- | --- | --- | --- | --- |
| 0 | Null (empty slot) | | | 0 | this section |
| 1 | Untyped | 0 | `2^size_bits`, 4 to 47 | watermark, in bytes from the base | [Memory and retype](#memory-and-retype) |
| 2 | TCB | 1 | [TCB layout](#tcb-layout) | 0 | [Threads and TCBs](#threads-and-tcbs) |
| 3 | Endpoint | 2 | [Object types and sizes](abi.md#object-types-and-sizes) | badge, 0 = unbadged | [IPC](#ipc) |
| 4 | Notification | 3 | [Object types and sizes](abi.md#object-types-and-sizes) | badge, 0 = unbadged | [Notifications](#notifications) |
| 5 | CNode | 4 | `2^(radix + 5)`, radix 1 to 42 | guard size (bits 0 to 5) and guard (bits 6 to 63) | [Capability addressing](#capability-addressing) |
| 6 | Frame | 5, 6 | `2^12`, `2^21` | mapping record: `mapped`, `table >> 13` (23 bits), `vaddr >> 12` (35 bits) | [Address spaces](#address-spaces) |
| 7 to 9 | PageTable, PageDirectory, PDPT | 7 to 9 | `2^13` ([Objects](#objects)) | mapping record: `mapped`, parent `table`, `index` (33 bits in all) | [Address spaces](#address-spaces) |
| 10 | PML4 | 10 | `2^13` ([Objects](#objects)) | 0 | [Address spaces](#address-spaces) |
| 11 | IRQControl | none; one at boot | | 0 | [Interrupts](#interrupts) |
| 12 | IRQHandler | none; from IRQControl | | the IRQ | [Interrupts](#interrupts) |
| 13 | IOPortControl | none; one at boot | | 0 | [I/O ports](#io-ports) |
| 14 | IOPort | none; from IOPortControl | | the port range: `first` in bits 0 to 15, `last` in bits 16 to 31 | [I/O ports](#io-ports) |
| 15 | Hypervisor | none; one at boot on Hyper-V | | `restricted`, `connection`, `post`, `signal`; see [The Hypervisor capability](#the-hypervisor-capability-m9) | [Hyper-V interface](#hyper-v-interface) |
| 16 | Reply | none; the master at TCB retype (the root task's at boot), the others by `Call` or fault delivery | names a TCB | bit 0: master | [Reply capabilities](#reply-capabilities) |
| 17 | Zombie | none; kernel-internal | names the CNode or TCB being destroyed | bits 0 to 47: slots left to clear; bit 63: 1 for a TCB | [Deletion and finalisation](#deletion-and-finalisation) |
| 18 to 23 | reserved; no ASID pool type, since back-references replace ASID pools | 11 and up | | | [Address spaces](#address-spaces) |
| 24 to 31 | reserved | | | | |

An object type defined in another section must be at least 16 bytes, a power
of two in size, and hold capability slots only as a TCB does (below).

### Capability representation

A capability is two words, `#[repr(C)] struct Cap { data: u64, header: u64 }`.
The header is the same for every type, so one decoder yields type, object,
size and rights; only `data` (table above) differs by type.

| Header bits | Field | Meaning |
| --- | --- | --- |
| 0 to 4 | `type` | the tag |
| 5 to 10 | `size_bits` | log2 of the object's size in bytes; 0 without memory |
| 11 to 14 | `rights` | Write, Read, Grant, GrantReply, in the rights word's order ([Rights](abi.md#rights)); used by Endpoint (all four), Notification and Frame (Write, Read) and Reply (Grant); 0 for other types |
| 15 | `device` | the memory is device memory (Untyped, Frame) |
| 16 to 63 | `object` | bits 4 to 51 of the object's physical address (a Reply names its TCB); 0 without memory |

The all-zero capability is Null, so fresh CNode memory is a table of empty
slots. Decoding is total: an unknown tag decodes as Null. For Frames and
paging structures the header holds base, size, device bit and rights, and
`data` holds only the mapping record, which `l4core::vspace` writes and
Mint, Mutate and Rotate never touch.

### Slots

A slot is 32 bytes: the capability, then its derivation node (see
[Derivation tracking](#derivation-tracking)). Links are slot physical
addresses, 32-byte aligned; 0 means none. No kernel object lies at physical
address 0: M4 makes no untyped below 1 MiB
([What each physical page becomes](#what-each-physical-page-becomes)), and
`core/` handles are `NonZeroU64`.

| Offset | Bits | Field |
| --- | --- | --- |
| 0 | 0 to 63 | `cap.data` |
| 8 | 0 to 63 | `cap.header` |
| 16 | 0 | `original`: the capability may have children |
| 16 | 5 to 51 | `prev`: bits 5 to 51 of the previous slot's address |
| 16 | 52 to 63 | `depth`, 0 to 4095 |
| 24 | 5 to 51 | `next`: bits 5 to 51 of the next slot's address |
| 24 | 52 to 63 | `low`, 0 to `depth` |

Other bits are zero. Slots live in three places:

- A CNode is `2^radix` slots.
- A TCB keeps five slots at offset 0, in this order: CSpace root, VSpace
  root, IPC buffer frame, `reply` (the master), `caller` (seL4 also puts
  them first, `include/object/structures.h`, `tcbCTable`). A Zombie treats a
  TCB as a container of five slots.
- The IRQ node is 192 slots in kernel static memory, inside the direct map
  ([The IRQ table](#the-irq-table)). They are ordinary slots in the derivation
  list, reached by the same `SlotAddr`; they are not a container, so the
  Zombie code never visits them.

No `CPtr` reaches a TCB or IRQ-node slot.

### How `core/` reaches kernel memory

`core/` makes every slot write, through two traits the kernel implements in
`kernel/src/arch/`. `SlotMemory` loads and stores a `Slot` by value at a
`SlotAddr`, a 32-byte-aligned physical address held in a `NonZeroU64`.
`Kernel: SlotMemory` adds the hooks into other subsystems: `finalise(cap,
last)`, which returns a cleanup capability as seL4's `cleanupInfo` (none
for a TCB), `after_delete(cleanup)`, `moved(cap, old_slot, new_slot)`,
`zero(paddr, len)`, `init_object(cap)` and `preempt()`, a preemption point
that polls the local APIC's IRR (the kernel never opens an `sti` window).
Every type's derivation rule is in `core/` (`l4core::cnode::derive`), so
derivation needs no hook.

Every relocation of a capability, Move, Mutate, both halves of Rotate, the
Rotate swap, every Zombie swap and IPC's `CNode_SaveCaller`, goes through one
`l4core::cdt` move or swap function, which calls `moved` before any preemption
point. The paging code uses it to rewrite a mapped capability's back-reference
([Capabilities](#capabilities)); every use of a back-reference checks the link
in both directions first and panics on a mismatch.

`core/` makes a `SlotAddr` only from a CNode capability and an index below
`2^radix`, a TCB handle (from a TCB capability, a queue or binding link, a
reply capability, or the current thread) and a slot number, an IRQ number, a
link it wrote, or a back-reference word `l4core::vspace` wrote (L2 and L3 in
[Back-references instead of ASIDs](#back-references-instead-of-asids)); the
kernel makes them only at boot. `arch` reads and writes
`PHYS_MAP_BASE + addr` by value through raw pointers, never holding a
reference into slot memory. Its `SAFETY:` argument is that core's invariants
make every `SlotAddr` a slot of a CNode or TCB whose memory has not been
reset, or an IRQ-node slot, all in RAM inside the direct map. Hooks may
change other slots, so `core/` re-reads slots after each. On the host, M2
implements the traits over fake physical memory, a `Vec<u64>` that panics
outside its bounds, so proptest can check zeroing and stray writes and Miri
runs the same tests.

In the kernel, from M4, the implementation is `arch::Objects`
(`arch/x86_64/objects.rs`), over the direct map. Each kernel operation (a
boot step, a system call, a self-test's call) makes one with
`Objects::begin`, which panics before `arch::init` has ended, and drops it
when the operation ends or is preempted. Debug builds check every slot
address and every range `zero` clears against `l4core::objmem::ObjectMemory`,
computed once at the end of step 5: the `USABLE`, `LOADER` and
`ACPI_RECLAIMABLE` memory of the map, merged, clipped to
`[1 MiB, direct map end)`, without the kernel image and a hypercall page the
firmware locked, as sorted ranges, so each check is one binary search. From
boot step 8 they also accept `.rootimage`'s reclaimed pages, which lie in the
kernel image. The IRQ node, 192 slots in the kernel image's `.bss`, lies in
the kernel image too, so from M7 the slot check (`Objects::check_slot`) also
accepts its range, from the physical address `objects::init` computes at the
end of step 5.

M4 left the hooks inert. M5 made them live, and M6 and M7 filled the rest;
each row names the milestone that filled it where that was not M5:

| Hook | Capability | What it does (M5 to M7) |
| --- | --- | --- |
| `init_object` | TCB | `tcb::init` (a full slice, RFLAGS `0x202`), `fpu::init_area` (the FP template; a zeroed MXCSR would unmask every SIMD exception), and in debug builds a place in the debug list |
| `init_object` | PML4 | the kernel's half, entries 256 to 511 (`arch::paging::init_object`) |
| `finalise` | TCB, last | `tcb::finalise`: its notification unbound (M6), then `tcb::suspend` (IPC cancelled, off its ready queue, `Inactive`); `fpu::forget` and `thread::forget` (its FP and FS and GS base ownership dropped without saving), and off the debug list |
| `finalise` | Endpoint or Notification, last; Reply | `ipc::finalise`: an endpoint's queue is released with `cancel_all_ipc`; a notification is unbound, then its waiters are released with `cancel_all_signals` (M6); a reply capability needs nothing |
| `finalise` | Frame, paging structure, PML4 | `arch::paging::finalise`: a mapped Frame or structure is unmapped, and a PML4's last capability empties its user half, loading the kernel PML4 first if CR3 holds it |
| `moved` | Frame, paging structure | `arch::paging::moved`: a mapped capability's back-reference follows it |
| `finalise` | IRQHandler, last (M7) | `l4core::irq::finalise` deletes the IRQ node slot's capability, as seL4's `deletingIRQHandler` (the notification's own `finalise` runs if that was its last capability); returns the IRQHandler as the cleanup |
| `after_delete` | IRQHandler (M7) | `l4core::irq::after_delete` masks the source and frees the entry and its vector, as seL4's `deletedIRQHandler` ([Deletion](#deletion-2)); the kernel executes the mask (`arch::ioapic::perform`) |
| `finalise` | IOPort, last (M7) | `l4core::ioport::finalise` returns the IOPort as the cleanup, as seL4's `Arch_finaliseCap` |
| `after_delete` | IOPort (M7) | `l4core::ioport::after_delete` clears its range in the bitmap, as seL4's `Arch_postCapDeletion` |

`finalise` returns a cleanup only for the last IRQHandler or IOPort
capability, and `after_delete` acts only on those two. For an Untyped,
IRQControl, IOPortControl or Hypervisor capability, which `core/` passes with
`last` set on every deletion, `finalise` never does anything.
`arch::Objects` also implements `Tcbs`, `Scheduling`, `Threads`, `IpcEnv`
and `PagingStore`, and from M7 `Interrupts` and `IoPorts`
([Interrupts](#where-the-code-lives-3), [I/O ports](#where-the-code-lives-4)).
The scheduler lives in a static that only `Objects`
reaches, which is sound while kernel code uses one `Objects` at a time for
scheduler calls. `preempt` reads the IRR; with `selftest` it also counts
polls, times the stretches between them and can report a preemption with
nothing pending, for the self-tests.

### Deletion and finalisation

If a deleted capability was the last to its object (`is_final`), the object
is finalised first, removing every kernel reference to it. Its memory
returns only when the covering untyped is reset. Deletion always runs the
`finalise` hook before it unlinks and zeroes the slot, so a Frame, which
unmaps on every deletion, and a paging structure, which unmaps on its only
deletion, are unmapped while their slot still holds them: a back-reference
never names an empty slot.

| Capability | When the last one is deleted | Described in |
| --- | --- | --- |
| Untyped, IRQControl, IOPortControl, Hypervisor | nothing | [Memory and retype](#memory-and-retype); [Interrupts](#interrupts), [I/O ports](#io-ports), [Hyper-V interface](#hyper-v-interface) |
| CNode | becomes a Zombie; every slot is deleted, the highest first | this section |
| TCB | unbound from its notification, then suspended (off every queue, IPC cancelled), then its slots are deleted as a CNode's | [Suspend, Resume and deletion](#suspend-resume-and-deletion) |
| Endpoint | every queued thread is released and restarts its system call | [Deletion and cancellation](#deletion-and-cancellation) |
| Notification | unbound from its TCB; every waiter released | [Notifications](#deletion-1) |
| Reply | see [Reply capabilities](#reply-capabilities); a master is deleted only when its TCB is finalised | [IPC](#ipc) |
| Frame | on every deletion, not only the last: the mapping this capability records is removed | [Address spaces](#deletion) |
| PageTable, PageDirectory, PDPT | on its only capability's deletion: unmapped from its parent table | [Address spaces](#deletion) |
| PML4 | the VSpace torn down | [Address spaces](#deletion) |
| IRQHandler | masked and unbound; once the slot is empty the IRQ can be issued again | [Interrupts](#deletion-2) |
| IOPort | once the slot is empty the range can be issued again | [I/O ports](#io-ports) |

A CNode or TCB can hold thousands of capabilities, some the last to another
container, so destroying one uses seL4's Zombie scheme (`src/object/cnode.c`:
`finaliseSlot`, `reduceZombie`, `capSwapForDelete`), ported to iterative
Rust:

1. The last capability becomes, in place, a Zombie naming the container and
   the slots left to clear; the slot keeps its derivation node.
2. A deletion a user asked for (`CNode_Delete`, or revoke deleting a
   descendant) clears the container from the highest slot down, one
   capability per step, storing the count in the Zombie and passing a
   preemption point after each step, where seL4's `finaliseSlot` has one; a
   restarted call finds the Zombie in its slot and resumes.
3. A nested deletion, of the last capability to another container `D`, does
   not recurse: `D`'s Zombie is swapped into `D`'s slot 0 and `D`'s old
   slot-0 capability is deleted instead. The swap carries both derivation
   nodes and calls `moved`; a preemption point follows it. A nested
   deletion that meets a Zombie already in its own container's slot 0 stops
   (seL4 `capCyclicZombie`). `D` stays, unreachable, until a revoke of its
   untyped reaches the Zombie (`cspace.tex`, "Deletion and Revocation",
   footnote).
   - **The cycle stop.** If `D`'s slot 0 is the slot being deleted, because
     each container holds the other's last capability, the step leaves
     `D`'s Zombie there, and the deletion ends without emptying the slot,
     before it checks whether `D` has anything left to clear. `D` stays
     detached in its slot 0, as any nested deletion leaves a container,
     even with one slot left. No lookup names that slot, so only a revoke
     gets here, and the revoke's own slot stays reachable. seL4 goes on to
     clear `D`, which a restarted revoke would not find again, so there the
     outcome depends on where the interrupt falls; here it does not.
4. The slot empties when the count reaches 0, or 1 with the Zombie in the
   container's own slot 0, except after the cycle stop of step 3, where it
   keeps `D`'s Zombie.

Nesting is at most two calls deep. A Zombie cannot be invoked
(`InvalidCapability`) or derived (`IllegalOperation`); it can be moved, and
deleting it resumes the clearing. A Zombie is not a CNode capability, so a
lookup stops at it: as a thread's CSpace root it gives `InvalidRoot`, and on
a path it ends the lookup like any other non-CNode slot. Since finalisation
starts only at the last capability to a container, no lookup reaches the
slots of a container being destroyed, and a TCB is suspended before its
slots are cleared, so the kernel inserts nothing into them either.

### Built when

M2: representation, slot traits, finality and the Zombie algorithm, with a
test `Kernel` that records hook calls. M4: CNode layout and the `arch`
implementations, `arch::Objects` with `l4core::objmem` behind its debug
assertions, every hook still inert. Then the hooks: M5 for TCBs, Endpoints,
Reply capabilities and paging objects (`arch/x86_64/objects.rs`, with
`paging.rs`, `fpu.rs` and `thread.rs`); M6 for Notifications and
`CNode_SaveCaller`; M7 for IRQHandlers, IOPorts and the IRQ node; M9 for
Hypervisor capabilities.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A capability never outlives its object: an object's memory is reused only when the untyped covering it is reset, which needs it to have no descendants, and every capability to an object in that region, except a reply capability (next row), is a descendant | `l4core` retype, insert and delete; proptest against `model/` with object liveness | M2 |
| Reply capabilities, the one exception (a master is a derivation root), never outlive their TCB: TCB finalisation deletes the outstanding reply capability (suspend, `cancel_ipc`) and the Zombie deletes the master before the TCB's last capability's slot empties | the TCB `finalise` hook's `tcb::finalise`, whose `tcb::suspend` calls `ipc::cancel_ipc`; host tests `suspending_a_caller_deletes_the_reply_capability_to_it` and `a_handler_that_deletes_the_faulting_thread_leaves_nothing_naming_it`; `test=fault`; from M6 the IPC model's proptest (`model/tests/ipc_random.rs`), which deletes TCBs whatever their state, a `Call` included, and its scenario `a_saved_reply_goes_when_its_caller_is_suspended_and_survives_its_holder` | M2, M5, M6 |
| No kernel object lies at physical address 0 | `l4core::boot::page_class` makes no untyped below 1 MiB, which `check_untyped` checks in host tests and `test=bootinfo`; `core/` handles are `NonZeroU64` | M2, M4 |
| No kernel reference (queue, binding, mapping) survives the last capability to its target | `finalise` hooks called by `core/` delete (M5: TCBs, Endpoints, Frames and paging structures; M6: Notifications and TCB bindings, above); proptest counts finalisations; each subsystem's tests, M5's in `core/src/{tcb,ipc,syscall}/tests.rs` and the `vspace` proptest, M6's in `core/src/ipc/notification/tests.rs` (`deleting_a_notification_restarts_its_waiters_in_order_and_unbinds_it`, `deleting_a_bound_tcb_unbinds_its_notification`) and the IPC model's proptest, which deletes endpoints, notifications and TCBs; M7's in `core/src/irq/tests.rs` (`deleting_the_last_handler_unbinds_masks_keeping_vector_and_trigger_and_frees_the_irq`, `deleting_the_handler_deletes_the_irq_nodes_capability_and_may_finalise_its_notification`, `revoking_irq_control_deletes_every_handler`) and `core/src/ioport/tests.rs` (`a_range_is_free_again_only_once_its_last_capability_is_deleted`, `the_hooks_free_only_the_last_capabilitys_range`), and the IRQ table's and the port bitmap's proptests, which delete, copy and revoke at random; `test=irq` and `test=ioport` | M2, M5 to M7, M9 |
| A back-reference never names an empty slot | `finalise` runs before unlink and zeroing, and the paging `finalise` unmaps through the slot its capability still occupies; the `vspace` proptest with mapped capabilities ([Address spaces](#address-spaces)) | M2, M5 |
| The last capability to an object is finalised exactly once, before its slot empties | `is_final` and the Zombie algorithm; proptest with random preemption | M2 |
| Every TCB, Endpoint, Notification, CNode and paging structure lies in RAM inside the direct map, below 64 GiB | retype refuses kernel objects from device untyped; RAM untyped only below the direct map's end, `min(phys_map_size, 64 GiB)` (`page_class`, checked by `check_untyped` in host tests and `test=bootinfo`); in debug builds `arch::Objects` checks every slot and zeroed range against `ObjectMemory` | M2, M4 |
| Only `core/` writes slots, and every `SlotAddr`, including each back-reference word, is a slot of a CNode or TCB whose memory has not been reset, or an IRQ-node slot | `SlotAddr` built only from capabilities, the current thread, IRQ numbers, links and back-references (L2, L3 in [Address spaces](#back-references-instead-of-asids)); fake memory panics on stray access; debug asserts in `arch::Objects` check every slot address against `l4core::objmem::ObjectMemory` (M4), which M7 widens to the IRQ node (`Objects::check_slot`); an IRQ-node `SlotAddr` comes only from an IRQ number below 192 (`l4core::irq::node_slot`), and the test kernels keep the node in fake memory of its own (`l4core::testing::IRQ_NODE_BASE`), so a stray one panics there too (M7); `l4core::vspace::paging` uses a back-reference only after checking that its slot holds the capability whose record names that entry (M5) | M2, M4, M5, M7 |
| Capabilities are created only by boot, retype, IRQControl and IOPortControl invocations, `Call` and fault delivery (reply capabilities), and deletion (Zombies); every other capability is derived from one its holder has | the only callers of `insert_root` and `insert_derived`; red-team brief 1 | M2, M10 |
| Destroying a CNode or TCB is preemptible, recurses at most two levels, and keeps every invariant at each step | Zombie algorithm; proptest with random preemption points over nested and cyclic containers, including deleting a slot inside the container its own deletion destroys | M2 |
| No lookup reaches, and the kernel inserts nothing into, a slot of a CNode or TCB being destroyed | finalisation starts only at the last capability, which becomes a Zombie that lookups stop at; the TCB `finalise` hook suspends the thread before `core/` clears its slots; proptest | M2, M5 |
| The Zombie code clears only CNode and TCB slots, never IRQ-node slots | IRQ-node slots belong to no container: the node is `IRQ_NODE` in the kernel image's `.bss` (`arch/x86_64/objects.rs`), and in the test kernels memory of its own at `IRQ_NODE_BASE`, which no CNode or TCB covers; M2's proptest, whose root CNode holds an IRQHandler; `test=redteam-irq`, which deletes a CNode K holding a handler whose IRQ node slot holds the last capability to a notification a thread W waits on, so that the handler is finalised inside the Zombie's reduction and its own hook (`irq::finalise`) deletes that capability from the IRQ node; the test checks that the kernel survives the deletion, that W never woke, and that ISA IRQ 0 (GSI 2) can be issued again. That W is released is not observed: released, it restarts its Wait on an empty slot and stops on the capability fault, with no fault handler, which root cannot tell from W still waiting | M2, M7 |
| Every relocation of a capability to another slot calls `moved(cap, old_slot, new_slot)` before the next preemption point, so back-references stay exact | one `l4core::cdt` move and one swap function, used by Move, Mutate, both halves of Rotate, the Rotate swap, every Zombie swap and `CNode_SaveCaller`; `arch::paging::moved` rewrites the back-reference; proptest over nested CNode deletion with a mapped capability in slot 0 of the nested CNode, rotates and swaps of mapped capabilities, and untyped revoke, at random preemption points (the `vspace` proptest from M5); host test `moves_rotates_and_swaps_rewrite_back_references`; `CNode_SaveCaller` moves with `cdt::move_slot` (M6; host test `save_caller_moves_the_reply_capability_below_its_callers_master`); red-team brief 4 | M2, M5, M6, M10 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| A bitfield layout per capability type (`include/object/structures_64.bf`, `include/arch/x86/arch/64/mode/object/structures.bf`) | One common header word and one per-type data word | One decoder for type, object, size and rights in `core/`; costs packing room, so a Frame's mapping record must fit one word |
| Capabilities hold kernel virtual pointers | Physical addresses | `core/` stays address-free and host-testable; `arch` adds `PHYS_MAP_BASE` |
| ASID control and pool capabilities | None; tags 18 to 23 stay reserved | Paging structures keep back-references to the installing slots instead ([ADR 0005](adr/0005-paging-back-references.md)) |
| Domain, IOSpace, VCPU and EPT capabilities | None | One scheduling domain, no IOMMU, no VT-x |
| No Hypervisor capability | Tag 15 | Hyper-V SynIC and hypercalls (PLAN.md, Hyper-V interface) |
| Odd tags mark architecture capabilities (`isArchCap`) | Flat 5-bit tags | One architecture |
| TCB slots in the order CTable, VTable, Reply, Caller, Buffer (`tcb_cnode_index`, `include/object/structures.h`) | CSpace root, VSpace root, IPC buffer, `reply`, `caller` | The [TCB layout](#tcb-layout); only the Zombie's clearing order (highest slot first) depends on it |
| When a cycle of containers leaves `D`'s Zombie in the slot being deleted, the same deletion goes on to clear `D`, and empties the slot at once if `D` has one slot left (`finaliseSlot`, `reduceZombie`, `src/object/cnode.c`) | The deletion ends there, before checking whether the Zombie is removable; `D`'s Zombie stays, detached, in `D`'s slot 0 until a deletion reaches it (step 3, the cycle stop). Otherwise deletion and revoke are seL4's, preemption points and partial revokes included | No lookup names that slot, so only a revoke gets there, and its own slot stays reachable. A restarted revoke looks for work only among the revoked capability's descendants, which `D`'s Zombie need not be, so a preemption point while clearing `D`, or before emptying the slot, would make the outcome depend on where the interrupt fell |

## Memory and retype

Retyping untyped memory is the only allocator, with seL4's rules: an untyped
allocates at its watermark, aligned up to each object's size, while it has
children, and is reset (cleared, watermark 0) only when it has none. Device
untyped yields only Frames and device untyped, and is never cleared.

### Retype

An untyped capability holds its base, `size_bits` (4 to 47), the device bit
and the watermark. Below the watermark there may be objects or stale data;
at or above it there is no live object and, in RAM, only zeros. Boot makes
every untyped with the watermark at its size, so the first retype clears it.
`Untyped_Retype` takes seL4's arguments (`type`, `size_bits`, `root`,
`node_index`, `node_depth`, `node_offset`, `num_objects`; `object-api.xml`)
and checks them in seL4's order (`src/object/untyped.c`;
[Untyped invocations](abi.md#untyped-invocations) lists each error; the
differences are under Compared with seL4 below). Then:

1. If the untyped has no children, start at 0 and reset first; otherwise
   start at the watermark.
2. If `(2^size_bits - start) >> object_bits < num_objects`, fail with
   `NotEnoughMemory`. Alignment cannot make a fitting request fail: the
   untyped's end is aligned to every smaller object size.
3. A kernel object from device untyped fails with `InvalidArgument`; an
   untyped at depth 4095 fails with `IllegalOperation`.
4. Reset if due, then set the watermark to the aligned start plus
   `num_objects << object_bits`.
5. Create the objects at consecutive aligned addresses. The memory is
   already zero, so `init_object` writes only non-zero fields. A new
   untyped starts with its watermark at 0, as seL4's `createObject` does:
   its RAM is zero, and device memory is never cleared.
6. Put each capability, with full rights, in slots `node_offset` onwards of
   the destination CNode, as an original child of the untyped. A new TCB's
   Reply master goes in its `reply` slot as a derivation root at depth 0,
   as seL4's `setupReplyMaster` makes it, so a `Call`'s reply
   capability is always at depth 1 and never meets the depth limit.

At most 256 objects per call (`RETYPE_FAN_OUT_LIMIT`, seL4's default), so
steps 5 and 6 need no preemption point. Kernel objects come only from RAM
untyped, and M4 makes RAM untyped only below the direct map's end, at most
64 GiB. Paging structures are 8 KiB and aligned to 8 KiB like every
object, so their addresses fit the 23-bit `table` field of a paging
capability ([Capabilities](#capabilities)).

### Reset and preemption

A reset clears `[0, watermark)` from the top down in 4 KiB chunks, lowering
the watermark after each and passing a preemption point. A preempted retype
restarts, decodes again, still finds no children and continues from the
lower watermark, so it progresses and "zero above the watermark" holds at
every step. An untyped smaller than a chunk is cleared in one step, as
seL4 does below its chunk size. A device untyped only sets its watermark to
0 (seL4 `resetUntypedCap`).

### Copies, revoke and reclaim

- Copying an untyped (Copy, Mint, IPC transfer) needs it to have no children
  (`RevokeFirst`). The copy is an original child and keeps the source's
  watermark, so memory the source handed out is reset before anything is
  made there again; the source's watermark then goes to its size, so only the
  copy allocates (seL4 `setUntypedCapAsFull`).
  Moving an untyped carries its watermark.
- Revoking an untyped deletes every capability derived from it, so every
  object in its region is finalised and the next retype resets it. This is
  how memory is reclaimed.
- Deleting an untyped whose objects live hands them to its parent, whose
  watermark already covers them. A boot untyped has no parent, so once it is
  deleted its region is never retyped again, even after those objects die,
  as in seL4.

PLAN.md's M2 says "an untyped with children cannot be retyped". microL4 keeps
seL4's rule instead ([ADR 0010](adr/0010-retype-watermark.md)): an untyped
with children cannot be reset or copied, and retype never overlaps a live
object.

### Built when

M2: `l4core::untyped` (checks, alignment, watermark, reset steps, placement)
against `model/` on fake memory. M4: boot untyped (`l4core::boot::untyped`),
`zero` and `init_object` in `arch::Objects` (`init_object` does nothing
until M5's TCB and PML4), `Untyped_Retype` decoded by `l4core::invoke`, which
runs `untyped::check_object` on `type` and `size_bits` before the
destination lookup, and `test=retype`, the self-test that retypes, revokes
and retypes again.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Retype never overlaps a live object | watermark rises while the untyped has children; reset only with none; proptest checks live objects are pairwise disjoint | M2 |
| An untyped with children is never reset or copied | `has_children` in retype and `derive`; proptest | M2 |
| Retype never allocates outside its untyped, and its arithmetic cannot overflow | `size_bits` at most 47, `num_objects` at most 256, the shift test of step 2; proptest with extreme arguments; red-team brief 3 | M2, M10 |
| Every object is aligned to its size | align-up in step 4; proptest | M2 |
| RAM at or above a watermark is zero, so every new object starts zeroed | reset clears before lowering the watermark; fake memory checked after each step; `test=retype` fills the first run's objects where nothing reads them before a reset (frames, TCBs' registers and XSAVE areas, PML4s' back-references 256 to 511), revokes U, and finds the 2,067 KiB the second run makes there zero, or as retype makes them (a TCB's RFLAGS and FP template) | M2, M4 |
| Device untyped yields only Frames and device untyped, and is never cleared | type check in retype; device bit inherited; red-team brief 3 | M2, M10 |
| A preempted reset leaves a consistent untyped, and the restarted retype completes it | top-down chunks; proptest with random preemption | M2 |
| Revoking an untyped and retyping it again gives the same objects at the same addresses | `test=retype`: 27 calls through `l4core::invoke` per run with CPtrs into the root CNode: U (the largest RAM untyped, 64 MiB on QEMU) into every object type, the CNode methods between the root CNode and a new CNode C, the child untyped retyped, a copy of root slot 9 and a mint of root slot 2 put in C, and three calls that must fail. The second run's slots (all four words and the parent) equal the first's. After each revoke the 26 slots the test filled are empty, every boot capability, U included, is the first run's capability as a root without links (from M5, but for the root TCB's copies of root slots 2, 3 and 10), slots 9 and 2 have no children (so only C's Zombie can have deleted their copies), and `cdt::check_slot` holds for every recorded slot and every root CNode slot. The test waits, interrupts off, until the timer is pending, so the first poll of U's first reset is always preempted by an interrupt; injected preemptions follow, and each call restarts from the idle path. A core with CNode Zombies disabled, or with the reset's clearing removed, fails it. `l4core::invoke` host tests restart retype, revoke and delete at every preemption point and end with the unpreempted call's memory and hook calls | M4 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Watermark (`capFreeIndex`) in 16-byte units | In bytes | The data word has room |
| `CONFIG_RESET_CHUNK_BITS` = 8; a preemption check every 100 work units | 4 KiB chunks; how often `preempt` polls is the kernel's choice | Fewer checks per page; `core/` stays agnostic of the polling cost |
| `size_bits` too small is `InvalidArgument` 1, too large `RangeError` 0 to 47 in object-size bits; a device type error is `InvalidArgument` 1; `node_depth` over 64 is `RangeError` 1 to 64, reported after `InvalidRoot` (`lookupSlotForCNodeOp`, `src/kernel/cspace.c`) | `RangeError` with the exact range of the argument at fault; the device error is `InvalidArgument` 0 (`type`); `node_depth` 0 to 64, checked before the root | Detail words name the argument at fault and its real range |
| `size_bits` of 64 or more is `RangeError` 0 to 47 for every type, fixed-size ones included (`decodeUntypedInvocation`), although `objects.tex`, "Summary of Object Sizes", says it is ignored | Ignored for fixed-size types | As the manual; the argument means nothing for them |
| A destination that is not a CNode is `MissingCapability` with `node_depth` bits left; with `node_depth` 0 the root check is skipped, so a `root` that is not a CNode is this case, with 0 bits left (`decodeUntypedInvocation`) | 0 bits left; `InvalidRoot` when `root` is not a CNode, at every `node_depth`, 0 included | One meaning for "bits left" in CNode lookups ([Lookup failures](#lookup-failures)), and one error for a `root` that is not a CNode; paging `FailedLookup` counts virtual-address bits |
| No derivation depth limit | Retype fails at depth 4095 | Field width ([Derivation tracking](#derivation-tracking)) |

## Capability addressing

A CSpace is seL4's guarded radix tree of CNodes with no fixed number of
levels: a `CPtr` is resolved from its most significant end, each CNode
consuming its guard and then `radix` bits, as `resolveAddressBits` does
(`src/kernel/cspace.c`). PLAN.md's "at most two levels to start" becomes a
root-task convention, not a kernel limit
([ADR 0011](adr/0011-cspace-levels.md)).

### Resolution

`resolve(root, cptr, n)` resolves the low `n` bits of `cptr`:

1. If `root` is not a CNode capability: `InvalidRoot`.
2. If `guard_size > n`, or the next `guard_size` bits differ from `guard`:
   `GuardMismatch`.
3. If `radix + guard_size > n`: `DepthMismatch`.
4. The next `radix` bits index the slot; `n` drops by `radix + guard_size`.
5. If `n` is 0, the result is the slot. If the slot holds a CNode
   capability, continue at 2 with it; otherwise the result is the slot, with
   `n` bits left.

Each level consumes at least one bit (radix is at least 1), so a lookup
takes at most 64 levels and needs no preemption point. Shifts use
`checked_shr` so that `n` = 64 with `guard_size` = 0 is defined.

### Two kinds of lookup

- **Capability lookups** (the invoked capability, extra capabilities, the
  fault endpoint, `receive_cnode`) start at the thread's CSpace root with
  `n` = 64, stop at the first slot not holding a CNode capability (empty
  included) and ignore the bits left, as in seL4: they consume up to 64
  bits. Failing on the invoked or an extra capability is a capability fault
  ([Faults](#faults)) carrying the lookup-failure words; [Faults](#faults)
  and [IPC](#ipc) handle the others.
- **Slot lookups** (each (root, index, depth) of a CNode or Untyped
  invocation, and the receive slot) need `depth` from 1 to 64
  (`RangeError`; `Untyped_Retype`'s `node_depth` may also be 0, naming
  `root` itself) and resolve exactly `depth` bits; bits left are a
  `DepthMismatch` with bits found 0. To name a slot holding a CNode
  capability, give the depth that ends there. Failing is `FailedLookup`.

### Lookup failures

| Failure | Detail | Raised when |
| --- | --- | --- |
| `InvalidRoot` | | the root is not a CNode capability |
| `MissingCapability` | bits left | the slot found is empty or of the wrong type for the operation |
| `DepthMismatch` | bits left, bits found | a CNode would resolve more bits than remain (bits found = its radix plus guard size), or a slot lookup stopped at a non-CNode with bits left (bits found = 0) |
| `GuardMismatch` | bits left, guard, guard size | the guard is longer than the bits left, or differs from them |

"Bits left" is always the number of `CPtr` bits not yet resolved where the
lookup stopped, so it is 0 when a slot lookup resolved exactly.
[Lookup failure description](abi.md#lookup-failure-description) gives the
encoding. A thread names only slots reachable from its CSpace
root. CNode capabilities carry no rights: holding one is full authority over
its slots. Guards change addressing, not authority, so Mint, Mutate and
Rotate may set any guard whose size plus the radix fits in 64 bits.

### Built when

M2: `resolve` in `l4core::cspace`, with host tests over hand-built CSpaces
and proptest over random guards, radixes and `CPtr`s. M4: slot arguments of
CNode and Untyped invocations, which `l4core::invoke` looks up from the
invoked CNode or from the extra capability `root`, `src_root` or
`pivot_root`, each with its own root and `depth` checks
([System-call dispatch](#system-call-dispatch)). M5: capability lookups from
the TCB's root.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A lookup returns only a slot of a live CNode reachable from its root | slots computed from CNode capabilities with index below `2^radix`; proptest against `model/` lookup | M2 |
| A lookup ends within 64 levels and never overflows or panics, for any `CPtr`, depth and guard | each level consumes at least 1 bit; checked shifts; proptest; red-team brief 6 fuzzer | M2, M10 |
| A slot lookup resolves exactly `depth` bits | `DepthMismatch` on bits left; host tests | M2 |
| Every CNode capability has `radix >= 1` and `guard_size + radix <= 64` | retype bounds; capability-data checks in Mint, Mutate and Rotate | M2 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| An empty source slot is `MissingCapability` with the source depth as bits left (`src/object/cnode.c`) | 0 bits left | "Bits left" means the same in every CNode lookup report |
| Rotate reports a pivot that fails to resolve as a source, but an empty pivot as not a source (`src/object/cnode.c`) | Both as a source | The was-source word means the same for every pivot failure |

## Derivation tracking

Each derivation tree is a doubly linked list of slots in preorder, and each
slot stores its tree `depth`, an `original` flag and `low`, the smallest
depth among itself and any deleted slots that stood between it and its
predecessor. A slot's descendants are the run of slots after it whose `low`
exceeds its depth, so revoke, "has children" and delete need no knowledge
of types ([ADR 0012](adr/0012-derivation-depths.md)).

### The list

A derived capability is inserted next to its source; boot capabilities are
roots (depth 0, original, each its own list). A slot `a` has children when
`next(a)` exists and `low(next(a)) > depth(a)`; its descendants are the
slots reached by following `next` while `low > depth(a)`. `is_final(a)`
holds when neither list neighbour names the same object: same type and
address, plus the same size for Frames (base and size), the same IRQ for
IRQHandlers and the same range for IOPorts; Untyped, control and Hypervisor
capabilities never share an object (seL4 `sameObjectAs`). A PDPT,
PageDirectory or PageTable capability cannot be derived, so it is unique and
always final; PML4 copies use the general rule. `is_final` is exact because
each derivation lands next to its source, so all capabilities to one object
are adjacent.

### Child or sibling

Every derived capability goes right after its source, as seL4's `cteInsert`
puts it. It is a child if the source is original; otherwise it is a sibling,
sharing the source's parent.

| Insert | Where | New slot | Neighbour |
| --- | --- | --- | --- |
| child `c` of an original `a` | right after `a` | `depth = depth(a) + 1`, `low = depth` | unchanged |
| sibling `s` of a plain copy `n` | right after `n` | `depth = depth(n)`, `low = depth` | unchanged |
| root | a list of its own | `depth = low = 0` | |

A new capability is original if it comes from retype, is an untyped, is an
Endpoint or Notification badged by this Mint, is a Hypervisor capability
this Mint narrowed, is an IRQHandler or IOPort issued by its control
capability, or is a boot capability or a Reply master, which are roots
(seL4 `isCapRevocable`, `insertNewCap`, `setupReplyMaster`). Any other
derived capability is a plain copy: it never has children, copying it makes
a sibling, and its holder can revoke nothing.

A child deeper than `MAX_DERIVATION_DEPTH` (4095) is refused. Honest trees
are a few dozen levels deep (untyped splits, then at most three levels per
object), but `depth` also counts deleted ancestors, so it only grows down a
chain: a ring-3 task holding an untyped reaches 4095 in about 8,190 calls by
copying it and deleting the source, over and over, with three slots. The
damage stays in that task's subtree: only derivations below its own
capabilities fail, and the holder of any ancestor can still revoke. One
child-insert function in `l4core::cdt` checks the limit; siblings keep
their source's depth and need no check. Every path that installs a derived
copy reports the refusal as `IllegalOperation`: `CNode_Copy`, `CNode_Mint`,
`Untyped_Retype` (an untyped at depth 4095), `TCB_Configure`,
`TCB_SetSpace` and `TCB_SetIPCBuffer`
([Creation and configuration](#creation-and-configuration)), and
`IRQHandler_SetNotification`
([IRQControl and IRQHandler](#irqcontrol-and-irqhandler)); IPC transfer
skips the capability ([Capability transfer](#capability-transfer)). Paths
that make children of roots never meet the limit: a
`Call`'s reply capability (child of its depth-0 master) and the IRQHandler
or IOPort issued by a control capability (a boot root) are at depth 1.

### Deleting from the middle

Unlinking `m` sets `low(next(m)) = min(low(next(m)), low(m))`. Picture
deleted slots as ghosts still in the list: the live list is the full
preorder with the ghosts removed, and `low(n)` is the smallest depth among
`n` and the ghosts just before it. A slot's subtree in the full list ends at
the first slot, live or ghost, no deeper than it, and `low` keeps the
ghosts' depths visible. So a deleted capability's children pass to its
nearest surviving ancestor, as in seL4, in constant time:

```
U(0) A(1) X(1) C(2)    delete X:   U(0) A(1) C(2, low 1)
revoke A: low(C) = 1, not > 1, so C is not A's.   revoke U: 1 > 0, C goes.
```

Without `low`, `C` would fall into `A`'s run and `A`'s holder could delete
it. A child goes right after its parent, before any ghosts, so it is the
parent's first child; a sibling goes right after a plain copy, which never
has children, so in the full list whatever follows it is no deeper. A
deeper live slot may follow it in the live list, but that slot's `low`
records the ghost between them. Either way the full list stays a valid
preorder.

### Slot operations

| Operation | Capability | Derivation list |
| --- | --- | --- |
| Copy | the source's, rights masked | child or sibling of the source |
| Mint | as Copy, plus the data word: a badge onto an unbadged Endpoint or Notification (a badged one fails, `IllegalOperation`), a CNode guard, or a Hypervisor narrowing | as Copy; a new badge or a narrowing makes it original |
| Move | unchanged | the node moves with it; neighbours' links rewritten; source zeroed; `moved` called |
| Mutate | Move, plus a CNode guard; an Endpoint or Notification, or a Hypervisor capability with a non-zero word, fails with `IllegalOperation` | as Move |
| Rotate | two Moves with data as Mutate, atomically, `moved` called for each; a swap when destination and source are one slot | as Move, twice |
| Delete | finalised if last, then removed | unlinked; `low` passes to the next slot |
| Revoke | the slot's own capability unchanged | delete `next(a)` while `has_children(a)`, a preemption point after each |

Rotate is kept: it swaps two capabilities without a spare slot, and `core/`
needs the swap for Zombies anyway. Mutate is kept: it is the only way to set
the guard of an original CNode capability without making a child. Revoke and
delete are sequences of single-capability steps with a preemption point
after each, where seL4 has them; an interrupted call restarts, looks its
slot up again and goes on ([System-call dispatch](#system-call-dispatch)).
Revoke re-reads its slot every step, so it stops cleanly if it deletes the
CNode holding its own slot. As in seL4 (`cspace.tex`, "Deletion and
Revocation"), a call can end part way in two cases:

- **Its work destroys a CNode on the lookup path that named its slot.** For
  a revoke this is the partial revoke, and any CNode on the path can go,
  the one holding its slot included. A Delete destroys only the CNode whose
  last capability its slot holds and the CNodes whose last capabilities lie
  in those, which a path reaches only through the deleted slot, so only a
  path that runs through that slot itself can be destroyed. Unpreempted,
  the call goes on as seL4's does: a revoke finishes the deletion that took
  the revoked capability with it, then stops, and the revoked capability's
  descendants not yet deleted pass to its parent and survive. Preempted
  once the path is destroyed, the restarted call fails its lookup and
  returns that failure, with the rest of the work undone, so the outcome
  depends on where the interrupt fell.
- **Its work finalises the caller's own TCB.** The caller is suspended, so a
  preempted call is never restarted.
- **Its work deletes the caller's own VSpace or IPC buffer before its TCB.**
  Preempted after that, the caller is restarted, but it cannot issue the
  call again: on its way back to ring 3 it faults (to its fault endpoint, or
  stops), so the rest of the work stays undone until a later revoke or
  delete finishes it. `test=redteam-selfdelete` meets this when a timer tick
  falls inside its round-1 revoke, and its root task finishes the revoke.

What a call cut short leaves is safe. Every slot keeps the derivation-list
invariants, every capability naming memory inside an untyped is still that
untyped's descendant, so no reset reuses memory a capability names, and the
work left can be finished. A Delete finishes a Zombie left in a slot the
user can name, such as the slot where the destroyed CNode's last capability
was ([Deletion and finalisation](#deletion-and-finalisation)); a Delete cut
short leaves only that. A revoke of an ancestor untyped finishes the rest:
a Zombie in its own CNode's slot 0, or capabilities left in a CNode no
lookup reaches, the revoked capability among them. Under a boot untyped,
which has no parent, that region stays dead. A user avoids all this, as in
seL4, by not naming a slot through a path the call destroys.

Copy, Mint, IPC transfer and the TCB and IRQ-node installs go through
`derive`, as seL4's `deriveCap`. It refuses Null, Zombie, Reply,
IRQControl, IOPortControl, PDPT, PageDirectory and PageTable capabilities
(`IllegalOperation`; paging structures are move-only) and an untyped
with children (`RevokeFirst`). It gives an unmapped copy of a Frame, whether
or not the source is mapped. PML4 and Hypervisor capabilities derive. Rights
only shrink: Copy and Mint take `rights(source) & rights(argument)`; nothing
else touches rights. A badge is set once and copies keep it (`ipc.tex`,
"Endpoint Badges"); Mint with badge 0 on an unbadged source is a Copy, and
any Mint of a badged source fails. A Hypervisor Mint only
narrows ([The Hypervisor capability](#the-hypervisor-capability-m9)); data 0
is a Copy.

### Badges, revoke and `CNode_CancelBadgedSends`

To retire badge `b`, a server revokes its badged original `B`, deleting
every capability derived from `B` wherever it was copied or sent, then calls
`CNode_CancelBadgedSends` on `B` to release senders already queued with `b`
(the queue side is in [Deletion and cancellation](#deletion-and-cancellation)),
and may then mint `b` again. Revoke
reaches only `B`'s descendants; another original with the same badge,
minted again or by a holder of an unbadged capability, survives. So a server
mints each badge once and gives clients only badged capabilities.
`CNode_CancelBadgedSends` needs an Endpoint capability with all four rights
(seL4 `hasCancelSendRights`) and does nothing for badge 0
(`invokeCNodeCancelBadgedSends`), so the server mints `B` with all four and
hands clients copies of `B` with fewer: a Copy of an original is its child,
so the revoke deletes it. Revoke comes first because the released senders
restart and resolve their `CPtr`s again: with the copies gone they find empty
slots and cannot queue again with `b`. A client whose `Call` was already
received keeps waiting for its reply, which no revoke or cancel touches
([Deletion and cancellation](#deletion-and-cancellation)).

### Built when

M2: `l4core::cdt` (insert, move, swap, unlink, runs, `is_final`), the
slot operations and every type's derive rule (paging included), against
`model/`, which keeps an explicit parent map;
proptest compares capabilities and parents after every step, including at
random preemption points. M4: CNode invocations decoded by `l4core::invoke`,
with `CNode_CancelBadgedSends` and `CNode_SaveCaller` `IllegalOperation`
until M6. M5: reply masters and reply capabilities, the TCB installs. M6: IPC
transfer (`ipc::transfer`, which copies through `cnode::copy`),
`CNode_SaveCaller` (`ipc::save_caller`, a `cdt::move_slot`) and
`CNode_CancelBadgedSends` (`ipc::cancel_badged_sends`). M7: the IRQ-node
install. M9: Hypervisor narrowing.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Revoke deletes exactly the capabilities derived, directly or not, from the slot, unless it is a partial revoke ([Slot operations](#slot-operations)) | `low`-run walk; proptest against `model/`'s transitive parent map | M2 |
| Deleting a capability changes no survivor's ancestry except that its children pass to its nearest surviving ancestor | `low` update in unlink; proptest | M2 |
| Rights never grow, a badge is set once, only Mint sets a badge, and a Hypervisor Mint never widens | `derive`, Mint and Mutate rules; proptest; from M6 IPC transfer copies with `cnode::copy` and every right of the source (host test `a_copy_of_a_copy_is_its_sibling_and_a_badged_original_keeps_its_badge`, the transfer proptest `random_sends_move_capabilities_where_the_model_says`), and `test=badge`, whose clients call through copies of the badged originals B1 and B2 with fewer rights and the original badges, and where `CNode_Mint` of B1 with a new badge, or of a copy of it with its own, is `IllegalOperation`; `core::hyperv` host tests; red-team brief 1 | M2, M6, M9, M10 |
| A PDPT, PageDirectory or PageTable capability is never derived, and a derived Frame capability is never mapped | `derive`, which gives an unmapped copy of a Frame; the `vspace` proptest copies mapped capabilities and checks every mapping record against its model; red-team brief 4 | M2, M5, M10 |
| A plain copy never has children, so holding one gives no power over other copies | the `original` rule; proptest | M2 |
| All capabilities to one object are adjacent, so `is_final` is exact | insertion next to the source; proptest compares `is_final` with `model/` | M2 |
| The list is consistent: `prev(next(a)) = a`, `low <= depth <= 4095`, empty slots have no links | `core/` operations; proptest checks every slot after every step, through the decoder too (`random_messages_keep_every_slot_consistent`); debug asserts | M2, M4 |
| No capability survives a completed revoke of an ancestor, whatever IPC, preemption or deletion is in progress, unless it is a partial revoke ([Slot operations](#slot-operations)) | single-step revoke with restart; a capability received by IPC is a descendant of the sender's (host test `a_received_copy_is_a_descendant_that_revoke_reaches`; `test=captransfer`, where the client's revoke of its frame takes the server's copy and its mapping), and a revoke of a badged original before `CNode_CancelBadgedSends` leaves the released senders nothing to send with (host test `revoking_first_retires_the_badge`, `test=badge`) (M6); red-team brief 2 | M2, M5, M6, M10 |
| `depth` never exceeds 4095 and never wraps, so no capability leaves its ancestors' runs | one child-insert function in `l4core::cdt` checks the limit; proptest drives a chain to 4095 by copy and delete; red-team brief 1 | M2, M10 |
| Every path that installs a derived copy reports a refused child insert, and none assumes it succeeds but where it cannot fail | `IllegalOperation` from CNode Copy and Mint and `Untyped_Retype` (M4), the TCB installs (M5; host test `installs_stop_at_the_depth_limit`) and `IRQHandler_SetNotification` (M7; `cdt::child_too_deep` before any change, host test `irq_handler_errors_in_order` with a notification capability at depth 4095); IPC transfer stops at that capability (M6; host test `a_copy_refused_at_the_depth_limit_ends_the_transfer`). Two inserts `.expect` success, and cannot be refused: IRQControl's and IOPortControl's issues (`l4core::irq`'s and `l4core::ioport`'s `insert_derived(..).expect(..)`), whose parent is boot's original at depth 0, from which nothing derives a copy (`cnode::derive` refuses both control capabilities, for Copy, Mint and IPC transfer alike), so the child is always at depth 1; tests at depth 4095 per path, for Copy, Mint and Retype through `l4core::invoke`, with the depth set directly and reached by 4,094 decoded copy-and-delete steps | M4 to M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| MDB node `prev`, `next`, `mdbRevocable`, `mdbFirstBadged` (`structures_64.bf`); children found by `isMDBParentOf`, which compares capabilities with `sameRegionAs` and badges (`src/object/cnode.c`) | `prev`, `next`, `original`, `depth`, `low`; children found structurally | Revoke and "has children" are type-agnostic and match a plain parent map in `model/`; costs 24 bits per slot and a depth limit |
| `mdbFirstBadged`, propagated on delete, separates badge groups | `low` does it for every level | One mechanism instead of a badge special case |
| A PDPT, PD or PT capability derives only while mapped (`Arch_deriveCap`, `Mode_deriveCap`) | Never derives; a PML4 always does | Back-references need one capability per paging structure ([ADR 0005](adr/0005-paging-back-references.md)) |
| On x86, Mint data narrows only an IOSpace capability, which `isCapRevocable` does not make original (`Arch_updateCapData`) | Mint narrows a Hypervisor capability, and the narrowed copy is original, as a new badge is | `vmbus` can delegate one channel and revoke it |
| `decodeCNodeInvocation` checks the message length in stages, between lookups | One length check per method, before any lookup | Simpler decode; only which error wins when several apply differs |
| No depth limit | 4095 | Field width; reachable by a task that repeatedly copies an untyped and deletes the source, but it only stops that task's own derivations |
| The master reply capability is a derivation root made by `setupReplyMaster` when a thread is first restarted (`src/object/cnode.c`, `src/kernel/thread.c`); reply capabilities are never an untyped's descendants (`cap_get_capIsPhysical` is false for them, `src/object/objecttype.c`) | Also a root, but made at TCB retype | The master exists for the TCB's whole life, so no later path has to make it ([Reply capabilities](#reply-capabilities)) |
| The manual says Mutate can also reduce rights (`cspace.tex`, "CNode Methods", "Capability Rights"); the code applies only the data word (`decodeCNodeInvocation`) | Mutate takes no rights word | As the code; only Copy and Mint reduce rights |

## Threads and TCBs

A thread is a 2 KiB TCB object (`TCB_BITS` = 11) holding its user registers,
its XSAVE area, its scheduling and IPC state, and five capability slots. The
TCB API is seL4's non-MCS API without the SMP, debug-register, virtualisation
and FPU-flag invocations.

### TCB layout

Only the size is ABI. The layout is internal, except that [Slots](#slots)
relies on the slots being at offset 0; `l4core::tcb` pins it with
compile-time asserts in every build.

| Offset | Bytes | Field | Contents |
| --- | --- | --- | --- |
| 0 | 160 | `slots[5]` | capability slots, 32 bytes each, the CNode slot format, so a Zombie treats TCB and CNode slots alike |
| 160 | 192 | `regs` | user register frame, 24 words |
| 352 | at most 256 | scalars | 21 words in `[352, 520)` (`l4core::tcb::field`): `state` with the blocking data of [Thread states used by IPC](#thread-states-used-by-ipc) in three words (the tag and the `can_grant`, `can_grant_reply` and `is_call` bits, the endpoint or notification, the badge), `priority`, `mcp`, `time_slice`, `queued`, `sched_prev`/`sched_next`, `ep_prev`/`ep_next`, `fault` (seven words: the fault type, 0 for none, and its data, a CapFault's lookup failure included), `fault_ep` (CPtr), `ipc_buffer` (user address, 0 for none), `bound_notification`; bytes 520 to 607 are spare |
| 608 | 16 | `debug_prev`, `debug_next` | debug builds only: the list of every TCB that `DebugDumpScheduler` walks (seL4 `ksDebugTCBs`, `tcbDebugAppend` at retype, `tcbDebugRemove` in `finaliseCap`); bytes 624 to 1023 are spare |
| 1024 | 1024 | `xsave` | XSAVE area, standard format, 64-byte aligned because the object is 2 KiB aligned; 576 bytes used |

The used XSAVE area, frame and slots alone take 928 bytes, so with the scalars
the TCB needs 2^11, as seL4's does on x86_64 with a 576-byte area. seL4 needs
2^12 once the area reaches AVX's 832 bytes; microL4's 1024-byte reserve
absorbs that (`seL4_TCBBits` in
`libsel4/sel4_arch_include/x86_64/sel4/sel4_arch/constants.h`).

| Slot | Holds | Written by |
| --- | --- | --- |
| 0 | CSpace root: a CNode capability, or a Zombie while a deletion of that CNode is interrupted | Configure, SetSpace |
| 1 | VSpace root: a VSpace (PML4) capability | Configure, SetSpace |
| 2 | IPC buffer frame: a non-device Frame capability that is not a SynIC page | Configure, SetIPCBuffer |
| 3, 4 | reply master and caller ([Reply capabilities](#reply-capabilities)) | retype (the master), IPC (the caller) |

Slots 0 to 2 hold copies derived from the capabilities the caller passes and
sit in the derivation list like CNode slots, so revoking the original empties
them. Every install goes through `insert_derived`, whose child insert checks the depth limit, so
a copy that would exceed `MAX_DERIVATION_DEPTH` (4095) is refused with
IllegalOperation. No CPtr can name a TCB slot.

### Thread states

| State | Runnable | Meaning |
| --- | --- | --- |
| `Inactive` | no | new, suspended, or stopped by a fault it could not deliver |
| `Running` | yes | continues at `next_ip` |
| `Restart` | yes | re-executes the instruction at `fault_ip`: an unfinished system call, or a faulting instruction after a fault reply |
| `BlockedOnSend` | no | [Thread states used by IPC](#thread-states-used-by-ipc); also a thread whose fault message waits for a receiver |
| `BlockedOnReceive`, `BlockedOnNotification` | no | [Thread states used by IPC](#thread-states-used-by-ipc) |
| `BlockedOnReply` | no | after Call, or after its fault message was received |
| `Idle` | | the idle thread only ([Idle thread](#idle-thread)) |

### Register frame and restart

`regs` (`l4core::regs::Regs`) holds the 15 general registers, in the M3 trap
frame's order so that entry copies them as a block, then `rsp`, `rflags`,
`fault_ip`, `next_ip`, `fs_base`, `gs_base`, the exception error code and
`exit`: 23 words, padded to 24. `exit` is a word, `Iret` = 0 and `Sysret` =
1, so a zeroed TCB leaves by `iretq`, and any other value reads as `Iret`.

- `fault_ip` is the instruction that entered the kernel: the `syscall`
  (`rcx` − 2) or the RIP the CPU pushed. `next_ip` is where the thread
  continues: `rcx`, or the pushed RIP.
- Activating a `Restart` thread sets `next_ip := fault_ip`. This is how a
  preempted system call ([Kernel execution model](#kernel-execution-model))
  or a resumed blocked thread re-executes.
- Suspending a `Running` thread sets `fault_ip := next_ip`, so Resume does not
  repeat a finished system call (seL4 `suspend`, `src/kernel/thread.c`).
- The user-visible `rip` is `next_ip` for a `Running` thread, else `fault_ip`;
  writing `rip` sets both.
- `exit` tells the exit path ([Exit](#exit)) whether `sysretq` may be used.
  Writing a thread's registers (WriteRegisters, CopyRegisters, a
  register-setting fault reply) forces `iretq`, because `sysretq` would
  overwrite `rcx` and `r11`. WriteRegisters forces it even when it writes no
  register, as seL4 does, and so do CopyRegisters and every fault reply,
  whatever they set. SetTLSBase does not, since `sysretq` leaves FS base
  alone, and neither do the writes of message registers, `rdi` and `rsi` by
  IPC and kernel replies, since `sysretq` changes only `rcx` and `r11`.
- `Regs::set_user` is the one writer of user-visible registers: it applies
  `sanitise`, the `rip` rule and the forced `iretq`. The message registers
  MR0 to MR3 are `r10`, `r8`, `r9` and `r15`.

### User register set and sanitising

Read/Write/CopyRegisters use seL4's 20-word order
([User register set](abi.md#user-register-set)): `rip`, `rsp`, `rflags`,
`rax` to `r15`, `fs_base`, `gs_base`. CS and SS are not in it; every
user thread runs on the user selectors. Every value the kernel installs, from
WriteRegisters, CopyRegisters, SetTLSBase or a fault reply, goes through
`l4core::regs::sanitise` (host tests at the boundaries, and proptest over
every word):

| Register | Rule | Why |
| --- | --- | --- |
| `rip`, `rsp`, `fs_base`, `gs_base` | a value ≥ `0x0000_8000_0000_0000` becomes 0 | `sysretq` to a non-canonical RIP takes #GP in ring 0 on the user stack (Intel; from memory, H9); lower-half FS and GS bases make a `swapgs` mistake harmless under SMAP |
| `rflags` | `(v & 0x0CD5) \| 0x0202` | the user sets CF, PF, AF, ZF, SF, DF, OF; bit 1 and IF forced on; TF, IOPL, NT, RF, VM, AC, VIF, VIP, ID forced off. IOPL 0 keeps port I/O behind IOPort capabilities. The same result as seL4's `sanitiseRegister` (`src/arch/x86/machine/registerset.c`) |
| the rest | unchanged | |

A thread can still set TF, DF or AC itself with `popfq`: TF single-steps only
itself into its own handler, and AC does nothing in ring 3 with CR0.AM = 0.
Every kernel entry clears DF and AC: `syscall` through IA32_FMASK, every
exception and interrupt stub with `clac` and `cld` ([Entry](#entry)).

### FS and GS base

CR4.FSGSBASE stays clear ([ADR 0015](adr/0015-fsgsbase.md)), so ring 3 cannot
run WRFSBASE or WRGSBASE. TLS uses FS base, set with TCB_SetTLSBase, which,
unlike WriteRegisters, also works on the caller (seL4 `invokeSetTLSBase`); GS
base is set with WriteRegisters word 19. Loading a segment selector can still
reset a base to 0, so on a switch away from a thread the kernel reads
IA32_FS_BASE and IA32_KERNEL_GS_BASE (the user GS base between the entry and
exit `swapgs`) into the TCB, skipping a TCB finalised in this entry, and on a
switch to a thread it writes them back. SetTLSBase on the current thread also
writes IA32_FS_BASE at once (`Threads::set_current_fs_base`). Checked in M5
on QEMU: `test=ring3` loads FS and GS with a selector in ring 3, which zeroes
IA32_FS_BASE and IA32_KERNEL_GS_BASE, and the kernel writes them back from
the thread's registers.

In code (`arch/x86_64/thread.rs`), a static names the thread whose bases are
in the MSRs. The switch in `exit_to_scheduled` saves that thread's bases
with `entry::save_user_bases` and loads the next one's with
`entry::load_user_bases`, which writes 0 for a base at or above 2^47, only
when the thread changes. TCB finalisation clears the static
(`thread::forget`), so a finalised TCB's bases are never saved, and the idle
thread, which has none, leaves it alone.

### Invocations

Labels `0x20` to `0x2D`, in seL4's order: ReadRegisters, WriteRegisters,
CopyRegisters, Configure, SetPriority, SetMCPriority, SetSchedParams,
SetIPCBuffer, SetSpace, Suspend, Resume, BindNotification and
UnbindNotification (from M6; semantics in [Binding](#binding)), SetTLSBase. The
caller may not be the target of Read/WriteRegisters nor either side of
CopyRegisters. Priority setters check an authority TCB's MCP
([Priorities and MCP](#priorities-and-mcp)).

Dropped: SetAffinity (one core); SetBreakpoint, GetBreakpoint,
UnsetBreakpoint, ConfigureSingleStepping (no hardware debug API, so DR7 keeps
its reset value `0x400`, with no breakpoint enabled); SetEPTRoot (no VT-x); SetFlags (every thread has FP state);
SetTimeoutEndpoint (MCS). Nothing is added.

`l4core::tcb::invocation` decodes a message into a `TcbInvocation` or the
first error in `docs/abi.md`'s order, changing nothing (`decode`), then
performs it (`perform`). Where the ABI leaves an order or a choice open:

- The label comes first: a label outside `0x20` to `0x2D` is
  `IllegalOperation` before any length check.
- BindNotification and UnbindNotification (M6) take no length check:
  BindNotification needs only its extra capability, and its
  `IllegalOperation` cases come in the ABI's order, seL4's
  (`decodeBindNotification`).
- Every check of Configure, SetSpace and SetIPCBuffer, the depth limit
  included, runs in `decode`, before any slot is emptied, in seL4's order:
  the buffer, the long-running delete, the CSpace root, the VSpace root.
- Only slot 0's deletion is checked for being long-running: slot 1 can hold
  only a PML4, whose deletion never is.
- ReadRegisters writes its results only for a `Call`; a `Send` leaves the
  caller's registers alone, as for any dropped reply.

Host tests check every error row in the ABI's order, and that a failed
invocation changes nothing (`core/src/tcb/tests.rs`; from M6
`bind_notification_errors_in_order`).

### Creation and configuration

Untyped_Retype zeroes the TCB, then sets `Inactive`, priority 0, MCP 0, a full
slice and `rflags = 0x202`, copies the FP template into `xsave`, puts the
thread's reply master in its `reply` slot ([Reply
capabilities](#reply-capabilities)), and in debug builds appends the TCB to
the debug list. `exit` is `Iret`, its zero value. Retype inserts the master;
the kernel's `init_object` hook does the rest (`tcb::init`, `fpu::init_area`,
[How `core/` reaches kernel memory](#how-core-reaches-kernel-memory)). The
creator calls Configure, SetSchedParams, and WriteRegisters with `rip`, `rsp`
and `resume_target`.

The IPC buffer frame (Configure, SetIPCBuffer) must be a non-device Frame that
is not one of the two SynIC pages, whose physical addresses the kernel records
at boot; those are refused with InvalidCapability, because the hypervisor
writes them and the kernel must never read one as an IPC buffer. The check
refuses a frame that contains either page anywhere, not only one whose base
is the page. The two lie in the boot region, which no untyped covers, so
only the SynIC frame capabilities and their copies can contain them. The
`Threads::synic_pages` hook gives the addresses, none before M9.

Installing a root or buffer first deletes the slot's old capability, which
may finalise its object, so afterwards the kernel re-checks that the source
and the TCB capability still exist before copying (seL4
`invokeTCB_ThreadControl`, `src/object/tcb.c`). If the delete would be
long-running (slot 0 holds the last capability to a CNode, or a Zombie left by
an interrupted deletion), Configure and SetSpace fail with IllegalOperation
(seL4 `slotCapLongRunningDelete`, which counts a CNode, a TCB or a Zombie).

A thread with an empty VSpace slot runs on the kernel's own page tables, which
have no lower-half entries after M3, and takes a VMFault at its first
fetch; with an empty CSpace slot every lookup fails. Neither is a kernel error.

### Suspend, Resume and deletion

| Target | Suspend | Resume |
| --- | --- | --- |
| current thread (the caller) | for a `Call`, the empty success reply (`rsi` = 0, `rdi` = 0) is written first (a `Send` leaves the registers alone); then `Inactive`; another thread is chosen. A later Resume continues after the `syscall` as if Suspend returned NoError | no effect |
| ready (`Running` or `Restart`) | dequeued, `Inactive` | no effect |
| blocked on send, receive or notification | removed from the queue, `Inactive` | IPC cancelled, `Restart`: it re-executes its system call, or its faulting instruction if it was sending a fault |
| `BlockedOnReply` | the server's reply capability to it is deleted ([Reply capabilities](#reply-capabilities)), `Inactive` | the same, then `Restart` |
| `Inactive` | no effect | `Restart`, made runnable |

Cancelling IPC clears a pending fault in every state, so a thread suspended
while its fault message waits never sends it later. Suspend and Resume leave
a binding alone (seL4 `suspend`, `restart`; host test
`suspend_and_resume_keep_a_binding`).

Deleting the last capability to a TCB runs `tcb::finalise`, which unbinds
its notification (`ipc::unbind_notification`) and then suspends it
(`tcb::suspend`, which also takes it out of any queue, cancels its IPC and
clears a scheduler action naming it). The kernel's hook then drops FP
ownership and FS and GS base ownership without saving (`fpu::forget`,
`thread::forget`) and removes it from the debug list (debug builds), and
`core/` deletes the five slots with the long-running delete of [Deletion and
finalisation](#deletion-and-finalisation). seL4's `finaliseCap` also
unbinds, then suspends (`src/object/objecttype.c`). Afterwards nothing in the
kernel names the TCB, except `current` until the kernel entry ends. A thread
deleting its own last TCB capability is `Inactive` at once and gets no reply;
if its slot deletion hits a preemption point, the remainder waits in the slot
until someone deletes it again, as with seL4's Zombie.

A fault handler is whichever thread receives on the fault endpoint; no TCB
names it. Deleted while waiting, it leaves the endpoint queue and faulting
threads wait for the next receiver. Deleted after receiving a fault, its caller
slot goes and the faulting thread stays `BlockedOnReply` until someone with its
TCB capability resumes it (it re-executes the faulting instruction) or
suspends it. If the fault endpoint is deleted, threads queued on it restart,
fault again, find no endpoint and become `Inactive`.

`test=fault` shows the handler's side on QEMU. The faulting thread runs above
its handler, so the handler runs only once the fault has blocked the thread,
and a `DebugDumpScheduler` before the kill shows it `BlockedOnReply`. The
handler reads the faulting
thread's registers, whose `rip` is the faulting instruction, kills it with
`TCB_Suspend`, which cancels its fault IPC and deletes the reply capability,
and then replies with label 0 through an empty caller slot, which does
nothing; the thread stays stopped.

### `core/` and `arch/`

- `l4core::regs` (M5): `Regs`; `UserReg`, the user register set in the ABI's
  order (seL4's `seL4_UserContext`); `sanitise`; `Regs::user` and `set_user`,
  the `rip` rule; `restart` and `stop_running`; the message registers; `Fault`
  with `from_exception` and its TCB record; `fault_message`, the encoder; and
  `fault_reply`, the reply decoder, which returns `FaultOutcome::Restart` or
  `Inactive`.
- `l4core::tcb` (M5, M6): the layout offsets (`field`); `ThreadState` with
  its blocking data; the handles `TcbRef`, `EpRef` and `NtfnRef`, physical
  addresses; `Tcbs`, which reads and writes a word at a multiple of 8 in
  `[160, 1024)` and builds the typed accessors on it; `Threads`, a `Kernel`
  and `Scheduling` with the hooks the kernel and IPC fill (`cancel_ipc`,
  from M6 `cancel_badged_sends`, `invoked_by_call`, `synic_pages`,
  `set_current_fs_base`, `write_buffer_word`) and, from M6, the
  notification words (`notification_word`, `set_notification_word`);
  `init`, `init_root`, `suspend`, `finalise` (M6), `restart`, `activate`,
  `buffer_word` and `set_mr`. `tcb::invocation` decodes and performs the
  invocations, which `l4core::invoke` sends to it; the M10 fuzzer targets it.
- Why those M6 members are on `Threads` and not on `IpcEnv`, which extends
  it: `l4core::invoke` and `tcb::invocation` are generic over `Threads`, so
  `CNode_CancelBadgedSends` reaches `ipc::cancel_badged_sends` through the
  hook, and `TCB_BindNotification`, which reads a notification's binding
  and queue and may deliver its word, needs the notification words there.
  The typed accessors on those words are `ipc::notification` and
  `ipc::set_notification`, and only `l4core::ipc` writes notifications.
- `arch` (M5): `arch::Objects` implements `Tcbs` over the direct map, and
  `Threads`, from M6 with the notification words read and written by value
  through raw pointers, as endpoint words are; `fpu.rs` owns XSAVE and the
  control registers, `entry.rs` the MSRs and the frame, `thread.rs` the
  switch. Host tests implement the traits over fake memory
  (`l4core::testing`).

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every register value installed for ring 3 passes `sanitise`: `rip`, `rsp`, FS and GS base below 2^47; RFLAGS with IF = 1, IOPL = 0, TF = NT = AC = 0 | `Regs::set_user`, the one writer of user-visible registers, applies `l4core::regs::sanitise`, and SetTLSBase sanitises its value; host tests `sanitise_at_the_canonical_boundaries`, `write_registers_sanitises_and_forces_iret` and `fault_reply_values_are_sanitised`, and proptest `sanitise_holds_for_any_word` | M5 |
| A user thread always runs in ring 3 on the user CS and SS; no invocation names CS or SS | register set excludes them; `exit_frame` writes the selectors as constants; `test=ring3` finds them in every frame from ring 3 | M5 |
| Returning to ring 3 never faults in ring 0 | sanitiser plus the exit path's checks; `test=ring3`'s exits by both paths, one to RIP 0; red-team scenario resuming threads with random registers | M5, M10 |
| User FS and GS bases stay below 2^47, and CR4.FSGSBASE = 0 | sanitiser, and `entry::load_user_bases` writes 0 for a base at or above 2^47; `fpu::init` clears CR4.FSGSBASE in boot step 3 and `fpu::check_control_state` reads it back; the boot summary prints CR4 | M5 |
| In a TCB that is not itself being destroyed, slot 0 holds only a CNode or a Zombie left by an interrupted deletion, slot 1 only a VSpace root, slot 2 only a non-device Frame that is not a SynIC page, or nothing; no CPtr names a TCB slot | `l4core::tcb::invocation::decode` checks; host tests `configure_errors_in_order`, `set_space_errors_in_order`, `set_ipc_buffer_errors_in_order` and `configure_refuses_a_long_running_cspace_deletion` | M5 |
| The kernel never uses a SynIC message or event page as an IPC buffer | SetIPCBuffer and Configure refuse a frame containing either page the kernel records at boot (`Threads::synic_pages`, none before M9); host tests `set_ipc_buffer_errors_in_order` and `configure_errors_in_order` | M5, M9 |
| No TCB slot install exceeds `MAX_DERIVATION_DEPTH` | the one child-insert function in `l4core::cdt`; host test `installs_stop_at_the_depth_limit`: a source at 4094 installs at 4095, one at 4095 is refused | M5 |
| At every kernel exit after a TCB is finalised, no ready or endpoint queue, reply capability, scheduler action, `current`, FP owner or debug list names it; nor, from M6, any notification queue or bound notification | the TCB `finalise` hook ([How `core/` reaches kernel memory](#how-core-reaches-kernel-memory)), from M6 through `tcb::finalise`, which unbinds before it suspends; host tests `a_thread_that_deletes_its_own_tcb_gets_no_reply` and `a_handler_that_deletes_the_faulting_thread_leaves_nothing_naming_it`, which check the scheduler's and IPC's invariants at every exit; from M6 `tcb_finalisation_unbinds_then_suspends`, `deleting_a_bound_tcb_unbinds_its_notification`, `deleting_a_waiting_tcb_takes_it_out_of_the_queue` and `a_thread_that_deletes_its_own_bound_tcb_leaves_nothing_naming_it`, which also run `ipc::check_notifications`; the notification proptest (`random_notification_operations_match_the_model`) and the IPC model's proptest (`model/tests/ipc_random.rs`), which delete TCBs whatever their state and check the invariants at every exit; red-team brief 2 | M5, M6 |
| A suspended or deleted thread has no pending fault | `ipc::cancel_ipc` clears `fault` in every state; host test `a_handler_that_suspends_the_faulting_thread_cancels_its_reply`; `test=fault` | M5 |
| A thread that suspends itself and is resumed continues after its `syscall` with a NoError reply | Suspend by `Call` writes the reply first; host tests `a_thread_that_suspends_itself_resumes_after_its_syscall_with_no_error` and `a_thread_that_suspends_itself_by_call_resumes_after_its_syscall` | M5 |
| User threads cannot set debug registers; DR7 keeps its reset value `0x400`, with no breakpoint enabled | no invocation writes them; `gdt::init` writes `0x400` in boot step 3 | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| A 16-slot CNode area at offset 0 and `tcb_t` in the upper half, found by masking (`include/object/structures.h`) | one struct: five slots at offset 0, then the frame and scalars, the XSAVE area at 1024 | plain Rust struct with asserted offsets; slots first keeps seL4's property that a Zombie walks TCB slots like CNode slots |
| TCB slot order CTable, VTable, Reply, Caller, Buffer (`tcb_cnode_index` in `structures.h`) | CSpace root, VSpace root, IPC buffer frame, reply master, caller | the three slots TCB invocations write come first, the two IPC uses after them |
| `TCB_Suspend` on the caller sets it `Restart` first (`decodeTCBInvocation`) and `suspend` keeps that restart PC, so a resumed self-suspender runs Suspend again and suspends itself again (undocumented) | the empty success reply is written first; a resumed self-suspender continues after its `syscall` | a thread can park itself and be woken by a Resume |
| Sanitiser zeroes non-canonical RIP, FS and GS base, accepts upper-half values, ignores RSP (`src/arch/x86/64/machine/registerset.c`) | `rip`, `rsp`, FS and GS base at or above 2^47 become 0 | user code never runs in the upper half; keeps `sysretq` and `swapgs` mistakes harmless |
| CR4.FSGSBASE on by default (`KernelFSGSBase` in `src/arch/x86/config.cmake`, `head.S`) | off; FS base through SetTLSBase; the kernel switches both bases | `swapgs` safety ([ADR 0015](adr/0015-fsgsbase.md)) |
| ReadRegisters reports `FaultIP` in every state (`frameRegisters`) | `rip` is `next_ip` for a `Running` thread | reports where the thread will continue |
| WriteRegisters clamps a count above 20 | RangeError | explicit errors |
| CopyRegisters accepts the caller as source or destination | IllegalOperation | same rule as Read/WriteRegisters |
| CopyRegisters resumes the destination before copying (`invokeTCB_CopyRegisters`) | copies, then resumes | the order WriteRegisters uses; the registers end the same |
| Undefined flag bits are ignored; bits 8 and up go to `Arch_decodeTransfer`, which ignores them on x86 (`src/arch/x86/object/tcb.c`) | any undefined bit returns InvalidArgument 0 | explicit errors; a flag added later cannot be silently ignored by an older kernel |
| Configure and SetSpace take `vspace_root_data`, which x86 ignores (`Arch_updateCapData`) | dropped | dead argument |
| Configure and SetIPCBuffer need a frame capability even for address 0 | not needed for address 0 | simpler calls |
| SetFlags, SetAffinity, breakpoint invocations, SetEPTRoot; VCPU objects and `seL4_VMEnter` (manual "Virtualisation") | dropped | always FP, one core, no debug API, no VT-x |
| Non-MCS `cancelIPC` clears a pending fault only for `BlockedOnReply` (`src/object/endpoint.c`) | clears it in every state, as seL4's MCS build does | a thread suspended mid-fault could otherwise send a stale fault on its next Send |

## Scheduling

The scheduler is seL4's classic one: 256 fixed priorities (255 highest), the
highest-priority runnable thread runs, round-robin within a priority with a
10 ms slice that is one tick of the 100 Hz local APIC timer, and a maximum
controlled priority (MCP) caps the priorities a thread can grant. Unlike seL4,
a woken thread that does not run at once joins the tail of its queue
([ADR 0013](adr/0013-scheduling.md)).

### Priorities and MCP

- Priority and MCP are `u8`. A new TCB has 0 and 0. The root task starts at
  255 with MCP 255 (seL4 `seL4_MaxPrio`, manual "Scheduling").
- SetPriority, SetMCPriority and SetSchedParams take an authority TCB
  capability; each new value must be at most the authority's MCP before the
  call, else RangeError with bounds 0 and that MCP (seL4 `checkPrio`).
- A TCB capability is full authority over that thread, MCP included. A thread
  can raise priorities only up to the highest MCP among TCBs it holds
  capabilities to, so the root task must not give a less trusted task its own
  TCB capability or one to a higher-MCP thread.
- Lowering an MCP leaves the priority alone (seL4 `setMCPriority`).

### Ready queues

`queues[256]` are intrusive doubly linked lists through `sched_prev` and
`sched_next`. A two-level bitmap, `l1: u64` (bits 0 to 3) over `l2: [u64; 4]`,
has bit `p` of `l2` set exactly when queue `p` is non-empty. The highest ready
priority is `64 i + 63 − lzcnt(l2[i])` with `i = 63 − lzcnt(l1)`. The running
thread is not queued (seL4 `switchToThread` dequeues it).

### Scheduler action and decision

`action` is `ResumeCurrent`, `ChooseNew` or `SwitchTo(t)`, as seL4's
`ksSchedulerAction`.

- `reschedule()` (seL4 `rescheduleRequired`): appends a pending `SwitchTo`
  target to its queue; `action` becomes `ChooseNew`.
- `make_runnable(t)` (seL4 `possibleSwitchTo`): `ResumeCurrent` becomes
  `SwitchTo(t)`; otherwise `reschedule()` runs and `t` is appended to its
  queue.
- `set_thread_state(t, s)` (seL4 `setThreadState` and `scheduleTCB`): if
  `s` is not runnable, `t` leaves its ready queue, a `SwitchTo(t)` becomes
  `ChooseNew`, and so does `ResumeCurrent` if `t` is the current thread, so
  a current thread that blocks, stops or is deleted is never resumed at the
  end of the entry. `schedule()` also treats `ResumeCurrent` with a current
  thread that is no longer runnable as `ChooseNew`.
- `schedule()`, at the end of every kernel entry, unless `ResumeCurrent`:
  1. A runnable, unqueued current thread is pushed at the head of its queue,
     so a preempted thread keeps its turn.
  2. For `SwitchTo(c)`, with `h` the highest queued priority (−1 if every
     queue is empty; the idle thread counts as not runnable): `c` runs if
     `c.priority > h`, or if `c.priority == h` and the current thread is no
     longer runnable. Otherwise `c` is appended to its queue.
  3. If nothing was picked, the head of the highest non-empty queue runs, or
     the idle thread.

Step 2's tie rule is the direct switch that runs the partner of a Call or
ReplyRecv at once when the caller blocks. Every other wake-up waits its turn.

| Event | Target | Current thread |
| --- | --- | --- |
| IPC or notification wake-up ([IPC](#ipc) calls `make_runnable`) | runs now if step 2 allows, else queue tail | continues, or queue head if preempted |
| Resume of a stopped thread | `Restart`, `make_runnable` | as above |
| Suspend | dequeued, `Inactive`; a `SwitchTo` naming it becomes `ChooseNew` | if it is the target, another thread is chosen |
| SetPriority on the current thread | new priority, `reschedule()` | head of its new queue; a higher ready thread runs |
| SetPriority on another runnable thread | dequeued, new priority, `make_runnable` | as for a wake-up |
| SetPriority on a blocked thread | priority changes; endpoint queues are FIFO ([Priorities](#priorities)) | unaffected |
| Tick ends the slice | | slice refilled, queue tail, `reschedule()` |
| Yield (system call 7) | | queue tail, `reschedule()`; slice not refilled (seL4 `handleYield`) |

### Timer tick

The local APIC timer runs at 100 Hz from M3 ([The timer](#the-timer)), and its
interrupt calls `sched::tick()` on each tick (`irq::tick`), whether it was
taken in ring 3 or in the idle loop. Unless idle, `tick` decrements the
current thread's `time_slice`; at 0 it refills it with `TIME_SLICE_TICKS` = 1
and ends the slice. Only a runnable current thread is charged: a thread that
stopped earlier in the same entry, suspending or deleting itself, must not
be queued. On QEMU `test=threads` shows the slice at work: two threads at
priority 100 each spin 40 ms between their lines with no system call, and
the test passes only if each saw the other run in between at least three
times. Slices are charged in whole ticks: a thread switched in just before
a tick loses most of its slice, and one that always blocks just before the
tick is never charged. seL4's non-MCS scheduler has the same
property at 2 ms; it is accepted here and checked by red-team brief 9
([Open questions](#open-questions)).

### Idle thread

The idle thread is a kernel context in static memory, not a TCB object: never
queued, below every priority, with no capabilities and no FP state. It runs in
ring 0 on the kernel's own page tables, which have no lower-half entries after
M3, so a VSpace deleted while the kernel idles is never live in CR3:
`thread::exit_to_scheduled` loads the kernel PML4 before it idles. It runs a
`sti; hlt` loop. An interrupt taken there discards the idle frame and runs the
normal interrupt path, after which `schedule()` picks a thread or idles again.
The entry and exit paths for this are in [Interrupts and exceptions taken in
ring 0](#interrupts-and-exceptions-taken-in-ring-0) and
[Interrupts](#interrupts).

### `core/` and `arch/`

`l4core::sched` (M5) holds `Scheduler` (the queues, bitmap, `action` and the
current thread, `None` for the idle thread), `enqueue`, `append`, `dequeue`,
`reschedule`, `make_runnable`, `set_thread_state`, `schedule`, which returns
the thread to run or `None` to idle, `tick`, `yield_now`, `set_priority`,
`check_prio`, and the checks `check` and `check_exit`, generic over
`Scheduling`, a `Tcbs` that also holds the scheduler. Proptest runs 512
random sequences of up to 200 operations against a model of 256
`VecDeque`s and checks the invariants after every step. `arch` (M5) keeps
the `Scheduler` in a static that only `arch::Objects` reaches, and does the
switch itself in `thread::exit_to_scheduled` (CR3 through `set_vm_root`
([Where the code lives](#where-the-code-lives)), FS and GS base, FP state),
the idle loop and the tick glue.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| At every kernel exit the current thread is runnable or idle, and no queued thread has a higher priority | `l4core::sched::schedule`; `sched::check_exit`, which debug kernels run at every exit; proptest against the model | M5 |
| At every kernel exit, each runnable thread but the current one is in exactly the queue of its priority, no other thread is queued, and bitmap bit `p` is set exactly when queue `p` is non-empty | `l4core::sched`; `sched::check` within `check_exit` at every exit in debug kernels; proptest | M5 |
| `SwitchTo(t)` names a runnable, unqueued thread other than the current one | `make_runnable` and `set_thread_state`; `sched::check`; proptest | M5 |
| No invocation sets a priority or MCP above the authority's MCP | `l4core::sched::check_prio`, `u8` types; host tests `check_prio_bounds_by_the_authority_mcp` and `priority_setters_errors_in_order` | M5 |
| A thread at the highest runnable priority waits at most one slice per other thread at that priority, plus one tick | tail rule and tick; host test `equal_priorities_take_turns_one_tick_each`; `test=threads` (two threads at one priority interleave under preemption) | M5 |
| A lower-priority thread never runs while a higher-priority thread is runnable | decision rule; proptest against the model; red-team brief 9 | M5, M10 |
| The idle thread is never queued, never owns FP state, holds no capabilities | not a TCB object (type): the scheduler names it as no current thread, and the exit path switches no FP state for it | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| 2 ms tick, 5-tick slice (`KernelTimerTickMS`, `KernelTimeSlice` in `config.cmake`) | 10 ms tick, 1-tick slice | PLAN.md; a fifth of the interrupts under TCG; coarser accounting |
| A woken thread that cannot run at once is prepended (`tcbSchedEnqueue` from `possibleSwitchTo`, `rescheduleRequired`, `schedule`, `restart`, and from `cancelAllIPC`, `cancelBadgedSends`, `cancelAllSignals`); `schedule` appends only one that ties with a still-runnable current thread | appended | round-robin fairness: a thread that blocks often does not jump the queue, except a Call or ReplyRecv partner through step 2. Costs wake-up latency: a driver woken by its interrupt waits behind every queued peer |
| Domain scheduler (manual "Domains") | none | one domain, seL4's default too (`KernelNumDomains` 1 in `config.cmake`) |
| MCS scheduling contexts, budgets, passive threads, donation, timeout faults (manual "MCS Scheduling" to "Scheduling algorithm") | none | PLAN.md: classic scheduler; MCS is a stretch goal |
| Idle thread is a TCB, `ksIdleThread` | a static kernel context | nothing to invoke, retype or delete |
| SMP affinity | none | one core |

## FP and SIMD

The kernel requires XSAVE, enables only x87 and SSE state (XCR0 = `0x3`, 576
bytes), and swaps it with XSAVE64 and XRSTOR64 whenever a different user thread
is about to run, with no #NM trap. The kernel never uses FP or SIMD registers.

### Control registers and XCR0 (M5)

| Bit | Value | Why |
| --- | --- | --- |
| CR0.EM, CR0.TS | 0, always | no emulation, no lazy switching, so #NM never fires |
| CR0.MP, CR0.NE | 1 | WAIT honours TS; x87 errors raise #MF, not FERR# |
| CR0.AM | 0 | #AC never fires in ring 3 and user AC is harmless |
| CR4.OSFXSR, OSXMMEXCPT, OSXSAVE | 1 | SSE on; unmasked SIMD exceptions raise #XM, not #UD; XSAVE and XSETBV usable, XCR0 readable with XGETBV |
| CR4.FSGSBASE, CR4.PKE | 0 | [FS and GS base](#fs-and-gs-base); PKRU stays disabled |
| XCR0 | `0x3` | x87 and SSE; every other component disabled |

`fpu::init` (`arch/x86_64/fpu.rs`) sets them in boot step 3, and
`fpu::check_control_state` reads CR0, CR4 and XCR0 back and panics on any
difference. On QEMU the boot summary's CR0 `0x80010033` and CR4 `0x340ee8`
show MP, NE, OSFXSR, OSXMMEXCPT and OSXSAVE set and EM, TS, AM, FSGSBASE and
PKE clear. Of the bit meanings, M5 checked on QEMU that with CR0.NE an
unmasked x87 exception raises #MF in ring 3 (`test=ring3`); that
CR4.OSXMMEXCPT makes an unmasked SIMD exception raise #XM was checked at the
M5 Hyper-V check, since QEMU's TCG raises no SIMD exception: `test=ring3`
step 9 takes #XM for a `divsd` by zero with ZM clear ([FP
exceptions](#fp-exceptions)). The rest are from memory. The M3 feature
check already requires CPUID.1:ECX.XSAVE (bit 26) ([CPU
features](#cpu-features)). M5 checks that CPUID.(EAX=0xD, ECX=0).EAX has bits
0 and 1 before XSETBV (as seL4's `Arch_initFpu` checks its feature mask),
writes XCR0, and reads CPUID.(EAX=0xD, ECX=0).EBX, the area size for the
enabled features: it panics unless that is at least 576 and at most the TCB's
1024-byte reserve (for x87 and SSE it is 576; `l4core::fpu`'s
`check_supported` and `check_size`). From M5 the boot summary also prints XCR0
and the size, for the Hyper-V check: `fpu: XCR0 0x3 of 0x21f supported, XSAVE
area 576 bytes of the TCB's 1024` on QEMU under `-cpu max,la57=off`. QEMU's
default TCG model, `qemu64`, lacks XSAVE [H1], so from M3 xtask's
`base_command()` passes `-cpu max,la57=off`, and a scenario `cpu_refuse` uses
the `qemu_args:` key to boot `-cpu qemu64` and expect the kernel's one refusal
line, which names XSAVE among the missing features. The Hyper-V VM runs with
processor compatibility mode off (`tools/hyperv/New-L4Vm.ps1`).

Only x87 and SSE, seL4's default (`XSAVE_FEATURE_SET` 3, `XSAVE_SIZE` 576 in
`src/arch/x86/config.cmake`), so QEMU TCG and every Hyper-V host behave alike
([ADR 0014](adr/0014-fp-simd.md)). AVX raises #UD; its 832-byte state
would fit the reserve later without changing `TCB_BITS`.

### Switching (M5)

`fpu_owner` names the TCB whose state is in the registers, or none. Before
returning to user thread `t` with `fpu_owner != t`, the kernel XSAVE64s the
owner's state into its `xsave` (if there is an owner), XRSTOR64s `t`'s, and
sets `fpu_owner = t`, with XCR0 as the feature mask (`fpu::switch_to`, from
`thread::exit_to_scheduled` at every exit to a thread; `fpu::forget` at TCB
finalisation; `fpu::init_area` writes the template into a new TCB). The idle
thread and the kernel never take ownership, so A, idle, A costs nothing. Every
switch between two user threads swaps the state and nothing traps: PLAN.md's
eager switching, with seL4's owner tracking (`lazyFPURestore`,
`include/machine/fpu.h`). Deleting the owner clears `fpu_owner` without
saving; the next XRSTOR64 loads every enabled component, so nothing of it
survives. Plain XSAVE64 (seL4's default too) exists wherever XSAVE does, keeps
fixed offsets, and avoids reasoning about XSAVEOPT's modified optimisation.

### Initial state

`l4core` holds a 576-byte template built from constants: FCW `0x037F`, FSW 0,
abridged FTW 0 (all empty), MXCSR `0x1F80`, registers 0, XSTATE_BV `0x3`,
XCOMP_BV and reserved header bytes 0. A new thread starts with every x87 and
SIMD exception masked, 64-bit precision, round to nearest and zeroed
registers, as in seL4 after `finit` and `MXCSR_INIT_VALUE`
(`src/arch/x86/machine/fpu.c`), but the kernel executes no x87 or SSE
instruction to make it. Host tests pin the offsets (`l4core::fpu`,
`offsets_are_the_sdm_layout`, `the_template_is_the_abi_initial_state`), and
M5 checked them on QEMU: `test=ring3`'s first thread reads FCW `0x37F` and
MXCSR `0x1F80` from the template with `fnstcw` and `stmxcsr`, and XMM0,
XMM15, ST0, ST1 and MXCSR values it sets are found at their offsets after
XSAVE64.

### FP exceptions

#MF (16, an unmasked x87 exception at the thread's next waiting x87
instruction) and #XM (19) become UserException with code 0; #UD from disabled
AVX becomes UserException 6. #NM cannot happen; if it does it is
UserException 7. XSAVE64 and XRSTOR64 do not raise a pending x87 exception,
so it travels with its thread's state. Checked in M5 on QEMU: `test=ring3`
carries a pending, unmasked x87 divide by zero (FCW `0x37b`, FSW `0xb8a4`)
across XSAVE64 and XRSTOR64 with nothing raised in ring 0, and the thread
takes #MF at its next `fwait`. QEMU's TCG raises no SIMD exception: a
`divsd` by zero with ZM clear sets ZE in MXCSR and nothing traps, so the #XM
path ran first at the M5 Hyper-V check: on Hyper-V `test=ring3` step 9 takes
#XM (vector 19) as UserException 19, and step 10 reads MXCSR `0x1d84` with ZE
set. No invocation
exposes FP state, so a handler cannot read FSW or MXCSR ([Open
questions](#open-questions)).

### The kernel never touches SSE; the user target

`x86_64-unknown-none` turns off MMX and SSE and selects soft float,
`kernel/src/main.rs` refuses to compile with `target_feature = "sse"`, and
kernel assembly uses only XSAVE64, XRSTOR64, XSETBV and XGETBV, all in
`arch/x86_64/fpu.rs`. So a user thread's state stays live across kernel
entries and is swapped only when the thread changes. User crates also build
for `x86_64-unknown-none` through M10, since no planned program needs
floating point; xtask adds `-C relocation-model=static -C code-model=small`,
as they are linked at `0x40_0000`, not in the top 2 GiB
([Root-task image and address space](#root-task-image-and-address-space)).
The kernel switches the state regardless, because isolation must not depend
on what user code executes, so a later SSE target needs no kernel change.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A thread never observes another thread's x87 or SSE state, a deleted thread's included | `fpu::switch_to` XRSTOR64s with XCR0 whenever ownership changes, at every exit to a thread; `fpu::forget` clears the owner when its TCB is finalised; `test=isolation` has the scheduler preempt and switch two threads for 160 ms, and each keeps its own XMM0 to XMM15, ST0, ST1, MXCSR and FCW (and its FS and GS bases, twelve general registers, DF and AC), as does the root task; `test=ring3` switches to another TCB's initial state and back by hand, and checks XMM0, XMM15, ST0, ST1 and MXCSR in both areas and in the thread | M5 |
| The kernel executes no FP or SIMD instruction but XSAVE64, XRSTOR64, XSETBV, XGETBV | `x86_64-unknown-none` and `compile_error!` on SSE (both in place since M0); the four live only in `arch/x86_64/fpu.rs`; review of `arch` assembly | M5 |
| XRSTOR64 in the kernel never faults | areas written only by XSAVE64 or from the template (`fpu::init_area`); no invocation exposes them; host tests `xrstor_accepts_the_template` and `the_template_is_the_abi_initial_state` | M5 |
| XCR0 is `0x3` and the enabled area fits the TCB's reserve | `fpu::init`'s check of CPUID leaf 0xD (`l4core::fpu::check_supported`, `check_size`, host test `cpuid_checks`); the `fpu:` boot summary line | M5 |
| The kernel refuses to boot on a CPU without XSAVE, with its one refusal line, rather than fault later | the M3 feature check ([Privilege levels](#privilege-levels)); QEMU scenario `cpu_refuse` (`qemu_args: -cpu qemu64`) | M3 |
| The FP owner is never a finalised TCB | the TCB `finalise` hook calls `fpu::forget` | M5 |
| CR0.TS = CR0.EM = 0, CR0.NE = 1, CR4.OSFXSR = OSXMMEXCPT = OSXSAVE = 1 from boot on | `fpu::init` in boot step 3; `fpu::check_control_state` reads them back on every boot; the boot summary prints CR0 and CR4, and scenarios match the line | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| FXSAVE or one of four XSAVE variants, chosen at build time (`KernelFPU`, `KernelXSave`) | XSAVE64 only; XSAVE required | one code path; Hyper-V and QEMU's `-cpu max,la57=off` have XSAVE |
| Feature set and area size are build options | XCR0 fixed at `0x3`, checked against CPUID at boot | same layout and behaviour on every machine |
| Per-thread `fpuDisabled` flag (`SetFlags`) | none | simplicity, at one save and restore per switch |
| Initial state captured at boot after `finit` and `ldmxcsr` | template built from constants | the kernel runs no x87 or SSE instruction |
| CR4.OSXMMEXCPT is defined but never set (`cpu_registers.h`; `Arch_initFpu` sets only OSFXSR and OSXSAVE), so an unmasked SIMD exception raises #UD, a UserException 6 | set; it raises #XM, UserException 19 | a handler can tell a SIMD exception from an invalid opcode |

## Faults

Faults follow seL4's classic model: a fault becomes a Call from the faulting
thread to the endpoint its `fault_ep` CPtr names in its own CSpace at fault
time. A reply with label 0 restarts the thread, any other label leaves it
`Inactive`, and for UnknownSyscall and UserException the reply can rewrite
registers whatever its label. If the lookup fails the thread becomes
`Inactive`.

### Fault types and sources

Labels are seL4's x86 non-MCS numbers
(`libsel4/arch_include/x86/sel4/arch/shared_types.bf`); 4 is reserved for
seL4's DebugException, and 0 and 6 up are never sent.

| Label | Fault | Raised when |
| --- | --- | --- |
| 1 | CapFault | Call or Send names a CPtr or extra capability whose lookup fails; Recv, NBRecv or a receive phase names one that fails lookup, lacks the receive right, is not an endpoint or notification, or is a notification bound to another thread. NBSend fails silently (seL4 `handleInvocation`, `handleRecv`, `src/api/syscall.c`; details in [Decoding a system call](#decoding-a-system-call)) |
| 2 | UnknownSyscall | `rdx` names no system call this kernel has ([System calls](abi.md#system-calls)): anything but 1 to 8 and, with `debug`, 16 to 18 |
| 3 | UserException | a ring-3 exception other than #PF, below |
| 5 | VMFault | a ring-3 #PF |

| Vector from ring 3 | Result |
| --- | --- |
| 0 #DE, 6 #UD, 16 #MF, 19 #XM | UserException, code 0 |
| 1 #DB | UserException, code 0: TF single-step or `int1`. #DB runs on IST4; a ring-0 #DB returns only when its saved RIP is exactly `syscall_entry` (a `syscall` executed with TF set) or the #BP stub's first instruction (`mov ss` with TF set, then `int3`, which then gives UserException 3), and panics otherwise |
| 3 #BP | UserException, code 0, `rip` past the `int3`: vector 3 is the only DPL-3 gate |
| 10 #TS, 11 #NP, 12 #SS, 13 #GP | UserException with the error code; `int n` for any `n` but 3 hits a DPL-0 gate and arrives as #GP with code `8n + 2` (on QEMU `int 0x80` gives `0x402`, `test=ring3`) |
| 14 #PF | VMFault: CR2, the error code, its bit 4 as the instruction-fetch flag |
| 4 #OF, 5 #BR, 7 #NM | cannot occur (no compatibility-mode code segment, CR0.TS = 0); UserException with code 0 if they do |
| 17 #AC, 20 #VE, 21 #CP, 29, 30, and the reserved vectors 9, 15, 22 to 28, 31 | cannot occur (CR0.AM = 0, no #VE enabled, CET off, no SEV); the kernel panics if one does, from either ring |
| 2 NMI, 8 #DF, 18 #MC | never a user fault; the kernel panics ([NMI, double fault, machine check and debug](#nmi-double-fault-machine-check-and-debug), [Vector map](#vector-map)) |

### Delivery

1. The kernel resolves `fault_ep` in the thread's CSpace by an ordinary
   lookup. The result must be an endpoint capability with Write plus Grant or
   GrantReply, checked now, at fault time (seL4 `sendFaultIPC`).
2. Only then does it store `fault`, and for a CapFault the lookup failure, in
   the TCB (seL4 `sendFaultIPC`, `src/kernel/faulthandler.c`), so a thread
   left `Inactive` by a missing handler holds no fault.
3. It sends the fault as a Call: label = fault type, badge = that capability's
   badge, words per [Fault messages](abi.md#fault-messages). The thread is
   `BlockedOnSend` until a handler receives, then `BlockedOnReply`; the
   handler gets a reply capability
   ([Reply capabilities](#reply-capabilities)). Words past MR3 go to the
   handler's IPC buffer if it is writable; otherwise it gets MR0 to MR3 and
   length 4 (seL4 `setMR`, `lookupIPCBuffer`).

Delivery touches only kernel memory (the faulting TCB, the endpoint, the
handler's registers and IPC buffer frame through the direct map), so it cannot
fault and never blocks the kernel. In code: `l4core::entry::classify` makes
a ring-3 exception an `Exception { vector, error, cr2 }`,
`l4core::syscall::handle_exception` turns it into a `Fault`
(`Fault::from_exception`), and `l4core::ipc::deliver_fault` runs the three
steps; an unknown system call and a failed lookup reach `deliver_fault` from
`handle_syscall`. On QEMU `test=fault` shows a VMFault delivered to a
handler thread through a fault endpoint with only Write and GrantReply, with
the words [Fault messages](abi.md#fault-messages) gives: label 5, length 4,
badge 0, the faulting instruction, the address, prefetch 0 and an error code
of `0x4`, a user-mode read of a page not present.

### Reply

| Fault | Label 0 | Other label | Registers the reply sets |
| --- | --- | --- | --- |
| CapFault, VMFault | `Restart` | `Inactive` | none |
| UnknownSyscall | `Restart` | `Inactive` | the first `min(length, 18)` of MR0 to MR17, in message order |
| UserException | `Restart` | `Inactive` | the first `min(length, 3)`: `rip`, `rsp`, `rflags` |

Registers are set whatever the label, as in seL4, where `copyMRsFaultReply`
runs before the label test (`handleFaultReply`, `src/api/faults.c`). Words
past MR3 are read from the handler's IPC buffer only if it is readable;
otherwise only the first four are set.

`Restart` resumes at `rip`: a faulting instruction or the `syscall` runs
again, while after a trap (#BP, #DB) `rip` is already past it. To emulate a
system call a handler adds 2 to MR15. Registers set by a reply go through
`sanitise`, and the thread then exits through `iretq`.

### Missing handlers and double faults

- If the lookup fails or finds anything but a suitable endpoint, the thread
  becomes `Inactive`; there is no second-level handler. Debug builds print both
  faults and `rip` (seL4 `handleDoubleFault`, `src/kernel/faulthandler.c`):
  `deliver_fault` returns a `DoubleFault`, and `kernel/src/dispatch.rs` prints
  `thread <TCB> stopped at <fault_ip>: <fault>; its fault endpoint: <lookup
  failure>`. The root task's `fault_ep` is 0, so a fault stops it.
- The fault endpoint's failure is a send-phase CapFault on `fault_ep`: the
  lookup's own failure if the `CPtr` does not resolve, and
  `MissingCapability` with 0 bits left if it resolves to anything but an
  endpoint capability with Write and Grant or GrantReply, as seL4's
  `sendFaultIPC` reports it (host test
  `a_fault_without_a_suitable_handler_stops_the_thread`).
- A handler that faults sends to its own fault endpoint. A thread that handles
  its own faults deadlocks with itself, a user error the kernel ignores.
- A ring-0 exception is a kernel bug and panics.

### `core/` and `arch/`

`arch` hands a ring-3 vector, error code and CR2 to `l4core::entry::classify`
(M3 decodes, M5 classifies). `l4core::regs` holds `Fault`, the encoder
(`fault_message`) and the reply decoder (`fault_reply`) (M5). Delivery
(`ipc::deliver_fault`), reply capabilities and fault replies are built in M5
with the endpoint path they need, in `l4core::ipc`, under host tests. From
M6 the IPC model's proptest covers them too: it raises faults of every type,
with and without a handler, and replies to them
([Where the code lives](#where-the-code-lives-1)); M6's host tests add that
a fault message and a fault reply move no capability
(`fault_messages_and_fault_replies_move_no_capability`) and that
`CNode_CancelBadgedSends` restarts a queued fault
(`callers_already_received_keep_waiting_and_a_queued_fault_restarts`).

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every ring-3 exception the configuration allows, and every failed lookup, ends with a fault message on an endpoint the thread could Call, or with the thread `Inactive`; never with a kernel panic | `l4core::entry::classify`, `l4core::syscall` and `ipc::deliver_fault`; host tests `exceptions_classify_as_docs_abi_says`, the fault tests in `core/src/ipc/tests.rs` and `a_pointer_that_does_not_resolve_faults_except_for_nbsend`; `test=fault` (a VMFault reaches its handler); `test=ring3` raises #BP, #MF, #DB, #PF, #UD and #GP from ring 3 into its own hook; from M6 the receive-phase fault on a notification bound to another thread (host test `a_bound_thread_may_wait_on_its_notification_and_no_other_thread_may`) and the IPC model's proptest (`random_ipc_sequences_match_the_model`), whose random system calls, exceptions and failed lookups each end in a fault message to a handler or a stopped thread, as in the model | M5, M6 |
| A fault is sent only to an endpoint capability with Write plus Grant or GrantReply, checked at fault time | delivery step 1 (`deliver_fault`); host test `a_fault_without_a_suitable_handler_stops_the_thread`; `test=fault`'s fault endpoint has Write and GrantReply only | M5 |
| A fault message carries only the faulting thread's own registers and fault data | `l4core::regs::fault_message` reads only the fault and the faulting thread's registers; host test `fault_messages_carry_the_abi_words` | M5 |
| A fault reply changes only the registers its fault type names, through `sanitise`, and only label 0 restarts | `l4core::regs::fault_reply`; host tests `a_fault_reply_sets_only_the_registers_its_type_names`, `fault_reply_values_are_sanitised` and `a_fault_reply_with_another_label_stops_the_thread` | M5 |
| Fault delivery never blocks or faults the kernel and allocates nothing | delivery is a Call that blocks the faulting thread and touches kernel memory only; `deliver_fault` has no preemption point, and its time is bounded by the lookup and the message | M5 |
| A ring-0 #DB returns only to `syscall_entry` or to the #BP stub's first instruction, never to the #DB stub's; every other ring-0 #DB, and any of vectors 9, 15, 17 or 20 to 31, panics | IDT handlers (M3); `l4core::entry::single_step_into_syscall_entry` and `single_step_into_breakpoint_stub` in `trap_from_kernel`, host tests `single_step_into_syscall_entry_needs_db_ring_0_and_that_rip` and `single_step_into_breakpoint_stub_needs_db_ring_0_and_vector_3s_stub`; `test=ring3` runs `syscall` with TF set and takes the single step in ring 3 (QEMU raises no ring-0 #DB there); `test=redteam-movss` runs `mov ss` with TF set before `syscall`, `int3`, `int 0x80`, `int1` and `ud2` (QEMU raises the #DB in ring 3; the Hyper-V check runs it on a real CPU) | M3, M5 |
| No user action makes the kernel take an exception in ring 0 | the kernel never dereferences user addresses; syscall fuzzer; red-team briefs 5 and 6 | M10 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| A CapFault or VMFault reply always restarts; UnknownSyscall and UserException restart only on label 0 (`handleFaultReply` in `src/api/faults.c`, `Arch_handleFaultReply` in `src/arch/x86/api/faults.c`) | label 0 restarts, any other leaves the thread `Inactive` | one rule for every fault; a handler can stop a faulting thread without its TCB capability, where seL4's can only withhold the reply and leave it `BlockedOnReply`. Costs compatibility with seL4 pagers that reply with a non-zero label |
| `int n` on a user trap gate becomes an UnknownSyscall (`src/arch/x86/c_traps.c`) | `int n` raises #GP, a UserException | `syscall` is the only system call entry |
| Every vector below 32 from user mode, NMI and #MC included, becomes a UserException (`c_handle_interrupt`, `handleUserLevelFault`) | NMI, #DF and #MC are never user faults; vectors 9, 15, 17 and 20 to 31 panic from either ring | the thread did not cause the first three; the others cannot occur in this configuration, so one arriving means the kernel's assumptions are wrong |
| The manual ("Exceptions") says the handler capability is installed in the TCB and validated, not looked up, at fault time; that is the MCS build (`handleFault` under `CONFIG_KERNEL_MCS`); non-MCS looks up the CPtr when the fault happens (`sendFaultIPC`, `src/kernel/faulthandler.c`) | the CPtr is looked up when the fault happens | microL4 follows classic, non-MCS seL4 |
| DebugException (label 4), Timeout (MCS) | none; label 4 reserved | no debug API, no MCS |

## IPC

Endpoints follow classic, non-MCS seL4: a thread sends or receives through an
endpoint capability, waits in a FIFO queue until a partner arrives, and one
kernel entry then moves the whole message: up to 120 words, the sender's
badge, and at most one copied capability. `Call` leaves a one-shot reply
capability in the receiver's TCB. The state machine is safe Rust in
`l4core::ipc`, generic over a trait the kernel implements in
`kernel/src/arch/`. M5 built the endpoint calls that fault delivery needs
([ADR 0023](adr/0023-fault-ipc-in-m5.md)); M6 added capability transfer,
`CNode_SaveCaller`, `CNode_CancelBadgedSends` and notifications, and a
reference model that proptest runs the whole machine against on the host.

### Endpoint states and queues

An endpoint has a state and one queue of TCBs, oldest first. It is four
words (`l4core::ipc::ep_field`): the queue's head and tail, the state and a
reserved word. Zeroed memory is an `Idle`, empty endpoint, so retype needs no
initialisation, and a state word no writer stores reads as `Idle`.

| State | Queue | Every queued thread is |
| --- | --- | --- |
| `Idle` | empty | (none) |
| `Send` | non-empty | `BlockedOnSend` on this endpoint |
| `Recv` | non-empty | `BlockedOnReceive` on this endpoint |

The queue is a doubly linked list through two TCB fields, `ep_next` and
`ep_prev`; the endpoint holds the head and the tail. Append, take-head and
remove-anywhere are O(1). Notification queues use the same two fields, since
a thread waits on at most one object. Queues are strictly FIFO; priority plays
no part (see [Priorities](#priorities)).

### Thread states used by IPC

[Thread states](#thread-states) lists the full set (`Inactive`, `Running`,
`Restart`, idle). IPC adds four blocked states. Each payload records what the
kernel needs from the invoked capability, so changing or deleting that
capability after the thread blocks does not change the badge or rights the
message carries. The message itself (`MessageInfo`, message registers, extra
capability pointers) is read only at transfer, from the sender's registers
and its IPC buffer as they are then, as in seL4 (`src/kernel/thread.c`,
`doNormalTransfer`).

| State | Payload | Queued on |
| --- | --- | --- |
| `BlockedOnSend` | endpoint, badge, `can_grant`, `can_grant_reply`, `is_call` | the endpoint |
| `BlockedOnReceive` | endpoint, `can_grant` of the capability received on | the endpoint |
| `BlockedOnReply` | none | nothing |
| `BlockedOnNotification` | notification | the notification |

Each TCB also holds the fields below for IPC; [TCB layout](#tcb-layout)
places them.

| Field | Meaning |
| --- | --- |
| `ep_next`, `ep_prev` | queue links, null when not queued |
| `bound_notification` | the bound notification, or null |
| `fault` | the fault being delivered or awaiting its reply, or none; [Faults](#faults) fixes its contents |
| IPC buffer slot (slot 2, offset 64) | a derived copy of the buffer's frame capability ([Creation and configuration](#creation-and-configuration), `TCB_SetIPCBuffer`) |
| `reply` slot (slot 3, offset 96) | the thread's master reply capability, made when the TCB is retyped, or by boot for the root task |
| `caller` slot (slot 4, offset 128) | the reply capability this thread answers with `Reply` |

No TCB slot is reachable through a `CPtr`. `Restart` means the thread
re-executes its `syscall` instruction, or its faulting instruction, when it
next runs. IPC writes a thread's registers only when it completes that
thread's operation, so a restarted system call still has its own arguments.

### Decoding a system call

Before a send or receive phase runs, the kernel's dispatcher looks up `rdi`
in the caller's CSpace (all 64 bits); for `Send`, `NBSend` and `Call`, if the
caller has a readable IPC buffer, it also looks up the `extra_caps` pointers
in `caps_or_badges`, whatever the target. A failed send-time lookup is a
capability fault for `Send` and `Call` and silent for `NBSend`, as in seL4's
`handleInvocation` (`src/api/syscall.c`; `ipc.tex`, "Errors", says an error
is returned, but the code faults). `ReplyRecv` runs its reply phase first and
looks up `rdi` only afterwards, as seL4's `handleReply` then `handleRecv`, so
a receive-phase fault never holds back the reply. The dispatcher then
dispatches on the capability type and checks rights:

| Capability | `Send`, `NBSend` | `Call` | `Recv`, `NBRecv`, receive phase of `ReplyRecv` |
| --- | --- | --- | --- |
| Endpoint | send; needs Write | send and wait for the reply; needs Write, and Grant or GrantReply | receive; needs Read |
| Notification | signal; needs Write | signal, then an empty kernel reply; needs Write | wait; needs Read and no binding to another thread |
| Reply | reply | reply, then an empty kernel reply | not allowed |
| Other kernel object | invocation, reply dropped (each object's section) | invocation (each object's section) | not allowed |

What each failure produces (a capability fault, an error reply, or nothing) is
listed in [Errors, faults and silent
drops](abi.md#errors-faults-and-silent-drops). `Reply` and the reply phase of
`ReplyRecv` take no capability: they use the caller slot.

A signal ignores its message registers; its `extra_caps` pointers are
looked up at send time, so a failed lookup faults as for an endpoint, but
nothing is transferred. A notification capability without Write gets
`InvalidCapability` for `Call` and nothing for `Send` and `NBSend`, as an
endpoint capability without Write does. `l4core::syscall` does this
decoding ([System-call dispatch](#system-call-dispatch)): its `invocation`
signals before it tries a reply capability or a kernel object, and its
`receive` waits on a notification only with Read and `ipc::may_wait`; any
other receive falls through to the endpoint case, whose capability fault is
`MissingCapability` with 0 bits left
([ADR 0026](adr/0026-receive-phase-cap-faults.md)).

### Send phase

`send(T, E, badge, g, gr, call, blocking)` runs for `Send`, `NBSend` and
`Call` on an endpoint, and for fault delivery. `badge`, `g` (Grant) and `gr`
(GrantReply) come from the invoked capability.

| Endpoint | `blocking` | Effect |
| --- | --- | --- |
| `Idle` or `Send` | true | `T` becomes `BlockedOnSend(E, badge, g, gr, call)` at the tail; `E` becomes `Send` |
| `Idle` or `Send` | false | the message is dropped; `T` continues |
| `Recv` | either | take the head `R` (`E` becomes `Idle` if the queue empties); `transfer(T, R, badge, g, E)`; `R` becomes `Running`. If `call`, `T` becomes `BlockedOnReply` and a reply capability to `T`, with Grant equal to `R`'s stored `can_grant`, goes into `R`'s caller slot. Otherwise `T` continues |

### Receive phase

`receive(R, E, g, blocking)` runs for `Recv` and `NBRecv` on an endpoint, and
for the receive phase of `ReplyRecv`. `g` is the Grant right of the invoked
capability.

1. Delete whatever is in `R`'s caller slot: a server that receives on an
   endpoint again before replying gives up that reply.
2. If `R` has a bound notification in state `Active`, deliver its signal (see
   [Notifications](#notifications)) and stop.
3. Otherwise:

| Endpoint | `blocking` | Effect |
| --- | --- | --- |
| `Idle` or `Recv` | true | `R` becomes `BlockedOnReceive(E, g)` at the tail; `E` becomes `Recv` |
| `Idle` or `Recv` | false | `R` gets badge 0 and `MessageInfo` 0 |
| `Send` | either | take the head `S`; `transfer(S, R, S.badge, S.can_grant, E)`. If `S.is_call`, `S` becomes `BlockedOnReply` and a reply capability to `S`, with Grant equal to `g`, goes into `R`'s caller slot. Otherwise `S` becomes `Running` |

A queued `is_call` sender always gets a reply capability: `Call` and fault
delivery both require Grant or GrantReply before the thread can queue.

### Reply phase

`reply(R, slot)` runs for `Reply` and the reply phase of `ReplyRecv`, where
`slot` is `R`'s caller slot, and for `Send`, `NBSend` or `Call` on a reply
capability saved in a CSpace slot.

- If `slot` is empty, nothing happens. This also keeps a restarted
  `ReplyRecv` harmless.
- If it holds a reply capability to `C` with Grant `g`, delete it, then:
  - if `C` has no fault, `transfer(R, C, 0, g, none)` and `C` becomes
    `Running`;
  - if `C` has a fault, the fault-reply rule ([Reply](#reply)) reads `R`'s
    message, `C` becomes `Restart` or `Inactive`, and the fault is cleared.
    No capability moves, whatever `g` and `R`'s `extra_caps` (seL4
    `doReplyTransfer` calls `handleFaultReply`, not `doIPCTransfer`).

A reply never blocks: a reply capability exists only while its target is
`BlockedOnReply`.

### Message transfer

`transfer(S, R, badge, g, E)` copies one message from `S` to `R`:

1. If `S` has a fault, the fault encoder ([Faults](#faults)) produces the
   message:
   `label` is the fault type and no capabilities move. Step 5 applies. The
   kernel supplies the words, so words 4 and up need only `R`'s writable
   buffer, not `S`'s (seL4's `doFaultTransfer` and `setMR`,
   `src/kernel/thread.c`, `include/object/tcb.h`).
2. Otherwise `S`'s `MessageInfo` comes from its `rsi`; a `length` above 120
   counts as 120.
3. The first `min(length, 4)` message registers (`r10`, `r8`, `r9`, `r15`)
   are copied. `msg[4..length]` is copied only if `S` has a readable IPC
   buffer and `R` a writable one; otherwise the delivered length is
   `min(length, 4)`. A receiver declares no maximum: with a buffer it accepts
   120 words.
4. Capabilities move as in [Capability transfer](#capability-transfer).
5. `R`'s `rdi` gets `badge` and its `rsi` gets the sender's `label` with the
   delivered `length`, `extra_caps` and `caps_unwrapped`. Message registers
   beyond the delivered length keep `R`'s own values.

The kernel reaches an IPC buffer only through the frame capability in the
TCB's IPC buffer slot, through the direct map. That capability sits in the
derivation list, so revoking the frame empties the slot before the frame can
be retyped. The buffer is readable if the capability is a non-device frame
with Read, and writable if it also has Write.

### Capability transfer

A message names up to three capabilities and copies at most one
([ADR 0017](adr/0017-capability-transfer.md)). Capabilities move only if the
sender's capability has Grant (for a reply, the reply capability's Grant), the
sender has a readable IPC buffer and sets `extra_caps`, and the receiver has a
writable IPC buffer. Unwrapping needs the same: if any condition fails,
nothing is copied or unwrapped and `R` receives `extra_caps` and
`caps_unwrapped` 0 (seL4 `doNormalTransfer`, `transferCaps`). Then:

1. The `extra_caps` pointers are looked up again in `S`'s CSpace, because
   `S` may have blocked since the send-time lookup. `Reply` and the reply
   phase of `ReplyRecv` have no send-time lookup, so this is their only one
   and its failure is no fault (seL4 `handleReply`). A pointer that reaches
   an empty slot has not failed; step 3 stops at it. If any lookup fails, no
   capability moves, not even those named before it: seL4's
   `doNormalTransfer` looks them all up before `transferCaps` moves any
   (`ipc.tex`, "Errors", says the earlier ones still move).
2. The receive slot is found once: `receive_cnode`, resolved with all 64 bits
   in `R`'s CSpace, must be a CNode capability; `receive_index`, resolved
   from it with `receive_depth` bits, must reach a slot, and a
   `receive_depth` of 0 or above 64 reaches none (seL4 `getReceiveSlots`,
   `lookupTargetSlot`); the slot must be empty. Otherwise there is no
   slot.
3. For each capability `i` in order: if it is an endpoint capability to `E`,
   whatever its rights, its badge goes into `R`'s `caps_or_badges[i]`, bit
   `i` of `caps_unwrapped` is set, and the capability itself is not copied
   (this never happens for replies, which have no `E`). Otherwise, if the
   slot is still free, the capability passes the capability core's `derive`
   (reply capabilities never do), and `insert_derived` accepts the copy
   below `MAX_DERIVATION_DEPTH`, the copy goes into the slot with the same
   rights and badge, derived from `S`'s capability exactly as `CNode_Copy`
   would place it, and the slot is used. Otherwise the loop stops; a copy
   refused at the depth limit is simply not transferred, like any capability
   that cannot be derived.
4. The delivered `extra_caps` is the number of capabilities processed before
   the loop stopped.

Neither side is told about a failure; the receiver compares `extra_caps`
with what its protocol expects. Because the copy sits in the derivation list
like any copy, revoking a capability it derives from also removes it. As in
seL4, `insert_derived` makes a copy of an original (unbadged, or the first
badged copy) its child and a copy of a copy its sibling
(`src/object/cnode.c`, `cteInsert`, `isMDBParentOf`;
`src/object/objecttype.c`, `isCapRevocable`; `cspace.tex`, "Capability
Derivation Tree").

### Reply capabilities

The reply capability is classic seL4's
([ADR 0016](adr/0016-reply-capability.md)):

- **Where.** The one-shot reply capability lives in the receiver's `caller`
  slot. It names the caller's TCB and is derived from the caller's master
  reply capability, in the caller's `reply` slot. The master is a
  derivation root at depth 0, as seL4's `setupReplyMaster` inserts it
  (`src/object/cnode.c`), so no revoke reaches it and the reply capability,
  at depth 1, never meets the depth limit. The master dies only when its TCB
  is finalised, after `cancel_ipc`. It is the one stated exception to the
  rule ([Kernel objects](#kernel-objects)) that every capability to an
  object in an untyped's region descends from that untyped.
- **Created** when a `Call` or a fault meets a receiver. Its Grant is the
  Grant of the capability the receiver received on; it has no other rights.
- **Destroyed** when used; while it is in the holder's `caller` slot, when
  its holder receives on an endpoint again or the holder's TCB is deleted (a
  saved one survives both);
  when it is deleted from a CSpace slot, directly or with the CNode that
  holds it (it has no children, so revoking it does nothing); when the
  caller leaves `BlockedOnReply` any other way (`cancel_ipc` deletes the one
  capability derived from the caller's master).
- **Saving.** It cannot be copied, minted or sent by IPC, but can be moved.
  `CNode_SaveCaller` (label `0x18`) moves it from the caller slot into an
  empty CSpace slot, so a server can keep a client waiting while it serves
  others; the saved capability is used with `Send`, `NBSend` or `Call`. A
  full destination is `DeleteFirst` and is checked first; an empty caller
  slot is then `IllegalOperation`, where seL4 succeeds (see Compared with
  seL4 below), and so is an invocation no thread made, which only a
  self-test can make. The move keeps the capability's place below the
  caller's master, so `cancel_ipc` still finds it.
- **Lost reply.** If it is destroyed without a reply, the caller stays
  `BlockedOnReply` until it is suspended, restarted or deleted. The kernel
  never invents a reply: `Call` trusts the server for liveness, as in seL4.
- **Rights for `Call`.** Write and Grant or GrantReply on the endpoint
  capability; without Grant or GrantReply, `Call` returns
  `InvalidCapability` and sends nothing.
- **Nesting.** `Call` leaves the caller's own caller slot alone, so a server
  can `Call` another server while it holds a reply.

### Badges

A badge is a 64-bit word on an endpoint or notification capability; 0 means
unbadged. `CNode_Mint` sets it once on an unbadged capability
([Slot operations](#slot-operations)). An endpoint message carries the badge
of the capability the sender invoked, recorded when the send started, in the
receiver's `rdi`. Replies and kernel replies carry 0. A sender cannot choose
or change the badge it sends. The badge of the capability a thread receives
or waits on plays no part (seL4 `receiveIPC`, `receiveSignal`).

### Deletion and cancellation

| Event | Queue side | The removed thread becomes |
| --- | --- | --- |
| The final capability to endpoint `E` is deleted | `cancel_all_ipc(E)`: every queued thread leaves, and is made runnable, in queue order; `E` becomes `Idle` | `Restart` |
| `CNode_CancelBadgedSends` on a capability to `E` with badge `b` and all four rights, Read, Write, Grant and GrantReply ([Badges, revoke and `CNode_CancelBadgedSends`](#badges-revoke-and-cnode_cancelbadgedsends)) | `cancel_badged_sends(E, b)`: every `BlockedOnSend` thread whose stored badge is `b` leaves, and is made runnable, in queue order, as for `cancel_all_ipc`; the rest keep their order, and `E` becomes `Idle` if none is left; nothing for `b` = 0 or a `Recv` queue | `Restart` |
| Thread `T` is suspended, restarted or deleted ([Suspend, Resume and deletion](#suspend-resume-and-deletion)) | `cancel_ipc(T)`: `T` leaves its queue; if `BlockedOnReply`, the reply capability to `T` is deleted wherever it is | what [Suspend, Resume and deletion](#suspend-resume-and-deletion) sets |

Each also clears the thread's fault record. A restarted thread re-executes
its system call and resolves its `CPtr` afresh. After a final deletion no
capability to `E` is left, so the pointer reaches an empty slot (`Call` gets
`InvalidCapability`, `Send` and `NBSend` do nothing, `Recv` takes a
capability fault), fails to resolve (a capability fault, except for
`NBSend`, which does nothing), or reaches whatever the slot holds now. A
thread that was delivering a fault re-raises it and looks up its handler
again. After `cancel_all_ipc` nothing refers to the endpoint, so its memory
may be reused once its finalisation
([Deletion and finalisation](#deletion-and-finalisation)) completes.

To reuse a badge, a server follows [Badges, revoke and
`CNode_CancelBadgedSends`](#badges-revoke-and-cnode_cancelbadgedsends);
messages already delivered are not affected. `cancel_badged_sends` touches
only the endpoint's queue, as seL4's does: a queued `Call` with badge `b`
restarts whole, and so sends again only if its capability survived; a
caller whose message was already received is `BlockedOnReply`, keeps its
reply capability, which names its TCB and not the badge, and waits for that
reply as before.

`cancel_all_ipc`, `cancel_badged_sends` and `cancel_all_signals` are not
preemptible in v0, as in seL4 (`cancelAllIPC`, `cancelBadgedSends`,
`cancelAllSignals`): each loops over its queue with interrupts off, one O(1)
step per thread. The queue holds at most the TCBs that exist, which untyped
memory bounds: 2^29 / 2^11 = 2^18 on the 512 MiB Hyper-V VM. A task alone
can queue only the TCBs its own untyped buys. M10 brief 9 measures the
worst case and adds a dying-marker loop, as seL4's Zombie does for CNodes,
only if it matters; a plain restartable loop would livelock, because
restarted threads re-resolve the still-present final capability and queue
again.

### Fault delivery

Fault delivery is a `Call` the kernel makes on the faulting thread's behalf.
[Delivery](#delivery) gives the lookup of the fault endpoint at fault time,
the rights it needs, and what happens without one. Once it has a suitable
capability, the kernel stores the fault in the TCB and runs
`send(T, E, badge, g, gr, call = true, blocking = true)` with that
capability's badge and rights. The handler receives the fault message
([Fault messages](abi.md#fault-messages)), the capability's badge in `rdi`,
and a reply capability to `T`. Its reply runs the reply phase, where
[Reply](#reply) decides whether `T` restarts and which registers the reply
sets. Fault messages carry no capabilities and follow the same truncation
rule.

### Priorities

IPC does no priority inheritance or donation ([ADR
0018](adr/0018-ipc-priorities.md)). A woken thread is passed to the
scheduler's `make_runnable`. IPC never switches threads itself; the
scheduler's tie rule ([Scheduler action and
decision](#scheduler-action-and-decision)) runs a `Call` or `ReplyRecv`
partner at once. IPC never reads or changes a priority or timeslice. `IpcEnv`
extends `Threads`, which can set priorities, so the type does not show this;
the host tests check after every step that no priority changed ([Where the
code lives](#where-the-code-lives-1)). Inversion is avoided by configuration:
`root` gives each server a priority at least that of every client, an
immediate priority ceiling, and the maximum controlled priority ([Priorities
and MCP](#priorities-and-mcp)) stops a client raising itself past it.

### Where the code lives

| Part | Where | Milestone |
| --- | --- | --- |
| `MessageInfo` packing, IPC buffer word indices (`word::*`, pinned by offset asserts), message-register mapping (`mr_location`, `delivered_length`) | `l4core::ipc::message`, shared with `libsys` | M5 |
| Endpoint and thread-state types; `Send`, `NBSend`, `Call`, `Recv`, `NBRecv`, `Reply`, `ReplyRecv` on endpoints; reply capabilities; fault delivery; `cancel_ipc`, `cancel_all_ipc`; `check`, the invariants below as a function | `l4core::ipc` (`endpoint.rs`: the endpoint, its queue, `IpcEnv`, `EndpointCap`; `machine.rs`: `send`, `receive`, `reply`, `transfer`, `cancel_ipc`, `cancel_all_ipc`, `finalise`, `deliver_fault`, `check`), generic over `IpcEnv` | M5 |
| Capability transfer and unwrapping | `l4core::ipc::transfer` (`transfer_caps`, which `transfer` calls for a message that is not a fault; the re-lookup `lookup_extra_caps`; `receive_slot`), copying through `l4core::cnode::copy` with every right | M6 |
| `CNode_SaveCaller` | `ipc::save_caller` in `machine.rs`, over `Kernel`: one `cdt::move_slot` from the caller slot; decoded in `l4core::invoke` | M6 |
| `CNode_CancelBadgedSends` | `ipc::cancel_badged_sends` (`badge.rs`), over `IpcEnv`; decoded in `l4core::invoke`, which reaches it through the `Threads::cancel_badged_sends` hook | M6 |
| Notifications, binding and `cancel_all_signals` | `l4core::ipc::notification` ([Notifications](#where-the-code-lives-2)) | M6 |
| Reference model and the IPC state-machine proptest | `model/src/ipc.rs` (the model), `model/src/ipc_harness.rs` (the two run side by side), `model/tests/ipc_random.rs` and `model/tests/ipc_scenarios.rs` | M6 |
| `IpcEnv` and `Threads` for the kernel: endpoint and notification words, IPC buffer words, saved register frames, the scheduler, the `cancel_ipc` and `cancel_badged_sends` hooks | `arch::Objects` (`kernel/src/arch/x86_64/objects.rs`) | M5, M6 |
| System-call dispatch, capability lookup, rights checks | `l4core::syscall`, host-tested; the kernel's `dispatch.rs` acts on its `Outcome` | M5, M6 |
| Messages with words past MR3 and extra capabilities, and what a receive says about the capabilities it got | `libsys::transfer` (`compose`, `ReceivedCaps`; `Ipc::set_receive_slot` names the receive slot) | M6 |

M5 built what its done-when test needs: a page fault reaches a handler
thread through an endpoint, which needs fault delivery and reply
capabilities, and the handler kills the faulting thread, which is
`BlockedOnReply` and so needs `cancel_ipc` (`test=fault`). Once user code can
delete an endpoint, its finalisation needs `cancel_all_ipc`. M5's host tests
cover these functions. M6 added capability transfer, the two CNode methods
that act on IPC state, notifications, and the reference model.

`core/` names objects by physical-address handles (`TcbRef`, `EpRef`,
`NtfnRef`) that wrap `NonZeroU64`: no kernel object lies at physical address
0, because M4 makes no untyped below 1 MiB, so a stored 0 means none. Handles
are made only from a capability of the matching type or from links IPC
maintains. `IpcEnv` extends `l4core::tcb::Threads`, and so the capability
core's `Kernel`, `Scheduling` and `Tcbs`: it adds the endpoint words
(`endpoint_word`, `set_endpoint_word`) and the read side of IPC buffers
(`read_buffer_word`). The notification words (`notification_word`,
`set_notification_word`) and the `cancel_badged_sends` hook are on
`Threads` itself, because `TCB_BindNotification` and the CNode methods are
decoded over `Threads`, which has no `IpcEnv` ([`core/` and
`arch/`](#core-and-arch-2)). The TCB's IPC fields come through `Tcbs`; a
message word is found by index with `tcb::buffer_word` (0 to 3 in saved
registers, 4 to 119 in the buffer, `None` without a usable buffer) and
written with `Threads::write_buffer_word`; the scheduler is called through
`l4core::sched` (`make_runnable`, `set_thread_state`). Since `Threads` can
set priorities, the type no longer shows that IPC changes none ([ADR
0018](adr/0018-ipc-priorities.md)); the host tests check it after every step
instead. As for slots, `arch/` reads and writes through raw pointers into the
direct map and never forms a Rust reference into an object or an IPC buffer.
Buffers may alias: two threads may name the same 1 KiB (sender and receiver
included), and a DMA-capable device may write it. The `SAFETY:` argument is
the no-dangling invariant below and the rule that no object lies at address 0.
On the host, `l4core::testing::IpcTestKernel` implements the same traits over
fake physical memory, with the kernel's hooks.

M5's host tests (`core/src/ipc/tests.rs`, `core/src/syscall/tests.rs`) cover
every call, its errors and silent drops, the caller slot, `ReplyRecv` and its
restart, each fault type with restart and stop, a handler deleting or
suspending the faulting thread, a missing handler, an endpoint deleted with
threads queued, queue order and preemption, and self-suspend and self-delete.
At every kernel exit they check the scheduler's and IPC's invariants
(`sched::check_exit`, `ipc::check`, and from M6 `ipc::check_notifications`)
and that no priority changed. M6's host tests do the same:

- `core/src/ipc/transfer/tests.rs`: each rule of [Capability
  transfer](#capability-transfer), driven through system calls, with the
  capability core's invariants checked over every slot after every step,
  and the proptest `random_sends_move_capabilities_where_the_model_says`,
  random sends checked against a model of where each capability must end
  up;
- `core/src/invoke/ipc_tests.rs`: `CNode_SaveCaller` and
  `CNode_CancelBadgedSends`;
- `core/src/ipc/notification/tests.rs` and its proptest
  ([Notifications](#where-the-code-lives-2)).

The reference model, `l4model::ipc`, is plain data written from this note
and `docs/abi.md`, not from `l4core`: threads with their whole register
sets, IPC buffers and caller slots, endpoints and notifications as
`VecDeque`s, CNodes as vectors of capabilities, and the scheduler's queues,
action and current thread, each system call applied atomically. Its
harness (`l4model::ipc_harness::World`) runs `l4core::syscall` over
`IpcTestKernel` beside it, from six threads, four endpoints, three
notifications and a 64-slot root CNode, restarts a preempted TCB deletion
until it completes, and after every step compares every live thread's
state, registers, fault, caller slot, binding, priority and slice, every
IPC buffer word, every endpoint's and notification's state and queue, the
ready queues and the current thread, every CNode slot and the outcome, and
runs `ipc::check`, `ipc::check_notifications`, `sched::check_exit` and the
model's own check. A world may give some threads a second 64-slot CNode as
their CSpace root, holding copies of only some of the root's capabilities,
most in other slots, and a copy of the root CNode's: a `CPtr` then names
different capabilities in the two CSpaces, so a lookup in the wrong one
(the receive slot in the sender's CSpace, extra capabilities in the
receiver's, a fault endpoint or a CNode invocation in another thread's)
shows. `ipc_random.rs` generates intents resolved against the world, every
slot from the acting thread's CSpace: system calls, signals, faults,
ticks, invocations and deletions, 20,000 cases of up to 60 steps by
default (`PROPTEST_CASES` for more), about 14 seconds, in about two worlds
of three with some threads in the second CNode. Each step lets a thread at
the highest runnable priority act, the current one or one queued at its
priority, since `sched::check_exit` forbids a lower one to run, so the
model does not depend on the scheduler's choice among them.
`ipc_scenarios.rs` holds 70 hand-written sequences, one rule each. The
model has limits: an untyped is never sent, a CNode is never finalised
(neither CNode's own capability is ever deleted), the second CNode holds
no TCB capability, so its threads invoke TCBs only through capabilities
they receive, and derivation depth and revoke are not modelled, so the
transfer proptest and host tests above cover where a received copy sits
in the derivation list.

On QEMU `test=pingpong` makes 1,000 timed `Call` and `ReplyRecv` round
trips, after 16 warm-up ones, between the root task and a server thread at
priority 200 for each of 1-, 0- and 120-word messages, checking every
reply, and prints the TSC cycles per round trip (mean, fastest and median).
In the 120-word run the server checks every word of MR4 to MR119 it
received and answers each plus one, and the root task checks every word of
the reply. Under TCG on a busy host, M6's fastest 1-word round trip took
166,000 to 185,000 cycles, about 80 to 90 µs at 2.1 GHz. The fastest
120-word one took 524,000 to 771,000 before both sides checked every word,
and about 615,000 with those checks timed in. The numbers show trends, not
performance ([Open questions](#open-questions)).

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| No kernel object lies at physical address 0 | M4 untyped builder, host test; `core/` handles are `NonZeroU64` | M2, M4 |
| A thread is in at most one queue, and it is in object `O`'s queue exactly when it is `BlockedOnSend`, `BlockedOnReceive` or `BlockedOnNotification` on `O` | `l4core::ipc` queue functions; `ipc::check` at every kernel exit of the host tests, which from M6 also follows each `BlockedOnNotification` thread into its notification's queue, and `ipc::check_notifications`; from M6 the IPC model's proptest (`random_ipc_sequences_match_the_model`, `model/tests/ipc_random.rs`), which compares every endpoint's and notification's queue with the model's after every step, and the notification proptest (`random_notification_operations_match_the_model`), which does the same in its own world | M5, M6 |
| An endpoint is `Idle` exactly when its queue is empty; in `Send` every queued thread is `BlockedOnSend` on it, in `Recv` every one is `BlockedOnReceive` | `l4core::ipc`; `ipc::check` in the host tests (`check_finds_broken_states` shows it catches each breach); from M6 the IPC model's proptest, which compares every endpoint's state and queue with the model's and runs `ipc::check` after every step | M5, M6 |
| Queued threads are served in arrival order | host tests `queues_are_fifo_whatever_the_priority` and `deleting_an_endpoint_restarts_every_queued_thread_in_order`; from M6 `cancel_badged_sends_restarts_exactly_that_badges_senders_in_queue_order` and `deleting_a_notification_restarts_its_waiters_in_order_and_unbinds_it`, the IPC model's proptest against the model's `VecDeque` queues, and `test=badge`, whose server receives the queued clients in the order they called | M5, M6 |
| No queue, link or reply capability refers to a deleted endpoint, notification or TCB: finalisation empties queues and bindings, and deleting a TCB cancels its IPC, before the memory can be retyped | `cancel_all_ipc` from an endpoint's last capability (`ipc::finalise`) and `cancel_ipc` from the TCB's (`tcb::suspend`) (M5); host tests `deleting_an_endpoint_restarts_its_receivers` and `a_handler_that_deletes_the_faulting_thread_leaves_nothing_naming_it`; from M6 a notification's last capability unbinds it and runs `cancel_all_signals` (`ipc::finalise`), and a TCB's unbinds it before `tcb::suspend` (`tcb::finalise`): host tests `deleting_a_notification_restarts_its_waiters_in_order_and_unbinds_it`, `deleting_a_bound_tcb_unbinds_its_notification` and `deleting_a_waiting_tcb_takes_it_out_of_the_queue`, and the IPC model's and the notification proptests, which delete endpoints, notifications and TCBs; red-team brief 2 | M5, M6, M10 |
| A reply capability, other than a master, exists only while the thread it names is `BlockedOnReply`, and there is at most one per thread | `send`, `receive`, `reply`, `cancel_ipc`, and from M6 `save_caller`, which keeps a saved reply capability below its caller's master, where `cancel_ipc` finds it; `ipc::check` in the host tests; from M6 host tests `save_caller_moves_the_reply_capability_below_its_callers_master` and `a_saved_reply_capability_goes_when_its_caller_is_suspended`, and the IPC model's proptest, which saves, uses and deletes reply capabilities and compares every root CNode slot | M5, M6 |
| Every TCB's `reply` slot holds its own master reply capability, a derivation root at depth 0, from retype (or, for the root task's TCB, from boot) until finalisation; nothing but that finalisation copies, moves, revokes or deletes a master, and only a master has a reply capability derived from it | TCB retype inserts the master as a root, and boot step 8 the root TCB's; the capability core refuses masters as sources and inserts reply capabilities only under one; `ipc::check`; host test `tcb_retype_makes_a_reply_master_root`; from M6 the IPC model's proptest, which runs `ipc::check` after every step | M5, M6 |
| A thread `BlockedOnReceive` has an empty caller slot | receive step 1; `ipc::check`; host test `receiving_again_before_replying_gives_up_the_reply`; from M6 the IPC model's proptest, which compares every caller slot after every step | M5, M6 |
| The receiver gets the first delivered-length words of the sender's message and nothing else from any thread; its other message registers keep its own values | `transfer`; host tests `a_send_to_a_waiting_receiver_moves_the_message` and `nbrecv_with_nothing_pending_returns_zeros_and_keeps_the_message_registers`; from M6 the IPC model's proptest, which compares every thread's whole register set and every IPC buffer word after every step and checks that the kernel wrote buffers only where it may, and `test=pingpong`, whose server checks every word of each 120-word request and answers each changed, and whose root task checks every word of each reply | M5, M6 |
| The kernel reads an IPC buffer only through a non-device frame capability in the TCB's IPC buffer slot, writes it only with Write, and touches only its 128 words | `l4core::tcb::buffer_word` takes a word index below 128 and needs Read, and Write to write (host test `buffer_words_need_a_frame_with_the_rights`); `TCB_SetIPCBuffer` checks ([Creation and configuration](#creation-and-configuration)) | M5 |
| A capability moves by IPC only if the sender's capability has Grant, only into an empty slot the receiver named, at most one per message, with unchanged rights and badge, derived from the sender's capability by `derive` and `insert_derived` below `MAX_DERIVATION_DEPTH` | `ipc::transfer`'s `transfer_caps`: Grant, both buffers and `extra_caps` checked first, one receive slot found once, copies through `cnode::copy` with every right; host tests in `core/src/ipc/transfer/tests.rs`, among them `without_grant_nothing_is_copied_or_unwrapped`, `a_sender_needs_a_readable_buffer_and_a_receiver_a_writable_one`, `an_unusable_receive_slot_takes_no_copy_but_badges_still_arrive`, `the_first_capability_that_can_be_neither_unwrapped_nor_copied_ends_the_transfer`, `a_copy_of_a_copy_is_its_sibling_and_a_badged_original_keeps_its_badge` and `a_copy_refused_at_the_depth_limit_ends_the_transfer`; the proptest `random_sends_move_capabilities_where_the_model_says`, with the capability core's checks over every slot; the IPC model's proptest, which compares every root CNode slot but models no derivation; `test=captransfer`; red-team brief 1 | M6, M10 |
| Only an endpoint capability to the endpoint carrying the message is unwrapped, and the receiver learns only its badge | `transfer_caps` unwraps only a capability to the endpoint the message goes through, and never in a reply; host tests `a_capability_to_the_endpoint_carrying_the_message_arrives_as_its_badge` and `a_reply_never_unwraps`; the transfer proptest and the IPC model's; `test=captransfer`, where capabilities to the endpoint arrive as their badges, 0 included, whatever their rights | M6 |
| The badge a receiver sees is the badge of the capability the sender invoked, or 0 for a reply; no sender can choose it | `send` stores the capability's badge in `BlockedOnSend` (M5; host test `the_badge_is_the_one_the_sender_invoked_when_it_sent`); from M6 the IPC model's proptest, whose world holds badged and unbadged copies of the endpoints and compares every receiver's `rdi`, and `test=badge`, where every call of four clients arrives with its own capability's badge | M5, M6 |
| `Send` and `Call` need Write, `Call` also Grant or GrantReply, receiving needs Read, and a fault endpoint needs Write and Grant or GrantReply, checked at fault time | `l4core::syscall` and `ipc::deliver_fault` (`EndpointCap::can_send`, `can_call`, `can_receive`); host tests `call_needs_write_and_grant_or_grant_reply`, `send_needs_write_but_no_grant` and `receiving_needs_read`; syscall fuzzer, red-team brief 6 | M5, M10 |
| A thread leaves a blocked state only by completing its operation (a bound thread's endpoint receive also completes with a signal from its notification, through `signal` or bind) or through `cancel_ipc`, `cancel_all_ipc`, `cancel_badged_sends` or `cancel_all_signals`, so a restarted thread re-executes its system call with its own arguments | `l4core::ipc` state machine; host tests `suspend_takes_a_thread_out_of_its_queue_and_resume_restarts_it` and `a_restarted_reply_recv_is_harmless`; from M6 the IPC model's and the notification proptests, which compare every thread's state and registers after every step | M5, M6 |
| A thread's fault record is set only while it is `BlockedOnSend` or `BlockedOnReply` for that fault | `deliver_fault`, `reply`, `cancel_*`; `ipc::check` in the host tests; from M6 host test `callers_already_received_keep_waiting_and_a_queued_fault_restarts` and the IPC model's proptest, which compares every thread's fault after every step | M5, M6 |
| Every IPC system call finishes in one kernel entry, in time bounded by the message (120 words, 3 capabilities) or, for a cancellation, by its queue, which holds at most the TCBs that exist (2^18 in 512 MiB with `TCB_BITS` = 11); no argument makes the kernel block or panic | no preemption point and no other loop in `l4core::ipc`; from M6 capability transfer is at most three lookups, one receive-slot lookup and one copy (`transfer_caps`), and `cancel_badged_sends` and `cancel_all_signals` take one O(1) step per queued thread; syscall fuzzer, red-team brief 6; worst-case cancellation measured by red-team brief 9 | M5, M6, M10 |
| IPC never changes a thread's priority or timeslice | no function in `l4core::ipc` sets either; `IpcEnv` extends `Threads`, which can, so the type no longer enforces it ([ADR 0018](adr/0018-ipc-priorities.md)), and the host tests check after every step that no priority changed; red-team brief 9 | M5, M10 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| An endpoint is 16 bytes (`seL4_EndpointBits` = 4), its tail pointer and state packed into one word (`include/object/structures_64.bf`) | 32 bytes, every field a whole word ([Objects](abi.md#objects)) | `core/` reads plain `#[repr(C)]` words with no bit packing; the cost is 16 bytes per endpoint |
| `Call` on a capability without Grant or GrantReply delivers the message and leaves the caller `Inactive` (`src/object/endpoint.c`, `sendIPC` and `receiveIPC`; `ipc.tex`, "Calling and Replying") | `Call` returns `InvalidCapability` and sends nothing | the rights are known when the call is decoded; a silently suspended client is a hang nobody can diagnose, and no protocol needs it |
| `CNode_SaveCaller` with an empty caller slot succeeds and leaves the destination empty (`src/object/cnode.c`, `invokeCNodeSaveCaller`) | returns `IllegalOperation` | the server learns it had nothing to save instead of failing later on an empty slot |
| Non-MCS `cancelIPC` clears the fault record only for `BlockedOnReply`, and non-MCS `cancelAllIPC` and `cancelBadgedSends` restart a fault sender without clearing it; MCS clears it in `cancelIPC` and makes a cancelled fault sender `Inactive` (`src/object/endpoint.c`, `cancelIPC`, `restart_thread_if_no_fault`) | every cancellation clears it and restarts the thread, which re-raises the fault if its cause remains | `doIPCTransfer` (`src/kernel/thread.c`) sends a fault message whenever the record is set, so a stale record would turn a later ordinary send into a fault message, and `doReplyTransfer` would treat the reply to a later `Call` as a fault reply |
| `cancelAllIPC` and `cancelBadgedSends` put each released thread at the head of its ready queue, in the endpoint queue's order (`SCHED_ENQUEUE`, which is `tcbSchedEnqueue`, `tcb_queue_prepend` in `src/object/tcb.c`; with MCS through `possibleSwitchTo`, which prepends too), then call `rescheduleRequired` (`src/object/endpoint.c`, `src/kernel/thread.c`): among released threads of one priority the last released runs first, ahead of the threads already queued at that priority | `cancel_all_ipc` and `cancel_badged_sends` make each runnable in queue order (`sched::make_runnable`), and unless it runs at once it joins the tail of its ready queue: the first to have waited runs first, after the threads already queued there | on purpose: the release keeps the order the endpoint queue promised ([ADR 0018](adr/0018-ipc-priorities.md)), and a released thread does not jump threads already waiting to run ([ADR 0013](adr/0013-scheduling.md)'s tail rule; [Scheduling](#scheduling), Compared with seL4) |
| `NBRecv` with nothing pending sets only the badge register (`src/kernel/thread.c`, `doNBRecvFailedTransfer`) | also sets `rsi` to 0 | every register a receive returns is defined, so the model can compare it and `libsys` can rely on it |
| The master reply capability is made when the thread is first started (`src/kernel/thread.c`, `restart`, and `src/kernel/boot.c` for the initial thread, both calling `setupReplyMaster`) | made when the TCB is retyped, and by boot for the root task's TCB | the master then exists for the TCB's whole life, so no path has to check for it; nothing observable changes, since only a started thread can `Call` or fault |
| A reply transfers the message, then deletes the reply capability (`src/kernel/thread.c`, `doReplyTransfer`) | deletes it first, then transfers | "consumed when used" holds before any other effect. It differs only when a saved reply capability sits in the very slot the caller names as its receive slot: seL4 finds that slot full and moves no capability, microL4 can fill it |
| A fastpath handles common `Call` and `ReplyRecv` cases (`src/arch/x86/c_traps.c`, `include/arch/x86/arch/fastpath/fastpath.h`) | none in v0 | one path to model and test; timings under TCG mean little (PLAN.md, Risks) |

## Notifications

Notifications are seL4's: a 64-bit word that signals OR their badge into, a
FIFO queue of waiters, and an optional one-to-one binding to a TCB so a
server can wait on an endpoint and a notification at once. Interrupts and
SynIC events arrive as signals the kernel sends with the same semantics.

### States

| State | Queue | Word |
| --- | --- | --- |
| `Idle` | empty | 0 |
| `Waiting` | non-empty; every thread `BlockedOnNotification` on it | 0 |
| `Active` | empty | the OR of the badges signalled since the last wait; 0 if only unbadged capabilities signalled |

`Active` with word 0 is a real state: a signal through an unbadged capability
is remembered, so a waiter that arrives later does not miss it. This is
what seL4's code does (`src/object/notification.c`, `sendSignal` and
`receiveSignal` test the state, not the word); `notifications.tex`,
"Signalling, Polling and Waiting", says a wait blocks while the word is 0.

### Signal

`signal(N, b)` runs for `Send`, `NBSend` and `Call` on a notification
capability with Write, where `b` is that capability's badge, and when the
kernel signals for an interrupt or a SynIC event ([Delivery](#delivery-1),
[SynIC](#synic-m9)).

| Notification | Effect |
| --- | --- |
| `Waiting` | take the head `W`; `W` becomes `Running` with `rdi` = `b` and `rsi` = 0; `N` becomes `Idle` if the queue empties |
| `Idle`, bound to a thread `T` that is `BlockedOnReceive` on any endpoint | `cancel_ipc(T)` takes `T` off that endpoint's queue (the endpoint becomes `Idle` if it empties); `T` becomes `Running` with `rdi` = `b` and `rsi` = 0; `N` stays `Idle` |
| `Idle`, otherwise | `N` becomes `Active` with word `b` |
| `Active` | word = word OR `b` |

A signal never blocks and never fails, so the interrupt path never waits on
user space. A bound thread in any other state is not woken: `BlockedOnSend`
or `BlockedOnReply` (a `Call` in progress, which seL4's `sendSignal` also
leaves alone), waiting on another notification, runnable or `Inactive`. The
signal then stays pending until the thread next receives on an endpoint or
waits on this notification.
Repeated signals coalesce: a waiter sees which bits were signalled, not how
often, and interrupts that arrive before the driver waits are merged, not
lost. The IRQ and SynIC paths use exactly this `signal`, with the badge of
the notification capability they hold.

### Wait and poll

`wait(T, N, blocking)` runs for `Recv` and the receive phase of `ReplyRecv`
(blocking) and for `NBRecv` (not) on a notification capability with Read.
The capability's badge plays no part: a badged capability waits on the same
word as an unbadged one. If `N` is bound, only its bound thread may wait on
it; any other thread takes a capability fault in the receive phase, the same
fault as for a capability without Read (MissingCapability with 0 bits left,
seL4 `handleRecv`; [ADR 0026](adr/0026-receive-phase-cap-faults.md)). A
bound thread that waits on another notification gets nothing from its own
(seL4 `receiveSignal` does not look at the binding).

| Notification | `blocking` | Effect |
| --- | --- | --- |
| `Active` | either | `T` gets `rdi` = word and `rsi` = 0; `N` becomes `Idle` with word 0 |
| `Idle` or `Waiting` | true | `T` becomes `BlockedOnNotification(N)` at the tail; `N` becomes `Waiting` |
| `Idle` or `Waiting` | false | `T` gets `rdi` = 0 and `rsi` = 0 |

Message registers are unchanged. Waiting on a notification leaves the caller
slot alone, unlike receiving on an endpoint, so a server can wait for an
interrupt while it holds a reply. A poll that returns 0 cannot be told apart
from an `Active` notification signalled only through unbadged capabilities;
a protocol that polls gives every signaller a non-zero badge.

### Binding

`TCB_BindNotification` binds a TCB and a notification one to one;
[Invocations](#invocations) numbers it and
[`abi.md`](abi.md#tcb_bindnotification-and-tcb_unbindnotification) gives its
semantics. It needs a
notification capability with Read, whose badge plays no part, and fails if
the TCB is already bound or the notification is bound or has waiters (seL4
`decodeBindNotification`): a thread already waiting on a notification
cannot then be bound to it, but a thread waiting on another notification
can. Binding sets the TCB's `bound_notification` and the notification's
`bound_tcb`. If the notification is already `Active` and the TCB is
`BlockedOnReceive`, the signal is delivered at once, as if it had arrived
after binding: `cancel_ipc` takes the TCB off its endpoint's queue, the TCB
becomes `Running` with `rdi` = word and `rsi` = 0, and `N` becomes `Idle`
with word 0. In any other state the signal stays pending, as in
[Signal](#signal).

A bound thread gets a pending signal instead of an IPC at step 2 of the
receive phase, is woken out of an endpoint receive by a signal, and may still
wait on the notification directly. It tells a signal from a message by `rsi`
and badge: a signal returns `rsi` = 0 with the notification word in `rdi`,
and a message its `MessageInfo` in `rsi` with the sender's badge in `rdi`.
A message's `MessageInfo` may also be 0, so `root` gives every notification
capability a non-zero badge in bits that no endpoint capability's badge
touches, and a receive is a signal when `rsi` is 0 and `rdi` has one of
those bits (`libsys::Event::classify`; `test=ipcntfn` uses bit 32 and up
for signals and `0x1` to `0x3` for endpoints).

`TCB_UnbindNotification` clears both links and nothing else: the
notification keeps its state and word, a thread in an endpoint receive stays
there, and a thread already waiting directly on the notification stays
queued (seL4 `unbindNotification`). Suspend and Resume leave a binding alone
(seL4 `suspend`, `restart`). Deleting the TCB, or the final capability to
the notification, also unbinds.

### Deletion

When the final capability to `N` is deleted, the kernel unbinds it and runs
`cancel_all_signals(N)`, in that order, as seL4's `finaliseCap` does. Every
waiter, in queue order, becomes `Restart` and is made runnable (its retried
`Recv` resolves its `CPtr` afresh, as for endpoints), the bound thread
included if it was waiting directly, so among waiters of one priority the
first to have waited runs first, where in seL4 the last does (Compared with
seL4 below); the pending word is discarded, and `N` becomes `Idle`. A bound
thread in an endpoint receive loses only the link and stays queued there.
Like the endpoint cancellations, the loop is not preemptible and its queue
is bounded by the TCBs that exist. `cancel_ipc` on a
`BlockedOnNotification` thread removes it from the queue.

### Where the code lives

| Part | Where | Milestone |
| --- | --- | --- |
| The object: `Notification`, `NtfnState`, the word offsets `ntfn_field`, `NotificationCap` (`can_signal`, `can_wait`), the typed accessors `notification` and `set_notification` | `l4core::ipc::notification` (`core/src/ipc/notification.rs`) | M6 |
| `signal`; `wait` and `may_wait`; `complete_bound_signal`, step 2 of an endpoint receive; `bind_notification`, `unbind_notification`; `cancel_all_signals`; `finalise`, which `ipc::finalise` calls for a notification's last capability; `cancel_signal`, the `BlockedOnNotification` arm of `cancel_ipc`; `check_notifications`, the invariants below as a function | the same | M6 |
| Dispatch: `Send`, `NBSend` and `Call` signal, `Recv`, `NBRecv` and the receive phase of `ReplyRecv` wait or poll | `l4core::syscall` (`invocation`, `receive`) | M6 |
| `TCB_BindNotification` and `TCB_UnbindNotification` | `l4core::tcb::invocation`, over `Threads`; TCB finalisation unbinds through `tcb::finalise` | M6 |
| The notification words in the kernel | `arch::Objects` (`Threads::notification_word`, `set_notification_word`), by value through raw pointers into the direct map | M6 |
| Signal, wait and poll, and telling a signal from a message | `libsys::notification` (`signal`, `wait`, `poll`, `Event::classify`); `tcb_bind_notification` and `tcb_unbind_notification` in `libsys::invoke` | M6 |
| The kernel's signal for an interrupt; for a SynIC event | `l4core::irq::deliver`, which calls `signal` with the IRQ node capability's badge ([Delivery](#delivery-1)); M9 | M7, M9 |

The notification words are on `Threads`, not `IpcEnv`, because
`TCB_BindNotification` is decoded over `Threads` ([`core/` and
`arch/`](#core-and-arch-2)). Every function but `signal` is generic over
`Threads`; `signal` may take a bound thread out of an endpoint receive with
IPC's `cancel_ipc` and so needs `IpcEnv`, while `bind_notification` does the
same through the `Threads::cancel_ipc` hook.

`core/src/ipc/notification/tests.rs` checks each rule of this section
through system calls, with the scheduler's, IPC's and the notifications'
invariants at every kernel exit, and `check_notifications_finds_broken_states`
shows the checker catches each breach. Its proptest, `random_notification_operations_match_the_model`
(`core/src/ipc/notification/tests/model.rs`, 1,024 cases of up to 80 steps),
runs random signals by system call and by the kernel, waits, polls, binds,
unbinds, endpoint sends and receives, suspends, resumes and deletions by six
threads on three notifications and two endpoints against a model of words,
queues and bindings, and compares them after every step;
`random_sequences_reach_every_path` checks that the sequences reach every
path the model knows. The IPC model's proptest ([Where the code
lives](#where-the-code-lives-1)) covers notifications too, mixed with every
other system call. On QEMU `test=ipcntfn` runs a server bound to a
notification that takes calls and signals on one receive, with
`TCB_BindNotification`'s refusals, scripted orderings, two clients and
two signallers running freely, and last a bind that delivers a pending
signal at once.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A notification is `Waiting` exactly when its queue is non-empty; `Idle` and `Waiting` have word 0; `Active` has an empty queue | `l4core::ipc::notification`'s queue functions; `check_notifications` at every kernel exit of the host tests (`check_notifications_finds_broken_states`); the notification proptest and the IPC model's, which compare every notification's state, word and queue with the model's after every step | M6 |
| Binding is one to one and symmetric: `T.bound_notification` = `N` exactly when `N.bound_tcb` = `T` | `bind_notification`, `unbind_notification`, `notification::finalise` and `tcb::finalise`; `check_notifications`; host tests `bind_sets_both_links_and_unbind_clears_them`, `deleting_a_bound_tcb_unbinds_its_notification` and `tcb_finalisation_unbinds_then_suspends`; the notification proptest and the IPC model's, which compare every binding after every step | M6 |
| While a notification is bound, only its bound thread waits on it | `TCB_BindNotification` refuses a notification with waiters (`tcb::invocation::decode`; host tests `bind_errors_in_order` and `bind_notification_errors_in_order`); the dispatcher's `ipc::may_wait` check (host test `a_bound_thread_may_wait_on_its_notification_and_no_other_thread_may`); `check_notifications`; the notification proptest, whose sequences include waits by another thread on a bound notification; `test=ipcntfn`, where binding a second thread to N is `IllegalOperation`; red-team brief 1 | M6, M10 |
| A bound thread is never `BlockedOnReceive` while its notification is `Active` | `signal` and `bind_notification` deliver at once, and an endpoint receive takes a pending signal first (`complete_bound_signal`); `check_notifications`; host tests `a_signal_wakes_a_bound_thread_out_of_an_endpoint_receive`, `binding_delivers_a_pending_signal_to_a_thread_in_an_endpoint_receive` and `a_bound_thread_receiving_on_an_endpoint_takes_a_pending_signal_first`; the notification proptest and the IPC model's; `test=ipcntfn`, which binds its server while it waits on an endpoint with a signal pending, and the signal arrives at once | M6 |
| No signalled bit is lost: each is returned to exactly one waiter or bound receiver, or is still pending, until the notification is deleted | the notification proptest and the IPC model's, which compare every notification word and every thread's `rdi` and `rsi` with the model's after every step; host test `signals_with_nobody_waiting_or_their_badges_into_the_word`; `test=ipcntfn`, where a shared sequence number shows each signaller's bit reached the server after its last signal | M6 |
| A signal never blocks or fails, so interrupt delivery never waits on user space | `ipc::signal` has no blocking path and no error; the kernel's own signal takes the same path (host test `the_kernel_signals_through_the_same_path`, and the `Interrupt` action of the IPC model's proptest); from M7 `l4core::irq::deliver` signals the same way (host tests `a_signal_from_an_interrupt_wakes_the_waiter_and_preempts_only_for_a_higher_priority` and `an_interrupt_in_the_idle_thread_runs_the_woken_thread`, the IRQ table's proptest); `test=irq`, whose interrupts signal a notification the root task polls, and `test=console`, where uart waits on its notification | M6, M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| A notification is 32 bytes (`seL4_NotificationBits` = 5 without MCS), its queue tail and state packed into one word (`include/object/structures_64.bf`) | 64 bytes, every field a whole word ([Objects](abi.md#objects)) | as for endpoints; the cost is 32 bytes per notification |
| A delivered signal sets only the badge register; `rsi` keeps whatever the thread passed in (`src/object/notification.c`, `sendSignal`, `receiveSignal`, `completeSignal`) | `rsi` is set to 0 | every register a receive returns is defined |
| Binding a thread that is `BlockedOnReceive` to an `Active` notification leaves the signal pending, and later signals only OR into the word, until an IPC arrives (`src/object/notification.c`, `bindNotification`; `src/object/tcb.c`, `decodeBindNotification`) | the pending signal is delivered at bind | closes a wake-up that could otherwise wait forever, and keeps the invariant above unconditional |
| `cancelAllSignals` puts each waiter at the head of its ready queue, in the notification queue's order (`SCHED_ENQUEUE`, as `cancelAllIPC` in [IPC](#ipc), Compared with seL4; with MCS `possibleSwitchTo`), then calls `rescheduleRequired` (`src/object/notification.c`): among waiters of one priority the last to have waited runs first | `cancel_all_signals` makes each runnable in queue order, and unless it runs at once it joins the tail of its ready queue: the first to have waited runs first | on purpose, as for endpoints: the release keeps the queue's order |

## Interrupts

The kernel runs the local APIC in xAPIC mode, keeps the 8259 PIC masked, and
routes device interrupts through the I/O APIC (M7), MSI (M9) and Hyper-V's
SynIC (M9). IRQControl issues one IRQHandler per interrupt source; the kernel,
not user space, picks the vector and applies the MADT's interrupt source
overrides, and each interrupt arrives as a signal on the notification bound to
its handler ([ADR 0019](adr/0019-irqcontrol.md)).

### Vector map

| Vectors | Use | Handling |
| --- | --- | --- |
| `0x00`-`0x1F` | CPU exceptions | from ring 3: a fault to the thread's handler ([Faults](#faults)), except NMI, #DF and #MC, which panic ([NMI, double fault, machine check and debug](#nmi-double-fault-machine-check-and-debug)); 9, 15, 17 and 20 to 31 cannot occur and panic from either ring; from ring 0: panic with the decoded frame (M3), except a `#DB` at `syscall_entry` or at the #BP stub's first instruction, which returns ([NMI, double fault, machine check and debug](#nmi-double-fault-machine-check-and-debug)) |
| `0x20`-`0x2F` | 8259 PIC, remapped here and masked | never expected; spurious: no EOI unless the vector's ISR bit is set (an injected MSI) |
| `0x30`-`0xEF` | 192 device vectors, allocated by the kernel to I/O APIC pins, MSIs and SINTs | IRQ number = vector - `0x30`; see [Delivery](#delivery-1) |
| `0xF0`-`0xFC` | reserved for IPIs (multi-core stretch goal) | unexpected: logged in debug builds, EOI |
| `0xFD` | local APIC timer, 100 Hz | EOI, then the scheduler tick ([Timer tick](#timer-tick)) |
| `0xFE` | local APIC error | read and clear ESR, log in debug builds, EOI |
| `0xFF` | local APIC spurious vector | return, no EOI |

`#DB` (1) runs on IST4; NMI (2), double fault (8) and machine check (18) run
on their IST stacks ([NMI, double fault, machine check and
debug](#nmi-double-fault-machine-check-and-debug)). `#BP` (3) has DPL 3, so
`int3` is UserException 3 with `rip` after it; every other gate has DPL 0, so
`int n` from ring 3 is a `#GP` fault and cannot enter a device or timer
handler. `int1` raises `#DB` without a DPL check (from memory; M10 brief 5
checks it from ring 3, since QEMU 8.2's TCG raises `#UD` for `int1` in ring 0,
and the `trap_debug` scenario single-steps instead): from ring 3 it is
UserException 1; a ring-0 `#DB` returns only when
the saved RIP is exactly `syscall_entry` or the #BP stub's first instruction,
and any other panics. Vectors 9, 15,
17 (`#AC`, CR0.AM = 0) and 20 to 31 (`#VE` not enabled, `#CP` without CET, 29
and 30 SEV only, the rest reserved) cannot occur; only an injected MSI reaches them, and the
kernel panics. Their gates take the no-error-code entry, so the panic reads
the frame correctly. An MSI cannot inject vectors 0-15, which the LAPIC
rejects as illegal (SDM, from memory). The kernel takes interrupts only with
IF = 1, in ring 3 or the idle loop ([Idle thread](#idle-thread)). A preemption
point polls the LAPIC IRR words for `0x30`-`0xFE`, masking off `0x20`-`0x2F`
in the word they share with `0x30`-`0x3F`, as seL4's
`apic_is_interrupt_pending` does (`src/arch/x86/kernel/xapic.c`); it never
opens an `sti` window. M3 provides the poll as `arch::apic::interrupt_pending`,
and the `ticks` scenario checks that it sees the timer with IF = 0.

### Local APIC, PIC and I/O APIC (M3)

The kernel reaches the LAPIC, the I/O APICs and the HPET only through the
kernel device window at `KERNEL_DEVICE_BASE`
([The kernel half](#the-kernel-half)): LAPIC at offset 0, I/O APIC `i` at
`0x1000 * (1 + i)` (`i` < 4), HPET at `0x5000`. The 2 MiB direct-map pages
that hold these devices are mapped uncached as well, and M4 makes no RAM
untyped from them.

With IF = 0, after Hyper-V's leftovers are off ([Firmware
leftovers](#firmware-leftovers-m3)): if `IA32_APIC_BASE` shows x2APIC mode,
leave it through the disabled state, since the SDM makes a direct x2APIC to
xAPIC write raise #GP ("x2APIC State Transitions"; an `l4core::apic` host
test checks the order of writes); the boot summary prints `IA32_APIC_BASE` as
found. Refuse a local APIC that is not integrated (version `0x10`-`0x1F`), as
seL4's `apic_init` does. Mask every LVT the version register counts: the timer
(the firmware may have armed it), LINT0, LINT1 and error, and the
performance, thermal and CMCI LVTs from a maximum LVT index of 4, 5 and 6, as
Linux's `clear_local_APIC` decides; TPR = 0; SVR = enabled, vector `0xFF`,
EOI-broadcast suppression off (level-triggered pins need it). Write EOI until
no ISR bit is set, at most 256 times, since a vector the firmware left in
service would hold back every vector of its priority class and below; read
and clear ESR; LVT error = `0xFE`, unmasked. Only then, with LINT0 masked, if
the MADT flag `PCAT_COMPAT` is set, remap the PIC to `0x20`/`0x28` and mask
all lines: its first initialisation word clears the masks until the last
write sets them again. Mask every I/O APIC redirection entry, keeping its
vector. Then set up the HPET, calibrate and start the timer. xAPIC because
every x86-64 CPU and both platforms offer it, so one path runs on every boot.
OVMF hands over in xAPIC mode with one vCPU (`IA32_APIC_BASE` `0xfee00900`:
enabled, the boot processor; the `hello` scenario), and TCG's `-cpu max` does
not offer x2APIC, even with `x2apic=on`, so the x2APIC path never runs on
QEMU; only its host test covers it. On QEMU the local APIC reports version
`0x50014` with six LVT entries, and the I/O APIC version `0x20` with 24 pins
(the `hello` scenario). Lost: only the speed of the MSR access Hyper-V
recommends (TLFS CPUID `0x4000_0004` EAX bits 3 and 8).

The MADT gives up to four I/O APICs (ID, base, GSI base); the pin count is the
version register's MRE + 1, at most 120, since the 8-bit register select
reaches redirection entries 0 to 119 only. An I/O APIC whose GSI base plus
pin count passes 2^32 serves no GSI (`Routing::from_platform`; bad firmware
only), since a GSI is 32 bits; `ioapic.rs` keeps each I/O APIC's version
beside its registers and writes the EOI register only from version `0x20`.

Remote IRR (bit 14 of an entry) is set when the I/O APIC sends a level
interrupt, and a level pin sends nothing more until an EOI for that vector
clears it; on an edge entry it is undefined (82093AA datasheet, from memory;
QEMU clears it). Normally the local APIC's EOI broadcast clears it, as in
seL4: every delivery is EOI'd, EOI-broadcast suppression is off, and a masked
or freed pin keeps its vector and trigger, so the broadcast still matches. It
is left set, stale, only when a delivery's EOI never came: the firmware had it
in service when the local APIC was reset (leaving x2APIC through the disabled
state clears ISR; SDM, from memory), say. So on issue the kernel first masks
the pin's entry, keeping vector, trigger and polarity, and reads it back. If
Remote IRR is set, it clears it as Linux's `clear_IO_APIC_pin` and
`__eoi_ioapic_pin` do (`arch/x86/kernel/apic/io_apic.c`, from memory; M7 did
not read Linux's source, but on QEMU both paths below clear a stranded Remote
IRR, as the `irq_stale` and `irq_stale_0x11` scenarios show):
it writes the entry level-triggered, still masked and with its old
vector, since an EOI clears Remote IRR only on a level entry (QEMU's
`ioapic_eoi_broadcast` checks the trigger, from memory); then, on an I/O APIC
of version `0x20` or later (QEMU's), it writes the old vector to the EOI
register at offset `0x40`, and on an older one, which has none (Hyper-V's
`0x11`), it writes the entry edge-triggered and then level-triggered again,
both masked, which is how Linux simulates that EOI ([ADR
0027](adr/0027-stale-remote-irr.md)). It reads Remote IRR again; if it is
still set, the issue fails with `RevokeFirst` and the pin stays masked.
Masking and unmasking would not clear it, since the mask bit only holds back
new messages, and the kernel cannot make the local APIC broadcast an EOI for a
vector that is not in service (an EOI broadcasts only an in-service vector
whose TMR bit is set, and a self-IPI is edge-triggered). This runs in the
resource check, before the destination slot
([Conventions](abi.md#conventions-1)), so an issue that then fails may have
cleared a free pin's stale Remote IRR; it changes nothing else. Only once
every check has passed does it write the final entry, the destination word
first: physical destination the boot CPU, then vector, fixed delivery, the
requested trigger and polarity, unmasked. The EOI register makes the register
block `0x44` bytes from version `0x20`, and all of it must lie in the I/O
APIC's window page.

ISA IRQ `n` goes to GSI `n`, edge, active high, unless an override (bus 0,
source `n`) gives the GSI and flags ("conforms to bus", and a reserved
polarity or trigger value, mean the ISA default).
An ISA IRQ whose GSI is another IRQ's override target has no route (IRQ 2 on
q35, where IRQ 0 goes to GSI 2). COM1 is ISA IRQ 4 on GSI 4, edge, active
high. On q35 the `acpi` scenario and the host tests on its dumped MADT show
both, and IRQs 5, 9, 10 and 11 level-triggered, active high; Hyper-V's COM1
route is checked at the M3 Hyper-V check.

### The IRQ table

Fixed kernel memory, indexed by IRQ number 0-191: `source` (`Free` or
`IoApic { gsi, pin, level, active_low }`; M9 adds `Msi` and `Sint(n)`),
`pending` (an edge pin delivered since the last Ack), `masked` (the kernel
masked the pin and waits for Ack), and an IRQ node slot holding the bound
notification capability or nothing; two counters for debug output beside it,
`lost` (deliveries with no notification bound) and `stale` (deliveries to a
free entry). IRQ node slots are ordinary 32-byte slots, 192 of them (6 KiB)
in the kernel image's `.bss`, in the derivation list and reached by the same
slot handles as CNode slots; no `CPtr` names them and the Zombie code never
visits them.
A bound capability sits where `CNode_Copy` of the capability passed to
`SetNotification` would put it (derived from an original, else a sibling of a
copy), as seL4's `cteInsert` into `intStateIRQNode` does
(`invokeIRQHandler_SetIRQHandler`, `src/object/interrupt.c`). A GSI or SINT
has at most one entry.

### IRQControl and IRQHandler

The root task gets the only IRQControl capability (slot 4 in M4, invocations
in M7). As in seL4, deriving it yields nothing: it can be moved or deleted,
not copied or minted.

| Invocation | Source | Milestone |
| --- | --- | --- |
| `GetISA(isa_irq)` | ISA IRQ 0-15, routed through the MADT | M7 |
| `GetIOAPIC(gsi, trigger, polarity)` | any I/O APIC pin, explicit flags | M7 |
| `GetMSI()` | one MSI or MSI-X message; returns its address and data | M9 |
| `GetSint(sint)` | SynIC SINT 0-15, Hyper-V only | M9 |

Each checks that the source is free, takes the lowest free vector, programs
the source and writes an IRQHandler capability (holding the IRQ number) into
the destination slot as a revocable child of IRQControl. A source that already
has a handler, no free vector, or a pin whose Remote IRR stays set once the
kernel has tried to clear it gives `RevokeFirst`. A new entry starts with
`pending` and `masked` clear and the IRQ node slot empty.

IRQHandler capabilities can be copied; mint data is ignored.
`SetNotification(ntfn)` needs a notification capability with the Write right
(seL4's `CanSend`) and fails with `IllegalOperation` if the copy would exceed
`MAX_DERIVATION_DEPTH`; after every check it deletes any bound capability,
then copies the given one, badge included, into the IRQ node slot. `Clear`
deletes the bound capability. Neither touches the source: a pin the kernel
masked stays masked until an Ack, and `pending` stays as it was, as seL4's
`invokeIRQHandler_SetIRQHandler` and `invokeIRQHandler_ClearIRQHandler` only
replace or delete the slot's capability. `Ack` clears `pending` and unmasks the pin if the
kernel masked it; for MSI and SINTs it does nothing.

| Source | On issue | On delivery | On Ack | On handler deletion |
| --- | --- | --- | --- | --- |
| I/O APIC, level | masked, a stale Remote IRR cleared, then programmed unmasked | masked before EOI | unmasked | mask bit set; vector and trigger kept |
| I/O APIC, edge | masked, a stale Remote IRR cleared, then programmed unmasked | `pending` set; if it was already set, masked | `pending` cleared; unmasked if masked | mask bit set; vector and trigger kept |
| MSI | vector reserved | unchanged | nothing | vector freed |
| SINT | SINTn = vector, unmasked | unchanged | nothing | SINTn masked |

A level line re-fires at every EOI while asserted, so it stays masked until
the driver has serviced its device. An edge pin stays open for the first edge
after an Ack, so no edge that follows an Ack is lost, even on an I/O APIC that
drops edges on a masked pin (82093AA datasheet, from memory), as QEMU 8.2's
does: in `test=irq` an edge raised while the pin is masked signals nothing,
then or at the next Ack. A second edge before Ack masks the pin, so a device the driver cannot
or will not quiet (the PIT at its highest rate, say) costs at most three
interrupts per Ack (two, plus one the local APIC may already hold when the
mask lands), and interrupt load follows the driver's own scheduling.
An edge lost while masked can belong to a cause the driver's service has
already passed, so a driver of an edge pin Acks before it services: the
pin is then open for every cause after its last look at the device, and a
second edge during service masks it again but leaves a signal, so the
driver runs once more (ADR 0028). A level line keeps asserting, so its
driver services first and then Acks. An MSI cannot be
masked without touching the device; a masked SINT loses message interrupts
and makes the host's `HvCallSignalEvent` fail (TLFS
`inter-partition-communication.md`). A driver of a level pin loops wait,
service, Ack, and one of an edge pin wait, Ack, service. After
`SetNotification` either Acks once and services its device once, since an
interrupt between issue and binding signalled nothing.

### Delivery

On vector `v` in `0x30`-`0xEF`, with the interrupted thread's registers saved:
take entry `v - 0x30`; if it is `Free`, drop the interrupt (a stale MSI, or a
source deleted while pending) and count it in `stale`; for a level pin, mask
it and set `masked`; for an edge pin, if `pending` is set mask it and set
`masked`, then set `pending`; if the IRQ node slot holds a notification
capability, signal that notification with the capability's badge (the
semantics of [Signal](#signal)), else count it in `lost`; EOI; return through
the scheduler, which runs the woken thread at once only if it outranks the one
interrupted. The work is constant and reads no user memory. An interrupt with
no notification is lost, but the pin's state still advances, so the driver's
Ack is still needed.

The steps up to the signal are `l4core::irq::deliver`; the EOI is not one of
its actions but the interrupt path's own, after `deliver` returns
(`arch::irq::handle`, as `l4core::apic::needs_eoi` decides for every vector),
so a delivery's mask lands before its EOI and the EOI is written once whatever
`deliver` did.

### Deletion

Deleting the final IRQHandler capability deletes the IRQ node capability
(which may finalise the notification, as seL4's `deletingIRQHandler` does),
masks the source (an I/O APIC pin: only its mask bit, keeping vector and
trigger, as seL4's `ioapic_mask`; a SINT: its mask bit), and then frees the
entry and vector. As in seL4, the first step is the `finalise` hook's, which
returns the IRQHandler as the cleanup, and the other two are `after_delete`'s,
once the handler's slot is empty (`deletedIRQHandler`, through
`postCapDeletion`), so the IRQ is free exactly when the last slot naming it is
([How `core/` reaches kernel memory](#how-core-reaches-kernel-memory)).
Keeping the vector matters for a level interrupt that arrived during the
deletion: its stale delivery is taken as soon as the kernel returns with
IF = 1, before the vector can be reissued, lands on a `Free` entry, and its EOI
broadcast still matches the pin's entry, so Remote IRR clears; reissue clears
a stale one anyway ([Local APIC, PIC and I/O APIC
(M3)](#local-apic-pic-and-io-apic-m3)). The freed vector may go to another
source while the masked pin still names it; the pin never sends it, and the
new source's EOI broadcasts can only clear the old pin's Remote IRR. A deleted
MSI that the device keeps sending lands on a `Free` entry, or after reuse
gives the new owner a spurious signal; drivers treat signals as hints.
Revoking IRQControl deletes every IRQHandler. A notification cannot be
finalised while bound, because the IRQ node holds a capability to it; revoking
an ancestor (its untyped, say) deletes that capability as a descendant first.

### MSI (M9) and the trust model

`GetMSI` returns address `0xFEE0_0000 | (boot APIC ID << 12)` and data =
vector, fixed delivery, edge (from memory; check in M9 against the SDM), which
the driver writes into its MSI capability or MSI-X entry. One vector per call:
multi-message MSI is not offered; MSI-X covers virtio-net. No PCI identity is
recorded: without an IOMMU nothing could check it.

Trust model: DMA is as strong as the kernel, since a driver that programs a
device's DMA can read and write all memory. MSI is no weaker: an
MSI is a DMA write to `0xFEEx_xxxx`, so a driver that can program MSI can send
any vector with any delivery mode, including NMI, INIT and `#MC`'s vector, and
stop the machine. Both are accepted for drivers the root task trusts, and
recorded for M10 brief 7.

### Where the code lives

| Part | Where | Milestone |
| --- | --- | --- |
| The IRQ table (`IrqTable`, `Entry`, `Source`), IRQ numbers and vectors (`vector`, `irq_of_vector`), the routes (`Routing`: each I/O APIC's GSI base, pin count and version, and the ISA routes through the MADT's overrides), the IRQ node's slots (`node_slot`) | `l4core::irq` (`core/src/irq.rs`) | M7 |
| `invoke_control` (`GetISA`, `GetIOAPIC`), `invoke_handler` (`Ack`, `SetNotification`, `Clear`), `deliver`, and `finalise` and `after_delete`, the IRQHandler arms of the kernel's hooks; `check`, the invariants below as a function | the same | M7 |
| The I/O APIC accesses, as values: `Action` (`MaskRte`, `UnmaskRte`, `CheckRemoteIrr`, `ClearRemoteIrr` with the `ClearPath` the I/O APIC's version picks, `ProgramRte`), and `Action::writes`, the register writes each makes to an entry that reads a given low word. There is no EOI action ([Delivery](#delivery-1)); M9 adds the SINT actions | the same | M7 |
| What `core::irq` needs from the kernel beyond slots, threads and IPC: the `Interrupts` trait (`irq_table`, `irq_table_mut`, `routing`, `irq_node`, `irq_action`), which `l4core::invoke::invoke` and the system-call dispatch require beside `Kernel`, `Threads` and `PagingStore` | the same | M7 |
| The local APIC, I/O APIC and PIC registers, the values boot writes, `redirection_entry` and `remote_irr`, and the EOI rule (`needs_eoi`); the ISA routes (`Platform::isa_route`) | `l4core::apic`; `l4core::acpi` | M3 |
| `Objects`' `Interrupts`: the IRQ table in a static only `Objects` reaches (with the port bitmap), as the scheduler is; the IRQ node, `IRQ_NODE`, 192 zeroed slots in `.bss`, reached by value through the direct map at the physical address `objects::init` computes; `init_interrupts`, which records the routes at step 5 | `kernel/src/arch/x86_64/objects.rs` | M7 |
| `ioapic::perform`: one action, as a read of the entry's low word and then `Action::writes`'s writes; boot's masking of every pin, keeping its vector | `kernel/src/arch/x86_64/ioapic.rs` | M3, M7 |
| The interrupt path: `deliver` for a device vector, then the EOI, then the caller's scheduler | `kernel/src/arch/x86_64/irq.rs`, with `idt.rs`, `apic.rs` and `pic.rs` | M3, M7 |
| `test=irq_stale`: strands a level pin's Remote IRR with the HPET's last comparator, then issues the pin through `l4core::invoke` | `kernel/src/arch/x86_64/irq_stale.rs`, with `selftest` only | M7 |
| The invocations from user space: `irq_control_get_isa` (which decodes the route it returns into `IsaIrq`), `irq_control_get_ioapic`, `irq_handler_ack`, `irq_handler_set_notification` and `irq_handler_clear`, each message built by a host-tested `device::Request` | `libsys::device` | M7 |

`core/src/irq/tests.rs` checks each rule of this section through system calls
on a test kernel with models of the local APIC and of QEMU 8.2's I/O APIC
(`l4core::testing::FakeIoApic`, from memory of `hw/intc/ioapic.c`: level pins
with Remote IRR, cleared by an EOI broadcast or, from version `0x20`, the EOI
register; edges dropped on a masked pin; an entry written edge-triggered
loses Remote IRR; and a mode where nothing clears it), with the scheduler's,
IPC's, the notifications' and the IRQ table's invariants (`check`) at every
kernel exit, and a count of writes that unmasked a pin with Remote IRR set,
which must stay 0: the routes of the q35 and Hyper-V MADT dumps, each
action's writes, every invocation's errors in order, both ways of clearing a
stale Remote IRR, the edge and level rules, delivery's wake-ups, deletion and
revoke; `check_finds_broken_tables` shows the checker catches each breach.
Its proptest, `random_irq_operations_and_interrupts_match_the_model`
(`core/src/irq/tests/model.rs`, 512 cases of up to 80 steps, at I/O APIC
version `0x20` or `0x11`), runs random issues, copies, deletions and revokes
of IRQControl, Acks, `SetNotification`s, `Clear`s, polls, stranded Remote
IRRs and line changes, some falling inside the next kernel entry, against a
model of the table written from this section, and compares the table,
bindings and notification words after every step;
`random_sequences_reach_every_path` checks that the sequences reach every
path. On QEMU `test=irq` runs the edge and level rules, `Clear`, deletion
and revoke from ring 3 with COM1's THRE interrupt, and `test=irq_stale`
both Remote IRR paths, with QEMU's I/O APIC at version `0x20` and, in the
`irq_stale_0x11` scenario, at `0x11`.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Each interrupt source (GSI, SINT, MSI vector) has at most one issued IRQHandler, copies aside | `l4core::irq`'s issue refuses a GSI that has an entry (`IrqTable::holder`) with `RevokeFirst`; `irq::check` ("a GSI has two entries"); host tests `irq_control_errors_in_order` and `a_refused_issue_never_touches_an_issued_pin`; the IRQ table's proptest, whose model issues a GSI once; `test=irq`, where `GetISA(4)` again and `GetIOAPIC(4)` are `RevokeFirst`. SINTs and MSI vectors: M9 | M7, M9 |
| Each vector in `0x30`-`0xEF` belongs to at most one source; no other vector is issued | an entry's vector is its index plus `0x30` (`irq::vector`, host test `irq_n_is_vector_0x30_plus_n`), and an issue takes the lowest free entry (`IrqTable::lowest_free`) or fails with `RevokeFirst` (host test `with_every_vector_taken_an_issue_is_revoke_first`); the IRQ table's proptest, whose model allocates the same way | M7 |
| An IRQ node slot holds only a notification capability with the Write right and never names a deleted notification | `SetNotification`'s checks before any change (host test `irq_handler_errors_in_order`); `irq::check` at every kernel exit of the host tests and the proptest; the bound capability is a derivation-list child or sibling like any copy (host test `set_notification_copies_the_capability_into_the_irq_node_as_cnode_copy_would`), so it keeps its notification alive and goes with the handler (host tests `rebinding_the_last_capability_to_a_notification_finalises_it`, `deleting_the_handler_deletes_the_irq_nodes_capability_and_may_finalise_its_notification`); host test `revoking_a_bound_notifications_original_empties_the_irq_node_slot`, where a revoke of the bound capability's original deletes the IRQ node's copy and the next interrupt is lost; `test=redteam-irq`, where revoking the untyped of the bound notification N deletes N and the IRQ node's copy, and a notification N2 retyped at N's address gets no signal in 200 ms of the PIT's interrupts and Acks until the handler is bound to it | M7 |
| Deleting the last IRQHandler masks its source, empties its IRQ node slot and frees its vector | `irq::finalise` and `irq::after_delete` through the kernel's hooks; host tests `deleting_the_last_handler_unbinds_masks_keeping_vector_and_trigger_and_frees_the_irq`, `revoking_irq_control_deletes_every_handler` and `a_freed_vector_reissued_elsewhere_never_hears_the_old_pin`; the IRQ table's proptest, which checks after every step that every pin without an entry is masked; `test=irq`, where a deleted ISA IRQ 4 is issued again as IRQ 0, a copy keeps it issued and revoking IRQControl deletes both handlers | M7 |
| Between two Acks an I/O APIC pin delivers at most three interrupts: two, plus one the local APIC already holds when the mask lands | `irq::deliver`'s `pending` and `masked`; host tests `an_edge_pin_stays_open_for_the_first_edge_and_masks_on_the_second_before_ack`, `the_local_apic_may_hold_a_third_interrupt_when_the_mask_lands` and `a_level_pin_is_masked_on_delivery_and_refires_at_ack_while_asserted`; the IRQ table's proptest, which fails an edge pin's fourth interrupt or a level pin's second between two Acks (its random sequences reach two; the third only in the host test); `test=irq`, where a fourth edge with no Ack signals nothing; `test=redteam-irq`'s PIT storm, about 18.6 kHz of edges on GSI 2, whose polls may find at most three signals in 200 ms with no Ack and in 20 ms after each of ten Acks (runs have found 1, and 1 or 2 per Ack). The PIT at its highest rate is not driven | M7 |
| No pin is unmasked with Remote IRR set | Two writes unmask a pin. Issue's `ProgramRte` comes only after `l4core::irq`'s `MaskRte`, then `CheckRemoteIrr` (`ioapic::perform` reads the entry and answers from its Remote IRR bit), `ClearRemoteIrr` if it is set and `CheckRemoteIrr` again, which refuses the issue with `RevokeFirst` if it is still set; from `MaskRte` on the I/O APIC sends nothing on the pin, so nothing sets Remote IRR between. Ack's `UnmaskRte` does not look at Remote IRR: it relies on the interrupt path, `arch::irq::handle`, which EOIs every device vector after `deliver` and before the kernel exits, with EOI-broadcast suppression off (`apic::SVR_VALUE`, host test `svr_error_and_timer_values`), so a level delivery's Remote IRR is clear before any Ack can run; a level pin deleted with a delivery pending keeps its vector, so that delivery's EOI clears it too. Tested: `FakeIoApic` counts every write that unmasks a level entry with Remote IRR set, which must stay 0 after every step of the host tests and the proptest, whose sequences strand Remote IRRs; host tests `issue_clears_a_stale_remote_irr_through_the_eoi_register_from_version_0x20`, `below_version_0x20_issue_clears_a_stale_remote_irr_by_toggling_the_trigger`, `a_remote_irr_that_stays_set_is_revoke_first_and_the_pin_stays_masked`, `a_level_pin_is_masked_on_delivery_and_refires_at_ack_while_asserted` and `a_level_interrupt_pending_at_deletion_is_dropped_and_its_eoi_clears_remote_irr`, the only test with a delivery pending at the deletion; `test=irq`, where an Ack with the level line high signals again (so the Ack found Remote IRR clear), and a level handler deleted after its delivery and EOI, the line still high, is issued again; `test=irq_stale`, which strands a level pin's Remote IRR (its entry's vector changed between delivery and EOI) and then issues the pin, with QEMU's I/O APIC at version `0x20` and, in the `irq_stale_0x11` scenario, at `0x11` (`-global ioapic.version=0x11` through `qemu_args:`; QEMU accepts only those two, from memory). The EOI register is written only on an I/O APIC whose version, read and kept by `ioapic.rs`'s `IoApic`, is `0x20` or later | M7 |
| Every fixed interrupt is EOI'd exactly once: `0x30`-`0xFE` always, `0x20`-`0x2F` only when its ISR bit is set, `0xFF` never | `l4core::apic::needs_eoi` (host test `every_fixed_interrupt_is_eoied_once`), asked once per interrupt by `arch::irq::handle`, after `deliver` for a device vector, which writes no EOI itself; the `ticks` scenario and, from M7, `irq` and `console`, whose device interrupts keep arriving | M3, M7 |
| User code cannot enter an interrupt handler with `int n` | DPL 0 on every gate but `#BP`; red-team brief 5 | M3, M10 |
| No interrupt arrives before the IDT is loaded; pins stay masked until issued; the PIC, LINT0 and LINT1 stay masked | M3 init order, QEMU scenario | M3 |
| A vector that cannot occur (9, 15, 17, 20 to 31) panics from either ring and never makes the kernel misread a frame | no-error-code gates and panic path; red-team brief 7 | M3, M10 |
| Handling an interrupt takes constant time and reads no user memory | `irq::deliver` reads one entry and one IRQ node slot and makes at most one mask action and one `ipc::signal`, which never blocks and wakes at most one thread; `arch::irq::handle` adds only the EOI; review | M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| User space picks the vector in `GetIOAPIC` and `GetMSI` (`src/arch/x86/object/interrupt.c`) | The kernel allocates it and returns the IRQ number | No vector namespace for root to manage, and the kernel can refuse a second handler for a pin, which seL4 never checks (`ioapic_decode_map_pin_to_vector`, `src/plat/pc99/machine/ioapic.c`). Lost: user-chosen APIC priority classes, which matter little with IF = 0 in the kernel |
| `GetIOAPIC` names an I/O APIC by its MADT index and a pin on it (`object-api-arch.xml`, `ioapic_decode_map_pin_to_vector`) | `GetIOAPIC` names a GSI; `GetISA` an ISA IRQ | GSIs are what the MADT's I/O APIC bases and overrides use, so root needs no I/O APIC ordering |
| Overrides are printed, not applied (`MADT_ISO` in `acpi.c`); user space parses ACPI from the RSDP | `GetISA` applies them in the kernel | User space has no ACPI parser and never reads ACPI |
| Every `IRQSignal` source is masked on delivery until Ack (`handleInterrupt`, `src/object/interrupt.c`), though an x86 MSI cannot be masked (`maskInterrupt`, `include/plat/pc99/plat/machine/interrupt.h`) | Level pins the same; an edge pin is masked only by a second delivery before Ack; MSI and SINTs never | An edge pin masked from its first delivery loses any edge between the driver's last poll and its Ack; the `pending` bit still bounds it to three interrupts per Ack; a masked SINT breaks host signalling |
| Deleting the handler sets the pin's mask bit and keeps its vector (`deletedIRQHandler`, `src/object/interrupt.c`; `ioapic_mask`, `ioapic.c`) | The same | A level interrupt pending at the deletion is EOI'd against the kept vector, so its Remote IRR clears |
| Remote IRR is never read. Boot writes every pin masked, edge-triggered, vector 0 (`single_ioapic_init`, `ioapic.c`), which clears it where a switch to edge does (QEMU); issue writes the pin's entry without looking (`ioapic_map_pin_to_vector`), so a level pin with a stale one stays silent | Boot keeps each pin's vector and trigger; issue clears a stale Remote IRR (the EOI register from version `0x20`, Linux's trigger toggle below it) and refuses the pin with `RevokeFirst` if it stays set ([ADR 0027](adr/0027-stale-remote-irr.md)) | A level pin must not be handed out dead; Hyper-V's I/O APIC is version `0x11`, with no EOI register |
| The destination slot is looked up before `GetIOAPIC`'s I/O APIC, pin, level and polarity are checked (`Arch_decodeIRQControlInvocation`) | Arguments, then the source and vector, then the destination slot | One order for every invocation in the range ([Conventions](abi.md#conventions-1)) |
| `lookupTargetSlot` checks the destination's root before its depth (`lookupSlotForCNodeOp`, `src/kernel/cspace.c`), so a root that is not a CNode with a depth of 0 is `FailedLookup` (`InvalidRoot`) | The depth first: that case is `RangeError(1, 64)` (`l4core::invoke::destination`, for IRQControl and IOPortControl alike; host test `irq_control_errors_in_order`, its case "depth 0, a root that is no CNode") | The order [Conventions](abi.md#conventions-1) lists, as `Untyped_Retype` checks `node_depth` before the root ([Memory and retype](#memory-and-retype)) |
| PIC mode with `IRQControl_Get` for ISA IRQs (`Arch_checkIRQ`) | I/O APIC only; PIC always masked | Both platforms have an I/O APIC |
| `GetMSI` takes PCI bus, device, function and handle | Takes no source; returns address and data | Unchecked without an IOMMU; spares drivers the APIC ID |
| IOSpace and IOPageTable objects drive the VT-d IOMMU, with a master IOSpace capability minted per PCI device (`io.tex`, "I/O Space") | No IOMMU objects; a driver that can program DMA or MSI is trusted with the machine | Neither target gives the guest an IOMMU by default (q35 without `intel-iommu`; Hyper-V, from memory); PLAN.md records DMA as a known limitation (M10 brief 7) |
| xAPIC or x2APIC at build time (`KernelLAPICMode`, `src/arch/x86/config.cmake`); an xAPIC kernel refuses to boot if the firmware left x2APIC on (`apic_enable`, `src/arch/x86/kernel/xapic.c`) | xAPIC only; x2APIC left on is turned off through the disabled state | One path, run on every boot; a firmware that hands over in x2APIC still boots ([Open questions](#open-questions)) |
| DPL 3 interrupt gates for `#BP` and for vectors `int_trap_min` (158, or 160 with SMP) to 255 (`init_idt_entry`, `src/arch/x86/64/kernel/vspace.c`); 158/160-254 become unknown system calls (`c_handle_interrupt`, `src/arch/x86/c_traps.c`) | Only `#BP` is DPL 3 | `syscall` is the only entry for system calls |
| Every exception vector from ring 3, 17, 21, 29 and 30 included, becomes a user fault (`handleUserLevelFault`, `c_traps.c`) | 9, 15, 17 and 20 to 31 panic from either ring | They cannot occur here; only an injected MSI reaches them, and such a driver can already stop the machine with an NMI |
| Timer 157, spurious 255 (`include/plat/pc99/plat/machine.h`); the LVT error entry is never programmed (`apic_init`, `src/arch/x86/kernel/apic.c`) | Timer `0xFD`, error `0xFE`, spurious `0xFF` | Kernel vectors above every device vector; APIC errors are logged in debug builds |

## I/O ports

User space reaches I/O ports only through IOPort invocations, as in seL4:
IOPortControl issues an IOPort capability for a range that overlaps no other
issued range, and each In or Out checks the port against the capability. No
thread ever runs with IOPL above 0 or with an I/O permission bitmap.

### Objects and checks

IOPortControl is one capability, in the root task's slot 7 from M4; as in seL4
(`Arch_deriveCap`) it cannot be copied or minted. IOPort `{ first, last }`,
with `first` in bits 0 to 15 of its `data` word and `last` in bits 16 to 31
(`l4core::ioport::port_cap`), can be copied, but mint cannot narrow it: an
IOPort ignores mint data, so a mint is a copy, and a narrower range is a
separate `Issue`.
A static 65,536-bit bitmap (8 KiB) records issued ports: `Issue` sets the
range, and deleting the last capability with the same `(first, last)` clears it
(seL4's `Arch_postCapDeletion`). `Issue` needs `first <= last <= 0xFFFF`, no
issued port in the range (`RevokeFirst`) and no kernel-reserved port. In and
Out need `port <= 0xFFFF`, `first <= port` and `port + width - 1 <= last` in
32-bit arithmetic, so `In32` at `0xFFFE` cannot wrap. In zero-extends; Out
uses the low `width` bytes. `Send` on an IOPort does the access and drops the
reply ([System calls](abi.md#system-calls)).

### Ports the kernel uses

| Ports | Kernel use | Issuable |
| --- | --- | --- |
| `0x20`-`0x23` (PIC, IMCR), `0xA0`-`0xA1` (PIC) | programmed at boot only | no: they could route legacy interrupts past the LAPIC mask (IMCR from memory; M7 did not check it, [Open questions](#open-questions)) |
| `0x3F8`-`0x3FF` (COM1) | debug builds only: `serial::init` at boot, then panics and `DebugPutChar`, which touch only THR and LSR; the writer bounds its wait for THRE, so a `uart` that breaks the UART cannot hang it | yes; in debug builds `uart` shares it with kernel output, as in seL4 |
| `0xF4` (`isa-debug-exit`, QEMU) | `arch::exit` ends the run: `DebugHalt`, a panic, a kernel self-test's end | yes, so user-space tests can end a run in any build (`test=release` issues `0xF4`-`0xF7` and writes there with `IOPort_Out32`); scenarios still require `TEST PASS` |
| `0x40`-`0x43`, `0x61` (PIT, speaker) | none | yes |
| `0x64`, `0x92`, `0xCF9`, the ACPI PM1 control port | none | yes, but each can reset or power off the machine; root gives them only to trusted servers (M10 brief 7) |
| `0xCF8`-`0xCFF` (PCI configuration) | none | yes, but it reaches every device, which is as strong as DMA; root gives it only to a trusted PCI manager (M9 uses ECAM) |
| `0x510`-`0x51B` (QEMU's `fw_cfg`) | none | yes, but its DMA interface at `0x514`-`0x51B` makes QEMU read or write guest memory at any address the guest names, which is as strong as DMA (from memory of QEMU's `hw/nvram/fw_cfg.c`); no M7 server needs it, and root gives it to none |

The kernel keeps only the 8259s' primary ports. Intel's ICH chipsets also
decode them at aliases, `0x24`-`0x3D` and `0xA4`-`0xBD` (from memory of the
ICH datasheets); neither QEMU's q35 nor Hyper-V does, so on both targets those
ports reach nothing. On hardware with an ICH they would reach the PIC, and
the kernel would have to keep them too.

### Why invocations, not the TSS I/O bitmap

A per-thread I/O bitmap would let drivers run `in` and `out` directly, at the
cost of up to 8 KiB per TCB or a TSS rewrite per switch, a search of every
bitmap on revoke, and no capability check at the time of access. Invocations
check at use, match seL4 and need no per-thread state. Lost: a system call per
access; COM1 at 115,200 baud needs at most about 23,000 a second. The TSS has
no bitmap (I/O map base past its limit), and user RFLAGS.IOPL is always 0,
enforced by `WriteRegisters` and every return to user mode
([User register set and sanitising](#user-register-set-and-sanitising)),
since `sysretq` loads RFLAGS from `r11`.

### Where the code lives

| Part | Where | Milestone |
| --- | --- | --- |
| The bitmap (`PortBitmap`), the kernel's ports (`RESERVED`, `reserved`), the capability's range (`port_cap`, `port_range`), `invoke_control` (`Issue`) and `invoke_port` (In and Out of 8, 16 and 32 bits), and `finalise` and `after_delete`, the IOPort arms of the kernel's hooks | `l4core::ioport` (`core/src/ioport.rs`) | M7 |
| What `core::ioport` needs from the kernel: the `IoPorts` trait (`port_bitmap`, `port_bitmap_mut`, and `port_in` and `port_out`, which make the access the checks allowed); nothing in `core/` executes `in` or `out` | the same; `l4core::invoke::invoke` and the dispatch require it beside `Interrupts` | M7 |
| `Objects`' `IoPorts`: the bitmap in the static that holds the IRQ table, and the accesses through `io.rs` | `kernel/src/arch/x86_64/objects.rs` | M7 |
| The only `in` and `out` in the kernel: `inb`, `inw`, `inl`, `outb`, `outw`, `outl`, each `#[inline(never)]` and taking its port as its first argument, for the release kernel's disassembly check ([A release kernel without UART code](#a-release-kernel-without-uart-code)) | `kernel/src/arch/x86_64/io.rs` | M0, M7 |
| The invocations from user space: `ioport_control_issue`, `ioport_in8` to `ioport_in32`, `ioport_out8` to `ioport_out32`, each message built by a host-tested `device::Request` | `libsys::device` | M7 |

`core/src/ioport/tests.rs` checks every rule above through system calls on
the test kernel, which records each access instead of making it: the kernel's
ports, the bitmap across word boundaries, the capability's data word, every
error row of `Issue`, In and Out in `docs/abi.md`'s order with nothing
changed by a failed call, zero-extension and the low bytes of Out, and the
hooks. Its proptest, `random_issues_copies_deletions_and_accesses_match_a_model_of_ranges`
(256 cases of up to 60 steps), runs random issues near COM1, the PIC and
`0xFFFF`, copies, deletions, revokes of IOPortControl and accesses of every
width against a model of each slot's range; `random_sequences_reach_every_path`
checks that the sequences reach every path. On QEMU `test=ioport` issues
COM1's range from ring 3 and reads and writes COM1's scratch register.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| User code never executes `in` or `out`: user RFLAGS.IOPL is 0 and the TSS has no I/O bitmap | TSS setup (M3); RFLAGS sanitised on `WriteRegisters` (`l4core::regs::sanitise`) and every return (`l4core::entry::exit_frame`) (M5); red-team briefs 5 and 7 | M3, M5, M10 |
| An IOPort invocation touches only ports inside its capability's range, width included, with no wrap past `0xFFFF` | `l4core::ioport::invoke_port` checks `port <= 0xFFFF`, `first <= port` and `port + width - 1 <= last` before `IoPorts::port_in` or `port_out`; host tests `in_reads_zero_extended_within_the_range_width_included` and `ioport_errors_in_order`; the port bitmap's proptest, which checks every access the test kernel recorded against the model's range; `test=ioport`, which reads at both ends of COM1's range, the width included, and is refused one port past either end | M7 |
| Issued ranges are pairwise disjoint and contain no kernel-reserved port | `invoke_control` checks `reserved` and then the bitmap (`PortBitmap::any_set`) before the destination; host tests `the_kernel_keeps_the_pic_and_imcr_ports` and `issue_errors_in_order`; the port bitmap's proptest, which compares the bitmap with the model's ranges after every step; `test=ioport`, where every range overlapping COM1's is `RevokeFirst` | M7 |
| A range becomes issuable again only once its last IOPort capability is deleted | `ioport::finalise` returns only the last capability as the cleanup, and `ioport::after_delete` clears its bits once its slot is empty; host tests `a_range_is_free_again_only_once_its_last_capability_is_deleted`, `the_hooks_free_only_the_last_capabilitys_range` and `revoking_iocontrol_frees_every_range_and_it_cannot_be_copied`; the port bitmap's proptest; `test=ioport`, where the range stays issued until its last capability goes and a revoke of IOPortControl frees it | M7 |
| The release kernel contains no UART code | `cfg(feature = "debug")` on `serial.rs` and `kprintln!`'s writer; `cargo xtask test`'s disassembly check (`xtask/src/disasm.rs`); the `release` scenario ([A release kernel without UART code](#a-release-kernel-without-uart-code)) | M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Ports are read as `getSyscallArg(...) & 0xffff`, so `0x1_03F8` means `0x03F8` (`src/arch/x86/object/ioport.c`) | A port or bound above `0xFFFF` is `InvalidArgument` | Bad input should fail, not alias |
| No reserved ports (`x86KSAllocatedIOPorts` starts empty) | PIC and IMCR ports are never issued | They control legacy routing the kernel keeps off |
| Exclusive ranges, `RevokeFirst` on overlap, `IllegalOperation` outside the range, freed with the last capability | Same | Kept |

## ACPI and the timer

The kernel alone parses ACPI, once at boot (M3), from the RSDP the loader
passes: the XSDT (the RSDT only for revision 0), the MADT, the HPET table and
the MCFG. The parser is in `core/`, host-tested on tables dumped from QEMU's
q35, and from the owner's Hyper-V Generation 2 VM at the M3 Hyper-V check
(`core/tests/acpi/hyperv-gen2.dump`, without its 123 KB DSDT, which the
parser never reads); user space gets
the few facts it needs in BootInfo's
`InterruptInfo`, never the tables, and `ACPI_RECLAIMABLE` memory becomes RAM
untyped after parsing. The local APIC timer runs periodically at 100 Hz,
calibrated against the Hyper-V reference counter if present, else the HPET;
with neither, the kernel panics. The same windows measure the TSC.

### Tables and validation

| Table | The kernel takes | If absent or invalid |
| --- | --- | --- |
| RSDP, XSDT (RSDT) | table addresses | panic: no MADT |
| MADT | LAPIC address (the header's, or the first Local APIC Address Override's), `PCAT_COMPAT`, I/O APICs, interrupt source overrides | panic |
| HPET | MMIO base (system-memory address space only) | no HPET, as on q35 with `hpet=off` and on Hyper-V (checked at the M3 Hyper-V check); also when the base is 0 or the 1 KiB register block crosses a page |
| MCFG | ECAM ranges for M9 | no PCI for user space, as on Hyper-V; also when the entry area is not a whole number of 16-byte entries |

The FADT and AML are not read: no ACPI shutdown and no PCI INTx routing
(`_PRT`), so PCI drivers use MSI, as virtio-net can.

- RSDP: signature `"RSD PTR "`, checksum over 20 bytes. Revision 0 uses the
  RSDT; any other revision needs `length` 36-4096, a checksum over `length`
  and a non-zero XSDT.
- Other tables: header read first; `length` from the table's minimum to 1 MiB;
  `[address, address + length)` inside the direct map without overflow;
  expected signature; byte sum 0. A failing table counts as absent, with a
  warning. The XSDT entry area is a multiple of 8 bytes (RSDT: 4). A root
  entry that is 0, or whose header cannot be read, is skipped with a warning.
- MADT entries from offset 44: a length below 2 or an entry past the end
  rejects the MADT (seL4 does not check; a zero length loops forever); a known
  type below its minimum length is skipped, as seL4's `acpi_madt_valid` does.
  An I/O APIC at address 0 and an override for a bus other than ISA (0) are
  skipped with a warning; an override with a reserved polarity or trigger
  value is kept, with the ISA default in that field and a warning. The device
  window takes the local APIC's page from `IA32_APIC_BASE`, and the boot log
  warns if the MADT's address differs.
- Duplicates. Two MADTs or two HPET tables at different addresses are a panic,
  since either could be the right one; a table the root lists twice at the
  same address is skipped with a warning, and a second MCFG at another
  address is ignored with a warning.
- Fixed capacity. More than four I/O APICs is a panic, since a device page
  left out would become device untyped; past 16 overrides or 4 ECAM ranges,
  entries are dropped with a warning, and the boot log's table list holds
  the first 32 tables, though a MADT, HPET table or MCFG past them is still
  read. Bounds-checked byte
  reads only, never a cast of table memory. Layouts follow ACPI 6.5; host
  tests check them against the q35 dumps, and against Hyper-V's after the M3
  Hyper-V check.

`l4core::acpi::parse(mem: &impl PhysRead, rsdp: u64)` returns a fixed-size
`Platform`; the kernel's `PhysRead` in `arch/` copies from the direct map below
`phys_map_size`, so `core/` needs no `unsafe`. It runs once at boot; nothing
reads ACPI memory afterwards, which is what lets M4 make it untyped.
With the word `acpidump` on the command line, the loader, in any build,
prints every ACPI table it can reach to COM1 before it loads the kernel
(`docs/boot.md`, [Command line](boot.md#command-line)); `cargo xtask
acpidump` turns that log into a dump in `core/tests/acpi/`. Host tests use
those dumps (q35 with and without its HPET; Hyper-V's from the M3 Hyper-V
check), hand-made edge cases and a random-bytes proptest, all under Miri. The
q35 dumps show an ACPI 2.0 RSDP (revision 2) with an XSDT, one processor,
the local APIC at `0xfee00000`, one I/O APIC at `0xfec00000` with GSI base 0,
the HPET at `0xfed00000`, and one ECAM range at `0xe0000000` for buses 0 to
255; `hpet=off` removes the HPET table.

### What user space gets, and kernel devices

BootInfo ([Initial CSpace and BootInfo](#initial-cspace-and-bootinfo)) carries
IRQControl, IOPortControl, the Hypervisor capability and the two SynIC frames
in initial slots 4, 7, 12, 13 and 14; the RSDP address, for information only;
`tsc_hz`; and, in its `interrupts` block, `InterruptInfo`: the ECAM ranges,
the I/O APICs' GSI ranges and the 16 ISA routes (layout in
[`abi.md`](abi.md#interrupts-io-ports-and-hyper-v)). The LAPIC page with the
whole MSI window `0xFEE0_0000`-`0xFEEF_FFFF`, each I/O APIC page and the HPET
page never become device untyped (M4) and are reached only through the device
window: a user LAPIC could EOI, send INIT to its own CPU or retune the timer,
and a user HPET could send FSB interrupt messages anywhere. ECAM stays device
untyped; root should give each driver only its own function's 4 KiB of
configuration space.

### The timer

- Periodic LAPIC timer, divide by 1, vector `0xFD`, initial count = APIC ticks
  per 10 ms; seL4's non-MCS kernel also runs it periodic (`apic.c`).
- Calibration (M3): count LAPIC ticks (one-shot, masked, from `0xFFFF_FFFF`)
  and TSC ticks over 20 ms of the reference, three times, and take each
  median; the TSC rate goes into BootInfo's `tsc_hz` for M6's IPC timings.
  Each window opens at a reference edge, and each reference read is
  bracketed by a LAPIC and a TSC read, whose midpoints stand for the moment
  of the reference read; reading the three in sequence gave rates 200 to
  450 ppm high under TCG. QEMU's APIC clock calibrates to within about 30 ppm
  of 1 GHz (the `hello` and `ticks` boot logs).
  The Hyper-V reference counter (MSR `0x4000_0020`, 100 ns units; TLFS
  `timers.md`, FreeBSD `include/hyperv.h`) goes first, since Hyper-V has no
  HPET (checked at the M3 Hyper-V check). TCG ignores the `hv-*` flags and
  never reports `Hv#1`, so the reference-counter path runs only on Hyper-V.
  HPET: period in femtoseconds in `GCAP_ID[63:32]`, valid if
  `0 < period <= 10^8`; counter at `0xF0`; enable is bit 0 of `0x10`, which
  OVMF leaves clear (the `hello` scenario's `hpet:` lines). M3 first turns
  off legacy-replacement mode and each comparator's interrupt enable and FSB
  delivery, and clears any interrupt status the firmware left; then it
  starts the counter and checks that it moves. Only the main counter is used.
  `NUM_TIM_CAP` can claim 32 comparators, but only 24 have registers inside
  the 1 KiB block, and the kernel touches no more. Under TCG the LAPIC timer
  and the HPET follow QEMU's virtual clock, so calibration holds however
  slowly TCG runs; the TSC follows the host clock, so `tsc_hz` there shows
  trends only (both from memory).
- Neither reference: panic `no timer reference`, proven by the
  `no_timer_reference` scenario (`qemu_args: -machine hpet=off`). Both
  platforms have one, a guessed rate would silently skew every timeslice, and
  a PIT fallback would never run in a test. Lost: other HPET-less machines,
  a non-goal. A frequency outside 1 MHz-10 GHz also panics.
- No TSC-deadline mode: it needs the TSC rate to be exact and pays off only for
  one-shot programming, which classic scheduling does not use. Lost: tickless
  idle and the precise one-shots of MCS (a stretch goal).
- The `ticks` scenario times ten ticks against the reference and needs
  100 ms within 1%. It dates each tick by the timer's reload: the reference
  read in the handler, less the countdown's progress since the reload at the
  calibrated rate. Handler-to-handler times include the host's delay in
  delivering each interrupt, often hundreds of microseconds under TCG, and
  measured 0.47% short of 100 ms under load, half the allowance. A wrong
  calibration still shows in full, since it sets the reload interval itself;
  the scenario prints the handler time beside it.
- `core/src/timer.rs` (M3): the 128-bit arithmetic, bounds and median, with
  host tests such as QEMU's 1 GHz APIC clock giving 10,000,000.
  `core/src/calibration.rs` reads one window and dates a tick by its reload,
  and `core/src/hpet.rs` holds the HPET's registers and its clean-up; both
  are host-tested.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| The ACPI parser never reads outside a validated table or the direct map, never panics, and terminates on any input | `core::acpi` bounds-checked reads, proptest on random bytes, Miri | M3 |
| A table with a bad signature, length or checksum is never used | `core::acpi` validation, host tests on corrupted copies of the dumped tables | M3 |
| The kernel reads ACPI memory only during boot, before M4 makes it untyped | one `parse` call at boot into `Platform`; no `PhysRead` after boot | M3, M4 |
| The kernel reaches the LAPIC, I/O APICs and HPET only through the uncached device window | `arch` device accessors take window offsets only; M3 table builder | M3 |
| The LAPIC page, the MSI window, the I/O APIC pages and the HPET page never become device untyped, and no RAM untyped comes from a 2 MiB page holding one | boot reservation list, BootInfo self-test | M4 |
| The kernel never schedules on an uncalibrated or implausible timer | calibration bounds; panic without a reference; `no_timer_reference` scenario | M3 |
| The timer ticks at 100 Hz within 1% on both platforms | `ticks` scenario timed against the reference, each tick dated by its reload; Hyper-V check | M3 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Walks the RSDT; checks only the RSDP and RSDT checksums (`acpi_validate_rsdp`, `src/plat/pc99/machine/acpi.c`) | XSDT first; every table's checksum, length and bounds | q35 is ACPI 2.0+ (revision 2 RSDP with an XSDT, host tests on its dump), and Hyper-V's revision is checked at the M3 Hyper-V check; checks are cheap and host-tested |
| Trusts MADT entry lengths (`acpi_madt_scan`) | A malformed entry rejects the MADT | A zero length would loop forever |
| Gives user space the RSDP (`src/arch/x86/kernel/boot.c`) | Gives the ECAM ranges, I/O APIC GSI ranges and ISA routes in `InterruptInfo`; `GetISA` applies overrides | User space never reads ACPI, whose memory becomes untyped |
| Reads the FADT for the physical-APIC-mode flag and the DMAR for IOMMUs (`acpi_fadt_scan`, `acpi_dmar_scan`) | Reads neither | One core needs no logical IDs; no IOMMU support |
| Maps the LAPIC and I/O APIC pages into its kernel window (`map_kernel_window_devices`, `src/arch/x86/kernel/vspace.c`) but leaves them, like every non-RAM gap, in device untyped (`create_untypeds`, `src/kernel/boot.c`) | Maps them and the HPET in its device window and keeps them, with the whole MSI window, out of every untyped | The kernel uses the HPET; user LAPIC, I/O APIC or HPET access breaks isolation |
| The APIC timer is calibrated against the PIT (`apic_measure_freq`, `src/arch/x86/kernel/apic.c`), the TSC against a model-specific MSR or the PIT (`tsc_init`, `src/plat/pc99/machine/hardware.c`) | Against the reference counter or the HPET; panic with neither | The plan's choice; both are exact, and Hyper-V may have no PIT (from memory) |

## Hyper-V interface

Only the kernel executes hypercalls and touches synthetic MSRs. A Hypervisor
capability exposes exactly two hypercalls, `HvCallPostMessage` and
`HvCallSignalEvent`, plus EOM and the VP index. SINT interrupts are ordinary
IRQHandlers from IRQControl, so SynIC messages and events arrive as
notification signals. The SynIC message and event-flag pages are two
boot-region RAM frames, mapped write-back, that the kernel never touches after
setting them up; the root task gets them in slots 13 and 14 and maps them into
`vmbus` ([ADR 0020](adr/0020-hypervisor-capability.md)).

### Detection (M3)

The kernel checks CPUID.1:ECX bit 31, then leaf `0x4000_0000` EAX at least
`0x4000_0005`, then leaf `0x4000_0001` EAX = `"Hv#1"` (`0x3123_7648`): the TLFS
says to base compatibility on that interface signature, not the vendor string
(`feature-discovery.md`). The vendor is printed and still decides whether
`isa-debug-exit` exists. Leaf `0x4000_0003` gives the privileges
(`hv_partition_privilege_mask.md`): `AccessPartitionReferenceCounter` (EAX 1)
for M3's calibration; `AccessFrequencyRegs` (EAX 11) together with EDX bit 8
for the TSC and APIC frequency MSRs (`0x4000_0022`, `0x4000_0023`), which M3
prints beside its calibration (Linux and FreeBSD also require both bits
before reading them); `AccessSynicRegs` (EAX 2), `AccessHypercallMsrs` (EAX 5),
`AccessVpIndex` (EAX 6), `PostMessages` (EBX 4) and `SignalEvents` (EBX 5) for
M9. The kernel touches a synthetic MSR only if its privilege bit is set, so no
request can make it fault on one. The Hypervisor capability exists only if all
five M9 bits are set and the hypercall page can be `.hvcall`. Otherwise
slots 12, 13 and 14 are null, no SynIC is set up, `GetSint` returns
`IllegalOperation`, and the boot log says why.

### Firmware leftovers (M3)

The Generation 2 firmware boots from VMBus storage, so it uses the SynIC (from
memory), and it may leave overlay pages enabled over memory the kernel will
hand out. Before M4 reuses `USABLE` memory, and before the local APIC is set
up, the kernel turns these off, each only with its privilege. First the
interrupt sources: the enable bit of the synthetic timers (`0x4000_00B0`,
`B2`, `B4`, `B6`; `AccessSyntheticTimerRegs`, EAX 3) and of the synthetic
time-unhalted timer (`0x4000_0114`, which can deliver an NMI; also CPUID
`0x4000_0003` EDX bit 23), whose enable bit is bit 8, above its vector, not
bit 0 as for every other register here (TLFS `timers.md`). Then it masks
SINT0-15 and clears the enable bit of SCONTROL, SIMP and SIEFP
(`AccessSynicRegs`), of the reference TSC page (`0x4000_0021`,
`AccessPartitionReferenceTsc`, EAX 9), of the VP assist page (`0x4000_0073`)
and of the hypercall page (`0x4000_0001`, `AccessHypercallMsrs`). The TLFS
names no privilege for the VP assist page; the kernel requires
`AccessIntrCtrlRegs` (EAX 4), as KVM's Hyper-V emulation does
(`hv_check_msr_access`, from memory). If the firmware
Locked the hypercall MSR, M3 records the page, M4 never makes it untyped and
the boot region avoids it; unless it is `.hvcall`, there is no
Hypervisor capability. M3 prints what it found. TCG ignores the `hv-*`
flags, so none of this runs on QEMU. The M3 Hyper-V check ran it: the
firmware had left only SCONTROL on, and the hypercall MSR was neither enabled
nor locked.

### Hypercalls (M9)

The kernel writes `HV_X64_MSR_GUEST_OS_ID` (`0x4000_0000`), replacing any value
the firmware left, then
enables the hypercall page (TLFS `hypercall-interface.md`): the 4 KiB
page-aligned `.hvcall` section in the kernel's text, mapped read-execute,
never mapped for user space and named by no capability. Hypercall
input lives in a page-aligned kernel BSS page, ordinary RAM as the TLFS
requires. `PostMessage` (code `0x005C`) builds its 256-byte block there:
connection ID, reserved zero, message type, payload size, 240 payload bytes
(`HvCallPostMessage.md`). `SignalEvent` (code `0x005D`) is a fast hypercall
with `rdx` = `connection | flag << 32` (`HvCallSignalEvent.md`). `arch/` calls
the page with `rcx` = input value, `rdx` = input address or fast input, `r8`
= 0, declares `rax`, `rcx`, `rdx` and `r8` clobbered, uses no XMM register,
and returns `rax` bits 0-15 to the caller in MR0 with label `NoError`.

### SynIC (M9)

Before untyped is made, the kernel takes two 4 KiB RAM frames from the boot
region ([Static kernel memory and the boot
region](#static-kernel-memory-and-the-boot-region)), zeroes them, records
their physical addresses, writes them into SIMP and SIEFP with the enable bit,
and sets SCONTROL, preserving each register's reserved bits as the TLFS asks
(`inter-partition-communication.md`). No untyped covers them, so revoke and
retype never reuse memory the hypervisor writes, as seL4 keeps root-server
objects outside every untyped (`rootserver_mem`, `src/kernel/boot.c`). The
root task gets a Frame capability (4 KiB, read-write, write-back) for each, in
slot 13 (SIM) and slot 14 (SIEF), and passes them to `vmbus`; deleting every
copy leaks 8 KiB and the pages stay enabled. After boot the kernel never reads
or writes them: `TCB_SetIPCBuffer` refuses either frame with
`InvalidCapability` ([Creation and
configuration](#creation-and-configuration)), and no other kernel path reads a
frame through a capability. SINTs stay masked until `GetSint(n)` writes SINTn =
vector, unmasked, AutoEOI off (the TLFS recommends against it: CPUID
`0x4000_0004` EAX bit 9), polling off, reserved bits preserved.

`vmbus` then works as FreeBSD's `vmbus.c` does on SINT 2: clear event flags
atomically, copy the message, set its type to 0, fence, then `Eom` if
`MessagePending` is set when read after the fence (TLFS `hv_message.md`;
`vmbus_msg_task`). Delivery throttles itself: one message slot per SINT, and
an event interrupt only on a clear-to-set change
(`inter-partition-communication.md`).

### The Hypervisor capability (M9)

No object stands behind it. Fields: `restricted`, and for a restricted
capability a 24-bit `connection` and the rights `post` and `signal`. The root
task's, in slot 12, is unrestricted. Hypervisor capabilities pass `derive`, so
copy and IPC transfer keep the fields. Mint with a non-zero data word
([Hypervisor](abi.md#hypervisor)) narrows an unrestricted capability to one
connection, never widens, and makes an original, as a new badge does, so
`vmbus` can revoke every copy it gave a channel driver. Mutate and Rotate with
non-zero data fail with `IllegalOperation`. Deleting the last one changes
nothing in the SynIC.

| Invocation | Unrestricted | Restricted |
| --- | --- | --- |
| `PostMessage(connection, type, size, payload)` | any connection | own connection, `post` |
| `SignalEvent(connection, flag)` | any connection | own connection, `signal` |
| `Eom()`, `VpIndex()` | yes | no |

`root` gives `vmbus` an unrestricted capability for channel management on the
VMBus message connection; `vmbus` mints for `netvsc` one restricted to
signalling its channel's connection ID from the offer, which FreeBSD's
`vmbus_chan.c` passes to `HvCallSignalEvent`. That separation needs a VMBus
version after WS2008, which sends every channel's events on connection 2
(`vmbus_chan.c`), and channel drivers that signal with `SignalEvent` rather
than the shared monitor pages; `vmbus` refuses older versions.

### Attack surface

| Attack | Defence | Milestone |
| --- | --- | --- |
| Another hypercall, or the hypervisor reading or writing a chosen guest address | Only codes `0x5C` and `0x5D`; the kernel builds the input value (no rep, no variable header) and the block in its own page; user space never supplies an address | M9 |
| A hypercall from ring 3 | The page is never mapped for user space; below CPL 0 a hypercall raises `#UD` (TLFS) | M9, M10 |
| A channel driver posting or signalling on another channel | Restricted capabilities checked in `core::hyperv`; mint never widens; `vmbus` revokes its narrowed originals | M9 |
| `vmbus` naming any guest page in a VMBus message (a GPADL, or `CONNECT`'s event-flag and monitor pages, FreeBSD `vmbus_reg.h`), which the host then reads and writes | Not defended: the message connection is as strong as DMA, and so is any restricted capability with `post` on it; accepted, recorded for M10 brief 8 | M10 |
| Making the kernel read or write a SynIC page, for example as an IPC buffer | Physical addresses recorded at boot; `TCB_SetIPCBuffer` refuses them; no other path reads a frame through a capability | M9 |
| Malformed SynIC messages | The kernel never reads the SIM or SIEF page; `vmbus` validates and is fuzzed against a mock host | M9, M10 |
| A SynIC interrupt flood | Self-throttling delivery; constant work per interrupt | M9 |
| Arguments that make the hypervisor fault | Connection below `2^24`, type 1 to `2^31 - 1`, size at most 240, flag below `2^16`; the rest is a status, not a fault | M9 |
| `vmbus` corrupting its SIM or SIEF page | Affects only VMBus delivery to `vmbus` | M9 |
| A hostile hypervisor | Out of scope (PLAN.md, M10 brief 8) | n/a |

`core/src/hyperv.rs` holds CPUID and privilege decoding and the table of
firmware leftovers, each with its MSR, enable bit and privilege (M3), and
from M9 the MSR values, hypercall input value, `PostMessage` block encoder,
capability data word, permission check and message decoding; `vmbus`'s mock-host tests
reuse the encoders. `arch/x86_64/hyperv.rs` does `rdmsr`, `wrmsr`, the
overlay reset and the hypercall `call`.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| No hypervisor overlay page covers untyped memory or any kernel object but its own page | overlay reset before memory reuse; a Locked hypercall page kept out of untyped and the boot region; SynIC frames outside every untyped; hypercall page in the image | M3, M4, M9 |
| On a user's behalf the hypervisor reads or writes only the kernel's input page and the two SynIC frames | two fixed hypercalls with kernel-built input; red-team brief 8 | M9, M10 |
| A restricted Hypervisor capability acts only on its own connection and rights; mint never widens | `core::hyperv` check, host tests; capabilities model test of Mint | M9 |
| User code can neither execute a hypercall nor touch a synthetic MSR | kernel-only hypercall page; `rdmsr`/`wrmsr` fault at CPL 3; red-team brief 8 | M9, M10 |
| The kernel never reads or writes the SIM or SIEF page after boot | recorded physical addresses; `TCB_SetIPCBuffer` refusal ([Creation and configuration](#creation-and-configuration)) and its host test; no other path reads a frame through a capability; red-team brief 8 | M9, M10 |
| The kernel touches a synthetic MSR only with its privilege bit | `core::hyperv` feature gate, host tests | M3, M9 |

### Compared with seL4

seL4 has no guest-side hypervisor interface; the rows compare reused patterns.

| seL4 | microL4 | Reason |
| --- | --- | --- |
| No hypercall or synthetic-MSR interface for the guest kernel | Hypervisor capability: two fixed hypercalls, EOM, VP index | VMBus needs them and they need CPL 0 |
| Interrupt sources become IRQHandlers through IRQControl (`src/object/interrupt.c`) | SINTs too, through `GetSint` | One delivery path, one driver loop |
| Root-server objects lie outside every untyped (`src/kernel/boot.c`) | The SynIC frames too | Hypervisor-written memory must never be retyped |
| Only device frames are refused as an IPC buffer (`checkValidIPCBuffer`, `src/arch/x86/kernel/vspace.c`) | The two SynIC frames are refused too | They are RAM the hypervisor writes at any time; the kernel must never touch them |
| Mint data narrows some capabilities per type (`Arch_updateCapData`, IOSpace) | Narrows a Hypervisor capability to one connection and makes an original | `vmbus` can delegate one channel and revoke it |

## Debug

Three debug system calls, kernel console output and every line of UART code
exist only in a kernel built with the `debug` Cargo feature; a kernel built
without it treats numbers 16 to 31 like any unknown number and touches COM1
only when a holder of an IOPort capability for it (`uart`) invokes it
([ADR 0021](adr/0021-debug-feature.md)).

### The `debug` feature

`kernel/Cargo.toml` has had `debug` and `selftest`, which implies `debug`,
since M4. From M5 `debug` gates the debug system calls, which only a `debug`
kernel decodes, and the TCB list they walk; until M7 every kernel was built
with it and printed. `selftest` gates every `test=` arm and all test-only
kernel code: `kernel/src/selftest.rs` and `kernel/src/rootimage.rs`, the trap,
paging, timer, NMI-stack, ring-3 and address-space tests and the tick, resume
and user-entry hooks in `arch`, the preemption-point statistics and injected
preemptions, `arch::kernel_memory` and the stack-use report after a panic.
From M5 a `test=` name the kernel does not know goes to the root task, which
reads it from BootInfo: the kernel prints `test=<name>: not a kernel
self-test; the root task runs it` and runs boot step 10; the root task
fails a name it does not know. A kernel without `selftest` knows no
test, so it passes every `test=` to the root task, saying it has no
self-tests if it has `debug`. xtask builds two kernels (`compile::Kernel`):
the selftest kernel, with `--features selftest`, and from M7 the release
kernel, with `--no-default-features`, so neither `debug` nor `selftest`
([A release kernel without UART code](#a-release-kernel-without-uart-code)).
`test` and `build` build both; `image`, `run` and `gdb` build the one
`--kernel selftest` (the default) or `--kernel release` names; `acpidump`
builds the selftest kernel, since the Hyper-V check reads COM1. `cargo xtask
clippy` lints the kernel three times, so that every `cfg` compiles each way:
as the two kernels are built, and from M7 with `debug` alone
(`--no-default-features --features debug`), the one configuration with the
debug output but no self-tests. From M7,
only with `debug` does the kernel contain `arch/x86_64/serial.rs` (the only
file naming ports `0x3F8` to `0x3FF`), `kprintln!`'s writer, the panic
message, the boot summary, the report of a fault with no handler ([Missing
handlers and double faults](#missing-handlers-and-double-faults)), system
calls 16 to 18 and the TCB list they walk. Without it `kprintln!` expands to
`if false { let _ = format_args!(...); }`, which type-checks its arguments and
emits nothing, and a panic only exits with failure.

The boot summary, which scenarios match line by line, grows by milestone: M0's
lines (image, memory map, framebuffer, hypervisor, command line); from
M3 the CPUID features the kernel checks; the ACPI summary (the RSDP and its
revision, the table list, the MADT flags, I/O APICs and overrides, COM1's
route, the HPET and the ECAM ranges), which replaces M0's own RSDP line;
`IA32_PAT` as found and as written, and the kernel's tables; the Hyper-V
interface and the overlay MSRs found; `IA32_APIC_BASE` at handover and the
local APIC, PIC, I/O APIC and HPET as set up; the calibration windows and
rates and, when Hyper-V allows it, the APIC and TSC frequency MSRs beside
them; from M4 `cpu: physical address width 40 bits` (on QEMU) after the
timer's periodic line; then CR0, CR4 and EFER, `IA32_APIC_BASE`, and
`cpu: meltdown: vulnerable`, `not vulnerable` or `unknown`; from M4 the
BootInfo summary, in `bootinfo:` lines: the boot region, its size and the addresses of
the root CNode, the IPC buffer and BootInfo; the untyped count with the KiB of
RAM, the MiB of device memory and the `2^phys_addr_bits` bound (106 to 110
untyped on QEMU, with the loader's allocations); the framebuffer's range and
its device untyped, listed first, or `no framebuffer`, or a warning that it
gets no untyped and why; and one line per non-empty slot region with its
first and last slot and its size. From M5, right after the command line,
boot step 3 prints `entry: syscall_entry at <address>, IA32_STAR
0x13000800000000, IA32_FMASK 0x257fd5, EFER.SCE on, IA32_SYSENTER_CS 0` and
`fpu: XCR0 0x3 of <supported> supported, XSAVE area 576 bytes of the TCB's
1024`; after the BootInfo lines come `boot: root task: image <start>-<end>,
entry <entry>; TCB at <address>, PML4 at <address>, <p> PDPT, <d> PD, <t> PT,
<n> image frames` and `boot: .rootimage <start>-<end> unmapped from the kernel
window and reclaimed as RAM untyped`, and step 10 prints `boot: entering the
root task at <entry> in ring 3`. `DebugHalt` prints `dispatch: invocations
preempted and restarted: <n>` before its own line.

### Debug system calls

| Number | Name | In | Effect | Out |
| --- | --- | --- | --- | --- |
| 16 | `DebugPutChar` | `rdi` bits 0 to 7 | writes the byte to COM1, `\n` as `\r\n` | all registers preserved except `rcx`, `r11` |
| 17 | `DebugHalt` | `rdi`: status | prints `DEBUG HALT <status> from TCB <address>`, then `arch::exit`: status 0 is success, any other failure; under QEMU the run ends, elsewhere the machine halts | does not return |
| 18 | `DebugDumpScheduler` | none | prints one line per TCB, newest first: address, state, priority, `next_ip` or `fault_ip`, and whether current (`tcb <address>: <state>, priority <p>, at <address>`, and a `*` after the caller's) | as 16 |

They take no capability: in a debug kernel any thread may print, dump and
halt. Interrupts are off throughout, so one call's output is never split.
`l4core::syscall::handle_syscall` returns them as `Outcome::Debug` without
touching a register, and `kernel/src/dispatch.rs` performs them for the
current thread (`serial::put_byte` for `DebugPutChar`). `DebugDumpScheduler`
walks a list of every TCB whose two link words live in the TCB's debug-only
tail, as seL4 keeps `ksDebugTCBs`. The walk has no preemption point, so its
time grows with the number of TCBs, which any thread with untyped memory can
raise, and any thread can call it in a loop; accepted, as these calls exist
only in a debug kernel, which makes no timing promise (M5 review). Numbers 19 to 31 stay reserved; there is no
`DebugNameThread`. A user-space test ends a QEMU run with `libsys::exit(0)`
after printing `TEST PASS`: `DebugHalt(0)`, or, once the test has set an
`isa-debug-exit` port as `test=release` must, `IOPort_Out32(0xF4, 0x10)`
([`libsys`](#libsys)). In debug scenarios the kernel's writer and `uart`
share COM1: after `serial::init` the kernel only polls LSR and writes THR, so
they coexist, with lines possibly interleaved.

### A release kernel without UART code

The release kernel is the kernel crate built without features
(`--no-default-features`): neither `debug` nor `selftest`. Cargo links both
kernels to `target/x86_64-unknown-none/<profile>/kernel`, so xtask builds the
release kernel first and copies it to
`target/xtask/release-kernel/<profile>/kernel.elf`, leaving the selftest
kernel's file in place (`xtask/src/compile.rs`); Cargo keeps both builds, so
switching between them recompiles nothing. A scenario with `kernel: release`
boots it ([The harness](#the-harness)), and `cargo xtask image`, `run` and
`gdb` take `--kernel release`. It prints nothing, and a panic only exits with
failure.

M7's done-when is checked three ways. The `serial` module, `kprintln!`'s
writer and `debug::print` are `#[cfg(feature = "debug")]`, so release code
naming them does not compile. Before any scenario, `cargo xtask test`
disassembles the release kernel (`xtask/src/disasm.rs`, with `llvm-objdump`
from rustup's `llvm-tools`, which `tools/setup.sh` adds, else one on `PATH`)
and fails on any of seven things:

- a `call` or jump to one of `io.rs`'s functions from any function but the
  three that may make one (`disasm::IO_CALLERS`): the IOPort executor
  (`Objects`' `IoPorts::port_in` and `port_out`), `pic::init` and
  `arch::exit`, each found by the address range its symbol covers;
- a `call` or jump to the IOPort executor (`disasm::EXECUTOR`) from any
  function but `disasm::EXECUTOR_CALLERS`, exactly
  `l4core::ioport::invoke_port::<kernel::arch::x86_64::objects::Objects>`,
  the IOPort invocation for the kernel's own objects;
- an address inside `io.rs`'s functions or the executor's anywhere but as a
  direct call's or jump's target: in an instruction that loads, compares,
  pushes or stores it (a sign-extended 32-bit immediate or displacement,
  `movabs`, or the target objdump prints for a rip-relative operand), or as
  eight bytes anywhere in the kernel's data sections but `.rootimage`, the
  root task's ELF, which is where a function pointer or a vtable entry would
  sit;
- an `in` or `out`, string forms included, outside `io.rs`'s functions (the
  address ranges their symbols cover);
- an immediate in `0x3F8` to `0x3FF` moved into `dx`, `edx` or `rdx` (only a
  move into the port register counts, since `0x3FF` alone is also the IPC
  buffer's alignment mask);
- a `call` or jump to one of `io.rs`'s functions after the straight-line code
  before it moved such an immediate into `dil`, `di`, `edi` or `rdi`, their
  port argument: that is how a caller would name COM1, since the functions
  move the port into `dx` themselves;
- any symbol whose name contains `serial`.

It also fails if the listing has fewer than 1,000 instructions, no `io.rs`
function with an `in` and one with an `out`, no call to them from the three
callers, no call to the executor from `invoke_port`, or no data to scan, so a
listing it misreads cannot pass by finding nothing. So that each `in` and
`out` sits under an `io.rs` symbol, the six functions there (`inb`, `inw`,
`inl`, `outb`, `outw`, `outl`) are `#[inline(never)]` and take the port as
their first argument, which they move into `dx` themselves; so that each call
sits under a caller's symbol, the three callers and `invoke_port` are
`#[inline(never)]` too. A release kernel calls `io.rs` from
those three places only: the IOPort invocations, `pic::init` at boot (ports
`0x20`, `0x21`, `0xA0` and `0xA1`, when the MADT sets `PCAT_COMPAT`, as q35's
does) and `arch::exit` (`isa-debug-exit`, after a panic). The first three
rules hold whatever port UART code would compute: it needs `in` and `out`,
which only `io.rs` has, so it would have to reach `io.rs` from one of those
three functions, whose code a reviewer reads once, and the executor only
through the IOPort invocation, whose capability check it would have to pass.
The port rules are a second line; alone they missed a port read from memory
or computed from a base (the M7 red team's finding,
`docs/redteam/m7-disasm-computed-port.md`, whose listing is now a host test
that fails the call-site rule). The `release` scenario
([Scenarios](#scenarios)) boots that kernel: all output comes from `uart`, and
root ends the run through an IOPort capability for `isa-debug-exit` (`0xF4`)
made from IOPortControl, writing what `arch::exit` writes: `0x10` for success,
which QEMU turns into exit status 33, or `0x11` for failure (35). BootInfo
does not say whether the kernel has `debug`, so root learns it from the
scenario's `test=` name: that test makes no debug system call, since one would
raise `UnknownSyscall` in root, which has no fault handler, and stop it
silently until the 60-second limit. The test checks that fault itself, from
another thread whose fault endpoint root holds.

The executor cannot be called with a port of the caller's choosing in the
first place. `port_in` and `port_out` take an `l4core::ioport::PortAccess`,
the port and width `invoke_port` checked against the invoked capability's
range; its fields and its constructor are private to `l4core::ioport`, so
only `invoke_port` builds one, after those checks, and kernel code that calls
the executor with a port of its own, `unsafe` or not, does not compile (two
`compile_fail` doctests on `PortAccess` keep it so). Their SAFETY comments
rest on that token. The token proves only what `invoke_port` read through its
kernel's `load`, which is why the executor's caller rule names
`invoke_port::<Objects>` exactly: a kernel type of its own, whose `load`
returned a COM1 capability no slot holds, could otherwise run `invoke_port`
and pass the token on (the re-check of the M7 fix round found the executor's
callers unchecked: a writer calling `port_out` with COM1 passed; its listing
is the host test `a_writer_through_the_ioport_executor_fails_the_check`).

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A kernel built without `debug` contains no UART code and touches ports `0x3F8` to `0x3FF` only in IOPort invocations | `cfg(feature = "debug")` on `serial.rs`, `kprintln!`'s writer and `debug::print`, so release code naming them does not compile (every release build, and `cargo xtask clippy`'s release configuration); the IOPort executor's `PortAccess`, which only `l4core::ioport::invoke_port` builds, so kernel code outside `l4core` cannot call the executor with a port of its own (two `compile_fail` doctests); `cargo xtask test`'s disassembly check, `disasm::check` (`io.rs` called only from the IOPort executor, `pic::init` and `arch::exit`, the executor only from `invoke_port::<Objects>`, their addresses in no other instruction and in no data, no `in` or `out` outside `io.rs`'s functions, no `0x3F8` to `0x3FF` moved into `dx`, none passed as `io.rs`'s port argument, no `serial` symbol), whose host tests in `xtask/src/disasm.rs` run each rule on listings and an ELF that break it, the M7 red team's computed-port writer and the fix-round re-check's writer through the executor among them; the `release` and `release_fault` scenarios, whose `next:` puts the root task's first line right after the loader's last, so a release kernel that prints anything at boot fails, and whose `forbid:` lines catch a debug kernel's banner, BootInfo summary, `DEBUG HALT` and panic lines | M7 |
| Without `debug`, numbers 16 to 31 raise `UnknownSyscall` | `Syscall::from_number(_, false)`; host test `debug_numbers_need_a_debug_kernel`; the `release` scenario, whose root test (`user/root/src/release.rs`) has a probe thread make `DebugPutChar`, `DebugHalt`, `DebugDumpScheduler` and numbers 19 and 31, and takes each `UnknownSyscall` on endpoint D with the number in MR18 (`root::check::console`, host test `the_probes_faults_are_answered_two_bytes_on`) | M5, M7 |
| `DebugPutChar` and `DebugDumpScheduler` change no register a thread can rely on | `l4core::syscall` returns them without writing a register, and `dispatch` writes none; host test `debug_system_calls_go_back_to_the_kernel` | M5 |
| Debug system calls read no user memory and take no capability | `dispatch::debug_call` uses only `rdi`'s value and kernel state; review | M5 |
| The TCB size is the same with and without `debug` | the debug list's two link words live in the TCB's debug-only tail at offset 608 in every build; `l4core::tcb`'s compile-time layout asserts | M5 |
| A debug kernel's boot summary shows the CPU features, control registers and Meltdown status it booted with | summary lines; M3 scenarios match them, including a `-cpu qemu64` refusal through `qemu_args:` | M3 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| `DebugPutChar` and `DebugDumpScheduler` under `CONFIG_PRINTING`, `DebugHalt` under `CONFIG_DEBUG_BUILD`; the dump itself prints only with `CONFIG_DEBUG_BUILD` too (`syscall.xml`, `handleUnknownSyscall` in `src/api/syscall.c`) | one `debug` feature | one switch to test |
| Debug calls numbered after the API calls in `syscall.xml` and decoded on the unknown-syscall path (`slowpath`, `src/arch/x86/c_traps.c`) | fixed numbers 16 to 18, decoded with the others by `Syscall::from_number` | [ADR 0022](adr/0022-abi-v0-numbering.md); one decoder |
| `DebugHalt` takes no argument and halts (`handleUnknownSyscall`) | takes a status and exits through `isa-debug-exit` | scenarios need a pass or fail exit status |
| Dump prints thread names (`debug_printTCB`, `include/api/debug.h`) | address, no name | no `DebugNameThread` in v0; 19 to 31 reserved |
| `DebugCapIdentify`, `DebugSnapshot`, `DebugNameThread`, benchmark calls | none | not needed for the plan; numbers reserved |

## User-level drivers and console

From M7 COM1 belongs to user space. `uart` drives the 16550 through an
IOPort capability and the IRQHandler of ISA IRQ 4; `console` multiplexes
clients onto it, keeps each client's lines whole and edits input lines;
`root` builds both and gives each only the capabilities listed below. In a
kernel built without `debug` they are the only path to COM1 ([A release
kernel without UART code](#a-release-kernel-without-uart-code)). Both are
threads of the root image, each in a CSpace and a VSpace of its own. Their
logic is plain code in host-tested crates; the QEMU scenarios check only
what needs the machine: the device, the interrupt path, separate address
spaces and the harness's input. This section is about user space: the
kernel side is in [Interrupts](#interrupts), [I/O ports](#io-ports) and
[Debug](#debug), and the protocols below are not part of `docs/abi.md`.

### Where the servers run

`uart` and `console` are threads of the root image, as every server is
([Root-task image and address space](#root-task-image-and-address-space)):
one ELF to build, embed and check, and no ELF loader in `root`. They do not
share root's VSpace, as the M5 and M6 test threads do: `root` builds a VSpace
for each from its own image frames, so a server writes only its own memory,
and a fault stops only that server and reaches root's `watch`. Clients in
`test=console` are test code and run in root's VSpace, each with a CSpace of
its own.

| Range in a server's VSpace | Frames | Mapping |
| --- | --- | --- |
| text | copies of root's image frame capabilities, with Read only | RX |
| read-only data (`.rodata`, `.eh_frame`) | the same | R, NX |
| `.data` and `.bss` | fresh frames, each a copy of root's page as it stands at spawn | RW, NX |
| `.thread_stack.0` to `.5` | none | unmapped |
| `.libsys_stack`, 64 KiB | fresh zeroed frames, the server's stack; the guard page below stays unmapped | RW, NX |
| `user_image_end`, one page | a fresh frame, the server's IPC buffer | RW, NX |
| BootInfo's two pages | none | unmapped |

The paging structures are those root's own image range needs (one PDPT, PD
and PT with M6's image and with M7's). root fills each fresh data frame through a scratch
mapping in its own VSpace (a free page under its image's page table, as
`test=tlb` maps one), unmaps it there, then maps it in the server; a frame
capability maps once. The IPC buffer sits at root's address, so the
pointer libsys's `_start` recorded in root's data, which the copy carries,
names the server's own buffer, and `Ipc::root()` works unchanged. Every other
static starts as root's value at spawn: server code keeps its state in locals
of its entry function and relies on no static root may have written. A server
gets no arguments; its slots are fixed (below). `user/link.ld` exports the
segment bounds (`__rodata_start`, `__data_start`, `__data_end`,
`__libsys_stack_start`), from which, with the thread stacks' addresses,
`root::process::Plan`, host-tested, gives each image page its role and its
frame capability's slot: BootInfo's `user_image_frames` has one frame per
page a segment covers, in address order. A server costs one root slot per
text, read-only and data page, 17 for its stack and buffer, four paging
structures, its TCB and its CNode (`Plan::slots`): with M7's image of 118
frames (57 text, 20 read-only and 1 data page in the dev profile), 101 of the
root CNode's 4,096, which `test=console` prints, and about 107 KiB of RAM
(18 fresh frames, four 8 KiB paging structures, a 2 KiB TCB and a 512-byte
CNode).

#### Capabilities

uart receives on endpoint U and is bound to notification NU, which IRQ 4
signals; console receives on endpoint C and is bound to notification NC,
which uart signals; root receives client reports on endpoint D; root's
thread `watch` receives the servers' faults on endpoint F
([Failures](#failures)). Each server's CNode has 16 slots, with guard 0 of
size 60 applied through `TCB_Configure`, so its CPtr `n` is slot `n`; slot 1
holds the CNode with the same guard, so `CNode_SaveCaller` on slot 1 names
slot `n` with `index` `n` and `depth` 64, as root names its own slots. The
slot numbers are constants of the server's crate (`uart::slot`,
`console::slot`), which `root` fills from.

| `uart` slot | Capability | Rights, badge |
| --- | --- | --- |
| 1 | its own CNode, guard 0 of size 60 | for `CNode_SaveCaller` |
| 2 | endpoint U, uart's requests | Read |
| 3 | IOPort `0x3F8`-`0x3FF`, a copy of root's | |
| 4 | IRQHandler of ISA IRQ 4, a copy of root's, already bound to notification NU | |
| 5 | console's notification NC | Write, badge `RX_READY` (bit 32) |
| 6 | endpoint F, its fault endpoint | Write, GrantReply, badge `UART` (1, `root::process::fault_badge`) |
| 7 | empty: a held request's reply capability | |

| `console` slot | Capability | Rights, badge |
| --- | --- | --- |
| 1 | its own CNode, guard 0 of size 60 | for `CNode_SaveCaller` |
| 2 | endpoint C, console's requests | Read |
| 3 | endpoint U | Write, GrantReply, badge 1 (the writer) |
| 4 | endpoint F, its fault endpoint | Write, GrantReply, badge `CONSOLE` (2) |
| 5 | from M8, notification NT, term's ([Framebuffer, terminal and TUI](#framebuffer-terminal-and-tui)) | Write, badge `KEYS` (bit 32) |
| 8 to 15 | empty: client `b`'s saved Read reply goes in slot 7 + `b` | |

A client holds endpoint C with Write and GrantReply and a badge from 1 to 8,
which is its client number. No server holds a TCB, VSpace, untyped or paging
capability, so none can change its priority, map memory or make objects; no
capability carries Grant, so none can pass capabilities on. `uart` holds no
capability to console's endpoint: it never sends to console and so can never
block on it. It signals NC with `RX_READY` when input arrives, and console
fetches the bytes with a `Call`.

`root` binds before it hands over, so neither server holds a notification
with Read and neither can bind or rebind itself: `IRQControl_GetISA(4)` into
its own CNode, whose flags must say edge and active high (root fails the test
otherwise, since uart's loop is right only for an edge pin: [The
loop](#the-loop)), `IRQHandler_SetNotification` with a capability to NU
badged `IRQ` (bit 32), `TCB_BindNotification` of uart to NU and of console to
NC, then copies of the handler and the COM1 IOPort into uart's CNode. uart
could still point its handler at NC, the one notification it can signal; that
harms only the service it provides.

| `root` keeps | Why |
| --- | --- |
| IRQControl and IOPortControl | later servers: M8's need neither, M9's drivers will |
| the original IRQHandler and COM1 IOPort | revoking one takes uart's copy back; `watch` writes a failure line through the IOPort |
| the original of every object it retyped for a server | revoking stops the server and reclaims its memory |
| endpoint C's original, and a client capability with badge 1 | root is console's client 1 |
| endpoint U with badge 2 | `Stats` only |
| endpoint D | client reports, and the faults of clients (badged with their client numbers, 2 and 3 in `test=console`) and of `test=release`'s probe (badge 9) |
| endpoint F and the thread `watch` | the servers' faults ([Failures](#failures)) |
| in `test=release` under QEMU, IOPort `0xF4`-`0xF7` | `isa-debug-exit`, to end a run in any kernel |

#### Server priorities

| Thread | Priority | Why |
| --- | --- | --- |
| `root` | 255 | builds everything, then only blocks: on D, or in a call to console or uart |
| `watch` | 255 | blocks only on F; it must run even while root waits in a call to a server that has faulted |
| `uart` | 200 | above everything it serves, so a receive or THRE interrupt preempts console and clients at once |
| `console` | 150 | above its clients, as [Priorities](#priorities) asks of every server |
| `term` (M8) | 125 | above its client `tui`, below console, whose client it is |
| clients, and `tui` (M8) | 100 | |

Each MCP equals its thread's priority. `root` at 255 is a console client
above console, the inversion [Priorities](#priorities) warns of; only uart
runs between them, briefly, so root's calls are not held up.

### `uart`

#### Setup

Offsets are from `0x3F8`. Every access is an `IOPort_In8` or `IOPort_Out8`
on slot 3.

| Step | Access | Why |
| --- | --- | --- |
| 1 | LCR (3) = `0x03`; IER (1) = 0 | DLAB clear, so offset 1 is IER whatever LCR held; no interrupt during setup |
| 2 | read LSR (5) until TEMT, at most 10,000 times | bytes the loader, a debug kernel or root wrote leave before the FIFO reset; one a debug kernel writes between this step and step 4 is still dropped, so tests print nothing while uart starts |
| 3 | LCR (3) = `0x80`; DLL (0) = 1; DLM (1) = 0; LCR = `0x03` | 115,200 baud, 8 data bits, no parity, 1 stop bit: the setting of the kernel's writer and of OVMF |
| 4 | FCR (2) = `0x87` | FIFOs on and cleared, receive trigger at 8 bytes, as Linux's 8250 driver sets a 16550A (from memory) |
| 5 | read IIR (2) | bits 6 and 7 both set: working FIFOs, burst 15; otherwise a 16450 or a 16550 with broken FIFOs: FCR = 0, burst 1 |
| 6 | MCR (4) = `0x0B` | DTR, RTS and OUT2, which gates the interrupt line on a PC (QEMU's model does not gate it, from memory); the kernel's writer leaves OUT2 off |
| 7 | read LSR and MSR (6) | clears latched errors and modem deltas |
| 8 | IER = `0x05` | received data (with the character timeout) and line status; THRE only while needed; modem status never |
| 9 | `IRQHandler_Ack`, then the service routine | an interrupt between issue and binding signalled nothing ([IRQControl and IRQHandler](#irqcontrol-and-irqhandler)) |

#### The loop

uart is bound to NU and receives on U with `Recv`, and with `ReplyRecv` after
a request it answers at once. A receive is a signal when `rsi` is 0 and `rdi`
has `IRQ` (`libsys::Event::classify` with bits 32 and up). A signal runs
`IRQHandler_Ack`, then the service routine: wait, Ack, service, the order of
setup's step 9, and not the wait, service, Ack that
[IRQHandler](abi.md#irqhandler) describes, which suits a level pin and loses
interrupts on an edge pin (below). A message runs one request. uart sends
only to reply capabilities and signals only NC, so it blocks nowhere but in
its receive.

The service routine reads IIR until bit 0 says no interrupt is pending and
handles each cause in the 16550's priority order. A read whose cause moves no
byte (a line status, THRE with the queue empty, a data cause with LSR.DR
clear) counts toward a limit of 64 a routine; the reads that move bytes are
bounded by the queue and the ring, since a full ring clears IER's data bit
and an empty queue clears IER.THRI.

| IIR bits 1 to 3 | Cause | uart | Cleared by |
| --- | --- | --- | --- |
| `0x6` | line status | read LSR; count OE as an overrun and PE, FE and BI as line errors; the byte stays in the FIFO and is read as data | the LSR read |
| `0x4`, `0xC` | data at the trigger, or the character timeout | move bytes from RBR to the receive ring while LSR.DR is set; if the ring fills, clear IER's data bit and stop | reading RBR |
| `0x2` | THRE: the transmit FIFO is empty | if the queue is empty, release a held Drain and clear IER.THRI; else write one burst, then release a held Write that now fits | the IIR read, or the THR writes |
| `0x0` | modem status, never enabled | read MSR | the MSR read |

If the routine moved any byte into the ring, it signals NC once.

**Lost interrupts.** Draining until IIR is clear leaves the line low, so the
next cause makes a new edge. The kernel masks an edge pin on the second
delivery since the last Ack ([IRQControl and
IRQHandler](#irqcontrol-and-irqhandler)), and an I/O APIC may drop an edge
while the pin is masked; QEMU 8.2's does (`test=irq`; from memory,
`ioapic_set_irq` in `hw/intc/ioapic.c` cites the 82093AA). With the Ack first, every delivery
since the Ack came after the receive that woke uart, so if one masked the pin
its signal is still pending: a cause that arrives after the routine's last
IIR read either finds the pin open and makes an edge, or finds a signal
waiting, and uart's next receive returns at once and services it. Servicing
before the Ack would lose it: two deliveries while uart handles a request (its
own accesses can lower the line, and so can a debug kernel's THR write) mask
the pin, and their signals merge into the one the next receive returns; a
cause after that routine's last IIR read then loses its edge and finds no
signal, and the line, held high by the cause, makes no new edge, so input, or
a held Write and console with it, waits for good. The price is spurious
signals: uart's own accesses raise the line again within a routine, and QEMU
takes every raise of its line as a new edge (from memory), so a signal often
finds IIR clear at its first read. As insurance against a device that loses a
THRE interrupt anyway, every Write and Drain first reads LSR and, if THRE is
set and bytes wait, writes a burst; every Read first moves what LSR.DR shows
into the ring. The limit of 64 keeps a device whose IIR never clears from
holding uart forever: uart then counts it (`Stats` MR7) and receives again;
on hardware its line stays high and makes no new edge, so the device is
served again only when a request touches it: that is a broken device. QEMU
transmits a burst as it is written and so reports THRE again after each one
(from memory: `serial_xmit`); one routine then empties the queue, up to 137
bursts, none of which counts toward the limit.

**Overruns.** An overrun loses bytes; uart counts it (`Stats`) and goes on.
While the receive ring is full, the data bit stays clear and the 16550 keeps
what it has. QEMU then takes no more bytes from its character device, since
its receive path never takes more bytes than the FIFO has room for (from
memory: `serial_can_receive`, `hw/char/serial.c`, which offers at most the
trigger level), so input is never lost on QEMU; on
hardware the FIFO overruns and LSR.OE counts it. A Read that frees ring space
sets the data bit again, and the 16550 raises its data or timeout interrupt
for what it held.

#### Transmit and receive

| Item | Rule |
| --- | --- |
| Transmit queue | 2,048-byte ring, at least twice the largest Write |
| Burst | 15 bytes into the 16-byte FIFO, 1 without FIFOs; the 16th place is for a debug kernel's byte (below), so only a 16550 with working FIFOs shares safely with a debug kernel |
| IER.THRI | set exactly while the queue holds bytes or a Drain is held, so an idle uart takes no THRE interrupts |
| Write of `n` bytes | if the queue has room for all `n`, they are queued, uart writes a burst if LSR.THRE is set, and replies `n` at once; otherwise uart moves the caller's reply capability into slot 7 (`CNode_SaveCaller`), keeps the bytes, and replies through slot 7 once THRE bursts have made room for all of them. Back-pressure is a late reply |
| Held requests | one at a time: a Write or Drain while one is held, found by `CNode_SaveCaller`'s `DeleteFirst`, gets `Busy`. console, single-threaded and the only writer, never sees it |
| Longest hold | until 952 bytes have drained: about 83 ms at 115,200 baud |
| Drain | answered once the queue is empty and LSR.THRE is set: at once, or at the THRE interrupt that finds the queue empty. The last byte may still be in the shift register, at most 87 µs; QEMU transmits a byte as it is written (from memory: `serial_xmit`), so a run ended then loses nothing |
| Receive ring | 256 bytes; Read returns all it holds, possibly nothing, and uart signals NC again for anything that arrives later, so console reads once per signal |

#### Sharing COM1 with a debug kernel

A debug kernel's writer polls LSR until THRE and writes THR, with a bounded
wait, and after its `serial::init` at boot touches no other register
([Ports the kernel uses](#ports-the-kernel-uses)). uart and the writer then
coexist:

- A kernel byte can fall between any two of uart's, so output interleaves at
  byte granularity; console's whole-line guarantee covers its own output
  only. Tests on a debug kernel print through console alone while console
  runs, and the kernel prints nothing then unless a test fails.
- The writer writes only when THRE says the FIFO is empty, so when uart
  bursts after seeing THRE the FIFO holds at most one byte the writer added
  since; 15 bytes then never overflow it, even if uart is preempted
  mid-burst. Without FIFOs (a 16450, or FIFOs that do not work) the holding
  register has no spare place: a kernel byte written between uart's look at
  THRE and its own write is replaced, so a byte can be lost (the `uart` host
  tests give a kernel writer only to a device with FIFOs). QEMU's 16550 has
  them; Hyper-V's is an M8 check ([Open questions](#open-questions)).
- A kernel write to THR clears a pending THRE condition; the next THRE comes
  when that byte has drained, and uart refills then.
- The writer's LSR reads clear LSR's error bits, so uart may miss overruns
  and line errors in a debug kernel; its counts are exact only in a release
  kernel.

#### The uart protocol

Byte strings, labels and errors are as for console ([Protocols](#protocols)).

| Label | Request | Words | Reply | Errors |
| --- | --- | --- | --- | --- |
| `0x110` | `Write` | a byte string of at most 952 bytes | MR0 `n`, once all `n` bytes are queued | `BadLength`, `Busy` |
| `0x111` | `Read` | none | a byte string: everything the receive ring held | |
| `0x112` | `Drain` | none | nothing, once the queue and the FIFO are empty | `Busy` |
| `0x113` | `Stats` | none | MR0 signals handled, MR1 bytes received, MR2 bytes sent, MR3 bursts written for a THRE cause in the service routine (not those a request wrote), MR4 overruns, MR5 line errors, MR6 Writes held, MR7 service routines cut short by the limit of 64; from M8 MR8 the burst, 15 with working FIFOs and 1 without | |

`Write`, `Read` and `Drain` need badge 1, console's; any other badge gets
`BadBadge`. `Stats` takes any badge.

### `console`

console is bound to NC and receives on C. A signal with `RX_READY` makes it
call uart's `Read` once and feed each byte to its terminal state; a message is
one client request. Each event's output goes to uart in `Write`s of at most
952 bytes, one after another; console does nothing else in between, so they
stay contiguous on the wire. console never waits for a client: a `Read` it
cannot answer yet is saved with `CNode_SaveCaller` into slot 7 + `b` and
answered later with `Send` on that slot ([Reply
capabilities](#reply-capabilities): a receive would delete it in the caller
slot). It blocks only in calls to uart, which always reply; while it does,
NC's signals stay pending and clients queue on C.

#### Protocols

A byte string travels as MR0 = its length `n` and MR1 to MR⌈`n`/8⌉ = its
bytes, eight per word, little-endian: byte `i` is bits 8(`i` mod 8) to
8(`i` mod 8) + 7 of MR(1 + ⌊`i`/8⌋). `length` is 1 + ⌈`n`/8⌉, at most 120, so
`n` is at most 952. Up to 24 bytes travel in registers; more need IPC buffers
on both sides. A server answers `BadLength` when `n` is over its limit or
`length` does not match `n`, and ignores the unused bytes of the last word.
It checks the label, then the badge, then the length, then whether it can
hold the request; a request that takes no words ignores any sent, whatever
their `length`. A request is never accepted in part: all `n` bytes or an
error. `libsys` splits longer writes.

A reply's label is 0 on success. Errors have `length` 0:

| Label | Error | When |
| --- | --- | --- |
| `0x101` | `BadLabel` | a label the server does not know, including a reserved one |
| `0x102` | `BadLength` | as above |
| `0x103` | `Busy` | the server already holds the one request of this kind it can: uart's held `Write` or `Drain`, or console's saved `Read` for this badge |
| `0x104` | `BadBadge` | a badge outside the requests' range |

Request labels are above every kernel invocation label (`0x01` to `0x8F`),
so a request sent on a kernel object's capability gets `IllegalOperation`
from the kernel, never a kernel operation (on a notification it is only a
signal, and on the other server's endpoint `BadLabel`); every request label
is non-zero, so a request's `rsi` is never 0 and never looks like a signal to
`Event::classify`; error labels are above the kernel's error
codes (1 to 10), so a client tells a server's refusal from the kernel's, such
as `InvalidCapability` for a capability without Write.

| Label | Request | Words | Reply | Errors |
| --- | --- | --- | --- | --- |
| `0x120` | `Attach` | a byte string of at most 16 bytes: the client's name | MR0 its client number | `BadLength` |
| `0x121` | `Write` | a byte string of at most 952 bytes | MR0 `n`, once every line it completed is in uart's queue | `BadLength` |
| `0x122` | `Flush` | none | nothing, once the client's unfinished line is in uart's queue | |
| `0x123` | `Read` | none | a byte string of at most 255 bytes: the next line typed while this client had focus, without its terminator | `Busy` |
| `0x124` | `Sync` | none | nothing, once everything console has emitted has left the UART: `Flush`, then uart's `Drain` | |
| `0x125` | `ReadRaw`, from M8: client 4's raw input ([Input and the term protocol](#input-and-the-term-protocol)) | none | a byte string: everything in client 4's raw queue, possibly nothing, at once | `BadBadge` for any badge but 4 |

Every request needs a badge from 1 to 8, else `BadBadge`; from M8 so does
client 4's `Read`, and any other client's `ReadRaw`. A client exists from
its first request and needs no `Attach`; `Attach` only names it in status
lines. A saved `Read` reply vanishes if its client is suspended or deleted
(`libsys::invoke::cnode_save_caller`), leaving slot 7 + `b` empty. console
cannot tell: its `Send` on the empty slot does nothing, so a line typed for
the client meanwhile is lost; the client's next `Read` saves into the slot as
usual, so the slot, not a flag of console's, decides `Busy`.

Neither protocol is in `docs/abi.md`, which is the kernel's and the loader's
contract: the kernel sees only messages with user labels. Both are defined
once, in `libsys::proto`, and described here; both ends are built into one
root image, so a change needs this note and `libsys` changed together, and no
ADR.

#### Output

Each client has an unfinished output line of up to 512 bytes, which console
holds until the client ends it with `\n`, flushes it, reads, or fills it. The
terminal's current line has an owner:

| Owner | Meaning |
| --- | --- |
| none | the cursor is at the start of a line |
| output of `c` | `c`'s unfinished line, flushed or over-long, is the last thing on the terminal |
| input of `c` | `c`'s input line, its prompt and its edit buffer, is the last thing on the terminal |

A *break* is `\r\n`, sent only when the owner is neither none nor output of
the event's client. *Showing* `f`'s input line is `\r\n` unless the owner is
none, then `f`'s prompt and edit buffer. *Restoring* is showing the focused
client's input line when the owner is none and it has one: a `Read` pending,
or typed bytes.

| Event | console sends, in order | Owner after |
| --- | --- | --- |
| A `Write` by `c` completes one or more lines (its held bytes, then the new ones, up to the last `\n`) | a break; the lines, each `\n` as `\r\n`; then restoring | none, or input of the focused client |
| `c`'s held bytes reach 512 with no `\n` | a break; the 512 bytes | output of `c` |
| `Flush` by `c` with held bytes | the same, with the held bytes | output of `c` |
| `Read` by `c` with a typed line waiting | as `Flush`; the line is the reply, at once | |
| `Read` by `c` with none | `c`'s held bytes become its prompt; if `c` has focus, showing its input line | input of `c`, if focused |
| A printable byte, BS, DEL or Ctrl-U typed for the focused client `f` | showing `f`'s input line, unless the owner is input of `f`; then the byte's echo ([Input](#input)) | input of `f` |
| Enter (CR, or LF not after CR) | as a printable byte; the line answers `f`'s saved `Read`, which clears `f`'s prompt, or joins `f`'s waiting lines | none |
| Ctrl-T and a digit `n` | `\r\n` unless the owner is none; the status line `[console] focus n (name)`, or `client n` before it has attached, in reverse video (`ESC [7m` before it, `ESC [0m` after), and `\r\n`; then restoring | none, or input of `n` |
| Any other typed byte: Ctrl-T itself and a non-digit after it, an LF after CR, ESC and what it skips, a dropped byte | nothing; the input line is not redrawn | unchanged |

So a line of at most 512 bytes that its client does not flush midway reaches
the wire whole, with no other byte inside it (a debug kernel's aside),
whatever the client's write boundaries: the clients' output interleaves line
by line. Only a longer line can be broken, into 512-byte pieces. Echo,
breaks, redrawn input lines and status lines go only to the terminal, never
to a client. A prompt is what the client wrote since its last newline and had
not flushed; a client writes its prompt and reads, with no `Flush` between.
The prompt is shown again with every redraw of the client's input line until
its `Read` is answered, and then cleared.

A client's bytes reach the terminal shown, not obeyed (`console::shown`, the
M7 red team's finding 1, `docs/redteam/m7-console-escapes.md`): printable
ASCII (`0x20`-`0x7E`) and tab as they are; the C0 controls and DEL in caret
notation, `^[` for ESC, `^M` for CR, `^H` for BS, `^?` for DEL; and every byte
from `0x80` up, the C1 controls among them, as `\xNN`. That holds for its
output, its prompt and its `Attach` name in a status line; the `\r\n` that
ends each of its lines is console's own. Sent as they were, a client's ESC and
CSI sequences would move a VT100 terminal's cursor up into other lines, erase
console's focus status line and forge one. M8's raw mode (label `0x125`) is
about input only ([Input and the term
protocol](#input-and-the-term-protocol)): console shows its raw client's
output as every client's, and `term`'s escape sequences go to the
framebuffer, never to COM1. A client can still print text that reads like a
status line, but only on a line of its own, below the real one, and in plain
text: console's own status lines are in reverse video (`console::STATUS_ON`
and `STATUS_OFF`), which a client, whose ESC shows as `^[`, cannot ask for.

#### Input

| Byte | Effect on the focused client's edit buffer | Echo |
| --- | --- | --- |
| `0x20` to `0x7E` | appended, if it holds fewer than 255 bytes | the byte; BEL (`0x07`) if full |
| `0x08` (BS), `0x7F` (DEL) | the last byte removed | `\b \b`, nothing if empty |
| `0x15` (Ctrl-U) | emptied | `\b \b` per byte removed |
| `0x0D` (CR) | Enter: the buffer becomes a line | `\r\n` |
| `0x0A` (LF) | Enter, unless it follows CR, when it is dropped | `\r\n` |
| `0x14` (Ctrl-T) | the next byte, `1` to `8`, focuses that client; any other drops both | the status line |
| `0x1B` (ESC) | skipped with what follows: `[`, parameters and a final byte in `0x40`-`0x7E`, or one byte | none |
| anything else | dropped | none |

Focus starts on client 1. Ctrl-T and a digit focuses that client whether or
not it has attached or is reading. Each client has its own prompt, edit
buffer and waiting lines (up to 512 bytes of complete lines, each counted
with its terminator), so switching
focus leaves a half-typed line where it was; Enter with no room for the line
rings BEL and leaves it in the edit buffer. Each byte goes to the client
focused when console reads it, whether or not that client is reading yet:
routing is a function of the byte stream alone, so a test that sends the focus
key before its text routes deterministically however its input races the
clients. A focus key rather than a per-line prefix also works for raw
keystrokes, which M8's `term` needs. Ctrl-T because QEMU's `-nographic`
multiplexer, which `cargo xtask run` uses, takes Ctrl-A, and Ctrl-T has no
role in a line editor; Ctrl-T Ctrl-T is how M8's raw mode passes a literal
Ctrl-T ([Input and the term protocol](#input-and-the-term-protocol)).

#### Back-pressure

| Direction | Where bytes wait | When full |
| --- | --- | --- |
| Output | the client's unfinished line in console (512 bytes); uart's queue (2,048) | console replies to a `Write` only after uart has queued its complete lines, and uart holds console's `Write` while its queue is full, so a client that writes faster than the line waits in its call, and the clients behind it wait on C |
| Input | the client's waiting lines (512); uart's ring (256); the 16550's FIFO (16); under QEMU, the host's pipe | Enter rings BEL; uart stops reading the FIFO; the FIFO overruns on hardware, and QEMU waits |

### `libsys`

| Part | What |
| --- | --- |
| `libsys::proto` | the byte-string encoding, the request labels of both protocols, the error labels, `MAX_BYTES` = 952 |
| `libsys::console::Client` | a client capability: `attach`, `write` (split into messages of at most 952 bytes), `flush`, `read_line`, `sync`, and `core::fmt::Write` |
| `libsys::uart::Client` | console's side of uart: `write`, `read`, `drain`, `stats` |
| `libsys::CallError` | why either client's request failed: the server's refusal, the kernel's error, or a reply that is neither |
| `libsys::output` | where `print!` and `println!` go: `DebugPutChar`, the default, or a console client capability (`use_console`, `use_debug`); `set_exit_port` names an IOPort for `isa-debug-exit`; `reset` restores both defaults; `exit(status)` syncs the console if `print!` goes there, then writes `0x10` (status 0) or `0x11` to that port with `IOPort_Out32` if one is set, and stops, else calls `DebugHalt(status)`; `exit_now` is the same without the `Sync`, for a panic while printing |
| `libsys::device` | the IRQControl, IRQHandler, IOPortControl and IOPort invocations ([Where the code lives](#where-the-code-lives-3)) |
| `libsys::vspace`, `libsys::image` | `Frame_Map`, `Frame_Unmap` and the paging structures' `Map`, and the segment bounds `user/link.ld` exports, for building a server's VSpace |
| `libsys::output::Polled` | a `core::fmt::Write` on a COM1 IOPort capability that bypasses uart, for [Failures](#failures): before each byte it polls LSR until THRE, at most 100,000 times as the kernel's writer does, then writes THR (`\n` as `\r\n`); after the text it polls for TEMT within the same bound; it touches no other register |

The panic handler and root's `fail!` end with `libsys::exit(1)`, so a test
that has set an exit port fails at once on a release kernel, where
`DebugHalt` would be an `UnknownSyscall` fault with no handler; without one,
everything behaves as before. A server's `DebugHalt` or `DebugPutChar` in a
release kernel, its panic message included, faults to `watch`, which ends the
run with failure. The output and the exit port are statics of a VSpace, and a
CPtr names a slot of one CSpace, so:

- `root` spawns the servers before it points its own output at console, and
  each server's entry calls `output::reset`, which sets its output to
  `DebugPutChar` and drops the exit port its copy of root's data may name (a
  server printing through console would call itself);
- `watch` shares root's VSpace, whose `print!` names console once root has
  switched, so it never uses `print!`, only `Polled`;
- threads in root's VSpace with CSpaces of their own, such as
  `test=console`'s clients, write through a `console::Client` of their own;
  `print!` there would use root's CPtr;
- in `test=release` root prints nothing until console is up, then its usual
  summary through console.

### Failures

root is console's client, so it cannot also be the servers' fault handler: a
server that faults while root waits in a call to it, or in a call to console
while console waits on uart, leaves its fault queued on an endpoint no thread
receives on, and `fail!`'s print and `exit`'s `Sync` would wait on the dead
server too, until the 60-second limit. So the servers' fault endpoint is F,
and a thread of root's, `watch`, does nothing but receive on it.

| Item | Rule |
| --- | --- |
| `watch` | root's VSpace and CSpace, a stack from `spawn::STACKS`, no IPC buffer (a fault then arrives as MR0 to MR3), no fault endpoint, priority and MCP 255; root starts it before either server, with the CPtrs of F, root's COM1 IOPort and the exit port (0 for none) as its arguments, so root issues the COM1 range, and `0xF4`-`0xF7` in `test=release`, before it starts `watch` |
| On a message | whatever its label: `TEST FAIL: <the server its badge names> fault <label>, MR0 to MR3 <words>` through `Polled` on root's COM1 IOPort, then the end of the run with failure: `IOPort_Out32(0xF4, 0x11)` if it has an exit port, else `DebugHalt(1)`; it never replies, so the server stays stopped |
| Its bytes | may fall between bytes uart had already written and a debug kernel's; uart, below watch, does not run while it writes, and `Polled` waits for THRE, so the FIFO cannot overflow |

Faults of clients and of `test=release`'s probe go to D, where root expects
them ([Scenarios](#scenarios)); root reports a client's fault through
console, which still answers. root's own `fail!` and panic still print through
console, and `exit(1)` still syncs: console answers a `Write` once the line is
in uart's queue, not on the wire, so without the `Sync` the end of the run
could overtake the failure line. That cannot hang on a faulted server: root
runs `fail!` only after console has answered its last call, and a server that
faults during the print or the `Sync` ends the run through `watch`. So a
failure is reported through console while both servers run, and through
`Polled` once one has faulted. Only these still end at the 60-second limit: a
server that stops answering without faulting, and, in a release kernel, a
fault of root or of `watch`, which have no handler and print nothing.

### The harness

Five new scenario directives and values in M7, and `screendump:` in M8
(`xtask/src/scenario.rs`); a scenario without them runs exactly as before.

| Directive | Meaning |
| --- | --- |
| `send: <text>` | writes `<text>` to QEMU's standard input, COM1's receive side, once every `expect:` above it has matched; consecutive `send:` lines go together, in order. Escapes: `\r`, `\n`, `\t`, `\e` (ESC), `\\` and `\xHH`; a `\` before anything else is an error. As for every value, the ends are trimmed and ` #` starts a comment, so a space or `#` there is `\x20` or `\x23`. A scenario's `send:` lines total at most 4 KiB once unescaped (a parse error otherwise), far below a pipe's 64 KiB, so the blocking write to QEMU's stdin never waits past the timeout on a guest that has stopped reading |
| `kernel: release` | boots the kernel built without features (no `debug`, no `selftest`), in the run's profile; `kernel: selftest` is the default |
| `forbid: <text>` | no line of the transcript may contain `<text>`; checked as each line arrives and reported when the run ends, naming the first such line |
| `next: <text>` | right after an `expect:` or another `next:` (a parse error otherwise): the serial line right after the one that step matched must start with `<text>`, so no line came between them; any other line there fails the scenario, naming it, and ends the boot at once, since nothing after it can match. `release` and `release_fault` put the root task's first line next after the loader's `entering kernel`, so a release kernel that prints anything at boot fails them, whatever it prints |
| `exit: timeout` | beside `success` and `failure`: the guest must still be running when the scenario's `timeout:`, which it then needs, ends the boot, with every `expect:` matched. For a kernel with no exit of its own; no scenario uses it now that `release` ends through `isa-debug-exit` |
| `screendump: <name>` | (M8) right after an `expect:` or `next:` (a parse error otherwise): once that step has matched, and before any later `send:` is written, xtask takes the screen through QEMU's QMP `screendump`, and when the boot has ended compares it pixel for pixel with `tests/qemu/golden/<name>.png`. QEMU connects to a loopback port xtask listens on (`-qmp tcp:127.0.0.1:<port>`), and such a scenario boots with `-parallel none`, so that a machine without a display device fails rather than giving the parallel port's text console. The screen stays beside `serial.log` as `<name>.png`; a mismatch fails the scenario, saying how many pixels differ and in what box, or that the sizes differ, and adds `<name>.diff.png`, the golden at a quarter of its brightness with each differing pixel magenta. `cargo xtask test <scenario> --bless` (only `test` takes `--bless`) writes a screen that differs, or has no golden, as the golden, but only in a run that passed everything else, and never over a golden whose `Source` text is `microL4 host render`: it leaves that one as it is and the scenario fails, saying the golden is the host's (host test `bless_leaves_a_host_render_golden_as_it_is`). Besides `--bless`, only xtask's host test `tui_screendumps_are_the_host_render` writes a golden, with `MICROL4_BLESS=1`: the `tui` scenario's, which the host draws ([The screendump goldens](#golden-tests)); nothing else writes one. A name is lowercase letters, digits, `-` and `_`, used by one scenario only, and every file in `tests/qemu/golden/` must be a screendump some scenario takes (host test `repo_goldens_are_used_and_read`). Goldens are PNG, palette-indexed at 256 colours or fewer, with QEMU's version as their `Source` text, or `microL4 host render` for the host's, which a mismatch names when it differs. The comparison is exact, with no tolerance or mask: the guest must keep the screen still from the line the screendump follows until it is taken, say by waiting for a `send:` after it, and so cannot blink a cursor. `screendump` takes q35's std VGA, which OVMF sets to 1280x800 from its EDID (`-vga std -global VGA.xres=640 -global VGA.yres=480` gives 640x480); OVMF's own text is drawn as its lines reach COM1, so a screendump before the loader runs can catch it part drawn |

**Timing.** A `send:` must have an `expect:` above it (a parse error
otherwise): until the guest's uart has started, OVMF reads COM1, where a key
can stop the boot in its boot manager, and uart's FIFO reset drops whatever
arrived. A guest line that the `expect:` before a `send:` names is printed
through uart, so uart is running when the text is written. Text is written
all at once: QEMU feeds the UART only as its FIFO has room, so nothing is
lost however fast it arrives. Each `send:` is logged in `serial.log` as an
`xtask: sent "<text>"` line at the point it was written, and each screendump
as `xtask: screendump "<name>"`; neither the matcher nor `forbid:` reads
those lines.

**Implementation.** The scenario becomes a list of steps (`expect`, `send`,
`next` and, from M8, `screendump`); the matcher, unchanged in what `expect:`
matches, returns the sends it reaches as it advances, takes a `next:` only
at the start of the line after its step's, and stays broken once one fails,
and the main loop writes them to QEMU's stdin, which is piped for scenarios
with a `send:` and stays `/dev/null` for the others. Matching stays
line-based: a prompt without a newline is never seen, so a test makes the line before each `send:` a whole
one and checks echo with host tests. xtask builds the release kernel beside
the selftest one and copies it out to
`target/xtask/release-kernel/<profile>/kernel.elf`, since a feature change
rebuilds in place ([A release kernel without UART
code](#a-release-kernel-without-uart-code)). `cargo xtask image`, `run` and
`gdb` boot the selftest kernel unless given `--kernel release`.

### Scenarios

**`console`** (`cmdline: test=console`, the selftest kernel). Root prints its
summary through `DebugPutChar`, starts `watch`, builds uart and console,
attaches as client 1 (`root`), points its output at console and starts
clients `a` (badge 2) and `b` (badge 3), and `r`, whose console capability
has root's badge, so that it reads as client 1 for root, each with an IPC
buffer in KiB 1, 2 or 3 of root's buffer frame (`spawn`), which attach and
report on D. A client asks
for its next step with a `Call` on D whose message reports on its last one,
with label `0x130`, above every fault type: MR0 the step it did (`u64::MAX`
for its first report, once it has attached), MR1 its status (0, or the error
that stopped it), and MR2 on the line it read, as a byte string
(`root::check::console::Report`); its fault endpoint is the same
capability, D with Write, GrantReply and its client number as badge, so root
tells a fault from a report by the label. Root answers one client at a time
and keeps the others' reply capabilities saved (`CNode_SaveCaller`), so every
write boundary is fixed, and root blocks only on D or in calls to console and
uart, never in a call to a client that may fault:

| Part | What the clients do | What the transcript shows |
| --- | --- | --- |
| Interleaved lines | `a` writes `a1 alpha `, `b` writes `b1 bravo `, `a` writes `one\n`, `b` writes `one\n`; `b` writes a 300-byte line, `b2` and filler, in three writes of 100 bytes (through the IPC buffer), with `a`'s whole line `a2 short` between them; `a` writes `a3 x\na4 y\na5 ` in one write, `b` writes `b3 z\n`, `a` writes `end\n` | `a1 alpha one`, `b1 bravo one`, `a2 short`, the 300-byte `b2` line, `a3 x`, `a4 y`, `b3 z`, `a5 end`, each whole and in that order |
| Burst | `b` writes twelve 200-byte lines back to back | `b burst 01` to `b burst 12`, whole. On hardware uart may hold some of console's writes; QEMU's transmitter empties at once, so its queue never fills and `Stats` shows 0 Writes held (MR6) |
| Input | `a` and `b` each write a prompt and `Read`; root answers both before it prints `console: input next`, then waits on D for both reports | see the steps below |
| Type-ahead | once uart's `Stats` show the harness's line received and root's `Sync` has made console take it, `a` writes a 35-byte prompt and `Read`s | `a`'s 37-byte line, waiting, answers the `Read` at once, after console has flushed the prompt; both pass MR3, so the reply and the flush's uart `Write` share the IPC buffer |
| Drain | `r` (for client 1), `a` and `b` each report that they have the step and, once root has all three reports and answers them, `Read` once more | nothing: console must save all three `Read`s, as nothing more was typed for any client (below) |
| Totals | root asks uart's `Stats` | signals and THRE bursts (MR0, MR3) above 0, exactly the 60 bytes the harness sent (22 for the input, 38 for the type-ahead line), 0 overruns and line errors |

```text
expect: console: input next
send: \x143to b\r                  # Ctrl-T 3: focus b
expect: [console] focus 3 (b)
expect: b: read "to b"
send: \x142hellp\x7fo\x15hi a\r    # Ctrl-T 2, a typo, DEL, Ctrl-U, the line
expect: [console] focus 2 (a)
expect: a: read "hi a"
```

Each client prints what it read and reports it to root, which checks that `a`
received exactly `hi a` and `b` exactly `to b` (`root::check::console`). Then
the type-ahead line, typed while `a` has no `Read`, waits for `a` and answers
its next `Read` at once. Last, the drain shows that nothing else reached any
client, root included: once every drain step's `Read` is made (root lets every
thread above priority 1 run until it blocks, `spawn::let_others_run`) and
console has taken all three (root's `Sync`, queued behind any it has not, is
answered) and every thread has blocked again, a `Read` console answered would
have its client's report waiting on D, so root's `NBRecv` on D must find
nothing (`check::drained`). Each client reports first that it has its drain
step, so a step that never reached a client hangs the test rather than passing
it. Root then prints `TEST PASS` through console, syncs and calls
`DebugHalt(0)`; the scenario ends with `DEBUG HALT 0 from TCB` and exit
success. The echoed lines (`b> to b`) are in the transcript but not expected,
since whether a prompt shows depends on whether the client's `Read` arrived
before its input; host tests pin echo exactly. Typed bytes reach console only
after uart's service routine, which alone signals `RX_READY`, has run for
them, so the input part shows receive interrupts at work; MR3 shows transmit
interrupts. `expect:` matches substrings, so wholeness rests on the pieces:
every piece of the interleaved lines is distinct, and a piece console put
inside another line would be missing from its own, whose `expect:` then fails.

**`release`** (`kernel: release`, `cmdline: test=release`). The loader prints
as always; the kernel prints nothing. Root issues the COM1 range, IRQ 4 and,
under QEMU (`BootInfo.hypervisor_vendor`), `0xF4`-`0xF7`, sets its exit port,
starts `watch`, builds uart and console, attaches as client 1, sets its
output, and prints through console:

- its usual summary (`root: microL4 root task`, the command line, the slot
  regions);
- a line saying a probe thread's `DebugPutChar`, `DebugHalt`,
  `DebugDumpScheduler` and reserved numbers 19 and 31 each raised
  `UnknownSyscall` with the number in MR18; root answers each fault with the
  probe's registers and `ip` + 2, so the probe goes on to the next;
- `release: type a line`, then, after `send: release input\r`, `release: read
  "release input"`, since focus starts on client 1;
- uart's `Stats` (signals and THRE bursts above 0, 14 bytes received, 0
  overruns), then `TEST PASS`.

Then `Sync`, and `IOPort_Out32(0xF4, 0x10)` ends the run. xtask expects those
lines in order and exit success, with `next: root: microL4 root task` right
after the loader's `entering kernel`, so no line may come between the two:
a release kernel that printed anything at boot fails, whatever it printed.
It also has `forbid: microL4 kernel`, `forbid: bootinfo:`, `forbid: DEBUG
HALT` and `forbid: KERNEL PANIC`, which a kernel with `debug` would print
later too. With `cargo xtask test`'s disassembly of the same
kernel, this is M7's "the release kernel contains no UART code". A server
fault there ends the run with failure and a `TEST FAIL` line through `watch`;
a root-task fault has no handler and no output, so it shows only as the
60-second timeout.

### Code and tests

| Part | Where | Host tests |
| --- | --- | --- |
| Byte strings, labels, error labels; the two clients; `print!`'s output and `exit`; the device invocations | `libsys::proto`, `libsys::console`, `libsys::uart`, `libsys::output`, `libsys::device` | round trips for every `n` from 0 to 952, each `length`, `BadLength` cases, the ignored high bytes; writes split at 952; `fmt::Write`; `Polled` against a model port; each device invocation's message |
| The 16550 driver: registers, setup, the service routine, the rings, held requests, requests; `uart::run`, the loop | crate `uart` (`user/uart`), `no_std`, `#![forbid(unsafe_code)]`, generic over a port trait; `run` for the target only | against a 16550 model (IIR priorities, THRE cleared by an IIR read or a THR write, 16-byte FIFOs, the trigger and the timeout, OE, OUT2 and an edge-triggered line; a transmitter that takes a byte time per byte, and one that empties at once as QEMU's does) and an I/O APIC pin with the kernel's Ack rule that drops edges while masked: setup's accesses in order; in 400 random interleavings of host input, transmit progress, a kernel writer (with FIFOs only: [Sharing COM1 with a debug kernel](#sharing-com1-with-a-debug-kernel)) and uart's steps, uart never loses a byte, overflows the FIFO, or blocks with a cause pending and no signal (`random_interleavings_lose_nothing_and_never_strand_uart`); the same model finds such a state when the loop services before it Acks, so the test can tell (`servicing_before_the_ack_strands_uart`); on a working device with input no faster than the line rate the limit of 64 is never reached; held Writes released in order; Drain answered only when empty; a full ring stops and resumes reception; a device whose IIR never clears is left after 64 reads |
| The terminal: clients, output arbitration, line editing, focus, how a client's bytes are shown; `console::run`, the loop | crate `console` (`user/console`), the same way | golden byte transcripts for every row of the event and input tables and for every byte's shown form, in output, prompts and names; the M7 red team's attack over a VT100 screen model (`tests/redteam.rs`); a proptest of random writes of any bytes at random boundaries, flushes, reads and typed bytes, focus keys included, by eight clients against a model of per-client lines, checking the invariants below |
| Building a server's VSpace and CSpace; `watch` | the plan and `watch`'s failure line in `root::process` (`user/root/src/process.rs`, in the root crate's library); the invocations and `watch` itself in `user/root/src/servers.rs`, in the program | the page plan of M6's image, of an image across a 2 MiB boundary, and of segments with gaps; no scratch page when the mapping ends on a 2 MiB boundary; `watch`'s failure line for each fault type |
| The two tests | `user/root/src/console.rs`, `release.rs`; verdicts in `root::check::console` | the script (the drain's one `Read` per client, root's included, last), the reports' layout, the lines each client must receive, the drain's verdict, uart's totals, the probe's faults |
| The directives and the release kernel | `xtask/src/scenario.rs`; the release kernel in `xtask/src/compile.rs`, its disassembly check in `xtask/src/disasm.rs` | parsing `send:` escapes and placement, the 4 KiB cap, `kernel:`, `forbid:`, `next:` and its placement, and `exit: timeout`; the matcher releasing each send after the expects above it, and consecutive sends together, and taking a `next:` only at the start of the next line, failing on a line between, a line that only contains it, or the text further along the same line; each disassembly rule on a listing (or, for data, an ELF) that breaks it, and on one that passes |

`cargo xtask test` runs the host tests of `uart` and `console` beside
`libsys`'s and `root`'s, and `cargo xtask clippy` lints both crates for the
host and the target. Their tests shrink under Miri (`cfg!(miri)`), but CI
runs Miri on `l4core` only. QEMU covers what the host cannot: QEMU's 16550, IRQ 4
through the I/O APIC to a notification, the IOPort invocations, separate
VSpaces built from root's frames, the harness's input through COM1, and the
release kernel.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| uart is the only holder of the COM1 IOPort and the IRQ 4 handler besides root, which keeps the originals; no server holds a TCB, VSpace, untyped, paging or Grant capability | `servers::start` (`user/root/src/servers.rs`) fills each server's CNode only from the entries it lists against the crate's slot table (`uart::slot`, `console::slot`), with the rights the tables above give; `test=console` and `test=release` start no other holder, and `test=console` prints the slots uart's copies came from; review | M7 |
| No page is writable in two VSpaces: a server maps root's text and read-only pages read-only, and its own data, stack and IPC buffer frames | `root::process::Plan`: text and read-only pages are copies of root's frame capabilities, which `servers.rs` makes with Read only and maps R or RX, and every writable page a fresh frame (`Role::fresh`); host test `m6s_image`, which checks both for every page, and the other plan tests; review | M7 |
| uart never blocks except in its receive on U: it sends only to reply capabilities and signals only NC; the one endpoint it could send on is its fault endpoint, which only the kernel uses | `uart::run` (`user/uart/src/run.rs`) receives with `Recv` and `ReplyRecv` on U, answers held requests with `Send` on slot 7, a reply capability, and signals only slot 5; `uart::slot` holds no other capability it could send on but F; review | M7 |
| uart never writes more than 15 bytes into the FIFO per THRE seen, so with working FIFOs even a debug kernel's byte cannot overflow it | `Uart` writes at most its burst, 15 with working FIFOs and 1 without, after each THRE it sees; `random_interleavings_lose_nothing_and_never_strand_uart` checks the most bytes after one THRE against the burst and that the model's FIFO never overflows, with a debug kernel's writer on devices with FIFOs (without them a kernel byte can be lost: [Sharing COM1 with a debug kernel](#sharing-com1-with-a-debug-kernel)) | M7 |
| uart never blocks with an interrupt cause pending and no signal pending, whatever the order of device events, edges dropped on a masked pin included | `Uart::on_interrupt` Acks before every service routine, which drains until IIR is clear (ADR 0028); `servers::start` refuses a level or active-low route for IRQ 4; host test `random_interleavings_lose_nothing_and_never_strand_uart`, which fails if uart waits with the line high, against a pin model that drops edges while masked, and `servicing_before_the_ack_strands_uart`, which shows the model finds the old order's stranding; the `console` and `release` scenarios' typed input | M7 |
| Every byte queued for transmit is sent once and in order; every byte received, unless overrun, reaches console once and in order | host tests `random_interleavings_lose_nothing_and_never_strand_uart` (every byte console wrote on the wire once and in order, the kernel's beside them; every byte the host sent received, or with overruns the survivors in order), `a_write_that_does_not_fit_is_held_and_released_in_order` and `a_full_ring_stops_and_resumes_reception`; the `console` and `release` scenarios, where uart's `Stats` count exactly the 60 and 14 bytes the harness sent (`root::check::console`, host test `uarts_totals`) | M7 |
| Whenever uart waits, IER.THRI is set exactly while the transmit queue holds bytes or a Drain is held, and IER's data bit is clear only while the receive ring is full | `Uart::wanted_ier`; `random_interleavings_lose_nothing_and_never_strand_uart` compares the model's IER with it each time uart waits; host tests `a_drain_is_answered_only_when_the_queue_and_fifo_are_empty` and `a_full_ring_stops_and_resumes_reception` | M7 |
| console emits each client's bytes once and in order, `\n` as `\r\n` and every byte but printable ASCII and tab as its visible escape; a line of at most 512 bytes that its client does not flush midway reaches the wire with no other byte from console inside it | `Terminal::write`, `flush` and `read`, through `put_shown` (`console::shown`); the proptest `eight_clients_against_a_model_of_their_lines` (512 cases of up to 120 operations), which checks each client's bytes on the terminal against the model's, its own rendering of the escapes, and that each whole line's bytes are consecutive; goldens `a_write_that_completes_lines_sends_them_whole`, `a_break_comes_only_after_another_clients_line`, `held_bytes_go_out_at_512` and `a_clients_control_bytes_are_shown_not_sent`; the `console` scenario's interleaved and burst parts | M7 |
| No client can move the terminal's cursor out of its own line: none can erase or overwrite console's status line or another client's line | the escapes above, on a client's output, prompt and `Attach` name alike; the proptest, which fails any byte of a client's output or prompt that reaches the terminal as a control byte but tab and the CR LF that ends its line; the M7 red team's tests (`user/console/src/tests/redteam.rs`, `docs/redteam/m7-console-escapes.md`), which run its cursor-up and erase attack over a VT100 screen model and find console's status line kept. A client can still print text that reads like a status line, on a line of its own, but not in reverse video, which console's status lines alone have: the red team's guarantee test finds a client's look-alikes, with escapes and without, plain on the screen model | M7 |
| Each typed line reaches exactly one client, the one focused while its bytes were read, as edited; echo, status and redrawn lines reach no client | `Terminal::input` routes each byte by the focus when it is read, and only Enter hands a line to a client; the proptest, which compares every line a typed byte completes, and its client, with the model's; goldens for every row of the input table and `the_scenarios_input_reaches_the_right_clients`; the `console` scenario, where root checks each client's lines (`root::check::console`, host test `each_client_reads_its_line_and_nothing_else`) and its drain finds no line left for root, `a` or `b` (host test `a_drain_read_answered_is_something_more`) | M7 |
| Every `Read` is answered at most once, and exactly once if its client survives and a line is typed for it | an Enter answers a saved `Read` once and clears it, and `CNode_SaveCaller` refuses a second save, which console answers with `Busy`; the proptest, which compares every `Read`'s answer (a line, saved, or `Busy`) with the model's; golden `enter_answers_the_saved_read_or_joins_the_waiting_lines` | M7 |
| console never blocks on a client; it blocks only in calls to uart, which always reply | `console::run` (`user/console/src/run.rs`) answers clients only by `ReplyRecv` or by `Send` on a saved reply capability, and calls only uart, whose requests always get a reply (a held one later); review | M7 |
| Priorities: uart above console above its clients | `servers.rs`'s `WATCH_PRIORITY`, `UART_PRIORITY`, `CONSOLE_PRIORITY` and `CLIENT_PRIORITY`, set with `TCB_SetSchedParams` with an equal MCP; both scenarios print them | M7 |
| A server fault ends the run with failure, whatever root is waiting on, and a client fault reaches root, which never waits in a call to a client | `watch` (`servers.rs`), which only receives on F and ends the run through `Polled` and the exit port or `DebugHalt(1)`; its failure line, host test `watchs_line_for_each_fault`; clients driven through their `Call`s on D, their fault endpoint; review; the `release_fault` scenario, where root revokes its COM1 IOPort, deleting uart's copy, while root waits in console's `Write` and console in uart's: uart's port access fails, its panic's `DebugPutChar` raises `UnknownSyscall`, and `watch` writes `TEST FAIL: uart fault 2` through `Polled` and ends the run with failure, on a kernel that prints nothing | M7 |
| In a release kernel, everything on COM1 after the loader comes from uart, or from `watch` once a server has faulted | the `release` and `release_fault` scenarios' `next:`, which puts the root task's first line right after the loader's last, and `release`'s `forbid:` lines; the disassembly check ([A release kernel without UART code](#a-release-kernel-without-uart-code)); `watch` writes only through `Polled` on root's COM1 IOPort | M7 |

### Compared with seL4

seL4 itself has no console; the rows compare the seL4 ecosystem's usual
structure, written from memory of the seL4 Device Driver Framework (sDDF)
and CAmkES.

| seL4 ecosystem | microL4 | Reason |
| --- | --- | --- |
| sDDF serial: a driver and separate transmit and receive virtualisers, each a protection domain, passing bytes through shared-memory queues and signalling each other with notifications | `uart` and `console` pass bytes in IPC messages; uart only signals that input waits | at 115,200 baud a call per 952 bytes costs nothing that matters, and no shared frames or memory-ordering rules are needed. Lost: zero-copy throughput, which a serial line does not need |
| sDDF's receive virtualiser sends input to one client and switches on a control character followed by a client number | Ctrl-T and one digit | the same idea; one digit, so the sequence ends without a terminator |
| sDDF does no line editing; clients see raw bytes | console edits lines; from M8 its client 4, the terminal, gets raw bytes | PLAN.md puts line editing in console |
| CAmkES builds such systems from components, each an ELF that the capDL loader places in an address space of its own, connected by RPC and dataport connectors | servers are threads of root's own image, in VSpaces root builds from its image frames | one ELF to build and embed, and no loader in root; text is shared read-only |
| A seL4 kernel with `CONFIG_PRINTING` writes to the UART that a user driver also drives | the same in a debug kernel; lines may interleave | debug kernels make no isolation claim ([ADR 0021](adr/0021-debug-feature.md)) |

## Framebuffer, terminal and TUI

From M8 a terminal emulator draws on the GOP framebuffer and a TUI app runs
inside it. `term` owns the framebuffer: it parses its client's bytes as a
VT100-family terminal does, keeps a screen model and draws it with an 8×16
bitmap font. `tui` is the client, the demo app. Keys still come from COM1:
console's client 4 is raw, so console passes the bytes typed for it to
`term` unedited. Both are threads of the root image, each in a CSpace and a
VSpace of its own, as M7's servers are; root maps the framebuffer's frames
into term's VSpace write-combining and gives each thread only the
capabilities listed below. The parser, the screen model, the font, the
renderer and the app are plain code in host-tested crates, checked against
hundreds of golden screens; the QEMU scenario checks what needs the machine:
the frames mapped write-combining, the path from COM1 to the app, and what
QEMU displays, compared pixel for pixel with images the host renderer drew
from the same bytes. This section is about user space. The kernel and
`docs/abi.md` do not change: M8 uses device untyped, 4 KiB and 2 MiB frames
mapped `WriteCombining` and M6's IPC as they are, though no earlier test
mapped a device frame write-combining or made a 2 MiB frame from device
untyped.

| PLAN.md | M8 | Why |
| --- | --- | --- |
| `fb` is a server that takes the GOP frames and shares them with `term` | `fb` is a library (geometry, pixel formats, the frame plan, a write-only surface); root maps the frames into term's VSpace and term writes the pixels | one display client and no mode setting: a server would add a copy or a message per damaged rectangle and no isolation, since only term's VSpace maps the framebuffer either way |
| `term` reads keyboard input from `uart` | from console, whose client 4 is raw | uart keeps one reader, and console's focus switching keeps working |
| `tui` is a monitor of threads and capabilities, or a small editor | a menu of fixed panels | a screendump is compared pixel for pixel, so nothing on screen may move with the build or the run: no address, slot count or time |
| console multiplexes clients onto the UART | unchanged; console's output stays on COM1 only | COM1 is the log the harness and the owner read; mixing it into the framebuffer would make the screendump depend on timing |

### Where it runs

| Thread | VSpace | CNode | Priority and MCP | Bound to | Receives on |
| --- | --- | --- | --- | --- | --- |
| `term` | root's image, as M7's servers ([Where the servers run](#where-the-servers-run)), plus its state window and the framebuffer window | 16 slots, guard 0 of size 60 | 125 | notification NT | endpoint T |
| `tui` | root's image, as M7's servers | 16 slots, guard 0 of size 60 | 100 | none | nothing: it only calls |

console (150) is above term, its client, and term above tui, its client, as
[Priorities](#priorities) asks. tui is also console's client, at 100 as M7's
clients are.

| Range in term's VSpace | Frames | Mapping |
| --- | --- | --- |
| the image's ranges | as M7's servers | as M7's servers |
| `term::layout::STATE` = `0x0800_0000`, 106 pages | fresh RAM frames, zeroed by retype | RW, NX, `WriteBack` |
| `fb::WINDOW` = `0x1000_0000` up, the framebuffer's first byte at `WINDOW` + (`base` mod 2 MiB) | the framebuffer's frames, retyped from its device untyped ([`fb`](#fb)) | RW, NX, `WriteCombining` |

Both windows lie in the first GiB, under the page directory root's image
range already uses, and below `0x4000_0000`, so root adds only page tables:
one for the state window, and one for each 2 MiB of the framebuffer window
that holds 4 KiB frames; a 2 MiB frame maps in the page directory itself.
The image ends below `0xC0_0000` (at most 8 MiB from `0x40_0000`), so
neither window overlaps it. The state window holds three grids of
`term::MAX_COLS` × `term::MAX_ROWS` = 240 × 75 words: the main screen, the
alternate screen and what the renderer last drew (432,000 bytes); the rest
of term's state is small and lives in locals of its entry function, as M7's
servers keep theirs.

A server gets no arguments in M7; term gets three, in `rdi`, `rsi` and `rdx`:
`width | height << 32`, `stride | format << 32`, and the first pixel's offset
in the window (`fb::Geometry::to_words`). Its entry stub in
`user/root/src/servers.rs`, `term_main`, resets `libsys::output` (its
statics are a copy of root's), checks the words again
(`fb::Geometry::from_words`, which returns `None` for words it refuses, and
term panics) and makes a `&'static mut [u32]` of `stride × height` pixels at
the first pixel and a `&'static mut [u64]` of the state's words. With the
pixel slice and the TSC read of root's write-combining check (`clear` and
`tsc` in `user/root/src/tui.rs`, [`fb`](#fb)), these are the only `unsafe`
blocks M8 adds outside libsys, whose one more is
`libsys::cpu::store_fence`'s `sfence`. The slices' `SAFETY:` comments rest
on root having mapped exactly those pages there, read-write, in this VSpace
and no other, and on every bit pattern being a valid `u32` and `u64`;
`tsc` is an `rdtsc` without `nomem`, so that, as with `store_fence`, no
store of the timed clear moves across it (`libsys::rdtsc` is `nomem`,
which lets the compiler move stores across it). Then `term_main` calls
`term::run`, which, like `uart` and `console`, is
`#![forbid(unsafe_code)]`.

#### Capabilities

Two objects are new: endpoint T, term's requests, and notification NT,
term's, which console signals when keys wait for it. `servers::start`
creates NT with M7's objects and fills console's new slot 5 from it at spawn,
whether or not term will run: a signal with no thread bound waits in NT.

| `term` slot | Capability | Rights, badge |
| --- | --- | --- |
| 1 | its own CNode, guard 0 of size 60 | for `CNode_SaveCaller` |
| 2 | endpoint T, term's requests | Read |
| 3 | endpoint C | Write, GrantReply, badge 4: console's raw client |
| 4 | endpoint F, its fault endpoint | Write, GrantReply, badge `TERM` (3, `root::process::fault_badge`) |
| 5 | empty: its client's saved `Read` | |

| `tui` slot | Capability | Rights, badge |
| --- | --- | --- |
| 1 | its own CNode, guard 0 of size 60, as `servers::start` fills every server's; tui does not use it | |
| 2 | endpoint T | Write, GrantReply, badge 1: term's client |
| 3 | endpoint C | Write, GrantReply, badge 5: its log lines |
| 4 | endpoint D | Write, GrantReply, badge 5: its report to root, and its fault endpoint, as M7's clients have |

| `console` slot (from M8) | Capability | Rights, badge |
| --- | --- | --- |
| 5 | notification NT | Write, badge `KEYS` (bit 32) |

Root binds term to NT before it starts it. Neither thread holds a TCB,
VSpace, untyped, paging, frame or IOPort capability, a notification with
Read, or Grant. term holds no capability to the framebuffer's frames, so it
cannot unmap, remap or pass the framebuffer on; tui holds nothing that names
the framebuffer at all, so an app can reach the screen only through term's
parser.

| `root` keeps | Why |
| --- | --- |
| the framebuffer's device untyped (BootInfo's `framebuffer_untyped`, originals) and every frame retyped from them | revoking an untyped takes the framebuffer back; each frame is mapped once, in term's VSpace |
| term's state frames, the windows' page tables, and both threads' TCBs, CNodes and VSpaces | revoking stops a thread and reclaims its memory |
| endpoint T's original, and a copy with badge 2 | term's `Stats` |
| notification NT's original | |
| endpoint D | tui's report and its faults |

The slot cost on QEMU, as `test=tui` measures it: 489 framebuffer frames
and the window's one page table, 107 for term's state and its page table,
and 128 for each of the four servers' VSpaces and CNodes with the 145-frame
image; with the boot regions (about 280 slots, as the untyped count varies)
and the endpoints, notifications, TCBs and CNodes, about 1,405 of the root
CNode's 4,096. `test=tui` prints the count, `servers: term and tui started;
root CNode 1407 of 4096 slots used` in one run ([Open
questions](#open-questions)).

#### Failures

`watch` names badge 3 `term`: a term fault ends the run with failure through
`watch`, whatever root is waiting on, as a uart or console fault does
([Failures](#failures)); tui, blocked in a call to the dead term, stays
blocked, which no longer matters. A tui fault reaches root on D, where root
waits once both threads run; root reports it through console as `TEST
FAIL: tui fault <label> (<kind>), MR0 to MR3 <words>`, the words of
`watch`'s line (`root::check::tui::OnD`), and fails the test. A term panic
prints through `DebugPutChar` and ends with `libsys::exit(1)` on a debug
kernel, and faults to `watch` on a release kernel, as M7's servers do.

Two review scenarios, `term_fault` and `tui_fault`
([Scenarios](#scenarios-1)), make each fault once tui has drawn its first
frame, with root waiting in a call to term, or on D: root suspends the
thread, writes its `rip` 0 with `TCB_WriteRegisters` and resumes it, and
its fetch from page 0, which nothing maps, is a `VMFault` with MR0 to MR3
`0x0 0x0 0x1 0x14`. Both expect the failure line exactly, with `next:`
lines that put the halt's two lines right after it. A term panic is not
tested: a fault is what reaches `watch` either way.

### `fb`

`fb` (`user/fb`) is a `no_std`, `#![forbid(unsafe_code)]` library with no
dependencies. Root uses it to decide whether there is a usable framebuffer
and which frames to make; term uses it to write pixels.

**Geometry.** `fb::Geometry::check` takes BootInfo's `framebuffer` fields
and the descriptors of `framebuffer_untyped`, as plain numbers, and gives
the geometry or the reason there is none, checking in this order:

| Check | Unusable as | Root prints |
| --- | --- | --- |
| `format` is 0 or `base` is 0 | `None` | `fb: none: the loader found no GOP framebuffer` (none, or a bitmask or BLT-only mode, which the loader does not pass) |
| `framebuffer_untyped` is empty | `NotHandedOut` | `fb: none: the kernel kept it (see its boot summary)`, as [ADR 0024](adr/0024-framebuffer-untyped-rejections.md) allows |
| `format` is neither 1 (RGB) nor 2 (BGR) | `Format` | the number |
| `width` below 640 or `height` below 384, 80 × 24 cells | `TooSmall` | the size |
| `stride` below `width`, `base` not 4-byte aligned, 4 × `stride` × `height` above `size`, or `base` + `size` past the address space | `Geometry` | the fields |
| the untyped are not all device memory of at least a page, each aligned to its size, tiling the page-rounded `[base, base + size)` in order | `Untyped` | the first that does not, or where they end short |
| the window, from `WINDOW` to the visible bytes' end rounded up to 2 MiB, would pass `0x4000_0000` | `TooLarge` | the size |

`Geometry::to_words` gives the three words root passes term, and
`Geometry::from_words` checks them again on term's side: a known format, at
least 640 × 384, a stride of at least the width, an offset 4-byte aligned and
below 2 MiB, and a window below `0x4000_0000`; anything else is `None`.
`Geometry::new` makes a geometry for a host buffer, any size from 1 × 1
whose window fits, without the 640 × 384 minimum, so that host tests can
draw on small surfaces; root and term never use it.

**Pixel formats.** A colour `(r, g, b)` is the `u32` `r | g << 8 | b << 16`
for RGB (byte 0 red) and `b | g << 8 | r << 16` for BGR (byte 0 blue); byte 3
is written 0. Both targets are BGR: QEMU's OVMF gives 1280x800, stride 1280,
at `0x80000000` (`core/tests/boot/q35.memmap`), and Hyper-V 1024x768,
stride 1024, at `0xF8000000` (the M0 Hyper-V check). RGB is host-tested
only.

**The frame plan.** `fb::Plan` lists the frames that cover the visible bytes,
`[base, base + 4 × stride × height)` rounded out to pages, taken from the
framebuffer's untyped in order: from each, a 2 MiB frame for every 2 MiB
stretch that is 2 MiB-aligned and lies inside that untyped, 4 KiB frames for
the rest, stopping once the visible bytes are covered; at most 256 per
`Untyped_Retype` (`RETYPE_FAN_OUT_LIMIT`). A frame at physical `p` maps at
`WINDOW` + `p` − (`base` rounded down to 2 MiB), so virtual and physical
addresses agree modulo 2 MiB and every 2 MiB frame is 2 MiB-aligned in the
window. On QEMU the six untyped give one 2 MiB frame and 488 4 KiB frames
under one page table. On Hyper-V, 4 × 1024 × 768 bytes is 3 MiB, which would
need two untyped, but the M5 Hyper-V check's log reports one, so the GOP
reports a larger power-of-two size there; with 4 MiB or more the plan is two
2 MiB frames and no page table. Root's `fb:` line is the plan's `Display`
and term's grid, with the GOP's size; on QEMU it reads `fb: 1280x800 BGR,
stride 1280, 4000 KiB at 0x80000000: 6 untyped, 1 2 MiB and 488 4 KiB
frames; 160x50 cells`. Root retypes each `Plan::retypes` entry from its
untyped, named rather than chosen (`libsys::ObjectAlloc::retype_from`), so
the frames land in consecutive slots in the plan's order
(`servers::framebuffer_objects`).

**The surface.** `fb::Surface` is the geometry and the pixel slice, which
`Surface::new` refuses if it holds fewer than `stride × height` pixels. It
fills the visible area and writes an 8×16 block of pixels at a cell's
position, each bounds-checked against `width` and `height`, never the
stride's padding: a cell past the right or bottom edge is cut there.
It has no read method: nothing reads the framebuffer, which is slow
uncached and write-combining memory, and the renderer keeps what it drew in
the state window instead.

**No framebuffer.** Root prints the reason and starts neither term nor tui.
console's client 4 stays raw, with nothing attached as it and nothing
reading its queue ([Input](#input-and-the-term-protocol)). `test=tui` then
fails with the reason; `test=nofb` passes.

**The write-combining check, H10.** Before term starts, `test=tui`
(`write_combining_check` in `user/root/src/tui.rs`) maps the window's page
tables and every framebuffer frame into root's own VSpace at `WINDOW`,
first `Uncached`, fills the visible area once with 0 and times it with the
TSC, unmaps the frames, then does the same `WriteCombining`; each fill ends
with `sfence` before its second TSC read, and both reads (`tsc`) are
compiler barriers, so the fill's stores stay between them. Root prints
`fb: full clear: uncached <n> us, write-combining <m> us`.
`PageTable_Unmap` (`libsys::vspace::unmap_table`) then leaves the page
tables unmapped and empty, so they move to term's VSpace (Map takes an
unmapped, empty structure). QEMU's TCG has no cache model, so the two
times, about a millisecond each, mean nothing there; on Hyper-V a
write-combining clear
several times faster than the uncached one confirms that a PAT type of WC
wins over the firmware's MTRR type for the framebuffer [H10]. Only a single
mapping of each frame exists at any time, apart from the direct map's UC
alias, which the kernel never touches ([Mapping](#mapping)).

### The font

The font is 8×16 pixels, one byte per row from the top, bit 7 the leftmost
pixel; 266 glyphs, 4,256 bytes of read-only data in `term::font`.

| Code points | Glyphs | Source |
| --- | --- | --- |
| U+0020 to U+007E | 95, printable ASCII | Spleen's 8×16 |
| U+00A0, U+00A3, U+00B0, U+00B1, U+00B7 | 5: no-break space, `£`, `°`, `±`, `·`, for DEC Special Graphics | Spleen's 8×16, whose README says every size covers ISO/IEC 8859-1 (read 2026-11-23) |
| U+2500 to U+257F, box drawing | 128 | generated |
| U+2580 to U+259F, block elements | 32 | generated |
| U+23BA to U+23BD, scan lines 1, 3, 7 and 9 | 4, for DEC Special Graphics | generated |
| U+25C6, black diamond | 1, for DEC Special Graphics | generated |
| every other code point, U+FFFD included | the replacement glyph, an outline box over rows 2 to 13 and columns 1 to 6 | generated |

**Spleen.** [Spleen](https://github.com/fcambus/spleen), by Frederic Cambus,
is released under the BSD 2-Clause licence. The glyphs come from its tag
`2.3.0` (commit `b2d04a6180d4`), whose `LICENSE` is that licence, with the
line `Copyright (c) 2018-2026, Frederic Cambus`, the clauses for source and
binary redistributions and the disclaimer. `tools/spleen.py` fetches that
tag's `spleen-8x16.bdf` and `LICENSE` (or takes local copies), refuses
either unless its SHA-256 is the one pinned in the script, and writes
`user/term/src/font/spleen.rs`: the 100 glyphs above, one entry per glyph,
each row a binary literal so that a glyph reads as a picture, under a
header that names the tag, the commit, the BDF's SHA-256 and the licence
text, with an FNV-1a checksum of the rows. It copies the `LICENSE`
verbatim to `user/term/src/font/LICENSE-spleen`; the output depends only on
the two inputs. `cargo xtask image` copies `LICENSE-spleen` to
`\licenses\spleen.txt` on the ESP (`xtask::image::LICENCES`), since the
VHDX is a binary redistribution, for which the licence's second clause asks
that the notice come with it. Moving to another tag means reading its
`LICENSE` first, then updating the script's tag, commit and hashes.

**Generated glyphs.** The others are computed by `const fn` from a
description, so they need no font's coverage and always join across cells:

| Glyphs | Rule |
| --- | --- |
| box drawing | four arms, up, right, down and left, each none, light, heavy or double, drawn from the cell's edge to its centre: light vertical in column 3 and light horizontal in row 7; heavy in columns 3 and 4 and rows 7 and 8; double in columns 2 and 5 and rows 6 and 9. A light or heavy arm runs from its edge through the centre square, column 3 or row 7 for light and columns 3 and 4 or rows 7 and 8 for heavy, so heavy corners such as U+251B have no notch. Each of a double arm's two lines runs from its edge to the arm beside it on that line's side: to that arm's nearer line if there is one (row 9 for a down arm's left line beside a double left arm), else to the farther line of the arm on the other side (row 6 for that line beside only a double right arm, as in U+2554), else to the centre row or column. So U+2554 draws an outer corner at column 2, row 6 and an inner one at column 5, row 9, and U+256C four inner corners. A light arm beside a double one (no glyph mixes heavy and double) runs to the double's farther line, so that a corner such as U+2556 or U+2558 closes, but stops at its nearer line when the double runs straight through the cell, a double arm on each side of the light one, and no arm continues the light one beyond it, so that a T such as U+255F or U+2564 stops at the double line. A glyph is the union of its arms, so every arm meets its neighbour's at the same column or row. Dashed forms are their line cut into 2 (U+254C to U+254F), 3 (U+2504 to U+2507) or 4 (U+2508 to U+250B) dashes per cell, each followed by a gap of an eighth of the cell's length, one pixel across or two rows down; the rounded corners U+256D to U+2570 are drawn as the light corners; U+2571 to U+2573 are lines corner to corner, one pixel per row and two rows per column |
| block elements | eighths: U+2581 to U+2588 fill the bottom 2, 4, ... 16 rows and U+2589 to U+258F the left 7 down to 1 columns; U+2594 the top 2 rows and U+2595 column 7; halves at row 8 and column 4; quadrants of 4 × 8 pixels; the shades U+2591 (`(x + 2y) mod 4 = 0`), U+2592 (`x + y` even) and U+2593 (the complement of U+2591) |
| scan lines | a light line in row 1, 4, 10 or 13, so with U+2500 in row 7 the five DEC scan lines are evenly spaced |
| U+25C6 | a filled diamond centred on the cell: the pixels whose centres lie within 3 of the cell's centre, (3.5, 7.5), in the L1 norm, 6 pixels wide in columns 1 to 6 and 6 tall in rows 5 to 10 |

### `term`: the parser

`term::parser` is Paul Williams' state machine for DEC's ANSI-compatible
terminals ([vt100.net](https://vt100.net/emu/dec_ansi_parser), PLAN.md's
reference), fed one byte at a time; its actions go to the screen model. Its
state lives in the parser, not in the bytes of one `Write`, so a sequence
split across writes acts as it would whole.

| State | Entry and exit | Bytes |
| --- | --- | --- |
| ground | | C0: execute; `0x20` to `0x7E`: print; `0x80` to `0xFF`: the UTF-8 decoder, which prints each code point it completes |
| escape | clear | C0: execute; `0x20` to `0x2F`: collect, to escape intermediate; `[`: to CSI entry; `]`: to OSC string; `P`: to DCS entry; `X`, `^`, `_`: to SOS/PM/APC string; any other `0x30` to `0x7E`: ESC dispatch, to ground |
| escape intermediate | | C0: execute; `0x20` to `0x2F`: collect; `0x30` to `0x7E`: ESC dispatch, to ground |
| CSI entry | clear | C0: execute; `0x20` to `0x2F`: collect, to CSI intermediate; digits and `;`: param, to CSI param; `:`: to CSI ignore; `<` to `?`: collect, to CSI param; `0x40` to `0x7E`: CSI dispatch, to ground |
| CSI param | | C0: execute; digits and `;`: param; `:` and `<` to `?`: to CSI ignore; `0x20` to `0x2F`: collect, to CSI intermediate; `0x40` to `0x7E`: CSI dispatch, to ground |
| CSI intermediate | | C0: execute; `0x20` to `0x2F`: collect; `0x30` to `0x3F`: to CSI ignore; `0x40` to `0x7E`: CSI dispatch, to ground |
| CSI ignore | | C0: execute; `0x20` to `0x3F`: ignore; `0x40` to `0x7E`: to ground, no dispatch |
| DCS entry | clear | C0: ignore; `0x20` to `0x2F`: collect, to DCS intermediate; digits and `;`: param, to DCS param; `:`: to DCS ignore; `<` to `?`: collect, to DCS param; `0x40` to `0x7E`: to DCS passthrough |
| DCS param | | C0: ignore; digits and `;`: param; `:` and `<` to `?`: to DCS ignore; `0x20` to `0x2F`: collect, to DCS intermediate; `0x40` to `0x7E`: to DCS passthrough |
| DCS intermediate | | C0: ignore; `0x20` to `0x2F`: collect; `0x30` to `0x3F`: to DCS ignore; `0x40` to `0x7E`: to DCS passthrough |
| DCS passthrough | hook; unhook on leaving | C0, `0x20` to `0x7E` and `0x80` to `0xFF`: put |
| DCS ignore | | every byte ignored |
| OSC string | OSC start; OSC end on leaving | `0x20` to `0x7E` and `0x80` to `0xFF`: OSC put; BEL: to ground; other C0: ignore |
| SOS/PM/APC string | | every byte ignored |

In every state, CAN (`0x18`) and SUB (`0x1A`) execute and go to ground, ESC
(`0x1B`) goes to escape, running the state's exit action, and DEL (`0x7F`)
is ignored. A string ends with ESC `\`: the ESC leaves the string state, and
`\` is ST's ESC dispatch, which does nothing. C0 here is `0x00` to `0x17`,
`0x19` and `0x1C` to `0x1F`. Dispatch passes the final byte, up to two
collected intermediates (a private marker `<` to `?` is collected like one)
and up to 16 parameters, each saturating at 65,535, with an empty parameter
read as 0; parameters after the 16th are dropped and the sequence still
dispatches, and a sequence with more than two intermediates is not
dispatched but ignored. A `:` anywhere in a CSI or DCS sequence sends it to
its ignore state, so xterm's colon forms of SGR (`38:2::r:g:b`) are ignored
whole. Every dispatch the screen model does not act on, a CSI ignore, a
sequence with too many intermediates, every DCS and SOS, PM or APC string,
and an OSC other than 0 and 2 counts as an ignored sequence in term's
`Stats`. An SGR, SM, RM, DECSET or DECRST counts as ignored only if none of
its parameters acted. A CSI or ESC sequence cut short by CAN, SUB or ESC
never dispatches and does not count; a string cut short that way ends as at
ST, so a DCS or SOS, PM or APC string counts and an OSC string dispatches.

| Williams | term | Why |
| --- | --- | --- |
| `0x80` to `0x9F` are C1 controls in every state, and `0xA0` to `0xFF` print as GR in ground | bytes from `0x80` are UTF-8: decoded in ground, OSC put in an OSC string, put in DCS passthrough, ignored elsewhere; no 8-bit C1 control exists, so ST is ESC `\` and CSI is ESC `[` | apps send UTF-8 and 7-bit controls; xterm in UTF-8 mode and VTE do the same (from memory) |
| an OSC string ends at ST | also at BEL | xterm's terminator, which most apps send (from memory) |
| ground prints `0x7F` and an OSC string puts it (from memory); a VT terminal then ignores it as fill | DEL ignored in every state | the same result on screen, one rule |
| sixteen parameters stored (the VT500's limit), the rest silently ignored; a sequence with more than two intermediates made a no-op; no bound on a parameter's value (from memory) | the same, with each value saturating at 65,535 and the first 64 bytes of an OSC string kept | bounded state, a fixed size in the state window |
| `:` sends CSI and DCS sequences to their ignore states | the same | xterm parses colon sub-parameters in SGR; apps here use the `;` forms, and the ignored count shows any that do not |

**UTF-8.** A lead byte `0xC2` to `0xDF` takes one continuation byte, `0xE0`
to `0xEF` two and `0xF0` to `0xF4` three, the second byte restricted as in
the Unicode standard's table of well-formed sequences (`E0` `A0`–`BF`, `ED`
`80`–`9F`, `F0` `90`–`BF`, `F4` `80`–`8F`), so overlong forms, surrogates and
code points above U+10FFFF are refused. Each maximal ill-formed subpart
prints one U+FFFD, and the byte that ended it is taken afresh; so does a
sequence cut short by a C0 control, ESC, CAN, SUB or DEL, before the control
acts. Decoded code points U+0080 to U+009F are dropped. The decoder's state
survives the end of a `Write`.

### The screen model

`term::screen` acts on the parser's actions. It has no dependency: it
writes cells into a grid of words and queues replies.

| State | Content |
| --- | --- |
| size | `cols` = min(`width` / 8, 240), `rows` = min(`height` / 16, 75): 160 × 50 on QEMU, 128 × 48 on Hyper-V; fixed for the run |
| a cell | a code point, a foreground and a background (each the default or a palette index, 0 to 255), and attributes: bold, faint, italic, underline, blink, inverse, conceal, strike. A blank cell is a space in the default foreground. Each cell is one word of the state window |
| two buffers | main and alternate, each `cols` × `rows` cells; one is active |
| cursor | row and column, the pending wrap (DEC's last-column flag), and the pen: the foreground, background and attributes the next print uses |
| saved cursor | one per buffer (DECSC), as in xterm: position, pen, G0, G1 and which is in GL, DECOM, the pending wrap. The position is absolute; DECRC that restores DECOM on keeps the row inside the region |
| scroll region | top and bottom rows, the whole screen by default; one for both buffers, as in xterm |
| tab stops | one bit per column, every eighth column (1, 9, 17, ...) at reset |
| character sets | G0 and G1, each ASCII or DEC Special Graphics; GL is G0 after SI and G1 after SO |
| modes | below |
| title | the bytes after `0;` or `2;` among the first 64 bytes of the last OSC string whose number, before its first `;`, is exactly `0` or `2`, however the string ended (ST, BEL, CAN, SUB or ESC), so at most 62, not decoded; shown nowhere, kept for tests |
| replies | bytes term owes its client (DSR and DA answers), queued as input ([Input](#input-and-the-term-protocol)) |

Rows and columns count from 1 in sequences and in this section.

**Printing** a code point: if the pending wrap is set and DECAWM is on, CR
and IND first; with IRM, the cells from the cursor shift right one, the last
is lost; the cell under the cursor takes the code point and the pen; then
the cursor moves right, or, in the last column, stays and sets the pending
wrap if DECAWM is on. An ASCII byte `0x5F` to `0x7E` printed while GL holds
DEC Special Graphics becomes that set's character: `_` a blank (U+00A0), `` ` ``
◆, `a` ▒, `b` to `e` and `h`, `i` the control pictures ␉ ␌ ␍ ␊ ␤ ␋, `f` °,
`g` ±, `j` ┘, `k` ┐, `l` ┌, `m` └, `n` ┼, `o` ⎺, `p` ⎻, `q` ─, `r` ⎼, `s` ⎽,
`t` ├, `u` ┤, `v` ┴, `w` ┬, `x` │, `y` ≤, `z` ≥, `{` π, `|` ≠, `}` £, `~` ·
(the VT100's table, from memory). The six control pictures, `≤`, `≥`, `π`
and `≠` are not in the font ([The font](#the-font)) and draw as the
replacement glyph, where a VT100 draws them; the model and the goldens keep
their code points. Code points from UTF-8 print as they are.
Every code point takes one cell: there are no wide or combining characters
([Open questions](#open-questions)).

**The pending wrap** is set only by a print into the last column with DECAWM
on, and cleared by every action that moves the cursor, to the same cell or
not, by ICH, DCH, ECH, EL, ED but ED 3, IL and DL inside the region and a
DECSTBM that sets a region, and by a print; DECRC restores the saved one.
Everything else keeps it: SU, SD, HTS, TBC, DSR, DA, SGR, a buffer switch
without DECRC (47, 1047) and a change of DECAWM among them. With DECAWM
reset, a pending wrap does nothing: the next print writes the last column
again.

| Control | Effect |
| --- | --- |
| BEL (`0x07`) | nothing: no sound |
| BS (`0x08`) | left one, stopping at column 1 |
| HT (`0x09`) | the next tab stop, or the last column |
| LF, VT, FF (`0x0A` to `0x0C`) | IND; with LNM, CR as well |
| CR (`0x0D`) | column 1 |
| SO, SI (`0x0E`, `0x0F`) | G1, G0 into GL |
| any other C0 | nothing |

| Escape | Name | Effect |
| --- | --- | --- |
| `ESC 7`, `ESC 8` | DECSC, DECRC | save, restore the active buffer's cursor; with nothing saved, DECRC homes the cursor with the default pen, ASCII in G0 and G1 and DECOM off |
| `ESC D` | IND | down one; on the region's bottom row, scroll the region up one instead; on the screen's last row below the region, nothing |
| `ESC E` | NEL | CR, then IND |
| `ESC H` | HTS | a tab stop at the cursor's column |
| `ESC M` | RI | up one, stopping at row 1; on the region's top row, scroll the region down one instead |
| `ESC c` | RIS | power-on state: both buffers blank, main active, cursor home with the default pen, every mode at its default, the full screen as region, tab stops every eight columns, ASCII in G0 and G1, no title, both saved cursors gone |
| `ESC # 8` | DECALN | every cell an `E` in the default pen, whatever the pen, which itself stays as it was; the full screen as region, cursor home |
| `ESC ( 0`, `ESC ( B`, `ESC ) 0`, `ESC ) B` | SCS | G0 or G1 becomes DEC Special Graphics or ASCII |
| `ESC =`, `ESC >` | DECKPAM, DECKPNM | stored only: input passes through as typed |
| `ESC \` | ST | nothing |
| any other | | ignored |

In CSI sequences `Pn` defaults to 1, and 0 counts as 1; `Ps` defaults to 0.
A position past the screen stops at its last row or column. A count larger
than the cells or lines it can act on (ICH, DCH, ECH, IL, DL, SU, SD) acts
as that number, so one sequence costs at most a pass over the region; CHT
and CBT stop at the screen's edge, so one reads at most `cols`² tab bits,
and REP is bounded as its row says. Home
is where `CUP 1;1` puts the cursor: row 1 column 1, or with DECOM the
region's top row.

| CSI | Name | Effect |
| --- | --- | --- |
| `Pn @` | ICH | insert `Pn` blanks at the cursor; cells pushed past the last column are lost |
| `Pn A` | CUU | up `Pn`, stopping at the region's top, or at row 1 if the cursor started above the region (so a cursor below the region stops at its top, as xterm's `CursorUp` and DEC's rule do, from memory) |
| `Pn B`, `Pn e` | CUD, VPR | down `Pn`, stopping at the region's bottom, or at the last row if the cursor started below the region |
| `Pn C`, `Pn a` | CUF, HPR | right `Pn`, stopping at the last column |
| `Pn D` | CUB | left `Pn`, stopping at column 1 |
| `Pn E`, `Pn F` | CNL, CPL | as CUD, CUU, then column 1 |
| `Pn G`, `` Pn ` `` | CHA, HPA | column `Pn` |
| `Pn ; Pn H`, `Pn ; Pn f` | CUP, HVP | row and column, each stopping at the last; with DECOM the row counts from the region's top and stays inside it |
| `Pn I`, `Pn Z` | CHT, CBT | `Pn` tab stops forward, to the last column at most; back, to column 1 at most |
| `Ps J` | ED | 0: cursor to the screen's end; 1: the screen's start to the cursor; 2: the whole screen; 3: nothing (no scrollback) |
| `Ps K` | EL | 0: cursor to the line's end; 1: the line's start to the cursor; 2: the whole line |
| `Pn L`, `Pn M` | IL, DL | only with the cursor inside the region: insert or delete `Pn` lines at its row, lines moving within the region and blanks entering; then column 1 |
| `Pn P` | DCH | delete `Pn` cells at the cursor; blanks enter at the right |
| `Pn S`, `Pn T` | SU, SD | scroll the region up or down `Pn` lines; the cursor stays |
| `Pn X` | ECH | blank `Pn` cells from the cursor, not past the line's end; the cursor stays |
| `Pn b` | REP | print the last printed code point `Pn` more times, if the action just before was a print; else nothing, so a REP after a REP does nothing. It makes only as many prints as leave the state `Pn` prints would: without DECAWM at most `cols`; with it, `Pn` up to `s` = `cols` × (2 × `rows` + 2), and past that `s` + (`Pn` − `s`) mod `cols`, since from there the state repeats every `cols` prints, IRM or not |
| `Ps c` | DA | for 0 only: reply `CSI ? 1 ; 2 c`, a VT100 with advanced video |
| `Pn d` | VPA | row `Pn`, counted as CUP counts it |
| `Ps g` | TBC | 0: clear the stop at the cursor; 3: clear every stop |
| `Ps h`, `Ps l` | SM, RM | ANSI modes 4 and 20 (below), each parameter in turn |
| `? Ps h`, `? Ps l` | DECSET, DECRST | DEC modes (below), each parameter in turn |
| `Ps ; ... m` | SGR | below |
| `Ps n` | DSR | 5: reply `CSI 0 n`; 6: reply `CSI <row> ; <column> R`, with DECOM the row counted from the region's top |
| `Pt ; Pb r` | DECSTBM | `Pb` past the last row counts as the last row, as in xterm; then, if `Pt` is less than `Pb` (defaults 1 and the last row), the region becomes rows `Pt` to `Pb` and the cursor goes home; else nothing, the cursor included |
| `s`, `u` | SCOSC, SCORC | with no parameter, as DECSC, DECRC; with any, ignored |
| `Ps SP q` | DECSCUSR | 0 to 2: block; 3, 4: underline; 5, 6: bar. The cursor never blinks |
| any other final, or a listed one with another private marker or intermediate | | ignored |

Erasing (ED, EL, ECH, ICH and DCH's blanks, IL, DL, scrolling, clearing a
buffer) writes blanks in the pen's background colour with no attribute, as
xterm does with `bce`, so an app colours a line with an SGR and EL.

| Mode | Name | Default | Effect |
| --- | --- | --- | --- |
| 4 | IRM | reset | prints insert |
| 20 | LNM | reset | LF, VT and FF also return to column 1. term does no other output processing: an app that wants `\n` to start a line sets LNM or writes `\r\n` |
| ?1 | DECCKM | reset | stored only |
| ?5 | DECSCNM | reset | every cell drawn with its colours swapped |
| ?6 | DECOM | reset | addressing relative to the region; setting or resetting it homes the cursor |
| ?7 | DECAWM | set | autowrap |
| ?25 | DECTCEM | set | the cursor is drawn |
| ?47 | | reset | set: the alternate buffer; reset: the main |
| ?1047 | | reset | as 47, but reset clears the alternate buffer first if it is active |
| ?1048 | | reset | set: DECSC; reset: DECRC |
| ?1049 | | reset | set: DECSC, then the alternate buffer, cleared; reset: the main buffer, then DECRC |
| any other | | | ignored, mouse and bracketed paste included |

Setting 47, 1047 or 1049 while the alternate buffer is active, or resetting
one while the main is, switches and clears nothing; 1049's DECSC or DECRC
still acts, on the active buffer's saved cursor, as in xterm (from memory).
Beyond what DECRC restores, a switch leaves the region, the modes and
DECSCUSR as they are: both buffers share them.

| SGR | Effect |
| --- | --- |
| 0, or none | the default pen |
| 1, 2, 3, 4, 5, 7, 8, 9 | bold, faint, italic, underline, blink, inverse, conceal, strike on; 6 is 5, and 21 is 4 |
| 22 | bold and faint off; 23, 24, 25, 27, 28, 29 turn off italic, underline, blink, inverse, conceal and strike |
| 30 to 37, 90 to 97 | foreground 0 to 7, 8 to 15; 39 the default |
| 40 to 47, 100 to 107 | background 0 to 7, 8 to 15; 49 the default |
| 38 ; 5 ; `n`, 48 ; 5 ; `n` | foreground or background `n`, 0 to 255 |
| 38 ; 2 ; `r` ; `g` ; `b`, 48 ; 2 ; ... | true colour, mapped to the nearest palette entry from 16 up |
| 38 or 48 followed by anything else, or with a value above 255 | ignored, with every parameter after it in that SGR |
| any other | ignored, the rest of the SGR still applies |

Colours 0 to 15 are the VGA text palette: `000000`, `AA0000`, `00AA00`,
`AA5500`, `0000AA`, `AA00AA`, `00AAAA`, `AAAAAA`, `555555`, `FF5555`,
`55FF55`, `FFFF55`, `5555FF`, `FF55FF`, `55FFFF`, `FFFFFF`. 16 to 231 are
xterm's 6 × 6 × 6 cube, `16 + 36r + 6g + b` with levels `00`, `5F`, `87`,
`AF`, `D7`, `FF`; 232 to 255 its grey ramp, `08` + 10·`i`. The default
foreground is `AAAAAA` and the default background `000000`, the same as 7
and 0 but kept apart in the model, so SGR 39 and 49 can be tested. A true
colour maps to the cube's nearest entry (per channel, the nearest level,
ties to the lower) or the ramp's (the level nearest the channels' exact
mean, found by comparing `r + g + b` with three times each level, ties to
the lower), whichever is nearer by squared distance, the cube on a tie
(`term::palette::nearest`). A cell keeps nine bits per colour, the default
or an index, so it stays one word; 256 colours and the mapping are enough
for every app here. Bold draws the glyph overstruck and does not brighten
its colour.

**Scrolling** moves lines only inside the region. A line that leaves the
screen is gone: there is no scrollback.

**Size.** The grid is fixed at start and occupies the top-left `8 × cols` by
`16 × rows` pixels; any margin right or below it stays the default
background. There is no resize, so DECCOLM and window operations are
ignored.

### The renderer

`term::render` draws the screen model on a `term::Surface`, a trait of three
methods: `fill`, the whole visible area in one colour; `cell`, an 8×16 cell's
bits in two colours; and `fence`, called once at the end of every frame. On
the target the surface is `term::Pixels`, which adapts `fb::Surface`, with
its bounds checks and pixel format, and whose `fence` is `sfence`
(`libsys::cpu::store_fence`); on the host it is a buffer. After each
`Write`, once every byte is applied, `Renderer::frame` draws a frame: for
each cell of the active buffer it computes the cell's look
(`term::look`) and compares it with what it last drew there, kept in the
state window's third grid (`term::Drawn`); it draws exactly the cells whose
look changed, records them, and ends with `Surface::fence`, so
write-combining buffers have drained before term replies. Damage is
computed, not tracked: no action has to remember to mark a cell dirty, and a
change that leaves a cell looking the same draws nothing. `render::full`
draws a whole screen whatever was drawn before, which the host render and
the damage checks compare frames with.

| Step | Look |
| --- | --- |
| colours | the cell's foreground and background, the defaults resolved; swapped if inverse, and swapped again under DECSCNM |
| conceal | the glyph becomes the space and no line is drawn |
| faint | the foreground becomes the channel-wise mean of foreground and background, rounded down |
| glyph | the font's glyph for the code point; bold ORs each row with itself shifted one pixel right |
| lines | underline: row 14 in the foreground; strike: row 8 |
| cursor | if DECTCEM is set, at the cursor's cell: block swaps the cell's two colours, underline sets rows 14 and 15 and bar columns 0 and 1 in the foreground; with the pending wrap the cursor is in the last column |
| pixels | each colour through the surface's format |

A look is a glyph index, two 24-bit colours and five flags, so it fits one
word and the comparison is one per cell. `term::Session` is term's screen on
the framebuffer: the parser, the screen model and the renderer over
`term::Pixels`. `Session::start` is term's whole start-up, which
`term::run` and the host render both call: the grid is `term::cells` of the
geometry, its whole cells up to 240 × 75; it fills the whole visible area,
margins included, with the default background, records every cell as a
blank, puts the model in RIS's power-on state (the state window's words,
zeroed or not, are not taken for blanks), and draws its first frame, which
shows the cursor, a block, at home; nothing the firmware or root's
write-combining check drew survives. `Session::write` applies one
`Write`'s bytes and draws the frame, and keeps the counts `Stats` reports.
Italic and blink are kept in the model and the goldens but drawn upright and
steady: there is no italic font, and a blink or a blinking cursor would need
a timer and make every screendump depend on when it was taken. The renderer
never reads the framebuffer, so scrolling redraws the cells whose looks
moved; a full redraw at 160 × 50 is 8,000 cells, 4 MB of pixel writes.

### Input and the term protocol

**From COM1 to term.** console's client 4 is raw from the start. While it
has focus, every byte console reads goes to its raw queue (512 bytes) as it
is, without echo or editing, except the focus keys: Ctrl-T and a digit moves
the focus as in M7, Ctrl-T Ctrl-T puts one Ctrl-T in the queue, and Ctrl-T
followed by anything else drops both. ESC and what follows it pass. Client
4 has no input line: console never shows, echoes or redraws anything for
its bytes, so in [Output](#output)'s event table its typed bytes are "any
other typed byte" and restoring does nothing while it has focus. After
each uart `Read` that added a byte to the queue, console signals slot 5
(NT, `KEYS`) once, as uart signals console with `RX_READY`. A byte that
finds the queue full is dropped, and console sends BEL to COM1 at the first
byte a uart `Read` drops, once per `Read`, as Enter does in M7 with no room.
Raw mode is about input only: console shows its raw client's output as it
shows every client's ([Output](#output)), so no client can put an escape
sequence on COM1, and
M7's red-team guarantee holds unchanged. Client 4 is raw because of its
number, not because of a request, so routing stays a function of the byte
stream alone, as M7 requires; with no term running, its bytes wait in the
queue and the excess is dropped.

| console label | Request | Words | Reply | Errors |
| --- | --- | --- | --- | --- |
| `0x125` | `ReadRaw` | none | a byte string: everything in the raw queue, possibly nothing, at once; it is never saved | `BadBadge` for any badge but 4 |

client 4's `Read` is also `BadBadge`: it never has a line to read. Its
`Attach`, `Write`, `Flush` and `Sync` work as any client's; term attaches
as `term`, so the focus line reads `[console] focus 4 (term)`. With no term
nothing attaches as client 4, and the line reads `[console] focus 4 (client
4)`, as in `test=nofb`.

**term's loop.** term is bound to NT and receives on T. `term::server`
makes the protocol's decisions, pure and host-tested (`decode`,
`Server::request`, `Server::release` and the input queue, `Input`), and
`term::run`, on the target only, does the system calls around them. At
start term resets `libsys::output`, fills the screen and draws its first
frame (`Session::start`, [The renderer](#the-renderer)), then attaches to
console. A signal with `KEYS` makes it call `ReadRaw` once and
append the bytes to its input queue (512 bytes; past that they are dropped
and counted, below). NT exists from console's spawn, so a signal console sent
before term ran waits there, and term's first receive returns it. A message
is one request. Whenever the input queue is non-empty
and its client's `Read` is saved, term answers it with `Send` on slot 5 and
everything queued. term blocks only in calls to console, whose `ReadRaw`
always answers at once; it never waits for its client.

| Label | Request | Words | Reply | Errors |
| --- | --- | --- | --- | --- |
| `0x140` | `Write` | a byte string of at most 952 bytes | MR0 `n`, once every byte is applied and the frame is drawn | `BadLength` |
| `0x141` | `Read` | none | a byte string of at most 512 bytes: the input queue, all of it, at once if it holds anything; else the reply is saved in slot 5 (`CNode_SaveCaller`) and sent when bytes arrive | `Busy` |
| `0x142` | `Size` | none | MR0 columns, MR1 rows, MR2 width and MR3 height in pixels | |
| `0x143` | `Stats` | none | MR0 bytes written, MR1 frames drawn (the first included), MR2 cells drawn, MR3 sequences ignored, MR4 bytes `ReadRaw` brought from console (dropped ones included), MR5 bytes dropped: a key's that found the input queue full, and every byte of a reply that did not fit whole, MR6 reply bytes queued (a dropped reply's are not) | |

`Write`, `Read` and `Size` need badge 1, term's one client; `Stats` takes any
badge, and root's has 2. Labels, the byte-string encoding and the errors are
M7's ([Protocols](#protocols)), checked in the same order. The input queue
holds the keys and the replies DSR and DA queue, in the order they came,
with one exception below. A `Write` that queues a reply while another
thread of the client waits in a saved `Read` releases it. Like a
pseudo-terminal's slave side in raw mode, term passes input through as
typed, with no line discipline, echo, signals or key translation: the host
terminal on the other end of COM1 already sends VT sequences for its keys.

**Replies in the input queue.** The rules that keep a reply from changing
what the client reads as its keys, and where they stop
(`term::server::Input`, host-tested):

| Rule | Why |
| --- | --- |
| A key's bytes are queued as far as they fit, and the rest dropped and counted in MR5 | console splits keys anyway, at whatever its raw queue holds at each `ReadRaw` |
| A reply is queued whole or dropped whole, counted in MR5, never cut short | the first bytes of a reply and the next key typed can read as a key nobody typed: `ESC [` and a typed `A` is Up (`docs/redteam/m8-reply-cut-short.md`). A reply is at most 9 bytes, so a queue with room for one never loses it |
| A reply goes at the queue's end, unless the bytes still queued end in an unfinished escape sequence: ESC alone, or ESC `[` or ESC `O` followed only by parameter and intermediate bytes (`0x20` to `0x3F`), with no final byte yet. Then it goes before that sequence's ESC (`term::server::unfinished`; the last ESC decides), and replies queued there keep their order | a key console brought in two `ReadRaw`s then reaches the client whole, after the reply, rather than cut in two by it (F5, `ESC [ 1 5 ~`, would read as an unknown key, `5` and `~`). These are the sequences tui's decoder waits on ([`tui`](#tui)). ESC alone may be the Escape key, which term cannot tell from a sequence's start; the reply goes before it too |
| Limit: a key whose first part the client has already read is not helped, and a reply queued before the rest comes lands inside the key | those bytes have left the queue, and term has no timer to hold a reply back until the key ends. This is the case whenever the client already waits in `Read` as the key's first part comes, since term releases it at once (host test `a_reply_lands_inside_a_key_whose_first_part_the_client_has_read`). tui never asks DSR or DA |

The input queue belongs to the terminal's one client, not to the screen,
so RIS does not clear it: a client that begins with RIS still reads the keys
and replies an earlier one left unread. term answers a saved `Read` by
`Send` on slot 5 and does not learn whether it reached anyone. If root
suspends the client while its `Read` is saved, the kernel deletes the
reply capability in slot 5 ([Suspend, Resume and
deletion](#suspend-resume-and-deletion)), and the next bytes term
releases are sent to the empty slot and lost, uncounted; only root can
cause it.

| Part | What |
| --- | --- |
| `libsys::proto` | `TERM_WRITE` to `TERM_STATS`, `CONSOLE_READ_RAW` (`0x125`, which replaces `CONSOLE_RAW`), `TUI_REPORT` (`0x131`), `KEYS`, `CONSOLE_RAW_CLIENT` (4), `TERM_CLIENT` (1), `TermSize`, `TermStats` and its `term: stats:` text; `UartStats` gains MR8, uart's burst (15 with working FIFOs, 1 without), for the Hyper-V check, and its text ends `, burst <n>`, so every uart line root prints does |
| `libsys::term::Client` | `write` (split at 952 bytes), `read`, `size`, `stats`, and `core::fmt::Write` |
| `libsys::console::Client::read_raw` | console's `ReadRaw` |
| `libsys::cpu::store_fence` | `sfence`, after a frame's pixel writes and after each of root's timed clears; a sequentially consistent fence under Miri |
| `libsys::vspace` | the `UNCACHED` (3) and `WRITE_COMBINING` (4) attributes words, mapping a 2 MiB frame, and `unmap_table`, `PDPT_Unmap` to `PageTable_Unmap` |
| `libsys::objects` | retyping a named untyped, device untyped included, into frames (`ObjectAlloc::retype_from`) |

The term protocol is not in `docs/abi.md`, for the reason M7's are not: both
ends are in one root image, and `libsys::proto` is its only definition.

### `tui`

`tui` (`user/tui`) is `tui::App`, pure and host-tested, which turns the size
and each key into the bytes of a frame, and `tui::run`, its loop on the
target. Every byte `run` writes to term comes from `App`, the banner and the
goodbye included, so a host test that feeds term `App`'s output renders
exactly what the guest's term was sent. It asks term's `Size`, attaches to
console as `tui` and prints `tui: <cols>x<rows> terminal`; `App::new`
refuses a size outside 80 × 24 to 240 × 75. `App::start` writes `tui:
starting on a <cols>x<rows> terminal` and CR LF on the main screen, enters
the alternate buffer with `CSI ? 1049 h`, clears it with `CSI 2 J`, sets a
block cursor with `CSI 2 SP q` and the log's region with DECSTBM, and draws
its first frame. Then `run` loops: `Read` from term, decode keys, and for
each key a frame, after which it prints `tui: frame <n> drawn: <panel>, item
<k>` through console, as it did for the first. That line goes out only after
term has answered the frame's last `Write`, so when the harness sees it, the
framebuffer holds the frame and nothing will change it until the next key.

| Rows | Columns | What |
| --- | --- | --- |
| 1 | all | title bar: ` microL4 terminal demo` and `<cols>x<rows>`, right-aligned one cell short of the right edge, matching the one blank cell the title starts with; bold bright white on blue, the rest of the row blue through EL (`App::title`) |
| 2 | all | blank, through EL |
| 3 to 10 | 2 to 25 | the menu: a light box with rounded corners in UTF-8, ` Menu ` in bold, items `1 Overview`, `2 Attributes`, `3 Colours`, `4 Boxes`, `5 Keys` and `6 Quit` on rows 4 to 9; the selected one reads ` > <n> <name>`, its whole row inside the box in reverse video |
| 3 to `rows` − 11 | 27 to `cols` − 1 | the open panel: a double-line box in UTF-8, its name in bold, its content inside |
| `rows` − 10 | all | a heavy rule with ` Log ` in faint |
| `rows` − 9 to `rows` − 2 | all | the log, DECSTBM's region: each key appends `key <n>: <name>` at its bottom row, and LF scrolls it; `<name>` is `Up`, `Down`, `Enter`, the digit, or `unknown` and the key's bytes, escaped as `send:` writes them (the first 8, then `...`) |
| `rows` − 1 | all | the prompt `> ` with the cursor, a visible block, after it |
| `rows` | all | the status line in reverse video: ` Up/Down j/k: move  Enter: open  1-6: jump  q: quit`, and `frame <n>` right-aligned one cell short of the right edge, as the title's size is (`App::status`) |

| Panel | Content |
| --- | --- |
| Overview | what the demo is, the threads and their priorities (root 255, watch 255, uart 200, console 150, term 125, tui 100), the size in cells, how keys reach it, and one line with a word in each of bold, faint, underline, inverse and a colour |
| Attributes | a line per SGR attribute, on and off, and combinations; italic and blink labelled as drawn upright and steady |
| Colours | colours 0 to 15 as swatches labelled in a contrasting foreground, and as text; the 216-colour cube as six rows of 36 cells; the 24 greys; 24 true colours from red to blue, as mapped; text in 256 and true colours |
| Boxes | light, heavy, double and rounded boxes, their junctions, the block elements and shades, and one box drawn in DEC Special Graphics (`ESC ( 0` ... `ESC ( B`) |
| Keys | the key table below |

Every row but the log's is drawn whole each frame, from its first column to
its last, row 2 and the margins between and beside the boxes included, with
the cursor hidden (DECTCEM reset) until the frame ends at the prompt, and
term's renderer draws only what changed; the log is only appended to, so
the region's scrolling runs on the machine too. Every byte tui writes
depends only on the size and the keys typed, and tui uses only sequences
term acts on, so term's ignored count stays 0: CR and LF; CUP, EL and ED 2;
SGR, every row of its table but 6, 21 and the ignored forms; DECSTBM;
DECTCEM and DECSCUSR; `?1049`; and SCS `ESC ( 0` and `ESC ( B`. A frame
goes out in `Write`s of at most 952 bytes, each drawn as term answers it,
so a viewer may glimpse a frame half drawn; the screendumps never do. The
layout needs 80 × 24 cells, which `fb` guarantees.

| Bytes | Key | Effect |
| --- | --- | --- |
| `ESC [ A`, `ESC O A`, `k` | Up | the selection moves up, stopping at item 1 |
| `ESC [ B`, `ESC O B`, `j` | Down | the selection moves down, stopping at item 6 |
| CR, LF | Enter | each of them: opens the selected panel; on Quit, quits. So CR LF is two Enters |
| `1` to `6` | | selects that item and opens it |
| `q` | | quits |
| any other | | logged as an unknown key |

The decoder (`tui::Decoder`) is a function of the byte stream: ESC followed
by `[` or `O` and a final byte (`0x40` to `0x7E`), with any parameter and
intermediate bytes (`0x20` to `0x3F`) between, is one key, Up or Down for
`A` or `B` with nothing between, else an unknown key; ESC followed by
anything else is dropped and the byte after it decoded afresh; so is a
sequence cut short by any other byte, a control, DEL or a byte from `0x80`,
which is how a second ESC starts a new sequence; a sequence unfinished at
the end of a `Read` waits for the next. Quitting writes `CSI r`, giving the
whole screen back as the region, which the buffers share, then `CSI ? 1049
l`, so the main buffer and its cursor come back, then `tui: bye after <n>
keys` and CR LF on the main screen below the banner; prints `tui: quit
after <n> keys`; and reports to root with a `Call` on D, label `0x131`,
carrying the first 255 bytes it read from term as a byte string, those of
the quitting `Read` after the `q` included. Root never answers, so tui
stays blocked there. A fault
arrives on the same capability with a fault label, 1 to 5, so root tells the
two apart by the label, as in `test=console`.

### Golden tests

**term's goldens.** Each case is a text file under `user/term/golden/<group>/`
with the extension `.golden`, written to be read and written by hand:

```text
# CUP counts from 1; a print into the last column sets the pending wrap,
# and the next print wraps first.
size: 10x3
input: \e[1;9H\e[1;31mab
input: c
screen:
|        ab|
|c         |
|          |
attrs:
|        RR|
|R         |
|          |
key: R = bold fg 1
cursor: 2,2
```

| Line | Meaning |
| --- | --- |
| `#` | a comment, at the top |
| `size: <cols>x<rows>` | the terminal's size |
| `input: <text>` | bytes, unescaped as `send:` is ([The harness](#the-harness)): `\e`, `\r`, `\n`, `\t`, `\\` and `\xHH`; ends trimmed, so an end space is `\x20`. Lines go in order, each one `Write` |
| `screen:` | then `rows` lines, each `\|`, the row's `cols` cells and `\|`; a blank cell is a space, any other cell its code point, in UTF-8 |
| `attrs:` | then `rows` lines of the same shape: a space for a cell with the default colours and no attribute, any other character a key; without `attrs:`, every cell is default |
| `key: <c> = <words>` | what key `c` means: `fg <n>`, `bg <n>` (`n` 0 to 255; a missing colour is the default) and any of `bold`, `faint`, `italic`, `underline`, `blink`, `inverse`, `conceal` and `strike` |
| `cursor: <row>,<col>` | the cursor, from 1, then optionally `hidden`, `wrap` (pending) and `underline` or `bar` |
| `buffer: alternate` | the alternate buffer is active; the main otherwise |
| `reply: <text>` | the bytes queued for the client, escaped as `input:`; none otherwise |
| `title: <text>` | the title's bytes, escaped as `input:`; empty otherwise |
| `ignored: <n>` | sequences ignored; 0 otherwise |
| `modes: <words>` | the modes away from their defaults that no other line shows, in this order: `insert` (IRM), `newline` (LNM), `cursor-keys` (DECCKM), `reverse` (DECSCNM), `origin` (DECOM), `no-autowrap` (DECAWM reset) and `keypad` (DECKPAM); none otherwise |
| `region: <top>,<bottom>` | a scroll region other than the whole screen, from 1; the whole screen otherwise |

`size:` (1 to 240 columns by 1 to 75 rows), `screen:` and `cursor:` are
required. A case without one of them, a grid row of the wrong width, a key
used in `attrs:` but not defined, or a line of no kind above is an error
that fails its group, so no case passes by leaving its expectation out; a
case of only its comment, `size:` and `input:` lines fails too, until
`MICROL4_BLESS=1` fills it in. Every line left out has the stated default,
which is checked.

`user/term/src/tests/golden.rs` runs every case four ways: one `Write` per
`input:` line, all of it in one `Write`, one byte per `Write`, and split at
points drawn from a generator seeded with the file's name. Each run must
give the expected state, and after each run the frames drawn after every
`Write` must equal a full render of the final state, both as looks and as
the pixels the renderer draws with the font on a `Surface` over a host
buffer. So each case checks the parser's independence
from write boundaries and the renderer's damage as well as the model. The
test runs one group per `#[test]`, reports every failing case with a
side-by-side diff of its grids, and is skipped under Miri, which cannot read
files.

| Group | At least | Covers |
| --- | --- | --- |
| `parser` | 60 | every state's bytes and exits from the table above, C0 inside sequences, CAN and SUB, ESC inside a sequence, parameter and intermediate limits, the private markers, DCS, OSC (ST and BEL) and SOS/PM/APC strings, unknown finals |
| `utf8` | 25 | one to four bytes, every ill-formed kind, cut short by controls, across writes |
| `print` | 25 | autowrap and the pending wrap, DECAWM off, a wrap at the region's bottom, IRM, REP |
| `cursor` | 35 | each movement, its stops in and out of the region, DECOM, BS, CR, HT |
| `erase` | 25 | ED, EL and ECH in every form, with BCE |
| `edit` | 25 | ICH, DCH, IL and DL, inside and outside the region |
| `scroll` | 30 | IND, RI, NEL, LF at the bottom, SU, SD, DECSTBM's rules |
| `tabs` | 12 | HT, HTS, TBC, CHT, CBT |
| `sgr` | 40 | every attribute on and off, 16, 256 and true colours, the mapping, malformed 38 and 48, reset, combinations |
| `modes` | 25 | DECTCEM, DECSCNM, DECOM, LNM, the four alternate-buffer modes, DECSC and DECRC per buffer, RIS, DECALN, DECSCUSR |
| `charsets` | 8 | DEC Special Graphics in G0 and G1, SO and SI, its whole table |
| `reports` | 6 | DSR 5 and 6, with DECOM and with the pending wrap, DA |
| `programs` | 6 | realistic output of programs, beyond the note's twelve groups |
| total | 322 | |

As built the groups hold 479 cases. A group's `#[test]` also fails with
fewer cases than its minimum, and `every_group_directory_is_tested` fails a
directory under `golden/` that no test runs, so a case deleted by mistake
shows. The test writer writes them from this note alone, without reading the
implementation, as PLAN.md's role says, and the reviewer reads them: a case's
grids show what the screen must look like. `MICROL4_BLESS=1 cargo xtask test`
rewrites the expected lines of each failing case whose four runs agree from
the result, keeping its comment, `size:` and `input:`, and naming keys in the
order cells first use them, with the letters the case already gave a key of
the same meaning; it is for intended changes, and the commit's diff of the
cases is what the reviewer checks.

Beside the goldens: a proptest of random byte streams, weighted toward ESC,
`[`, digits, `;`, finals and UTF-8 lead and continuation bytes (512 cases of
up to 4 KiB), checking that nothing panics, the cursor and every write stay
in the grid and the region rules hold, the four ways of writing agree, and
damage equals a full render
(`random_streams_keep_the_invariants_however_they_are_split`, in
`user/term/src/tests/props.rs`, with `rep_acts_as_its_count_of_prints`
beside it); a test that walks every state and every byte `0x00` to `0xFF`
through the parser against a transcription of the table above, written in
the test, not taken from the parser
(`every_state_and_byte_follows_the_table`, `tests/table.rs`); and the
renderer's pixel tests, one per row of its table, against hand-drawn 8×16
cells (`tests/render.rs`).

**tui's goldens.** `user/tui/golden/<name>-<cols>x<rows>.golden` holds, in
the same format, the screens of every panel at 160 × 50 and the scenario's
three moments (below), `main`, `colours` and `quit`, at 160 × 50 and
128 × 48, with `keys:` lines in place of `input:`: each one `Read`'s bytes,
which `App` turns into frames after its start. `user/tui/src/tests/golden.rs`
(`the_panels_and_the_scenario_s_moments`) feeds `App`'s whole output to
`term::Terminal` in the `Write`s `run` makes, at most 952 bytes each, and
term's screen must be the file's, `modes:` and `region:` included, with
nothing ignored after any frame. The same bytes also go through a reference
model of the sequences tui writes (`user/tui/src/tests/screen.rs`), written
apart from term, which panics on any sequence tui may not send and must leave
the same screen; `MICROL4_BLESS=1` rewrites a failing case from term's
screen, but never one the two models disagree on.

**The screendump goldens.** xtask's host test
`tui_screendumps_are_the_host_render` (`xtask/src/hostrender.rs`) makes each
screendump's golden image without QEMU. For each of the three moments,
`tui-main`, `tui-colours` and `tui-quit` (`hostrender::MOMENTS`), it starts
term as the guest's term starts (`term::Session::start` on an `fb::Surface`
over a BGR host buffer), writes it `App`'s output up to that moment in the
`Write`s tui's `run` makes (the banner, the frames for the keys typed by
then and, for `tui-quit`, the goodbye), requires that term ignored nothing,
owes tui no reply and drew by damage exactly what `render::full` draws,
converts the pixels to RGB and compares them, exactly, with the
golden: at 1280×800 with `tests/qemu/golden/<name>.png`, which the `tui`
scenario's `screendump:` compares the guest's screen with, and at 1024×768
with `tools/hyperv/golden/<name>.png`, for the Hyper-V check (the harness
allows only goldens a QEMU scenario takes in `tests/qemu/golden/`). It lives
in xtask because xtask's PNG code (`xtask/src/screen.rs`, on `miniz_oxide`)
reads and writes every golden image; `fb`, `term` and `tui` are its
host-only dev-dependencies. A golden passes only if its pixels are the host
render's and its `Source` text is `microL4 host render`. Otherwise the test
fails, keeping the host render, and a difference image where the sizes
agree, under `target/xtask/host-render/`; `MICROL4_BLESS=1` instead writes
each such golden through that encoder (a palette at 256 colours or fewer),
with that `Source` text in place of QEMU's version. So a change that changes
the screen changes the PNG in the same commit, and the reviewer sees the new
image in the PR. The guest's screen is thus compared with an image only the
host drew: `cargo xtask test tui --bless` leaves a golden whose `Source`
names the host render as it is and fails, and a QEMU capture put there any
other way fails this host test, which requires the host render's `Source`
as well as its pixels, so QEMU cannot bless itself. `--bless` stays for goldens no host model can draw,
such as `screendump`'s `ovmf`, OVMF's own screen. Beside it,
`the_moments_are_the_scenarios_screendumps` checks that the moments are the
screendumps of `tests/qemu/tui.scenario`, which pins 1280×800, and of
`tools/hyperv/m8-tui.scenario`, and that `tools/hyperv/golden/` holds
nothing else; `the_host_render_fills_the_framebuffer_and_its_margins` checks
the grid and the margins at both sizes and at one that is not whole cells.

### Scenarios

**`tui`** (`cmdline: test=tui`, the selftest kernel, `qemu_args: -vga std
-global VGA.xres=1280 -global VGA.yres=800`, which pins the screen at the
size OVMF otherwise takes from the std VGA's EDID by default, so the
goldens' size does not rest on QEMU's default). Root prints its
summary, starts `watch`, uart and console, attaches as client 1, points its
output at console, checks the framebuffer and prints its `fb:` line, runs
the write-combining check, starts term and tui and prints `servers: term
and tui started; root CNode <k> of 4096 slots used`. It then shows every
framebuffer frame it holds mapped, and prints the priorities it set with
the MCPs it reads back, below; then it waits on D. The scenario
(`tests/qemu/tui.scenario`) expects:

```text
expect: root: cmdline "test=tui"
expect: fb: 1280x800 BGR, stride 1280, 4000 KiB at 0x80000000: 6 untyped, 1 2 MiB and 488 4 KiB frames; 160x50 cells
expect: fb: full clear: uncached
expect: servers: term and tui started; root CNode
expect: fb: all 489 frames are mapped: a second Frame_Map of each is refused as mapped, and a Frame_Remap without read for its rights
expect: servers: priority as set, MCP as read back: console 150, 150; term 125, 125; tui 100, 100
expect: tui: 160x50 terminal
expect: tui: frame 1 drawn: Overview, item 1
screendump: tui-main
send: \x144                        # Ctrl-T 4: focus term
expect: [console] focus 4 (term)
send: \e[B\e[B\r                   # Down, Down, Enter
expect: tui: frame 4 drawn: Colours, item 3
screendump: tui-colours
send: q
expect: tui: quit after 4 keys
expect: tui: read 8 bytes: \e[B\e[B\rq
expect: term: stats:
expect: , 0 ignored,
expect: , 0 dropped
expect: root: the TUI has quit; Ctrl-T 1 and Enter end the test
screendump: tui-quit
send: \x141\r                      # Ctrl-T 1, Enter: root's line
expect: [console] focus 1 (root)
expect: TEST PASS
expect: DEBUG HALT 0 from TCB
forbid: TEST FAIL
```

On QEMU the lines read, for example, `fb: full clear: uncached 1082 us,
write-combining 927 us`, `servers: term and tui started; root CNode 1407 of
4096 slots used` and `term: stats: 35394 bytes written, 41 frames drawn,
4291 cells drawn, 0 ignored, 8 bytes from console, 0 dropped, 0 reply bytes
queued`; tui also prints frames 2 and 3, for the two Downs.

Root checks that tui read exactly the bytes the harness typed for client 4,
the focus keys excluded (`root::check::tui::report`), and prints them from
tui's report as `tui: read <n> bytes: <bytes>`, escaped as `send:` writes
them; asks term's `Stats`, prints them on one `term: stats:` line and
requires (`check::tui::stats`) no sequence ignored, no byte dropped, exactly
the 8 typed bytes from console, no reply bytes queued, and at least 6
frames, some bytes and some cells; and, after the line that names the last
screendump, reads one line as client 1 so the run waits for it. The
three images are the main screen, the Colours panel after two moves and
Enter (the menu highlight moved, the panel replaced, three log lines
scrolled in), and the main buffer after quitting, with the banner kept while
the alternate buffer was in use and the goodbye line below it. Each is
compared with the host render of the same moment ([The screendump
goldens](#golden-tests)).

The screen holds still from the line each screendump follows until the
`send:` after it. term clears the whole visible area before it draws
anything, so nothing the firmware or the write-combining check left
survives, and it draws only in answer to a `Write`: there is no timer
redraw, no blinking cursor or text, and nothing on screen counts time. Each
line the screendumps follow is printed only after term has answered the
`Write` that ended its frame, and each image is taken while every thread
that could draw is blocked: tui in term's `Read` or in its report, term in
its receive, root on D or in console's `Read`; keys, the only thing that
moves them, come from the `send:` the harness writes after the image is
taken.

**The frames' mappings and the priorities.** Once term runs, root probes
each framebuffer frame it holds twice, in `docs/abi.md`'s order of checks,
which change nothing when they refuse: a second `Frame_Map`, into root's
VSpace at `fb::WINDOW` + 1, which no frame size divides, must be refused
with `InvalidCapability` 0, which the kernel checks before the alignment
(an unmapped frame would be an `AlignmentError`); and a `Frame_Remap`
asking no read right must be refused with `InvalidArgument` 0, which the
kernel checks only after finding the frame mapped (an unmapped frame is
`IllegalOperation`, and an empty slot `InvalidCapability` 0 to both, so this
probe also tells a frame from no capability). `root::check::tui::mapped`
decides; root prints `fb: all <n> frames are mapped: ...` or fails with
the frame and both results. The probes show that each frame is mapped
somewhere, not where: that the one mapping is in term's VSpace rests on
`start_terminal` and review. No invocation reads a priority back, so root
prints console's, term's and tui's as it set them, with each MCP read back:
`TCB_SetPriority` of the thread to 256, with itself as the authority, is
refused with a `RangeError` from 0 to that MCP and changes nothing.
`check::tui::priorities` requires each MCP equal to its priority and
console above term above tui.

**`term_fault` and `tui_fault`** (review; `cmdline: test=term_fault` or
`test=tui_fault`, the selftest kernel, the `tui` scenario's `qemu_args:`).
Root starts everything as `test=tui` does, then reads a line as client 1,
which has focus; the harness sends `\r` once `tui: frame 1 drawn` has
matched, when tui waits in term's `Read` and term in its receive. Root
prints `<test>: suspending <thread>, setting its rip to 0 and resuming it`,
syncs, then suspends the thread, writes its `rip` 0 with
`TCB_WriteRegisters` and resumes it. Its next fetch, from page 0, which no
VSpace maps, is a `VMFault`: ip 0, address 0, a fetch, error code `0x14`.

| Scenario | Root then | The fault | The run ends |
| --- | --- | --- | --- |
| `term_fault` | calls term's `Stats`, so it waits in a call to the dead term | on F with badge 3 | `watch`'s `TEST FAIL: term fault 5 (VMFault), MR0 to MR3 0x0 0x0 0x1 0x14` through `Polled`, then `DebugHalt(1)` |
| `tui_fault` | waits on D for tui's report, as `test=tui` does | on D with badge 5 | root's `TEST FAIL: tui fault 5 (VMFault), MR0 to MR3 0x0 0x0 0x1 0x14` through console, then `exit(1)`: a `Sync` and `DebugHalt(1)` |

Each expects root's line, then with `next:` the failure line whole and the
halt's two lines (`dispatch: invocations preempted and restarted:` and
`DEBUG HALT 1 from TCB`), so nothing is printed between them, and the
run's failure status. Each forbids root's lines for the fault that did not
come (`term answered Stats after its rip was set to 0`, `watch did not end
the run`, `tui reported after its rip was set to 0`), `tui: frame 2`, which
tui would print after any further frame, and `TEST PASS`. Neither takes a
screendump: no golden shows these moments, and the run ends at the halt.

**`nofb`** (`cmdline: test=nofb`, `qemu_args: -vga none`). OVMF finds no
display, the loader passes no framebuffer, and root prints `fb: none: the
loader found no GOP framebuffer`, starts no term and no tui, prints `nofb:
type a line` and reads one. The harness sends `\x144abc\e[A\x141hi\r`: the
bytes for client 4 wait in its raw queue with nothing reading them, and the
line reaches root, which prints `nofb: read "hi"` and `TEST PASS`. Nothing
attached as client 4, so the scenario expects `[console] focus 4 (client 4)`
before `[console] focus 1 (root)`, and ends with `DEBUG HALT 0 from TCB`.

**`release`**: every line root prints of uart's `Stats`, `test=release`'s
and `test=console`'s, ends `, burst <n>`, from MR8, and the scenario expects
`, burst 15`. `test=release` starts no term, so the `screendump` scenario's
golden `ovmf`, which shows what OVMF left on the screen during that test,
stays valid.

**What the scenarios take from the harness.** `screendump:` is in xtask
(4d9d067, [The harness](#the-harness)); the `tui` scenario relies on this of
it, and on one rule its goldens added:

| Behaviour | Why it matters here |
| --- | --- |
| `screendump: <name>` is a step right after an `expect:` or `next:` (a parse error otherwise): the screen is taken once that step has matched and before any later `send:` is written, and compared when the boot has ended | the guest is still only between the line above and the `send:` below |
| QEMU runs with `-display none` and QMP on a loopback port xtask listens on, since stdin is COM1, and with `-parallel none`; QMP's `screendump` of q35's std VGA follows the guest's writes and is deterministic once the loader runs (`tests/qemu/screendump.scenario`) | PLAN.md's first check, answered ([Open questions](#open-questions)) |
| the image is compared with `tests/qemu/golden/<name>.png`, one size per scenario; a name belongs to one scenario; a screen of another size fails, saying that the sizes differ | the `tui` goldens are 1280×800, pinned by its `qemu_args:`; another size fails loudly rather than comparing against the wrong image |
| exact: every pixel's red, green and blue equal, with no tolerance or mask | the guest writes exact palette colours, QEMU's 32-bit surface keeps them, and nothing scales or blends |
| a mismatch reports how many pixels differ and their bounding box, and keeps `<name>.png` and `<name>.diff.png` (the golden dimmed, differing pixels magenta) beside `serial.log` | the box's corner divided by 8 and 16 is the first cell to look at; the images show the rest |
| `--bless` leaves a golden whose `Source` text is `microL4 host render` as it is and fails the scenario, saying the golden is the host render's (`bless_leaves_a_host_render_golden_as_it_is`) | the `tui` goldens come from the host render only ([The screendump goldens](#golden-tests)); [The harness](#the-harness) names that host test as the one other writer of a golden |

### The Hyper-V check

CI uploads `microl4-vhdx-m8-check`: `tui/disk.vhdx` (`test=tui`, the
selftest kernel), `release/disk.vhdx` (`test=release`, the release kernel),
the 1024×768 goldens (`tools/hyperv/golden/`), and
`tools/hyperv/m8-tui.scenario` and `m8-release.scenario`: the QEMU
scenarios' steps with what differs on Hyper-V, the sizes (1024x768, 128x48)
and frame counts in the `fb:` line, which the GOP's size decides, and
`release`'s exit port, which root issues only under QEMU. xtask parses both
(`the_moments_are_the_scenarios_screendumps`). `Test-L4Vhdx.ps1` gains
`-Scenario <file>`, which follows its `expect:`, `next:`, `send:` and
`forbid:` lines over the named pipe, as xtask's matcher does, and, at each
`screendump:`, saves the VM's screen through Hyper-V's thumbnail API
(`Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage` at
1024×768) as `l4-<name>.png`, keeping the bytes the API returned beside it
as `l4-<name>.rgb565`; a screen it cannot save fails the run, which goes
on to the end so that the log is whole. `-ConnectAfterSeconds <n>` starts
the VM and opens the pipe only after `n` seconds; with `-Scenario`, the
script then follows the steps from the `expect:` right above the first
`send:`, whose line may have been printed with no client on the pipe: it
types that `send:` when its own line arrives or, if it never does, once no
line at all has come for 10 seconds, and requires the steps after it. A
transmitter that drains has dropped that line, and the root task, waiting
in its `Read`, prints nothing more; one that waits sends what it held as
soon as the pipe connects, and the boot's quiet stretches after that, the
release kernel's own start the longest, should be far shorter (the whole
`release` scenario takes about 2 seconds on QEMU's TCG). The script then
prints how many of the `expect:` lines above that `send:`, from the first
that starts `root: cmdline`, arrived, each counted wherever it comes: those
are uart's, which waits for THRE interrupts and loses nothing, while the
loader's polled writes give up after 100,000 polls a byte
(`loader/src/serial.rs`), so its lines are lost by a transmitter that waits
as well. `Read-L4Com1.ps1` takes the script's three callbacks, one when
the pipe connects, one per line and one each second with no line, and
writes its log even if one fails. `m8-release.scenario` expects `, burst
1`, which both `burst 15` and `burst 1` match, and forbids `, 0 THRE
bursts`.

| Image | Run | The log must show | It settles |
| --- | --- | --- | --- |
| `tui` | `-Scenario m8-tui.scenario` | `cpu: hypervisor Hyper-V`; `bootinfo: framebuffer 0xf8000000-...`; `fb: 1024x768 BGR, stride 1024, ... ; 128x48 cells` with the GOP's size; `fb: full clear: uncached <n> us, write-combining <m> us`; `tui: 128x48 terminal`; `tui: frame 1 drawn`; `[console] focus 4 (term)` and `tui: frame 4 drawn` after the script's keys; `tui: quit after 4 keys`; `tui: read 8 bytes`; `term: stats:` with 0 ignored and 0 dropped; `TEST PASS`. The owner attaches the three thumbnails, which must match `tools/hyperv/golden/tui-*.png` by eye | the framebuffer found, handed out and mapped write-combining on Hyper-V; WC faster than UC [H10]; keys through the named pipe; Hyper-V's video window showing the GOP framebuffer after `ExitBootServices` |
| `release` | `-Scenario m8-release.scenario`, the script typing the line | uart's line with `burst 15` (working FIFOs) or `burst 1`; `14 bytes received` and the line read whole, though its last 6 bytes stay below the receive trigger of 8, which only the character timeout delivers; THRE bursts above 0 | M7's 16550 questions: FIFOs, the character timeout, THRE interrupts |
| `release` | again with `-ConnectAfterSeconds 20 -TimeoutSeconds 30` (the reader's limit runs from the connect) | the script's `Of the 6 uart lines above the first send: (from 'root: cmdline'), K arrived` line: whether uart's lines written before the pipe had a client arrive once it connects (K = 6, the transmitter waits, and the line is typed when `release: type a line` arrives) or are missing (K = 0, it drains, and the line is typed after 10 seconds with no line), and that the run then goes on to `TEST PASS` | whether a transmitter with no client on the pipe stalls uart's writes |

The API's documentation calls the thumbnail "raw RGB 565", two bytes a
pixel, but gives no byte or row order: the script reads it as Windows'
`Format16bppRgb565` bitmaps are laid out (little-endian words, red in the
top five bits, rows from the top) and keeps the raw bytes in case that is
wrong. RGB 565 keeps 5 or 6 bits a channel, so the check compares by eye;
an exact comparison against the goldens reduced to RGB 565 is an [open
question](#open-questions). The PowerShell has not yet run on a Windows
host.

### Code and tests

| Part | Where | Host tests |
| --- | --- | --- |
| Geometry, pixel formats, the frame plan, the surface | crate `fb` (`user/fb`), `no_std`, `#![forbid(unsafe_code)]`, no dependencies: `Geometry`, `Format`, `Rgb`, `Fields`, `Untyped` and `Unusable` in `lib.rs`, `Plan` and `Retype` in `plan.rs`, `Surface` in `surface.rs` | `user/fb/src/tests.rs`: each row of the checks, in order (`no_format_or_no_base_is_no_framebuffer` to `a_window_past_one_gib_is_too_large`); QEMU's recorded framebuffer, 489 frames under one page table (`qemu_s_framebuffer_is_one_2mib_and_488_4kib_frames_under_one_page_table`), and Hyper-V's at 3, 4 and 8 MiB (`hyper_v_s_framebuffer_at_each_gop_size`); a base not aligned to 2 MiB; the plan stopping at the visible bytes and within the fan-out limit; `random_tilings_keep_the_plan_s_invariants`; `the_words_round_trip_and_are_checked_again`; both pixel formats; the surface's bounds and padding (`fill_writes_every_visible_pixel_and_no_padding`, `cells_are_cut_at_the_right_and_bottom_edges`, `a_surface_needs_its_pixels`) |
| Parser, screen model, palette, looks, font, renderer; term's session; the term protocol, the input queue and the saved `Read`; `term::run`, the loop | crate `term` (`user/term`), `no_std`, `#![forbid(unsafe_code)]`, on `fb` and `libsys`: `parser`, `screen`, `palette`, `look`, `font` (with `font/spleen.rs`, from `tools/spleen.py`), `render`, `session` (`Session`, `Pixels`, `cells`), `server`, and `Terminal`, `layout` and `slot` in `lib.rs`; the parser and the screen model use nothing but `core`; `run` on the target only | `user/term/src/tests/`: the goldens (`golden.rs`), the proptests (`props.rs`) and the parser's table test (`table.rs`) above; unit tests of the parser's limits, UTF-8, the palette and its mapping, cell and look words and each look step (`unit.rs`); the font (`font.rs`): every code point of its table, the arms of every box glyph against its Unicode name, the dashes, the double corners and junctions (U+2554 and U+256C among them) and a heavy corner (U+251B) against hand-drawn cells, light lines meeting double ones, the diagonals and the diamond, the blocks, shades and scan lines, the replacement glyph for every unlisted code point, U+FFFD included, and the Spleen table's checksum against its header; the renderer's pixel tests in both formats, margins and padding, the first frame and damage (`render.rs`); the session's start and frames, and requests decoded and refused in M7's order, `Read` answered at once, saved and released by keys or by a reply, `Busy`, the queue's order and limit (`server.rs`) |
| The raw client | crate `console` | `user/console/src/tests/raw.rs`, goldens for each raw rule: bytes unedited and unechoed, ESC sequences passing whole, the focus keys, Ctrl-T Ctrl-T, Ctrl-T and anything else, the full queue's BEL once per `Read`, `ReadRaw` at once, and the `ReadRaw` and `Read` badges; the proptest `eight_clients_against_a_model_of_their_lines`, whose model gains client 4 and `ReadRaw`, and checks its typed bytes reach the raw queue once, in order, unedited and unechoed |
| The app | crate `tui` (`user/tui`), `no_std`, `#![forbid(unsafe_code)]`, on `libsys`: `App`, `Panel` and the console lines in `lib.rs`, the decoder in `keys.rs`, the sequences in `draw.rs`, the panels in `panels.rs`; `run` on the target only | `user/tui/src/tests.rs`: every key of the table, sequences with parameters, ESC and anything else, `every_split_of_every_sequence_decodes_the_same`, unknown keys' escapes, the size limits, `the_scenario_s_byte_stream`, the report's 255 bytes, `no_frame_uses_a_sequence_term_ignores`, `every_frame_draws_all_but_the_log`, the log's scrolling and quitting; the goldens (`tests/golden.rs`) on term and on the reference model (`tests/screen.rs`) |
| The term protocol in libsys; the fence, attributes, `unmap_table` and retyping a named untyped | `libsys::proto`, `libsys::term`, `libsys::console`, `libsys::cpu`, `libsys::vspace`, `libsys::objects` | `TermSize` and `TermStats` round trips and `term_stats_show_what_the_scenario_matches`; `UartStats`'s text with its burst; `the_queues_match`; `the_store_fence_runs`; `attribute_words_are_the_abis`; `a_named_untyped_device_or_ram_places_at_its_watermark` |
| Starting term and tui; the write-combining check; the mapping probes and the priorities; the fault tests; the verdicts | `user/root/src/servers.rs` (`start`'s NT, `framebuffer_objects`, `FbObjects`, `start_terminal`, whose `Terminal` keeps both TCBs, `term_main`, `TERM_PRIORITY`, `TUI_PRIORITY`), `user/root/src/tui.rs` (`run`, `fault` for `test=term_fault` and `test=tui_fault`, `start`, `mcp`, `write_combining_check`, `tsc`), `user/root/src/nofb.rs`; `root::check::tui` (`user/root/src/check/tui.rs`: `mapped`, `Priorities`, `OnD` among the rest) and `watch`'s line in `root::process` (`Fault`, which root's line for a tui fault shares) | `the_fb_line_on_qemu`, `the_fb_line_on_hyper_v`, `no_framebuffer`, `the_clear_and_started_lines`, `the_probes_show_a_frame_mapped`, `the_priorities_line`, `a_message_on_d_that_is_not_the_report`, `tui_must_report_the_typed_bytes`, `terms_counts`, `nofbs_line`; `watchs_line_for_each_fault`, with badge 3 |
| `screendump:`, the golden images and the host render; the licence on the ESP | `xtask/src/scenario.rs`, `screen.rs` and `qemu.rs` (in xtask from 4d9d067), with `--bless` leaving a host-render golden; `xtask/src/hostrender.rs`, a test module; `xtask/src/image.rs`'s `LICENCES` | `parses_screendumps`, `screendump_names_are_unique_across_scenarios`, `matcher_releases_screendumps_in_step_order`, `checks_screens_against_goldens`, `bless_leaves_a_host_render_golden_as_it_is`, `repo_goldens_are_used_and_read`; PPM, PNG and comparison tests in `screen.rs`; QMP against a fake QEMU in `qemu.rs`; `tui_screendumps_are_the_host_render`, `the_moments_are_the_scenarios_screendumps` and `the_host_render_fills_the_framebuffer_and_its_margins`; `the_spleen_licence_goes_on_the_esp` |

`cargo xtask test` runs the new crates' host tests beside M7's, and `cargo
xtask clippy` lints them for the host and the target. Plain `cargo test`
runs xtask's tests, the host render among them. Every golden image is
read and written by xtask's own PNG code, on `miniz_oxide`; `fb`, `term`
and `tui` are xtask's host-only dev-dependencies. QEMU covers
what the host cannot: device frames retyped and mapped write-combining, 2
MiB device frames, the IPC chain from COM1 through uart, console and term to
tui, and what QEMU's display shows.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Only term's VSpace maps the framebuffer, read-write and write-combining; root maps it in its own VSpace only for the write-combining check, before term exists, and never two mappings of a frame at once; no other thread holds a capability that names a framebuffer frame | `servers::start_terminal` maps `fb::Plan`'s frames, which root keeps (`FbObjects`), into term's VSpace alone (`FbObjects::map_frames` with `WRITE_COMBINING`) and fills term's and tui's CNodes only from the entries it lists against `term::slot` and `tui::slot`, none a frame; `write_combining_check` (`user/root/src/tui.rs`) unmaps every frame after each clear (`FbObjects::unmap_frames`) and the page tables before `start_terminal` maps them again; `Frame_Map` refuses a frame capability already mapped; the `tui` scenario runs it, and once term runs shows every frame root holds mapped: a second `Frame_Map` of each refused as mapped and a `Frame_Remap` without read refused for its rights, which the kernel checks only of a mapped frame (`root::check::tui::mapped`, host test `the_probes_show_a_frame_mapped`; the line `fb: all 489 frames are mapped`); review. That the one mapping is in term's VSpace, and no other thread's capabilities, rest on review | M8 |
| No page is writable in two VSpaces, and no thread M8 adds holds a TCB, VSpace, untyped, paging, frame or Grant capability | as M7's invariant: `root::process::Plan` for the image (host test `m6s_image`) and `fill` against the slot tables, with no Grant in any right `start_terminal` gives; term's state frames retyped fresh and mapped once, in term's VSpace; review | M8 |
| Every pixel term writes lies in the visible area, inside the framebuffer's frames; term never reads the framebuffer | `fb::Surface::fill` and `cell`, which bounds-check against `width` and `height`, and its lack of a read method; `Surface::new`, which needs `stride` × `height` pixels; `fb::Geometry::check`, which requires 4 × `stride` × `height` within `size` and the untyped tiling it, and `Geometry::from_words` in `term_main`; host tests `fill_writes_every_visible_pixel_and_no_padding`, `cells_are_cut_at_the_right_and_bottom_edges`, `a_surface_needs_its_pixels`, `a_stride_alignment_or_size_that_does_not_hold_the_pixels_is_bad_geometry`, `untyped_must_be_device_memory_tiling_the_framebuffer_in_order`, `the_words_round_trip_and_are_checked_again`, and term's `margins_stay_the_default_background_and_padding_is_never_written` | M8 |
| When term replies to a `Write`, the framebuffer shows exactly the screen model's active buffer, cursor included, and the frame's writes have left the CPU's write-combining buffers | `term::Session::write`, which draws `Renderer::frame` and ends with `Surface::fence` (`term::Pixels`: `libsys::cpu::store_fence`) before `term::run` replies; the goldens' check of looks and pixels after every `Write` (`tests/golden.rs`); the proptests `random_streams_keep_the_invariants_however_they_are_split` and `frames_after_random_writes_equal_a_full_render`; `frames_after_each_write_leave_what_a_full_render_leaves`; the host render's check that frames drawn by damage equal `render::full`; the `tui` scenario's screendumps against the host render | M8 |
| Every byte stream is accepted: the parser never panics, takes bounded work per byte, keeps the cursor and every write in the grid, and acts the same however the stream is split into writes | the parser's fixed limits (`MAX_PARAMS`, `MAX_PARAM`, `MAX_INTERMEDIATES`, `MAX_OSC`); the screen model's clamped counts, CHT's and CBT's stop at the edge and REP's `rep_prints`; the proptest `random_streams_keep_the_invariants_however_they_are_split` and `rep_acts_as_its_count_of_prints`; the goldens' four runs; the table test `every_state_and_byte_follows_the_table` | M8 |
| term never blocks except in its receive on T and in calls to console, which always reply at once; it answers its client only by `ReplyRecv` or by `Send` on its saved slot | `term::run` (`user/term/src/run.rs`) receives with `recv` and `reply_recv` on slot 2, sends only on slot 5, and calls only console's `Attach` and `ReadRaw`; console answers `ReadRaw` at once and never saves it (`console::run`; host test `read_raw_takes_everything_at_once_possibly_nothing`); review | M8 |
| Every byte typed while client 4 has focus, but the focus keys, reaches term's client once, in order, unedited and unechoed, unless a queue was full, when it is dropped: with BEL on COM1 in console's queue, counted in term's | console's `Terminal::input` and its raw queue; term's `server::Input`; console's raw goldens (`user/console/src/tests/raw.rs`, `a_full_queue_drops_and_rings_bel_once_per_read` among them) and the proptest `eight_clients_against_a_model_of_their_lines` with client 4; term's `keys_and_replies_queue_in_order` and `bytes_past_the_queues_512_are_dropped_and_counted`; the `tui` scenario, where `root::check::tui::report` requires the 8 bytes tui read and `check::tui::stats` 8 bytes from console and none dropped (host tests `tui_must_report_the_typed_bytes`, `terms_counts`) | M8 |
| Routing stays a function of the byte stream alone, and no client can put an escape sequence on COM1 | client 4 is raw by its number (`console::RAW`; `console::decode` refuses its `Read` and any other client's `ReadRaw`); raw mode changes input only, and console shows client 4's output as every client's (M7's invariants hold unchanged); goldens `only_client_4_reads_raw_and_it_never_reads_lines` and `client_4_has_no_input_line_and_its_output_is_shown`, and the proptest | M7, M8 |
| Priorities: console above term above tui | `servers.rs`'s `TERM_PRIORITY` (125) and `TUI_PRIORITY` (100), set by `spawn_server` with `TCB_SetSchedParams` with an equal MCP; the `tui` scenario's line `servers: priority as set, MCP as read back: console 150, 150; term 125, 125; tui 100, 100`, the priorities as root passed them, since no invocation reads one back, and each MCP read back from the `RangeError` of a refused `TCB_SetPriority`; `root::check::tui::priorities` (host test `the_priorities_line`); review | M8 |
| A term fault ends the run with failure, whatever root waits on, and a tui fault reaches root | term's fault endpoint F, badge `fault_badge::TERM` (3), to `watch`; tui's D (`tui::slot::REPORT`), on which root's `tui::run` fails anything but the report's label and badge, naming a fault as `watch` does (`check::tui::OnD`); host tests `watchs_line_for_each_fault`, with term's line, and `a_message_on_d_that_is_not_the_report`; the review scenarios `term_fault`, where term faults while root waits in a call to it and `watch` ends the run with `TEST FAIL: term fault 5 (VMFault), ...`, and `tui_fault`, where root reports `TEST FAIL: tui fault 5 (VMFault), ...` from D and fails, each followed by nothing but the halt; review for the other states a fault can come in and for a term panic | M8 |
| What the screen shows depends only on the framebuffer's size and the bytes typed | `tui::App` is pure; term draws no time, address or count; no cursor blink and no timer redraw; tui's goldens at both sizes (`the_panels_and_the_scenario_s_moments`) and `the_scenario_s_byte_stream`; the screendumps, which equal the host render | M8 |
| The font's glyphs come from Spleen, whose licence notice travels with the source and the image, or are generated in the repository | `tools/spleen.py`, which takes the pinned tag's BDF and `LICENSE` only if their SHA-256s match; `user/term/src/font/spleen.rs`'s header and `LICENSE-spleen`; `xtask::image::LICENCES`, which puts it on the ESP as `\licenses\spleen.txt`; host tests `the_spleen_table_matches_its_header` and `the_spleen_licence_goes_on_the_esp` | M8 |

### Compared with seL4

seL4 has no framebuffer, font, terminal or console. The rows compare the
mechanisms microL4 uses and the seL4 ecosystem's usual structure, from
memory.

| seL4 ecosystem | microL4 | Reason |
| --- | --- | --- |
| A device untyped retypes only into frames, and x86 frames take a write-combining attribute (`seL4_X86_WriteCombining`, PAT entry 4 in `init_pat_msr`) | the same: the framebuffer's device untyped become frames mapped `WriteCombining` | no divergence |
| sDDF has device classes for serial, network, block and I2C, with drivers and virtualisers sharing memory through queues, and no display class | term draws the pixels itself; its client passes bytes in messages | one client at a terminal's bandwidth needs no shared queues |
| Genode, which runs on seL4 among other kernels, has a terminal component that serves a Terminal session and draws it through a framebuffer or GUI session | term is the same shape without the GUI layer: one server owns the parser and the pixels, and its client gets a terminal session | one display client; no compositor to share the screen |

## Open questions

Each question has a default that this note and `docs/abi.md` already assume,
and the milestone that must confirm or change it. A question a milestone has
answered stays in the table with its answer in the last column. Changing a
default that touches the ABI needs an ADR. Sorted by milestone.

| Question | Why it matters | Answer in | Default, or answer |
| --- | --- | --- | --- |
| Should nested CNodes found while destroying a CNode be cleared, rather than left unreachable until their untyped is revoked? | seL4's behaviour keeps the objects their slots name alive, which can leak memory when a process tree is not torn down leaves first | M2 | Keep seL4's behaviour; `root` tears down CSpaces leaves first or revokes the covering untyped |
| Does the owner's Hyper-V VM report SMEP, SMAP and XSAVE? | Without them the kernel refuses to boot ([Privilege levels](#privilege-levels)) | M3, first Hyper-V check (answered) | Answered at the M3 Hyper-V check (2026-10-30): yes, with processor compatibility mode off. The kernel passed `check_cpu` and booted to `TEST PASS` |
| Does Hyper-V's Generation 2 firmware, or OVMF under `-cpu max`, hand over in x2APIC mode? | The kernel is xAPIC-only and leaves x2APIC through the disabled state; that path otherwise never runs in a test | M3 (answered) | No on both. OVMF hands over in xAPIC mode, `IA32_APIC_BASE` `0xfee00900` (the `hello` scenario), and TCG's `-cpu max` does not offer x2APIC even with `x2apic=on`. Hyper-V's firmware also hands over in xAPIC mode (`0xfee00900`), though its CPUID offers x2APIC (the M3 Hyper-V check). So the x2APIC exit path has run on neither platform; only the `l4core::apic` host test covers it |
| Does Generation 2 Hyper-V set `PCAT_COMPAT`, and does it have an 8259 PIC, a PIT and an HPET? | Decides whether the PIC is touched, and confirms the reference counter is the only timer reference there | M3 Hyper-V check (answered) | Answered at the M3 Hyper-V check: the MADT flags are 0, so the kernel leaves the 8259s alone, and there is no HPET table, so the timer calibrates against the reference counter. Whether a PIT exists was not checked; nothing uses one. The tables are FACP, OEM0, WAET, APIC, SRAT and BGRT: no MCFG, so no ECAM |
| Does the Generation 2 firmware leave the hypercall page, SIMP, SIEFP, reference TSC page, VP assist page or synthetic timers enabled, or the hypercall MSR locked, at `ExitBootServices`? | An overlay left on over `USABLE` memory corrupts whatever M4 retypes there; a locked hypercall MSR removes the Hypervisor capability | M3 Hyper-V check (answered) | Answered at the M3 Hyper-V check: only SCONTROL was left enabled (`0x1`), and the kernel turned it off. The hypercall page, SIMP, SIEFP, the reference TSC page, the VP assist page, the four synthetic timers and the time-unhalted timer were all off, and no SINT was unmasked. The hypercall MSR read `0x0`: neither enabled nor locked |
| Should the timer read `HV_X64_MSR_APIC_FREQUENCY` instead of calibrating, when Hyper-V allows it? | It gives the exact rate with no measurement | M3 Hyper-V check (answered) | Keep calibrating against the reference counter, as PLAN.md says, and print the MSR as a cross-check. At the M3 Hyper-V check the calibrated LAPIC rate, 200,001,000 Hz, was 5 ppm from the MSR's 200,000,000 Hz, and the TSC 57 ppm from its MSR, so the two agree well inside the 1% the timer needs |
| How long are the calibration windows, and how close must the rate be? | Too short a window gives a wrong rate; too long slows every boot | M3 (answered) | Answered in M3: three 20 ms windows, median, for the local APIC timer and the TSC, with each reference read bracketed by a LAPIC and a TSC read; QEMU's 1 GHz APIC clock calibrates to within about 30 ppm. The `ticks` scenario requires 1% over ten ticks, each dated by the timer's reload ([The timer](#the-timer)) |
| Is 8 KiB enough for a fatal handler's panic report on its IST stack? | An overflow of the #DF stack ends in a second #DF over the first, with the report cut short | M3 (answered) | Answered in M3: yes. The `double_fault` scenario's #DF report used 1,872 bytes of IST1's 8,192 in the dev profile and 1,904 in release, so no fixed-format writer is needed ([Static kernel memory and the boot region](#static-kernel-memory-and-the-boot-region)) |
| Is 4 KiB the right chunk for clearing an untyped between preemption points? | seL4 clears 256 bytes per preemption point; 4 KiB under TCG may take tens of microseconds | M4 on QEMU (answered); Hyper-V (open) | Answered on QEMU in M4: keep 4 KiB with an IRR read after each chunk, and no work-unit counter. Under TCG, `test=retype`'s second run, which clears again the 4 MiB of U the first run used, is the steady state: a 4 KiB chunk and its poll take about 4.5 µs on average, and the longest stretch between two polls is 48 to 278 µs in the dev profile and 49 µs in release. In the first run, which touches U's 64 MiB for the first time, a slow stretch comes every 512 polls, once per 2 MiB, and the longest is 13.6 to 63.7 ms in dev and 8.8 ms in release: the host faulting in guest RAM, which a smaller chunk would not shorten. Nothing points at the chunk size. Still open for Hyper-V, which has not been measured; every image has the self-tests, so `test=retype` runs there unchanged |
| Are boot-created objects (root CNode, TCB, VSpace, BootInfo) covered by an untyped? | If they are, revoking that untyped destroys the root task; if not, their memory is never reclaimed | M4 (answered) | Answered in M4: as seL4, they come from the boot region, outside every untyped, and their capabilities are derivation roots. `check_untyped` and `test=bootinfo` check that no untyped covers the region, and `check_root_cnode` that every boot capability is an original at depth 0 with no links |
| Are 448 untyped descriptors enough? | Boot panics if not | M4, from the recorded QEMU and Hyper-V memory maps (answered) | Answered in M4: yes, by several times on both targets. At every physical address width from 36 to 52 bits, QEMU's recorded map gives 106 to 148 untyped, 342 to 300 below 448, and Hyper-V's 73 to 115, 375 to 333 below ([Untyped](#untyped)). If a machine needs more, BootInfo grows to four pages as version 2 |
| What if the framebuffer shares a 2 MiB page with RAM-like memory? | It could not be device untyped without aliasing the write-back direct map, so `fb` could not run | M4 (answered) | Answered in M4: no untyped covers it, `framebuffer_untyped` is empty, BootInfo's `framebuffer` still describes it, and the boot summary prints a `bootinfo: warning:` line with the reason (host test `framebuffer_sharing_a_2mib_page_with_ram`). Not seen: QEMU's framebuffer at 2 GiB gets 6 device untyped, and Hyper-V's at `0xF8000000` 2 on the recorded map |
| Does a `syscall` executed with RFLAGS.TF set raise `#DB` on the first kernel instruction? | Any thread can set TF; the `#DB` handler returns only when RIP is exactly `syscall_entry`, and a trap anywhere else in ring 0 panics | M5 on QEMU and Hyper-V (answered) | Answered in M5: no, on QEMU and on Hyper-V. `test=ring3` runs a `syscall` with TF set and counts no ring-0 #DB; `sysretq` restores TF, and the thread traps at the return address before its next instruction runs. The RIP special case stays as insurance. At the M5 Hyper-V check `test=ring3` step 12 counted 0 as well. For `mov ss` with TF set the answer differs: Hyper-V defers the step past `int3` into ring 0 (`test=redteam-movss` probe 1, `0x3/0x0`), which the kernel now returns from; `int n` drops it and `int1` folds it into one ring-3 #DB ([NMI, double fault, machine check and debug](#nmi-double-fault-machine-check-and-debug)) |
| Does an unmasked SIMD exception raise #XM with CR4.OSXMMEXCPT set? | QEMU's TCG raises no SIMD exception, so the #XM path, UserException 19, had not run | M5 Hyper-V check (answered) | Answered at the M5 Hyper-V check (2026-11-22): yes. `test=ring3` step 9 takes #XM, vector 19, for a `divsd` by zero with ZM clear, and step 10 reads MXCSR `0x1d84` with ZE set; on QEMU the same `divsd` only sets ZE ([FP exceptions](#fp-exceptions)) |
| Is `swapgs` worth keeping on one core? | seL4's uniprocessor build avoids it and a class of mistakes with it | M5 (answered) | Answered in M5: kept, for the multi-core stretch goal. `swapgs` runs once per entry from ring 3 and once per exit, the IST handlers never read GS, and `test=ring3` checks `IA32_GS_BASE` at every entry from ring 3 |
| Which register is a cancelled thread's restart point? | Cancelled threads become `Restart` and re-execute `syscall`; IPC relies on their argument registers being untouched | M5 (answered) | Answered in M5: `fault_ip`, the saved user `rcx` minus 2, the length of `syscall` (`l4core::entry::save`); `tcb::activate` sets `next_ip` to it when a `Restart` thread next runs. IPC writes a blocked thread's registers only on completion (host tests in `core/src/ipc/tests.rs`) |
| In what order are each invocation's errors checked? | The M10 fuzzer's model needs it | M5 (answered) | Answered in M5: the order `docs/abi.md` lists them in, with the label first; the TCB invocations that install capabilities check seL4's order (buffer, long-running delete, CSpace root, VSpace root) before any slot changes. The other choices the ABI leaves open are in [Invocations](#invocations); host tests check every error row of the TCB and paging invocations in order |
| Enable AVX? | It costs 256 more bytes of save and restore per switch and makes behaviour differ between hosts | M5 (answered) | Answered in M5: no; XCR0 is `0x3` (QEMU's `-cpu max` offers `0x21f`). AVX fits the 1024-byte XSAVE reserve if it is wanted later |
| Which target do user crates build for? | A target with SSE needs the XSAVE switching to be exercised | M5 (answered) | Answered in M5: `x86_64-unknown-none` for every user crate through M10, with the static relocation model and the small code model; nothing planned needs floating point |
| Are Read and Write the only Frame rights? | The capability header has four rights bits, all assigned | M5 (answered) | Answered in M5: yes; execute permission is bit 3 of the attributes word, off by default (`l4core::vspace::paging::Attributes`) |
| Should a populated paging structure be movable between VSpaces? | It would let a table holder expose frames whose capabilities it does not hold | M5 (answered) | Answered in M5: no. Map refuses a structure that is mapped or not empty (`InvalidCapability` 0), and Unmap empties it |
| May device frames be mapped write-back? | Device memory that is really memory would run uncached | M5 (answered) | Answered in M5: no; a device frame maps only `Uncached` or `WriteCombining`. Neither target needs more. Revisit with an ADR if a driver does |
| Should page 0 be mappable? | Some programs place data at 0 | M5 (answered) | Answered in M5: no; `Frame_Map` below `USER_MIN` is `InvalidArgument` 0. No program here needs page 0 |
| Should `Frame_Remap` on an unmapped capability return `InvalidCapability`, as Map does for a capability in the wrong mapping state? | One error convention is simpler for `libsys` | M5 (answered) | Answered in M5: it returns `IllegalOperation`, as seL4 does for an operation the capability's state does not allow |
| Should a caller whose reply capability is destroyed be woken with an error? | A server that receives again, deletes the reply or dies leaves its client blocked until someone suspends it | M6 (answered) | Answered in M6: no, as in seL4. Any error label would be indistinguishable from a reply; a client needing a timeout uses a watchdog thread holding its TCB capability. `CNode_CancelBadgedSends` leaves such a caller waiting too ([Reply capabilities](#reply-capabilities); host tests `receiving_again_before_replying_gives_up_the_reply` and `callers_already_received_keep_waiting_and_a_queued_fault_restarts`, the model's `deleting_a_saved_reply_capability_leaves_its_caller_waiting`) |
| How does a server tell "nothing pending" from a message or signal with badge 0? | `NBRecv` returns badge 0 both for nothing and for unbadged senders | M6, `libsys` (answered) | Answered in M6: an empty `NBRecv` returns `rdi` = 0 and `rsi` = 0, so a server that polls gives every signaller a non-zero badge, and every client a non-zero badge or a message whose `MessageInfo` is not 0. `root` does both: `test=badge`'s server stops at a receive with `rdi` and `rsi` both 0, and its unbadged client sends a non-zero label; `test=ipcntfn` gives every notification capability a single bit from bit 32 up, and `libsys::Event::classify` takes a receive for a signal only when `rsi` is 0 and `rdi` has one of those bits ([Binding](#binding)) |
| What else must `libsys` document? | Two seL4 behaviours surprise servers | M6 (answered) | Answered in M6: reusing a notification badge needs revoke, an `NBRecv` to drain old bits, then a new Mint (`libsys::notification`); a saved reply capability vanishes when its client is suspended or deleted (`libsys::invoke::cnode_save_caller`). `cnode_cancel_badged_sends` says to revoke the badged original first |
| Are the IMCR ports `0x22` and `0x23` real on q35 and Hyper-V? | They are kept from user space on the assumption that they can route PIC interrupts around the local APIC | M7 (answered) | Answered in M7 without checking the ports: keep them reserved, since reserving an absent port costs nothing and no planned server needs them. `l4core::ioport::RESERVED` refuses `0x20`-`0x23` and `0xA0`-`0xA1` (host test `the_kernel_keeps_the_pic_and_imcr_ports`). Whether the IMCR exists on q35 or Hyper-V is still from memory |
| What if Remote IRR stays set on an I/O APIC older than version `0x20`, which has no EOI register? | Issuing the pin fails with `RevokeFirst` until the stale delivery arrives, and on such an I/O APIC it may never arrive | M7 (answered) | Decided by the M7 spec check ([ADR 0027](adr/0027-stale-remote-irr.md)) and answered in M7 on QEMU: both paths clear a stranded Remote IRR, the EOI register in the `irq_stale` scenario and the trigger toggle in `irq_stale_0x11` (`-global ioapic.version=0x11`), and the host tests run both against the I/O APIC model, with `RevokeFirst` when nothing clears it. QEMU's I/O APIC is version `0x20`, Hyper-V's `0x11` (the M3 Hyper-V check). Normal operation needs nothing: the local APIC's EOI broadcast clears Remote IRR on any version, as in seL4, because a pin keeps its vector and trigger. For a stale one, issue writes the entry level-triggered and masked, then writes the old vector to the EOI register from version `0x20`, or below it switches the entry to edge-triggered and back, as Linux's `__eoi_ioapic_pin` does (from memory). Masking and unmasking leaves Remote IRR set, and the local APIC broadcasts an EOI only for a vector in service, so neither is an option. `test=irq_stale` runs both paths on QEMU, whose I/O APIC takes `version=0x11`. Hyper-V's path stays unchecked: no planned driver there uses a level pin (COM1 is edge; VMBus uses SINTs) |
| Must a driver of an edge pin Ack before it services, not after? | [IRQHandler](abi.md#irqhandler) and [IRQControl and IRQHandler](#irqcontrol-and-irqhandler) give every driver the loop wait, service, Ack, and say that an edge lost while masked comes after a signal the driver has not yet handled; but two deliveries whose signals merge before the driver's receive mask the pin, and a cause after its last poll then loses its edge with no signal pending on an I/O APIC that drops edges while masked, as QEMU 8.2's does (`test=irq`; [IRQControl and IRQHandler](#irqcontrol-and-irqhandler) then said QEMU latched them) | M7 (answered) | Answered in M7: yes (ADR 0028). A driver of an edge pin loops wait, Ack, service, and one of a level pin wait, service, Ack; [IRQHandler](abi.md#irqhandler) and [IRQControl and IRQHandler](#irqcontrol-and-irqhandler) now say so. The kernel's behaviour does not change. The Ack-first loop loses nothing whether an I/O APIC latches an edge on a masked pin or drops it; `test=irq` shows that QEMU 8.2's drops it, and the `uart` host tests show the old loop stranding uart against a model that does (`servicing_before_the_ack_strands_uart`) |
| Should handlers see another thread's FP state? | An `#MF` or `#XM` handler cannot read FSW or MXCSR, and a debugger cannot show FP registers | M8 | No; if needed, a `TCB_CopyRegisters` flag copies the XSAVE area |
| Is a 4096-slot root CNode with an 8 MiB root image enough once `root` carries every server and the terminal font? | Boot or the xtask size check would fail | M8 (answered) | Answered in M8: yes, and the radix stays 12. `test=tui` on QEMU uses about 1,405 of 4,096 slots (`servers: term and tui started; root CNode 1407 of 4096 slots used`): 489 framebuffer frames and one page table, 107 for term's state, 128 for each of the four servers' VSpaces and CNodes, and about 280 for the boot regions ([Capabilities](#capabilities-2)), where the design had estimated 1,600 with 155 a server. The root image's 145 frames are far inside 8 MiB, and the font is 4 KiB of read-only data in it |
| Does M8's `term` read keystrokes through console's raw mode (label `0x125`) or straight from `uart`? | Focus switching keeps working only if console sees every byte | M8 (answered) | Decided in the M8 design, and built so: through console. Client 4 is raw by its number, so routing stays a function of the byte stream; console signals term's notification and term fetches with `ReadRaw`, which never waits, so uart keeps one reader and term never blocks on console. Raw mode is input only: console's output, and every client's, stays on COM1 ([Input and the term protocol](#input-and-the-term-protocol)). The `tui` scenario's keys reach tui this way |
| Does QEMU's `screendump` with `-display none` capture the framebuffer as the guest left it? | The done-when compares it with a golden image | M8, first (answered) | Answered in M8 by the harness builder (4d9d067, 7cb611f): yes. QMP's `screendump` with `-display none` takes q35's std VGA as the guest last wrote it, the same in every run once the loader runs; `tests/qemu/screendump.scenario` compares OVMF's screen with `tests/qemu/golden/ovmf.png`. Only a screendump taken while OVMF is still drawing its text varies |
| Does OVMF on CI's runner pick 1280x800, as on this image? | The goldens are pinned to the screendump's size | M8 (answered) | Answered in M8 by the harness builder: OVMF takes the mode from the std VGA's EDID, 1280x800 by default, so the size is QEMU's to set; `tui` pins it with `-vga std -global VGA.xres=1280 -global VGA.yres=800`, and a screen of another size fails, the harness saying the sizes differ. The goldens are one size per scenario, `tests/qemu/golden/<name>.png` |
| Does Hyper-V's COM1 behave as a 16550A for `uart`: FIFOs (IIR bits 6 and 7), the character timeout, a THRE interrupt when THRI is set with the FIFO empty, OUT2 gating the line, and a transmitter that drains with no client on the named pipe? | `uart`'s setup, its 15-byte burst and its lost-interrupt reasoning assume it ([`uart`](#uart)); a transmitter that stalls without a pipe client would hold console's writes, and every client's, for good | M8 Hyper-V check | Yes, as Linux guests' 8250 driver assumes there (from memory); without FIFOs `uart` falls back to 1-byte bursts. The M8 check boots `test=release` with the script typing its line, where uart's line ends `, burst <n>` from `Stats` MR8, THRE bursts must be above 0 and the 14-byte line needs the character timeout, then once with the pipe opened 20 seconds late, when the script reports how many of the lines before its first `send:` arrived ([The Hyper-V check](#the-hyper-v-check)). Open until the owner's check |
| Does Hyper-V's video window show the GOP framebuffer after `ExitBootServices`, with no synthetic video driver? | Without it nothing term draws is visible on Hyper-V | M8 Hyper-V check | Yes, as Linux's `efifb` works on Generation 2 guests (from memory); the owner's thumbnails show it. Open until the owner's check |
| Does a write-combining mapping of the framebuffer take effect on Hyper-V [H10]? | A UC framebuffer works but every frame is slower | M8 Hyper-V check | Yes: `fb: full clear` shows the WC clear several times faster than the UC one. If not, nothing breaks; note the times. Open until the owner's check: QEMU's TCG, with no cache model, prints about a millisecond for each |
| Can the Hyper-V check compare the screen exactly? | The QEMU check is exact; the owner's is by eye | M8 Hyper-V check | Not yet. The thumbnail API's documentation calls its image "raw RGB 565", but not its byte or row order, which the script assumes and keeps the raw bytes for ([The Hyper-V check](#the-hyper-v-check)). Once the owner's thumbnails confirm the layout, and that one taken at the native 1024×768 is not scaled, an exact comparison against `tools/hyperv/golden/` reduced to RGB 565 could follow; until then the check is by eye |
| Must `vmbus` send VMBus `UNLOAD` before `INITIATE_CONTACT` because the firmware left a connection open? | Contact fails or channels are stale if the host still sees the firmware's session | M9 | Yes, as other guests do after kexec; confirm against FreeBSD's `vmbus.c` |
| Which value goes into `HV_X64_MSR_GUEST_OS_ID`? | The TLFS asks open-source guests for an OS type Microsoft allocates; microL4 has none | M9 | Bit 63 (open source) set, OS type 0, version 0, build = the kernel's build number |
| Should an MSI vector be quarantined after its handler is deleted? | A device that keeps sending gives the vector's next owner spurious signals | M9 | No: drivers treat signals as hints, and an MSI-capable driver is trusted with the machine anyway |
| Should a narrowed Hypervisor capability cover a range of connections? | A driver with several channels needs one capability per connection | M9 | One connection per capability; mint several |
| Should `Frame_GetAddress` need a right, or refuse device frames? | Physical addresses help Rowhammer-style attacks on real hardware, a non-goal | M9 | No, as seL4: any Frame capability |
| Should the kernel check the GPADL page numbers `vmbus` posts? | Without it, posting on the VMBus message connection is as strong as DMA | M10, brief 8 | No: it would put VMBus parsing in the kernel; recorded as an accepted risk |
| Should slice accounting be finer than a tick? | A thread that blocks just before each tick is never charged and can starve its equal-priority peers | M10, brief 9 | Accept it, as seL4's non-MCS scheduler does; the fix is a one-shot timer re-armed with the remaining slice |
| Priority inversion | Without priority inheritance a server below its client's priority can be starved by middle-priority threads | M10, brief 9 | Accept it, as seL4 does; `root` gives every server a priority at or above all of its clients' |
| Segment selectors as a covert channel | DS, ES, FS and GS selector values survive a thread switch | M10, brief 5 | Accept it; the fix is to load null selectors before writing the base MSRs at each switch |
| Should the TUI run on the release kernel? | The end-state demo would run without `debug` | M10 | Not for M8, whose done-when uses the selftest kernel; root would learn the kernel from the test's name, as `test=release` does |
| Should `term` draw wide and combining characters? | An app writing CJK or accents gets one cell per code point | after M10 | No: every code point takes one cell, and the font has no such glyphs |
| Should `term` keep scrollback? | Lines scrolled off the top are gone | after M10 | No; ED 3 does nothing |
| Is an IPC fastpath needed? | Round trips go through the general path | after M10 | No; revisit only with Hyper-V timings, since TCG timings mean little |
| Should paging structures shrink back to 4 KiB once a cheaper reverse map is found? | It halves the paging overhead | after M10 | No; 8 KiB keeps one simple layout |
| Should user space ever read ACPI (shutdown through the FADT, PCI `_PRT`)? | Without it there is no ACPI power-off and PCI INTx is unusable | after M10 | No: ACPI memory becomes untyped after boot; v0 shuts down by halting and PCI drivers use MSI |
| PCID | Fewer TLB refills on each switch | stretch goals (multi-core) | Off in v0; a later scheme assigns tags without a user-visible namespace |
