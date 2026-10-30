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
| [Kernel entry and exit](#kernel-entry-and-exit) | Syscall ABI | M3, M5 |
| [Kernel objects](#kernel-objects) | Kernel objects | M2, M4 |
| [Memory and retype](#memory-and-retype) | Memory | M2, M4 |
| [Capability addressing](#capability-addressing) | Capability addressing | M2, M4 |
| [Derivation tracking](#derivation-tracking) | Derivation tracking | M2, M4 |
| [Threads and TCBs](#threads-and-tcbs) | (TCB) | M5 |
| [Scheduling](#scheduling) | Scheduling | M3, M5 |
| [FP and SIMD](#fp-and-simd) | FP and SIMD | M5 |
| [Faults](#faults) | (faults) | M5, M6 |
| [IPC](#ipc) | IPC | M5, M6 |
| [Notifications](#notifications) | Notifications | M6 |
| [Interrupts](#interrupts) | Interrupts | M3, M7, M9 |
| [I/O ports](#io-ports) | Kernel objects (I/O ports) | M4, M7 |
| [ACPI and the timer](#acpi-and-the-timer) | Scheduling, Interrupts | M3 |
| [Hyper-V interface](#hyper-v-interface) | Hyper-V interface | M3, M9 |
| [Debug](#debug) | Debug | M3, M5, M7 |
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
| Kernel code runs with interrupts disabled, from entry to exit; only the idle thread's halt loop runs with `IF = 1` in ring 0 | `IA32_FMASK` clears IF; every IDT gate is an interrupt gate; no `sti` outside the idle loop (review, M10 brief 5) | M3, M5 |
| Every kernel operation whose length a ring-3 task can grow has a preemption point, except the IPC queue-cancel loops, which are bounded by the number of TCBs the task could retype ([IPC](#ipc)) | `core/` loops call the kernel's `preempt` hook after each unit of work; M10 brief 6 | M2, M4, M5, M6, M10 |
| A system call restarted after a preemption point continues its work and never repeats a completed step | progress lives in the objects (untyped watermark, Zombie capabilities, the derivation list itself); proptest with preemption injected at random | M2, M4 |
| The kernel allocates no memory after boot | the kernel links no allocator; every object comes from `Untyped_Retype` | M4 |
| The kernel never dereferences a user virtual address | user memory is reached only through frames, via the direct map; SMAP on (M3); no `stac` anywhere (CI grep over `kernel/`) | M3, M5 |
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

Hardware facts this document relies on are listed once, here. Each is from memory
of the Intel SDM or of QEMU and Hyper-V behaviour, not checked against a
source in M1; the milestone named checks it.

| Ref | Fact (from memory; check in the milestone named) | Check in |
| --- | --- | --- |
| H1 | QEMU's default TCG CPU model `qemu64`, which xtask uses today, has NX, PGE and PAT but not SMEP, SMAP, UMIP, PCID or 1 GiB pages. `-cpu max` under TCG has SMEP and SMAP, and LA57 unless `la57=off`. | M3 |
| H2 | Hyper-V passes SMEP and SMAP through to a Generation 2 guest when the host CPU has them and processor compatibility mode is off. | M3 |
| H3 | Exception and interrupt delivery clears TF, NT and RF (and IF for interrupt gates) but not AC or DF; `syscall` clears the RFLAGS bits set in `IA32_FMASK`. | M3 |
| H4 | With CR4.PCIDE = 0, a CR3 write invalidates every non-global TLB entry and every paging-structure-cache entry. Clearing and setting CR4.PGE invalidates every entry, global ones included. | M3 |
| H5 | `invlpg a` invalidates the TLB entries for the page holding `a`, whatever its size, and all paging-structure-cache entries. | M5 |
| H6 | Changing an entry's P flag from 0 to 1 needs no invalidation: no TLB or paging-structure-cache entry is made from a not-present entry. Any other change to a present entry needs one. | M5 |
| H7 | Effective R/W and U/S are the AND over the walk and XD the OR, so intermediate entries may grant everything and leaves restrict. | M5 |
| H8 | PAT index = 4·PAT + 2·PCD + PWT; the PAT bit is bit 7 of a 4 KiB PTE and bit 12 of a 2 MiB PDE. Type encodings: UC `00h`, WC `01h`, WT `04h`, WB `06h`, UC- `07h`. A page mapped UC or WC must not also be mapped WB (SDM vol. 3, 11.12.4). | M3 |
| H9 | `sysretq` with a non-canonical RCX raises #GP in ring 0 on Intel CPUs, after the kernel has restored the user's RSP. | M5 |
| H10 | An MTRR type of UC with a PAT type of WB gives UC; a PAT type of WC gives WC whatever the MTRR. Fixed-range MTRRs make the legacy hole at `0xA0000` UC. | M3 |
| H11 | UMIP makes `sgdt`, `sidt`, `sldt`, `smsw` and `str` raise #GP at CPL 3. | M3 |
| H12 | CPUID: leaf 1 EDX bit 13 PGE, bit 16 PAT; leaf `0x8000_0001` EDX bit 20 NX; leaf 7.0 EBX bit 7 SMEP, bit 20 SMAP; leaf 7.0 ECX bit 2 UMIP. | M3 |
| H13 | The CPU may fill TLB and paging-structure-cache entries at any time, in any ring, from any present entry reachable from CR3, including for speculative accesses that never retire (SDM vol. 3, 4.10.2.3). So a flush must follow the entry write it covers, never precede it. | M5 |
| H14 | CPUID leaf 7.0 EDX bit 29 says `IA32_ARCH_CAPABILITIES` (MSR `0x10A`) exists; its bit 0, `RDCL_NO`, says the CPU is not open to Meltdown (rogue data cache load). | M3 |

### Rings and segments

M3 loads this GDT; M5, which adds system calls, writes `IA32_STAR` =
`0x0013_0008_0000_0000`.

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
| XSAVE (CPUID.1:ECX bit 26) | M3 checks it; M5 sets CR4.OSXSAVE and XCR0 | refuse to boot | eager FP switching ([FP and SIMD](#fp-and-simd)) |

"Refuse to boot" means that M3 checks CPUID [H12] before it changes any
state and panics with one line, `CPU lacks <features>`, naming every missing
feature, which reaches COM1 as a `KERNEL PANIC` line. XSAVE, which M5 first
uses, is checked from M3 with the rest. Hardening that is silently missing on one target is
hardening the M10 red team never tested. QEMU's default model lacks SMEP and
SMAP [H1], so from M3 xtask's `base_command()` passes `-cpu max,la57=off`,
and a scenario key `qemu_args:` appends arguments, so a refusal test boots
`-cpu qemu64`. `tools/hyperv/New-L4Vm.ps1` turns processor
compatibility mode off, and the M3 Hyper-V check confirms SMEP and SMAP
[H2]. The M3 boot summary prints the CPUID features the kernel requires and
the Meltdown line below.

### The kernel half

| PML4 slot | Virtual range | Maps | Pages | Attributes |
| --- | --- | --- | --- | --- |
| 0 to 255 | `[0, 0x0000_8000_0000_0000)` | user mappings; empty in the kernel PML4 | | |
| 256 | `PHYS_MAP_BASE` + `[0, min(phys_map_size, 64 GiB))` | the direct map | 2 MiB; 4 KiB over the kernel image | RW, NX, global; WB or UC by the rules below; the image's `.text` and `.rodata` read-only |
| 257 to 510 | | nothing | | |
| 511 | `KERNEL_VIRT_BASE` to `__kernel_end` | the kernel image | 4 KiB | `.text` and `.hvcall` RX, `.rodata` R, `.data` and `.bss` RW NX; global, WB; a hole under each stack |
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
  and the M3 table builder skips them. An overflow takes a page fault and
  then a double fault on IST1; an overflow of IST1 itself ends in a triple
  fault. This closes the STATUS.md open issue.
- **From what memory.** The kernel's tables are static, in `.bss`: the
  kernel PML4; the direct-map PDPT, 64 page directories (256 KiB, enough for
  64 GiB of 2 MiB pages) and 9 page tables for the image's alias; the image
  PDPT, PD and 8 page tables; the device window's PD and page table: 87
  pages, 348 KiB. Nothing comes from the memory map, so M4 reserves no pages
  for them beyond the image.
- **Bounds.** The direct map covers at most 64 GiB: the loader allocates below
  64 GiB, M3 panics if the kernel image, the handoff or its memory map ends
  above the direct map, and RAM above it becomes no untyped
  ([ADR 0006](adr/0006-direct-map-bound.md)). The image, `.rootimage`
  included, is at most `KERNEL_IMAGE_MAX` = 16 MiB: `kernel/linker.ld` asserts
  it, and from M5 xtask strips `root` before embedding it and checks the
  kernel against the limit.
- **Sharing.** Kernel PML4 entries 256 and 511 point at the kernel's PDPTs
  with U/S = 0. Retyping a PML4 copies entries 256 to 511 from the kernel
  PML4, as seL4's `copyGlobalMappings` copies its kernel slots (511 only, or
  from the TLB-bitmap slot below it on SMP: `TLBBITMAP_PPTR`,
  `src/arch/x86/64/kernel/vspace.c`). The kernel writes its PML4 only
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
values there (from memory; check in M3), so the whole MSR is fixed.

M3 boot sequence, in this order:

1. Check CPUID; refuse to boot if a required feature is missing. Panic if
   the kernel image, the handoff or its memory map ends above 64 GiB.
2. Load the kernel's GDT, TSS and IDT
   ([Descriptor tables and MSRs](#descriptor-tables-and-msrs),
   [Vector map](#vector-map)).
3. Program `IA32_PAT`.
4. Find the kernel device pages: the local APIC from `IA32_APIC_BASE`, the
   I/O APICs from the MADT and the HPET from its table, read by the ACPI
   parser ([ACPI and the timer](#acpi-and-the-timer)) through the loader's
   direct map. No device
   register is touched yet.
5. Build the tables in `.bss` from the handoff's `kernel_phys_base`,
   `kernel_size`, memory map and `phys_map_size` and the device pages, with
   the type of each direct-map page computed by `core`.
6. Set CR4.SMEP, CR4.SMAP, CR4.PGE, and CR4.UMIP if present; check EFER.NXE
   and CR0.WP.
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
in `STATUS.md`, and M10 lists the risk.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| User code runs only in ring 3 and in 64-bit mode | the GDT has no DPL-3 32-bit code descriptor and there is no LDT; user CS and SS are fixed selectors, never taken from user registers | M3, M5 |
| The kernel never runs without NX, PGE, PAT, SMEP, SMAP and XSAVE | `arch::cpu::check_features` before any other M3 step; the `cpu_refuse` scenario boots `qemu_args: -cpu qemu64` and expects one `CPU lacks` line naming SMEP, SMAP and XSAVE | M3 |
| CR0.WP, EFER.NXE, CR4.SMEP, CR4.SMAP and CR4.PGE are set before the first user instruction and never cleared | M3 init; the boot summary prints CR0, CR4 and EFER and a scenario matches the line | M3 |
| Every boot states its Meltdown exposure | M3 prints `cpu: meltdown: vulnerable`, `not vulnerable` or `unknown` from `RDCL_NO`; a scenario matches the line; the Hyper-V check records it in `STATUS.md`; M10 lists the accepted risk | M3, M10 |
| Kernel code always runs with RFLAGS.AC = 0 and DF = 0 | `IA32_FMASK` includes AC and DF; `clac` and `cld` at every exception and interrupt entry; review of `arch` entry code | M3, M5 |
| The kernel never executes `stac` | CI grep over `kernel/` | M3 |
| Ring 3 cannot use I/O ports directly | IOPL 0 in every user RFLAGS (`IA32_FMASK`, register writes sanitise it); the TSS denies every port | M3, M5 |
| Every upper-half translation is supervisor-only; no user-accessible translation is global | kernel PML4 entries 256 to 511 have U/S = 0; the `core` leaf encoder always sets U/S and never sets G | M3, M5 |
| Every PML4's entries 256 to 511 equal the kernel PML4's | PML4 retype copies them; the kernel PML4 is written only in the M3 boot sequence; user mappings end below `USER_TOP` | M3, M5 |
| No address space contains the loader's 1:1 map | the kernel PML4's lower half is empty after M3's CR3 switch and PGE toggle; PML4 retype copies only entries 256 to 511 | M3, M5 |
| The kernel reaches device registers only through the UC device window, and no 2 MiB direct-map page holding a kernel device page or no RAM is WB | the M3 table builder; `l4core::vspace::direct_map_type`, host tests on the QEMU and Hyper-V memory maps and MADTs; M4 makes no RAM untyped from a 2 MiB page holding a kernel device page | M3, M4 |
| The page below the kernel stack and below each of the four IST stacks is unmapped | linker-script holes; the M3 table builder skips them; a scenario overflows the kernel stack and expects the double-fault report | M3 |
| No mapping of kernel text or read-only data is writable, and no mapping of kernel data is executable; the one exception is the direct-map alias of `.rootimage`, which is writable and never executed | M3 image tables from the linker sections; the direct map's 4 KiB pages over the image; CR0.WP; NX required; a host test of the table builder over each alias | M3 |
| The kernel image, the handoff and its memory map lie inside the direct map | the loader allocates below 64 GiB; M3 panics otherwise | M3 |
| The kernel image, `.rootimage` included, is at most 16 MiB | `kernel/linker.ld` assertion (M3); xtask strips `root` and checks the size | M3, M5 |

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
| Skim window against Meltdown, on by default on x86_64 (`KernelSkimWindow` in `src/arch/x86/config.cmake`; `map_skim_window`): user address spaces map only a small kernel window, and kernel mappings are then not global (`KERNEL_IS_GLOBAL`) | none; M3 prints whether the CPU is vulnerable | accepted risk in v0: a skim window needs separate kernel and user tables and non-global kernel pages; instead every boot says whether its CPU is exposed (TCG is not; from memory, check in M3) |
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
direct map, so 23 bits of an 8 KiB-aligned address suffice. Derivation rules,
which the capability core applies in M2:

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
  swap, every Zombie swap and `CNode_SaveCaller`. M2 defines and calls the hook; M5 fills it in.

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
turns a broken link into a panic instead of a write into reused memory.
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
| The last PML4 capability is deleted | if CR3 holds it, load the kernel PML4 first; then clear the mappings of the PDPT capabilities named by back-references 0 to 255 | CR3 write |
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
mode. The flush must follow the entry write: the CPU may refill the TLB from a
still-present entry at any moment, speculatively and in ring 0 [H13], so a
flush issued first could be undone before the write. Returning `Flush` from
the operation that wrote the entry gives that order by construction. A missed
flush lets a thread keep using a frame after unmap; if the frame is then
retyped into a kernel object, the thread can write that object. A missed
reload after a table detach lets the CPU keep walking, and setting accessed
and dirty bits in, a table whose memory may be retyped. TCG hides both
(PLAN.md), so the host model below checks them.

### Where the code lives

- **`l4core::vspace`** (`core/`): the constants; entry encoding; range,
  rights and attribute checks; the type of each direct-map page (M3); map,
  remap, unmap, table unmap, deletion and the move hook, written against two
  traits: `PagingStore`, which reads and writes an entry or a back-reference
  of the structure at a physical address, and the capability core's slot
  store (M2). Every operation returns a `#[must_use]` `Flush`: `None`,
  `Page(vaddr)` or `All`. Host tests cover the bounds; a proptest runs random
  map, remap, unmap, delete and move sequences against a model of the
  mappings, checking L1 to L3 and the tree shape, and runs a TLB model that
  caches every translation of the loaded PML4 before each step and checks,
  after the step and its `Flush`, that no cached translation disagrees with
  the tables.
- **`kernel/src/arch/x86_64/paging.rs`**: `PagingStore` over the direct map;
  `apply(Flush)`, which holds the only `invlpg` and the only CR3 reload;
  `set_vm_root`, the only other CR3 write after boot (thread switch and PML4
  finalisation); the M3 table builder, the PAT and
  CR4 setup. `cpu.rs` checks the features.

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
| Every frame mapping lies in `[USER_MIN, USER_TOP)`; no invocation writes a PML4 entry above 255 | `l4core::vspace` range checks before any walk; host tests at both bounds and around 2^47 | M5 |
| L1, L2 and L3 hold after every operation | one `core` module writes all entries, back-references and mapping fields; `moved(cap, old_slot, new_slot)` runs after every Move, Mutate, both halves of Rotate, the Rotate swap, every Zombie swap and `CNode_SaveCaller`; the M2 proptest covers nested CNode deletion with mapped capabilities in slot 0 and random preemption, and M5 adds mapping state to the model | M2, M5 |
| Every use of a back-reference or mapping field first checks the link in both directions, and a mismatch panics instead of writing | `l4core::vspace` link checks before each write through a link; a host test breaks a link and expects the panic | M5 |
| A present entry points at a live object of the right kind | frames and structures detach before they die; L1 to L3; proptest | M5 |
| A paging structure is mapped at most once, only when empty, and only into a structure reachable from a PML4, so mappings form trees | derivation refuses table capabilities; the Map checks; proptest | M2, M5 |
| A frame capability maps at most one page; its copies start unmapped | derivation clears the mapping; Map refuses a mapped capability | M2, M5 |
| A mapping's rights never exceed its capability's; every user-half leaf has U/S = 1 and G = 0 | `core` rights mask and leaf encoder; host tests | M5 |
| No physical page is mapped both cacheable and uncacheable | the attribute check by `device`; M4 makes no device untyped from a WB direct-map page; host tests | M4, M5 |
| Paging structures are made only from RAM untyped | the retype rule ([Retype](#retype)) | M2, M4 |
| Every change to a present user entry is followed by its flush before the next user instruction | `Flush` returned by `core`, applied by `arch`; the TLB model in proptest; review; red-team brief 4 | M5, M10 |
| The TLB holds user translations only for the PML4 in CR3 | CR4.PCIDE never set; CR3 written on every VSpace change | M3, M5 |
| CR3 always holds the kernel PML4 or a live PML4 | PML4 finalisation switches CR3 first; the exit path recomputes CR3 from the thread's VSpace slot | M5 |
| Unmapping or deleting any paging object touches at most 512 entries | `core` loops, no recursion | M5 |
| A thread without a valid VSpace runs no user code | it runs on the kernel PML4, whose lower half is empty | M5 |

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
| 3 | M3 | GDT, TSS, IDT, `IA32_PAT` ([Privilege levels](#privilege-levels)) and CR4.MCE; `IA32_GS_BASE` = the per-CPU area; DR7 = `0x400`, its reset value, no breakpoint enabled. The firmware's GDT, IDT and stack are now dead |
| 4 | M3 | ACPI is parsed through the loader's direct map: the kernel device pages (the local APIC, at most four I/O APICs, the HPET), the ISA overrides and the ECAM ranges ([ACPI and the timer](#acpi-and-the-timer)). Then the kernel's page tables are built in `.bss`, with the kernel device window at `KERNEL_DEVICE_BASE`, and replace the loader's in the order [The kernel half](#the-kernel-half) gives (CR4.SMEP, SMAP, PGE and UMIP, then CR3); the 1:1 map is gone |
| 5 | M3 | The local APIC, the PIC and the I/O APICs are set up; the local APIC timer and the TSC are calibrated in one window, giving `tsc_hz`; Hyper-V overlay pages the firmware left enabled are switched off ([ACPI and the timer](#acpi-and-the-timer), [Firmware leftovers](#firmware-leftovers-m3)). The kernel device pages, the MSI window and a locked Hyper-V hypercall page go into `BootPlan.kernel_reserved`. Only now are `USABLE`, `LOADER` and `ACPI_RECLAIMABLE` pages free |
| 6 | M4 | `l4core::boot::plan` sizes the boot region; the kernel allocates and zeroes it |
| 7 | M4 | The root CNode is made in the boot region and the fixed capabilities written |
| 8 | M5 | The root ELF is copied from `.rootimage` into image frames; its VSpace, IPC buffer and TCB are built. `.rootimage` is unmapped from the kernel window, ending with a CR4.PGE toggle ([The kernel half](#the-kernel-half)) |
| 9 | M4 | `l4core::boot::untyped` computes the untyped; caps go into the CNode, descriptors and the rest of BootInfo into its frames |
| 10 | M5 | Syscall MSRs are written, `IA32_FS_BASE` and `IA32_KERNEL_GS_BASE` get the root task's bases (0), and the kernel exits to the root task through `iretq` |

In M4, which has no root task, steps 6, 7 and 9 run, the kernel prints the
BootInfo summary and the self-tests run instead of step 10.

### What each physical page becomes

The rules are applied in this order; a later row overrides an earlier one.

| Physical range | Becomes | Why |
| --- | --- | --- |
| `USABLE`, `LOADER`, `ACPI_RECLAIMABLE` | RAM untyped | the loader, its tables, the handoff and the map are dead after steps 2 and 4; ACPI is parsed in step 4 |
| `RESERVED`, `MMIO`, ranges absent from the map, below `2^phys_addr_bits` | device untyped | PCI BARs, ECAM ([Memory map](abi.md#memory-map)) |
| `ACPI_NVS`, `FIRMWARE`, `BAD` | nothing | firmware-owned or broken |
| the kernel image, except `.rootimage` | nothing | |
| `.rootimage` | RAM untyped (from the `LOADER` row) | reclaimed in step 8 |
| the GOP framebuffer, page-rounded | its own device untyped, listed first; none at all if any 2 MiB page it touches is write-back in the direct map (a debug kernel warns) | `fb` (M8) gets all of it or none of it |
| any 2 MiB page the direct map maps write-back | no device untyped | a device frame would alias a WB mapping ([The kernel half](#the-kernel-half), H8) |
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
report on their 8 KiB IST stack; M3 measures the panic path's depth against
it.

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
TCB. It is zeroed when allocated, no untyped covers it, and it is never freed,
so the root task cannot revoke its own CNode. Boot-only kernel code (a few
KiB) is not reclaimed.

### Untyped

`l4core::boot::untyped(&BootPlan)`, a pure function, classifies every page
below `2^phys_addr_bits` by the table above (using
`l4core::vspace::direct_map_type` for both 2 MiB rules, and subtracting the
fixed-size `kernel_reserved` list, which `plan` subtracts too), merges runs
of one class, cuts each run into the largest naturally aligned power-of-two
chunks between 4 KiB and the maximum untyped size in
[Object sizes](abi.md#object-sizes) (seL4's `create_untypeds_for_region`),
and yields the framebuffer's chunks first,
then the rest by ascending address. BootInfo holds 448 descriptors; if more
are needed, boot panics with the count rather than drop memory. An M4 host
test runs the function on memory maps recorded from QEMU and Hyper-V and
checks the margin.

### Root-task image and address space

`cargo xtask build` links `user/root` as a static ELF at `0x40_0000`,
strips it, refuses one whose `PT_LOAD` segments span more than 8 MiB (from
the first segment's page to the end of the last), and the kernel embeds it
with `include_bytes!` in `.rootimage`, its own read-only, NX `PT_LOAD`
segment between `__rootimage_start` and `__rootimage_end`, which starts and
ends on a page boundary so that no other kernel byte shares its pages. From
M5 xtask also checks the whole kernel image, `.rootimage` included, against
`KERNEL_IMAGE_MAX` = 16 MiB. Other servers travel inside root's image.
Step 8 checks the image with `l4core::elf` (ET_EXEC, x86_64, no page shared
by two segments) and `l4core::boot` (segments inside
`[USER_MIN, USER_TOP - 12 KiB)`, span at most 8 MiB, no segment both writable
and executable, entry in an executable segment), copies the file bytes,
leaves the rest zero, and maps each page with its segment's permissions. A
page inside the span that no segment covers gets no frame and no mapping.

| Root virtual range | Content | Mapping |
| --- | --- | --- |
| `[image_start, image_end)` | the pages the ELF's segments cover, 4 KiB frames | from segment flags; uncovered pages unmapped |
| `image_end` | IPC buffer, one frame | RW, NX |
| `image_end + 4 KiB` | BootInfo, two frames | RW, NX |

There is no stack. As in seL4, root's `_start` in `libsys` switches to a
stack in its own `.bss`.

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

BootInfo is one 8 KiB `#[repr(C)]` struct in `l4core::bootinfo`, shared by the
kernel and `libsys` with compile-time offset asserts: a 1 KiB header and 448
untyped descriptors ([BootInfo](abi.md#bootinfo)). Beyond seL4's fields it
carries the framebuffer and the slot range of its untyped, the RSDP address
(for information), the command line
([ADR 0003](adr/0003-scenarios-select-tests-by-command-line.md)), the TSC
frequency measured in M3, the hypervisor vendor, the physical address width,
the image bounds, and the 256-byte `InterruptInfo` block, whose fields [What
user space gets, and kernel devices](#what-user-space-gets-and-kernel-devices)
lists.

### Root-task entry state

`rip` = ELF entry, `rdi` = BootInfo, `rsp` and other registers 0, RFLAGS
`0x202`, the FP template of [Initial state](#initial-state), priority and
MCP 255, no fault endpoint, `exit` = `Iret` so the first exit is an `iretq`
([Root-task entry state](abi.md#root-task-entry-state)).

### `core/` and `arch/`

| Part | Where | Built in |
| --- | --- | --- |
| BootInfo, `SlotRegion`, `UntypedDesc`, slot constants | `l4core::bootinfo`, compile-time asserts | M4 |
| Boot plan, untyped computation, slot plan, root layout and ELF checks | `l4core::boot`, host tests and proptest | M4, M5 |
| Handoff copy, boot region allocation, writing BootInfo and image frames | `arch` gives `core` `&mut` views of the boot region's frames through the direct map, each with a `SAFETY:` comment that boot code owns them exclusively | M4, M5 |
| `.rootimage` section, unmap and flush | `kernel/linker.ld`, `arch` | M5 |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| No untyped covers the kernel image (except reclaimed `.rootimage`), the boot region, a `kernel_reserved` page, `[0, 1 MiB)`, `ACPI_NVS`, `FIRMWARE` or `BAD` memory; the boot region holds no `kernel_reserved` page and touches no 2 MiB page that holds one | `l4core::boot::plan` and `untyped` both subtract `kernel_reserved`; proptest over generated maps, including a reserved page inside the chosen `USABLE` range | M4 |
| No kernel object lies at physical address 0 | no untyped and no boot region below 1 MiB (`l4core::boot::untyped`, host test); `core/` handles are `NonZeroU64` | M2, M4 |
| Untyped are pairwise disjoint, each aligned to its size and at least 4 KiB | `l4core::boot::untyped`; proptest | M4 |
| RAM untyped lie inside the direct map; no device untyped lies in a write-back direct-map page; no RAM untyped lies in a 2 MiB page holding a kernel device page | `l4core::boot::untyped` with `direct_map_type`; host tests on the QEMU and Hyper-V maps | M4 |
| The kernel image, the handoff and its memory map lie below the direct map's end | the loader's 64 GiB `AllocateMaxAddress` bound; M3 check, panic otherwise | M3 |
| The kernel image, `.rootimage` included, fits `KERNEL_IMAGE_MAX` = 16 MiB | `kernel/linker.ld` assert (M3); xtask strips `root` and checks the image (M5) | M3, M5 |
| The root task never holds a capability to kernel memory: kernel image, stacks, descriptor tables, kernel page tables, kernel device pages, or the boot-region pages that hold its CNode, TCB and paging structures (as frames or untyped) | the plan excludes them from every untyped and frame; M4 self-test checks every BootInfo descriptor against the kernel ranges | M4, M5 |
| No `USABLE`, `LOADER` or `ACPI_RECLAIMABLE` page outside the kernel image is written or handed out before step 5 ends: the firmware's GDT, IDT and stack, the loader's tables, ACPI and any firmware-enabled Hyper-V overlay are dead by then | the step order in `kmain`; the boot plan (step 6) is the first allocator; review | M3, M4 |
| Boot never drops memory silently: it panics if the untyped or slots do not fit | count checks in `l4core::boot`; host test on recorded maps | M4 |
| BootInfo's layout is identical in the kernel and in `libsys` | one `l4core::bootinfo` type; compile-time offset asserts | M4 |
| Slot `untyped.start + i` holds the untyped `untyped_list[i]` describes, for every `i` below `untyped.end - untyped.start`; every slot in `empty` is null | `l4core::boot` slot plan; host test; M4 self-test | M4 |
| After step 2 no code reads `LOADER` memory other than the kernel image | `BootState` copy; review | M3 |
| No page of `.rootimage` is mapped in the kernel window when it becomes untyped | step 8 unmaps and toggles CR4.PGE before step 9 | M5 |
| The root image cannot map outside `[USER_MIN, USER_TOP)` or make writable text: a writable and executable segment is refused; a page no segment covers is not mapped | `l4core::elf` and `l4core::boot` checks; host tests with a gap between segments | M5 |
| The root task starts with the registers, priority and capabilities [`abi.md`](abi.md#boot-and-the-root-task) lists | M5 scenario: root prints them and checks slot types | M5 |

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

Every entry from ring 3 runs `swapgs`, builds one trap frame at the top of
the single kernel stack and copies it into the current TCB; every exit
rebuilds the frame from the next thread's TCB and leaves by `sysretq` only if
that thread entered by `syscall`, else by `iretq`, with RIP always below
2^47. NMI, #DF, #MC and #DB run on their own IST stacks and never read GS.

### Descriptor tables and MSRs

The GDT is the one in [Rings and segments](#rings-and-segments): null,
kernel code `0x08`, kernel data `0x10`, user data `0x18` (selector `0x1B`),
64-bit user code `0x20` (`0x23`), TSS `0x28`, no 32-bit code descriptor.
`syscall` loads CS =
`STAR[47:32]`, SS = CS + 8; `sysretq` loads SS = `STAR[63:48]` + 8, CS =
`STAR[63:48]` + 16, with RPL 3 (from memory; check in M5). That forces the
order: kernel data right after kernel code, then user data, then 64-bit user
code. `STAR[63:48]` names index 2 with RPL 3, `0x13`, which is right whether
or not `sysretq` forces RPL 3. The selectors are loaded with fixed hidden
attributes, not read from the GDT; the GDT entries matter for `iretq`.

| Register | Value | Why |
| --- | --- | --- |
| `IA32_EFER` (`0xC000_0080`) | SCE set (M5); NXE from the loader | enables `syscall` |
| `IA32_STAR` (`0xC000_0081`) | `0x0013_0008_0000_0000`, as in [Rings and segments](#rings-and-segments) | entry CS `0x08`, SS `0x10`; exit SS `0x13 + 8 = 0x1B`, CS `0x13 + 16 = 0x23` |
| `IA32_LSTAR` (`0xC000_0082`) | `syscall_entry` | |
| `IA32_CSTAR` (`0xC000_0083`) | `compat_entry`: `swapgs`, load the kernel stack, panic | unreachable, since no compatibility-mode code segment exists; if reached, it never runs on the user stack |
| `IA32_FMASK` (`0xC000_0084`) | `0x0025_7FD5`: CF PF AF ZF SF TF IF DF OF IOPL NT RF AC ID, seL4's `FLAGS_SYSCALL_MASK` | IF: the kernel runs with interrupts off. DF: Rust assumes it clear for string operations. TF: no single-step trap inside the kernel. AC: with AC set SMAP is off in ring 0. NT: a later `iretq` with NT set would attempt a task return and fault (from memory). The rest gives a defined state |
| `IA32_SYSENTER_CS` (`0x174`), `_ESP`, `_EIP` | 0 | firmware may leave them set; with CS 0, `sysenter` faults in ring 3 on Intel and is #UD in long mode on AMD (from memory; check in M5) |
| `IA32_GS_BASE` (`0xC000_0101`) | the per-CPU area while in ring 0 | |
| `IA32_KERNEL_GS_BASE` (`0xC000_0102`) | the current thread's GS base while in ring 0 | swapped in by the exit `swapgs`; written at a thread switch ([FS and GS base](#fs-and-gs-base)) |

TSS: RSP0 = the kernel stack top; IST1 #DF, IST2 NMI, IST3 #MC, IST4 #DB, each
8 KiB above an unmapped guard page; I/O map base past the limit, so ring 3 has
no port ([Rings and segments](#rings-and-segments)). IDT: 256 64-bit interrupt
gates on `0x08`, all DPL 0 except vector 3 (#BP), which is DPL 3 so that
`int3` raises UserException 3 with `rip` after it, as in seL4; vectors 1, 2, 8
and 18 use their IST, every other gate none. [Vector map](#vector-map) assigns
vectors 32 to 255.

### The per-CPU area and `swapgs`

`PerCpu` is a `#[repr(C)]` static: `self` (offset 0), `kernel_stack_top` (8),
`user_rsp` (16). `swapgs` runs once per entry from ring 3 and once per exit to
it, so GS points at `PerCpu` in ring 0 and at the user's GS base in ring 3.
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

vector_N:                      ; non-IST gate; RSP0 if from ring 3
    push 0 (if the CPU pushed no error code), N
    clac
    cld
    test byte [rsp + 24], 3    ; saved CS
    jz   trap_from_kernel
    swapgs
    push rax ... r15
    mov  rdi, rsp
    call trap_from_user
```

The CPU pushes an error code for vectors 8 and 10 to 14 (from memory; check
in M3). Vectors 17, 21, 29 and 30 also push one when raised as exceptions,
but none can be raised here (CR0.AM clear, no CET, no SEV), so they take the
no-error-code stub, which also reads an MSI injected on them correctly. They
and the vectors with no use here (9, 15, 20, 22 to 28, 31; from memory, check
in M3) panic from either ring. Every stub, IST ones included, runs
`clac` and `cld` before any Rust code.

The Rust handlers read CR2 first for #PF, then copy the frame into the current
TCB's `regs` ([Register frame and restart](#register-frame-and-restart)): for
`syscall`, `next_ip` = `rcx`, `fault_ip` = `rcx` − 2, `exit` = `Sysret`;
otherwise `next_ip` = `fault_ip` = the pushed RIP, `exit` = `Iret`. Then they
dispatch, schedule and exit; nothing stays on the kernel stack between
entries. The kernel has no SSE code (`kernel/src/main.rs`), so x87 and SSE
state is untouched until a thread switch swaps it
([Switching](#switching-m5)).

### Exit

`exit_to_user(t)` writes the trap frame at the top of the kernel stack from
`t.regs` through `l4core::entry::exit_frame`, a pure function:

- `rip` = `next_ip`, `rsp` = `rsp`, each replaced by 0 if at or above
  `0x0000_8000_0000_0000`, the sanitiser's rule
  ([User register set and sanitising](#user-register-set-and-sanitising)). A
  debug
  kernel prints a warning when this fires. Without a kernel bug it fires
  only for an `rsp` the thread set itself, or for a `rip` restarted after a
  fault on an upper-half fetch; otherwise a writer forgot to sanitise.
- `rflags` = `(rflags & 0x0024_0DD5) | 0x0202`: CF PF AF ZF SF TF DF OF AC
  ID, which ring 3 can set itself with `popfq`, are kept; IF and bit 1 are
  forced on; IOPL, NT, RF, VM, VIF and VIP are forced off (ring 3 can set NT
  too, but it is never needed). The register-write sanitiser is stricter: a
  register write also clears TF, AC and ID, as seL4's `sanitiseRegister`
  does (`src/arch/x86/machine/registerset.c`). `exit_frame` applied after it
  changes nothing.
- `cs` = `0x23`, `ss` = `0x1B`, constants, never from the TCB.
- The path is `Sysret` if `t.regs.exit` is `Sysret`, else `Iret`.

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
newly retyped TCB leaves by `iretq`. With nothing runnable, `exit_to_idle`
resets RSP to the stack top and runs `idle_loop`: `sti; hlt` in a loop.

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
(from memory; check in M5).

### NMI, double fault, machine check and debug

| Vector | Stack | From ring 3 | From ring 0 |
| --- | --- | --- | --- |
| 1, #DB | IST4 | `swapgs`, save the frame into the TCB, continue on the kernel stack; UserException 1 (`int1`, TF; [Faults](#faults)) | if the saved RIP is exactly `syscall_entry` (a `syscall` executed with TF set, if the CPU traps there; from memory, check in M5), `iretq` at once; otherwise panic |
| 2, NMI | IST2 | panic | panic |
| 8, #DF | IST1 | panic | panic |
| 18, #MC | IST3 | panic | panic |
| 9, 15, 17, 20 to 31 | none | panic | panic |

These handlers never read GS and never use the interrupted RSP, so an NMI or
#DB at the first instruction of `syscall_entry`, while RSP is still the
user's, is safe. The kernel sends no NMIs, so one means a hardware error, a
host operator, or a bus-master device whose driver programmed an NMI (or a
vector-18) MSI, which is as strong as DMA
([MSI (M9) and the trust model](#msi-m9-and-the-trust-model)); as it is
fatal, no handler returns from IST2 and a nested NMI cannot overwrite a live
frame. Separate ISTs keep an NMI inside a #MC
handler off its stack. CR4.MCE is set so a machine check reaches the panic
report instead of shutting down (from memory; check in M3). DR7 keeps its
reset value `0x400`, no breakpoint enabled ([Invocations](#invocations)), so the
single-step case is the only ring-0 #DB.

### Interrupts and exceptions taken in ring 0

IF is 0 everywhere in the kernel except `idle_loop`, and preemption points
poll the local APIC's IRR without ever opening an `sti` window, so there is no
nested-interrupt path like seL4's `nested_interrupt`. A vector of 32 or more
from ring 0 must have RIP inside `idle_loop`; its frame is discarded and the
interrupt path runs ([Idle thread](#idle-thread)). Any other ring-0 vector is
a kernel bug: panic with vector, error code, CR2, RIP, RSP and the decoded #PF
bits (M3's page-fault scenario), without reading GS.

### System-call dispatch

`l4core::abi::Syscall::from_number(rdx, cfg!(feature = "debug"))` returns
the system call or none; none raises an `UnknownSyscall` fault
([Faults](#faults)), with `fault_ip` on the `syscall` instruction. Otherwise:

| System call | Kernel action |
| --- | --- |
| `Call`, `Send`, `NBSend` | look up `rdi` (up to 64 bits, stopping at the first slot that is not a CNode) and dispatch on its type: Endpoint, Notification, Reply ([IPC](#ipc), [Notifications](#notifications)); any other object decodes `label` within its type's range ([Invocation label index](abi.md#invocation-label-index)), else `IllegalOperation`. `Call` gets the result or error as a kernel reply; `Send` and `NBSend` drop it |
| `Recv`, `NBRecv` | Endpoint or Notification receive ([Receive phase](#receive-phase), [Wait and poll](#wait-and-poll)) |
| `Reply` | the caller slot's reply capability ([Reply capabilities](#reply-capabilities)) |
| `ReplyRecv` | `Reply`, then `Recv` on `rdi` |
| `Yield` | the scheduler ([Scheduling](#scheduling)) |
| 16 to 18 | [Debug](#debug) |

What each lookup or rights failure produces is in the table [Errors, faults
and silent drops](abi.md#errors-faults-and-silent-drops). An operation that
reaches a preemption point leaves the thread `Restart`, so it re-executes
`syscall` from `fault_ip` with its argument registers unchanged.

### `core/` and `arch/`

| Part | Where | Built in |
| --- | --- | --- |
| GDT, TSS, IDT, IST stacks, ring-0 exception decode, NMI, #DF, #MC handlers, idle loop and its interrupt path | `arch/x86_64/{gdt,idt,trap}.rs` | M3 |
| Syscall MSRs, `syscall_entry`, user trap entry, `exit_sysret`, `exit_iret`, `PerCpu` | `arch/x86_64/{entry,percpu}.rs` | M5 |
| `Syscall::from_number`, `exit_frame` | `l4core::abi`, `l4core::entry`; host tests at `2^47 - 1`, `2^47`, `2^64 - 2^47`, and proptest over all `u64` | M5 |

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| `sysretq` never runs with RCX at or above 2^47 | `l4core::entry::exit_frame`; host tests and proptest; M10 brief 5 scenario: `syscall` in the last mappable page, and WriteRegisters with a non-canonical RIP | M5, M10 |
| `sysretq`, `iretq` and the FS and GS base `wrmsr`s at a switch cannot fault in ring 0 | `exit_frame` (constant CS and SS, canonical RIP and RSP, masked RFLAGS); the FS and GS base sanitiser ([FS and GS base](#fs-and-gs-base)) | M5 |
| User code always runs with IF = 1, IOPL = 0, NT = 0 and the user selectors | `exit_frame`; proptest | M5 |
| Kernel code always runs with IF = 0 outside `idle_loop`, and with DF = AC = TF = NT = 0 | `IA32_FMASK`; `clac` and `cld` in every IDT stub, IST ones included; review | M3, M5 |
| `int n` from ring 3 reaches no handler but #BP's, which treats it as the `int3` trap it is | every gate DPL 0 but vector 3's | M3 |
| Vectors 9, 15, 17 and 20 to 31 never reach a fault handler or the interrupt path, and no injected vector makes the kernel misread a frame | no-error-code stubs for 17, 21, 29, 30; panic from either ring; red-team brief 7 | M3, M10 |
| NMI, #DF, #MC and #DB never run on the interrupted RSP and never read GS | IST1 to IST4; review; M10 brief 5 | M3, M5 |
| GS points at `PerCpu` whenever a ring-0 path outside the IST handlers and the two windows reads it | `swapgs` exactly once per ring-3 entry and exit, keyed on saved CS; review; M10 brief 5 | M5 |
| `sysenter`, compatibility-mode `syscall` and far transfers cannot enter ring 0 | `IA32_SYSENTER_CS` = 0; no 32-bit code descriptor; `IA32_CSTAR` stub | M5 |
| A ring-0 interrupt is accepted only from `idle_loop`; every other ring-0 exception panics with a decoded report | `trap_from_kernel` RIP check; M3 page-fault scenario | M3 |
| An overflow of the kernel stack or of the NMI, #MC or #DB IST stack ends in a #DF report, and an overflow of the #DF stack in a triple fault, never in silent corruption | a guard page below each of the five stacks, reserved by the linker script and skipped by the M3 table builder; #DF on IST1; M3 scenarios overflow the kernel stack and, from a `test=` hook, the NMI stack after a self-NMI | M3 |
| The kernel stack holds no state across entries | every entry starts at RSP0 or the stack top; exits rebuild the frame from the TCB | M5 |
| An unknown or, without `debug`, a debug system call number reaches no handler and raises `UnknownSyscall` | `Syscall::from_number`; host tests for both builds | M5 |
| A preempted system call restarts with the caller's arguments | `fault_ip`, `Restart` ([Register frame and restart](#register-frame-and-restart)); M5 self-test | M5 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Uniprocessor builds use no `swapgs` and find the thread through `ksCurThread` (`traps.S`, `MAYBE_SWAPGS`) | `swapgs` with a per-CPU area | PLAN.md's Syscall ABI row ([ADR 0008](adr/0008-kernel-entry-and-exit.md)); stubs ready for multi-core; costs one invariant |
| User context pushed straight into the TCB with RSP as the pointer (`handle_fastsyscall`, `LOAD_USER_CONTEXT`) | trap frame on the kernel stack, copied into the TCB in Rust | one frame layout for every entry, logic in Rust; costs a 22-word copy |
| Every IDT gate on IST1, a six-word IRQ stack (`init_tss`, `init_idt_entry` in `src/arch/x86/64/kernel/vspace.c`) | RSP0 for ring-3 entries; IST only for #DF, NMI, #MC, #DB | a nested exception cannot overwrite another's frame |
| `sysretq` after `xor rsp, rsp`; libsel4 keeps RSP in RBX across `syscall` (`restore_user_context`, `syscalls_syscall.h`) | the kernel saves and restores RSP; RBX preserved | the register table in [System calls](abi.md#system-calls) |
| `IA32_STAR[63:48]` = `SEL_CS_3` (`0x2B`), so `sysretq` loads CS selector `0x3B`, GDT_FS's slot, and SS `0x33`, while `iretq` uses CS `0x2B` from the TCB (`init_syscall_msrs`, `src/arch/x86/64/kernel/vspace.c`; `include/arch/x86/arch/64/mode/object/structures.h`; `Arch_initContext`; SYSRET arithmetic from memory) | `0x13`: selectors agree on both paths. Like seL4, the field holds an RPL-3 selector | one user CS value |
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
| 14 | IOPort | none; from IOPortControl | | the port range | [I/O ports](#io-ports) |
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
last)`, which returns a cleanup capability as seL4's `cleanupInfo`,
`after_delete(cleanup)`, `moved(cap, old_slot, new_slot)`, `zero(paddr,
len)`, `init_object(cap)` and `preempt()`, a preemption point that polls the
local APIC's IRR (the kernel never opens an `sti` window). Every type's
derivation rule is in `core/` (`l4core::cnode::derive`), so derivation needs
no hook.

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
| TCB | suspended and unbound (off every queue, IPC cancelled, notification unbound), then its slots are deleted as a CNode's | [Suspend, Resume and deletion](#suspend-resume-and-deletion) |
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
   preemption point after each; a restarted call resumes.
3. A nested deletion, of the last capability to another container `D`, does
   not recurse: `D`'s Zombie is swapped into `D`'s slot 0 and `D`'s old
   slot-0 capability is deleted instead. The swap carries both derivation
   nodes and calls `moved`; a preemption point may follow it. A nested
   deletion that meets a Zombie already in its own container's slot 0 stops
   (seL4 `capCyclicZombie`). `D` stays, unreachable, until a revoke of its
   untyped reaches the Zombie (`cspace.tex`, "Deletion and Revocation",
   footnote).
4. The slot empties when the count reaches 0, or 1 with the Zombie in the
   container's own slot 0.

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
implementations. Then the hooks: M5 for TCBs, Endpoints, Reply capabilities
and paging objects; M6 for Notifications and `CNode_SaveCaller`; M7 for
IRQHandlers, IOPorts and the IRQ node; M9 for Hypervisor capabilities.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A capability never outlives its object: an object's memory is reused only when the untyped covering it is reset, which needs it to have no descendants, and every capability to an object in that region, except a reply capability (next row), is a descendant | `l4core` retype, insert and delete; proptest against `model/` with object liveness | M2 |
| Reply capabilities, the one exception (a master is a derivation root), never outlive their TCB: TCB finalisation deletes the outstanding reply capability (suspend, `cancel_ipc`) and the Zombie deletes the master before the TCB's last capability's slot empties | threads and IPC finalisation; proptest deleting TCBs blocked in `Call` | M2, M5 |
| No kernel object lies at physical address 0 | M4 untyped builder, host test; `core/` handles are `NonZeroU64` | M2, M4 |
| No kernel reference (queue, binding, mapping) survives the last capability to its target | `finalise` hooks called by `core/` delete; proptest counts finalisations; each subsystem's tests | M2, M5 to M7, M9 |
| A back-reference never names an empty slot | `finalise` runs before unlink and zeroing; proptest with mapped capabilities ([Address spaces](#address-spaces)) | M2, M5 |
| The last capability to an object is finalised exactly once, before its slot empties | `is_final` and the Zombie algorithm; proptest with random preemption | M2 |
| Every TCB, Endpoint, Notification, CNode and paging structure lies in RAM inside the direct map, below 64 GiB | retype refuses kernel objects from device untyped; RAM untyped only below the direct map's end, `min(phys_map_size, 64 GiB)`; host test of the untyped builder | M2, M4 |
| Only `core/` writes slots, and every `SlotAddr`, including each back-reference word, is a slot of a CNode or TCB whose memory has not been reset, or an IRQ-node slot | `SlotAddr` built only from capabilities, the current thread, IRQ numbers, links and back-references (L2, L3 in [Address spaces](#back-references-instead-of-asids)); fake memory panics on stray access; debug asserts in `arch` | M2, M4, M5, M7 |
| Capabilities are created only by boot, retype, IRQControl and IOPortControl invocations, `Call` and fault delivery (reply capabilities), and deletion (Zombies); every other capability is derived from one its holder has | the only callers of `insert_root` and `insert_derived`; red-team brief 1 | M2, M10 |
| Destroying a CNode or TCB is preemptible, recurses at most two levels, and keeps every invariant at each step | Zombie algorithm; proptest with random preemption points over nested and cyclic containers, including deleting a slot inside the container its own deletion destroys | M2 |
| No lookup reaches, and the kernel inserts nothing into, a slot of a CNode or TCB being destroyed | finalisation starts only at the last capability, which becomes a Zombie that lookups stop at; TCB finalisation suspends first; proptest | M2, M5 |
| The Zombie code clears only CNode and TCB slots, never IRQ-node slots | IRQ-node slots belong to no container; proptest | M2, M7 |
| Every relocation of a capability to another slot calls `moved(cap, old_slot, new_slot)` before the next preemption point, so back-references stay exact | one `l4core::cdt` move and one swap function, used by Move, Mutate, both halves of Rotate, the Rotate swap, every Zombie swap and `CNode_SaveCaller`; proptest over nested CNode deletion with a mapped capability in slot 0 of the nested CNode, rotates and swaps of mapped capabilities, and untyped revoke, at random preemption points; red-team brief 4 | M2, M5, M6, M10 |

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
against `model/` on fake memory. M4: boot untyped, `zero` and `init_object`
in `arch`, `Untyped_Retype` decoded, and the self-test that retypes, revokes
and retypes again.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Retype never overlaps a live object | watermark rises while the untyped has children; reset only with none; proptest checks live objects are pairwise disjoint | M2 |
| An untyped with children is never reset or copied | `has_children` in retype and `derive`; proptest | M2 |
| Retype never allocates outside its untyped, and its arithmetic cannot overflow | `size_bits` at most 47, `num_objects` at most 256, the shift test of step 2; proptest with extreme arguments; red-team brief 3 | M2, M10 |
| Every object is aligned to its size | align-up in step 4; proptest | M2 |
| RAM at or above a watermark is zero, so every new object starts zeroed | reset clears before lowering the watermark; fake memory checked after each step | M2, M4 |
| Device untyped yields only Frames and device untyped, and is never cleared | type check in retype; device bit inherited; red-team brief 3 | M2, M10 |
| A preempted reset leaves a consistent untyped, and the restarted retype completes it | top-down chunks; proptest with random preemption | M2 |
| Revoking an untyped and retyping it again gives the same objects at the same addresses | M4 self-test | M4 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Watermark (`capFreeIndex`) in 16-byte units | In bytes | The data word has room |
| `CONFIG_RESET_CHUNK_BITS` = 8; a preemption check every 100 work units | 4 KiB chunks; how often `preempt` polls is the kernel's choice | Fewer checks per page; `core/` stays agnostic of the polling cost |
| `size_bits` too small is `InvalidArgument` 1, too large `RangeError` 0 to 47 in object-size bits; a device type error is `InvalidArgument` 1; `node_depth` over 64 is `RangeError` 1 to 64, reported after `InvalidRoot` (`lookupSlotForCNodeOp`, `src/kernel/cspace.c`) | `RangeError` with the exact range of the argument at fault; the device error is `InvalidArgument` 0 (`type`); `node_depth` 0 to 64, checked before the root | Detail words name the argument at fault and its real range |
| `size_bits` of 64 or more is `RangeError` 0 to 47 for every type, fixed-size ones included (`decodeUntypedInvocation`), although `objects.tex`, "Summary of Object Sizes", says it is ignored | Ignored for fixed-size types | As the manual; the argument means nothing for them |
| A destination that is not a CNode is `MissingCapability` with `node_depth` bits left | 0 bits left; `InvalidRoot` when `root` is not a CNode | One meaning for "bits left" in CNode lookups ([Lookup failures](#lookup-failures)); paging `FailedLookup` counts virtual-address bits |
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
CNode and Untyped invocations. M5: capability lookups from the TCB's root.

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
had children, so whatever follows is no deeper. Either way the full list
stays a valid preorder.

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
after each; an interrupted call restarts, looks its slot up again and goes
on. Revoke re-reads its slot every step, so it stops cleanly if it deletes
the CNode holding its own slot; if it destroys the caller's TCB, the caller
is suspended and a preempted revoke is never restarted (the partial-revoke
cases of `cspace.tex`, "Deletion and Revocation").

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
(seL4 `hasCancelSendRights`) and does nothing for badge 0.

### Built when

M2: `l4core::cdt` (insert, move, swap, unlink, runs, `is_final`), the
slot operations and every type's derive rule (paging included), against
`model/`, which keeps an explicit parent map;
proptest compares capabilities and parents after every step, including at
random preemption points. M4: CNode invocations decoded. M5: reply masters
and reply capabilities, the TCB installs. M6: IPC
transfer, `CNode_SaveCaller` and `CNode_CancelBadgedSends`. M7: the
IRQ-node install. M9: Hypervisor narrowing.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Revoke deletes exactly the capabilities derived, directly or not, from the slot | `low`-run walk; proptest against `model/`'s transitive parent map | M2 |
| Deleting a capability changes no survivor's ancestry except that its children pass to its nearest surviving ancestor | `low` update in unlink; proptest | M2 |
| Rights never grow, a badge is set once, only Mint sets a badge, and a Hypervisor Mint never widens | `derive`, Mint and Mutate rules; proptest; badge scenario (M6); `core::hyperv` host tests; red-team brief 1 | M2, M6, M9, M10 |
| A PDPT, PageDirectory or PageTable capability is never derived, and a derived Frame capability is never mapped | `derive`; proptest; red-team brief 4 | M2, M5, M10 |
| A plain copy never has children, so holding one gives no power over other copies | the `original` rule; proptest | M2 |
| All capabilities to one object are adjacent, so `is_final` is exact | insertion next to the source; proptest compares `is_final` with `model/` | M2 |
| The list is consistent: `prev(next(a)) = a`, `low <= depth <= 4095`, empty slots have no links | `core/` operations; proptest checks every slot after every step; debug asserts | M2, M4 |
| No capability survives a completed revoke of an ancestor, whatever IPC, preemption or deletion is in progress | single-step revoke with restart; red-team brief 2 | M2, M5, M6, M10 |
| `depth` never exceeds 4095 and never wraps, so no capability leaves its ancestors' runs | one child-insert function in `l4core::cdt` checks the limit; proptest drives a chain to 4095 by copy and delete; red-team brief 1 | M2, M10 |
| Every path that installs a derived copy reports a refused child insert, and none assumes it succeeds | `IllegalOperation` from CNode Copy and Mint and `Untyped_Retype` (M4), the TCB installs (M5) and `IRQHandler_SetNotification` (M7); IPC transfer skips the capability (M6); tests at depth 4095 per path | M4 to M7 |

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
relies on the slots being at offset 0; `kernel/src/arch/x86_64/` pins it
with compile-time asserts.

| Offset | Bytes | Field | Contents |
| --- | --- | --- | --- |
| 0 | 160 | `slots[5]` | capability slots, 32 bytes each, the CNode slot format, so a Zombie treats TCB and CNode slots alike |
| 160 | 192 | `regs` | user register frame, 24 words |
| 352 | at most 256 | scalars | `state` (with the blocking data of [Thread states used by IPC](#thread-states-used-by-ipc)), `priority`, `mcp`, `time_slice`, `queued`, `fault` and `lookup_failure` (pending fault), `fault_ep` (CPtr), `ipc_buffer` (user address, 0 for none), `bound_notification`, `sched_prev`/`sched_next`, `ep_prev`/`ep_next` |
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

`regs` holds the 15 general registers, `rsp`, `rflags`, `fault_ip`,
`next_ip`, `fs_base`, `gs_base`, the exception error code and `exit`: 23
words, padded to 24.

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
- `exit` tells the exit path ([Exit](#exit)) whether `sysretq` may be
  used. Writing a thread's registers (WriteRegisters, CopyRegisters, a
  register-setting fault reply) forces `iretq`, because `sysretq` would
  overwrite `rcx` and `r11`.

### User register set and sanitising

Read/Write/CopyRegisters use seL4's 20-word order
([User register set](abi.md#user-register-set)): `rip`, `rsp`, `rflags`,
`rax` to `r15`, `fs_base`, `gs_base`. CS and SS are not in it; every
user thread runs on the user selectors. Every value the kernel installs, from
WriteRegisters, CopyRegisters, SetTLSBase or a fault reply, goes through
`l4core::regs::sanitise`:

| Register | Rule | Why |
| --- | --- | --- |
| `rip`, `rsp`, `fs_base`, `gs_base` | a value ≥ `0x0000_8000_0000_0000` becomes 0 | `sysretq` to a non-canonical RIP takes #GP in ring 0 on the user stack (Intel; from memory, check in M5); lower-half FS and GS bases make a `swapgs` mistake harmless under SMAP |
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
writes IA32_FS_BASE at once. (MSR behaviour from memory; check in M5.)

### Invocations

Labels `0x20` to `0x2D`, in seL4's order: ReadRegisters, WriteRegisters,
CopyRegisters, Configure, SetPriority, SetMCPriority, SetSchedParams,
SetIPCBuffer, SetSpace, Suspend, Resume, BindNotification and
UnbindNotification (M6; semantics in [Binding](#binding)), SetTLSBase. The
caller may not be the target of Read/WriteRegisters nor either side of
CopyRegisters. Priority setters check an authority TCB's MCP
([Priorities and MCP](#priorities-and-mcp)).

Dropped: SetAffinity (one core); SetBreakpoint, GetBreakpoint,
UnsetBreakpoint, ConfigureSingleStepping (no hardware debug API, so DR7 keeps
its reset value `0x400`, with no breakpoint enabled); SetEPTRoot (no VT-x); SetFlags (every thread has FP state);
SetTimeoutEndpoint (MCS). Nothing is added.

### Creation and configuration

Untyped_Retype zeroes the TCB, then sets `Inactive`, priority 0, MCP 0, a full
slice and `rflags = 0x202`, copies the FP template into `xsave`, puts the
thread's reply master in its `reply` slot ([Reply
capabilities](#reply-capabilities)), and in debug builds appends the TCB to
the debug list. `exit` is `Iret`, its zero value.
The creator calls Configure, SetSchedParams, and WriteRegisters with
`rip`, `rsp` and `resume_target`.

The IPC buffer frame (Configure, SetIPCBuffer) must be a non-device Frame that
is not one of the two SynIC pages, whose physical addresses the kernel records
at boot; those are refused with InvalidCapability, because the hypervisor
writes them and the kernel must never read one as an IPC buffer.

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
while its fault message waits never sends it later.

Deleting the last capability to a TCB unbinds its notification, suspends it,
removes it from the debug list (debug builds), drops FP ownership without
saving, clears a scheduler action naming it, then deletes the five slots with
the long-running delete of
[Deletion and finalisation](#deletion-and-finalisation) (seL4 `finaliseCap`,
`src/object/objecttype.c`). Afterwards nothing in the kernel names the TCB,
except `current` until the kernel entry ends. A thread deleting its own last
TCB capability is `Inactive` at once and gets no reply; if its slot deletion
hits a preemption point, the remainder waits in the slot until someone deletes
it again, as with seL4's Zombie.

A fault handler is whichever thread receives on the fault endpoint; no TCB
names it. Deleted while waiting, it leaves the endpoint queue and faulting
threads wait for the next receiver. Deleted after receiving a fault, its caller
slot goes and the faulting thread stays `BlockedOnReply` until someone with its
TCB capability resumes it (it re-executes the faulting instruction) or
suspends it. If the fault endpoint is deleted, threads queued on it restart,
fault again, find no endpoint and become `Inactive`.

### `core/` and `arch/`

`l4core::regs` (M5) holds the register-set order, `sanitise`, and the fault
encoder and reply decoder. `l4core::tcb` (M5) decodes each TCB invocation into
a typed request or an error; the M10 fuzzer targets it. `arch` (M5) owns the
frame layout, XSAVE, MSRs and control registers. `core` names TCBs by `TcbRef`
handles (physical addresses) and reaches fields through a `Tcbs` trait, which
the kernel implements in `arch` over the direct map and host tests over a
`Vec`.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every register value installed for ring 3 passes `sanitise`: `rip`, `rsp`, FS and GS base below 2^47; RFLAGS with IF = 1, IOPL = 0, TF = NT = AC = 0 | `l4core::regs::sanitise` called by every writer; proptest | M5 |
| A user thread always runs in ring 3 on the user CS and SS; no invocation names CS or SS | register set excludes them; frame initialised at retype | M5 |
| Returning to ring 3 never faults in ring 0 | sanitiser plus the exit path's checks; red-team scenario resuming threads with random registers | M5, M10 |
| User FS and GS bases stay below 2^47, and CR4.FSGSBASE = 0 | sanitiser; arch init; boot self-test reads CR4 | M5 |
| In a TCB that is not itself being destroyed, slot 0 holds only a CNode or a Zombie left by an interrupted deletion, slot 1 only a VSpace root, slot 2 only a non-device Frame that is not a SynIC page, or nothing; no CPtr names a TCB slot | `l4core::tcb` decode checks, host tests | M5 |
| The kernel never uses a SynIC message or event page as an IPC buffer | SetIPCBuffer and Configure compare the frame with the addresses recorded at boot; host test | M5, M9 |
| No TCB slot install exceeds `MAX_DERIVATION_DEPTH` | the one child-insert function in `l4core::cdt`; host test at depth 4095 | M5 |
| At every kernel exit after a TCB is finalised, no ready or endpoint queue, reply capability, scheduler action, `current`, FP owner or debug list names it; nor, from M6, any notification queue or bound notification | finalisation sequence; scheduler proptest and scenarios with deletes (M5); IPC state-machine proptest (M6); red-team brief 2 | M5, M6 |
| A suspended or deleted thread has no pending fault | `cancel_ipc` clears `fault` | M5 |
| A thread that suspends itself and is resumed continues after its `syscall` with a NoError reply | Suspend writes the reply first; `l4core::tcb` host test; QEMU scenario `suspend_self` | M5 |
| User threads cannot set debug registers; DR7 keeps its reset value `0x400`, with no breakpoint enabled | no invocation writes them | M5 |

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
interrupt calls `sched::tick()` on each tick. Unless idle, `tick` decrements
the current thread's `time_slice`; at 0 it refills it with `TIME_SLICE_TICKS` =
1 and ends the slice. Slices are charged in whole ticks: a thread switched in
just before a tick loses most of its slice, and one that always blocks just
before the tick is never charged. seL4's non-MCS scheduler has the same
property at 2 ms; it is accepted here and checked by red-team brief 9
([Open questions](#open-questions)).

### Idle thread

The idle thread is a kernel context in static memory, not a TCB object: never
queued, below every priority, with no capabilities and no FP state. It runs in
ring 0 on the kernel's own page tables, which have no lower-half entries after
M3, so a VSpace deleted while the kernel idles is never live in CR3. It runs a
`sti; hlt` loop. An interrupt taken there discards the idle frame and runs the
normal interrupt path, after which `schedule()` picks a thread or idles again.
The entry and exit paths for this are in [Interrupts and exceptions taken in
ring 0](#interrupts-and-exceptions-taken-in-ring-0) and
[Interrupts](#interrupts).

### `core/` and `arch/`

`l4core::sched` (M5) holds the queues, bitmap, `action`, the decision, `tick`,
`yield` and `check_prio`, generic over the `Tcbs` trait; proptest runs random
operation sequences against a model of 256 `VecDeque`s and checks the
invariants after every step. `arch` (M5) does the switch itself (CR3 through
`set_vm_root` ([Where the code lives](#where-the-code-lives)), FS and GS
base, FP state), the idle loop and the tick glue.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| At every kernel exit the current thread is runnable or idle, and no queued thread has a higher priority | `l4core::sched::schedule`, proptest against the model | M5 |
| At every kernel exit, each runnable thread but the current one is in exactly the queue of its priority, no other thread is queued, and bitmap bit `p` is set exactly when queue `p` is non-empty | `l4core::sched`, proptest | M5 |
| `SwitchTo(t)` names a runnable, unqueued thread other than the current one | `make_runnable` and Suspend; proptest | M5 |
| No invocation sets a priority or MCP above the authority's MCP | `l4core::sched::check_prio`, `u8` types, host tests | M5 |
| A thread at the highest runnable priority waits at most one slice per other thread at that priority, plus one tick | tail rule and tick; QEMU scenario `sched_rr` (two threads interleave) | M5 |
| A lower-priority thread never runs while a higher-priority thread is runnable | decision rule; QEMU scenario `sched_prio`; red-team brief 9 | M5, M10 |
| The idle thread is never queued, never owns FP state, holds no capabilities | not a TCB object (type) | M5 |

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

(Bit meanings from memory; check in M5.) The M3 feature check already
requires CPUID.1:ECX.XSAVE (bit 26) ([CPU features](#cpu-features)). M5 checks
that CPUID.(EAX=0xD, ECX=0).EAX has bits 0 and 1 before XSETBV (as seL4's
`Arch_initFpu` checks its feature mask), writes XCR0, and reads
CPUID.(EAX=0xD, ECX=0).EBX, the area size for the enabled features: it
panics if that exceeds the TCB's 1024-byte reserve (for x87 and SSE it is
576). From M5 the boot summary also prints XCR0 and the size, for the
Hyper-V check. QEMU's default TCG model, `qemu64`, lacks XSAVE
(from memory), so from M3 xtask's `base_command()` passes
`-cpu max,la57=off`, and a scenario `cpu_refuse` uses the `qemu_args:` key to
boot `-cpu qemu64` and expect the kernel's one refusal line, which names XSAVE
among the missing features. The Hyper-V VM runs with processor
compatibility mode off (`tools/hyperv/New-L4Vm.ps1`).

Only x87 and SSE, seL4's default (`XSAVE_FEATURE_SET` 3, `XSAVE_SIZE` 576 in
`src/arch/x86/config.cmake`), so QEMU TCG and every Hyper-V host behave alike
([ADR 0014](adr/0014-fp-simd.md)). AVX raises #UD; its 832-byte state
would fit the reserve later without changing `TCB_BITS`.

### Switching (M5)

`fpu_owner` names the TCB whose state is in the registers, or none. Before
returning to user thread `t` with `fpu_owner != t`, the kernel XSAVE64s the
owner's state into its `xsave` (if there is an owner), XRSTOR64s `t`'s, and
sets `fpu_owner = t`, with XCR0 as the feature mask. The idle thread and the
kernel never take ownership, so A, idle, A costs nothing. Every switch between
two user threads swaps the state and nothing traps: PLAN.md's eager switching,
with seL4's owner tracking (`lazyFPURestore`, `include/machine/fpu.h`).
Deleting the owner clears `fpu_owner` without saving; the next XRSTOR64 loads
every enabled component, so nothing of it survives. Plain XSAVE64 (seL4's
default too) exists wherever XSAVE does, keeps fixed offsets, and avoids
reasoning about XSAVEOPT's modified optimisation.

### Initial state

`l4core` holds a 576-byte template built from constants: FCW `0x037F`, FSW 0,
abridged FTW 0 (all empty), MXCSR `0x1F80`, registers 0, XSTATE_BV `0x3`,
XCOMP_BV and reserved header bytes 0. A new thread starts with every x87 and
SIMD exception masked, 64-bit precision, round to nearest and zeroed
registers, as in seL4 after `finit` and `MXCSR_INIT_VALUE`
(`src/arch/x86/machine/fpu.c`), but the kernel executes no x87 or SSE
instruction to make it. (Offsets from memory; a host test pins them, and an M5
scenario reads FCW and MXCSR in a new thread.)

### FP exceptions

#MF (16, an unmasked x87 exception at the thread's next waiting x87
instruction) and #XM (19) become UserException with code 0; #UD from disabled
AVX becomes UserException 6. #NM cannot happen; if it does it is
UserException 7. XSAVE64 and XRSTOR64 do not raise a pending x87 exception
(from memory; check in M5), so it travels with its thread's state. No
invocation exposes FP state, so a handler cannot read FSW or MXCSR
([Open questions](#open-questions)).

### The kernel never touches SSE; the user target

`x86_64-unknown-none` turns off MMX and SSE and selects soft float,
`kernel/src/main.rs` refuses to compile with `target_feature = "sse"`, and
kernel assembly uses only XSAVE64, XRSTOR64, XSETBV and XGETBV. So a user
thread's state stays live across kernel entries and is swapped only when the
thread changes. Default for M5: user crates also build for
`x86_64-unknown-none` through M10, since no planned program needs floating
point. The kernel switches the state regardless, because isolation must not
depend on what user code executes, so a later SSE target needs no kernel
change.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A thread never observes another thread's x87 or SSE state, a deleted thread's included | XRSTOR64 with XCR0 whenever ownership changes; owner cleared on delete; QEMU scenario `fp_isolation` (two threads keep distinct XMM and x87 values across preemption) | M5 |
| The kernel executes no FP or SIMD instruction but XSAVE64, XRSTOR64, XSETBV, XGETBV | `x86_64-unknown-none` and `compile_error!` on SSE (both in place since M0); review of `arch` assembly | M5 |
| XRSTOR64 in the kernel never faults | areas written only by XSAVE64 or from the template; no invocation exposes them; host test of the template's header and MXCSR | M5 |
| XCR0 is `0x3` and the enabled area fits the TCB's reserve | boot check of CPUID leaf 0xD | M5 |
| The kernel refuses to boot on a CPU without XSAVE, with its one refusal line, rather than fault later | the M3 feature check ([Privilege levels](#privilege-levels)); QEMU scenario `cpu_refuse` (`qemu_args: -cpu qemu64`) | M3 |
| The FP owner is never a finalised TCB | TCB finalisation clears it | M5 |
| CR0.TS = CR0.EM = 0, CR0.NE = 1, CR4.OSFXSR = OSXMMEXCPT = OSXSAVE = 1 from boot on | arch init; boot self-test reads them back | M5 |

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
| 1 #DB | UserException, code 0: TF single-step or `int1`. #DB runs on IST4; a ring-0 #DB returns only when its saved RIP is exactly `syscall_entry` (a `syscall` executed with TF set) and panics otherwise |
| 3 #BP | UserException, code 0, `rip` past the `int3`: vector 3 is the only DPL-3 gate |
| 10 #TS, 11 #NP, 12 #SS, 13 #GP | UserException with the error code; `int n` for any `n` but 3 hits a DPL-0 gate and arrives as #GP with code `8n + 2` |
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
fault and never blocks the kernel.

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
  faults and `rip` (seL4 `handleDoubleFault`, `src/kernel/faulthandler.c`).
  The root task's `fault_ep` is 0, so a fault stops it.
- A handler that faults sends to its own fault endpoint. A thread that handles
  its own faults deadlocks with itself, a user error the kernel ignores.
- A ring-0 exception is a kernel bug and panics.

### `core/` and `arch/`

`arch` turns a ring-3 vector, error code and CR2 into a `Fault` (M3 decodes,
M5 classifies). `l4core::regs` holds `Fault`, the encoder and the reply
decoder (M5). Delivery, reply capabilities and fault replies are built in M5
with the endpoint path they need; from M6 they are operations of the IPC
state machine in `l4core` under its proptest.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every ring-3 exception the configuration allows, and every failed lookup, ends with a fault message on an endpoint the thread could Call, or with the thread `Inactive`; never with a kernel panic | fault path in `l4core` and `arch`; QEMU scenarios `vmfault`, `fault_no_handler` and one per reachable vector (M5); IPC state-machine proptest (M6) | M5, M6 |
| A fault is sent only to an endpoint capability with Write plus Grant or GrantReply, checked at fault time | delivery step 1; host test | M5 |
| A fault message carries only the faulting thread's own registers and fault data | encoder reads only the faulting TCB; host tests | M5 |
| A fault reply changes only the registers its fault type names, through `sanitise`, and only label 0 restarts | `l4core::regs` reply decoder, host tests | M5 |
| Fault delivery never blocks or faults the kernel and allocates nothing | delivery is a Call that blocks the faulting thread and touches kernel memory only | M5 |
| A ring-0 #DB returns only to `syscall_entry`; every other ring-0 #DB, and any of vectors 9, 15, 17 or 20 to 31, panics | IDT handlers (M3); QEMU scenario: a thread runs `syscall` with TF set and is single-stepped into its own handler (M5) | M3, M5 |
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
`kernel/src/arch/`. M5 builds the endpoint calls that fault delivery needs
([ADR 0023](adr/0023-fault-ipc-in-m5.md)); M6 adds capability transfer and
notifications and tests the whole machine on the host under proptest.

### Endpoint states and queues

An endpoint has a state and one queue of TCBs, oldest first.

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
writable IPC buffer. Then:

1. The `extra_caps` pointers are looked up again in `S`'s CSpace, because
   `S` may have blocked since the send-time lookup. If any lookup fails, no
   capability moves.
2. The receive slot is found once: `receive_cnode`, resolved with all 64 bits
   in `R`'s CSpace, must be a CNode capability; `receive_index`, resolved
   from it with `receive_depth` bits, must reach a slot; the slot must be
   empty. Otherwise there is no slot.
3. For each capability `i` in order: if it is an endpoint capability to `E`,
   its badge goes into `R`'s `caps_or_badges[i]`, bit `i` of
   `caps_unwrapped` is set, and the capability itself is not copied (this
   never happens for replies, which have no `E`). Otherwise, if the slot is
   still free, the capability passes the capability core's `derive` (reply
   capabilities never do), and `insert_derived` accepts the copy below
   `MAX_DERIVATION_DEPTH`, the copy goes into the slot with the same rights
   and badge, derived from `S`'s capability exactly as `CNode_Copy` would
   place it, and the slot is used. Otherwise the loop stops; a copy refused
   at the depth limit is simply not transferred, like any capability that
   cannot be derived.
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
  `CNode_SaveCaller` (label `0x18`) moves it from the caller slot into a
  CSpace slot, so a server can keep a client waiting while it serves others;
  the saved capability is used with `Send`, `NBSend` or `Call`.
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
or change the badge it sends.

### Deletion and cancellation

| Event | Queue side | The removed thread becomes |
| --- | --- | --- |
| The final capability to endpoint `E` is deleted | `cancel_all_ipc(E)`: every queued thread leaves, and is made runnable, in queue order; `E` becomes `Idle` | `Restart` |
| `CNode_CancelBadgedSends` on a capability to `E` with badge `b` and all four rights, Read, Write, Grant and GrantReply ([Badges, revoke and `CNode_CancelBadgedSends`](#badges-revoke-and-cnode_cancelbadgedsends)) | `cancel_badged_sends(E, b)`: every `BlockedOnSend` thread whose stored badge is `b` leaves, in queue order, the rest keep their order; nothing for `b` = 0 or a `Recv` queue | `Restart` |
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
messages already delivered are not affected.

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

IPC does no priority inheritance or donation
([ADR 0018](adr/0018-ipc-priorities.md)). A woken thread is passed to the
scheduler's `make_runnable`. IPC never switches threads itself; the
scheduler's tie rule
([Scheduler action and decision](#scheduler-action-and-decision)) runs a
`Call` or `ReplyRecv` partner at once. IPC never reads or changes a priority
or timeslice. Inversion is avoided by configuration: `root` gives each
server a priority at least that of every client, an immediate priority
ceiling, and the maximum controlled priority
([Priorities and MCP](#priorities-and-mcp)) stops a client raising itself
past it.

### Where the code lives

| Part | Where | Milestone |
| --- | --- | --- |
| `MessageInfo` packing, IPC buffer word indices, message-register mapping | `l4core::ipc`, shared with `libsys` | M5 |
| Endpoint and thread-state types; `Send`, `NBSend`, `Call`, `Recv`, `NBRecv`, `Reply`, `ReplyRecv` on endpoints without capability transfer; reply capabilities; fault delivery; `cancel_ipc`, `cancel_all_ipc` | `l4core::ipc`, generic over `IpcEnv` | M5 |
| Capability transfer and unwrapping, badge tests, notifications and binding, `CNode_SaveCaller`, `cancel_badged_sends`, `cancel_all_signals` | `l4core::ipc` | M6 |
| Reference model and the IPC state-machine proptest | `model/`; tests in `core/` | M6 |
| `IpcEnv` for the kernel: object access, saved register frames, IPC buffer frames | `kernel/src/arch/x86_64/` | M5, M6 |
| System-call dispatch, capability lookup, rights checks | kernel, safe code calling `l4core` | M5, M6 |

M5 builds what its done-when test needs: a page fault reaches a handler
thread through an endpoint, which needs fault delivery and reply
capabilities, and the handler kills the faulting thread, which is
`BlockedOnReply` and so needs `cancel_ipc`. Once user code can delete an
endpoint, its finalisation needs `cancel_all_ipc`. M5's host tests cover
these functions; M6 adds the rest and the proptest.

`core/` names objects by physical-address handles (`TcbRef`, `EpRef`,
`NtfnRef`) that wrap `NonZeroU64`: no kernel object lies at physical address
0, because M4 makes no untyped below 1 MiB, so a stored 0 means none.
Handles are made only from a capability of the matching type or from links
IPC maintains. `IpcEnv` extends the capability core's `Kernel` trait: it
loads and stores endpoints, notifications and the TCB's IPC fields by value,
reads and writes message words by index (0 to 3 in saved registers, 4 to 119
in the buffer, `None` without a usable buffer), and calls the scheduler
(`make_runnable`, dequeue). As for slots, `arch/` reads and writes through
raw pointers into the direct map and never forms a Rust reference into an
object or an IPC buffer. Buffers may alias: two threads may name the same
1 KiB (sender and receiver included), and a DMA-capable device may write it.
The `SAFETY:` argument is the no-dangling invariant below and the rule that
no object lies at address 0; `model/` implements the same trait over maps.
Proptest runs random system calls by a few threads on a few endpoints and
notifications, mixed with kernel signals, binds, suspends, deletions and
badge cancellations; each step lets any `Running` thread act,
so the model does not depend on the scheduler's choice. After every step it
compares thread states, queues, notification words, caller slots and
delivered registers with the model.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| No kernel object lies at physical address 0 | M4 untyped builder, host test; `core/` handles are `NonZeroU64` | M2, M4 |
| A thread is in at most one queue, and it is in object `O`'s queue exactly when it is `BlockedOnSend`, `BlockedOnReceive` or `BlockedOnNotification` on `O` | `l4core::ipc` queue functions and their host tests; proptest against `model/` after every step | M5, M6 |
| An endpoint is `Idle` exactly when its queue is empty; in `Send` every queued thread is `BlockedOnSend` on it, in `Recv` every one is `BlockedOnReceive` | `l4core::ipc` and host tests; proptest | M5, M6 |
| Queued threads are served in arrival order | host tests; proptest against the model's FIFO queues | M5, M6 |
| No queue, link or reply capability refers to a deleted endpoint, notification or TCB: finalisation empties queues and bindings, and deleting a TCB cancels its IPC, before the memory can be retyped | `cancel_ipc` and `cancel_all_ipc` from finalisation (M5); `cancel_all_signals` and unbind (M6); proptest with deletions; red-team brief 2 | M5, M6, M10 |
| A reply capability, other than a master, exists only while the thread it names is `BlockedOnReply`, and there is at most one per thread | `send`, `receive`, `reply`, `cancel_ipc` and their host tests; proptest | M5, M6 |
| Every TCB's `reply` slot holds its own master reply capability, a derivation root at depth 0, from retype (or, for the root task's TCB, from boot) until finalisation; nothing but that finalisation copies, moves, revokes or deletes a master, and only a master has a reply capability derived from it | TCB retype; the capability core refuses masters as sources and inserts reply capabilities only under one; proptest | M5, M6 |
| A thread `BlockedOnReceive` has an empty caller slot | receive step 1, host test; proptest | M5, M6 |
| The receiver gets the first delivered-length words of the sender's message and nothing else from any thread; its other message registers keep its own values | `transfer` and host tests; proptest comparing register sets; ping-pong scenario | M5, M6 |
| The kernel reads an IPC buffer only through a non-device frame capability in the TCB's IPC buffer slot, writes it only with Write, and touches only its 128 words | `IpcEnv` buffer accessor takes a word index below 128; `TCB_SetIPCBuffer` checks ([Creation and configuration](#creation-and-configuration)) | M5 |
| A capability moves by IPC only if the sender's capability has Grant, only into an empty slot the receiver named, at most one per message, with unchanged rights and badge, derived from the sender's capability by `derive` and `insert_derived` below `MAX_DERIVATION_DEPTH` | transfer loop; proptest; capability-transfer scenario; red-team brief 1 | M6, M10 |
| Only an endpoint capability to the endpoint carrying the message is unwrapped, and the receiver learns only its badge | transfer loop; proptest | M6 |
| The badge a receiver sees is the badge of the capability the sender invoked, or 0 for a reply; no sender can choose it | `send` stores the capability's badge (M5); badge scenario (M6) | M5, M6 |
| `Send` and `Call` need Write, `Call` also Grant or GrantReply, receiving needs Read, and a fault endpoint needs Write and Grant or GrantReply, checked at fault time | dispatcher and fault-path checks; syscall fuzzer, red-team brief 6 | M5, M10 |
| A thread leaves a blocked state only by completing its operation or through `cancel_ipc`, `cancel_all_ipc`, `cancel_badged_sends` or `cancel_all_signals`, so a restarted thread re-executes its system call with its own arguments | `l4core::ipc` state machine and host tests; proptest | M5, M6 |
| A thread's fault record is set only while it is `BlockedOnSend` or `BlockedOnReply` for that fault | `send`, `reply`, `cancel_*` and host tests; proptest | M5, M6 |
| Every IPC system call finishes in one kernel entry, in time bounded by the message (120 words, 3 capabilities) or, for a cancellation, by its queue, which holds at most the TCBs that exist (2^18 in 512 MiB with `TCB_BITS` = 11); no argument makes the kernel block or panic | no other loop in `l4core::ipc`; syscall fuzzer, red-team brief 6; worst-case cancellation measured by red-team brief 9 | M5, M6, M10 |
| IPC never changes a thread's priority or timeslice | `IpcEnv` has no method that can; red-team brief 9 | M5, M10 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| An endpoint is 16 bytes (`seL4_EndpointBits` = 4), its tail pointer and state packed into one word (`include/object/structures_64.bf`) | 32 bytes, every field a whole word ([Objects](abi.md#objects)) | `core/` reads plain `#[repr(C)]` words with no bit packing; the cost is 16 bytes per endpoint |
| `Call` on a capability without Grant or GrantReply delivers the message and leaves the caller `Inactive` (`src/object/endpoint.c`, `sendIPC` and `receiveIPC`; `ipc.tex`, "Calling and Replying") | `Call` returns `InvalidCapability` and sends nothing | the rights are known when the call is decoded; a silently suspended client is a hang nobody can diagnose, and no protocol needs it |
| `CNode_SaveCaller` with an empty caller slot succeeds and leaves the destination empty (`src/object/cnode.c`, `invokeCNodeSaveCaller`) | returns `IllegalOperation` | the server learns it had nothing to save instead of failing later on an empty slot |
| Non-MCS `cancelIPC` clears the fault record only for `BlockedOnReply`, and non-MCS `cancelAllIPC` and `cancelBadgedSends` restart a fault sender without clearing it; MCS clears it in `cancelIPC` and makes a cancelled fault sender `Inactive` (`src/object/endpoint.c`, `cancelIPC`, `restart_thread_if_no_fault`) | every cancellation clears it and restarts the thread, which re-raises the fault if its cause remains | `doIPCTransfer` (`src/kernel/thread.c`) sends a fault message whenever the record is set, so a stale record would turn a later ordinary send into a fault message, and `doReplyTransfer` would treat the reply to a later `Call` as a fault reply |
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
| `Idle`, bound to a thread `T` that is `BlockedOnReceive` on any endpoint | `T` leaves that endpoint's queue and becomes `Running` with `rdi` = `b` and `rsi` = 0 |
| `Idle`, otherwise | `N` becomes `Active` with word `b` |
| `Active` | word = word OR `b` |

A signal never blocks and never fails, so the interrupt path never waits on
user space. A bound thread that is `BlockedOnReply`, `BlockedOnSend` or
waiting on another notification is not woken; the signal stays pending
until it next receives on an endpoint or waits on this notification.
Repeated signals coalesce: a waiter sees which bits were signalled, not how
often, and interrupts that arrive before the driver waits are merged, not
lost. The IRQ and SynIC paths use exactly this `signal`, with the badge of
the notification capability they hold.

### Wait and poll

`wait(T, N, blocking)` runs for `Recv` (blocking) and `NBRecv` (not) on a
notification capability with Read. If `N` is bound, only its bound thread
may wait on it; any other thread takes a capability fault.

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
notification capability with Read, and fails if the TCB is already bound or
the notification is bound or has waiters. Binding sets the TCB's
`bound_notification` and the notification's `bound_tcb`. If the
notification is already `Active` and the TCB is `BlockedOnReceive`, the
signal is delivered at once, as if it had arrived after binding.

A bound thread gets a pending signal instead of an IPC at step 2 of the
receive phase, is woken out of an endpoint receive by a signal, and may still
wait on the notification directly. It tells a signal from a message by
badge: `root` gives the notification capabilities badges that no endpoint
capability uses. `TCB_UnbindNotification` clears both links; a thread
already waiting directly on the notification stays queued. Deleting the TCB,
or the final capability to the notification, also unbinds.

### Deletion

When the final capability to `N` is deleted, the kernel unbinds it and runs
`cancel_all_signals(N)`: every waiter, in queue order, becomes `Restart`
(its retried `Recv` resolves its `CPtr` afresh, as for endpoints), the
pending word is discarded, and `N` becomes `Idle`. Like the endpoint
cancellations, the loop is not preemptible and its queue is bounded by the
TCBs that exist. `cancel_ipc` on a `BlockedOnNotification` thread removes it
from the queue.

### Where the code lives

`Notification`, `signal`, `wait`, bind, unbind and `cancel_all_signals` live
in `l4core::ipc` and share the endpoint code's `IpcEnv`, model and proptest
(M6). The kernel's interrupt signal is M7's; the SynIC one is M9's.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A notification is `Waiting` exactly when its queue is non-empty; `Idle` and `Waiting` have word 0; `Active` has an empty queue | `l4core::ipc`; proptest against `model/` | M6 |
| Binding is one to one and symmetric: `T.bound_notification` = `N` exactly when `N.bound_tcb` = `T` | bind, unbind and finalisation; proptest | M6 |
| While a notification is bound, only its bound thread waits on it | bind refuses a notification with waiters; dispatcher check; red-team brief 1 | M6, M10 |
| A bound thread is never `BlockedOnReceive` while its notification is `Active` | `signal` and bind deliver at once; proptest | M6 |
| No signalled bit is lost: each is returned to exactly one waiter or bound receiver, or is still pending, until the notification is deleted | proptest against the model | M6 |
| A signal never blocks or fails, so interrupt delivery never waits on user space | `signal` has no blocking path; IRQ scenario | M6, M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| A notification is 32 bytes (`seL4_NotificationBits` = 5 without MCS), its queue tail and state packed into one word (`include/object/structures_64.bf`) | 64 bytes, every field a whole word ([Objects](abi.md#objects)) | as for endpoints; the cost is 32 bytes per notification |
| A delivered signal sets only the badge register; `rsi` keeps whatever the thread passed in (`src/object/notification.c`, `sendSignal`, `receiveSignal`, `completeSignal`) | `rsi` is set to 0 | every register a receive returns is defined |
| Binding a thread that is `BlockedOnReceive` to an `Active` notification leaves the signal pending, and later signals only OR into the word, until an IPC arrives (`src/object/notification.c`, `bindNotification`; `src/object/tcb.c`, `decodeBindNotification`) | the pending signal is delivered at bind | closes a wake-up that could otherwise wait forever, and keeps the invariant above unconditional |

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
| `0x00`-`0x1F` | CPU exceptions | from ring 3: a fault to the thread's handler ([Faults](#faults)), except NMI, #DF and #MC, which panic ([NMI, double fault, machine check and debug](#nmi-double-fault-machine-check-and-debug)); 9, 15, 17 and 20 to 31 cannot occur and panic from either ring; from ring 0: panic with the decoded frame (M3), except a `#DB` at `syscall_entry`, which returns ([Kernel entry and exit](#kernel-entry-and-exit)) |
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
handler. `int1` raises `#DB` without a DPL check (from memory; check in M10
brief 5): from ring 3 it is UserException 1; a ring-0 `#DB` returns only when
the saved RIP is exactly `syscall_entry`, and any other panics. Vectors 9, 15,
17 (`#AC`, CR0.AM = 0) and 20 to 31 (`#VE` not enabled, `#CP` without CET, 29
and 30 SEV only, the rest reserved) cannot occur; only an injected MSI reaches them, and the
kernel panics. Their gates take the no-error-code entry, so the panic reads
the frame correctly. An MSI cannot inject vectors 0-15, which the LAPIC
rejects as illegal (SDM, from memory). The kernel takes interrupts only with
IF = 1, in ring 3 or the idle loop ([Idle thread](#idle-thread)). A preemption
point polls the LAPIC IRR words for `0x30`-`0xFE`, masking off `0x20`-`0x2F`
in the word they share with `0x30`-`0x3F`, as seL4's
`apic_is_interrupt_pending` does (`src/arch/x86/kernel/xapic.c`); it never
opens an `sti` window.

### Local APIC, PIC and I/O APIC (M3)

The kernel reaches the LAPIC, the I/O APICs and the HPET only through the
kernel device window at `KERNEL_DEVICE_BASE`
([The kernel half](#the-kernel-half)): LAPIC at offset 0, I/O APIC `i` at
`0x1000 * (1 + i)` (`i` < 4), HPET at `0x5000`. The 2 MiB direct-map pages
that hold these devices are mapped uncached as well, and M4 makes no RAM
untyped from them.

With IF = 0: if the MADT flag `PCAT_COMPAT` is set, remap the PIC to
`0x20`/`0x28` and mask all lines. If `IA32_APIC_BASE` shows x2APIC mode, leave
it through the disabled state, since the SDM forbids x2APIC to xAPIC directly
(from memory; check in M3); the M3 boot summary prints `IA32_APIC_BASE`.
Mask the LVT timer (the firmware may have armed it), LINT0, LINT1, and the
thermal, performance and CMCI LVTs if present; TPR = 0; SVR = enabled, vector
`0xFF`, EOI-broadcast suppression off (level-triggered pins need it); LVT
error = `0xFE`. Mask every I/O APIC redirection entry. Then calibrate and
start the timer. xAPIC because every x86-64 CPU and both platforms offer it
and OVMF hands over in xAPIC mode with one vCPU (from memory; the boot summary
shows it), so one path runs on every boot even though QEMU's `-cpu max`
also offers x2APIC (from memory). Lost: only the speed of the MSR access
Hyper-V recommends (TLFS CPUID `0x4000_0004` EAX bits 3 and 8).

The MADT gives up to four I/O APICs (ID, base, GSI base); the pin count is the
version register's MRE + 1. On issue the kernel first writes the pin's entry
masked and edge-triggered, keeping its old vector, and reads back Remote IRR.
If it is set, the kernel writes the old vector to the I/O APIC's EOI register
(version `0x20` or later; from memory, check in M7) and reads again; if it is
still set, the issue fails with `RevokeFirst` and the pin stays masked. Only
then does it write the final entry: vector, fixed delivery, physical
destination the boot CPU, the requested trigger and polarity, unmasked.
ISA IRQ `n` goes to GSI `n`, edge, active high, unless an override (bus 0,
source `n`) gives the GSI and flags ("conforms to bus" means the ISA default).
An ISA IRQ whose GSI is another IRQ's override target has no route (IRQ 2 on
q35, where IRQ 0 goes to GSI 2; from memory). COM1 is ISA IRQ 4 on GSI 4,
edge, active high, on both platforms (from memory; the M3 host tests on the
dumped MADTs check it).

### The IRQ table

Fixed kernel memory, indexed by IRQ number 0-191: `source` (`Free`,
`IoApic { gsi, level, active_low }`, `Msi` or `Sint(n)`), `pending` (an edge
pin delivered since the last Ack), `masked` (the kernel masked the pin and
waits for Ack), and an IRQ node slot holding the bound notification
capability or nothing. IRQ node slots are ordinary 32-byte slots in kernel
static memory, in the derivation list and reached by the same slot handles as
CNode slots; no `CPtr` names them and the Zombie code never visits them.
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

Each checks that the source is free, takes the lowest free vector, programs the
source and writes an IRQHandler capability (holding the IRQ number) into the
destination slot as a revocable child of IRQControl. A source that already has
a handler, no free vector, or a pin whose Remote IRR stays set gives
`RevokeFirst`.

IRQHandler capabilities can be copied; mint data is ignored.
`SetNotification(ntfn)` needs a notification capability with the Write right
(seL4's `CanSend`) and fails with `IllegalOperation` if the copy would
exceed `MAX_DERIVATION_DEPTH`; after every check it deletes any bound
capability, then copies the given one, badge included, into the IRQ node slot.
`Clear` deletes the bound capability. `Ack` clears `pending` and unmasks the
pin if the kernel masked it; for MSI and SINTs it does nothing.

| Source | On issue | On delivery | On Ack | On handler deletion |
| --- | --- | --- | --- | --- |
| I/O APIC, level | Remote IRR checked, then programmed unmasked | masked before EOI | unmasked | mask bit set; vector and trigger kept |
| I/O APIC, edge | Remote IRR checked, then programmed unmasked | `pending` set; if it was already set, masked | `pending` cleared; unmasked if masked | mask bit set; vector and trigger kept |
| MSI | vector reserved | unchanged | nothing | vector freed |
| SINT | SINTn = vector, unmasked | unchanged | nothing | SINTn masked |

A level line re-fires at every EOI while asserted, so it stays masked until
the driver has serviced its device. An edge pin stays open for the first edge
after an Ack, so no edge that follows an Ack is lost, even on an I/O APIC that
drops edges on a masked pin (82093AA datasheet, from memory; QEMU latches
them). A second edge before Ack masks the pin, so a device the driver cannot
or will not quiet (the PIT at its highest rate, say) costs at most three
interrupts per Ack (two, plus one the local APIC may already hold when the
mask lands), and interrupt load follows the driver's own scheduling.
An edge lost while masked comes after a signal the driver has not yet
handled, so draining the device before Ack still sees it. An MSI cannot be
masked without touching the device; a masked SINT loses message interrupts
and makes the host's `HvCallSignalEvent` fail (TLFS
`inter-partition-communication.md`). Every driver runs one loop: wait,
service, Ack. After `SetNotification` it Acks once and services its device
once, since an interrupt between issue and binding signalled nothing.

### Delivery

On vector `v` in `0x30`-`0xEF`, with the interrupted thread's registers saved:
take entry `v - 0x30`; if it is `Free`, drop the interrupt (a stale MSI, or a
source deleted while pending); for a level pin, mask it and set `masked`; for
an edge pin, if `pending` is set mask it and set `masked`, then set `pending`;
if the IRQ node slot holds a notification capability, signal that notification
with the capability's badge (the semantics of [Signal](#signal)), else bump a
debug counter; EOI; return through the scheduler. The work is constant and
reads no user memory. An interrupt with no notification is lost, but the pin's
state still advances, so the driver's Ack is still needed.

### Deletion

Deleting the final IRQHandler capability deletes the IRQ node capability
(which may finalise the notification, as seL4's `deletingIRQHandler` does),
masks the source (an I/O APIC pin: only its mask bit, keeping vector and
trigger, as seL4's `ioapic_mask`; a SINT: its mask bit), and then frees the
entry and vector. Keeping the vector matters for a level interrupt that
arrived during the deletion: its stale delivery is taken as soon as the kernel
returns with IF = 1, before the vector can be reissued, lands on a `Free`
entry, and its EOI broadcast still matches the pin's entry, so Remote IRR
clears; reissue checks Remote IRR anyway. A deleted MSI that the device keeps
sending lands on a `Free` entry, or after reuse gives the new owner a spurious
signal; drivers treat signals as hints. Revoking IRQControl deletes every
IRQHandler. A notification cannot be finalised while bound, because the IRQ
node holds a capability to it; revoking an ancestor (its untyped, say)
deletes that capability as a descendant first.

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

`core/src/irq.rs` (M7) holds the IRQ table, vector allocator, ISA routes, the
issue, bind, Ack, Clear, delete and deliver transitions, and message decoding.
It returns hardware actions (`MaskRte`, `UnmaskRte`, `CheckRemoteIrr`,
`ProgramRte`, `ProgramSint`, `MaskSint`, `Eoi`) and touches no hardware; host
tests and a proptest against a set-based model cover it.
`kernel/src/arch/x86_64/` (`idt.rs`, `lapic.rs`, `ioapic.rs`, `pic.rs`, from
M3) executes the actions through the device window.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Each interrupt source (GSI, SINT, MSI vector) has at most one issued IRQHandler, copies aside | `core::irq` source check, proptest against the model | M7, M9 |
| Each vector in `0x30`-`0xEF` belongs to at most one source; no other vector is issued | `core::irq` allocator, proptest | M7 |
| An IRQ node slot holds only a notification capability with the Write right and never names a deleted notification | checks in `SetNotification`; IRQ node slots in the derivation list; model test of revoke | M7 |
| Deleting the last IRQHandler masks its source, empties its IRQ node slot and frees its vector | finalise path, `core::irq` tests, QEMU scenario | M7 |
| Between two Acks an I/O APIC pin delivers at most three interrupts: two, plus one the local APIC already holds when the mask lands | `core::irq` state machine, proptest, QEMU scenario with the PIT at its highest rate | M7 |
| No pin is unmasked with Remote IRR set | `core::irq` actions, read-back in `ioapic.rs`, QEMU scenario that deletes a handler with a level interrupt pending | M7 |
| Every fixed interrupt is EOI'd exactly once: `0x30`-`0xFE` always, `0x20`-`0x2F` only when its ISR bit is set, `0xFF` never | common interrupt exit, timer and device scenarios | M3, M7 |
| User code cannot enter an interrupt handler with `int n` | DPL 0 on every gate but `#BP`; red-team brief 5 | M3, M10 |
| No interrupt arrives before the IDT is loaded; pins stay masked until issued; the PIC, LINT0 and LINT1 stay masked | M3 init order, QEMU scenario | M3 |
| A vector that cannot occur (9, 15, 17, 20 to 31) panics from either ring and never makes the kernel misread a frame | no-error-code gates and panic path; red-team brief 7 | M3, M10 |
| Handling an interrupt takes constant time and reads no user memory | review of the delivery path | M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| User space picks the vector in `GetIOAPIC` and `GetMSI` (`src/arch/x86/object/interrupt.c`) | The kernel allocates it and returns the IRQ number | No vector namespace for root to manage, and the kernel can refuse a second handler for a pin, which seL4 never checks (`ioapic_decode_map_pin_to_vector`, `src/plat/pc99/machine/ioapic.c`). Lost: user-chosen APIC priority classes, which matter little with IF = 0 in the kernel |
| `GetIOAPIC` names an I/O APIC by its MADT index and a pin on it (`object-api-arch.xml`, `ioapic_decode_map_pin_to_vector`) | `GetIOAPIC` names a GSI; `GetISA` an ISA IRQ | GSIs are what the MADT's I/O APIC bases and overrides use, so root needs no I/O APIC ordering |
| Overrides are printed, not applied (`MADT_ISO` in `acpi.c`); user space parses ACPI from the RSDP | `GetISA` applies them in the kernel | User space has no ACPI parser and never reads ACPI |
| Every `IRQSignal` source is masked on delivery until Ack (`handleInterrupt`, `src/object/interrupt.c`), though an x86 MSI cannot be masked (`maskInterrupt`, `include/plat/pc99/plat/machine/interrupt.h`) | Level pins the same; an edge pin is masked only by a second delivery before Ack; MSI and SINTs never | An edge pin masked from its first delivery loses any edge between the driver's last poll and its Ack; the `pending` bit still bounds it to three interrupts per Ack; a masked SINT breaks host signalling |
| Deleting the handler sets the pin's mask bit and keeps its vector (`deletedIRQHandler`, `src/object/interrupt.c`; `ioapic_mask`, `ioapic.c`) | The same, and issuing a pin first checks that Remote IRR is 0 | A level interrupt pending at an earlier deletion must not leave the pin dead for its next owner |
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
(`Arch_deriveCap`) it cannot be copied or minted. IOPort `{ first, last }` can
be copied, but mint cannot narrow it; a narrower range is a separate `Issue`.
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
| `0x20`-`0x23` (PIC, IMCR), `0xA0`-`0xA1` (PIC) | programmed at boot only | no: they could route legacy interrupts past the LAPIC mask (IMCR from memory; check in M7) |
| `0x3F8`-`0x3FF` (COM1) | debug builds only: panics and `DebugPutChar`; the writer bounds its wait for THRE, so a `uart` that breaks the UART cannot hang it | yes; in debug builds `uart` shares it with kernel output, as in seL4 |
| `0xF4` (`isa-debug-exit`, QEMU) | ends the run | yes, so user-space tests can end a run in any build; scenarios still require `TEST PASS` |
| `0x40`-`0x43`, `0x61` (PIT, speaker) | none | yes |
| `0x64`, `0x92`, `0xCF9`, the ACPI PM1 control port | none | yes, but each can reset or power off the machine; root gives them only to trusted servers (M10 brief 7) |
| `0xCF8`-`0xCFF` (PCI configuration) | none | yes, but it reaches every device, which is as strong as DMA; root gives it only to a trusted PCI manager (M9 uses ECAM) |

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

`core/src/ioport.rs` (M7) holds the bitmap, the reserved set, the checks and
message decoding, with host tests and a proptest against a set model;
`arch/x86_64/io.rs` (since M0) only executes `in` and `out`.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| User code never executes `in` or `out`: user RFLAGS.IOPL is 0 and the TSS has no I/O bitmap | TSS setup (M3); RFLAGS sanitised on `WriteRegisters` and every return (M5); red-team briefs 5 and 7 | M3, M5, M10 |
| An IOPort invocation touches only ports inside its capability's range, width included, with no wrap past `0xFFFF` | `core::ioport` checks, proptest | M7 |
| Issued ranges are pairwise disjoint and contain no kernel-reserved port | bitmap check in `Issue`, proptest | M7 |
| A range becomes issuable again only once its last IOPort capability is deleted | finalise path, `core::ioport` test | M7 |
| The release kernel contains no UART code | `debug` feature gate, xtask disassembly check, release-kernel scenario | M7 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Ports are read as `getSyscallArg(...) & 0xffff`, so `0x1_03F8` means `0x03F8` (`src/arch/x86/object/ioport.c`) | A port or bound above `0xFFFF` is `InvalidArgument` | Bad input should fail, not alias |
| No reserved ports (`x86KSAllocatedIOPorts` starts empty) | PIC and IMCR ports are never issued | They control legacy routing the kernel keeps off |
| Exclusive ranges, `RevokeFirst` on overlap, `IllegalOperation` outside the range, freed with the last capability | Same | Kept |

## ACPI and the timer

The kernel alone parses ACPI, once at boot (M3), from the RSDP the loader
passes: the XSDT (the RSDT only for revision 0), the MADT, the HPET table and
the MCFG. The parser is in `core/`, host-tested on tables dumped from both
platforms; user space gets the few facts it needs in BootInfo's
`InterruptInfo`, never the tables, and `ACPI_RECLAIMABLE` memory becomes RAM
untyped after parsing. The local APIC timer runs periodically at 100 Hz,
calibrated against the Hyper-V reference counter if present, else the HPET;
with neither, the kernel panics. The same windows measure the TSC.

### Tables and validation

| Table | The kernel takes | If absent or invalid |
| --- | --- | --- |
| RSDP, XSDT (RSDT) | table addresses | panic: no MADT |
| MADT | LAPIC address, `PCAT_COMPAT`, I/O APICs, interrupt source overrides | panic |
| HPET | MMIO base (system-memory address space only) | no HPET, as on Hyper-V (from memory) |
| MCFG | ECAM ranges for M9 | no PCI for user space, as on Hyper-V |

The FADT and AML are not read: no ACPI shutdown and no PCI INTx routing
(`_PRT`), so PCI drivers use MSI, as virtio-net can.

- RSDP: signature `"RSD PTR "`, checksum over 20 bytes. Revision 0 uses the
  RSDT; any other revision needs `length` 36-4096, a checksum over `length`
  and a non-zero XSDT.
- Other tables: header read first; `length` from the table's minimum to 1 MiB;
  `[address, address + length)` inside the direct map without overflow;
  expected signature; byte sum 0. A failing table counts as absent, with a
  warning. The XSDT entry area is a multiple of 8 bytes (RSDT: 4).
- MADT entries from offset 44: a length below 2 or an entry past the end
  rejects the MADT (seL4 does not check; a zero length loops forever); a known
  type below its minimum length is skipped, as seL4's `acpi_madt_valid` does.
- Fixed capacity. More than four I/O APICs or more than one HPET table is a
  panic, since a device page left out would become device untyped; past 16
  overrides or 4 ECAM ranges, entries are dropped with a warning. Bounds-checked byte reads only, never a cast of
  table memory. Layouts follow ACPI 6.x (from memory; the M3 host tests check
  them).

`l4core::acpi::parse(mem: &impl PhysRead, rsdp: u64)` returns a fixed-size
`Platform`; the kernel's `PhysRead` in `arch/` copies from the direct map below
`phys_map_size`, so `core/` needs no `unsafe`. It runs once at boot; nothing
reads ACPI memory afterwards, which is what lets M4 make it untyped.
Host tests use tables the loader dumps in debug builds on both platforms
(`core/tests/acpi/`), hand-made edge cases and a random-bytes proptest, all
under Miri.

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
  The Hyper-V reference counter (MSR `0x4000_0020`, 100 ns units; TLFS
  `timers.md`, FreeBSD `include/hyperv.h`) goes first, since Hyper-V has no
  HPET (from memory) and QEMU without `hv-*` flags never reports `Hv#1`.
  HPET: period in femtoseconds in `GCAP_ID[63:32]`, valid if
  `0 < period <= 10^8`; counter at `0xF0`; enable is bit 0 of `0x10` (from
  memory; check in M3). M3 first clears any comparator interrupt enable, FSB
  delivery and legacy-replacement mode the firmware left on; only the main
  counter is used. Under TCG the LAPIC timer and the HPET follow QEMU's
  virtual clock, so calibration holds however slowly TCG runs; the TSC follows
  the host clock, so `tsc_hz` there shows trends only (both from memory).
- Neither reference: panic `no timer reference`, proven by a scenario with
  `qemu_args: -machine q35,hpet=off`. Both platforms have one, a guessed
  rate would silently skew every timeslice, and a PIT fallback would never run
  in a test. Lost: other HPET-less machines, a non-goal. A frequency outside
  1 MHz-10 GHz also panics.
- No TSC-deadline mode: it needs the TSC rate to be exact and pays off only for
  one-shot programming, which classic scheduling does not use. Lost: tickless
  idle and the precise one-shots of MCS (a stretch goal).
- `core/src/timer.rs` (M3): the 128-bit arithmetic, bounds and median, with
  host tests such as QEMU's 1 GHz APIC clock (from memory) giving 10,000,000.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| The ACPI parser never reads outside a validated table or the direct map, never panics, and terminates on any input | `core::acpi` bounds-checked reads, proptest on random bytes, Miri | M3 |
| A table with a bad signature, length or checksum is never used | `core::acpi` validation, host tests on corrupted copies of the dumped tables | M3 |
| The kernel reads ACPI memory only during boot, before M4 makes it untyped | one `parse` call at boot into `Platform`; no `PhysRead` after boot | M3, M4 |
| The kernel reaches the LAPIC, I/O APICs and HPET only through the uncached device window | `arch` device accessors take window offsets only; M3 table builder | M3 |
| The LAPIC page, the MSI window, the I/O APIC pages and the HPET page never become device untyped, and no RAM untyped comes from a 2 MiB page holding one | boot reservation list, BootInfo self-test | M4 |
| The kernel never schedules on an uncalibrated or implausible timer | calibration bounds; panic without a reference; `hpet=off` scenario | M3 |
| The timer ticks at 100 Hz within 1% on both platforms | ten-tick scenario timed against the reference; Hyper-V check | M3 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| Walks the RSDT; checks only the RSDP and RSDT checksums (`acpi_validate_rsdp`, `src/plat/pc99/machine/acpi.c`) | XSDT first; every table's checksum, length and bounds | Both platforms are ACPI 2.0+ (from memory); checks are cheap and host-tested |
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
for M3's calibration; `AccessSynicRegs` (EAX 2), `AccessHypercallMsrs` (EAX 5),
`AccessVpIndex` (EAX 6), `PostMessages` (EBX 4) and `SignalEvents` (EBX 5) for
M9. The kernel touches a synthetic MSR only if its privilege bit is set, so no
request can make it fault on one. The Hypervisor capability exists only if all
five M9 bits are set and the hypercall page can be `.hvcall`. Otherwise
slots 12, 13 and 14 are null, no SynIC is set up, `GetSint` returns
`IllegalOperation`, and the boot log says why.

### Firmware leftovers (M3)

The Generation 2 firmware boots from VMBus storage, so it uses the SynIC (from
memory), and it may leave overlay pages enabled over memory the kernel will
hand out. Before M4 reuses `USABLE` memory, the kernel masks SINT0-15, clears
SCONTROL, and clears the enable bit of SIMP, SIEFP, the reference TSC page
(`0x4000_0021`), the VP assist page (`0x4000_0073`), the synthetic timers
(`0x4000_00B0`, `B2`, `B4`, `B6`), the synthetic time-unhalted timer
(`0x4000_0114`, which can deliver an NMI) and the hypercall page
(`0x4000_0001`), each only with its privilege (reference TSC page
`AccessPartitionReferenceTsc`, EAX 9; synthetic timers
`AccessSyntheticTimerRegs`, EAX 3, the time-unhalted timer also CPUID
`0x4000_0003` EDX bit 23; hypercall page `AccessHypercallMsrs`; for the VP
assist page `AccessIntrCtrlRegs`, from memory; check in M3). If the firmware
Locked the hypercall MSR, M3 records the page, M4 never makes it untyped and
the boot region avoids it; unless it is `.hvcall`, there is no
Hypervisor capability. M3 prints what it found.

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

`core/src/hyperv.rs` holds CPUID and privilege decoding (M3), and from M9 the
MSR values, hypercall input value, `PostMessage` block encoder, capability
data word, permission check and message decoding; `vmbus`'s mock-host tests
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

`kernel/Cargo.toml` gets `debug` and `selftest`, which implies `debug`. xtask
enables `debug` for every scenario, `run`, `gdb` and `image` (the Hyper-V
check reads COM1); M7 adds a build without it. Only with `debug` does the
kernel contain `arch/x86_64/serial.rs` (the only file naming ports `0x3F8` to
`0x3FF`), `kprintln!`'s writer, the panic message, the boot summary, the
report of a fault with no handler ([Missing handlers and double
faults](#missing-handlers-and-double-faults)), system calls 16 to 18 and the
TCB list they walk. Without it `kprintln!` expands to `if false { let _ =
format_args!(...); }`, which type-checks its arguments and emits nothing, and
a panic only exits with failure.

The boot summary, which scenarios match line by line, grows by milestone: M0's
lines (image, memory map, framebuffer, RSDP, hypervisor, command line); from
M3 the CPUID features the kernel requires, `IA32_APIC_BASE`, CR0, CR4 and EFER, and `cpu: meltdown: vulnerable`,
`not vulnerable` or `unknown`, the MADT flags and ACPI table list, the
Hyper-V overlay MSRs found and, when Hyper-V allows it, the APIC frequency
MSR; from M4 the BootInfo summary (untyped
count, RAM and device bytes, the slot regions); from M5 XCR0 and the XSAVE
size.

### Debug system calls

| Number | Name | In | Effect | Out |
| --- | --- | --- | --- | --- |
| 16 | `DebugPutChar` | `rdi` bits 0 to 7 | writes the byte to COM1, `\n` as `\r\n` | all registers preserved except `rcx`, `r11` |
| 17 | `DebugHalt` | `rdi`: status | prints `DEBUG HALT <status> from TCB <address>`, then `arch::exit`: status 0 is success, any other failure; under QEMU the run ends, elsewhere the machine halts | does not return |
| 18 | `DebugDumpScheduler` | none | prints one line per TCB: address, state, priority, `next_ip` or `fault_ip`, and whether current | as 16 |

They take no capability: in a debug kernel any thread may print, dump and
halt. Interrupts are off throughout, so one call's output is never split.
`DebugDumpScheduler` walks a list of every TCB whose two link words live in
the TCB's debug-only tail, as seL4 keeps `ksDebugTCBs`. Numbers 19 to 31
stay reserved; there is no `DebugNameThread`. A user-space test ends a QEMU
run with `DebugHalt(0)` after printing `TEST PASS`. In debug scenarios
the kernel's writer and `uart` share COM1: the kernel only polls LSR and
writes THR, so they coexist, with lines possibly interleaved.

### A release kernel without UART code

M7's done-when is checked three ways. The `serial` module is
`#[cfg(feature = "debug")]`, so release code naming it does not compile.
`cargo xtask test` builds the kernel without `debug`, disassembles it, and
fails on any `in` or `out` outside the IOPort invocation path in `io.rs`,
any immediate in `0x3F8` to `0x3FF` moved into `dx`, `edx` or `rdx`, and any
`serial` symbol (`0x3FF` alone is also the IPC buffer's alignment mask); that also catches a port write added outside `serial.rs` or
inlined into another function. A
scenario boots that kernel: all output comes from `uart`, and root ends the
run through an IOPort capability for `isa-debug-exit` (`0xF4`) made from
IOPortControl.

### Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| A kernel built without `debug` contains no UART code and touches ports `0x3F8` to `0x3FF` only in IOPort invocations | `cfg(feature = "debug")`; xtask disassembly check (no `in` or `out` outside the IOPort path, no `0x3F8` to `0x3FF` moved into `dx`, no `serial` symbol); release scenario | M7 |
| Without `debug`, numbers 16 to 31 raise `UnknownSyscall` | `Syscall::from_number(_, false)`; host test; release scenario | M5, M7 |
| `DebugPutChar` and `DebugDumpScheduler` change no register a thread can rely on | debug scenario comparing registers before and after | M5 |
| Debug system calls read no user memory and take no capability | handlers use only registers and kernel state; review | M5 |
| The TCB size is the same with and without `debug` | the debug list's two link words live in the TCB's debug-only tail; compile-time size assert | M5 |
| A debug kernel's boot summary shows the CPU features, control registers and Meltdown status it booted with | summary lines; M3 scenarios match them, including a `-cpu qemu64` refusal through `qemu_args:` | M3 |

### Compared with seL4

| seL4 | microL4 | Reason |
| --- | --- | --- |
| `DebugPutChar` and `DebugDumpScheduler` under `CONFIG_PRINTING`, `DebugHalt` under `CONFIG_DEBUG_BUILD`; the dump itself prints only with `CONFIG_DEBUG_BUILD` too (`syscall.xml`, `handleUnknownSyscall` in `src/api/syscall.c`) | one `debug` feature | one switch to test |
| Debug calls numbered after the API calls in `syscall.xml` and decoded on the unknown-syscall path (`slowpath`, `src/arch/x86/c_traps.c`) | fixed numbers 16 to 18, decoded with the others by `Syscall::from_number` | [ADR 0022](adr/0022-abi-v0-numbering.md); one decoder |
| `DebugHalt` takes no argument and halts (`handleUnknownSyscall`) | takes a status and exits through `isa-debug-exit` | scenarios need a pass or fail exit status |
| Dump prints thread names (`debug_printTCB`, `include/api/debug.h`) | address, no name | no `DebugNameThread` in v0; 19 to 31 reserved |
| `DebugCapIdentify`, `DebugSnapshot`, `DebugNameThread`, benchmark calls | none | not needed for the plan; numbers reserved |

## Open questions

Each question has a default that this note and `docs/abi.md` already assume,
and the milestone that must confirm or change it. Changing a default that
touches the ABI needs an ADR. Sorted by milestone.

| Question | Why it matters | Answer in | Default |
| --- | --- | --- | --- |
| Should nested CNodes found while destroying a CNode be cleared, rather than left unreachable until their untyped is revoked? | seL4's behaviour keeps the objects their slots name alive, which can leak memory when a process tree is not torn down leaves first | M2 | Keep seL4's behaviour; `root` tears down CSpaces leaves first or revokes the covering untyped |
| Does the owner's Hyper-V VM report SMEP, SMAP and XSAVE? | Without them the kernel refuses to boot ([Privilege levels](#privilege-levels)) | M3, first Hyper-V check | Yes on any host CPU from about 2015 with processor compatibility mode off, which `tools/hyperv/New-L4Vm.ps1` will set (from memory); the M3 boot summary prints the required CPUID features |
| Does Hyper-V's Generation 2 firmware, or OVMF under `-cpu max`, hand over in x2APIC mode? | The kernel is xAPIC-only and leaves x2APIC through the disabled state; that path otherwise never runs in a test | M3 | The boot summary prints `IA32_APIC_BASE` on both platforms; if either hands over in x2APIC, that boot exercises the path |
| Does Generation 2 Hyper-V set `PCAT_COMPAT`, and does it have an 8259 PIC, a PIT and an HPET? | Decides whether the PIC is touched, and confirms the reference counter is the only timer reference there | M3 | Mask the PIC only if `PCAT_COMPAT` is set; expect no HPET on Hyper-V; the M3 Hyper-V check prints the MADT flags and table list |
| Does the Generation 2 firmware leave the hypercall page, SIMP, SIEFP, reference TSC page, VP assist page or synthetic timers enabled, or the hypercall MSR locked, at `ExitBootServices`? | An overlay left on over `USABLE` memory corrupts whatever M4 retypes there; a locked hypercall MSR removes the Hypervisor capability | M3 | Disable each one before M4 reuses memory; keep a locked hypercall page out of every untyped and the boot region; print the values found |
| Should the timer read `HV_X64_MSR_APIC_FREQUENCY` instead of calibrating, when Hyper-V allows it? | It gives the exact rate with no measurement | M3 | Calibrate against the reference counter, as PLAN.md says, and print the frequency MSR as a cross-check when allowed |
| How long are the calibration windows, and how close must the rate be? | Too short a window gives a wrong rate; too long slows every boot | M3 | Three 20 ms windows, median, for the local APIC timer and the TSC; the ten-tick scenario requires 1% |
| Is 8 KiB enough for a fatal handler's panic report on its IST stack? | An overflow of an IST stack ends in a triple fault with no report | M3 | Yes; measure the panic path's depth, and fall back to a fixed-format writer without `core::fmt` if not |
| Is 4 KiB the right chunk for clearing an untyped between preemption points? | seL4 clears 256 bytes per preemption point; 4 KiB under TCG may take tens of microseconds | M4 | 4 KiB with an IRR read after each chunk; measure the longest non-preemptible stretch on QEMU and Hyper-V, and add a work-unit counter like seL4's only if the reads dominate |
| Are boot-created objects (root CNode, TCB, VSpace, BootInfo) covered by an untyped? | If they are, revoking that untyped destroys the root task; if not, their memory is never reclaimed | M4 | As seL4: they come from the boot region, outside every untyped, and their capabilities are derivation roots |
| Are 448 untyped descriptors enough? | Boot panics if not | M4, from the recorded QEMU and Hyper-V memory maps | Yes, by several times on both targets; if not, BootInfo grows to four pages as version 2 |
| What if the framebuffer shares a 2 MiB page with RAM-like memory? | It could not be device untyped without aliasing the write-back direct map, so `fb` could not run | M4 | `framebuffer_untyped` is empty and a debug kernel prints a warning; not seen on QEMU or Hyper-V |
| Does a `syscall` executed with RFLAGS.TF set raise `#DB` on the first kernel instruction? | Any thread can set TF; the `#DB` handler returns only when RIP is exactly `syscall_entry`, and a trap anywhere else in ring 0 panics | M5: a scenario sets TF and calls `Yield`, on QEMU and Hyper-V | No trap is taken; the RIP special case stays as insurance |
| Is `swapgs` worth keeping on one core? | seL4's uniprocessor build avoids it and a class of mistakes with it | M5 | Keep it for the multi-core stretch goal; the IST handlers never read GS |
| Which register is a cancelled thread's restart point? | Cancelled threads become `Restart` and re-execute `syscall`; IPC relies on their argument registers being untouched | M5 | Restart `rip` is the saved user `rcx` minus 2, the length of `syscall`; IPC writes a blocked thread's registers only on completion |
| In what order are each invocation's errors checked? | The M10 fuzzer's model needs it | M5 | The order `docs/abi.md` lists them in; the TCB invocations that install capabilities give an explicit order, seL4's (buffer, long-running delete, CSpace root, VSpace root) |
| Enable AVX? | It costs 256 more bytes of save and restore per switch and makes behaviour differ between hosts | M5, with the user-target decision | No; it fits the 1024-byte XSAVE reserve if it is wanted later |
| Which target do user crates build for? | A target with SSE needs the XSAVE switching to be exercised | M5 | `x86_64-unknown-none` for every user crate through M10; nothing planned needs floating point |
| Are Read and Write the only Frame rights? | The capability header has four rights bits, all assigned | M5 | Yes; execute permission comes from a map attribute, off by default |
| Should a populated paging structure be movable between VSpaces? | It would let a table holder expose frames whose capabilities it does not hold | M5 | No: Map requires an empty structure, and Unmap empties it |
| May device frames be mapped write-back? | Device memory that is really memory would run uncached | M5 | No; neither target needs it. Revisit with an ADR if a driver does |
| Should page 0 be mappable? | Some programs place data at 0 | M5 | No; no program here needs it |
| Should `Frame_Remap` on an unmapped capability return `InvalidCapability`, as Map does for a capability in the wrong mapping state? | One error convention is simpler for `libsys` | M5 | Keep `IllegalOperation`, as seL4 does for an operation the capability's state does not allow |
| Should a caller whose reply capability is destroyed be woken with an error? | A server that receives again, deletes the reply or dies leaves its client blocked until someone suspends it | M6 | No, as seL4: any error label would be indistinguishable from a reply; a client needing a timeout uses a watchdog thread holding its TCB capability |
| How does a server tell "nothing pending" from a message or signal with badge 0? | `NBRecv` returns badge 0 both for nothing and for unbadged senders | M6, `libsys` | `root` gives every client and signaller of a polled object a non-zero badge |
| What else must `libsys` document? | Two seL4 behaviours surprise servers | M6 | Reusing a notification badge needs revoke, an `NBRecv` to drain old bits, then a new Mint; a saved reply capability vanishes when its client is suspended or deleted |
| Are the IMCR ports `0x22` and `0x23` real on q35 and Hyper-V? | They are kept from user space on the assumption that they can route PIC interrupts around the local APIC | M7 | Keep them reserved; reserving an absent port costs nothing |
| What if Remote IRR stays set on an I/O APIC older than version `0x20`, which has no EOI register? | Issuing the pin fails with `RevokeFirst` until the stale delivery arrives | M7 | Accept: both platforms' I/O APICs are version `0x20` or later (from memory; check in M7) |
| Should handlers see another thread's FP state? | An `#MF` or `#XM` handler cannot read FSW or MXCSR, and a debugger cannot show FP registers | M8 | No; if needed, a `TCB_CopyRegisters` flag copies the XSAVE area |
| Is a 4096-slot root CNode with an 8 MiB root image enough once `root` carries every server and the terminal font? | Boot or the xtask size check would fail | M8 | Yes; raise the radix to 13 if not |
| Must `vmbus` send VMBus `UNLOAD` before `INITIATE_CONTACT` because the firmware left a connection open? | Contact fails or channels are stale if the host still sees the firmware's session | M9 | Yes, as other guests do after kexec; confirm against FreeBSD's `vmbus.c` |
| Which value goes into `HV_X64_MSR_GUEST_OS_ID`? | The TLFS asks open-source guests for an OS type Microsoft allocates; microL4 has none | M9 | Bit 63 (open source) set, OS type 0, version 0, build = the kernel's build number |
| Should an MSI vector be quarantined after its handler is deleted? | A device that keeps sending gives the vector's next owner spurious signals | M9 | No: drivers treat signals as hints, and an MSI-capable driver is trusted with the machine anyway |
| Should a narrowed Hypervisor capability cover a range of connections? | A driver with several channels needs one capability per connection | M9 | One connection per capability; mint several |
| Should `Frame_GetAddress` need a right, or refuse device frames? | Physical addresses help Rowhammer-style attacks on real hardware, a non-goal | M9 | No, as seL4: any Frame capability |
| Should the kernel check the GPADL page numbers `vmbus` posts? | Without it, posting on the VMBus message connection is as strong as DMA | M10, brief 8 | No: it would put VMBus parsing in the kernel; recorded as an accepted risk |
| Should slice accounting be finer than a tick? | A thread that blocks just before each tick is never charged and can starve its equal-priority peers | M10, brief 9 | Accept it, as seL4's non-MCS scheduler does; the fix is a one-shot timer re-armed with the remaining slice |
| Priority inversion | Without priority inheritance a server below its client's priority can be starved by middle-priority threads | M10, brief 9 | Accept it, as seL4 does; `root` gives every server a priority at or above all of its clients' |
| Segment selectors as a covert channel | DS, ES, FS and GS selector values survive a thread switch | M10, brief 5 | Accept it; the fix is to load null selectors before writing the base MSRs at each switch |
| Is an IPC fastpath needed? | Round trips go through the general path | after M10 | No; revisit only with Hyper-V timings, since TCG timings mean little |
| Should paging structures shrink back to 4 KiB once a cheaper reverse map is found? | It halves the paging overhead | after M10 | No; 8 KiB keeps one simple layout |
| Should user space ever read ACPI (shutdown through the FADT, PCI `_PRT`)? | Without it there is no ACPI power-off and PCI INTx is unusable | after M10 | No: ACPI memory becomes untyped after boot; v0 shuts down by halting and PCI drivers use MSI |
| PCID | Fewer TLB refills on each switch | stretch goals (multi-core) | Off in v0; a later scheme assigns tags without a user-visible namespace |
