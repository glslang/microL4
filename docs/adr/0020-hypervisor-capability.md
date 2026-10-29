# 0020: The Hypervisor capability exposes two hypercalls; SINTs are IRQ handlers; the SynIC pages are boot frames given to the VMBus server and never touched by the kernel

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Hyper-V row says hypercalls and the SynIC need ring 0, a Hypervisor
capability lets the VMBus server post messages and signal events, SynIC
messages arrive as notification signals, and the kernel finds Hyper-V through
CPUID leaf `0x40000000` ("Microsoft Hv"). seL4 has no equivalent. The row
leaves open which hypercalls are reachable, how a server is confined to its
own channels, where the SynIC message (SIM) and event-flag (SIEF) pages live
given that the kernel allocates nothing after boot, and who reads them.

From the TLFS (`MicrosoftDocs/Virtualization-Documentation`, read
2026-10-29): hypercalls below CPL 0 raise `#UD`; hypercall input must be in
ordinary RAM at a guest physical address the caller names; the SIM and SIEF
are per-processor pages the hypervisor writes at any time; a masked SINT
loses message interrupts and makes the host's `HvCallSignalEvent` fail; the
hypercall MSR can be Locked; and compatibility should be based on the
interface signature `"Hv#1"` from leaf `0x40000001`, not on the vendor string.

## Decision

- Detection uses leaf `0x40000001` = `"Hv#1"`; the vendor string is printed
  only. Each synthetic MSR is touched only if its privilege bit in leaf
  `0x40000003` is set.
- Before reusing firmware memory (M3), the kernel disables any overlay the
  firmware left enabled: SIMP, SIEFP, reference TSC page, VP assist page,
  synthetic timers, the hypercall page, and masks all SINTs. A Locked
  hypercall page is recorded, never made untyped and avoided by the boot
  region ([ADR 0007](0007-boot-region-and-bootinfo.md)).
- The Hypervisor capability has four invocations: `PostMessage`
  (`HvCallPostMessage`), `SignalEvent` (`HvCallSignalEvent`), `Eom` and
  `VpIndex`. The kernel builds the hypercall input value and the input block
  in its own page and calls the `.hvcall` page in its text; user space
  never names a guest physical address. No other hypercall is reachable. If
  the firmware locked the hypercall MSR outside `.hvcall`, there is no
  Hypervisor capability.
- Hypervisor capabilities pass `derive`. Mint narrows one to a single
  connection ID with `post` and `signal` rights and makes an original, so
  `vmbus` can hand a channel driver the right to signal its own channel only,
  and revoke it.
- SINTs are interrupt sources: `IRQControl_GetSint` issues an IRQHandler, so
  SynIC messages and events arrive as notification signals. SINTs are never
  masked on delivery and AutoEOI is off.
- At boot the kernel takes two RAM frames from the boot region, outside every
  untyped, records their physical addresses, makes them the SIM and SIEF
  pages, and gives the root task write-back Frame capabilities to them in
  initial slots 13 and 14. `vmbus` maps and reads them. The kernel never
  touches them again: `TCB_SetIPCBuffer` refuses them with
  `InvalidCapability`, and no other kernel path reads a frame through a
  capability.

## Consequences

- The kernel has no VMBus code and never parses hypervisor-written data, so
  malformed SynIC messages cannot reach it; `vmbus` must validate them and is
  fuzzed against a mock host.
- `vmbus` holds an unrestricted capability, and posting on the VMBus message
  connection lets it name any guest page in a GPADL for the host to read and
  write. That is as strong as DMA. It is accepted and recorded for M10
  brief 8.
- Revoke and retype can never reuse memory the hypervisor writes; 8 KiB stays
  reserved for good, plus a Locked hypercall page if the firmware left one.
- `TCB_SetIPCBuffer` (`docs/abi.md`,
  [`TCB_SetIPCBuffer`](../abi.md#0x27-tcb_setipcbuffer)) gains a check
  against the two recorded addresses.
- QEMU under TCG cannot run any of this; `core/` holds every encoder and check
  for host tests, and the owner's Hyper-V host proves the rest in M9.
- The row's detection by vendor string changes; `docs/abi.md` gets the
  [Hypervisor](../abi.md#hypervisor) section and the [SynIC frame
  layout](../abi.md#synic-frames).
