# 0029: The kernel writes guest OS ID `0x8000_0000_0000_0000` and makes the Hypervisor capability only once the hypercall page reads back enabled

Status: accepted, M9 (2026-11-27). Amends ADR 0020.

## Context

[ADR 0020](0020-hypervisor-capability.md) made the Hypervisor capability
depend on the M9 privileges and on the hypercall page being `.hvcall`, and
`docs/abi.md` listed when initial slot 12 is null: not Hyper-V, an M9
privilege missing, or a hypercall MSR the firmware locked outside `.hvcall`.
`docs/design.md` left the guest OS identity open, defaulting to bit 63 set
and "build = the kernel's build number".

The M9 spec check read the TLFS (`MicrosoftDocs/Virtualization-Documentation`,
`tlfs/hypercall-interface.md`, read 2026-11-27) and FreeBSD's Hyper-V code
(`sys/dev/hyperv/vmbus/hyperv.c`, `x86/hyperv_x86.c`):

- A non-zero value must be in `HV_X64_MSR_GUEST_OS_ID` before the hypercall
  page can be enabled; if none is, "the enable bit will remain zero even when
  writing a one to it". So a write of the hypercall MSR can fail silently.
- The hypercall MSR's bits 11:2 are RsvdP, "preserved on writes".
- FreeBSD's `hypercall_page_setup` keeps those bits, writes the MSR, reads it
  back and gives up Hyper-V's services if the enable bit is clear. FreeBSD
  writes its guest OS ID unconditionally, though the TLFS's step 3 writes one
  only if the register is zero.
- The TLFS's encoding for open-source systems is bit 63 set, bits 62:56 an OS
  type Microsoft allocates (Linux 1, FreeBSD 2, Xen 3, Illumos 4), bits 55:48
  an OS ID, 47:16 a version and 15:0 a build. Microsoft has allocated no type
  for microL4, and the kernel has no build or version number.

A kernel that took a failed enable for success would hand out a Hypervisor
capability whose first invocation runs `.hvcall`'s `int3` filler in ring 0, a
kernel panic.

## Decision

- With the five M9 privileges, after step 5's overlay reset, the kernel
  writes `HV_X64_MSR_GUEST_OS_ID` = `0x8000_0000_0000_0000` (open source,
  every other field 0), replacing any value the firmware left, as FreeBSD
  does (and Linux, from memory).
- It writes `HV_X64_MSR_HYPERCALL` with `.hvcall`'s physical page number, the
  enable bit and bits 11:2 as read, then reads it back.
- Unless the read-back is enabled at `.hvcall`, there is no Hypervisor
  capability and no SynIC: initial slots 12, 13 and 14 are null, `GetSint`
  is `IllegalOperation`, and a debug kernel says why.

## Consequences

- One more case leaves slot 12 null on Hyper-V. User code already handles a
  null slot 12; `docs/abi.md`'s lists of the null cases name it.
- No path can call a hypercall page that did not enable.
- The value names no OS type. If Hyper-V treats type 0 differently in some
  way the TLFS does not say, the M9 Hyper-V check is where it shows; the
  owner could ask Microsoft for a type later, which changes only this value.
- `core::hyperv` gains the guest OS ID, the hypercall MSR value built from
  its old value and the page, and the read-back decision, each host-tested.
