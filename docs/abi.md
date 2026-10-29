# microL4 ABI

Status: v0, M1 (2026-10-29). This is the contract between the kernel and user
space, and between the loader and the kernel. Every later milestone codes
against it. `docs/design.md` explains why each part is the way it is; any
change here needs an ADR in `docs/adr/`.

The ABI is shaped like seL4's classic (non-MCS) x86_64 ABI so it can be
compared with it, but it is not binary-compatible: system call numbers,
object type numbers, invocation labels and BootInfo all differ. "seL4" below
means seL4 at commit `7a852638f502` (2026-10-29).

## Contents

- [Conventions](#conventions)
- [System calls](#system-calls)
- [Messages](#messages)
- [Capability pointers](#capability-pointers)
- [Errors](#errors)
- [Object types and sizes](#object-types-and-sizes)
- [Capabilities: rights, data words, lookup, Untyped and CNode](#capabilities)
- [IPC and notifications](#ipc-and-notifications)
- [Threads](#threads)
- [Address spaces](#address-spaces)
- [Interrupts, I/O ports and Hyper-V](#interrupts-io-ports-and-hyper-v)
- [Boot and the root task](#boot-and-the-root-task)
- [Debug system calls](#debug-system-calls)
- [Boot handoff (loader to kernel)](#boot-handoff-loader-to-kernel)
- [Invocation label index](#invocation-label-index)

## Conventions

- A word is 64 bits. Everything is little-endian.
- Every structure in this document is `#[repr(C)]` with fixed-width fields.
  `core/` holds the Rust definitions and pins every offset with compile-time
  asserts, checked on every target's build (as `core/src/handoff.rs` does
  for the boot handoff).
- Reserved fields and bits are written as zero and ignored on read, unless a
  row says the kernel rejects a non-zero value.
- Addresses in kernel-to-user structures are physical unless a row says
  virtual.
- Milestones named in a row (M2 to M10) are where that part is built; the
  layout is fixed now.

## System calls

A thread enters the kernel with the `syscall` instruction. The kernel
returns with `sysretq`, or with `iretq` when the return state cannot be
expressed by `sysretq` (see [System-call entry and
exit](#system-call-entry-and-exit)). The register use is seL4's x86_64
register use.

| Register | On entry | On return |
| --- | --- | --- |
| `rdx` | system call number | preserved |
| `rdi` | capability pointer (destination or source) | badge of the received message (receive phases); otherwise preserved |
| `rsi` | `MessageInfo` | `MessageInfo` of the received or reply message; preserved by `Send`, `NBSend`, `Reply` and `Yield` |
| `r10`, `r8`, `r9`, `r15` | message registers MR0, MR1, MR2, MR3 | MR0 to MR3 of the received or reply message; preserved by `Send`, `NBSend`, `Reply` and `Yield` |
| `rcx`, `r11` | destroyed by `syscall` (user RIP, RFLAGS) | destroyed |
| `rax`, `rbx`, `rbp`, `r12`, `r13`, `r14` | ignored | preserved |
| `rsp` | ignored | preserved; a value at or above 2^47 reads back as 0 |

System call numbers are positive; 0 is invalid.

| Number | Name | Number | Name |
| --- | --- | --- | --- |
| 1 | `Call` | 5 | `Recv` |
| 2 | `ReplyRecv` | 6 | `Reply` |
| 3 | `Send` | 7 | `Yield` |
| 4 | `NBSend` | 8 | `NBRecv` |

Numbers 16 to 31 are debug system calls, compiled in only with the kernel's
`debug` feature: 16 `DebugPutChar`, 17 `DebugHalt`, 18 `DebugDumpScheduler`;
19 to 31 are reserved. Any other number, and a debug number in a kernel
built without `debug`, raises an `UnknownSyscall` fault for the caller
([Fault messages](#fault-messages)).

Signalling a notification is `Send` (or `NBSend`) on a notification
capability; waiting is `Recv`; polling is `NBRecv`. Invoking a kernel object
(Untyped, CNode, TCB, paging structure, Frame, IRQ, I/O port, Hypervisor) is
`Call` on its capability; `Send` and `NBSend` on a kernel object perform the
invocation and drop the reply, including any error.

### System-call entry and exit

`syscall` is the only way into the kernel from ring 3. The tables above give
the system-call numbers and the registers each one reads and writes; this
section adds the rest of the state on return and how the kernel dispatches.

| State | On return from any system call |
| --- | --- |
| `rcx`, `r11` | unspecified; today `rcx` is the return address and `r11` the RFLAGS after a `sysretq` exit, and their entry values after an `iretq` exit |
| RFLAGS | the caller's CF, PF, AF, ZF, SF, TF, DF, OF, AC and ID; IF = 1; IOPL, NT, RF = 0. That is `(rflags & 0x0024_0DD5) \| 0x0202` |
| `rbx`, `rsp`, `rbp`, `r12` to `r14`, and every register the table above lists as preserved | preserved; an `rsp` at or above `0x0000_8000_0000_0000` reads back as 0 |
| FS base, GS base, x87 and SSE state | preserved |
| CS, SS | `0x23`, `0x1B` |
| DS, ES, FS, GS selectors | not saved per thread: the kernel never loads them after boot, so they hold whatever any thread last loaded, possibly another thread's value (as in seL4); their bases are 0 in every user-loadable descriptor, and FS and GS bases are switched through the MSRs |

Other ways a thread might try to enter the kernel end in a fault for that
thread (a [`UserException`](#userexception-3)): `int n` raises #GP because
every IDT gate but vector 3's has DPL 0; `int3` raises #BP and `int1` raises
#DB, each a `UserException` for its own vector; `sysenter` raises #GP
(`IA32_SYSENTER_CS` = 0) or #UD; a far transfer to a 32-bit code segment
finds none.

#### Dispatch

The kernel decodes `rdx` first, then resolves `rdi` in the caller's CSpace,
consuming up to 64 bits and stopping at the first slot that is not a CNode
([Capability lookup](#capability-lookup)). What a failed lookup, an empty
slot or a missing right produces, for any capability type, is in [Errors,
faults and silent drops](#errors-faults-and-silent-drops); errors from
decoding a kernel invocation are in each object's section.

| `rdx` | System call | `rdi` names | Accepted capability types |
| --- | --- | --- | --- |
| 0 | none | | `UnknownSyscall` fault |
| 1 | `Call` | destination | Endpoint, Notification, Reply, and every kernel object type: Untyped, CNode, TCB, PageTable, PageDirectory, PDPT, PML4, Frame, IRQControl, IRQHandler, IOPortControl, IOPort, Hypervisor. A kernel object decodes the `MessageInfo` label; a label outside its type's range ([Invocation label index](#invocation-label-index)) gives `IllegalOperation` |
| 2 | `ReplyRecv` | receive source | reply phase: the caller slot; receive phase: Endpoint, Notification |
| 3 | `Send` | destination | as `Call`; a kernel object's reply, including an error, is dropped |
| 4 | `NBSend` | destination | as `Send`, never blocking |
| 5 | `Recv` | source | Endpoint, Notification |
| 6 | `Reply` | ignored | the caller slot |
| 7 | `Yield` | ignored | none |
| 8 | `NBRecv` | source | Endpoint, Notification |
| 9 to 15 | none | | `UnknownSyscall` fault |
| 16 to 18 | debug | see [Debug system calls](#debug-system-calls) | debug kernels; otherwise `UnknownSyscall` fault |
| 19 to 31 | reserved for debug | | `UnknownSyscall` fault |
| 32 and up | none | | `UnknownSyscall` fault |

An `UnknownSyscall` fault leaves `fault_ip` on the `syscall` instruction; the
message and what a reply does are in [Fault messages](#fault-messages).

## Messages

### MessageInfo

seL4's 64-bit layout:

| Bits | Field | Meaning |
| --- | --- | --- |
| 0 to 6 | `length` | message registers used, at most `MSG_MAX_LENGTH` = 120 |
| 7 to 8 | `extra_caps` | capabilities named in `caps_or_badges`, at most 3 |
| 9 to 11 | `caps_unwrapped` | IPC: which extra capabilities were unwrapped to badges |
| 12 to 63 | `label` | IPC: user data. Kernel invocation: the invocation label. Reply from the kernel: the error code |

### IPC buffer

seL4's layout: 128 words, 1024 bytes, aligned to 1024 bytes, inside one
frame the thread's TCB names (`TCB_SetIPCBuffer`).

| Word | Byte offset | Field |
| --- | --- | --- |
| 0 | 0 | `tag`, a `MessageInfo` (not used by the kernel; for user libraries) |
| 1 to 120 | 8 to 967 | `msg[0..120]`; MR0 to MR3 travel in registers and `msg[0..4]` are then unused |
| 121 | 968 | `user_data`, never touched by the kernel |
| 122 to 124 | 976 to 999 | `caps_or_badges[3]`: capability pointers on send, badges of unwrapped capabilities on receive |
| 125 | 1000 | `receive_cnode` |
| 126 | 1008 | `receive_index` |
| 127 | 1016 | `receive_depth` |

How the kernel reads and writes each field is in [IPC and
notifications](#ipc-and-notifications).

## Capability pointers

A capability pointer (`CPtr`) is a 64-bit word, resolved from the thread's
CSpace root through CNodes with guards. An invocation lookup consumes up to
64 bits: it stops at the first slot that does not hold a CNode capability,
and ignores the bits left. CNode operations name a slot as (root CNode
capability, index, depth) and must consume exactly `depth` bits. A CNode
slot is 32 bytes (`SLOT_BITS` = 5), so a CNode of `2^radix` slots occupies
`2^(radix + 5)` bytes. The rules and the failure encoding are in
[Capability lookup](#capability-lookup).

## Errors

A kernel invocation made with `Call` returns a `MessageInfo` whose `label`
is an error code and whose `length` counts the detail words in MR0 and up.
A successful invocation returns label 0 and its results in MR0 and up. The
codes are seL4's:

| Code | Name | Code | Name |
| --- | --- | --- | --- |
| 0 | `NoError` | 6 | `FailedLookup` |
| 1 | `InvalidArgument` | 7 | `TruncatedMessage` |
| 2 | `InvalidCapability` | 8 | `DeleteFirst` |
| 3 | `IllegalOperation` | 9 | `RevokeFirst` |
| 4 | `RangeError` | 10 | `NotEnoughMemory` |
| 5 | `AlignmentError` | | |

The detail words for each code are in [Error detail
words](#error-detail-words). IPC returns no error codes except `InvalidCapability` from a `Call` on an
endpoint capability without the rights it needs; what a
thread sees when an IPC cannot complete is in [Errors, faults and silent
drops](#errors-faults-and-silent-drops).

## Object types and sizes

`Untyped_Retype` takes one of these type numbers. Sizes are powers of two;
each object is aligned to its size.

| Number | Type | Size | `size_bits` argument | Details |
| --- | --- | --- | --- | --- |
| 0 | Untyped | `2^size_bits`, 16 B to 128 TiB | 4 to 47 | [Object sizes](#object-sizes) |
| 1 | TCB | 2 KiB (`TCB_BITS` = 11) | ignored | [TCB object](#tcb-object) |
| 2 | Endpoint | 32 B (`ENDPOINT_BITS` = 5) | ignored | [Objects](#objects) |
| 3 | Notification | 64 B (`NOTIFICATION_BITS` = 6) | ignored | [Objects](#objects) |
| 4 | CNode | `2^(radix + 5)` | radix, 1 to 42 | [Object sizes](#object-sizes) |
| 5 | Frame, 4 KiB | 4 KiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 6 | Frame, 2 MiB | 2 MiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 7 | PageTable (level 1, maps 4 KiB frames) | 8 KiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 8 | PageDirectory (level 2, maps page tables and 2 MiB frames) | 8 KiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 9 | PDPT (level 3) | 8 KiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 10 | PML4 (level 4, the VSpace root) | 8 KiB | ignored | [Address-space object sizes](#address-space-object-sizes) |
| 11 and up | reserved | | | `Untyped_Retype` returns `InvalidArgument` |

Capabilities that no retype creates: IRQControl, IRQHandler, IOPortControl,
IOPort, Hypervisor (made at boot or by an invocation of another capability)
and the reply capabilities a TCB holds. Their type tags are in
`docs/design.md`, [Object and capability
types](design.md#object-and-capability-types).

## Capabilities

This section fixes rights, capability data, lookup rules, error detail words,
and the Untyped and CNode invocations. Object type numbers, error codes,
`MessageInfo` and the system-call registers are in the sections above, and
label ranges in the [Invocation label index](#invocation-label-index).
`docs/design.md`, [Kernel objects](design.md#kernel-objects) to [Derivation
tracking](design.md#derivation-tracking), explains the behaviour.

### Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `SLOT_BITS` | 5 | a CNode slot is 32 bytes |
| `MIN_UNTYPED_BITS` | 4 | smallest untyped, 16 bytes |
| `MAX_UNTYPED_BITS` | 47 | largest untyped, 128 TiB |
| `MIN_CNODE_RADIX` | 1 | smallest CNode, 2 slots |
| `MAX_CNODE_RADIX` | 42 | largest CNode, `2^47` bytes |
| `RETYPE_FAN_OUT_LIMIT` | 256 | most objects one `Untyped_Retype` creates |
| `MAX_DERIVATION_DEPTH` | 4095 | deepest derivation. A ring-3 task can reach it. Every invocation that would derive a child below it fails with `IllegalOperation` (`CNode_Copy`, `CNode_Mint`, `Untyped_Retype`, `TCB_Configure`, `TCB_SetSpace`, `TCB_SetIPCBuffer`, `IRQHandler_SetNotification`); IPC transfer skips the capability |

### Object sizes

| Object | Type number | `size_bits` argument | Size in bytes | Why |
| --- | --- | --- | --- | --- |
| Untyped | 0 | log2 of the size, 4 to 47 | `2^size_bits` | 16 bytes is the smallest object and the alignment of capability object addresses; 47 is seL4's x86_64 limit and keeps `256 << 47` inside 64 bits |
| CNode | 4 | radix, 1 to 42 | `2^(radix + 5)` | a slot is a 16-byte capability plus a 16-byte derivation node; radix 1 makes every level resolve at least one bit; `radix + 5 <= 47` fits the largest untyped |

For every other type `size_bits` is ignored; its size is in [Object types
and sizes](#object-types-and-sizes). Every object is aligned to its size.

### Rights

Copy and Mint take a rights word. A derived capability's rights are its
source's rights AND this word, so rights never grow.

| Bit | Right | Endpoint | Notification | Frame | Reply |
| --- | --- | --- | --- | --- | --- |
| 0 | Write | send | signal | map writable ([Rights word](#rights-word)) | |
| 1 | Read | receive | wait, poll | map readable ([Rights word](#rights-word)) | |
| 2 | Grant | send any capability ([Capability transfer](#capability-transfer)) | | | send capabilities in the reply ([Capability transfer](#capability-transfer)) |
| 3 | GrantReply | send a reply capability ([Reply capability](#reply-capability)) | | | |

Bits 4 to 63 are ignored. Other capability types have no rights and are
unchanged by the rights word. A capability made by `Untyped_Retype` has every
right its type uses. Signalling a notification needs Write; a thread's fault
endpoint capability needs Write and Grant or GrantReply, checked when the
fault happens ([Fault messages](#fault-messages)); `CNode_CancelBadgedSends`
needs all four rights.

### Capability data

Mint, Mutate and Rotate take a data word whose meaning depends on the
capability:

| Capability | Mint | Mutate, and each half of Rotate |
| --- | --- | --- |
| Endpoint, Notification | the badge, all 64 bits. The source must be unbadged, otherwise `IllegalOperation`. Badge 0 leaves it unbadged, so Mint is then a Copy. A new badge makes the copy an original | `IllegalOperation`, whatever the word |
| CNode | the guard, below | the guard, below |
| Hypervisor | a narrowing, as [Mint data word](#mint-data-word) defines it; 0 is a Copy; a word that would widen is `IllegalOperation`. A narrowed copy is an original | `IllegalOperation` unless the word is 0 |
| Frame, paging structures | ignored; the mapping record is never changed | ignored |
| any other | ignored | ignored |

CNode data word, the layout of seL4's `seL4_CNode_CapData`:

| Bits | Field | Meaning |
| --- | --- | --- |
| 0 to 5 | `guard_size` | bits of guard, 0 to 63 |
| 6 to 63 | `guard` | the guard value; only its low `guard_size` bits are kept |

A `guard_size` with `guard_size + radix > 64` is `IllegalOperation`. A guard
longer than 58 bits has its top bits zero. Mint and Mutate always replace
the guard; there is no "keep" value.

### Capability lookup

A capability pointer is resolved through CNodes from its most significant
end. At each CNode, the next `guard_size` bits must equal the guard, and the
next `radix` bits index a slot.

- **Capability lookups** (the invoked capability in `rdi`, the extra
  capabilities in `caps_or_badges`) start at the thread's CSpace root and
  have 64 bits. They end at the first slot that does not hold a CNode
  capability (an empty slot or a Zombie included), or when the bits run
  out; leftover bits are ignored. A thread whose CSpace root slot holds
  anything but a CNode capability fails every lookup with `InvalidRoot`.
  A failure is a capability fault ([CapFault](#capfault-1)), carrying the
  lookup failure description below.
- **Slot arguments** name a slot as a root CNode capability, an `index` and a
  `depth`. Exactly the low `depth` bits of `index` are resolved, starting at
  the root. `depth` must be 1 to 64 (`RangeError` 1, 64), except that
  `Untyped_Retype`'s `node_depth` may be 0, naming the root itself, as in
  seL4. If a slot holding a
  non-CNode capability, or an empty slot, is reached with bits left, the
  lookup fails with `DepthMismatch` (bits found 0). To name a slot that holds
  a CNode capability, give the depth that ends at that slot.

Example: a single-level CSpace whose root CNode has radix 12 and a 52-bit
guard of 0 resolves `CPtr` `n` (below 4096) to slot `n`; slot arguments use
`depth` 64.

### Lookup failure description

A failed lookup is described by one to four words: in `FailedLookup` errors
from MR1, in capability faults where [CapFault](#capfault-1) puts them.

| Word | `InvalidRoot` | `MissingCapability` | `DepthMismatch` | `GuardMismatch` |
| --- | --- | --- | --- | --- |
| 0 | 1 | 2 | 3 | 4 |
| 1 | | bits left | bits left | bits left |
| 2 | | | bits found | guard of the CNode |
| 3 | | | | guard size of the CNode |

| Failure | Meaning |
| --- | --- |
| `InvalidRoot` | the root is not a CNode capability |
| `MissingCapability` | the slot reached is empty, or holds the wrong type of capability for the operation |
| `DepthMismatch` | a CNode needs more bits (bits found: its radix plus guard size) than are left, or a slot argument reached a non-CNode with bits left (bits found: 0) |
| `GuardMismatch` | the CNode's guard is longer than the bits left, or differs from them |

Bits left is the number of `CPtr` bits not yet resolved where the lookup
stopped; it is 0 after a slot argument resolved exactly.

### Error detail words

| Code | Name | `length` | MR0 | MR1 and up |
| --- | --- | --- | --- | --- |
| 0 | `NoError` | results | the invocation's results | |
| 1 | `InvalidArgument` | 1 | index of the message register at fault (0 for MR0) | |
| 2 | `InvalidCapability` | 1 | which capability: 0 for the invoked one, `i + 1` for extra capability `i` | |
| 3 | `IllegalOperation` | 0 | | |
| 4 | `RangeError` | 2 | smallest accepted value | MR1: largest accepted value |
| 5 | `AlignmentError` | 0 | | |
| 6 | `FailedLookup` | 2 to 5 | 1 if the failed slot argument was a source (`src_*`, `pivot_*`), 0 otherwise | the lookup failure description |
| 7 | `TruncatedMessage` | 0 | | |
| 8 | `DeleteFirst` | 0 | | |
| 9 | `RevokeFirst` | 0 | | |
| 10 | `NotEnoughMemory` | 1 | bytes free in the untyped: from 0 if it has no children, else from its watermark | |

Words past MR3 go to the IPC buffer; a thread without one receives MR0 to
MR3 only, and `length` counts what it received. For every object:

- Invoking an empty slot or a Zombie: `InvalidCapability`, MR0 = 0.
- A label outside the object's range, or unassigned inside it:
  `IllegalOperation`.
- Fewer message registers or extra capabilities than the invocation needs:
  `TruncatedMessage`.

### Untyped invocations

| Label | Name |
| --- | --- |
| `0x01` | `Untyped_Retype` |
| `0x02` to `0x0F` | reserved |

#### `0x01` `Untyped_Retype`

Creates `num_objects` objects of one type in the untyped and puts a
capability to each, with full rights, in consecutive empty slots of one
CNode.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `type` | object type number ([Object types and sizes](#object-types-and-sizes)) |
| MR1 | `size_bits` | Untyped: log2 of the size; CNode: radix; ignored otherwise |
| MR2 | `node_index` | slot of the destination CNode capability, resolved from `root` |
| MR3 | `node_depth` | bits of `node_index` to resolve, 0 to 64; 0 means `root` itself is the destination |
| MR4 | `node_offset` | first destination slot in the destination CNode |
| MR5 | `num_objects` | objects to create, 1 to 256 |

Extra capability 0: `root`, a CNode capability. Results: none.

Errors, in the order they are checked:

| Error | Detail | When |
| --- | --- | --- |
| `TruncatedMessage` | | fewer than 6 message registers, or no extra capability |
| `InvalidArgument` | 0 | `type` is not an object type number |
| `RangeError` | 4, 47 / 1, 42 | `size_bits` out of range for an Untyped / a CNode |
| `RangeError` | 0, 64 | `node_depth` above 64 |
| `FailedLookup` | 0, description | `root` is not a CNode (`InvalidRoot`), or `node_index` does not resolve |
| `FailedLookup` | 0, `MissingCapability` 0 | the destination slot does not hold a CNode capability |
| `RangeError` | 0, `2^radix - 1` | `node_offset` past the destination CNode |
| `RangeError` | 1, 256 | `num_objects` is 0 or above 256 |
| `RangeError` | 1, `2^radix - node_offset` | the objects would run past the destination CNode |
| `DeleteFirst` | | a destination slot is not empty |
| `NotEnoughMemory` | bytes free | the objects do not fit above the start (aligned) |
| `InvalidArgument` | 0 | the untyped is device memory and `type` is neither Untyped nor a Frame |
| `IllegalOperation` | | the untyped is at `MAX_DERIVATION_DEPTH` |

The call may be preempted while the untyped is cleared; it then restarts
from the thread's saved registers with progress kept.

### CNode invocations

| Label | Name |
| --- | --- |
| `0x10` | `CNode_Revoke` |
| `0x11` | `CNode_Delete` |
| `0x12` | `CNode_CancelBadgedSends` |
| `0x13` | `CNode_Copy` |
| `0x14` | `CNode_Mint` |
| `0x15` | `CNode_Move` |
| `0x16` | `CNode_Mutate` |
| `0x17` | `CNode_Rotate` |
| `0x18` | `CNode_SaveCaller` (see [CNode_SaveCaller](#cnode_savecaller)) |
| `0x19` to `0x1F` | reserved |

The invoked CNode capability is the root for the first slot argument (MR0,
MR1). CNode invocations return no results. Each first checks, in order:

| Error | Detail | When |
| --- | --- | --- |
| `TruncatedMessage` | | fewer message registers or extra capabilities than the method takes |
| `RangeError` | 1, 64 | a `depth` is 0 or above 64 (checked as each slot is looked up, after its root: a `src_root` or `pivot_root` that is not a CNode is `FailedLookup` 1, `InvalidRoot`, first, as seL4) |
| `FailedLookup` | 0, description | MR0 and MR1 do not resolve from the invoked CNode |

#### `0x10` `CNode_Revoke`

Deletes every capability derived, directly or not, from the capability in a
slot; the capability itself stays. Preemptible.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `index` | the slot |
| MR1 | `depth` | bits of `index` to resolve |

No further errors. An empty slot, or one without children, is left as it is.

#### `0x11` `CNode_Delete`

Deletes the capability in a slot, finalising its object if it was the last
capability to it. Preemptible. Arguments as `CNode_Revoke`. No further
errors; an empty slot is left as it is.

#### `0x12` `CNode_CancelBadgedSends`

Releases every thread queued to send on the endpoint with this capability's
badge (`docs/design.md`, [Deletion and
cancellation](design.md#deletion-and-cancellation)). Arguments as
`CNode_Revoke`.

| Error | When |
| --- | --- |
| `IllegalOperation` | the slot does not hold an Endpoint capability with Write, Read, Grant and GrantReply |

An unbadged capability does nothing.

#### `0x13` `CNode_Copy`

Copies a capability, with rights reduced to the rights word.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `dest_index` | destination slot, resolved from the invoked CNode |
| MR1 | `dest_depth` | bits of `dest_index` to resolve |
| MR2 | `src_index` | source slot, resolved from `src_root` |
| MR3 | `src_depth` | bits of `src_index` to resolve |
| MR4 | `rights` | the rights word |

Extra capability 0: `src_root`, a CNode capability.

| Error | Detail | When |
| --- | --- | --- |
| `DeleteFirst` | | the destination is not empty |
| `FailedLookup` | 1, description | `src_root` is not a CNode (`InvalidRoot`), or the source does not resolve |
| `FailedLookup` | 1, `MissingCapability` 0 | the source is empty |
| `RevokeFirst` | | the source is an untyped with children |
| `IllegalOperation` | | the source cannot be copied (Zombie, Reply, IRQControl, IOPortControl, PDPT, PageDirectory, PageTable), or the copy would be deeper than `MAX_DERIVATION_DEPTH` |

A copy of a Frame capability is unmapped, whether or not the source is
mapped. PML4 and Hypervisor capabilities can be copied.

#### `0x14` `CNode_Mint`

As `CNode_Copy`, plus capability data.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 to MR4 | | as `CNode_Copy` |
| MR5 | `data` | badge or guard ([Capability data](#capability-data)) |

Errors: as `CNode_Copy`, and `IllegalOperation` if the source is a badged
Endpoint or Notification, the guard does not fit, or a Hypervisor word
would widen.

#### `0x15` `CNode_Move`

Moves a capability, unchanged, with its place in the derivation tree. Any
capability can be moved.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 to MR3 | | as `CNode_Copy` |

Extra capability 0: `src_root`. Errors: `DeleteFirst` and the two
`FailedLookup` rows of `CNode_Copy`.

#### `0x16` `CNode_Mutate`

Moves a capability and applies capability data to it; it stays in its place
in the derivation tree.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 to MR3 | | as `CNode_Copy` |
| MR4 | `data` | the new guard for a CNode capability |

Extra capability 0: `src_root`. Errors: as `CNode_Move`, and
`IllegalOperation` for an Endpoint or Notification capability, a guard that
does not fit, or a non-zero word for a Hypervisor capability.

#### `0x17` `CNode_Rotate`

Atomically moves the pivot's capability to the destination and the source's
capability to the pivot, applying capability data to each as Mutate does.
If the destination is the source, the two capabilities swap.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `dest_index` | destination slot, resolved from the invoked CNode |
| MR1 | `dest_depth` | bits of `dest_index` to resolve |
| MR2 | `dest_data` | data applied to the capability that ends in the destination |
| MR3 | `pivot_index` | pivot slot, resolved from `pivot_root` |
| MR4 | `pivot_depth` | bits of `pivot_index` to resolve |
| MR5 | `pivot_data` | data applied to the capability that ends in the pivot |
| MR6 | `src_index` | source slot, resolved from `src_root` |
| MR7 | `src_depth` | bits of `src_index` to resolve |

Extra capabilities: 0 `pivot_root`, 1 `src_root`, both CNode capabilities.

| Error | Detail | When |
| --- | --- | --- |
| `FailedLookup` | 1, description | the source does not resolve |
| `FailedLookup` | 1, description | the pivot does not resolve |
| `IllegalOperation` | | the pivot is the source or the destination |
| `DeleteFirst` | | the destination is not the source and is not empty |
| `FailedLookup` | 1, `MissingCapability` 0 | the source is empty |
| `FailedLookup` | 1, `MissingCapability` 0 | the pivot is empty |
| `IllegalOperation` | | either data word is invalid for its capability ([Capability data](#capability-data)) |

## IPC and notifications

This section gives the meaning of the IPC registers, `MessageInfo` and the
IPC buffer, whose layouts are in [System calls](#system-calls),
[MessageInfo](#messageinfo) and [IPC buffer](#ipc-buffer) above.
`docs/design.md`, [IPC](design.md#ipc) and
[Notifications](design.md#notifications), explains the behaviour. Endpoints
and notifications have no invocation labels.

### Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `MSG_MAX_LENGTH` | 120 | message registers per message |
| `MSG_REG_COUNT` | 4 | message registers held in CPU registers (`r10`, `r8`, `r9`, `r15`) |
| `MSG_MAX_EXTRA_CAPS` | 3 | capability pointers a message may name |
| `IPC_BUFFER_BITS` | 10 | the IPC buffer is 1024 bytes, aligned to 1024 bytes |
| `ENDPOINT_BITS` | 5 | an Endpoint is 32 bytes |
| `NOTIFICATION_BITS` | 6 | a Notification is 64 bytes |
| `BADGE_BITS` | 64 | a badge is a whole word; 0 means unbadged |

### Message registers

Message register `i` is in a CPU register for `i` < 4 and in IPC buffer word
`1 + i` (`msg[i]`) for 4 ≤ `i` < 120. Buffer words 1 to 4 (`msg[0..4]`) are
never read or written by the kernel; user stubs may spill MR0 to MR3 there.

A thread has a usable IPC buffer when its TCB's IPC buffer slot (slot 2, at
offset 64) holds a frame capability that is not a device frame
([`TCB_SetIPCBuffer`](#0x27-tcb_setipcbuffer)). The slot holds a derived
copy in the derivation list, so revoking the frame empties it. The buffer is
readable with Read on that capability and writable with Read and Write. The
kernel reaches it through the direct map at the frame's physical address plus
the buffer's virtual address modulo the frame size, never through the user
mapping. Every message the kernel moves or writes, whether IPC, a fault
message or a kernel reply, follows one rule: MR0 to MR3 always travel in
registers, and MR4 and up travel only if the sending side has a readable
buffer and the receiving side a writable one. For a fault message or a
kernel reply the kernel is the sending side and always counts as having
one, so only the receiver's buffer matters. Otherwise the delivered
`length` is cut to at most 4 and the receiver is not told.

### MessageInfo semantics

| Field | When sending (`rsi` on `Send`, `NBSend`, `Call`, `Reply`, `ReplyRecv`) | When received (`rsi` after a receive phase) |
| --- | --- | --- |
| `length` | message registers to send; 121 to 127 count as 120 | message registers delivered |
| `extra_caps` | capability pointers to send from `caps_or_badges[0..extra_caps]` | capabilities processed: copied or unwrapped |
| `caps_unwrapped` | ignored | bit `i` set: capability `i` was unwrapped and its badge is in `caps_or_badges[i]` |
| `label` | user data, passed unchanged; for a kernel invocation, the invocation label | the sender's `label`; for a fault message, the fault type ([Fault messages](#fault-messages)); for a kernel reply, the error code |

### Registers for each system call

For `Send`, `NBSend`, `Call`, `Recv`, `NBRecv`, `Reply` and `ReplyRecv` on
endpoints, notifications and reply capabilities:

| System call | `rdi` in | `rsi` in | MR0 to MR3 in | `rdi` out | `rsi` out | MR0 to MR3 out |
| --- | --- | --- | --- | --- | --- | --- |
| `Send`, `NBSend` | destination | `MessageInfo` | message | preserved | preserved | preserved |
| `Call` | destination | `MessageInfo` | message | 0 | reply's `MessageInfo` | reply |
| `Recv`, `NBRecv` | source | ignored | ignored | badge | received `MessageInfo` | message |
| `Reply` | ignored | reply's `MessageInfo` | reply | preserved | preserved | preserved |
| `ReplyRecv` | source | reply's `MessageInfo` | reply | badge | received `MessageInfo` | message |

"Message" out means MR0 up to the delivered `length`; registers beyond it
keep the values the thread had on entry. A blocked thread's registers are
written only when its operation completes. `ReplyRecv` sends its reply
before it looks up `rdi`, so a capability fault in its receive phase comes
after the reply has been delivered.

What a receive phase returns:

| Source | `rdi` | `rsi` | MR0 to MR3 |
| --- | --- | --- | --- |
| Endpoint message | badge of the sender's endpoint capability | sender's `label`; delivered `length`, `extra_caps`, `caps_unwrapped` | message |
| Fault message | badge of the fault endpoint capability | fault type and `length` ([Fault messages](#fault-messages)) | fault words |
| Reply to `Call` | 0 | replier's `label`; delivered `length` and `extra_caps`; `caps_unwrapped` 0 | reply |
| Kernel reply to `Call` | 0 | error code in `label`; `length` counts the result or detail words | results or detail words |
| Signal, from a wait on a notification or from a bound notification during an endpoint receive | the notification word | 0 | unchanged |
| `NBRecv` with nothing pending | 0 | 0 | unchanged |

### IPC buffer semantics

| Word | Field | The kernel reads it | The kernel writes it |
| --- | --- | --- | --- |
| 0 | `tag` | never | never |
| 1 to 4 | `msg[0..4]` | never | never |
| 5 to 120 | `msg[4..120]` | the sender's `msg[4..length]` during a transfer; a kernel invocation's arguments | the receiver's `msg[4..length]`; kernel reply results; fault words |
| 121 | `user_data` | never | never |
| 122 to 124 | `caps_or_badges` | the sender's first `extra_caps` entries, at the send-time lookup and again at transfer | the receiver's entry `i` when capability `i` is unwrapped |
| 125 to 127 | `receive_cnode`, `receive_index`, `receive_depth` | the receiver's, once per transfer that may copy a capability to it, before the first capability is processed | never |

### Capability transfer

A send names `extra_caps` capabilities by `CPtr` in `caps_or_badges`; each is
resolved with all 64 bits in the sender's CSpace. The receiver names one
receive slot: `receive_cnode` is a `CPtr` (all 64 bits) to a CNode
capability in the receiver's CSpace, and `receive_index` with
`receive_depth` bits names a slot from that CNode, as CNode invocations name
slots ([Capability lookup](#capability-lookup)). The slot must be empty.

Capabilities move only when all hold:

- the sender's endpoint capability has Grant, or the reply capability used
  has Grant;
- the sender has a readable IPC buffer and `extra_caps` > 0;
- the receiver has a writable IPC buffer.

Then, in order of `i`, capability `i` is unwrapped if it is an endpoint
capability to the endpoint the message goes through (not for replies):
`caps_or_badges[i]` gets its badge, which may be 0, and bit `i` of
`caps_unwrapped` is set. Otherwise it is copied into the receive slot if the
slot is valid, empty and unused by this message, the capability passes
`derive`, and `insert_derived` accepts the copy below `MAX_DERIVATION_DEPTH`
([Constants](#constants)). The copy keeps the rights and badge and is derived
from the sender's capability as `CNode_Copy` would place it: a child of an
original, a sibling of a copy. The first capability that can be neither
unwrapped nor copied, including one refused at the depth limit, ends the
transfer; so does a failed re-lookup of any of the sender's pointers at
transfer time, before anything moves. The received `extra_caps` counts the
capabilities processed before the end.

### Badges

A badge is the 64-bit badge of an endpoint or notification capability, set
by `CNode_Mint` on an unbadged capability ([Capability
data](#capability-data)); 0 means unbadged. An endpoint message delivers the
badge of the capability the sender invoked, as it was when the send began,
in `rdi`. A signal ORs the badge of the signalling capability into the
notification word. Replies and kernel replies deliver 0.

### Reply capability

`Call` on an endpoint capability with Write and with Grant or GrantReply
blocks the caller until a reply. When the message is delivered, the kernel
puts a reply capability to the caller in the receiver's caller slot (TCB slot
4, at offset 128), which no `CPtr` reaches. It is derived from the caller's
master reply capability, which sits in the caller's TCB slot 3 (at offset 96)
from retype until the TCB is finalised, as a derivation root at depth 0. The
reply capability's Grant is the Grant of the capability the receiver received
on; it carries no other rights. It is consumed by `Reply`, by the reply phase
of `ReplyRecv`, or, once saved, by `Send`, `NBSend` or `Call` on it (`Call`
then also returns an empty kernel reply). It is deleted unused when it is deleted from
a CSpace slot (directly or with the CNode holding it) and when the caller is
suspended, restarted or deleted; while it is still in the holder's `caller`
slot, also when the holder receives on an endpoint or its TCB is deleted (a
saved one survives both). It cannot be copied, minted or
transferred; it can be moved. `Reply` with an empty caller slot does nothing.

### CNode_SaveCaller

Label `0x18`, invoked with `Call` on a CNode capability, which is the root
for the destination. It moves the reply capability from the invoking
thread's caller slot to the destination slot.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `index` | the destination slot, resolved from the invoked CNode |
| MR1 | `depth` | bits of `index` to resolve |

Extra capabilities: none. Result: none (`label` 0, `length` 0). Errors are
checked in the order listed, as in seL4 (`src/object/cnode.c`,
`decodeCNodeInvocation`, `invokeCNodeSaveCaller`).

| Error | When |
| --- | --- |
| `TruncatedMessage` | `length` < 2 |
| `RangeError` | `depth` out of range ([Capability lookup](#capability-lookup)) |
| `FailedLookup` | `index` and `depth` do not name a slot (detail words: [Lookup failure description](#lookup-failure-description)) |
| `DeleteFirst` | the destination slot is not empty |
| `IllegalOperation` | the caller slot is empty |

### Notification semantics

| Operation | System call on a notification capability | Right | Effect |
| --- | --- | --- | --- |
| Signal | `Send`, `NBSend`; `Call` also returns an empty kernel reply | Write | word = word OR badge, or wake the first waiter, or wake the bound thread out of an endpoint receive; never blocks |
| Wait | `Recv` | Read | if a signal is pending, return the word and clear it; else block |
| Poll | `NBRecv` | Read | if a signal is pending, return the word and clear it; else return 0 |

The message registers of a signal are ignored, and its `extra_caps`, though
still looked up, are not transferred. Only the
bound thread may wait on or poll a bound notification. A pending signal
through an unbadged capability returns word 0, like an empty poll.

### TCB_BindNotification and TCB_UnbindNotification

Labels `0x2B` and `0x2C`, in the TCB range ([TCB
invocations](#tcb-invocations)).

`TCB_BindNotification`, `Call` on the TCB capability, binds that thread to a
notification. Extra capability 0 is a notification capability. No message
registers. Result: none.

| Error | When |
| --- | --- |
| `TruncatedMessage` | no extra capability, including when the caller has no readable IPC buffer |
| `IllegalOperation` | the TCB is already bound; the extra capability is not a notification capability or lacks Read; the notification is already bound or has waiters |

Errors are checked in the order listed, and the `IllegalOperation` cases in
the order given, as in seL4 (`src/object/tcb.c`, `decodeBindNotification`).

If the notification has a pending signal and the thread is blocked in an
endpoint receive, the signal is delivered at once.

`TCB_UnbindNotification`, `Call` on the TCB capability, unbinds it. No
arguments, no result. Error: `IllegalOperation` if the TCB is not bound.

### Errors, faults and silent drops

A capability fault is delivered to the thread's fault handler as a
[CapFault](#capfault-1) message, which says whether it happened in the send
or the receive phase. An error is a kernel reply to `Call`
([Errors](#errors), with [Error detail words](#error-detail-words)).

| Situation | `Send` | `NBSend` | `Call` | `Recv`, `NBRecv`, receive phase of `ReplyRecv` |
| --- | --- | --- | --- | --- |
| The `CPtr` does not resolve to a slot | capability fault | nothing | capability fault | capability fault |
| The slot is empty | nothing | nothing | `InvalidCapability` | capability fault |
| A pointer in `caps_or_badges[0..extra_caps]` does not resolve (send-time lookup) | capability fault | nothing | capability fault | |
| Endpoint or notification capability without Write | nothing | nothing | `InvalidCapability` | |
| Endpoint capability with Write but neither Grant nor GrantReply | sent | sent | `InvalidCapability` | |
| Capability without Read, not an endpoint or notification, or a notification bound to another thread | | | | capability fault |
| No receiver waiting on the endpoint | blocks | message dropped | blocks | |
| Nothing pending | | | | `Recv` blocks; `NBRecv` returns `rdi` = 0, `rsi` = 0 |

Silent outcomes, never reported to either thread:

| Situation | Outcome |
| --- | --- |
| `length` above 120 | treated as 120 |
| Either side has no usable IPC buffer | delivered `length` at most 4 |
| Sender's capability lacks Grant; no buffer on either side; a sender pointer fails to resolve at transfer; the receive slot is invalid or full; a capability cannot be derived, or its copy would exceed `MAX_DERIVATION_DEPTH`; a second capability would need the slot | fewer capabilities move; the received `extra_caps` says how many were processed |
| `Reply`, or the reply phase of `ReplyRecv`, with an empty caller slot | nothing happens |
| A server receives on an endpoint before replying | the reply capability is deleted; the caller stays blocked until suspended, restarted or deleted |
| The final capability to an endpoint or notification is deleted, or `CNode_CancelBadgedSends` matches, while a thread is queued | the thread restarts its system call or faulting instruction |
| The fault endpoint does not resolve, or is not an endpoint capability with Write and with Grant or GrantReply | the faulting thread becomes `Inactive` |

### Objects

Kernel memory for both objects is zero after retype, which is the `Idle`,
empty, unbound state. A TCB reference is the TCB's physical address, 0 for
none: no kernel object lies at physical address 0, because M4 makes no
untyped below 1 MiB, and `core/` handles are `NonZeroU64`. Neither layout is
visible to user space; they justify the sizes.

Endpoint, `ENDPOINT_BITS` = 5, 32 bytes:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `queue_head` | first queued TCB |
| 8 | 8 | `queue_tail` | last queued TCB |
| 16 | 8 | `state` | 0 `Idle`, 1 `Send`, 2 `Recv` |
| 24 | 8 | reserved | 0 |

Notification, `NOTIFICATION_BITS` = 6, 64 bytes:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `word` | pending badge bits |
| 8 | 8 | `bound_tcb` | bound TCB |
| 16 | 8 | `queue_head` | first waiting TCB |
| 24 | 8 | `queue_tail` | last waiting TCB |
| 32 | 8 | `state` | 0 `Idle`, 1 `Waiting`, 2 `Active` |
| 40 | 24 | reserved | 0 |

Three words do not make a power of two, so the endpoint rounds up to four;
five words round the notification up to eight. Keeping each field a whole
word avoids seL4's packing (see the seL4 comparisons in `docs/design.md`,
[IPC](design.md#ipc) and [Notifications](design.md#notifications)).

## Threads

This section gives the TCB object, priorities, the initial FP state, the
user register set, the TCB invocations and the fault messages. Error detail
words are in [Error detail words](#error-detail-words). `docs/design.md`,
[Threads and TCBs](design.md#threads-and-tcbs) to [Faults](design.md#faults),
explains the behaviour.

### TCB object

| Property | Value |
| --- | --- |
| Object type | 1 ([Object types and sizes](#object-types-and-sizes)) |
| Size | 2^11 = 2048 bytes, `TCB_BITS` = 11, aligned to its size |
| Why | five 32-byte capability slots at offset 0, a 192-byte register frame, at most 256 bytes of scheduling and IPC state, and a 1024-byte XSAVE reserve at offset 1024 (576 used). the slots, the frame and the used XSAVE area (928 bytes) would fit 1 KiB, but not with the scheduling and IPC state as well, so 2 KiB; the layout is internal to the kernel apart from the slots at offset 0 |

After `Untyped_Retype`, a TCB is `Inactive` with priority 0, MCP 0, every
register 0 except `rflags` = `0x202`, the initial FP state below, empty CSpace,
VSpace and IPC buffer slots, `fault_ep` = 0 and no bound notification. Its
first return to user mode is through `iretq`.

### Priorities and time

| Name | Value | Meaning |
| --- | --- | --- |
| `MIN_PRIO` | 0 | lowest priority |
| `MAX_PRIO` | 255 | highest priority |
| root task | priority 255, MCP 255 | set by the kernel at boot |
| new TCB | priority 0, MCP 0 | |
| time slice | 10 ms | one tick of the 100 Hz local APIC timer |

`Yield` (system call 7) takes no arguments and returns no message. The current
thread goes to the tail of its priority's queue, with its remaining slice, and
the highest-priority runnable thread runs, which may be the caller again.

### Initial FP state

x87 and SSE only (XCR0 = `0x3`). FCW `0x037F` (every x87 exception masked,
64-bit precision, round to nearest), FSW 0, all x87 registers empty, MXCSR
`0x1F80` (every SIMD exception masked, round to nearest), all x87, MMX and XMM
registers 0. AVX and later instructions raise #UD. User code may read XCR0
with XGETBV. (Field meanings from memory; check in M5.)

### User register set

`TCB_ReadRegisters`, `TCB_WriteRegisters` and `TCB_CopyRegisters` use this
order, seL4's `seL4_UserContext` for x86_64. Every value written goes through
the rule in the last column; reads return the stored values.

| Word | Register | Rule on write |
| --- | --- | --- |
| 0 | `rip` | ≥ `0x0000_8000_0000_0000` becomes 0 |
| 1 | `rsp` | ≥ `0x0000_8000_0000_0000` becomes 0 |
| 2 | `rflags` | `(v & 0x0CD5) \| 0x0202`: CF, PF, AF, ZF, SF, DF, OF are kept; bit 1 and IF are set; every other bit is cleared |
| 3 | `rax` | none |
| 4 | `rbx` | none |
| 5 | `rcx` | none |
| 6 | `rdx` | none |
| 7 | `rsi` | none |
| 8 | `rdi` | none |
| 9 | `rbp` | none |
| 10 to 17 | `r8` to `r15` | none |
| 18 | `fs_base` | ≥ `0x0000_8000_0000_0000` becomes 0 |
| 19 | `gs_base` | ≥ `0x0000_8000_0000_0000` becomes 0 |

Words 0 to 17 are the frame registers; 18 and 19 are seL4's "integer"
registers. `rip` reads as the address the thread will continue at: for a
thread blocked in or restarting a system call, that is the `syscall`
instruction, which runs again if the thread is resumed. Writing any register
makes the thread return to user mode through `iretq`, so `rcx` and `r11` are
restored exactly. CS and SS are not part of the set and cannot be changed.
User code cannot write FS or GS base itself (CR4.FSGSBASE is clear); loading a
segment selector resets the base to 0 (from memory; check in M5).

### TCB invocations

Every TCB invocation is a `Call` on a TCB capability (or `Send` or `NBSend`,
which drop the reply). A TCB capability has no rights bits. Message
words are MR0 and up; extra capabilities come from `caps_or_badges`. These
rules apply to all of them:

- A label in `0x2E` to `0x3F` returns `IllegalOperation`.
- Missing message words or extra capabilities return `TruncatedMessage`.
- A flag bit not defined below returns `InvalidArgument` with detail 0 (the
  argument index of the flags word).
- `InvalidCapability`'s detail is 1 + the extra capability's index, as in seL4.
- On success the reply has label 0 and length 0, except ReadRegisters.

| Label | Invocation |
| --- | --- |
| `0x20` | `TCB_ReadRegisters` |
| `0x21` | `TCB_WriteRegisters` |
| `0x22` | `TCB_CopyRegisters` |
| `0x23` | `TCB_Configure` |
| `0x24` | `TCB_SetPriority` |
| `0x25` | `TCB_SetMCPriority` |
| `0x26` | `TCB_SetSchedParams` |
| `0x27` | `TCB_SetIPCBuffer` |
| `0x28` | `TCB_SetSpace` |
| `0x29` | `TCB_Suspend` |
| `0x2A` | `TCB_Resume` |
| `0x2B` | `TCB_BindNotification` |
| `0x2C` | `TCB_UnbindNotification` |
| `0x2D` | `TCB_SetTLSBase` |
| `0x2E` to `0x3F` | reserved |

#### `0x20` `TCB_ReadRegisters`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `flags` | bit 0 `suspend_source`: suspend the target first |
| 1 | `count` | registers to read, 1 to 20, from word 0 |

Extra capabilities: none. Result: length `count`, MR `i` = register word `i`.
A caller without a writable IPC buffer gets at most MR0 to MR3 and length
`min(count, 4)` (seL4 `invokeTCB_ReadRegisters`, `lookupIPCBuffer(true, ...)`).

Errors: `TruncatedMessage` (fewer than 2 words); `InvalidArgument` 0;
`RangeError` 1 to 20 (`count`); `IllegalOperation` (the target is the
caller).

#### `0x21` `TCB_WriteRegisters`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `flags` | bit 0 `resume_target`: resume the target afterwards |
| 1 | `count` | registers to write, 0 to 20, from word 0 |
| 2 to `count` + 1 | values | register words 0 to `count` − 1 |

Extra capabilities: none. Effect: the first `count` registers are written,
sanitised; then, if `resume_target`, the target is resumed as by
`TCB_Resume`.

Errors: `TruncatedMessage` (fewer than 2 words); `InvalidArgument` 0;
`RangeError` 0 to 20 (`count`); `TruncatedMessage` (fewer than `count` + 2
words, checked after the `RangeError` so the sum cannot overflow);
`IllegalOperation` (the target is the caller).

#### `0x22` `TCB_CopyRegisters`

The invoked TCB is the destination.

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `flags` | bit 0 `suspend_source`; bit 1 `resume_target`; bit 2 `transfer_frame` (words 0 to 17); bit 3 `transfer_integer` (words 18 and 19) |

| Extra capability | Meaning |
| --- | --- |
| 0 | the source TCB |

Effect, in order: suspend the source if asked; copy the chosen words, sanitised
for the destination; resume the destination if asked.

Errors: `TruncatedMessage` (no flags word or no extra capability);
`InvalidArgument` 0; `InvalidCapability` 1 (extra capability 0 is not a TCB);
`IllegalOperation` (the source or the destination is the caller).

#### `0x23` `TCB_Configure`

`TCB_SetSpace` and `TCB_SetIPCBuffer` in one call.

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `fault_ep` | CPtr of the fault endpoint, resolved in the target's CSpace when it faults; not checked now |
| 1 | `cspace_root_data` | capability data word applied to the CSpace root (guard; [Capability data](#capability-data)); 0 leaves it unchanged |
| 2 | `ipc_buffer` | user address of the IPC buffer, a multiple of 1024; 0 for none |

| Extra capability | Meaning |
| --- | --- |
| 0 | CSpace root: a CNode capability |
| 1 | VSpace root: a PML4 capability ([Address spaces](#address-spaces)) |
| 2 | IPC buffer frame: a non-device Frame capability, not a SynIC page; needed only if `ipc_buffer` ≠ 0 |

Effect: stores `fault_ep`; deletes the old roots and buffer frame from the
TCB's slots and installs copies derived from the given capabilities; sets the
IPC buffer address. The kernel reaches the buffer through the frame at offset
`ipc_buffer` modulo the frame size. Priority is not changed.

Errors, checked in this order as in seL4's `decodeTCBConfigure`; the first
failure is returned, and no slot changes unless every check passes:

1. `TruncatedMessage`: fewer than 3 words, fewer than 2 extra capabilities,
   or no frame when `ipc_buffer` ≠ 0.
2. The buffer, when `ipc_buffer` ≠ 0: `IllegalOperation` if extra capability
   2 is not a non-device Frame or its derived copy would exceed
   `MAX_DERIVATION_DEPTH`; `InvalidCapability` 3 if it is one of the two
   SynIC pages; `AlignmentError` if `ipc_buffer` is not a multiple of 1024.
3. `IllegalOperation` if deleting the current CSpace root (slot 0) would be
   long-running.
4. The CSpace root: any error from applying `cspace_root_data`
   ([Capabilities](#capabilities)); `IllegalOperation` if the result is not a
   CNode or its derived copy would exceed `MAX_DERIVATION_DEPTH`.
5. The VSpace root: `IllegalOperation` if extra capability 1 is not a valid
   VSpace root or its derived copy would exceed `MAX_DERIVATION_DEPTH`.

Every depth refusal is decided while decoding, before any slot is emptied.

#### `0x24` `TCB_SetPriority`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `priority` | new priority |

| Extra capability | Meaning |
| --- | --- |
| 0 | `authority`: a TCB whose MCP bounds the new priority (it may be the target or the caller) |

The kernel compares the whole 64-bit word with the MCP before narrowing it to
a `u8` (seL4's `prio_t` is a word), so any value from 256 up is a `RangeError`.

Errors: `TruncatedMessage`; `InvalidCapability` 1 (`authority` is not a TCB);
`RangeError` 0 to the authority's MCP.

#### `0x25` `TCB_SetMCPriority`

As `TCB_SetPriority`, with MR0 `mcp`, the new MCP. The priority is unchanged.

#### `0x26` `TCB_SetSchedParams`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `mcp` | new MCP |
| 1 | `priority` | new priority |

Extra capability 0: `authority`, as for `TCB_SetPriority`. Both values are
checked against the authority's MCP before either is changed.

Errors: `TruncatedMessage`; `InvalidCapability` 1; `RangeError` 0 to the
authority's MCP if either value is above it (`mcp` is checked first, as in
seL4).

#### `0x27` `TCB_SetIPCBuffer`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `ipc_buffer` | user address, a multiple of 1024; 0 for none |

Extra capability 0: the IPC buffer frame, a non-device Frame capability,
needed only if `ipc_buffer` ≠ 0.

Effect: deletes the old buffer frame from slot 2, installs a copy derived
from the given capability (or leaves slot 2 empty when `ipc_buffer` = 0), and
sets the IPC buffer address.

Errors, checked in this order (step 2 of `TCB_Configure`): `TruncatedMessage`;
`IllegalOperation` (not a non-device Frame, or the derived copy would exceed
`MAX_DERIVATION_DEPTH`); `InvalidCapability` 1 (the frame is one of the two
SynIC pages, whose physical addresses the kernel records at boot; the kernel
never reads them through a capability); `AlignmentError`.

#### `0x28` `TCB_SetSpace`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `fault_ep` | as for `TCB_Configure` |
| 1 | `cspace_root_data` | as for `TCB_Configure` |

Extra capabilities: 0 the CSpace root, 1 the VSpace root, as for
`TCB_Configure`. Errors: steps 1, 3, 4 and 5 of `TCB_Configure`, in that
order (fewer than 2 words or 2 extra capabilities is `TruncatedMessage`).

#### `0x29` `TCB_Suspend`

No arguments. The target becomes `Inactive`: any IPC it is blocked in is
cancelled (a pending fault included) and it leaves the ready queue. If the
target is the caller and the invocation is a `Call`, the empty success reply
(`rsi` = 0, `rdi` = 0) is written first (with `Send` or `NBSend` the caller's
registers are left alone, as for any `Send`); it takes effect when the caller is resumed, which continues
after its `syscall` as if Suspend returned `NoError`. Suspending an
`Inactive` thread does nothing. Errors: none of its own.

#### `0x2A` `TCB_Resume`

No arguments. If the target is `Inactive` or blocked in IPC, its IPC is
cancelled and it becomes runnable in `Restart`: it re-executes the instruction
at `rip`, which for a thread that was blocked is its system call. Otherwise
nothing happens. Errors: none of its own.

#### `0x2B` `TCB_BindNotification`

Extra capability 0: a notification capability with the receive right.
[TCB_BindNotification and
TCB_UnbindNotification](#tcb_bindnotification-and-tcb_unbindnotification)
defines what binding does.

Errors: `TruncatedMessage`; `IllegalOperation` (the TCB already has a bound
notification; the capability is not a notification or lacks the receive right;
the notification is already bound or has waiting threads).

#### `0x2C` `TCB_UnbindNotification`

No arguments. Errors: `IllegalOperation` (no notification is bound).

#### `0x2D` `TCB_SetTLSBase`

| MR | Name | Meaning |
| --- | --- | --- |
| 0 | `tls_base` | new FS base, sanitised as register word 18 |

Works on any TCB, the caller included (seL4 too); on the caller it takes
effect before the call returns. Errors: `TruncatedMessage`.

### Fault messages

A fault arrives at the handler as a message on the faulting thread's fault
endpoint, sent as a Call: `rdi` holds the badge of the fault endpoint
capability, the `MessageInfo` label is the fault type, and `length` counts the
words below. Words past MR3 are in the handler's IPC buffer; a handler without
a writable one gets MR0 to MR3 and length 4.

| Label | Fault | Length |
| --- | --- | --- |
| 1 | `CapFault` | 4 to 7 |
| 2 | `UnknownSyscall` | 19 |
| 3 | `UserException` | 5 |
| 4 | reserved | |
| 5 | `VMFault` | 4 |

The fault endpoint is the `fault_ep` CPtr, looked up in the faulting thread's
CSpace when the fault happens. It must name an endpoint capability with Write
plus Grant or GrantReply, checked at that moment. Otherwise the thread
becomes `Inactive` and no message is sent.

#### CapFault (1)

| MR | Content |
| --- | --- |
| 0 | `ip`: the address of the `syscall` instruction |
| 1 | `addr`: the CPtr that failed |
| 2 | `in_recv_phase`: 1 if the failure was in a receive phase, else 0 |
| 3 to 6 | the lookup-failure description, one to four words ([Lookup failure description](#lookup-failure-description)): type 1 `InvalidRoot`, 2 `MissingCapability`, 3 `DepthMismatch` or 4 `GuardMismatch`; then bits left; then, for `DepthMismatch`, bits found, or for `GuardMismatch`, the guard and its size (seL4 `setMRs_lookup_failure`) |

#### UnknownSyscall (2)

| MR | Content |
| --- | --- |
| 0 to 14 | `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `r8`, `r9`, `r10`, `r11`, `r12`, `r13`, `r14`, `r15` |
| 15 | `ip`: the address of the `syscall` instruction |
| 16 | `rsp` |
| 17 | `rflags` |
| 18 | the system call number (`rdx`) |

`rcx` and `r11` hold what `syscall` put there: the return address and RFLAGS.

#### UserException (3)

| MR | Content |
| --- | --- |
| 0 | `ip`: the RIP the exception pushed (the faulting instruction, or the next one for a trap such as #BP) |
| 1 | `rsp` |
| 2 | `rflags` |
| 3 | `number`: the exception vector |
| 4 | `code`: the exception's error code, or 0 if it has none |

Vectors 0, 1, 3, 6, 10 to 13, 16 and 19 arrive here; 4, 5 and 7 would too,
with code 0, but cannot occur here. `int3` gives 3 with `ip`
after it (vector 3 is the only DPL-3 gate); `int n` for any other `n` gives 13
with code `8n + 2`; TF single-step and `int1` give 1. Page faults
are VMFaults. Vectors 9, 15, 17 and 20 to 31 cannot occur; if one does, the
kernel panics.

#### VMFault (5)

| MR | Content |
| --- | --- |
| 0 | `ip`: the faulting instruction |
| 1 | `addr`: the faulting address (CR2) |
| 2 | `prefetch`: 1 if the fault was an instruction fetch (error code bit 4), else 0 |
| 3 | `fsr`: the page-fault error code |

#### Fault replies

The handler answers with `Reply` or `ReplyRecv`, using the reply capability it
received.

| Fault | Reply label 0 | Reply label ≠ 0 | Registers set from the reply |
| --- | --- | --- | --- |
| `CapFault` | restart | thread becomes `Inactive` | none |
| `UnknownSyscall` | restart | `Inactive` | the first `min(length, 18)` words, in the order of MR0 to MR17 above |
| `UserException` | restart | `Inactive` | the first `min(length, 3)` words: `rip`, `rsp`, `rflags` |
| `VMFault` | restart | `Inactive` | none |

Registers are set whatever the reply's label, as in seL4. Words past MR3 come
from the handler's IPC buffer only if it is readable; otherwise only the first
four are set. Values set from a reply are sanitised as for
`TCB_WriteRegisters`, and the thread next leaves by `iretq`. A restarted
thread continues at `rip`: a faulting instruction or `syscall` runs again
unless the reply changed `rip`; to skip a `syscall`, add 2.

## Address spaces

This section gives the segment selectors, the kernel half, the user address
range, the paging objects and their invocations. `docs/design.md`,
[Privilege levels](design.md#privilege-levels) and [Address
spaces](design.md#address-spaces), explains the behaviour.

### Privilege levels

#### Segment selectors

| GDT offset | Selector | Segment |
| --- | --- | --- |
| `0x00` | | null |
| `0x08` | `0x08` | kernel code, ring 0, 64-bit |
| `0x10` | `0x10` | kernel data, ring 0 |
| `0x18` | `0x1B` | user data, ring 3; SS of every user thread |
| `0x20` | `0x23` | user code, ring 3, 64-bit; CS of every user thread |
| `0x28` | `0x28` | TSS, 16 bytes |

`IA32_STAR` = `0x0013_0008_0000_0000`: `syscall` loads CS `0x08` and SS
`0x10`, and `sysretq` loads CS `0x13 + 16` = `0x23` and SS `0x13 + 8` =
`0x1B`. User threads cannot choose other selectors, and there is no 32-bit
user code segment.

#### Kernel half

Not usable by user code; listed because the user range ends below it.

| Name | Value | Meaning |
| --- | --- | --- |
| `PHYS_MAP_BASE` | `0xFFFF_8000_0000_0000` | the direct map, at most 64 GiB |
| `KERNEL_VIRT_BASE` | `0xFFFF_FFFF_8000_0000` | the kernel image, at most 16 MiB including the embedded root task |
| `KERNEL_DEVICE_BASE` | `0xFFFF_FFFF_FFE0_0000` | the kernel's uncached device window: local APIC, four I/O APIC pages, HPET |

### Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `PAGE_BITS` | 12 | 4 KiB frame |
| `LARGE_PAGE_BITS` | 21 | 2 MiB frame |
| `PAGING_STRUCTURE_BITS` | 13 | every paging structure (PML4, PDPT, PageDirectory, PageTable) |
| `PAGING_INDEX_BITS` | 9 | entries per paging structure: 512 |
| `USER_MIN` | `0x0000_0000_0000_1000` | lowest virtual address a frame may map |
| `USER_TOP` | `0x0000_7FFF_FFFF_F000` | a frame mapping must end at or below this address |

A frame of size `s` maps at `vaddr` only when `vaddr` is a multiple of `s`,
`vaddr >= USER_MIN` and `vaddr <= USER_TOP - s`. The highest 4 KiB frame
maps at `0x0000_7FFF_FFFF_E000` and the highest 2 MiB frame at
`0x0000_7FFF_FFC0_0000`.

### Address-space object sizes

Type numbers are in [Object types and sizes](#object-types-and-sizes). All
six objects have a fixed size and are aligned to it.

| Type | Object | Size bits | Why |
| --- | --- | --- | --- |
| 5 | Frame, 4 KiB | 12 | the hardware page |
| 6 | Frame, 2 MiB | 21 | the hardware large page; physical alignment to 2 MiB is a hardware rule |
| 7 | PageTable | 13 | 4 KiB hardware table plus 4 KiB of back-references, below |
| 8 | PageDirectory | 13 | as PageTable |
| 9 | PDPT | 13 | as PageTable |
| 10 | PML4 | 13 | as PageTable; only back-references 0 to 255 are used, since entries 256 to 511 are the kernel's |

Paging-structure layout (kernel-internal; given to justify the size):

| Offset | Bytes | Content |
| --- | --- | --- |
| `0x0000` | 4096 | the hardware table: 512 entries of 8 bytes, entry `i` translating index `i` at this level |
| `0x1000` | 4096 | 512 back-reference words: 0, or the physical address of the capability slot holding the capability that installed entry `i`, with bit 0 set (slots are 32-byte aligned) |

A new PML4's entries 256 to 511 are copies of the kernel PML4's; everything
else in a new paging structure is zero.

### Rights word

`Frame_Map` and `Frame_Remap` take the rights word of [Rights](#rights).
They use its `read` and `write` bits and ignore the others. The mapping gets the
requested rights masked by the frame capability's rights. If `read` is not in
the result, the invocation fails, because x86 cannot map a page write-only or
with no access.

### Attributes word

| Bits | Field | Meaning |
| --- | --- | --- |
| 0 to 2 | `cache` | `0` `WriteBack`, `3` `Uncached`, `4` `WriteCombining`; any other value is invalid. The value is the PAT index. |
| 3 | `execute` | `1`: the mapping is executable; `0`: no-execute |
| 4 to 63 | reserved | must be 0 |

A frame from RAM untyped may use only `WriteBack`. A frame from device
untyped may use only `Uncached` or `WriteCombining`.

### Invocation labels

| Label | Invocation | Invoked capability |
| --- | --- | --- |
| `0x40` | `PDPT_Map` | PDPT |
| `0x41` | `PDPT_Unmap` | PDPT |
| `0x42` | `PageDirectory_Map` | PageDirectory |
| `0x43` | `PageDirectory_Unmap` | PageDirectory |
| `0x44` | `PageTable_Map` | PageTable |
| `0x45` | `PageTable_Unmap` | PageTable |
| `0x46` to `0x4F` | reserved | |
| `0x50` | `Frame_Map` | Frame, either size |
| `0x51` | `Frame_Unmap` | Frame |
| `0x52` | `Frame_Remap` | Frame |
| `0x53` | `Frame_GetAddress` | Frame |
| `0x54` to `0x5F` | reserved | |

A PML4 capability has no invocations. Any label not listed for the invoked
capability's type, including a map or unmap label for another level, returns
`IllegalOperation`. The `0x90` to `0x9F` range stays unused: address spaces
add no object type.

Error codes are in [Errors](#errors) and their detail words in [Error detail
words](#error-detail-words). Below, "cap `n`" is the capability index the
`InvalidCapability` detail names (0 is the invoked capability, 1 the first
extra capability), and "arg `n`" is the message-register index the
`InvalidArgument` detail names. `FailedLookup` reports a missing-capability
lookup failure, not on the source side, with the number of address bits left
unresolved below the missing level, as seL4 does: 39 when there is no PDPT,
30 when there is no PageDirectory, 21 when there is no PageTable (or a 2 MiB
frame is mapped where it would be). Checks run in the order listed, and
nothing changes unless all pass.

### `PDPT_Map`, `PageDirectory_Map`, `PageTable_Map`

Maps the invoked paging structure into a VSpace, one level below the
structure that covers `vaddr`.

| Register | Meaning |
| --- | --- |
| MR0 | `vaddr`: any address the structure will cover; the low 39 (PDPT), 30 (PageDirectory) or 21 (PageTable) bits are ignored |

Extra capability 0: the VSpace, a PML4 capability. Result: none.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 1 message register, or no extra capability |
| `InvalidCapability`, cap 1 | the extra capability is not a PML4 |
| `InvalidCapability`, cap 0 | the structure is mapped, or still holds entries (left when its parent was deleted or unmapped); `Unmap` it first |
| `InvalidArgument`, arg 0 | `vaddr` with the ignored bits cleared is at or above `USER_TOP` |
| `FailedLookup` | `PageDirectory_Map`: no PDPT covers `vaddr` (39). `PageTable_Map`: no PDPT (39) or no PageDirectory (30) covers `vaddr` |
| `DeleteFirst` | the entry this structure would occupy is present: a structure, or for `PageTable_Map` a 2 MiB frame |

### `PDPT_Unmap`, `PageDirectory_Unmap`, `PageTable_Unmap`

No arguments and no extra capabilities. Result: none. Errors: none beyond
`IllegalOperation` for the wrong type.

If the structure is mapped, the kernel clears its entry in the parent. It
then clears every entry of the structure itself: each frame or child
structure mapped there becomes unmapped (a child structure keeps its own
entries). The structure is then unmapped and empty, and can be mapped again.
On a structure that is already unmapped and empty, nothing happens.

### `Frame_Map`

Maps the invoked frame into a VSpace.

| Register | Meaning |
| --- | --- |
| MR0 | `vaddr`, aligned to the frame's size |
| MR1 | requested rights, a rights word |
| MR2 | attributes word |

Extra capability 0: the VSpace, a PML4 capability. Result: none.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 3 message registers, or no extra capability |
| `InvalidCapability`, cap 1 | the extra capability is not a PML4 |
| `InvalidCapability`, cap 0 | this frame capability is already mapped (map a copy, or use `Frame_Remap`) |
| `AlignmentError` | `vaddr` is not a multiple of the frame's size |
| `InvalidArgument`, arg 0 | `vaddr < USER_MIN`, or `vaddr > USER_TOP - size` |
| `InvalidArgument`, arg 1 | the requested rights masked by the capability's rights do not include `read` |
| `InvalidArgument`, arg 2 | reserved attribute bits are set, `cache` is invalid, or `cache` is not allowed for this frame (RAM or device) |
| `FailedLookup` | 4 KiB frame: no PDPT (39), PageDirectory (30) or PageTable (21) covers `vaddr`. 2 MiB frame: no PDPT (39) or PageDirectory (30) |
| `DeleteFirst` | the entry at `vaddr` is present: a frame, or for a 2 MiB frame a PageTable |

### `Frame_Unmap`

No arguments and no extra capabilities. Result: none. Errors: none beyond
`IllegalOperation` for the wrong type. Removes the frame capability's
mapping, if it has one; otherwise does nothing.

### `Frame_Remap`

Changes the rights and attributes of the invoked capability's existing
mapping.

| Register | Meaning |
| --- | --- |
| MR0 | requested rights, a rights word |
| MR1 | attributes word |

No extra capabilities. Result: none.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 2 message registers |
| `IllegalOperation` | the frame capability is not mapped |
| `InvalidArgument`, arg 0 | the requested rights masked by the capability's rights do not include `read` |
| `InvalidArgument`, arg 1 | as for `Frame_Map` arg 2 |

### `Frame_GetAddress`

No arguments and no extra capabilities. Result: length 1; MR0 is the physical
address of the frame's first byte. Errors: none beyond `IllegalOperation` for
the wrong type. Built in M9; before M9 the label returns `IllegalOperation`.

## Interrupts, I/O ports and Hyper-V

This section gives the interrupt vectors, the IRQControl, IRQHandler,
IOPortControl, IOPort and Hypervisor invocations, the SynIC frames and the
BootInfo fields for interrupts. Error detail words and destination-slot
lookup are in [Capabilities](#capabilities). `docs/design.md`,
[Interrupts](design.md#interrupts) to [Hyper-V
interface](design.md#hyper-v-interface), explains the behaviour.

### Conventions

- Every invocation here is `Call` on the capability, with the label below.
  `Send` and `NBSend` perform it and drop the reply.
- "Destination" means extra capability 0, the CNode that forms the root of the
  destination CSpace, plus the `index` and `depth` message registers; it is
  resolved and checked as the destination slot of a CNode invocation
  ([Capability lookup](#capability-lookup), [CNode
  invocations](#cnode-invocations)), and fails as there: `RangeError(1, 64)`
  for a `depth` of 0 or above 64, then `FailedLookup` or `DeleteFirst`.
- Checks run in this order, and the first failure is returned:
  1. the label is valid for this capability type (for `GetSint`, also that a
     usable SynIC exists), else `IllegalOperation`;
  2. enough message registers and extra capabilities, else `TruncatedMessage`;
  3. argument values, in message-register order (`InvalidArgument`,
     `RangeError`, `InvalidCapability`);
  4. the capability's own limits: an IOPort's range, a restricted Hypervisor
     capability's connection and rights (`IllegalOperation`);
  5. resources: source, vector or port range free, else `RevokeFirst`;
  6. the destination slot (`RangeError(1, 64)` for its `depth`, then
     `FailedLookup`, `DeleteFirst`).
- `InvalidArgument(n)` names message register `n`; `RangeError(min, max)` and
  `InvalidCapability(n)` carry the [detail words](#error-detail-words).
- A success returns label `NoError` and `length` = the number of result
  registers listed.
- Labels left unused inside the ranges `0x60` to `0x8F` are invalid
  (`IllegalOperation`), as is a label of the other type in a shared range,
  such as `IOPort_In8` on IOPortControl.

### Interrupt vectors

| Vector | Use |
| --- | --- |
| `0x00`-`0x1F` | CPU exceptions; only `#BP` (3) has DPL 3; 9, 15, 17 and 20 to 31 panic from either ring; `#DB` on IST4 |
| `0x20`-`0x2F` | 8259 PIC, remapped and masked; spurious if delivered, EOI only when the vector's ISR bit is set |
| `0x30`-`0xEF` | device vectors; IRQ number `irq` = vector - `0x30`, 0-191 |
| `0xF0`-`0xFC` | reserved |
| `0xFD` | local APIC timer |
| `0xFE` | local APIC error |
| `0xFF` | local APIC spurious |

User space sees vectors only as IRQ numbers in results, and as MSI data.

### Capabilities

None of these capabilities names memory: none is an `Untyped_Retype` object
type, and none has a size. Their fields, for the capability format of
`docs/design.md`, [Capability
representation](design.md#capability-representation):

| Capability | Fields | Copy | Mint | Children | Last capability deleted |
| --- | --- | --- | --- | --- | --- |
| IRQControl | none | no (derives to nothing) | no | IRQHandler, revocable | nothing |
| IRQHandler | `irq`, 8 bits | yes | data ignored | copies of the issued (original) handler | notification unbound; an I/O APIC pin or a SINT masked (a pin keeps its vector and trigger in its entry); vector freed |
| IOPortControl | none | no (derives to nothing) | no | IOPort, revocable | nothing |
| IOPort | `first`, `last`, 16 bits each | yes | data ignored | copies of the issued (original) range | range freed |
| Hypervisor | `restricted`, 1 bit; `connection`, 24 bits; `post`, `signal`, 1 bit each | yes (passes `derive`) | narrows and makes an original; see [Mint data word](#mint-data-word) | copies of an original: the boot capability or a narrowed one | nothing |

Static kernel memory reserved at boot for interrupts, I/O ports and Hyper-V:
the IRQ table and IRQ node (192 entries; the node is 192 slots of 32 bytes,
6 KiB), the port bitmap (65,536 bits, 8 KiB), the I/O APIC table (4
entries), and on Hyper-V the hypercall page (4 KiB, the `.hvcall` section of
kernel text), the hypercall input page (4 KiB, kernel BSS) and the two SynIC
frames (4 KiB of RAM each, from the boot region, outside every untyped,
mapped write-back).

### IRQControl

#### `0x60` `IRQControl_GetISA`

Issues a handler for an ISA IRQ, routed through the MADT's interrupt source
overrides; without one, ISA IRQ `n` is GSI `n`, edge, active high
(`InterruptInfo.isa_routes[n]` shows the result). Before the final entry it
writes the pin masked and edge-triggered and checks that Remote IRR is 0.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `isa_irq` | 0-15 |
| MR1 | `index` | destination slot |
| MR2 | `depth` | destination depth |

Extra capability 0: destination root CNode.

Result: MR0 `irq`; MR1 `gsi`; MR2 `flags`, bit 0 level-triggered, bit 1
active low.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 3 registers, or no extra capability |
| `RangeError(0, 15)` | `isa_irq` > 15 |
| `InvalidArgument(0)` | the IRQ has no route: its GSI is another IRQ's override target, or no I/O APIC serves it |
| `RevokeFirst` | the GSI already has a handler, no device vector is free, or the pin's Remote IRR stays set (retry later) |
| `RangeError(1, 64)`, `FailedLookup`, `DeleteFirst` | destination slot, checked last |

#### `0x61` `IRQControl_GetIOAPIC`

Issues a handler for a GSI with explicit flags; no override is applied. It
checks Remote IRR first, as `GetISA` does.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `gsi` | global system interrupt |
| MR1 | `trigger` | 0 edge, 1 level |
| MR2 | `polarity` | 0 active high, 1 active low |
| MR3 | `index` | destination slot |
| MR4 | `depth` | destination depth |

Extra capability 0: destination root CNode. Result: MR0 `irq`.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 5 registers, or no extra capability |
| `InvalidArgument(0)` | no I/O APIC serves `gsi` |
| `RangeError(0, 1)` | `trigger` or `polarity` > 1 |
| `RevokeFirst` | the GSI already has a handler, no device vector is free, or the pin's Remote IRR stays set (retry later) |
| `RangeError(1, 64)`, `FailedLookup`, `DeleteFirst` | destination slot, checked last |

#### `0x62` `IRQControl_GetMSI` (M9)

Reserves a vector for one MSI or MSI-X message. Before M9 this label returns
`IllegalOperation`.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `index` | destination slot |
| MR1 | `depth` | destination depth |

Extra capability 0: destination root CNode.

Result: MR0 `irq`; MR1 `address`, the message address (`0xFEE0_0000 | (APIC
ID << 12)`; the upper 32 bits are 0); MR2 `data`, the message data (the
vector, fixed delivery, edge). The driver writes both into the device
unchanged.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 2 registers, or no extra capability |
| `RevokeFirst` | no device vector is free |
| `RangeError(1, 64)`, `FailedLookup`, `DeleteFirst` | destination slot, checked last |

#### `0x63` `IRQControl_GetSint` (M9)

Issues a handler for a Hyper-V SynIC interrupt source and unmasks it.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `sint` | 0-15 |
| MR1 | `index` | destination slot |
| MR2 | `depth` | destination depth |

Extra capability 0: destination root CNode. Result: MR0 `irq`.

| Error | When |
| --- | --- |
| `IllegalOperation` | no usable SynIC: the kernel made no Hypervisor capability at boot (not Hyper-V, an M9 privilege missing, or a hypercall MSR locked outside `.hvcall`) |
| `TruncatedMessage` | fewer than 3 registers, or no extra capability |
| `RangeError(0, 15)` | `sint` > 15 |
| `RevokeFirst` | the SINT already has a handler, or no device vector is free |
| `RangeError(1, 64)`, `FailedLookup`, `DeleteFirst` | destination slot, checked last |

Labels `0x64`-`0x67` are reserved.

### IRQHandler

An interrupt signals the bound notification with that capability's badge,
with the [notification semantics](#notification-semantics) of IPC. Masking:

| Source | On delivery | `Ack` |
| --- | --- | --- |
| I/O APIC, level | masked | unmasks |
| I/O APIC, edge | `pending` set; masked if `pending` was already set | clears `pending`; unmasks if masked |
| MSI, SINT | unchanged | does nothing |

So between two `Ack`s an I/O APIC pin delivers at most three interrupts: two,
plus one the local APIC may already hold when the mask lands.
A driver binds, Acks once, services its device once, then loops: wait,
service, Ack.

#### `0x68` `IRQHandler_Ack`

No registers, no extra capabilities, no result, no errors beyond the
label check.

#### `0x69` `IRQHandler_SetNotification`

Extra capability 0: a notification capability with the Write right. Any
bound notification is unbound first; the given capability, badge included,
is copied into the handler's IRQ node slot, placed in the derivation list as
`CNode_Copy` would place it. Every check runs before the old binding is
removed. No registers, no result.

| Error | When |
| --- | --- |
| `TruncatedMessage` | no extra capability |
| `InvalidCapability(1)` | extra capability 0 is not a notification capability, or has no Write right |
| `IllegalOperation` | the copy would be deeper than `MAX_DERIVATION_DEPTH` = 4095 |

#### `0x6A` `IRQHandler_Clear`

Unbinds the notification, if any. No registers, no result, no errors beyond
the label check.

Labels `0x6B`-`0x6F` are reserved.

### IOPortControl and IOPort

Kernel-reserved ports, never issued: `0x20`-`0x23` and `0xA0`-`0xA1`.

#### `0x70` `IOPortControl_Issue`

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `first_port` | first port of the range |
| MR1 | `last_port` | last port, inclusive |
| MR2 | `index` | destination slot |
| MR3 | `depth` | destination depth |

Extra capability 0: destination root CNode. No result.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 4 registers, or no extra capability |
| `InvalidArgument(0)` | `first_port` > `0xFFFF` |
| `InvalidArgument(1)` | `last_port` > `0xFFFF`, or `last_port` < `first_port` |
| `InvalidArgument(0)` | the range holds a kernel-reserved port (checked once both bounds are valid) |
| `RevokeFirst` | the range overlaps an issued range |
| `RangeError(1, 64)`, `FailedLookup`, `DeleteFirst` | destination slot, checked last |

#### `0x71` `IOPort_In8`, `0x72` `IOPort_In16`, `0x73` `IOPort_In32`

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `port` | port to read; width 1, 2 or 4 |

Result: MR0 the value read, zero-extended.

| Error | When |
| --- | --- |
| `TruncatedMessage` | no MR0 |
| `InvalidArgument(0)` | `port` > `0xFFFF` |
| `IllegalOperation` | `port` < `first`, or `port + width - 1` > `last` |

#### `0x74` `IOPort_Out8`, `0x75` `IOPort_Out16`, `0x76` `IOPort_Out32`

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `port` | port to write; width 1, 2 or 4 |
| MR1 | `value` | the low 8, 16 or 32 bits are written; the rest is ignored |

No result. Errors as for In, with `TruncatedMessage` for fewer than 2
registers.

Labels `0x77`-`0x7F` are reserved.

### Hypervisor

Present only on Hyper-V with every privilege that `docs/design.md`,
[Detection (M3)](design.md#detection-m3), lists, and with the hypercall page
at `.hvcall`. A restricted capability allows `PostMessage` and `SignalEvent`
on its own connection with the matching right, and nothing else.

#### `0x80` `Hypervisor_PostMessage`

Runs `HvCallPostMessage` (code `0x005C`) with an input block the kernel builds.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `connection` | connection ID, below `2^24` |
| MR1 | `message_type` | 1 to `0x7FFF_FFFF` |
| MR2 | `payload_size` | bytes, at most 240 |
| MR3 onwards | `payload` | `ceil(payload_size / 8)` words; payload byte `i` is byte `i mod 8` (little-endian) of MR`3 + i / 8`; bytes past `payload_size` are ignored |

Result: MR0 the hypervisor's `HV_STATUS` (16 bits; 0 is success; other
values are the TLFS's, such as `HV_STATUS_INSUFFICIENT_BUFFERS`, which the
caller retries).

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 3 registers |
| `InvalidArgument(0)` | `connection` >= `2^24` |
| `InvalidArgument(1)` | `message_type` is 0 or >= `2^31` |
| `InvalidArgument(2)` | `payload_size` > 240 |
| `TruncatedMessage` | fewer than `3 + ceil(payload_size / 8)` registers |
| `IllegalOperation` | restricted capability without `post`, or another connection |

#### `0x81` `Hypervisor_SignalEvent`

Runs `HvCallSignalEvent` (code `0x005D`) as a fast hypercall.

| Register | Name | Meaning |
| --- | --- | --- |
| MR0 | `connection` | connection ID, below `2^24` |
| MR1 | `flag` | event flag number relative to the port's base, below `2^16` |

Result: MR0 the hypervisor's `HV_STATUS`.

| Error | When |
| --- | --- |
| `TruncatedMessage` | fewer than 2 registers |
| `InvalidArgument(0)` | `connection` >= `2^24` |
| `InvalidArgument(1)` | `flag` >= `2^16` |
| `IllegalOperation` | restricted capability without `signal`, or another connection |

#### `0x82` `Hypervisor_Eom`

Writes 0 to the SynIC EOM register (MSR `0x4000_0084`), so the hypervisor
delivers the next queued message. No registers, no result. `IllegalOperation`
on a restricted capability.

#### `0x83` `Hypervisor_VpIndex`

Result: MR0 this processor's VP index (MSR `0x4000_0002`). No registers.
`IllegalOperation` on a restricted capability.

Labels `0x84`-`0x8F` are reserved.

#### Mint data word

`CNode_Mint` of a Hypervisor capability interprets its data word as:

| Bits | Field | Meaning |
| --- | --- | --- |
| 0-23 | `connection` | the only connection the new capability may use |
| 24 | `post` | may `PostMessage` |
| 25 | `signal` | may `SignalEvent` |
| 26-63 | | must be 0 |

- Data 0: the new capability equals the source.
- Unrestricted source, non-zero data: a restricted capability with these
  fields.
- Restricted source, non-zero data whose `connection` equals the source's and
  whose rights are a subset of the source's: the result has the rights given.
- Anything else, including set bits 26-63, fails with `IllegalOperation`, the
  code `CNode_Mint` gives for data that does not fit ([Capability
  data](#capability-data); seL4 `decodeCNodeInvocation`,
  `src/object/cnode.c`, for a capability that `updateCapData` nulls, such
  as an IOSpace).
- A Mint with non-zero data makes an original, as a new badge does, so the
  minter can revoke every copy of the narrowed capability.
- `CNode_Mutate` and `CNode_Rotate` with non-zero data on a Hypervisor
  capability fail with `IllegalOperation`, as seL4 refuses Mutate data for an
  IOSpace (`Arch_updateCapData` with `preserve`).

#### SynIC frames

The frames in initial slots 13 and 14 are the hypervisor's pages for this
processor (TLFS `inter-partition-communication.md`, `hv_message.md`,
`hv_synic_event_flags.md`): RAM, mapped write-back. The kernel never reads or
writes them after boot, and `TCB_SetIPCBuffer` refuses either with
`InvalidCapability`.

Message frame (SIM): 16 slots of 256 bytes; slot `s`, at offset `256 * s`,
holds the message for SINT `s`.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | `MessageType`; 0 means the slot is empty |
| 4 | 1 | `PayloadSize`, at most 240 |
| 5 | 1 | `MessageFlags`; bit 0 `MessagePending` |
| 6 | 2 | reserved |
| 8 | 8 | origination: sender port or partition ID |
| 16 | 240 | payload |

To consume a message: copy it, write 0 to `MessageType`, execute a full
fence (`mfence` or a locked instruction), then read `MessageFlags` again and,
if `MessagePending` is set, invoke `Hypervisor_Eom`. The hypervisor may set
the flag after delivery, so the copy's value is not enough (TLFS
`hv_message.md`; FreeBSD `vmbus_msg_task`).

Event-flag frame (SIEF): 16 slots of 256 bytes; flag `n` of SINT `s` is bit
`n mod 8` of byte `256 * s + n / 8`. Clear flags with a locked instruction
(`lock and` or `lock cmpxchg`).

### BootInfo fields for interrupts and Hyper-V

[Initial CSpace](#initial-cspace) and [BootInfo](#bootinfo) give the whole
layout; these are the slots and fields that interrupts, I/O ports and
Hyper-V fill, under the same names.

| Item | Where | Meaning | Milestone |
| --- | --- | --- | --- |
| `CAP_IRQ_CONTROL` | initial slot 4 | IRQControl | M4 (invocations M7) |
| `CAP_IO_PORT_CONTROL` | initial slot 7 | IOPortControl | M4 |
| `CAP_HYPERVISOR` | initial slot 12 | unrestricted Hypervisor capability; null if not Hyper-V, if an M9 privilege is missing, or if the firmware locked the hypercall MSR outside `.hvcall` | M9 |
| `CAP_SYNIC_MESSAGE_FRAME` | initial slot 13 | 4 KiB Frame for the SIM page; null whenever slot 12 is | M9 |
| `CAP_SYNIC_EVENT_FRAME` | initial slot 14 | 4 KiB Frame for the SIEF page; null whenever slot 12 is | M9 |
| `rsdp` | BootInfo offset 176 | physical address of the RSDP, or 0; for information only, as ACPI memory becomes untyped | M4 |
| `tsc_hz` | BootInfo offset 184 | TSC ticks per second, measured in the timer calibration windows | M3, M4 |
| `interrupts` | BootInfo offset 512, 256 bytes | `InterruptInfo`, below | M4 |

`InterruptInfo`, `#[repr(C)]`, 256 bytes, filled from the ACPI tables at boot;
unused entries and reserved bytes are 0.

| Offset | BootInfo offset | Width | Field | Meaning |
| --- | --- | --- | --- | --- |
| 0 | 512 | 4 | `ecam_count` | entries used in `ecam`, 0 to 4 |
| 4 | 516 | 4 | `ioapic_count` | entries used in `ioapics`, 0 to 4 |
| 8 | 520 | 64 | `ecam` | `[Ecam; 4]`, PCI ECAM ranges from the MCFG |
| 72 | 584 | 32 | `ioapics` | `[IoApicInfo; 4]`, the GSI ranges `GetIOAPIC` accepts |
| 104 | 616 | 128 | `isa_routes` | `[IsaRoute; 16]`, indexed by ISA IRQ: what `GetISA` would program |
| 232 | 744 | 24 | `reserved` | 0 |

`Ecam`, 16 bytes; the kernel drops an MCFG entry whose bus range is reversed
or whose region overflows.

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `base` | physical address of bus 0's configuration space in this segment, as in the MCFG, even when `start_bus` > 0 |
| 8 | 2 | `segment` | PCI segment group |
| 10 | 1 | `start_bus` | first bus decoded |
| 11 | 1 | `end_bus` | last bus decoded |
| 12 | 4 | `reserved` | 0 |

Function `(bus, device, function)` has its 4 KiB of configuration space at
`base + (bus << 20 | device << 15 | function << 12)`, within device untyped.

`IoApicInfo`, 8 bytes, in MADT order:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 4 | `gsi_base` | first GSI this I/O APIC serves |
| 4 | 2 | `pins` | number of pins, the version register's MRE + 1 |
| 6 | 1 | `id` | I/O APIC ID from the MADT |
| 7 | 1 | `reserved` | 0 |

`IsaRoute`, 8 bytes:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 4 | `gsi` | the GSI ISA IRQ `n` routes to |
| 4 | 1 | `flags` | bit 0 level-triggered, bit 1 active low, as `GetISA`'s MR2 |
| 5 | 1 | `routed` | 1 if the IRQ has a route; 0 if its GSI is another IRQ's override target or no I/O APIC serves it (`GetISA` then fails with `InvalidArgument(0)`) |
| 6 | 2 | `reserved` | 0 |

## Boot and the root task

This section gives the root task's initial CSpace, its BootInfo and its state
when it first runs. `docs/design.md`, [Boot](design.md#boot), explains how the
kernel builds them.

### Initial CSpace

The root task's CSpace is one CNode of 2^12 slots (2^17 bytes), and its
capability in slot 2 has guard 0 and guard size 52, so the root task's CPtr
`n` names slot `n` with all 64 bits resolved.

| Slot | Constant | Capability | seL4 slot |
| --- | --- | --- | --- |
| 0 | `CAP_NULL` | null | `seL4_CapNull` |
| 1 | `CAP_INIT_TCB` | the root task's TCB | `seL4_CapInitThreadTCB` |
| 2 | `CAP_INIT_CNODE` | this CNode | `seL4_CapInitThreadCNode` |
| 3 | `CAP_INIT_VSPACE` | the root task's PML4 | `seL4_CapInitThreadVSpace` |
| 4 | `CAP_IRQ_CONTROL` | IRQControl | `seL4_CapIRQControl` |
| 5 | | null (microL4 has no ASID control) | `seL4_CapASIDControl` |
| 6 | | null (no ASID pool) | `seL4_CapInitThreadASIDPool` |
| 7 | `CAP_IO_PORT_CONTROL` | IOPortControl | `seL4_CapIOPortControl` |
| 8 | | null (no IOMMU) | `seL4_CapIOSpace` |
| 9 | `CAP_BOOTINFO_FRAME` | BootInfo's first frame | `seL4_CapBootInfoFrame` |
| 10 | `CAP_INIT_IPC_BUFFER` | the root task's IPC buffer frame | `seL4_CapInitThreadIPCBuffer` |
| 11 | | null (no domains) | `seL4_CapDomain` |
| 12 | `CAP_HYPERVISOR` | the unrestricted Hypervisor capability on Hyper-V from M9; null elsewhere, before M9, when an M9 privilege is missing, and when the firmware locked the hypercall MSR to a page outside `.hvcall` | (`seL4_CapSMMUSIDControl`, Arm) |
| 13 | `CAP_SYNIC_MESSAGE_FRAME` | 4 KiB Frame for the SynIC message page (SIM), a boot-region RAM frame; null when slot 12 is null | (`seL4_CapSMMUCBControl`, Arm) |
| 14 | `CAP_SYNIC_EVENT_FRAME` | 4 KiB Frame for the SynIC event-flag page (SIEF), likewise | (`seL4_CapInitThreadSC`, MCS) |
| 15 | | null, reserved | (`seL4_CapSMC`, Arm) |

`NUM_INITIAL_SLOTS` = 16. From slot 16, in this order, each run named by a
BootInfo slot region:

| Region | Contents | Order |
| --- | --- | --- |
| `extra_bootinfo_frames` | BootInfo's second frame | |
| `user_image_paging` | the root VSpace's PDPT, PD and PT capabilities | by level, PDPT first, then by ascending virtual address (seL4's order) |
| `user_image_frames` | one 4 KiB Frame capability per page of `[user_image_start, user_image_end)` that a `PT_LOAD` segment covers; an uncovered page has none | ascending virtual address; the root task, which knows its own segments, maps index to address |
| `untyped` | Untyped capabilities | the framebuffer's first (`framebuffer_untyped`), then ascending physical address |
| `empty` | null capabilities, to slot 4095 | |

All these capabilities are originals with full rights. The frames, paging
structures and untyped are 4 KiB-page Frame, PDPT, PageDirectory, PageTable
and Untyped capabilities as [Address spaces](#address-spaces) and
[Capabilities](#capabilities) define them; the image, IPC buffer and
BootInfo frames are mapped, the SynIC frames are not. The kernel never reads
or writes the SynIC frames, and `TCB_SetIPCBuffer` refuses them.

### BootInfo

`l4core::bootinfo::BootInfo`, `#[repr(C)]`, 8192 bytes, two 4 KiB frames that
are physically and virtually contiguous, mapped RW and NX at the address in
the root task's `rdi`. Every address in it is virtual unless the field says
physical. Slot regions are `SlotRegion { start: u64, end: u64 }`: slots
`start` to `end - 1`, empty when `start == end`.

| Offset | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `magic` | u64 | `"uL4BINFO"` as a little-endian u64 |
| 8 | `version` | u32 | 1 |
| 12 | `size` | u32 | 8192 |
| 16 | `ipc_buffer` | u64 | the root task's IPC buffer |
| 24 | `root_cnode_bits` | u64 | 12 |
| 32 | `empty` | `SlotRegion` | null slots, free for the root task |
| 48 | `user_image_frames` | `SlotRegion` | image frames |
| 64 | `user_image_paging` | `SlotRegion` | paging structures |
| 80 | `extra_bootinfo_frames` | `SlotRegion` | BootInfo frames after the first |
| 96 | `untyped` | `SlotRegion` | every untyped |
| 112 | `framebuffer_untyped` | `SlotRegion` | the leading part of `untyped` that covers the framebuffer exactly, page-rounded; empty if there is no framebuffer, or if any 2 MiB page it touches is write-back in the direct map (a debug kernel warns) |
| 128 | `user_image_start` | u64 | first byte of the first image page |
| 136 | `user_image_end` | u64 | one past the last image page |
| 144 | `framebuffer` | `Framebuffer` | 32 bytes, the handoff's [layout](#handoff-structure), physical `base`; all zero if there is none |
| 176 | `rsdp` | u64 | physical address of the ACPI RSDP, or 0; for information only: the tables' memory is RAM untyped after boot, and user space never reads ACPI |
| 184 | `tsc_hz` | u64 | TSC ticks per second, measured in M3 in the same window that calibrates the local APIC timer |
| 192 | `hypervisor_vendor` | u32 | 0 none, 1 QEMU TCG, 2 QEMU KVM, 3 Hyper-V, 4 other; the Hypervisor capability itself is slot 12 |
| 196 | `phys_addr_bits` | u32 | the CPU's physical address width; no untyped reaches `2^phys_addr_bits` |
| 200 | `cmdline_len` | u64 | bytes used in `cmdline`, at most 256 |
| 208 | `cmdline` | [u8; 256] | the handoff's command line, copied unchanged |
| 464 | `reserved0` | [u8; 48] | 0 |
| 512 | `interrupts` | `InterruptInfo`, 256 bytes | defined field by field, with offsets, in [BootInfo fields for interrupts and Hyper-V](#bootinfo-fields-for-interrupts-and-hyper-v): the MCFG ECAM ranges and the I/O APIC and ISA override facts user space needs. Unused bytes are 0 |
| 768 | `reserved1` | [u8; 256] | 0 |
| 1024 | `untyped_list` | [`UntypedDesc`; 448] | `untyped_list[i]` describes slot `untyped.start + i`; entries from `untyped.end - untyped.start` on are 0 |

`UntypedDesc`, 16 bytes, seL4's `seL4_UntypedDesc`:

| Offset | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `paddr` | u64 | physical base, aligned to the size |
| 8 | `size_bits` | u8 | size is `2^size_bits` bytes, at least 12 |
| 9 | `is_device` | u8 | 1 for device untyped, 0 for RAM |
| 10 | `padding` | [u8; 6] | 0 |

Limits: at most 448 untyped and 4096 slots; the kernel refuses to boot
rather than exceed either. The root image spans at most 8 MiB
(`user_image_end - user_image_start`), which xtask checks at build time and
the kernel at boot, so the slot plan always fits. xtask strips the root ELF
before embedding it, and the kernel image, root image included, is at most
`KERNEL_IMAGE_MAX` = 16 MiB.

### Root-task entry state

| Item | Value |
| --- | --- |
| `rip` | the root ELF's entry point |
| `rdi` | BootInfo's address, `user_image_end + 0x1000` |
| `rsp` | 0; the root task's `_start` loads a stack of its own |
| `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rbp`, `r8` to `r15` | 0 |
| RFLAGS | `0x202` (IF set) |
| CS, SS | `0x23`, `0x1B` |
| FS base, GS base | 0 |
| x87, SSE | the [initial FP state](#initial-fp-state) |
| State | `Running`, with a full time slice |
| Priority, MCP | 255, 255 |
| CSpace root, VSpace root | slots 2 and 3 |
| IPC buffer | the frame in slot 10, at `user_image_end` (`BootInfo.ipc_buffer`) |
| Fault endpoint | CPtr 0, none: a fault stops the root task ([Fault messages](#fault-messages)) and a debug kernel prints it |

| Root virtual range | Content | Mapping |
| --- | --- | --- |
| `[user_image_start, user_image_end)` | the root ELF's `PT_LOAD` segments, file bytes then zeros; a page no segment covers is unmapped | per segment: RX, R or RW; NX unless executable |
| `[user_image_end, user_image_end + 0x1000)` | IPC buffer, one page | RW, NX |
| `[user_image_end + 0x1000, user_image_end + 0x3000)` | BootInfo, two pages | RW, NX |

The kernel requires every segment to be page-separated, not both writable
and executable, and inside `[USER_MIN, USER_TOP - 0x3000)`, the span to be
at most 8 MiB, and the entry point to lie in an executable segment. Nothing
else is mapped.

## Debug system calls

Present only in kernels built with the `debug` feature (`docs/design.md`,
[Debug](design.md#debug)). Without it, each of these numbers raises an
`UnknownSyscall` fault like any unknown number. None takes a capability;
`rdi` is a plain value.

| `rdx` | Name | `rdi` in | Effect | Registers out |
| --- | --- | --- | --- | --- |
| 16 | `DebugPutChar` | byte in bits 0 to 7; other bits ignored | writes the byte to COM1, `\n` as `\r\n` | all preserved except `rcx`, `r11` |
| 17 | `DebugHalt` | status | prints `DEBUG HALT <status> from TCB <address>`, then ends the run: under QEMU through `isa-debug-exit`, success for status 0 and failure otherwise; elsewhere the machine halts | does not return |
| 18 | `DebugDumpScheduler` | ignored | prints one line per TCB: kernel address, state, priority, the address it resumes at, and `*` for the caller | all preserved except `rcx`, `r11` |
| 19 to 31 | reserved | | `UnknownSyscall` fault | |

## Boot handoff (loader to kernel)

The UEFI loader enters the kernel with one `Handoff` structure. This is boot
ABI version 1, `l4core::handoff`, unchanged since M0, when `docs/boot.md`
specified it: every field and offset below is in code, and compile-time
asserts in `core/src/handoff.rs` pin them on both targets. Changing it needs
an ADR and a new `HANDOFF_VERSION`. The handoff never reaches user space; the
root task gets [BootInfo](#bootinfo). `docs/boot.md` describes the loader
that builds it.

### State at kernel entry

| Item | State |
| --- | --- |
| Mode | 64-bit long mode, CPL 0, the firmware's GDT and code segment |
| Interrupts | off (`IF = 0`); the firmware's IDT is still loaded |
| `rdi` | physical address of the `Handoff`, 8-byte aligned |
| `rsp` | the firmware's stack; the kernel switches away at once |
| CR3 | the loader's page tables |
| EFER.NXE | set if CPUID reports NX, otherwise clear and no NX bits are used |
| CR0.WP | set by the loader, so ring 0 honours read-only pages |
| CR4.LA57 | clear; the loader refuses to run under 5-level paging |
| CR4.PGE, SMEP, SMAP, PAT | as the firmware left them; M3 sets them |
| MTRRs | as the firmware left them; the kernel never changes them |
| 8259 PIC, local APIC timer | as the firmware left them; M3 masks them before enabling interrupts |
| Direction flag, SSE state, other registers | unspecified |
| Physical placement | every loader allocation (the kernel image, its page tables, the handoff, the memory map) lies below 64 GiB, the end of the kernel's direct map; M3 panics otherwise. M0's loader used 512 GiB; M3 lowers it |

The firmware's IDT and stack, and on some firmware its GDT, live in
boot-services memory, which the memory map reports as `USABLE`. EDK2-derived
firmware such as OVMF puts its GDT in runtime-services data, reported as
`FIRMWARE`. Either way the kernel must load its own GDT and IDT (M3) before it
reuses any `USABLE` memory (M4). Until then an NMI lands in the firmware's IDT.

### Address space at entry

| Virtual range | Maps | Page size | Permissions |
| --- | --- | --- | --- |
| `0` to `phys_map_size` | physical memory 1:1 | 2 MiB | RW, executable |
| `PHYS_MAP_BASE` (`0xFFFF_8000_0000_0000`) + `[0, phys_map_size)` | physical memory (the direct map) | 2 MiB | RW, NX if the CPU has NX |
| `KERNEL_VIRT_BASE` (`0xFFFF_FFFF_8000_0000`) to the image end | the kernel image, contiguous | 4 KiB | from each segment: `.text` RX, `.rodata` R, `.data`/`.bss` RW; the last two NX if the CPU has NX |

`phys_map_size` is the end of the highest range in the UEFI memory map that is
not `RESERVED` or `MMIO`, at least 4 GiB so that low MMIO (local APIC, I/O
APIC, HPET, framebuffer) is covered, rounded up to 1 GiB, and at most 512 GiB
(one PML4 slot). Reserved and MMIO ranges do not raise it: QEMU's q35 reports
a reserved range just below 1 TiB. Everything is mapped write-back through
PAT entry 0; the firmware's MTRRs keep MMIO uncached. The 1:1 map exists only
so the loader survives its own CR3 write; it and the direct map alias the
kernel image with weaker permissions until the kernel replaces these tables
in M3. The kernel's own direct map maps the 2 MiB regions covering the image
with 4 KiB pages, text and read-only data read-only and everything NX, so from
M3 no alias of the image is weaker than its own mapping (`docs/design.md`,
[Privilege levels](design.md#privilege-levels)).

### Handoff structure

`l4core::handoff::Handoff`, `#[repr(C)]`, 360 bytes. Every address in it is
physical.

| Offset | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `magic` | u64 | `"uL4BOOT\0"` as a little-endian u64 |
| 8 | `version` | u32 | 1 |
| 12 | `size` | u32 | 360, `size_of::<Handoff>()` |
| 16 | `kernel_phys_base` | u64 | first byte of the kernel image, page-aligned |
| 24 | `kernel_size` | u64 | bytes the image occupies, a multiple of 4 KiB |
| 32 | `phys_map_size` | u64 | bytes covered by the direct map and the 1:1 map |
| 40 | `memory_map` | u64 | address of the `MemoryRegion` array, 8-byte aligned |
| 48 | `memory_map_len` | u64 | number of entries |
| 56 | `rsdp` | u64 | ACPI RSDP, or 0 |
| 64 | `framebuffer` | `Framebuffer` | 32 bytes, below; all zero if there is none |
| 96 | `cmdline_len` | u64 | bytes used in `cmdline`, at most 256 |
| 104 | `cmdline` | [u8; 256] | the command-line bytes, not NUL-terminated and not checked; `Handoff::cmdline` reads invalid UTF-8 as empty |

`Framebuffer`, 32 bytes:

| Offset | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `base` | u64 | physical address of the first pixel, or 0 if there is none |
| 8 | `size` | u64 | bytes |
| 16 | `width` | u32 | pixels |
| 20 | `height` | u32 | pixels |
| 24 | `stride` | u32 | pixels per scan line, which may exceed `width` |
| 28 | `format` | u32 | 1 RGB (byte 0 red), 2 BGR (byte 0 blue), 0 none |

The loader passes no framebuffer for bitmask and BLT-only GOP modes.

`Handoff::validate` checks the magic, version, size, command-line length, and
that the memory-map array is aligned and inside the direct map. The kernel
calls it before using anything else in the handoff, and `arch::memory_map`
calls it again, so safe code cannot build a slice from an unchecked handoff.

### Memory map

An array of `MemoryRegion`, 24 bytes each, sorted by `base`, with empty
entries dropped and touching entries of the same kind merged. UEFI guarantees
its descriptors do not overlap; the loader does not check.

| Offset | Field | Type |
| --- | --- | --- |
| 0 | `base` | u64 |
| 8 | `len` | u64 |
| 16 | `kind` | u32 |
| 20 | `reserved` | u32, 0 |

| `kind` | Name | UEFI memory types | Meaning for the kernel |
| --- | --- | --- | --- |
| 1 | `USABLE` | Conventional, BootServicesCode, BootServicesData | free RAM, once the kernel has its own GDT and IDT |
| 2 | `RESERVED` | Reserved, Persistent, PalCode, Unaccepted, vendor types | never touch |
| 3 | `ACPI_RECLAIMABLE` | ACPIReclaimMemory | ACPI tables; free after parsing |
| 4 | `ACPI_NVS` | ACPIMemoryNVS | never touch |
| 5 | `MMIO` | MemoryMappedIO, MemoryMappedIOPortSpace | device memory the firmware chose to list |
| 6 | `LOADER` | LoaderCode, LoaderData | the kernel image, the page tables, the handoff, the memory map and the loader; the kernel decides what to keep |
| 7 | `FIRMWARE` | RuntimeServicesCode, RuntimeServicesData | UEFI runtime services; never touch |
| 8 | `BAD` | UnusableMemory | never touch |

Kinds are a transparent `u32`, not a Rust enum, so an unknown value read from
memory is not undefined behaviour. "Never touch" is about the kernel's own
accesses; which ranges become untyped for user space is in `docs/design.md`,
[Boot](design.md#boot).

## Invocation label index

One global numbering, grouped by object type; label 0 is invalid. A label
marked with a milestone returns `IllegalOperation` until that milestone. A label
outside the invoked capability's own rows returns `IllegalOperation`.
Endpoints and notifications have no labels: their `label` is user data.

| Label | Invocation | Label | Invocation |
| --- | --- | --- | --- |
| `0x01` | `Untyped_Retype` | `0x40` | `PDPT_Map` |
| `0x10` | `CNode_Revoke` | `0x41` | `PDPT_Unmap` |
| `0x11` | `CNode_Delete` | `0x42` | `PageDirectory_Map` |
| `0x12` | `CNode_CancelBadgedSends` (M6) | `0x43` | `PageDirectory_Unmap` |
| `0x13` | `CNode_Copy` | `0x44` | `PageTable_Map` |
| `0x14` | `CNode_Mint` | `0x45` | `PageTable_Unmap` |
| `0x15` | `CNode_Move` | `0x50` | `Frame_Map` |
| `0x16` | `CNode_Mutate` | `0x51` | `Frame_Unmap` |
| `0x17` | `CNode_Rotate` | `0x52` | `Frame_Remap` |
| `0x18` | `CNode_SaveCaller` (M6) | `0x53` | `Frame_GetAddress` (M9) |
| `0x20` | `TCB_ReadRegisters` | `0x60` | `IRQControl_GetISA` |
| `0x21` | `TCB_WriteRegisters` | `0x61` | `IRQControl_GetIOAPIC` |
| `0x22` | `TCB_CopyRegisters` | `0x62` | `IRQControl_GetMSI` (M9) |
| `0x23` | `TCB_Configure` | `0x63` | `IRQControl_GetSint` (M9) |
| `0x24` | `TCB_SetPriority` | `0x68` | `IRQHandler_Ack` |
| `0x25` | `TCB_SetMCPriority` | `0x69` | `IRQHandler_SetNotification` |
| `0x26` | `TCB_SetSchedParams` | `0x6A` | `IRQHandler_Clear` |
| `0x27` | `TCB_SetIPCBuffer` | `0x70` | `IOPortControl_Issue` |
| `0x28` | `TCB_SetSpace` | `0x71` to `0x73` | `IOPort_In8`, `IOPort_In16`, `IOPort_In32` |
| `0x29` | `TCB_Suspend` | `0x74` to `0x76` | `IOPort_Out8`, `IOPort_Out16`, `IOPort_Out32` |
| `0x2A` | `TCB_Resume` | `0x80` | `Hypervisor_PostMessage` (M9) |
| `0x2B` | `TCB_BindNotification` (M6) | `0x81` | `Hypervisor_SignalEvent` (M9) |
| `0x2C` | `TCB_UnbindNotification` (M6) | `0x82` | `Hypervisor_Eom` (M9) |
| `0x2D` | `TCB_SetTLSBase` | `0x83` | `Hypervisor_VpIndex` (M9) |

Reserved: `0x02` to `0x0F` (Untyped), `0x19` to `0x1F` (CNode), `0x2E` to
`0x3F` (TCB), `0x46` to `0x4F` (paging structures; a PML4 has no
invocations), `0x54` to `0x5F` (Frame), `0x64` to `0x67` (IRQControl),
`0x6B` to `0x6F` (IRQHandler), `0x77` to `0x7F` (I/O ports), `0x84` to
`0x8F` (Hypervisor), `0x90` and up (unassigned).
