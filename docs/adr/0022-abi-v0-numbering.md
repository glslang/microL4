# 0022: The ABI keeps seL4's x86_64 registers and layouts, with its own numbers

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md asks for a syscall ABI "close to seL4's x86_64 register use", written
down in `docs/abi.md`, and an API shaped like seL4's but not seL4-compatible.
M1 had six areas designed in parallel, so the parts every area shares had to
be fixed first: registers, system call numbers, `MessageInfo`, the IPC
buffer, capability pointers, error codes, object type numbers and invocation
labels.

## Decision

- **Registers:** seL4's x86_64 use. `rdx` holds the system call number,
  `rdi` the capability pointer or the received badge, `rsi` the
  `MessageInfo`, and `r10`, `r8`, `r9`, `r15` the message registers MR0 to
  MR3. `rcx` and `r11` are lost to `syscall`; every other register is
  preserved.
- **`MessageInfo` and the IPC buffer:** seL4's 64-bit layouts, unchanged:
  label 52 bits, `caps_unwrapped` 3, `extra_caps` 2, `length` 7; a
  1024-byte buffer of 120 message words, user data, three capability or
  badge words and the receive slot.
- **Error codes:** seL4's 0 to 10.
- **System call numbers:** positive, 1 to 8 for `Call`, `ReplyRecv`, `Send`,
  `NBSend`, `Recv`, `Reply`, `Yield`, `NBRecv`, in seL4's order; 16 to 31 for
  debug calls; 0 is invalid. seL4 numbers them −1 to −8.
- **Object type numbers:** 0 Untyped, 1 TCB, 2 Endpoint, 3 Notification,
  4 CNode, 5 and 6 Frames, 7 to 10 the paging levels from PageTable to PML4.
  seL4 interleaves architecture types after its generic ones.
- **Invocation labels:** one global numbering in ranges of 16 per object
  type, two for TCB (`0x01` Untyped, `0x10` CNode, `0x20` TCB, `0x40`
  paging, `0x50` Frame, `0x60` IRQ, `0x70` I/O ports, `0x80` Hypervisor), so
  a type can gain methods without renumbering another. seL4 generates one dense enumeration
  from its XML interface files.

## Consequences

- seL4's libsel4 and its tools cannot be reused unchanged; `libsys` (M5) is
  written against `docs/abi.md`. Wrong numbers fail loudly rather than
  invoking a neighbouring method.
- Anyone who knows seL4's x86_64 ABI can read microL4's registers, messages
  and errors without a translation table.
- Adding a method to a type uses a free label in its range; a type that
  needs more than its range takes one of the reserved ranges from `0x90`.
