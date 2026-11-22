# M7 red team: the release kernel's disassembly check misses a computed port

**Severity:** low. Nothing an attacker in ring 3 can use; the check guards
against a kernel developer's mistake, and this is a way the mistake gets
through. A release kernel with UART code passes it and writes on COM1,
which `docs/design.md` ("A release kernel without UART code") and ADR 0021
say it cannot.

**Where:** `xtask/src/disasm.rs`, `scan`.

**Status:** fixed in the M7 fix round, commit `6f5d6ea` ("disasm: io.rs is
reached only from its three callers"; [The fix](#the-fix)); the path
through the IOPort executor that its re-check found, in fix round 2
([The executor gap, and its fix](#the-executor-gap-and-its-fix)).

## What breaks

The check fails a release kernel for an `in` or `out` outside io.rs's
functions, an immediate `0x3F8`-`0x3FF` moved into `dx`, `edx` or `rdx`, a
call to io.rs whose `di`/`edi`/`rdi` the straight-line code before it set to
such an immediate, and a `serial` symbol. A UART driver written the usual
way, with its base in a struct or a static and a register offset added,
names none of these: the port reaches `edi` from another register.

For the test the red team added this to `kernel/src/arch/x86_64/mod.rs`,
called once after `pic::init` in every build, then removed it:

```rust
static REDTEAM_BASE: AtomicU16 = AtomicU16::new(0x3F8);

#[inline(never)]
fn redteam_uart(text: &[u8]) {
    let base = core::hint::black_box(REDTEAM_BASE.load(Ordering::Relaxed));
    for &b in text {
        while unsafe { io::inb(base + 5) } & 0x20 == 0 {}
        unsafe { io::outb(base, b) };
    }
}
```

`cargo xtask test release` then printed `disassembly: ... no COM1 port in dx
or passed to them, no serial symbol`, the `release` scenario passed, and its
`serial.log` held `[redteam: a release kernel wrote this]` from the kernel.
Without `black_box`, LLVM folded the never-written static to `0x3F8` and the
check caught both calls; a base read from memory the compiler cannot see
(a `read_volatile`, a field filled at boot, the ACPI SPCR table) escapes it
the same way, and so would a loop over a port table, a function pointer to
`outb`, or `lea edi, [rax + 0x3f8]`.

## The test

`xtask/src/disasm.rs`, the listing llvm-objdump gave of that function:

- `a_computed_com1_port_passes_the_check` passed before the fix: `scan`
  found nothing. The fix round removed it.
- `a_computed_com1_port_fails_the_check` states the guarantee; it failed
  before the fix and was `#[ignore]`d. It passes now, no longer ignored, and
  asserts the two findings: both calls come from a function that may not
  call `io.rs`, while the port rules alone still find nothing.

How sure: certain; the kernel was built and booted.

## Proposed fix

The release kernel calls io.rs from three places only (the IOPort
invocations, `pic::init`, `arch::exit`), and the design already says so.
Check that instead of the port values: fail on any call or jump to io.rs's
functions from a function other than an allow-list (the IOPort arm of
`Objects`, `pic::init`, `arch::exit`, and whatever inlines them, which the
symbol of the enclosing function names), and on any reference to io.rs's
addresses other than a direct call (a function pointer). Keep the
immediate rules as a second line. A runtime check helps too: the `release`
scenario could set COM1's scratch register and LCR to known values before
the kernel boots, or `forbid:` any byte before the loader's banner is
replaced by uart's, but neither proves the code is absent, which only the
call-site rule does.

## The fix

M7 fix round, in `xtask/src/disasm.rs` and the kernel:

- The check fails on a call or jump to one of `io.rs`'s functions from any
  function but `IO_CALLERS`: `Objects`' `IoPorts::port_in` and `port_out`
  (the IOPort executor), `pic::init` and `arch::exit`, each now
  `#[inline(never)]` so that its symbol bounds its code.
- It fails on an address inside `io.rs`'s functions anywhere but as a
  direct call's or jump's target: in any other instruction (sign-extended
  immediates and displacements, `movabs`, the target of a rip-relative
  operand) and as eight bytes anywhere in the kernel's data sections but
  `.rootimage`, which is where a function pointer would sit.
- It insists on calls from those callers and on data to scan, beside the
  old sanity checks; the port rules stay as a second line.
- Shown on real release kernels: the red team's writer above failed with
  "io.rs's function called from a function that may not call it" for both
  calls, a writer through a function pointer in a static failed on the
  pointer's address in `.rodata` (or, folded by LLVM, in its code), and
  reviewer U's writer (a run-time port, in a module not named `serial`)
  failed the same way.
- `docs/design.md` ("A release kernel without UART code") and ADR 0021's M7
  status state the rule.

## The executor gap, and its fix

The fix round's re-check found a path the call-site rule left open: the
IOPort executor, `Objects`' `IoPorts::port_in` and `port_out`, may call
`io.rs`, and they were safe trait methods that took any port, with nothing
checking who called them. A writer in a new kernel module, with no
`unsafe`, that called `Objects::begin().port_out(0x3F8, Width::Byte, b)`
after `arch::init` passed the check and wrote on COM1 from a release kernel;
only `release`'s `next:` failed it, because it printed at boot.
`port_out`'s SAFETY comment ("`l4core::ioport` checked the capability")
rested on every caller of a safe public method. The listing of that writer
is `EXECUTOR_LISTING` in `xtask/src/disasm.rs`.

Fixed in M7 fix round 2, two ways:

- **It does not compile.** The executor takes an
  `l4core::ioport::PortAccess`, the port and width `invoke_port` checked,
  whose fields and constructor are private to `l4core::ioport`: only
  `invoke_port` builds one, after checking them against the invoked IOPort
  capability's range. Kernel code outside `l4core` cannot build one, so a
  call with a port of its own choosing is a compile error; two
  `compile_fail` doctests on `PortAccess` (E0451 for the fields, E0624 for
  the constructor) keep it so. The SAFETY comments of `port_in` and
  `port_out` rest on the token.
- **The check finds it.** The token proves only what `invoke_port` read
  through its kernel's `load`: a kernel type of its own, whose `load`
  returns a capability for COM1 that no slot holds, could run `invoke_port`
  and pass the token on to `Objects`. So the check now also fails on a call
  or jump to the executor (`disasm::EXECUTOR`) from any function but
  `disasm::EXECUTOR_CALLERS`, exactly
  `l4core::ioport::invoke_port::<kernel::arch::x86_64::objects::Objects>`
  (`#[inline(never)]` now, so its symbol bounds its calls), and on the
  executor's addresses anywhere but as such a call's target, in code or in
  data; it insists on at least one executor call from `invoke_port`.
  `a_writer_through_the_ioport_executor_fails_the_check`, the `#[ignore]`d
  guarantee, passes now, and `..._fails_only_the_executor_rule`, the
  re-check's "passes" test turned round, asserts that both of the writer's
  calls are executor findings and that `io.rs`'s rules alone still find
  nothing. Further tests cover the allowed caller, with LLVM's suffix, nine
  names that are not it (`invoke_port` for another type, generic-less,
  a closure or `.specialized` clone of it, `invoke::invoke`,
  `invoke_control`, `pic::init`, `arch::exit`, another type's
  `IoPorts::port_out`), jumps inside and across the executor, and its
  address in operands and in `.rodata`. A clean release kernel's listing
  shows two executor calls, both from `invoke_port::<Objects>`.

What neither rules out is kernel code that forges a capability in a real
slot, which breaks every capability guarantee at once, not just this one; a
reviewer reads `invoke_port`'s callers (`l4core::invoke::invoke`) as for any
capability check.
