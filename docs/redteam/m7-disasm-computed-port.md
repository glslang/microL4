# M7 red team: the release kernel's disassembly check misses a computed port

**Severity:** low. Nothing an attacker in ring 3 can use; the check guards
against a kernel developer's mistake, and this is a way the mistake gets
through. A release kernel with UART code passes it and writes on COM1,
which `docs/design.md` ("A release kernel without UART code") and ADR 0021
say it cannot.

**Where:** `xtask/src/disasm.rs`, `scan`.

**Status:** open; not fixed, as the brief asks.

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

- `a_computed_com1_port_passes_the_check` passes today: `scan` finds
  nothing.
- `a_computed_com1_port_fails_the_check` states the guarantee and fails
  today; it is `#[ignore]`d. Run it with `cargo test -p xtask -- --ignored`.

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
