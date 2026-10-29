# L4 microkernel in Rust — project plan

> Exported from the [project plan doc](https://claude.ai/artifact/S11FB8azxQvMQtK36sCV3g) on 2026-10-29. The doc is the source of truth; re-export it here when it changes. The three diagrams in the doc are not exported.

2026-10-29 · Goncalo

## Goal and scope

The goal is a small L4-family microkernel, written from scratch in Rust, that boots on QEMU's x86_64 `q35` machine in every cloud session, and as a Hyper-V Generation 2 guest on your machine. It ends with a terminal emulator, a TUI app and a UDP echo service, all running as user-level processes.

**What runs in the kernel:** capabilities over untyped memory, threads, address spaces, synchronous IPC endpoints, notifications, and interrupts delivered as notifications. It runs on a single core. The API is shaped like seL4's so every design choice has a reference to compare against, but it is not seL4-compatible.

**What runs in user space:** everything else. That covers the serial, framebuffer and network drivers, a console server, the terminal emulator and the apps. The network driver is virtio-net on QEMU and the VMBus synthetic network adapter (netvsc) on Hyper-V, because a Generation 2 VM has no PCI devices for virtio.

**The end-state demo:**

1. A UEFI loader starts the kernel, which starts the root task.
2. The root task starts the driver and console servers.
3. The terminal emulator draws onto the UEFI GOP framebuffer.
4. A TUI app runs inside the terminal emulator.
5. UDP packets sent to the guest come back echoed: through a forwarded port on QEMU, and across the virtual switch on Hyper-V.

**Non-goals:** formal verification, POSIX or Linux compatibility, real hardware, matching seL4's performance, and binary compatibility with seL4.

**Stretch goals:** multi-core support, Hyper-V's synthetic keyboard and video over VMBus, booting under your own type-1 hypervisor, and an aarch64 port.

## How sessions should spend tokens

Credits should go on design, code, tests and review. Builds and QEMU boots should be short, timed checks. Cloud sessions start fresh each time, so `STATUS.md` in the repo is the only memory between them.

**Spend tokens on:**

- **A design note before code** for every subsystem, in `docs/`. A fresh subagent then reviews it against the seL4 manual or the matching seL4 source file.
- **Parallel subagents** for independent pieces, such as two drivers, the model tests and the docs. Each works in its own git worktree.
- **A fresh reviewer at the end of every milestone.** It should not have seen the code being written. Fix what it finds before ticking the milestone off.
- **Host-side tests over in-QEMU tests.** The capability and IPC logic lives in a `no_std` core crate that also runs under `cargo test` on Linux. Those tests are slow to write but fast to run.
- **Red-team agents with narrow briefs**, each told to break one guarantee and to prove it with a user-space test.

**Do not spend tokens on:**

- **Long QEMU runs or waiting on CI.** Every boot in a test has a 60-second timeout and checks serial output for marker lines.
- **Reading whole upstream trees.** Read the one seL4 file you are comparing against, not the repo.
- **Reinstalling toolchains by hand.** Put setup in `tools/setup.sh` and run it once per session.
- **Pulling in crates for the parts that are the point.** Capabilities, IPC, the scheduler, page tables, virtio and the terminal parser are written here. Small helpers such as `bitflags` are fine, and `smoltcp` is fine for optional TCP.

## Environment setup

I tested this on 29 Oct 2026 on the cloud image: Ubuntu 24.04, 2 vCPUs, 7 GB RAM and no `/dev/kvm`. A Rust UEFI image booted from a GPT disk under QEMU's UEFI firmware (OVMF) in about 2 seconds, printed on COM1 from ring 0, and the same disk converted to VHDX for Hyper-V. `rustup target add` fails because the proxy blocks `static.rust-lang.org`, so `build-std` uses Rust source fetched from GitHub instead.

| Check | Result |
| --- | --- |
| `apt-get install qemu-system-x86 ovmf qemu-utils mtools dosfstools gdisk` | Works; QEMU 8.2.2 |
| `rustup target add x86_64-unknown-uefi` | Fails: proxy returns 403 for `static.rust-lang.org` |
| `build-std` with library source cloned from GitHub | Works; release build of a UEFI app, including `core`, in 19 s |
| Boot a GPT disk with an EFI system partition on `-machine q35` under OVMF | Prints on COM1 from ring 0 in about 2 s; `isa-debug-exit` ends QEMU with a chosen status |
| `qemu-img convert -O vhdx` of the same disk | Works; not yet booted on Hyper-V |
| QEMU's Hyper-V enlightenment flags (`hv-relaxed` and others) under TCG | Did not boot in my test |
| An emulated Hyper-V network adapter in QEMU | None: QEMU has a VMBus bridge but no netvsc device |
| `virtio-net-pci` | Available |
| KVM | Not available; everything runs under TCG emulation |

The last three rows mean Hyper-V-specific code can be written and unit-tested in the cloud, but only runs for real on your machine.

**`tools/setup.sh`**, run once at the start of every session. Cloud sessions run as root, so there is no `sudo`.

```sh
#!/usr/bin/env bash
set -euo pipefail
apt-get install -y -qq qemu-system-x86 ovmf qemu-utils mtools dosfstools gdisk gdb

# rustup cannot reach static.rust-lang.org from the cloud box.
# Fetch the library source for the installed rustc from GitHub and use build-std.
V=$(rustc --version | awk '{print $2}')
SRC="$(rustc --print sysroot)/lib/rustlib/src/rust"
if [ ! -e "$SRC/library/Cargo.lock" ]; then
  git clone -q --depth 1 --filter=blob:none --sparse --branch "$V" \
    https://github.com/rust-lang/rust "$HOME/.cache/rust-src-$V"
  git -C "$HOME/.cache/rust-src-$V" sparse-checkout set library
  mkdir -p "$SRC" && ln -sfn "$HOME/.cache/rust-src-$V/library" "$SRC/library"
fi
```

**`.cargo/config.toml`** for the loader, kernel and user crates. `xtask` sets `RUSTC_BOOTSTRAP=1` on every build, because `build-std` is otherwise nightly-only. If you can allow `static.rust-lang.org` in the cloud environment's network settings, a pinned nightly is cleaner.

```toml
[unstable]
build-std = ["core", "alloc", "compiler_builtins"]
build-std-features = ["compiler-builtins-mem"]
```

**The disk image**, which `cargo xtask image` builds. The `-o` matters: without it, `sgdisk` wrote no partition table to the blank file and the image did not boot.

```sh
truncate -s 64M disk.img
sgdisk -o -n 1:2048:0 -t 1:ef00 -c 1:ESP disk.img
truncate -s $((128991 * 512)) esp.img      # the partition's size, from sgdisk -i 1
mkfs.fat -F 32 -n ESP esp.img
mmd -i esp.img ::/EFI ::/EFI/BOOT
mcopy -i esp.img loader.efi ::/EFI/BOOT/BOOTX64.EFI
mcopy -i esp.img kernel.elf ::/kernel.elf
dd if=esp.img of=disk.img bs=512 seek=2048 conv=notrunc
qemu-img convert -f raw -O vhdx -o subformat=dynamic disk.img disk.vhdx
```

**Base QEMU command.** Later milestones add `virtio-net-pci` (M9), a QEMU monitor for `screendump` (M8), and `-s -S` for GDB.

```sh
qemu-system-x86_64 -machine q35 -m 256M -nographic \
  -bios /usr/share/ovmf/OVMF.fd -drive format=raw,file=disk.img \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

**The Hyper-V VM on your machine**, created once and then pointed at each new VHDX. The VM is off after `New-VM`, which Secure Boot changes require.

```powershell
New-VM -Name l4 -Generation 2 -MemoryStartupBytes 512MB -VHDPath .\disk.vhdx -SwitchName "Default Switch"
Set-VMFirmware -VMName l4 -EnableSecureBoot Off
Set-VMComPort -VMName l4 -Number 1 -Path \\.\pipe\l4-com1
Start-VM l4
```

**The two platforms.** M0 and M3 confirm the Hyper-V column on your host.

| Item | QEMU `q35` with OVMF | Hyper-V Generation 2 |
| --- | --- | --- |
| Firmware | UEFI | UEFI, with Secure Boot off |
| Serial | COM1 at I/O port `0x3F8`, IRQ 4 | COM1 at `0x3F8`, once `Set-VMComPort` maps it to a named pipe |
| Display | GOP framebuffer | GOP framebuffer |
| Interrupt controller | Local APIC and I/O APIC, from the ACPI MADT | Same |
| Timer calibration | HPET | Hyper-V reference counter, MSR `0x40000020` |
| PCI | Yes, through ECAM from the ACPI MCFG table | No PCI devices |
| Network | `virtio-net-pci` | VMBus synthetic adapter (netvsc) |
| Keyboard input | Serial | Serial; the synthetic keyboard over VMBus is a stretch goal |
| Ending a test | `isa-debug-exit` at I/O port `0xF4` | Halt, then stop the VM |
| Hypervisor CPUID signature | `TCGTCGTCGTCG` (seen in my test) | `Microsoft Hv` |

## Proposed architecture

The kernel follows seL4's classic, non-MCS design. All authority is a capability, the kernel allocates nothing after boot, and user space owns every policy. M1 either confirms each row below or replaces it, recording the choice in an ADR.

*[Diagram in the original plan: end-state architecture · 9 user processes, 4 kernel subsystems, 4 devices]*

Arrows are IPC calls. `term` also takes keyboard input from `uart`, and each driver gets only its own device's registers or I/O ports.

| Area | Proposal | seL4 reference point |
| --- | --- | --- |
| Privilege levels | Kernel in ring 0, mapped in the upper half of every address space. User code in ring 3. SMEP and SMAP on from the start. | Same split on x86_64. |
| Boot | A small UEFI loader (`x86_64-unknown-uefi`) collects the memory map, the GOP framebuffer and the ACPI tables, loads the kernel ELF, exits boot services and jumps to the kernel. The kernel builds the root task from the embedded image and passes it a BootInfo page. | seL4 boots through multiboot; root server plus `seL4_BootInfo`. |
| Kernel objects | Untyped, CNode, TCB, Endpoint, Notification, Frame (4 KiB and 2 MiB), PageTable at all four levels, VSpace (PML4), IRQControl, IRQHandler, IOPortControl, IOPort. | Same set, including I/O port capabilities, minus ASID pools. |
| Memory | Retyping untyped memory is the only allocator. Revoking an untyped capability reclaims everything made from it. | Same model. |
| Capability addressing | CNodes of 2^n slots with guards, looked up by a capability pointer. At most two levels to start. | Guarded radix tree of CNodes. |
| Derivation tracking | A derivation-ordered list with depths, so revoke can find every descendant. Built and model-tested in `core/` first. | The mapping database (MDB). |
| IPC | Synchronous endpoints with Send, Recv, Call, Reply and ReplyRecv. The reply capability lives in the caller's TCB. Register message words, plus an IPC buffer page for longer messages and one transferred capability per message. | Classic reply caps, not MCS reply objects. |
| Notifications | A badge word that signals OR into. A notification can be bound to a TCB so a server waits on IPC and interrupts together. | Same, including bound notifications. |
| Scheduling | 256 fixed priorities, round-robin within a priority, and a 10 ms timeslice from the local APIC timer. The timer is calibrated against the HPET on QEMU and against Hyper-V's reference counter on Hyper-V. | Classic scheduler; MCS budgets are a stretch goal. |
| Interrupts | Local APIC and I/O APIC, found through the ACPI MADT. IRQControl issues IRQHandler capabilities, and interrupts arrive as notification signals that the driver acknowledges. MSI comes later, for virtio-net. | Same pattern, including I/O APIC and MSI routing. |
| Hyper-V interface | Hypercalls and the synthetic interrupt controller (SynIC) need ring 0. A Hypervisor capability lets the VMBus server post messages and signal events, and SynIC messages arrive as notification signals. The kernel finds Hyper-V through CPUID leaf `0x40000000` ("Microsoft Hv"). | No seL4 equivalent; this is new design work for M1. |
| FP and SIMD | Kernel built for `x86_64-unknown-none`, which keeps the compiler off SSE registers. Save and restore user state with XSAVE eagerly on every switch. | seL4 supports lazy and eager switching. |
| Syscall ABI | `syscall` and `sysret`, with `swapgs` on entry. Syscall number, capability pointer, message info and message registers sit in fixed registers, written down in `docs/abi.md`. | Close to seL4's x86_64 register use. |
| Debug | `putchar` to COM1, TCB dump and halt syscalls, compiled in only with a `debug` feature. | Same idea as seL4's debug syscalls. |

**User-space servers:**

- **`root`** reads BootInfo, retypes untyped memory, starts each server, and gives each one only the capabilities it needs.
- **`uart`** drives COM1, a 16550 UART at I/O ports `0x3F8`–`0x3FF`, through an IOPort capability and its IRQ handler. On Hyper-V, COM1 is connected to a named pipe on the host.
- **`console`** multiplexes clients onto the UART and provides line editing.
- **`fb`** takes the GOP framebuffer frames listed in BootInfo and shares them with `term`. There is no mode setting after boot.
- **`term`** holds the VT100/ANSI parser, a screen model and an 8×16 bitmap-font renderer. It gives apps a pty-like pair of endpoints and reads keyboard input from `uart`.
- **`tui`** is the demo app: a monitor of threads and capabilities queried from `root`, or a small editor.
- **`virtio-net`** is the QEMU network driver: PCI enumeration through ECAM, split virtqueues over DMA frames, and a Frame invocation that returns physical addresses.
- **`vmbus`** and **`netvsc`** are the Hyper-V network path. `vmbus` handles SynIC messages, channel offers, GPADLs and ring buffers. `netvsc` speaks NVSP and RNDIS over its channel.
- **`net`** implements ARP, IPv4, ICMP echo and UDP, all written in this repo, over whichever network driver is present.
- **`echo`** is the UDP echo service on port 7.

## Repo layout and tooling

The repo is one Cargo workspace driven by `cargo xtask`. A shared `no_std` core crate is used by both the kernel and a host-side model, so the hardest logic is tested on Linux without QEMU.

```
.
├── CLAUDE.md          rules every session follows; points at PLAN.md and STATUS.md
├── PLAN.md            this plan, exported to Markdown
├── STATUS.md          current milestone, what is done, what is next, open issues
├── docs/
│   ├── design.md      kernel design (M1)
│   ├── abi.md         syscall ABI, message layout, boot handoff, BootInfo
│   ├── adr/           one file per decision: 0001-cnode-layout.md, ...
│   └── redteam/       one file per finding
├── loader/            x86_64-unknown-uefi: memory map, GOP, ACPI, loads kernel.elf
├── core/              no_std: capability types, derivation tree, retype rules, IPC state machine
├── kernel/            no_std, x86_64-unknown-none, ring 0
├── user/
│   ├── libsys/        syscall wrappers, IPC helpers, a small allocator
│   ├── root/          root task: splits untyped memory, starts the servers
│   └── uart/ console/ fb/ term/ tui/ virtio-net/ vmbus/ netvsc/ net/ echo/
├── model/             std: proptest model and differential tests against core/
├── tests/qemu/        boot scenarios and the serial lines each must print
├── tools/hyperv/      PowerShell: create the VM, swap the VHDX, read COM1 from the pipe
└── xtask/             build, image, run, test, gdb
```

**Targets:** the loader builds for `x86_64-unknown-uefi`. The kernel builds for `x86_64-unknown-none`, which keeps the compiler off SSE registers. User crates start on the same target, so nothing uses SSE at first. Whether to move them to a custom target with SSE, which is when XSAVE switching starts to matter, is an M5 decision.

**xtask commands:**

- `cargo xtask build` builds the user crates, packs them into one boot image embedded in the kernel with `include_bytes!`, then builds the kernel and the loader.
- `cargo xtask image` builds the GPT disk with its EFI system partition, and converts it to VHDX for Hyper-V.
- `cargo xtask run` boots the disk under OVMF with COM1 on stdio.
- `cargo xtask test` runs `cargo test` for `core/` and `model/`, then every QEMU scenario. A scenario passes when its expected lines appear in order and the guest prints `TEST PASS` and exits through `isa-debug-exit`. Each boot has a 60-second timeout.
- `cargo xtask gdb` starts QEMU with `-s -S` and attaches GDB.

**CI** runs on `ubuntu-latest`. It installs QEMU and OVMF, runs `cargo xtask test`, `clippy`, `rustfmt` and Miri on `core/`, and uploads the VHDX as a build artifact for your Hyper-V checks.

**`CLAUDE.md` should say:**

- Read `PLAN.md` and `STATUS.md` first.
- Run QEMU only through `xtask`, never by hand.
- Keep `unsafe` inside `kernel/src/arch/`, each block with a `SAFETY:` comment.
- Record any decision that changes `docs/abi.md` as a new ADR.
- Never tick a milestone without a fresh reviewer's sign-off.
- Update `STATUS.md` before ending the session.

## Milestones

There are eleven milestones, M0 to M10, plus stretch goals. Each has a done-when test that a session can run itself. Do not start a milestone until the one before it has passed its fresh review. The exceptions are M2 and M3, which can run in parallel once M1 is done, and M8 and M9, which can run in parallel once M7 is done.

*[Diagram in the original plan: milestone order · 11 milestones, 2 points where sessions can run in parallel]*

Everything else is sequential. Each M10 red-team brief can also run as its own session.

### M0 · Bootstrap and tooling

An empty kernel prints over COM1 under `cargo xtask test` in QEMU, and the same disk boots under Hyper-V on your machine.

- Create the workspace, `xtask`, `tools/setup.sh`, `.cargo/config.toml`, `CLAUDE.md`, `STATUS.md` and `PLAN.md`.
- Write the UEFI loader. It reads the memory map, finds the GOP framebuffer and the ACPI RSDP, loads `kernel.elf` from the EFI system partition, exits boot services and jumps to the kernel with a handoff struct.
- In the kernel, set up the stack and zero BSS. Add a COM1 debug writer, and a panic handler that prints the file and line, then exits through `isa-debug-exit` on QEMU or halts on Hyper-V.
- Write the scenario runner: boot under OVMF, read COM1 with a 60-second timeout, and match the expected lines in order.
- Add `cargo xtask image` and the GitHub Actions workflow that uploads the VHDX.
- Write `tools/hyperv/` from the commands in Environment setup: create the VM, swap in a new VHDX, and read COM1 from the named pipe. Your `agent-sandbox-vm` scripts are a good model for this.

**Done when:** a `hello` scenario and a deliberate-panic scenario both pass, locally and in CI, and the CI-built VHDX prints the same hello over COM1 on your Hyper-V host.

### M1 · Design and ABI

Write `docs/design.md` and `docs/abi.md` v0, which every later milestone codes against.

- Write one design note per row of the architecture table. Each note states its invariants, such as "a capability never outlives its object" and "retype never overlaps a live object".
- Run parallel subagents: one per area writes the note, and a second compares it with the matching chapter of the seL4 manual and lists every divergence with its reason.
- Write an ADR for every row that changes, plus a list of open questions.
- `abi.md` covers syscall numbers, register use, the message-info layout, the IPC buffer layout, the BootInfo layout and the invocation labels for each object type.

**Done when:** a fresh reviewer finds no contradiction between the two documents, and every invariant names the milestone that enforces it.

### M2 · Capability core and model

The capability system exists as tested `no_std` code before the kernel uses it.

- In `core/`: the capability representation (type, object, size, rights, badge, guard), the slot operations (copy, mint, move, mutate, delete, revoke), the derivation list, and untyped retype with its watermark and alignment rules.
- In `model/`: a slow, obviously correct reference model of the same operations built from plain sets and maps.
- Proptest runs random operation sequences against both and compares the visible state after every step. After each step it checks that no capability dangles, revoke removes every descendant, rights only shrink on derivation, retyped objects never overlap, and an untyped with children cannot be retyped.
- Run Miri on `core/`. A `cargo-fuzz` target over the same sequences is optional.

**Done when:** 10,000 random sequences pass, Miri is clean, and a reviewer agent fails to hand-write a sequence that breaks an invariant.

### M3 · Paging and interrupts

The kernel runs on its own page tables, handles exceptions and takes timer interrupts.

- Load the kernel's own GDT, TSS and IDT. The TSS has IST stacks for double faults and NMIs, and every vector saves a full register frame.
- Build 4-level page tables: the kernel in the upper half, a direct map of physical memory, caching through the PAT, and NX, SMEP and SMAP on.
- Decode and print the vector, error code, CR2 and RIP on any unexpected exception.
- Parse ACPI from the RSDP through the XSDT to the MADT, HPET and MCFG tables. Host tests run against tables the loader dumps in debug mode, from QEMU and from your Hyper-V VM.
- Mask the legacy PIC and enable the local APIC. Calibrate its timer against the HPET on QEMU and the reference counter on Hyper-V, then run it at 100 Hz.

**Done when:** scenarios pass for ten timer ticks and for a deliberate page fault that prints the decoded error code and CR2, the ACPI parser's host tests pass, and the timer ticks at the right rate on your Hyper-V host.

### M4 · Kernel objects and BootInfo

The kernel builds the initial capability space and hands all free memory over as untyped.

- Lay out kernel objects in memory and wire `core/` into the kernel.
- Create untyped capabilities for free RAM, device untyped for MMIO, the root CNode, IOPortControl and the BootInfo page.
- Decode invocations for untyped retype and the CNode operations.
- Add in-kernel self-tests behind a feature flag.

**Done when:** a scenario prints the BootInfo summary, and a self-test that retypes, revokes and retypes again gets the same result both times.

### M5 · Threads, address spaces and the root task

User code runs in ring 3 in its own address space, under preemptive scheduling.

- Build the TCB: registers, an XSAVE area, priority, CSpace and VSpace roots, IPC buffer and fault endpoint.
- Add syscall entry and exit through `syscall` and `sysret` with `swapgs`, and the first drop to ring 3 through `iretq`.
- Add page-table objects at all four levels, Frame map and unmap invocations, and TLB flushing with `invlpg`.
- Add the scheduler, a minimal kernel-side ELF loader for `root`, and the `libsys` syscall wrappers.

**Done when:** two ring-3 threads at the same priority interleave their output under preemption, and a user page fault reaches its fault-handler thread, which prints it and kills the faulting thread. Boot the VHDX on Hyper-V once to confirm the same.

### M6 · IPC and notifications

Servers and clients talk through endpoints, and signals and interrupts arrive through notifications.

- Add endpoint queues, Send, Recv, Call, Reply and ReplyRecv, badges, and capability transfer through the IPC buffer.
- Add notifications, bound notifications, and fault delivery as IPC.
- Add the IPC state machine to `core/` and cover it with proptest.
- Time a round trip with the TSC. Under TCG emulation the number shows trends, not real performance.

**Done when:** 1,000 ping-pong round trips complete, and the capability-transfer, badge, and "IPC plus notification on one server" scenarios all pass.

### M7 · User-level drivers and console

The kernel stops touching the UART outside debug builds.

- Add IRQControl and IRQHandler with I/O APIC routing, plus IOPortControl and IOPort capabilities.
- Give `uart` an IOPort capability for `0x3F8`–`0x3FF` and IRQ 4, and make receive and transmit interrupt-driven.
- Write the `console` server with several clients and line editing, and wire it up in `root`.

**Done when:** two clients write interleaved lines through `console`, input typed by the test harness reaches the right client, and the release kernel contains no UART code.

### M8 · Framebuffer, terminal emulator and TUI

A TUI app runs inside a terminal emulator that draws to a framebuffer.

- In the `fb` server, take the GOP framebuffer frames listed in BootInfo. First confirm that QEMU's monitor `screendump` captures OVMF's framebuffer with `-display none`.
- Add an 8×16 bitmap font, either one with a permissive licence or drawn as data in the repo.
- Write the VT100/ANSI parser following Paul Williams' DEC state machine. Then write the screen model: cursor, attributes, scroll regions, the alternate screen and erase operations.
- Add a renderer with damage tracking, pty-like endpoints, keyboard input from `uart`, and the `tui` app.
- The parser and screen model run as host tests: escape-sequence fixtures go in, and screen text and attributes are compared with golden files. Writing hundreds of these cases is a good place to spend tokens.

**Done when:** the golden-screen host tests pass, and a QEMU scenario's `screendump` of the TUI app matches its golden image.

### M9 · Networking: virtio-net and netvsc

The guest echoes UDP packets on QEMU and on Hyper-V.

- **Shared:** write Ethernet, ARP, IPv4, ICMP echo and UDP in `net`, configured statically. QEMU user networking gives the guest `10.0.2.15` with the gateway at `10.0.2.2`. On Hyper-V, use an address on your virtual switch's subnet.
- **QEMU path:** enumerate PCI through ECAM, find `virtio-net-pci`, negotiate features, and build split virtqueues in DMA frames. The QEMU options are `-netdev user,id=n0,hostfwd=udp::5555-:7 -device virtio-net-pci,netdev=n0`.
- **Hyper-V path, `vmbus`:** set up the SynIC through the Hypervisor capability, make initial contact, take channel offers, and build GPADLs and ring buffers.
- **Hyper-V path, `netvsc`:** negotiate the NVSP version, share the receive and send buffers, then initialise RNDIS, query the MAC address and set the packet filter.
- QEMU has no netvsc device, so the Hyper-V path gets host tests against a mock VMBus host written from the published protocol, and is proven on your machine. This is the most writing-heavy part of the plan.

**Done when:** on QEMU, a scenario sends 100 UDP datagrams through the forwarded port and gets all 100 back. On Hyper-V, datagrams sent from the host across the virtual switch come back echoed.

### M10 · Red team

Find and fix every way an unprivileged task can break the kernel's guarantees.

Start with a threat model. The attacker is a ring-3 task holding a known set of capabilities. Its goals are to gain authority, read or write memory it was not given, crash or hang the kernel, or starve other threads beyond what the priority rules allow.

Then run one agent per brief, each in its own worktree:

1. **Capability confusion:** widen rights through mint, mutate and copy edge cases, guard tricks, or capability-pointer depth.
2. **Revoke and delete races:** IPC in flight while a capability is revoked, or an endpoint deleted with threads blocked on it.
3. **Untyped and retype:** overlap, alignment, size overflow, or device untyped retyped into kernel objects.
4. **Address spaces:** mapping kernel-owned frames, aliasing a page table as a frame, unmapping a page table still in use, stale TLB entries after unmap.
5. **Entry and exit:** `sysret` to a non-canonical address (the classic Intel fault taken in ring 0 on the user's stack), `swapgs` mistakes, NMIs and double faults on IST stacks, and SMEP or SMAP bypasses.
6. **Syscall arguments:** a user-space fuzzer task that issues random invocations with random registers. The kernel must never panic.
7. **Interrupts, I/O ports and DMA:** IOPort range checks and IRQ handler misuse. Without an IOMMU, the virtio-net driver can DMA anywhere; record that as a known limitation, which seL4 shares without one.
8. **Hyper-V interface:** a VMBus server using the Hypervisor capability beyond its own channels, and malformed SynIC messages. A hostile hypervisor is out of scope.
9. **Scheduler:** priority inversion, bypassing the priority ceiling, and timeslice abuse.

Each finding gets a proof-of-concept scenario in `tests/qemu/redteam/`, a fix, a regression test and a write-up in `docs/redteam/`.

**Done when:** every brief has run against the current tree, every finding is fixed or recorded as accepted, and the syscall fuzzer runs a million invocations without a kernel panic.

### Stretch goals

- Multi-core with INIT-SIPI-SIPI start-up and one big kernel lock, as seL4 does.
- MCS scheduling contexts with budgets.
- A fast-path IPC written in assembly.
- Hyper-V's synthetic keyboard and video over VMBus, so input no longer needs the serial pipe.
- Booting under your own type-1 hypervisor.
- An aarch64 port on QEMU's `virt` board.

## Session playbook

Every cloud session uses the same prompt and the same loop. Only the milestone line changes.

```
You are working on the L4-style microkernel in this repo.
1. Run tools/setup.sh. Read CLAUDE.md, PLAN.md and STATUS.md.
2. Continue milestone M<N> · <name>. Take the next unchecked task in STATUS.md.
3. Before writing code, write or update the design note for it in docs/.
   Have a fresh subagent check the note against the seL4 manual and fix what it finds.
4. Implement. Split independent pieces across parallel subagents, each in its own worktree.
5. Write host tests first wherever the logic allows. Add a QEMU scenario for anything
   that only runs on the board. Never run QEMU outside cargo xtask.
6. Run cargo xtask test.
7. Give the diff and the milestone's done-when test to a fresh reviewer subagent that
   has not seen this session's work. Fix everything it reports, or record in STATUS.md
   why not.
8. Update STATUS.md, commit, push a branch and open a PR.
Keep going until the done-when test passes or the task list is empty.
```

**Subagent roles:**

| Role | When | Brief |
| --- | --- | --- |
| Designer | Start of each task | Write the design note with its invariants. |
| Spec checker | After each design note | Compare it with the seL4 manual or source and list every divergence with its reason. |
| Builder (one or more) | Independent components | Implement with tests in its own worktree. |
| Test writer | Alongside a builder | Write host tests and golden files from the design note alone, without reading the implementation. |
| Reviewer | End of each milestone | Fresh eyes on the diff, checked against the done-when test and `STATUS.md`. |
| Red teamer | M10, plus one quick pass after each of M4 to M9 | Break one guarantee and prove it with a scenario. |

**Running sessions in parallel.** Milestones are sequential, except M2 and M3 after M1, and M8 and M9 after M7. Each M10 brief can be its own session. Two sessions on the same milestone will conflict. Your `address-pr-comments` skill from `agent-skills` can work through review threads on the PRs.

**Hyper-V checks happen on your machine.** Sessions write `tools/hyperv/` but cannot run it. At the end of M0, M3, M5, M8 and M9, download the VHDX from CI, boot it with those scripts, and paste the COM1 log into the PR. A session that finds a failing Hyper-V log in a PR treats it like a failing test.

**`STATUS.md` format:**

```markdown
# Status
Current milestone: M3 · Paging and interrupts

## Done
- [x] GDT, TSS and IDT with IST stacks (PR #12)

## Next
- [ ] Local APIC timer, calibrated against the HPET
- [ ] ACPI parser host tests

## Open issues
- Page-fault decoder does not name protection-key faults (low priority)

## Decisions this milestone
- ADR 0004: eager XSAVE on every switch

## Hyper-V checks
- M0 VHDX: boots, hello on COM1

## Last session
2026-11-02: IDT landed. Reviewer found the double-fault handler not on an IST stack; fixed.
```

## Budget split

The split follows how much writing and review each milestone needs, not how much code it ships.

*[Diagram in the original plan: proposed split of the $250 budget · set in this plan, not measured]*

- If a milestone finishes under its share, move the remainder to M10's red-team briefs.
- If a milestone runs more than half over its share, stop and cut scope before spending more.
- Cut stretch goals before cutting reviews.

## Risks and gotchas

The two biggest risks are the toolchain workaround and the Hyper-V code the cloud cannot run. If the cloud image's `rustc` changes, `build-std` has to follow it. VMBus code is only proven when you boot the VHDX on your machine.

| Risk | Effect | What to do |
| --- | --- | --- |
| `rustc` on the image changes version | The `build-std` source no longer matches the compiler | `setup.sh` keys the GitHub clone on `rustc --version`, so it fetches the matching tag. Fix the `build-std` flags if a new release changes them. |
| `RUSTC_BOOTSTRAP=1` on stable | Unstable flags can change between releases | Accept it, and keep every unstable flag in one config file. |
| Hyper-V paths cannot run in the cloud | VMBus, netvsc and Hyper-V timer code is written without running it | Host tests against a mock VMBus host, plus a Hyper-V check on your machine at the end of M0, M3, M5, M8 and M9. |
| The VHDX boots under OVMF but not under Hyper-V | Every Hyper-V check is blocked | Prove the VHDX on Hyper-V in M0, before anything depends on it, with Secure Boot off. |
| No public VMBus specification | netvsc depends on reading other drivers | Use the BSD-licensed FreeBSD drivers as the reference. Do not copy Linux's GPL code. |
| No KVM, 2 vCPUs, 7 GB RAM | Slow boots; timings are meaningless | Never draw performance conclusions. Run at most two QEMU instances at once. |
| TCG hides missing TLB flushes | A missing `invlpg` or CR3 reload stays hidden under QEMU | Reviewers check TLB maintenance by reading the code. Hyper-V runs on hardware virtualisation and may expose it. |
| Kernel built with SSE enabled by mistake | The compiler may use SSE registers in `memcpy` and corrupt user state | `xtask` refuses to build the kernel for any target except `x86_64-unknown-none`. |
| QEMU 8.2 behaviour | OVMF framebuffer capture and `virtio-net-pci` details differ across versions | Print the QEMU version in test output and pin golden images to it. |
| Scope creep in M8 and M9 | A terminal emulator and two network drivers can each absorb the whole budget | Stop at the done-when tests and move extras into stretch goals. |
| Sessions lose track | Work is redone, or two sessions diverge | The reviewer checks that `STATUS.md` is current before signing off. |
| Font licence | A copied font may not allow redistribution | Use a permissively licensed font, or draw one as data. |

## References

Sessions should read the specific section they need from these, not whole documents.

- [seL4 Reference Manual](https://www.sel4.systems/Info/Docs/seL4-manual-latest.pdf): the comparison point for M1, M2, M4 and M6.
- [seL4 source](https://github.com/seL4/seL4): read the one file that matches the subsystem being built.
- [Elphinstone and Heiser, "From L3 to seL4: what have we learnt in 20 years of L4 microkernels?" (SOSP 2013)](https://trustworthy.systems/publications/nictaabstracts/Elphinstone_Heiser_13.abstract): why the L4 design choices were made.
- [Heiser and Elphinstone, "L4 Microkernels: The Lessons from 20 Years of Research and Deployment" (2016)](https://trustworthy.systems/publications/nictaabstracts/Heiser_Elphinstone_16.abstract): the extended version.
- [Hyper-V Hypervisor Top Level Functional Specification](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs): hypercalls, the SynIC, the reference counter and CPUID leaves, for M3 and M9.
- [FreeBSD's Hyper-V drivers](https://github.com/freebsd/freebsd-src/tree/master/sys/dev/hyperv): the BSD-licensed reference for VMBus, NVSP and RNDIS, for M9.
- [Intel 64 and IA-32 Software Developer's Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html): paging, interrupts, `syscall` and `sysret`, XSAVE, SMEP and SMAP, for M3, M5 and M10.
- [UEFI and ACPI specifications](https://uefi.org/specifications): boot services, GOP and the memory map for the loader, and the MADT, HPET and MCFG tables for M3.
- [Virtio 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html): the PCI transport, split virtqueues and the network device, for M9.
- [Paul Williams, "A parser for DEC's ANSI-compatible video terminals"](https://vt100.net/emu/dec_ansi_parser): the state machine for the M8 parser.

