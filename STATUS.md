# Status
Current milestone: M0 · Bootstrap and tooling, complete: the done-when test passed and the fresh reviewer signed off on 2026-10-29. Next: M1 · Design and ABI.

## Done
- [x] Workspace, `xtask`, `tools/setup.sh`, `.cargo/config.toml`, `CLAUDE.md`, `STATUS.md` and `PLAN.md`
- [x] UEFI loader: memory map, GOP framebuffer, ACPI RSDP, `kernel.elf` and `cmdline.txt` from the ESP, initial page tables, ExitBootServices, jump with a handoff struct (`docs/boot.md`)
- [x] Kernel entry: BSS zeroed, boot stack, COM1 writer, panic handler printing file and line, `isa-debug-exit` on QEMU and halt elsewhere
- [x] Scenario runner (`cargo xtask test`): 60-second timeout, expected lines in order, exit status checked; `hello` and `panic` pass locally on QEMU 8.2.2 (TCG)
- [x] `cargo xtask image` (GPT disk, FAT32 ESP, dynamic VHDX) and the CI workflow that uploads the VHDX
- [x] `tools/hyperv/`: create the VM, swap the VHDX, read COM1 from the named pipe, and a one-step check (not run: no Hyper-V in the cloud)
- [x] Host tests: 30 in `core/` (handoff validation, memory-map normalisation, ELF parser, command line), 10 in `xtask/`; the handoff layout is checked at compile time on every target; Miri clean on `core/`
- [x] CI green on the first run (`ubuntu-latest`, QEMU 10.2); now pinned to `ubuntu-24.04` to match the cloud image's QEMU 8.2
- [x] Hyper-V check: the CI-built VHDX from 7c4609f boots on the owner's Generation 2 VM and prints the hello over COM1, ending in `TEST PASS` (log in the PR)
- [x] Spec check of `docs/boot.md` against seL4's x86_64 boot code, and a fresh review of the whole diff. Its three should-fixes were fixed in 7c4609f, along with its nits:
  - the empty-segment underflow in the loader, also found by Codex
  - `arch::memory_map` trusting an unvalidated handoff
  - the Hyper-V COM1 reader connecting too late
- [x] M0 sign-off: the reviewer verified the fixes and approved M0 on 7c4609f.

## Next
- [ ] Merge the M0 PR, then M1 · Design and ABI: `docs/design.md` and `docs/abi.md` v0; fold the handoff from `docs/boot.md` into `abi.md`

## Open issues
- The loader's 1:1 map of low memory is still live in the kernel. M3 must drop it before M5 creates a user address space, which uses the lower half (ADR 0002).
- `kprintln!` has no lock. Fine while interrupts are off; M3 must add one when it turns them on.
- The firmware's IDT and stack (and, on some firmware, its GDT) sit in memory reported as `USABLE`. The kernel must load its own GDT and IDT (M3) before reusing that memory (M4).
- No guard page under the 64 KiB boot stack; a kernel stack overflow corrupts `.data` silently until M3 maps a guard.
- M4 must make device untyped from the gaps in the memory map, not only from `MMIO` entries, or the virtio-net and framebuffer BARs go missing (`docs/boot.md`, Memory map).
- M5 must put the embedded root-task image in its own reclaimable section (`docs/boot.md`, Comparison with seL4).
- `rustup target add` worked in this session, unlike the plan's test; the `build-std` fallback is kept and was tested with `XTASK_FORCE_BUILD_STD=1` (ADR 0001).

## Decisions this milestone
- ADR 0001: stable Rust with prebuilt targets, `build-std` from GitHub source as the fallback
- ADR 0002: the loader builds the initial page tables; the kernel lives in the upper half from M0
- ADR 0003: scenarios select kernel tests through `\cmdline.txt` on the ESP

## Hyper-V checks
- M0 VHDX (7c4609f, 2026-10-29): boots with Secure Boot off; hello and `TEST PASS` on COM1 through the named pipe. It confirms the plan's Hyper-V column for M0:
  - CPUID signature is `Microsoft Hv`.
  - The GOP framebuffer is 1024x768 BGR at `0xF8000000`, stride 1024.
  - The ACPI RSDP is at `0x1FFFA014`.
  - The memory map has 10 regions, 509 MiB usable of 512 MiB; the highest RAM ends at `0x20000000`, so the direct map is the 4 GiB minimum.
  - Unlike QEMU, the map lists no MMIO or high reserved ranges.

## Last session
2026-10-29: M0 implemented end to end and signed off. Both scenarios pass locally in about 3 s each and in CI, and so do release builds and the build-std fallback. The owner's Hyper-V boot passed. The next session starts M1 from the playbook prompt, once the M0 PR is merged.
