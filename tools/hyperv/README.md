# Hyper-V checks

Cloud sessions cannot run Hyper-V, so these scripts run on your Windows host.
At the end of M0, M3, M5, M8 and M9, boot the VHDX that CI built and paste the
COM1 log into the milestone's PR. A session that finds a failing Hyper-V log in
a PR treats it like a failing test.

The scripts need the Hyper-V PowerShell module and an elevated PowerShell:
membership of Hyper-V Administrators manages the VM but may not open its COM1
pipe. They work in Windows PowerShell 5.1 and PowerShell 7. Windows client
editions refuse to run unsigned scripts by default; allow them for the current
window with:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## Once: create the VM

Download the `microl4-vhdx` artifact from the PR's CI run, either from the
Actions page or with the GitHub CLI:

```powershell
gh run download --repo glslang/microL4 --name microl4-vhdx --dir microl4-vhdx <run-id>
```

Then create the VM. It is a Generation 2 VM named `l4` with 512 MB, one vCPU
with processor compatibility mode off, Secure Boot off, COM1 on
`\\.\pipe\l4-com1`, and no automatic checkpoints. Pass `-SwitchName ''` if
you have no `Default Switch`; networking is not needed until M9.

```powershell
.\New-L4Vm.ps1 -VhdxPath .\microl4-vhdx\disk.vhdx
```

From M3 the kernel refuses to boot without SMEP, SMAP and XSAVE, which
processor compatibility mode hides. A VM created before M3 needs it turned off
once, with the VM off:

```powershell
Set-VMProcessor -VMName l4 -Count 1 -CompatibilityForMigrationEnabled $false
```

## Each check: boot a new VHDX

```powershell
.\Test-L4Vhdx.ps1 -VhdxPath .\microl4-vhdx\disk.vhdx
```

This swaps the disk in, starts the VM, copies COM1 to the console until
`TEST PASS`, `TEST FAIL`, `KERNEL PANIC`, `LOADER ERROR` or `LOADER PANIC`
(or 60 seconds), turns the VM off, and prints `PASS` or `FAIL`. The log is
saved as `l4-com1-<time>.log`; paste it into the PR.

The CI image boots with `test=hello`, so a passing M0 log ends like this, with
the hypervisor line reading Hyper-V:

```text
microL4 kernel 0.1.0 (debug)
...
cpu: hypervisor Hyper-V ("Microsoft Hv")
cmdline: "test=hello"
hello from microL4
TEST PASS
```

The kernel halts after `TEST PASS` on Hyper-V, since there is no
`isa-debug-exit` device; the script turns the VM off.

## Optional: the M4 check

CI builds a second image, the `microl4-vhdx-m4-check` artifact. It boots
`test=retype`, M4's done-when self-test: the kernel prints its boot summary
with the BootInfo lines, then retypes the largest RAM untyped into every
object type, works the CNode operations on the results, revokes it, does
it all again, and checks that both runs give the same result. M4 does not
need this check, but its numbers are the first from real hardware:

```powershell
.\Test-L4Vhdx.ps1 -VhdxPath .\microl4-vhdx-m4-check\disk.vhdx -TimeoutSeconds 120 `
    -LogPath m4-check.log -Expect 'cpu: hypervisor Hyper-V', `
    'cpu: physical address width', 'bootinfo: boot region', 'bootinfo: slots', `
    'retype: U is root slot', 'retype: an interrupt is pending', `
    'retype: run 1 done:', 'retype: revoke 1 done:', 'retype: run 2 done: the same', `
    'retype: revoke 2 done:', 'restarts from the idle path after', `
    'retype: the longest stretch between two polls:'
```

If you run it, paste `m4-check.log` into the PR. These lines are what the
check is for:

| Line | What it shows |
| --- | --- |
| `cpu: physical address width ...` | the width BootInfo reports; no untyped reaches `2^width` |
| `bootinfo: boot region ...` | where the root CNode, the IPC buffer and BootInfo went: the top of the highest usable range |
| `bootinfo: N untyped: ...` | the untyped count, under BootInfo's 448, and the RAM and device bytes |
| `bootinfo: framebuffer ...` | the GOP framebuffer's device untyped, or the warning and its reason when it gets none |
| `bootinfo: slots ...` | each slot region of the root CNode |
| `retype: U is root slot ...` | the untyped the test retypes, and its size |
| `retype: run 1 done: N slots recorded ...`, `run 2 done: the same N slots ...` | the record of every slot after each run; N moves with the untyped count |
| `retype: revoke 1 done: ...`, `revoke 2 done: ...` | the revoke emptied every slot the test filled |
| `retype: run 1: preempted ...` and the other phases' lines | each phase's preemptions by the timer and by injection, and the stretches between its preemption points: the longest and the mean |
| `retype: N restarts from the idle path ...` | every preempted call restarted from the idle path |
| `retype: the longest stretch between two polls: ...` | the longest time the kernel ran between two preemption points in each phase, which answers whether clearing 4 KiB between them is right |

The M3 check passed on 2026-10-30; its results are in `STATUS.md`. To run
it again, build its image with `cargo xtask image --cmdline "acpidump
test=ticks"`; `cargo xtask acpidump --from-log <log> --out
core/tests/acpi/hyperv-gen2.dump` turns its log into the Hyper-V test
tables.

## The pieces

| Script | Does |
| --- | --- |
| `New-L4Vm.ps1` | creates the VM, once |
| `Set-L4Vhdx.ps1` | turns the VM off and swaps in a new VHDX |
| `Read-L4Com1.ps1` | reads COM1 from the named pipe until a marker line |
| `Test-L4Vhdx.ps1` | all of the above, plus the pass or fail verdict |

To watch COM1 by hand instead, start the VM and run `.\Read-L4Com1.ps1`, or
connect PuTTY to the serial line `\\.\pipe\l4-com1`.
