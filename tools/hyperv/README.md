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

## At the M3 check

CI builds a second image for this check, the `microl4-vhdx-m3-check`
artifact. It boots `acpidump test=ticks`: the loader prints every ACPI table
to COM1, the kernel prints its boot summary, then it times ten ticks of the
100 Hz timer against the Hyper-V reference counter. The dump takes a few
seconds over COM1, so allow two minutes:

```powershell
.\Test-L4Vhdx.ps1 -VhdxPath .\microl4-vhdx-m3-check\disk.vhdx -TimeoutSeconds 120 `
    -LogPath m3-check.log -Expect 'acpidump: rsdp', 'acpidump: end', `
    'cpu: features NX PGE PAT SMEP SMAP XSAVE', 'cpu: hypervisor Hyper-V', `
    'hyperv: ', 'timer: calibrating against the Hyper-V reference counter', `
    'timer: periodic at 100 Hz', 'cpu: meltdown:', `
    'ticks: within 100000 us within 1%'
```

Paste `m3-check.log` into the PR. These lines are what the check is for:

| Line | What it shows |
| --- | --- |
| `cpu: features ...` | SMEP, SMAP and XSAVE are passed through; without them the boot stops at `CPU lacks` |
| `cpu: meltdown: ...` | recorded in `STATUS.md` |
| `apic: IA32_APIC_BASE ... at handover` | whether the firmware left x2APIC on; QEMU never does, so that path first runs here |
| `hyperv: ...` | the TLFS interface and privileges, each firmware overlay found and switched off, the hypercall MSR and whether it is locked, the frequency MSRs |
| `acpi: ...` | the tables, the I/O APIC, COM1's route (GSI 4, edge, active high expected) and no HPET |
| `pic: ...`, `ioapic: ...` | the 8259 and every I/O APIC pin masked |
| `timer: ...` | the calibration against the reference counter, and its agreement with the frequency MSRs |
| `ticks: ...` | ten ticks within 1% of 100 ms |

A session (or you) then turns the ACPI part of the log into the Hyper-V
test tables:

```sh
cargo xtask acpidump --from-log m3-check.log --out core/tests/acpi/hyperv-gen2.dump
```

That checks the dump is whole, prints what the parser makes of it (the
tables, the I/O APIC, each ISA route, the HPET, the ECAM ranges) and writes
the file to commit, with a host test that reads it. The log may have `\r\n`
line ends and other lines between the dump lines.

## The pieces

| Script | Does |
| --- | --- |
| `New-L4Vm.ps1` | creates the VM, once |
| `Set-L4Vhdx.ps1` | turns the VM off and swaps in a new VHDX |
| `Read-L4Com1.ps1` | reads COM1 from the named pipe until a marker line |
| `Test-L4Vhdx.ps1` | all of the above, plus the pass or fail verdict |

To watch COM1 by hand instead, start the VM and run `.\Read-L4Com1.ps1`, or
connect PuTTY to the serial line `\\.\pipe\l4-com1`.
