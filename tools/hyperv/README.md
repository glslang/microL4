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
you have no `Default Switch`; networking is not needed until M9, whose
`New-L4Switch.ps1` moves the adapter to a switch of its own.

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

## At the M5 check

CI builds one artifact, `microl4-vhdx-m5-check`, with one VHDX per test, each
in a folder named after the test: `threads` and `fault`, M5's done-when, and
`ring3`, `tlb`, `isolation` and `redteam-movss`, which show what QEMU cannot:
TF at `syscall_entry`, `#XM`, UMIP, a real TLB, XSAVE switching between
threads, and the `#DB` a `mov ss` defers into ring 0. Download it and boot
each in turn:

```powershell
gh run download --repo glslang/microL4 --name microl4-vhdx-m5-check --dir m5-check <run-id>

$expect = [ordered]@{
    'threads' = 'boot: entering the root task', 'threads: thread A was preempted',
        'threads: the preemptions in the order', 'TEST PASS'
    'fault' = 'boot: entering the root task', 'fault: handler received VMFault',
        'BlockedOnReply, priority 210', 'fault: handler killed thread F',
        'fault: thread F stayed stopped', 'TEST PASS'
    'ring3' = 'entry: syscall_entry at', 'ring3:  1 first entry', 'ring3:  9 #XM',
        'ring3: 10 MXCSR 0x1d84 after the #XM', 'ring3: 12 syscall with TF set:',
        'ring3: 24 done:', 'TEST PASS'
    'tlb' = 'boot: entering the root task', 'phase 1, Frame_Remap to read-only',
        'phase 1: Frame_Remap read-write', 'phase 2, Frame_Unmap', 'phase 2: Frame_Map',
        'phase 3, PageTable_Unmap', 'phase 3: PageTable_Map and Frame_Map', 'TEST PASS'
    'isolation' = 'boot: entering the root task',
        'isolation: thread X: x87, SSE and segment check 0, general-register check 0;',
        'isolation: thread Y: x87, SSE and segment check 0, general-register check 0;',
        "isolation: the root task's x87 and SSE state: check 0", 'TEST PASS'
    'redteam-movss' = 'boot: entering the root task', 'redteam: movss: 5 probes',
        'probe 0 (mov ss; syscall (Yield) with TF): label 3,',
        'probe 1 (mov ss; int3 with TF): label 3,',
        'probe 2 (mov ss; int 0x80 with TF): label 3,',
        'probe 3 (mov ss; int1 (ICEBP) with TF): label 3,',
        'probe 4 (mov ss; ud2 with TF): label 3,',
        'redteam: movss: all 5 probes ended in their own fault', 'TEST PASS'
}
$failed = @()
foreach ($test in $expect.Keys) {
    .\Test-L4Vhdx.ps1 -VhdxPath ".\m5-check\$test\disk.vhdx" -TimeoutSeconds 120 `
        -LogPath "m5-$test.log" -Expect (@('cpu: hypervisor Hyper-V') + $expect[$test])
    if ($LASTEXITCODE -ne 0) { $failed += $test }
}
"failed: $failed"
```

Paste the six logs, `m5-<test>.log`, into the PR. The script stops reading at
`TEST PASS`, so no expectation follows it: the root task's `DEBUG HALT 0`
comes after it and is never read. Each log must show:

| Test | What the log must show | What it settles |
| --- | --- | --- |
| `threads` | two ring-3 threads at the same priority, each preempted by the 100 Hz timer with the other running in between: `threads: thread A was preempted ... times with the other thread running in between` and the preemptions in order. Either thread's first line may come first | M5's done-when |
| `fault` | a user page fault reaching its handler thread, which prints it, sees the faulting thread `BlockedOnReply, priority 210` in the scheduler dump, kills it, and sees it stay stopped | M5's done-when |
| `ring3` | `ring3:  9 #XM SIMD floating-point exception (vector 19) from ring 3` and `ring3: 10 MXCSR 0x1d84 after the #XM: ZE set` (without them the test fails); `ring3: 12 syscall with TF set: N #DB at syscall_entry`, where N is 0 if the CPU checks TF after IA32_FMASK cleared it, as on QEMU, or 1 if it trapped there and the kernel returned; `UMIP on` in the `ring3: ... bytes of code` line with step 22's `sgdt under UMIP` `#GP`, or `UMIP is off` | the open questions on TF at `syscall_entry`, `#XM` and UMIP (`docs/design.md`, Open questions) |
| `tlb` | each phase's access faulting after `Frame_Remap`, `Frame_Unmap` and `PageTable_Unmap`, and restarting once the page is mapped again | `invlpg` and the CR3 reload on a real TLB |
| `isolation` | check 0 for both threads and the root task, each thread having seen the other run in both phases | XSAVE64 and XRSTOR64 between preempted threads on a real CPU |
| `redteam-movss` | every probe's line and `TEST PASS`, no `KERNEL PANIC`. Record probe 1's vector: `label 3, 0x3/0x0` means the CPU deferred the single step past `int3` and the kernel returned from the ring-0 `#DB` (the M5 fix), `0x1/0x0` that it did not defer it. A `fatal trap` on `trap_vector_0d` (probe 2) or `trap_vector_01` (probe 3) means `#GP` keeps the pending step or `int1` raises a second `#DB` | `docs/redteam/m5-movss-db.md`, "What stays to be confirmed on Hyper-V" |

The `fpu:` and `entry:` lines show XCR0, the XSAVE size, the system-call MSRs
and `IA32_TSC_AUX` as Hyper-V gives them to the kernel.

## At the M8 check

CI builds `microl4-vhdx-m8-check`: `tui/disk.vhdx` boots `test=tui` on the
selftest kernel, `release/disk.vhdx` boots `test=release` on the release
kernel, and beside them are the two scenarios the script follows,
`m8-tui.scenario` and `m8-release.scenario` (copies of this folder's), and
`golden/tui-main.png`, `tui-colours.png` and `tui-quit.png`: the screens
`term` must show at 1024x768, drawn on the host by xtask's
`tui_screendumps_are_the_host_render` from the same bytes `tui` sends.
Download it and run the three checks:

```powershell
gh run download --repo glslang/microL4 --name microl4-vhdx-m8-check --dir m8-check <run-id>

.\Test-L4Vhdx.ps1 -VhdxPath .\m8-check\tui\disk.vhdx -Scenario .\m8-check\m8-tui.scenario `
    -TimeoutSeconds 120 -LogPath m8-tui.log
.\Test-L4Vhdx.ps1 -VhdxPath .\m8-check\release\disk.vhdx -Scenario .\m8-check\m8-release.scenario `
    -LogPath m8-release.log
.\Test-L4Vhdx.ps1 -VhdxPath .\m8-check\release\disk.vhdx -Scenario .\m8-check\m8-release.scenario `
    -ConnectAfterSeconds 20 -TimeoutSeconds 30 -LogPath m8-release-late.log
```

`-Scenario` follows a scenario file in the QEMU harness's format, as
`cargo xtask test` does, over COM1's pipe: each `expect:` must appear after
the one before it, a `next:` must start the very next line, a `send:` is
typed into COM1 once the `expect:` lines above it have matched (`\x14` is
Ctrl-T, `\e` ESC, `\r` Enter), and no line may contain a `forbid:` text.
At each `screendump:` the script saves the VM's screen, through Hyper-V's
`Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage` at
1024x768, as `l4-<name>.png` beside the log, and the bytes the API
returned as `l4-<name>.rgb565`. Its documentation says only that they are
"raw RGB 565"; the script reads them as Windows' 16-bit RGB 565 bitmaps
are laid out (two bytes a pixel, little-endian, red in the top five bits,
rows from the top), which the M8 check confirmed. The buffer starts with
a 4-byte header, so the pixels are its last 2 × 1024 × 768 bytes; the log
line says how many header bytes it skipped. With the header skipped, the
M8 check's three screens equal `golden/tui-*.png` reduced to RGB 565 at
every pixel compared. If a PNG looks scrambled, shifted sideways or its colours
swapped, say so in the PR and keep the `.rgb565` files. A screen
the script cannot save fails the run, which still goes on to the end so
the log is whole.
`-ConnectAfterSeconds 20` starts the VM and opens the pipe only 20 seconds
later. The script then follows the steps from the `expect:` right above
the first `send:`: it types the `send:` when that line arrives or, if it
never does, once no line at all has come for 10 seconds, and requires the
steps after it. A transmitter that drains has dropped that line, and by
then the boot is over and the root task waits in its `Read`, printing
nothing more until the line is typed; one that waits held the boot back
and sends what it held as soon as the pipe connects, and the boot's quiet
stretches after that, the release kernel's own start the longest, should
take well under 10 seconds (the whole `release` scenario takes about 2
seconds on QEMU's TCG). The script then
prints how many of uart's lines above the `send:`, the `expect:` lines
from `root: cmdline` on, arrived, each counted wherever it comes, and how
the line was typed. The loader's lines do not count: its polled writes
give up after 100,000 polls a byte (`loader/src/serial.rs`), so a
transmitter that waits loses most of them too. The reader's 30-second
limit starts when the reader starts, after the 20-second wait, so in
practice when the pipe connects.

Paste the three logs into the PR and attach the three screens. The screens
must match `m8-check\golden\tui-*.png`: RGB 565 keeps 5 or 6 bits a
channel, so the colours differ slightly by eye, but reduced to RGB 565 the
two are equal pixel for pixel, which the session checks from the attached
screens.

| Run | The log must show | It settles |
| --- | --- | --- |
| `m8-tui` | `cpu: hypervisor Hyper-V`; `bootinfo: framebuffer 0xf8000000-...`; `fb: 1024x768 BGR, stride 1024, ...; 128x48 cells`, with the GOP's size and frame counts; `fb: full clear: uncached <n> us, write-combining <m> us`; `tui: 128x48 terminal`; `tui: frame 1 drawn`; `[console] focus 4 (term)` and `tui: frame 4 drawn` after the script's keys; `tui: quit after 4 keys`; `tui: read 8 bytes`; `term: stats:` with 0 ignored and 0 dropped; `TEST PASS`. Record both clear times | the framebuffer found, handed out and mapped write-combining on Hyper-V; whether write-combining wins over the firmware's MTRR type (H10: the WC clear several times faster than the UC one); keys through the named pipe; Hyper-V's video showing the GOP framebuffer after `ExitBootServices` |
| `m8-release` | every line whole (both M8 runs lost a few bytes of one root line, the cause open: `docs/design.md`, Open questions); uart's line with `burst 15` (working FIFOs) or `burst 1`, ending `, <n> stale THREs`: above 0 means Hyper-V reported THRE while its FIFO held bytes, which uart now ignores; `14 bytes received` and the line read whole, though its last 6 bytes stay below the receive trigger of 8, which only the character timeout delivers; THRE bursts above 0 | M7's 16550 questions: FIFOs, the character timeout, THRE interrupts |
| `m8-release-late` | the script's `Of the 6 uart lines above the first send: (from 'root: cmdline'), K arrived` line: K = 6 if uart's lines written before the pipe had a client arrive once it connects (the transmitter waits; the `send:` is then typed when `release: type a line` arrives), 0 if they are gone (it drains, as M0 saw Hyper-V drop COM1 output with no client; the `send:` is typed after 10 seconds with no line); anything between, say so in the PR; then the rest of the run, `release: read "release input"` to `TEST PASS` | whether a transmitter with no client on the pipe stalls `uart`'s writes |

The `-Scenario` and `-ConnectAfterSeconds` code and the thumbnail were
written without a Windows host to run them. If the script itself fails,
paste its error into the PR with the log, which is written all the same.

## At the M9 check

### First: COM1's lost bytes

Each M8 `m8-release` run lost a few bytes of one of root's lines while
root's summary flooded `uart`, though `uart` wrote every burst after an LSR
that said THRE (`docs/design.md`, Open questions). CI builds
`microl4-vhdx-m9-com1` for this alone, so it can come first:
`release-burst1/disk.vhdx` and `release-burst15/disk.vhdx` boot
`test=release` on the release kernel with `uart.burst=1` or `uart.burst=15`
and `release.flood=32`, and beside them are `m9-release-burst1.scenario`
and `m9-release-burst15.scenario`. `uart.burst=<n>` caps `uart`'s burst:
root prints `root: uart.burst=<n>: uart's burst capped at <n>` after its
`root: cmdline` line, and `uart`'s line ends `burst <n>, <m> stale THREs`.
`release.flood=32` makes root print, right after its summary, 32 lines
from `release: flood 01/32 123456789abc...` to `release: flood 32/32
wxyz...`, 75 bytes each with CR LF: 2,400 bytes, more than `uart`'s
2,048-byte queue, so `uart` holds console's writes and keeps its FIFO fed,
as root's summary did in M8. The scenarios expect the first flood line and
the other 31 with `next:`, each whole, and release's own line right after
the last; a cut line fails the run, and the script goes on from the next
`expect:`, so the log still reaches `uart`'s line and `TEST PASS`.

Run each image three times: twice with the normal reader, and once with
`-Raw`, which copies the pipe's bytes into a file as they come, through a
1 MiB buffer and off the script's thread, so COM1 never waits on the
script's work per line, and reads the lines back from that file:

```powershell
gh run download --repo glslang/microL4 --name microl4-vhdx-m9-com1 --dir m9-com1 <run-id>

foreach ($burst in 1, 15) {
    $vhdx = ".\m9-com1\release-burst$burst\disk.vhdx"
    $scenario = ".\m9-com1\m9-release-burst$burst.scenario"
    foreach ($run in 'a', 'b') {
        .\Test-L4Vhdx.ps1 -VhdxPath $vhdx -Scenario $scenario -LogPath "m9-burst$burst-$run.log"
    }
    .\Test-L4Vhdx.ps1 -VhdxPath $vhdx -Scenario $scenario -LogPath "m9-burst$burst-raw.log" `
        -Raw "m9-burst$burst-raw.com1"
}
```

Paste the six logs into the PR and attach the two `.com1` files, which
hold every byte as it came, CR LF and escape sequences included. A scenario
sees only the lines it expects, so a run can pass with another line cut;
the session reads every line for missing bytes.

| Run | The log must show | It settles |
| --- | --- | --- |
| `m9-burst1-a`, `-b` | `root: uart.burst=1: uart's burst capped at 1`; the 32 flood lines, each whole and right after the one before; `uart`'s line with `, burst 1,`; the rest as `m8-release`; whether every line is whole | with `m9-burst15`: lines whole with burst 1 but cut with 15 mean Hyper-V's FIFO takes fewer bytes after it reports THRE than `uart` writes; cut either way, the named pipe drops what its reader has not taken. Burst 1 also writes more slowly, a THRE interrupt a byte |
| `m9-burst15-a`, `-b` | `root: uart.burst=15: uart's burst capped at 15`; the same flood lines; `, burst 15,`; `Writes held`, which should be above 0: the flood filled the queue | the control: `uart` writes as in the M8 re-run, with the queue full, so whether the loss comes back |
| `m9-burst1-raw`, `m9-burst15-raw` | the same, read through `-Raw` | a burst-15 run cut with the normal reader but whole with `-Raw`: the reader fell behind the pipe, not `uart` or the FIFO; cut with `-Raw` too: Hyper-V's FIFO, or the pipe itself. The `.com1` file shows exactly which bytes went |

If every run is whole, the flood did not bring the loss back, and the M8
loss stays open.

### The network

The networking images go on an internal switch with a fixed subnet, not
the Default Switch, whose NAT subnet changes when the host restarts. Once,
from an elevated PowerShell:

```powershell
.\New-L4Switch.ps1
```

This makes the internal switch `l4-net`, gives the host's `vEthernet
(l4-net)` the address `192.168.77.1/24` and no other, and puts the VM's
network adapter on the switch, adding one, with the VM off, if it has
none; run it again to change the subnet. The CI images boot with
`net.ip=192.168.77.2/24 net.gw=192.168.77.1`. If another of the host's
networks overlaps `192.168.77.0/24`, the script stops and says so: pass
`-Subnet` with another, such as `-Subnet 10.77.0.0/24`, write the words it
prints into each image with `Set-L4Cmdline.ps1 -VhdxPath <disk.vhdx>
-Cmdline '<the image's command line with them>'` before booting it, and
change the scenario's `cmdline:` and the `expect:` lines that name the
addresses to match. `Set-L4Cmdline.ps1` mounts the VHDX, so run it on the
downloaded image, not the VM's copy, and paste its error into the PR if it
fails: it first runs at this check.

A scenario's `udp_echo: <n>` makes `Test-L4Vhdx.ps1 -Scenario` run
`Send-L4Udp.ps1` against the `net.ip=` of the scenario's `cmdline:`: it
pings the guest four times, sends `n` datagrams to its port 7 with
xtask's payloads, window of 8 and limits, prints `udp_echo: <n> sent, <k>
echoed` with any missing indices, and the guest's MAC as the host's
neighbour table has it beside the VM adapter's; its lines go into the log
as `l4:` lines, and a missing datagram or a bad echo fails the run. To try
it by hand while a networking image runs:

```powershell
.\Send-L4Udp.ps1 -Address 192.168.77.2
```

Windows answers the guest's ARP request for the host's address; its
firewall may drop the guest's ping of the host, which does not matter. The
host's pings and the guest's echoes come back as answers to the host's own
requests.

The network scripts were written without a Windows host to run them. If
one fails, paste its error into the PR with the log.

### Then: the network runs

CI builds `microl4-vhdx-m9-check` for M9's done-when on Hyper-V:
`net/disk.vhdx` boots `test=net net.ip=192.168.77.2/24
net.gw=192.168.77.1` on the selftest kernel, `net-mnf/disk.vhdx` the same
with `netvsc.mnf=1`, and beside them are the two scenarios the script
follows, `m9-net.scenario` and `m9-net-mnf.scenario`. With the VM's
adapter on the switch (`New-L4Switch.ps1`, above), run each once:

```powershell
gh run download --repo glslang/microL4 --name microl4-vhdx-m9-check --dir m9-check <run-id>

.\Test-L4Vhdx.ps1 -VhdxPath .\m9-check\net\disk.vhdx -Scenario .\m9-check\m9-net.scenario `
    -TimeoutSeconds 120 -LogPath m9-net.log
.\Test-L4Vhdx.ps1 -VhdxPath .\m9-check\net-mnf\disk.vhdx -Scenario .\m9-check\m9-net-mnf.scenario `
    -TimeoutSeconds 120 -LogPath m9-net-mnf.log
```

Root starts `vmbus`, `netvsc` and `net`; once `net` prints `echo:
listening on UDP port 7`, the script runs `Send-L4Udp.ps1` against
`192.168.77.2` (four pings, then 100 datagrams, each echo checked, its
lines logged as `l4:` lines), then types Enter, and root prints
`vmbus`'s, `netvsc`'s and `net`'s counters and its verdict. The
exchange comes before the gateway's line in the scenario, though `net`
prints that line first, so that a host that never answers still leaves
root's counters in the log. Paste both logs into the PR.

| Run | The log must show | It settles |
| --- | --- | --- |
| `m9-net` | `cpu: hypervisor Hyper-V`; root's `servers: Hyper-V: SINT 2 is IRQ <n>; channel frame ..., monitor pages ... and ..., event flags ...; netvsc signals the host with SignalEvent` and `servers: vmbus (priority 145, SINT 2 IRQ <n>), netvsc (priority 140), net (priority 130); root CNode <k> of 4096 slots used`; `vmbus: version 4.0` (or 3.0 or 2.4); every `vmbus: offer`, netvsc's among them; `vmbus: netvsc channel <id> open, connection <c>`; `netvsc: up: NVSP <v>, NDIS <v>, MAC 00:15:5d:..., link up, <n> send sections of <m> bytes`; `net: up: 192.168.77.2/24 via 192.168.77.1`; `echo: listening on UDP port 7`; the script's four ping replies and `udp_echo: 100 sent, 100 echoed`, and the guest's MAC in the host's neighbour table equal to the VM adapter's and to `netvsc: up`'s; `net: gateway 192.168.77.1 is at <mac>`; root's `vmbus: stats:`, `netvsc: stats:` with 0 broken packets, 0 dropped and 0 bad queue entries, and `net: stats:` with `, 4 ICMP echo requests answered,` and `, 100 datagrams echoed,`; `TEST PASS`. Record the versions, the offers, the section counts and sizes, and `netvsc`'s ignored messages (the host's notes count there) | the done-when on Hyper-V; the Hypervisor capability, SINT 2 and the SynIC frames on a real host; contact with no UNLOAD first; `SignalEvent` on a channel the host may monitor; the buffer sizes; the MAC Hyper-V assigned |
| `m9-net-mnf` | the same, with `through monitor page 2 and the event flags (netvsc.mnf=1)` in root's first `servers:` line; netvsc's offer line ends `, monitor trigger <t>` if the host may monitor the channel, and netvsc then signals through the monitor page, else with `SignalEvent` | FreeBSD's monitor-page signalling; with `m9-net`, which of the two the host takes |

Read a failed log from the top, since each server waits for the one
before it; the first of these that is missing says where it stopped:

1. `servers: Hyper-V: ...`. Without it, root's `TEST FAIL: servers: ...`
   names the invocation refused. `servers: no network: no Hypervisor
   capability in slot 12` means the kernel made none: its boot lines
   before root's say why (a privilege missing, or a hypercall page that
   did not enable).
2. `vmbus: version`. `vmbus: the host accepts none of VMBus 4.0, 3.0,
   2.4` or `vmbus: PostMessage of CONNECT: <status>` say what the host
   answered. No `vmbus:` line at all after root's `servers:` lines means
   no SINT 2 interrupt reached `vmbus`, or the host never answered
   CONNECT.
3. `vmbus: offer ...: netvsc` and `vmbus: netvsc channel ... open`.
   `vmbus: no netvsc offer` means the VM has no network adapter;
   `vmbus: netvsc channel <id>: the host refused <step> (status <s>)`
   names the GPADL or the open the host refused.
4. `netvsc: up`. A refused step is a `USER PANIC` line naming it, such as
   `netvsc: the host refused the receive buffer: ...`, after which the
   kernel halts and the script reads on until its timeout. The receive
   buffer's answer is a risk on a real host: `netvsc` checks that each
   section the host lays out lies inside its 1 MiB buffer, and the line
   gives the section's start, end, slot size and count and which of the
   three checks it failed. NVSP 4 or 2 in the up line means the host
   refused 5. In `m9-net-mnf`, nothing after the open line means the host
   did not take the monitor page's signal.
5. `net: gateway 192.168.77.1 is at`, the host's answer to `net`'s ARP
   request, the first frame `netvsc` sends. Missing while the pings and
   datagrams fail too, nothing `netvsc` sent reached the host. The other
   risk is there: from NVSP 5 FreeBSD adds a hash value to every frame it
   sends, which `netvsc` does not. `netvsc: stats:` then tells sent from
   lost: its `frames sent` against its `send completions`, and its
   `ignored messages`, where a send completion with a status other than
   OK is counted.
6. The `l4:` lines: a ping or datagram missing while the gateway's line
   came means frames from the host were lost; `netvsc: stats:` shows
   `packets skipped` and `dropped for no buffer`, and `net: stats:` the
   stack's drops by reason.

## Optional: the M4 check

The M4 self-test still runs on Hyper-V, though CI no longer uploads its
image: build it with `cargo xtask image --cmdline "test=retype"` and boot it
as below. It boots `test=retype`, M4's done-when self-test: the kernel prints its boot summary
with the BootInfo lines, then retypes the largest RAM untyped into every
object type, works the CNode operations on the results, revokes it, does
it all again, and checks that both runs give the same result. M4 does not
need this check, but its numbers are the first from real hardware:

```powershell
.\Test-L4Vhdx.ps1 -VhdxPath .\disk.vhdx -TimeoutSeconds 120 `
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
| `Read-L4Com1.ps1` | reads COM1 from the named pipe until a marker line; with `-Raw <file>` (M9), copies the pipe's bytes into the file as they come, off the script's thread, and reads the lines from it |
| `Test-L4Vhdx.ps1` | all of the above, plus the pass or fail verdict; with `-Scenario`, follows a scenario file, typing into COM1 and saving the screen (M8), and at a `udp_echo:` running `Send-L4Udp.ps1` (M9); `-Raw` as `Read-L4Com1.ps1`'s |
| `New-L4Switch.ps1` | (M9) once: the internal switch `l4-net` with the host at `192.168.77.1/24`, or `-Subnet`'s first address, and the VM's adapter on it |
| `Send-L4Udp.ps1` | (M9) pings the guest and has it echo UDP datagrams, as xtask's `udp_echo:` does |
| `Set-L4Cmdline.ps1` | (M9) writes another kernel command line into a VHDX, for a host whose network overlaps `192.168.77.0/24` |
| `m8-tui.scenario`, `m8-release.scenario` | the M8 check's scenarios; `golden/` holds the screens `m8-tui` must show |
| `m9-release-burst1.scenario`, `m9-release-burst15.scenario` | the M9 check's COM1 runs, with `uart`'s burst capped at 1 and at 15 and root's flood |
| `m9-net.scenario`, `m9-net-mnf.scenario` | the M9 check's network runs, M9's done-when on Hyper-V, with `netvsc` signalling the host by `SignalEvent` and through the monitor page |

To watch COM1 by hand instead, start the VM and run `.\Read-L4Com1.ps1`, or
connect PuTTY to the serial line `\\.\pipe\l4-com1`.
