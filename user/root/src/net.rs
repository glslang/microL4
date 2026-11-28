//! M9's network tests on QEMU (`docs/design.md`, "Network scenarios"):
//! `test=virtio_net`, `test=net`, the done-when, and `test=virtio_net_fault`.
//!
//! Each starts `watch`, `uart` and `console`, attaches as client 1 and
//! points its output at console, then sets up PCI and starts `virtio-net`
//! (140) with `servers::start_network`, and prints its `servers:` line
//! with the root CNode's slots in use.
//!
//! - `test=net` starts `net` (130) beside the driver, configured from the
//!   command line with QEMU's defaults (`10.0.2.15/24` via `10.0.2.2`),
//!   and reads a line as client 1, which the harness types once its
//!   datagrams are echoed. Then it asks the driver's and net's `Stats`,
//!   prints them, and requires `root::check::net`'s verdict: no bad queue
//!   entry or used element, no IP or UDP checksum error, no frame dropped
//!   for want of a buffer, and at least 100 datagrams echoed.
//! - `test=virtio_net` runs a probe thread of root's own instead of `net`,
//!   in root's VSpace on a copy of the frame queues' frame: it takes the
//!   link block, hands the driver the receive buffers, sends an ARP
//!   request for the gateway built with `net::arp`, and reports the reply
//!   to root, which prints it and the driver's `Stats` and checks them.
//! - `test=virtio_net_fault` (review) starts as `test=net` does, reads a
//!   line, and makes the driver fault at its next instruction: suspended,
//!   its `rip` written 0 and resumed, it fetches from page 0, which
//!   nothing maps. The fault goes to `watch`, which ends the run with
//!   failure, while root waits in a call to the dead driver.

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::console::Client;
use libsys::frames::{self, MAX_FRAME, Net};
use libsys::invoke::{tcb_resume, tcb_set_sched_params, tcb_suspend, tcb_write_registers};
use libsys::mem::Shared;
use libsys::proto::{VirtioNetStats, label};
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Registers, UserReg, call,
    println, recv, send, signal, wait,
};
use root::check::console::ROOT;
use root::check::net::{
    self as check, ArpLine, BadReply, Client as Beside, DriverLine, NetLine, Report, Started,
};
use root::network::{
    DRIVER_PRIORITY, NET_PRIORITY, ProbeError, ProbeReport, arp_reply, arp_request, default_config,
    probe_addresses, probe_word,
};
use root::process::{Fault, fault_kind};

use crate::fail;
use crate::servers::{self, Network, Peer};
use crate::spawn::{self, STACKS, Thread};

/// What runs once the network servers have started.
struct Running {
    ipc: Ipc,
    /// The root task as console's client 1.
    me: Client,
    network: Network,
    config: net::Config,
    /// For `test=virtio_net`: the probe's endpoint, its report and fault
    /// endpoint, and its TCB.
    probe: Option<(CPtr, CPtr)>,
}

/// `test=net`.
pub fn run(bi: &BootInfo) -> ! {
    let r = start(bi, "net", false);
    // The harness types Enter once its datagrams are echoed.
    read_line(&r, "net");
    let driver = driver_stats(&r).unwrap_or_else(|e| fail!("net: virtio-net's Stats: {e}"));
    println!("{}", DriverLine(driver));
    let report = stats::<{ Report::WORDS }>(&r, r.network.net_stats, label::NET_STATS)
        .map(Report::from_words)
        .unwrap_or_else(|e| fail!("net: net's Stats: {e}"));
    println!("{}", NetLine(report));
    check::net(&driver, &report).unwrap_or_else(|e| fail!("net: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
}

/// `test=virtio_net`: the driver without the stack.
pub fn virtio_net(bi: &BootInfo) -> ! {
    let r = start(bi, "virtio_net", true);
    let report = probe(&r);
    let mac = report
        .result
        .unwrap_or_else(|e| fail!("virtio_net: the probe: {e}"));
    println!(
        "{}",
        ArpLine {
            gateway: r.config.gateway(),
            mac
        }
    );
    println!(
        "virtio_net: the probe: {} frames sent, {} other frames taken before the reply",
        report.sent, report.skipped
    );
    let driver = driver_stats(&r).unwrap_or_else(|e| fail!("virtio_net: virtio-net's Stats: {e}"));
    println!("{}", DriverLine(driver));
    check::probe(&driver).unwrap_or_else(|e| fail!("virtio_net: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
}

/// `test=virtio_net_fault`: once net is up, the driver's next instruction
/// fetch is from address 0.
pub fn fault(bi: &BootInfo) -> ! {
    let test = "virtio_net_fault";
    let r = start(bi, test, false);
    read_line(&r, test);
    println!("{test}: suspending virtio-net, setting its rip to 0 and resuming it");
    // Every byte so far on the wire before the fault's line.
    r.me.sync()
        .unwrap_or_else(|e| fail!("{test}: root's Sync: {e}"));
    let tcb = r.network.driver_tcb;
    // Suspended, it leaves its receive; resumed, it fetches from address
    // 0, which no VSpace maps, and faults with a VMFault.
    tcb_suspend(tcb)
        .and_then(|()| {
            tcb_write_registers(r.ipc, tcb, true, &Registers::ZERO, UserReg::Rip.index() + 1)
        })
        .unwrap_or_else(|e| fail!("{test}: making virtio-net fault: {e}"));
    // The driver faults before it receives this; watch ends the run.
    let s = driver_stats(&r);
    println!("{test}: virtio-net answered Stats after its rip was set to 0: {s:?}");
    fail!("{test}: watch did not end the run")
}

/// Starts the servers, attaches, starts the network servers, with `net`
/// or, if `probe`, with the probe's objects, and prints the `servers:`
/// line.
fn start(bi: &BootInfo, test: &str, probe: bool) -> Running {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let s = servers::start(bi, ipc, &mut objects, None);
    let me = Client::new(s.client, Some(ipc));
    match me.attach("root") {
        Ok(ROOT) => {}
        other => fail!("{test}: root's Attach gave {other:?}, not client 1"),
    }
    // From here print! goes through console.
    libsys::output::use_console(s.client);
    // Before anything starts: the platform's defaults for what the
    // command line leaves out, QEMU's 10.0.2.15/24 via 10.0.2.2.
    let platform = servers::platform(bi);
    let config =
        net::Config::parse(bi.cmdline(), default_config(platform)).unwrap_or_else(|e| fail!("{e}"));
    let peer = if probe {
        Peer::Probe
    } else {
        Peer::Net(config)
    };
    let network = servers::start_network(bi, ipc, &mut objects, &s, platform, peer);
    // The probe's endpoint and TCB, before the count.
    let probe = probe.then(|| {
        let mut retype = |ty, what| {
            objects
                .retype(ipc, ty, 0, 1)
                .unwrap_or_else(|e| fail!("{test}: retyping the probe's {what}: {e}"))
        };
        (
            retype(ObjectType::Endpoint, "endpoint"),
            retype(ObjectType::Tcb, "TCB"),
        )
    });
    let slots = 1u64 << bi.root_cnode_bits;
    println!(
        "{}",
        Started {
            driver_priority: DRIVER_PRIORITY,
            irq: network.irq,
            client: if probe.is_some() {
                Beside::Probe
            } else {
                Beside::Net
            },
            client_priority: NET_PRIORITY,
            used: slots - objects.slots.remaining(),
            slots,
        }
    );
    Running {
        ipc,
        me,
        network,
        config,
        probe,
    }
}

/// Reads one line as client 1: the harness types it once what the test
/// waits for has happened.
fn read_line(r: &Running, test: &str) {
    let mut line = [0u8; libsys::console::MAX_LINE];
    r.me.read_line(&mut line)
        .unwrap_or_else(|e| fail!("{test}: root's Read: {e}"));
}

/// A `Stats` reply's `N` words from the server behind `cap`, or why the
/// reply is not one.
fn stats<const N: usize>(r: &Running, cap: CPtr, label: u64) -> Result<[u64; N], BadReply> {
    let reply = call(cap, &r.ipc.compose(label, &[], &[]));
    let info = reply.info;
    check::reply::<N>(info.label(), info.length(), |i| {
        r.ipc.received_word(&reply, i)
    })
}

/// virtio-net's `Stats`.
fn driver_stats(r: &Running) -> Result<VirtioNetStats, BadReply> {
    stats::<{ VirtioNetStats::WORDS }>(r, r.network.driver_stats, label::VIRTIO_NET_STATS)
        .map(VirtioNetStats::from_words)
}

/// Starts the probe thread at net's priority and waits on its endpoint
/// for its report; a fault of the probe's there, or anything else, fails
/// the test.
fn probe(r: &Running) -> ProbeReport {
    let Some((p, tcb)) = r.probe else {
        fail!("virtio_net: no probe objects")
    };
    let t = Thread {
        tcb,
        fault_ep: p,
        stack: STACKS[1],
        entry: probe_main,
        args: [p, r.network.nn, r.network.nv_frames, probe_word(&r.config)],
    };
    spawn::prepare(r.ipc, &t)
        .and_then(|()| tcb_set_sched_params(r.ipc, tcb, CAP_INIT_TCB, NET_PRIORITY, NET_PRIORITY))
        .and_then(|()| tcb_resume(tcb))
        .unwrap_or_else(|e| fail!("virtio_net: starting the probe: {e}"));
    let m = recv(p);
    let info = m.msg.info;
    if info.label() == ProbeReport::LABEL
        && info.length() == 4
        && let Some(report) = ProbeReport::from_words(m.msg.mr)
    {
        return report;
    }
    if fault_kind(info.label()).is_some() {
        fail!(
            "virtio_net: {}",
            Fault {
                who: "the probe",
                label: info.label(),
                mr: m.msg.mr
            }
        )
    }
    let [a, b, c, d] = m.msg.mr;
    fail!(
        "virtio_net: a message from the probe with label {:#x}, MR0 to MR3 {a:#x} {b:#x} {c:#x} {d:#x}",
        info.label()
    )
}

/// The probe: a thread in root's CSpace and VSpace, without an IPC
/// buffer, so it makes no call that needs one and never prints. It waits
/// on NN for the driver's first signal, takes the link block and hands
/// over the receive buffers, sends one ARP request for the gateway,
/// signals the driver through `nv`, and looks at every frame the driver
/// delivers until one is the reply; then it reports on `p` and waits on
/// NN for good.
extern "C" fn probe_main(p: CPtr, nn: CPtr, nv: CPtr, addresses: u64) -> ! {
    // SAFETY: `servers::start_qemu` mapped a copy of the frame queues'
    // frame, the one virtio-net maps, read-write and write-back at
    // `libsys::frames::WINDOW` in the root task's VSpace for this thread,
    // its only mapping there; it stays mapped for the run. The driver
    // writes it behind the compiler's back, and no other thread of this
    // VSpace names it, so nothing holds a reference into it: it is reached
    // only through `Shared`.
    let mem = unsafe { Shared::new(frames::WINDOW as *mut u8, frames::SIZE) };
    let mut queues = Net::new(mem);
    let report = arp(&mut queues, nn, nv, addresses);
    send(
        p,
        &Message::new(
            MessageInfo::new(ProbeReport::LABEL, 0, 0, 4),
            report.to_words(),
        ),
    );
    loop {
        wait(nn);
    }
}

/// The probe's work, after which it reports.
fn arp(queues: &mut Net<Shared>, nn: CPtr, nv: CPtr, addresses: u64) -> ProbeReport {
    let (ours, gateway) = probe_addresses(addresses);
    let failed = |e| ProbeReport {
        result: Err(e),
        skipped: 0,
        sent: 0,
    };
    // The driver signals once its link block is written.
    wait(nn);
    let Ok(link) = queues.attach() else {
        return failed(ProbeError::Link);
    };
    if queues.send(&arp_request(link.mac, ours, gateway)).is_err() {
        return failed(ProbeError::NoBuffer);
    }
    if queues.end_batch() {
        signal(nv);
    }
    let mut skipped = 0;
    let mut frame = [0u8; MAX_FRAME];
    loop {
        wait(nn);
        queues.reclaim();
        let mut found = None;
        while let Some(len) = queues.take_rx(&mut frame) {
            match arp_reply(&frame[..len.min(MAX_FRAME)], link.mac, ours, gateway) {
                Some(mac) if found.is_none() => found = Some(mac),
                _ => skipped += 1,
            }
        }
        // The buffers go back to the driver either way.
        if queues.end_batch() {
            signal(nv);
        }
        if let Some(mac) = found {
            return ProbeReport {
                result: Ok(mac),
                skipped,
                sent: queues.counters().sent,
            };
        }
    }
}
