//! The network servers' setup decisions that need no kernel
//! (`docs/design.md`, "Where the network servers run", "PCI on QEMU" and
//! "Network scenarios"): which platform's drivers root starts, the
//! windows it maps in their VSpaces and where they may lie, the words it
//! passes `virtio-net`, `vmbus`, `netvsc` and `net` in their registers,
//! the frames it maps for `vmbus` and `netvsc` and the checks of their
//! physical addresses, the command line's `netvsc.mnf=`, and the ARP
//! request and reply of `test=virtio_net`'s probe. The root task's
//! `servers.rs` and `net.rs` do the invocations; on Hyper-V no test runs
//! them before the owner's machine (QEMU's TCG has no SynIC), so every
//! decision they make is here.

use core::fmt;

use libsys::bootinfo::{CAP_SYNIC_EVENT_FRAME, CAP_SYNIC_MESSAGE_FRAME};
use libsys::frames::{self, Mac};
use net::arp::{self, Packet};
use net::ethernet::{self, Header};
use net::{Config, Ip};
use virtio_net::{Region, Start, StartError, Which};

use crate::process::{PAGE, PT_SPAN};

/// Priorities and MCPs (`docs/design.md`, "Where the network servers
/// run"): a driver above `net`, both below console (150), whose clients
/// they are. On Hyper-V, `vmbus` is above `netvsc`, its one client.
pub const VMBUS_PRIORITY: u64 = 145;
pub const DRIVER_PRIORITY: u64 = 140;
pub const NET_PRIORITY: u64 = 130;
/// The badge of root's own capabilities to the servers' endpoints:
/// `Stats` only.
pub const STATS_BADGE: u64 = 2;
/// Console's clients: `virtio-net` (or `vmbus`) 6, `netvsc` 7, `net` 8.
pub const DRIVER_CLIENT: u64 = 6;
pub const NETVSC_CLIENT: u64 = 7;
pub const NET_CLIENT: u64 = 8;

/// The windows the servers' VSpaces lie in: below the first GiB's end,
/// under the page directory the root image already uses.
pub const WINDOWS_END: u64 = 1 << 30;

// pci's regions are virtio-net's windows, in the same order.
const _: () = {
    assert!(pci::virtio::REGION_WINDOW == virtio_net::layout::REGION_WINDOW as u64);
    assert!(pci::Kind::Common.index() == Which::Common as usize);
    assert!(pci::Kind::Notify.index() == Which::Notify as usize);
    assert!(pci::Kind::Device.index() == Which::Device as usize);
    assert!(pci::virtio::MAX_REGION as usize == virtio_net::layout::REGION_MAX);
};

/// Which drivers root starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// `virtio-net` on PCI, found through ECAM.
    Qemu,
    /// `vmbus` and `netvsc` through the Hypervisor capability.
    HyperV,
}

/// Neither platform: no Hypervisor capability and no ECAM range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoPlatform;

impl fmt::Display for NoPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "servers: no network: no Hypervisor capability in slot 12 and no ECAM range in BootInfo",
        )
    }
}

impl Platform {
    /// Hyper-V when slot 12 holds a Hypervisor capability (the kernel
    /// makes one only on Hyper-V, with the hypercall page enabled), else
    /// QEMU when BootInfo lists an ECAM range (Hyper-V has no MCFG).
    pub const fn choose(hypervisor: bool, ecam_ranges: u64) -> Result<Platform, NoPlatform> {
        if hypervisor {
            Ok(Platform::HyperV)
        } else if ecam_ranges > 0 {
            Ok(Platform::Qemu)
        } else {
            Err(NoPlatform)
        }
    }
}

/// `net`'s configuration's defaults for what the command line leaves out:
/// QEMU user networking's on QEMU ([`Config::QEMU`]), none on Hyper-V,
/// where `net.ip=` and `net.gw=` are required (`docs/design.md`, "`net`").
pub const fn default_config(platform: Platform) -> Option<Config> {
    match platform {
        Platform::Qemu => Some(Config::QEMU),
        Platform::HyperV => None,
    }
}

/// A window root maps in a server's VSpace (or, for `test=virtio_net`'s
/// probe, its own): `bytes` from `start`, of 2 MiB frames mapped in the
/// page directory if `huge`, else of 4 KiB frames under page tables of
/// their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub name: &'static str,
    pub start: u64,
    pub bytes: u64,
    pub huge: bool,
}

impl Window {
    /// The 2 MiB blocks it takes: the page directory entries it fills or
    /// whose page tables it adds.
    const fn blocks(&self) -> (u64, u64) {
        let first = self.start & !(PT_SPAN - 1);
        let end = (self.start + self.bytes).next_multiple_of(PT_SPAN);
        (first, end)
    }
}

/// `virtio-net`'s windows: the DMA frame, the three regions' device
/// pages and the frame queues' original.
pub const VIRTIO_NET_WINDOWS: [Window; 3] = [
    Window {
        name: "the DMA frame",
        start: virtio_net::layout::DMA,
        bytes: virtio_net::layout::DMA_SIZE as u64,
        huge: true,
    },
    Window {
        name: "the virtio regions",
        start: virtio_net::layout::REGIONS,
        bytes: 3 * virtio_net::layout::REGION_WINDOW as u64,
        huge: false,
    },
    QUEUES,
];

/// `net`'s one window, the frame queues' copy; root maps the same in its
/// own VSpace for `test=virtio_net`'s probe.
pub const QUEUES: Window = Window {
    name: "the frame queues",
    start: frames::WINDOW,
    bytes: frames::SIZE as u64,
    huge: true,
};

/// Why a VSpace's windows do not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The window shares a 2 MiB block with the image's mapped pages (the
    /// IPC buffer and, in root's own VSpace, BootInfo's two pages
    /// included).
    Image {
        window: &'static str,
        image_end: u64,
    },
    /// It is not aligned as its frames are, or is empty.
    Alignment(&'static str),
    /// It passes [`WINDOWS_END`].
    TooHigh(&'static str),
    /// Two windows share a 2 MiB block.
    Overlap(&'static str, &'static str),
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WindowError::Image { window, image_end } => write!(
                f,
                "{window}'s window shares 2 MiB with the root image, which ends at {image_end:#x}"
            ),
            WindowError::Alignment(w) => write!(f, "{w}'s window is not aligned to its frames"),
            WindowError::TooHigh(w) => {
                write!(
                    f,
                    "{w}'s window passes {WINDOWS_END:#x}, the first GiB's end"
                )
            }
            WindowError::Overlap(a, b) => write!(f, "{a}'s and {b}'s windows share 2 MiB"),
        }
    }
}

/// Checks `windows` for a VSpace that maps the root image up to
/// `image_end`, BootInfo's `user_image_end`: each is aligned to its
/// frames and not empty, lies above the 2 MiB that holds the image's last
/// mapped page (its IPC buffer, and BootInfo's two pages after it in
/// root's VSpace) and below [`WINDOWS_END`], and shares no 2 MiB block
/// with another, so each 4 KiB window's page tables are its own and each
/// 2 MiB frame fills an empty page directory entry.
pub fn check_windows(image_end: u64, windows: &[Window]) -> Result<(), WindowError> {
    let mapped_end = image_end + 3 * PAGE;
    let image_blocks_end = mapped_end.next_multiple_of(PT_SPAN);
    for (i, w) in windows.iter().enumerate() {
        let align = if w.huge { PT_SPAN } else { PAGE };
        if w.bytes == 0 || !w.start.is_multiple_of(align) || !w.bytes.is_multiple_of(align) {
            return Err(WindowError::Alignment(w.name));
        }
        let (first, end) = w.blocks();
        if first < image_blocks_end {
            return Err(WindowError::Image {
                window: w.name,
                image_end,
            });
        }
        if end > WINDOWS_END {
            return Err(WindowError::TooHigh(w.name));
        }
        for v in &windows[..i] {
            let (vf, ve) = v.blocks();
            if first < ve && vf < end {
                return Err(WindowError::Overlap(v.name, w.name));
            }
        }
    }
    Ok(())
}

/// `virtio-net`'s arguments for the function `plan` describes and the DMA
/// frame at physical `dma`: each region's offset in its first page and
/// its length, and the notify multiplier, checked as the driver's entry
/// stub checks them ([`Start::from_words`] of [`Start::to_words`]), so a
/// word root would pass that the driver refuses fails in root instead.
pub fn virtio_net_start(plan: &pci::Plan, dma: u64) -> Result<Start, StartError> {
    let region = |w: Which| {
        let r = plan.regions[w as usize];
        Region {
            offset: r.in_page() as u16,
            // A length past 16 bits is refused as leaving its window.
            len: u16::try_from(r.length).unwrap_or(u16::MAX),
        }
    };
    let start = Start {
        dma,
        common: region(Which::Common),
        notify: region(Which::Notify),
        device: region(Which::Device),
        multiplier: plan.notify_off_multiplier,
    };
    Start::from_words(start.to_words())
}

/// `net`'s arguments: the configuration `Config::parse` takes from the
/// command line, QEMU's default for each word it leaves out
/// (`Some(Config::QEMU)`) or none on Hyper-V, as [`Config::to_words`]
/// lays it out and `net`'s entry stub checks it again.
pub fn net_words(config: &Config) -> [u64; 4] {
    config.to_words()
}

/// The SINT VMBus sends its messages and channel events on (FreeBSD's
/// `VMBUS_SINT_MESSAGE`), which root issues with `IRQControl_GetSint`.
pub const VMBUS_SINT: u64 = vmbus::synic::SINT as u64;

/// `vmbus`'s one window: the SynIC frames (initial slots 13 and 14), each
/// a 4 KiB page under a page table of its own.
pub const VMBUS_WINDOWS: [Window; 1] = [Window {
    name: "the SynIC frames",
    start: vmbus::layout::SYNIC,
    bytes: 2 * PAGE,
    huge: false,
}];

/// `netvsc`'s windows: the channel frame, the monitor window (mapped only
/// with `netvsc.mnf=1`, but checked always) and the frame queues'
/// original.
pub const NETVSC_WINDOWS: [Window; 3] = [
    Window {
        name: "the channel frame",
        start: netvsc::layout::CHANNEL,
        bytes: netvsc::layout::CHANNEL_SIZE as u64,
        huge: true,
    },
    Window {
        name: "the monitor window",
        start: netvsc::layout::MNF,
        bytes: netvsc::layout::MNF_SIZE as u64,
        huge: false,
    },
    QUEUES,
];

/// Where root maps the SynIC frames in `vmbus`'s VSpace: the root slot
/// of each and its address, the message frame at `vmbus::layout::SIM`,
/// the event-flag frame at `vmbus::layout::SIEF`.
pub const SYNIC_FRAMES: [(u64, u64); 2] = [
    (CAP_SYNIC_MESSAGE_FRAME, vmbus::layout::SIM),
    (CAP_SYNIC_EVENT_FRAME, vmbus::layout::SIEF),
];

/// The pages `vmbus` names to the host in CONNECT besides its GPADLs:
/// monitor page 1, monitor page 2 and the event-flags page, three 4 KiB
/// frames root retypes in one `Untyped_Retype`, which places them at
/// consecutive physical addresses in that order.
pub const MONITOR_FRAMES: u64 = 3;

/// Where root maps two of them in `netvsc`'s VSpace with `netvsc.mnf=1`:
/// each frame's index among the [`MONITOR_FRAMES`] and its address.
/// Monitor page 2 (the guest-to-host one) at the window's start, the
/// event-flags page a page above it, as `netvsc::layout` reads them.
pub const MNF_FRAMES: [(u64, u64); 2] = [
    (1, netvsc::layout::MNF + netvsc::layout::MNF_MONITOR as u64),
    (
        2,
        netvsc::layout::MNF + netvsc::layout::MNF_EVENT_FLAGS as u64,
    ),
];

// vmbus's and netvsc's layouts agree with what root maps and passes.
const _: () = {
    assert!(VMBUS_SINT == 2);
    assert!(vmbus::layout::SIM == vmbus::layout::SYNIC);
    assert!(vmbus::layout::SIEF == vmbus::layout::SYNIC + PAGE);
    assert!(vmbus::layout::PAGE == PAGE);
    assert!(netvsc::layout::PAGE as u64 == PAGE);
    assert!(netvsc::layout::CHANNEL_SIZE as u64 == vmbus::Start::CHANNEL_SIZE);
    assert!(netvsc::layout::CHANNEL_SIZE as u64 == PT_SPAN);
    assert!(netvsc::layout::MNF_SIZE as u64 == 2 * PAGE);
    assert!(netvsc::layout::MNF_MONITOR == 0);
    assert!(netvsc::layout::MNF_EVENT_FLAGS as u64 == PAGE);
};

/// The command line's `netvsc.mnf=<v>` word (`docs/design.md`, "Where the
/// network servers run"): `1` has `netvsc` signal the host as FreeBSD's
/// `vmbus_chan_signal` does, through the event-flags page and monitor
/// page 2, which root then maps in its VSpace; `0`, or no word,
/// `SignalEvent`. Any other value fails the test, so that a command line
/// written by hand (`Set-L4Cmdline.ps1`) cannot run the other way
/// unnoticed.
pub fn mnf(cmdline: &str) -> Result<bool, BadMnf<'_>> {
    match libsys::cmdline::value(cmdline, BadMnf::KEY) {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(v) => Err(BadMnf(v)),
    }
}

/// A `netvsc.mnf=` value other than 0 or 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadMnf<'a>(pub &'a str);

impl BadMnf<'_> {
    /// The word's key.
    pub const KEY: &'static str = "netvsc.mnf";
}

impl fmt::Display for BadMnf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "servers: {}={:?}: not 0 or 1", Self::KEY, self.0)
    }
}

/// Why root's words for `vmbus` or `netvsc` would be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HyperVError {
    /// The monitor pages and the event-flags page, by their physical
    /// addresses, are not three consecutive pages.
    Pages([u64; MONITOR_FRAMES as usize]),
    /// Words `vmbus::Start::from_words` refuses.
    Vmbus([u64; 4]),
    /// Words `netvsc::Start::from_words` refuses.
    Netvsc([u64; 4]),
}

impl fmt::Display for HyperVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HyperVError::Pages([a, b, c]) => write!(
                f,
                "the monitor pages and the event-flags page are at {a:#x}, {b:#x} and {c:#x}, not three consecutive pages"
            ),
            HyperVError::Vmbus([a, b, c, d]) => {
                write!(f, "vmbus would refuse {a:#x} {b:#x} {c:#x} {d:#x}")
            }
            HyperVError::Netvsc([a, b, c, d]) => {
                write!(f, "netvsc would refuse {a:#x} {b:#x} {c:#x} {d:#x}")
            }
        }
    }
}

/// `vmbus`'s arguments for the channel frame at physical `channel` and
/// the [`MONITOR_FRAMES`] at `pages`, as `Frame_GetAddress` gave them:
/// the pages must be consecutive (one `Untyped_Retype` placed them, and
/// `netvsc` maps the second as monitor page 2), and the words are checked
/// as `vmbus`'s entry stub checks them, so a word it would refuse fails in
/// root instead. `tsc_hz`, BootInfo's, times vmbus's waits between
/// `PostMessage` retries.
pub fn vmbus_start(
    channel: u64,
    pages: [u64; MONITOR_FRAMES as usize],
    tsc_hz: u64,
) -> Result<vmbus::Start, HyperVError> {
    let [monitor, monitor2, event_flags] = pages;
    if monitor.checked_add(PAGE) != Some(monitor2)
        || monitor2.checked_add(PAGE) != Some(event_flags)
    {
        return Err(HyperVError::Pages(pages));
    }
    let words = vmbus::Start {
        channel,
        monitor,
        event_flags,
        tsc_hz,
    }
    .to_words();
    vmbus::Start::from_words(words).ok_or(HyperVError::Vmbus(words))
}

/// `netvsc`'s arguments for the channel frame at physical `channel`, with
/// `netvsc.mnf=1`'s signalling if `mnf`, checked as its entry stub checks
/// them.
pub fn netvsc_start(channel: u64, mnf: bool) -> Result<netvsc::Start, HyperVError> {
    let words = netvsc::Start { channel, mnf }.to_words();
    netvsc::Start::from_words(words).ok_or(HyperVError::Netvsc(words))
}

/// The line root prints once the Hyper-V servers' frames are made and
/// checked, before it starts them: `servers: Hyper-V: SINT 2 is IRQ <n>;
/// channel frame <a>, monitor pages <m> and <m + 0x1000>, event flags
/// <e>; netvsc signals the host with SignalEvent` (or `through monitor
/// page 2 and the event flags (netvsc.mnf=1)`): the pages `vmbus` names
/// to the host, and which way `netvsc` rings it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HyperVLine {
    pub irq: u8,
    pub vmbus: vmbus::Start,
    pub mnf: bool,
}

impl fmt::Display for HyperVLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &self.vmbus;
        write!(
            f,
            "servers: Hyper-V: SINT {VMBUS_SINT} is IRQ {}; channel frame {:#x}, monitor pages {:#x} and {:#x}, event flags {:#x}; netvsc signals the host ",
            self.irq,
            s.channel,
            s.monitor,
            s.monitor2(),
            s.event_flags
        )?;
        if self.mnf {
            f.write_str("through monitor page 2 and the event flags (netvsc.mnf=1)")
        } else {
            f.write_str("with SignalEvent")
        }
    }
}

/// The addresses `test=virtio_net`'s probe uses: `config`'s address and
/// gateway, `10.0.2.15` and `10.0.2.2` on QEMU, in one word, the address
/// in the low half: its fourth argument.
pub const fn probe_word(config: &Config) -> u64 {
    config.address().to_u32() as u64 | (config.gateway().to_u32() as u64) << 32
}

/// The address and the gateway in [`probe_word`]'s word.
pub const fn probe_addresses(word: u64) -> (Ip, Ip) {
    (Ip::from_u32(word as u32), Ip::from_u32((word >> 32) as u32))
}

/// The ARP request `test=virtio_net`'s probe sends from `mac` at `ours`
/// for `gateway`: broadcast, built with `net::arp` and padded to 60
/// bytes, as `net` sends one.
pub fn arp_request(mac: Mac, ours: Ip, gateway: Ip) -> [u8; ethernet::MIN_PADDED] {
    let mut frame = [0u8; ethernet::MIN_PADDED];
    Header {
        dst: Mac::BROADCAST,
        src: mac,
        ethertype: ethernet::ARP,
    }
    .write(&mut frame);
    Packet {
        op: arp::REQUEST,
        sha: mac,
        spa: ours,
        tha: Mac::ZERO,
        tpa: gateway,
    }
    .write(&mut frame[ethernet::HEADER..]);
    frame
}

/// The gateway's MAC if `frame` is the reply to [`arp_request`]: an ARP
/// reply to `mac` and `ours` from `gateway`, with a unicast sender MAC;
/// `None` for any other frame.
pub fn arp_reply(frame: &[u8], mac: Mac, ours: Ip, gateway: Ip) -> Option<Mac> {
    let (h, body) = Header::parse(frame)?;
    if h.ethertype != ethernet::ARP || h.dst != mac {
        return None;
    }
    let p = Packet::parse(body)?;
    let ours = p.op == arp::REPLY
        && p.spa == gateway
        && p.tpa == ours
        && p.tha == mac
        && p.sha.is_unicast();
    ours.then_some(p.sha)
}

/// What `test=virtio_net`'s probe reports to root on its endpoint, in MR0
/// to MR3 (it has no IPC buffer): the gateway's MAC, and the frames it
/// took before the reply and sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    pub result: Result<Mac, ProbeError>,
    /// Frames it took from `RX_FILLED` that were not the reply.
    pub skipped: u64,
    /// Frames it pushed on `TX_FILLED`: its one request.
    pub sent: u64,
}

/// Why the probe found no reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The link block was refused: `libsys::frames::LinkError`'s text is
    /// the driver's; the probe gives its code.
    Link,
    /// No transmit buffer was free for the request.
    NoBuffer,
}

impl ProbeReport {
    /// The label of the probe's report on its endpoint, which is also its
    /// fault endpoint: no fault label (1 to 4) and no protocol's.
    pub const LABEL: u64 = 0x1F0;

    pub fn to_words(&self) -> [u64; 4] {
        let (code, mac) = match self.result {
            Ok(mac) => (0, mac.to_word()),
            Err(ProbeError::Link) => (1, 0),
            Err(ProbeError::NoBuffer) => (2, 0),
        };
        [code, mac, self.skipped, self.sent]
    }

    /// The report in these words; `None` for words
    /// [`ProbeReport::to_words`] never makes.
    pub fn from_words(w: [u64; 4]) -> Option<ProbeReport> {
        let result = match (w[0], w[1]) {
            (0, mac) if mac >> 48 == 0 => Ok(Mac::from_word(mac)),
            (1, 0) => Err(ProbeError::Link),
            (2, 0) => Err(ProbeError::NoBuffer),
            _ => return None,
        };
        Some(ProbeReport {
            result,
            skipped: w[2],
            sent: w[3],
        })
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Link => f.write_str("the frame queues' link block was refused"),
            ProbeError::NoBuffer => f.write_str("no transmit buffer was free for the ARP request"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::frames::MAX_FRAME;
    use pci::{Kind, Location, Msix, Plan};
    use std::string::ToString;

    /// The plan `test=pci` prints for QEMU's virtio-net-pci at 00:02.0:
    /// common, device and notify at BAR4 + 0x0, 0x2000 and 0x3000, 4 KiB
    /// each, with BAR4 at `0xc0_0000_0000`, multiplier 4; MSI-X's table at
    /// BAR1 + 0, BAR1 at `0x8101_1000`.
    fn qemu() -> Plan {
        let bar4 = 0xC0_0000_0000;
        let region = |kind, cap, offset| pci::Region {
            kind,
            cap,
            bar: 4,
            offset,
            length: 0x1000,
            paddr: bar4 + u64::from(offset),
        };
        Plan {
            function: pci::Address::new(0, 2, 0).unwrap(),
            regions: [
                region(Kind::Common, 0x70, 0),
                region(Kind::Notify, 0x58, 0x3000),
                region(Kind::Device, 0x60, 0x2000),
            ],
            notify_off_multiplier: 4,
            msix: Msix {
                cap: 0x98,
                control: 0x0003,
                vectors: 4,
                table: Location { bar: 1, offset: 0 },
                pba: Location {
                    bar: 1,
                    offset: 0x800,
                },
            },
            table: 0x8101_1000,
            pba: 0x8101_1800,
        }
    }

    #[test]
    fn the_platform() {
        assert_eq!(Platform::choose(false, 1), Ok(Platform::Qemu));
        assert_eq!(Platform::choose(true, 0), Ok(Platform::HyperV));
        // A Hypervisor capability decides, whatever the MCFG says.
        assert_eq!(Platform::choose(true, 1), Ok(Platform::HyperV));
        assert_eq!(Platform::choose(false, 0), Err(NoPlatform));
        assert_eq!(
            NoPlatform.to_string(),
            "servers: no network: no Hypervisor capability in slot 12 and no ECAM range in BootInfo"
        );
    }

    #[test]
    fn the_priorities_and_clients() {
        // Below console (150), vmbus above netvsc, a driver above net.
        const { assert!(150 > VMBUS_PRIORITY && VMBUS_PRIORITY > DRIVER_PRIORITY) };
        const { assert!(DRIVER_PRIORITY > NET_PRIORITY) };
        // Console's clients are 1 to 8; 4 is its raw client (term), 5 tui.
        for c in [DRIVER_CLIENT, NETVSC_CLIENT, NET_CLIENT] {
            assert!((6..=8).contains(&c));
        }
    }

    /// The windows `docs/design.md` gives fit above an image that ends
    /// below `0xC0_0000`, as M8's does, and the checks refuse each way a
    /// window could go wrong.
    #[test]
    fn the_windows() {
        let end = 0xBF_F000;
        assert_eq!(check_windows(end, &VIRTIO_NET_WINDOWS), Ok(()));
        assert_eq!(check_windows(end, &[QUEUES]), Ok(()));
        // An image whose BootInfo pages reach the DMA frame's 2 MiB.
        let image_end = virtio_net::layout::DMA - 3 * PAGE + 1;
        assert_eq!(
            check_windows(image_end, &VIRTIO_NET_WINDOWS),
            Err(WindowError::Image {
                window: "the DMA frame",
                image_end
            })
        );
        // One that ends one page short is fine: its last page is in the
        // 2 MiB below.
        assert_eq!(
            check_windows(virtio_net::layout::DMA - 3 * PAGE, &VIRTIO_NET_WINDOWS),
            Ok(())
        );
        let w = |name, start, bytes, huge| Window {
            name,
            start,
            bytes,
            huge,
        };
        assert_eq!(
            check_windows(end, &[w("a", 0x0810_0000, 0x20_0000, true)]),
            Err(WindowError::Alignment("a"))
        );
        assert_eq!(
            check_windows(end, &[w("a", 0x0800_0800, 0x1000, false)]),
            Err(WindowError::Alignment("a"))
        );
        assert_eq!(
            check_windows(end, &[w("a", 0x0800_0000, 0, false)]),
            Err(WindowError::Alignment("a"))
        );
        assert_eq!(
            check_windows(end, &[w("a", 0x3FE0_0000, 0x40_0000, true)]),
            Err(WindowError::TooHigh("a"))
        );
        // 4 KiB pages in a 2 MiB frame's block, or two windows at once.
        assert_eq!(
            check_windows(
                end,
                &[
                    w("dma", 0x0800_0000, 0x20_0000, true),
                    w("regs", 0x081F_F000, 0x1000, false),
                ]
            ),
            Err(WindowError::Overlap("dma", "regs"))
        );
        assert_eq!(
            check_windows(
                end,
                &[
                    w("a", 0x0C00_0000, 0x1000, false),
                    w("b", 0x0C1F_0000, 0x1000, false),
                ]
            ),
            Err(WindowError::Overlap("a", "b"))
        );
        assert_eq!(
            WindowError::Overlap("a", "b").to_string(),
            "a's and b's windows share 2 MiB"
        );
        assert_eq!(
            WindowError::Image {
                window: "the DMA frame",
                image_end: 0x800_0000
            }
            .to_string(),
            "the DMA frame's window shares 2 MiB with the root image, which ends at 0x8000000"
        );
    }

    /// The words root passes virtio-net for QEMU's device: what
    /// `docs/design.md`'s "Arguments" table gives, and what the driver's
    /// entry stub takes back.
    #[test]
    fn virtio_nets_words() {
        let dma = 0x0360_0000;
        let start = virtio_net_start(&qemu(), dma).unwrap();
        let words = start.to_words();
        assert_eq!(
            words,
            [
                dma,
                // Common at offset 0 of its page, 4 KiB; notify the same.
                0x1000_0000 | 0x1000_0000 << 32,
                0x1000_0000,
                4,
            ]
        );
        assert_eq!(Start::from_words(words), Ok(start));
        // Each window is where root maps its region's pages.
        for (w, k) in Which::ALL.into_iter().zip(Kind::ALL) {
            let (addr, len) = start.window(w);
            let page = qemu().pages().find(|p| p.kind == k).unwrap();
            assert_eq!(addr, virtio_net::layout::REGIONS + page.offset);
            assert_eq!(len, 0x1000);
        }
        // A region that starts inside its page keeps the offset.
        let mut plan = qemu();
        plan.regions[2].paddr += 0x40;
        plan.regions[2].offset += 0x40;
        plan.regions[2].length = 0x20;
        let start = virtio_net_start(&plan, dma).unwrap();
        assert_eq!(start.to_words()[2], 0x0020_0040);
        assert_eq!(
            start.window(Which::Device).0,
            virtio_net::layout::REGIONS + 0x2_0040
        );
    }

    /// What the driver would refuse, root refuses first.
    #[test]
    fn virtio_nets_words_refused() {
        use virtio_net::StartError::*;
        assert_eq!(virtio_net_start(&qemu(), 0), Err(Dma(0)));
        assert_eq!(
            virtio_net_start(&qemu(), 0x0360_1000),
            Err(Dma(0x0360_1000))
        );
        let mut plan = qemu();
        plan.notify_off_multiplier = 6;
        assert_eq!(virtio_net_start(&plan, 1 << 21), Err(Multiplier(6)));
        let mut plan = qemu();
        plan.regions[0].length = 40;
        assert!(matches!(
            virtio_net_start(&plan, 1 << 21),
            Err(Short {
                which: Which::Common,
                len: 40
            })
        ));
        // A length past 16 bits leaves its window.
        let mut plan = qemu();
        plan.regions[1].length = 0x1_0000;
        assert!(matches!(
            virtio_net_start(&plan, 1 << 21),
            Err(Region {
                which: Which::Notify,
                ..
            })
        ));
    }

    /// net's words for QEMU's default and for the command line's own.
    #[test]
    fn nets_words() {
        let qemu = Config::parse("test=net", default_config(Platform::Qemu)).unwrap();
        assert_eq!(qemu, Config::QEMU);
        let w = net_words(&qemu);
        assert_eq!(w, [0x0A00_020F | 24 << 32, 0x0A00_0202, 0, 0]);
        assert_eq!(Config::from_words(w), Some(qemu));
        let c = Config::parse(
            "test=net net.ip=192.168.77.10/24 net.gw=192.168.77.1",
            Some(Config::QEMU),
        )
        .unwrap();
        assert_eq!(net_words(&c), [0xC0A8_4D0A | 24 << 32, 0xC0A8_4D01, 0, 0]);
        assert_eq!(Config::from_words(net_words(&c)), Some(c));
        // On Hyper-V there is no default.
        let hyperv = default_config(Platform::HyperV);
        assert_eq!(
            Config::parse("test=net", hyperv),
            Err(net::ConfigError::NoAddress)
        );
        assert_eq!(
            Config::parse("test=net net.ip=192.168.77.10/24", hyperv),
            Err(net::ConfigError::NoAddress)
        );
        assert_eq!(
            Config::parse(
                "net.ip=192.168.77.10/24 net.gw=192.168.77.1 test=net",
                hyperv
            ),
            Ok(c)
        );
    }

    /// The Hyper-V servers' windows fit above an image that ends below
    /// `0xC0_0000`, as M8's does, each in its own VSpace's list, and the
    /// frames root maps lie in them.
    #[test]
    fn the_hyperv_windows() {
        let end = 0xBF_F000;
        assert_eq!(check_windows(end, &VMBUS_WINDOWS), Ok(()));
        assert_eq!(check_windows(end, &NETVSC_WINDOWS), Ok(()));
        let inside = |w: &Window, addr: u64| w.start <= addr && addr + PAGE <= w.start + w.bytes;
        for (slot, addr) in SYNIC_FRAMES {
            assert!(inside(&VMBUS_WINDOWS[0], addr), "slot {slot} at {addr:#x}");
        }
        assert_eq!(SYNIC_FRAMES.map(|(slot, _)| slot), [13, 14]);
        assert_ne!(SYNIC_FRAMES[0].1, SYNIC_FRAMES[1].1);
        for (i, addr) in MNF_FRAMES {
            assert!(i < MONITOR_FRAMES);
            assert!(inside(&NETVSC_WINDOWS[1], addr), "frame {i} at {addr:#x}");
        }
        assert_ne!(MNF_FRAMES[0].1, MNF_FRAMES[1].1);
        // An image whose last pages reach the SynIC window's 2 MiB.
        assert_eq!(
            check_windows(vmbus::layout::SYNIC - 2 * PAGE, &VMBUS_WINDOWS),
            Err(WindowError::Image {
                window: "the SynIC frames",
                image_end: vmbus::layout::SYNIC - 2 * PAGE
            })
        );
    }

    /// `netvsc.mnf=`: 1 or 0, or no word; anything else is refused.
    #[test]
    fn the_netvsc_mnf_word() {
        assert_eq!(mnf("test=net net.ip=192.168.77.2/24"), Ok(false));
        assert_eq!(mnf("test=net netvsc.mnf=1"), Ok(true));
        assert_eq!(mnf("netvsc.mnf=0 test=net"), Ok(false));
        // The first word wins, as for every key.
        assert_eq!(mnf("netvsc.mnf=1 netvsc.mnf=0"), Ok(true));
        // Other keys are not it.
        assert_eq!(mnf("netvsc.mnfx=1 xnetvsc.mnf=1"), Ok(false));
        for v in ["", "2", "01", "yes", "true", "1,", "0x1"] {
            let line = std::format!("test=net netvsc.mnf={v}");
            assert_eq!(mnf(&line), Err(BadMnf(v)), "{line:?}");
        }
        // A bare key has the empty value.
        assert_eq!(mnf("test=net netvsc.mnf"), Err(BadMnf("")));
        assert_eq!(
            BadMnf("yes").to_string(),
            "servers: netvsc.mnf=\"yes\": not 0 or 1"
        );
    }

    /// vmbus's and netvsc's words, as `docs/design.md`'s "Arguments"
    /// table gives them and their entry stubs take them back, and the
    /// pages netvsc maps with `netvsc.mnf=1` are the ones vmbus names to
    /// the host.
    #[test]
    fn vmbus_and_netvscs_words() {
        let channel = 0x1_4000_0000;
        let m = 0x0FF3_D000;
        let pages = [m, m + PAGE, m + 2 * PAGE];
        let s = vmbus_start(channel, pages, 2_400_000_000).unwrap();
        assert_eq!(s.to_words(), [channel, m, m + 2 * PAGE, 2_400_000_000]);
        assert_eq!(vmbus::Start::from_words(s.to_words()), Some(s));
        assert_eq!(s.monitor2(), m + PAGE);
        // netvsc's monitor window: monitor page 2, then the event flags,
        // as vmbus told the host they are.
        for (i, addr) in MNF_FRAMES {
            let want = match addr - netvsc::layout::MNF {
                0 => s.monitor2(),
                PAGE => s.event_flags,
                o => panic!("offset {o:#x} in the monitor window"),
            };
            assert_eq!(pages[i as usize], want, "frame {i}");
        }
        for mnf in [false, true] {
            let n = netvsc_start(channel, mnf).unwrap();
            assert_eq!(n.to_words(), [channel, mnf as u64, 0, 0]);
            assert_eq!(netvsc::Start::from_words(n.to_words()), Some(n));
            assert_eq!(n.channel_page(0), s.channel_page(0));
        }
    }

    /// What vmbus or netvsc would refuse, root refuses first, and pages
    /// out of order are refused before vmbus sees them.
    #[test]
    fn vmbus_and_netvscs_words_refused() {
        let channel = 0x1_4000_0000;
        let m = 0x0FF3_D000;
        for pages in [
            [m, m + 2 * PAGE, m + 3 * PAGE],
            [m, m + PAGE, m + 3 * PAGE],
            [m + 2 * PAGE, m + PAGE, m],
            [m, m, m],
            [u64::MAX - PAGE + 1, 0, PAGE],
        ] {
            assert_eq!(
                vmbus_start(channel, pages, 0),
                Err(HyperVError::Pages(pages)),
                "{pages:x?}"
            );
        }
        let pages = [m, m + PAGE, m + 2 * PAGE];
        for bad in [0, channel + PAGE, channel + (1 << 20), 1 << 52] {
            assert_eq!(
                vmbus_start(bad, pages, 0),
                Err(HyperVError::Vmbus([bad, m, m + 2 * PAGE, 0])),
                "{bad:#x}"
            );
        }
        // The pages inside the channel frame, or at 0.
        let inside = [channel + PAGE, channel + 2 * PAGE, channel + 3 * PAGE];
        assert!(matches!(
            vmbus_start(channel, inside, 0),
            Err(HyperVError::Vmbus(_))
        ));
        assert!(matches!(
            vmbus_start(channel, [0, PAGE, 2 * PAGE], 0),
            Err(HyperVError::Vmbus(_))
        ));
        for bad in [0, 0x1000, 0x30_0000] {
            assert_eq!(
                netvsc_start(bad, true),
                Err(HyperVError::Netvsc([bad, 1, 0, 0]))
            );
        }
        assert_eq!(
            HyperVError::Pages([0x5000, 0x7000, 0x8000]).to_string(),
            "the monitor pages and the event-flags page are at 0x5000, 0x7000 and 0x8000, not three consecutive pages"
        );
        assert_eq!(
            HyperVError::Vmbus([0x1000, 0x5000, 0x7000, 0]).to_string(),
            "vmbus would refuse 0x1000 0x5000 0x7000 0x0"
        );
        assert_eq!(
            HyperVError::Netvsc([0x1000, 1, 0, 0]).to_string(),
            "netvsc would refuse 0x1000 0x1 0x0 0x0"
        );
    }

    #[test]
    fn the_hyperv_line() {
        let s = vmbus_start(0x1_4000_0000, [0xFF3_D000, 0xFF3_E000, 0xFF3_F000], 0).unwrap();
        let line = |mnf| {
            HyperVLine {
                irq: 1,
                vmbus: s,
                mnf,
            }
            .to_string()
        };
        assert_eq!(
            line(false),
            "servers: Hyper-V: SINT 2 is IRQ 1; channel frame 0x140000000, monitor pages 0xff3d000 and 0xff3e000, event flags 0xff3f000; netvsc signals the host with SignalEvent"
        );
        assert!(line(true).ends_with(
            "; netvsc signals the host through monitor page 2 and the event flags (netvsc.mnf=1)"
        ));
        // Not the servers: line the scenarios expect.
        assert!(!line(false).starts_with("servers: vmbus ("));
    }

    #[test]
    fn the_probes_arp_request_and_reply() {
        let mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let slirp = Mac([0x52, 0x55, 10, 0, 2, 2]);
        let c = Config::QEMU;
        let word = probe_word(&c);
        assert_eq!(word, 0x0A00_0202_0A00_020F);
        let (ours, gw) = probe_addresses(word);
        assert_eq!((ours, gw), (Ip::new(10, 0, 2, 15), Ip::new(10, 0, 2, 2)));
        let req = arp_request(mac, ours, gw);
        let want: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 0x08,
            0x06, //
            0, 1, 0x08, 0, 6, 4, 0, 1, // Ethernet, IPv4, request
            0x52, 0x54, 0, 0x12, 0x34, 0x56, 10, 0, 2, 15, // sender
            0, 0, 0, 0, 0, 0, 10, 0, 2, 2, // target
        ];
        assert_eq!(&req[..42], &want);
        assert!(req[42..].iter().all(|&b| b == 0));
        assert!(req.len() <= MAX_FRAME);
        // libslirp's reply, unpadded.
        let mut reply = [0u8; 42];
        Header {
            dst: mac,
            src: slirp,
            ethertype: ethernet::ARP,
        }
        .write(&mut reply);
        let p = Packet {
            op: arp::REPLY,
            sha: slirp,
            spa: gw,
            tha: mac,
            tpa: ours,
        };
        p.write(&mut reply[14..]);
        assert_eq!(arp_reply(&reply, mac, ours, gw), Some(slirp));
        // Padded as well.
        let mut padded = [0u8; 60];
        padded[..42].copy_from_slice(&reply);
        assert_eq!(arp_reply(&padded, mac, ours, gw), Some(slirp));
        // Not the reply: the request itself, other senders, targets,
        // operations, a group MAC, another destination, cut short.
        assert_eq!(arp_reply(&req, mac, ours, gw), None);
        let other = |q: Packet, dst: Mac| {
            let mut f = [0u8; 42];
            Header {
                dst,
                src: slirp,
                ethertype: ethernet::ARP,
            }
            .write(&mut f);
            q.write(&mut f[14..]);
            arp_reply(&f, mac, ours, gw)
        };
        assert_eq!(other(p, mac), Some(slirp));
        for (q, dst) in [
            (
                Packet {
                    spa: Ip::new(10, 0, 2, 3),
                    ..p
                },
                mac,
            ),
            (
                Packet {
                    tpa: Ip::new(10, 0, 2, 16),
                    ..p
                },
                mac,
            ),
            (Packet { tha: slirp, ..p }, mac),
            (
                Packet {
                    op: arp::REQUEST,
                    ..p
                },
                mac,
            ),
            (
                Packet {
                    sha: Mac([1, 0, 0x5e, 0, 0, 1]),
                    ..p
                },
                mac,
            ),
            (p, Mac::BROADCAST),
            (p, slirp),
        ] {
            assert_eq!(other(q, dst), None, "{q:?} to {dst}");
        }
        assert_eq!(arp_reply(&reply[..41], mac, ours, gw), None);
        assert_eq!(arp_reply(&reply[..13], mac, ours, gw), None);
    }

    #[test]
    fn the_probes_report() {
        let slirp = Mac([0x52, 0x55, 10, 0, 2, 2]);
        for r in [
            ProbeReport {
                result: Ok(slirp),
                skipped: 3,
                sent: 1,
            },
            ProbeReport {
                result: Err(ProbeError::Link),
                skipped: 0,
                sent: 0,
            },
            ProbeReport {
                result: Err(ProbeError::NoBuffer),
                skipped: 0,
                sent: 0,
            },
        ] {
            assert_eq!(ProbeReport::from_words(r.to_words()), Some(r));
        }
        assert_eq!(
            ProbeReport {
                result: Ok(slirp),
                skipped: 3,
                sent: 1
            }
            .to_words(),
            [0, 0x0202_000a_5552, 3, 1]
        );
        for bad in [[3, 0, 0, 0], [1, 5, 0, 0], [0, 1 << 48, 0, 0]] {
            assert_eq!(ProbeReport::from_words(bad), None, "{bad:x?}");
        }
        // Not a fault label, which root tells apart on the same endpoint.
        assert_eq!(crate::process::fault_kind(ProbeReport::LABEL), None);
    }
}
