//! The network servers' setup decisions that need no kernel
//! (`docs/design.md`, "Where the network servers run", "PCI on QEMU" and
//! "Network scenarios"): which platform's drivers root starts, the
//! windows it maps in their VSpaces and where they may lie, the words it
//! passes `virtio-net` and `net` in their registers, and the ARP request
//! and reply of `test=virtio_net`'s probe. The root task's `servers.rs`
//! and `net.rs` do the invocations.

use core::fmt;

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
    /// `vmbus` and `netvsc` through the Hypervisor capability (builder Y).
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
