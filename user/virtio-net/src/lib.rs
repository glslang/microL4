//! `virtio-net`: the QEMU network driver (`docs/design.md`, "Networking",
//! "`virtio-net`").
//!
//! It drives a virtio 1.x network device through the modern PCI transport
//! ([`pci`]) with two split virtqueues of 64 entries ([`virtq`]), their
//! rings and 2 KiB buffers in one 2 MiB RAM frame whose physical base root
//! learns with `Frame_GetAddress` ([`layout`]), and one MSI-X vector, entry
//! 0 of the table root programmed. It negotiates `VIRTIO_F_VERSION_1`,
//! `VIRTIO_NET_F_MAC` and `VIRTIO_NET_F_STATUS` and nothing else, so the
//! device delivers whole frames and the stack computes every checksum. It
//! follows virtio 1.2 (2.1, 2.7, 3.1, 4.1 and 5.1), read in the OASIS
//! specification's TeX sources (fetched 2026-11-27) and, where this crate
//! says so, from memory.
//!
//! Every frame is copied between the device's buffers and the frame
//! queues it shares with `net` (`libsys::frames`), so `net` never maps
//! memory the device writes and the device is never given an address in
//! the queues.
//!
//! - [`Driver::start`] runs the setup's ten steps: reset, ACKNOWLEDGE and
//!   DRIVER, the features, FEATURES_OK read back, no configuration
//!   interrupt, the two queues, the MAC and link, the receive buffers,
//!   DRIVER_OK and the first notify, and the queues' link block.
//! - [`Driver::on_signal`] runs one signal's work, `IRQ` and `FRAMES`
//!   alike: it drains the receive queue's used ring into `RX_FILLED`,
//!   reclaims transmit descriptors, and copies `TX_FILLED`'s frames to the
//!   device, turning transmit completions on only while a frame waits for
//!   a descriptor.
//! - [`Driver::stats`] is the answer to root's `Stats`
//!   ([`libsys::proto::VirtioNetStats`]), [`request`] checks the request.
//!
//! Everything is generic over `libsys::mem`'s [`Regs`] (the three device
//! regions) and [`Memory`] (the DMA frame and the queues), and
//! host-tested against a model device written from the specification
//! (`src/tests/device.rs`). [`run`], the loop, exists only on the user
//! target, where root starts it in a VSpace and CSpace of its own with the
//! capabilities [`slot`] lists and the arguments [`Start`] decodes, bound
//! to notification NV, which its MSI handler signals with `IRQ` and `net`
//! with `FRAMES`.
//!
//! [`Regs`]: libsys::mem::Regs
//! [`Memory`]: libsys::mem::Memory

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod driver;
pub mod layout;
pub mod pci;
#[cfg(target_os = "none")]
mod run;
#[cfg(test)]
mod tests;
pub mod virtq;

use core::fmt;

use libsys::frames::Mac;
use libsys::proto::{Refusal, VirtioFeatures, label, virtio_feature};

pub use driver::{Counters, Driver, GENERATION_TRIES, RESET_READS, Refused};
#[cfg(target_os = "none")]
pub use run::run;

/// virtio-net's CSpace: a 16-slot CNode with guard 0 of size 60, so
/// `CPtr` `n` is slot `n` (`docs/design.md`, "Capabilities" under
/// "Networking").
pub mod slot {
    /// Slots in its CNode, and its radix and guard.
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard.
    pub const CNODE: u64 = 1;
    /// Endpoint VN, with Read: root's `Stats`.
    pub const ENDPOINT: u64 = 2;
    /// `net`'s notification NN, with Write and badge `FRAMES`.
    pub const NET: u64 = 3;
    /// Endpoint F, its fault endpoint, with Write and GrantReply, badge
    /// `VIRTIO_NET` (4).
    pub const FAULT: u64 = 4;
    /// Endpoint C, console's, with Write and GrantReply, badge 6: its log
    /// lines.
    pub const CONSOLE: u64 = 5;
}

/// `struct virtio_net_hdr_v1`'s bytes, `num_buffers` included, before
/// every frame in a buffer (virtio 1.2, 5.1.6): sent zeroed, skipped on
/// receive.
pub const HEADER: usize = 12;
/// The features the driver accepts when offered: `VERSION_1` (required),
/// `MAC` (required) and `STATUS`.
pub const FEATURES: u64 = virtio_feature::VERSION_1 | virtio_feature::MAC | virtio_feature::STATUS;
/// The physical addresses a DMA frame may cover: x86-64's architectural
/// limit, 52 bits.
pub const PHYS_LIMIT: u64 = 1 << 52;

/// One of the three virtio regions the driver uses, by its window's
/// number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    /// The common configuration ([`pci::common`]).
    Common = 0,
    /// Where queue notifications are written.
    Notify = 1,
    /// The network device's configuration ([`pci::net`]).
    Device = 2,
}

impl Which {
    pub const ALL: [Which; 3] = [Which::Common, Which::Notify, Which::Device];

    pub const fn name(self) -> &'static str {
        match self {
            Which::Common => "common",
            Which::Notify => "notify",
            Which::Device => "device",
        }
    }

    /// The fewest bytes the driver needs of it: the common configuration
    /// up to `queue_device` (56), one 16-bit notify (2), and the MAC and
    /// status (8).
    pub const fn min_len(self) -> usize {
        match self {
            Which::Common => pci::common::SIZE,
            Which::Notify => 2,
            Which::Device => pci::net::SIZE,
        }
    }
}

/// Where a region lies in its 64 KiB window: its offset, below 4 KiB (its
/// offset in its page), and its length, at most 60 KiB, so that it ends
/// inside the window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub offset: u16,
    pub len: u16,
}

impl Region {
    /// As `rsi` and `rdx` carry it: the offset in bits 0 to 15, the length
    /// in bits 16 to 31.
    pub const fn word(self) -> u32 {
        self.offset as u32 | (self.len as u32) << 16
    }

    pub const fn from_word(w: u32) -> Region {
        Region {
            offset: w as u16,
            len: (w >> 16) as u16,
        }
    }

    /// Whether it starts in its window's first page and is at most 60
    /// KiB long.
    pub const fn fits(self) -> bool {
        (self.offset as usize) < layout::REGION_OFFSET_LIMIT
            && self.len as usize <= layout::REGION_MAX
    }
}

/// The driver's arguments, which root passes in `rdi`, `rsi`, `rdx` and
/// `rcx` ([`Start::to_words`]) and its entry stub checks again
/// ([`Start::from_words`]), panicking on words it refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    /// The DMA frame's physical base ([`layout`]): offset `o` is at `dma +
    /// o`.
    pub dma: u64,
    pub common: Region,
    pub notify: Region,
    pub device: Region,
    /// The notify capability's `notify_off_multiplier`.
    pub multiplier: u32,
}

impl Start {
    /// `rdi`: the DMA frame's base; `rsi`: the common region in the low
    /// half, the notify region in the high; `rdx`: the device region;
    /// `rcx`: the multiplier.
    pub const fn to_words(&self) -> [u64; 4] {
        [
            self.dma,
            self.common.word() as u64 | (self.notify.word() as u64) << 32,
            self.device.word() as u64,
            self.multiplier as u64,
        ]
    }

    /// The arguments in these words, refusing a DMA base that is 0, not
    /// 2 MiB-aligned or a frame past 2^52; a region that leaves its window
    /// (or `rdx`'s high half not 0); a common region under 56 bytes, a
    /// notify region under 2 or a device region under 8; and a
    /// multiplier that is not 0 or an even power of 2, which the
    /// specification asks of a device without `NOTIFICATION_DATA` (virtio
    /// 1.2, 4.1.4.4).
    pub fn from_words(w: [u64; 4]) -> Result<Start, StartError> {
        let [dma, rsi, rdx, rcx] = w;
        if dma == 0
            || !dma.is_multiple_of(layout::DMA_SIZE as u64)
            || dma > PHYS_LIMIT - layout::DMA_SIZE as u64
        {
            return Err(StartError::Dma(dma));
        }
        let words = [rsi & 0xFFFF_FFFF, rsi >> 32, rdx];
        let mut regions = [Region::default(); 3];
        for (which, (word, region)) in Which::ALL
            .into_iter()
            .zip(words.into_iter().zip(&mut regions))
        {
            let r = Region::from_word(word as u32);
            if word > u64::from(u32::MAX) || !r.fits() {
                return Err(StartError::Region { which, word });
            }
            if usize::from(r.len) < which.min_len() {
                return Err(StartError::Short { which, len: r.len });
            }
            *region = r;
        }
        let multiplier = u32::try_from(rcx).map_err(|_| StartError::Multiplier(rcx))?;
        if multiplier != 0 && (multiplier == 1 || !multiplier.is_power_of_two()) {
            return Err(StartError::Multiplier(rcx));
        }
        let [common, notify, device] = regions;
        Ok(Start {
            dma,
            common,
            notify,
            device,
            multiplier,
        })
    }

    pub const fn region(&self, which: Which) -> Region {
        match which {
            Which::Common => self.common,
            Which::Notify => self.notify,
            Which::Device => self.device,
        }
    }

    /// Where region `which` is in virtio-net's VSpace, and its length:
    /// the address and length of the `Mmio` window root's entry stub makes
    /// of it.
    pub const fn window(&self, which: Which) -> (u64, usize) {
        let r = self.region(which);
        (
            layout::region_window(which as usize) + r.offset as u64,
            r.len as usize,
        )
    }
}

/// Why [`Start::from_words`] refused its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The DMA frame's base.
    Dma(u64),
    /// A region's word, which leaves its window.
    Region { which: Which, word: u64 },
    /// A region shorter than the driver needs.
    Short { which: Which, len: u16 },
    /// `rcx`, not a valid `notify_off_multiplier`.
    Multiplier(u64),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            StartError::Dma(b) => write!(
                f,
                "the DMA frame's base {b:#x} is not a 2 MiB-aligned address from 2 MiB to 2^52"
            ),
            StartError::Region { which, word } => write!(
                f,
                "the {} region's word {word:#x} leaves its window",
                which.name()
            ),
            StartError::Short { which, len } => write!(
                f,
                "the {} region is {len} bytes, under {}",
                which.name(),
                which.min_len()
            ),
            StartError::Multiplier(m) => write!(
                f,
                "notify_off_multiplier {m:#x} is not 0 or an even power of 2"
            ),
        }
    }
}

/// The three regions' register windows.
#[derive(Clone, Copy, Debug)]
pub struct Regions<R> {
    pub common: R,
    pub notify: R,
    pub device: R,
}

impl<R> Regions<R> {
    pub fn get(&self, which: Which) -> &R {
        match which {
            Which::Common => &self.common,
            Which::Notify => &self.notify,
            Which::Device => &self.device,
        }
    }
}

/// Checks a request on endpoint VN: only `Stats` (`0x150`) with no words,
/// from any badge, answered with [`Driver::stats`]' words.
pub fn request(label: u64, length: usize) -> Result<(), Refusal> {
    match (label, length) {
        (label::VIRTIO_NET_STATS, 0) => Ok(()),
        (label::VIRTIO_NET_STATS, _) => Err(Refusal::BadLength),
        _ => Err(Refusal::BadLabel),
    }
}

/// The line virtio-net prints once it is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Up {
    pub mac: Mac,
    pub features: u64,
    pub link_up: bool,
    /// The receive and transmit queues' sizes.
    pub sizes: [u16; 2],
}

/// `virtio-net: up: MAC 52:54:00:12:34:56, features VERSION_1 MAC STATUS,
/// link up, queues 64 and 64`.
impl fmt::Display for Up {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio-net: up: MAC {}, features {}, link {}, queues {} and {}",
            self.mac,
            VirtioFeatures(self.features),
            if self.link_up { "up" } else { "down" },
            self.sizes[0],
            self.sizes[1]
        )
    }
}
