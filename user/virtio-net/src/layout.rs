//! Where things are (`docs/design.md`, "Where the network servers run"
//! and "The DMA frame"): the windows root maps in virtio-net's VSpace, and
//! the layout of the DMA frame, whose physical base root passes in `rdi`,
//! so that the physical address of offset `o` is that base plus `o`.
//!
//! | Offset | What |
//! | --- | --- |
//! | `0x0000` | queue 0's split ring for 64 entries: descriptors at `0x000`, the available ring at `0x400`, the used ring at `0x800` |
//! | `0x1000` | queue 1's, the same |
//! | `0x1_0000` + 2,048 × `i` | receive buffer `i`, descriptor `i` of queue 0 |
//! | `0x3_0000` + 2,048 × `i` | transmit buffer `i`, descriptor `i` of queue 1 |
//!
//! Each descriptor names its own buffer, set once at start, so the driver
//! never writes any other physical address into a ring.

/// The DMA frame's window: one fresh 2 MiB RAM frame, mapped RW, NX,
/// `WriteBack`.
pub const DMA: u64 = 0x0800_0000;
/// The DMA frame: one 2 MiB RAM frame.
pub const DMA_SIZE: usize = 1 << 21;
/// The windows of the three virtio regions the driver uses, 64 KiB each:
/// region `r` ([`crate::Which`]: common, notify, device) in window `r`,
/// each the device frames under it, mapped RW, NX, `Uncached`.
pub const REGIONS: u64 = 0x0C00_0000;
/// One region's window.
pub const REGION_WINDOW: usize = 0x1_0000;
/// Where a region may start in its window: in its first page.
pub const REGION_OFFSET_LIMIT: usize = 0x1000;
/// The longest region: 60 KiB, so that it ends inside its window.
pub const REGION_MAX: usize = REGION_WINDOW - REGION_OFFSET_LIMIT;

/// Entries in each queue.
pub const QUEUE_SIZE: u16 = 64;
/// The queues the driver uses: 0 receives, 1 transmits.
pub const QUEUES: u16 = 2;
/// Queue `q`'s ring is at `RING + RING_STRIDE q`.
pub const RING: usize = 0x0000;
pub const RING_STRIDE: usize = 0x1000;
/// In a ring: the descriptor table, 16 bytes a descriptor.
pub const DESC: usize = 0x000;
/// The available ring: `flags`, `idx`, then 64 entries of 2 bytes.
pub const AVAIL: usize = 0x400;
/// The used ring: `flags`, `idx`, then 64 elements of 8 bytes.
pub const USED: usize = 0x800;
/// Receive buffer `i` is at `RX_BUFFERS + BUFFER_SIZE i`.
pub const RX_BUFFERS: usize = 0x1_0000;
/// Transmit buffer `i` is at `TX_BUFFERS + BUFFER_SIZE i`.
pub const TX_BUFFERS: usize = 0x3_0000;
/// A buffer: at least the 12-byte header and a 1,514-byte frame that
/// virtio 1.2 asks for without mergeable buffers (5.1.6.3.1).
pub const BUFFER_SIZE: usize = 2048;
/// The end of the last transmit buffer; the rest of the frame is unused.
pub const END: usize = 0x5_0000;

/// Bytes of a descriptor (`struct virtq_desc`).
pub const DESC_SIZE: usize = 16;
/// Bytes of the available ring for 64 entries: `flags`, `idx` and the
/// entries (no `used_event` without `EVENT_IDX`).
pub const AVAIL_SIZE: usize = 4 + 2 * QUEUE_SIZE as usize;
/// Bytes of the used ring for 64 elements (no `avail_event`).
pub const USED_SIZE: usize = 4 + 8 * QUEUE_SIZE as usize;

/// Where queue `q`'s ring starts in the DMA frame.
pub const fn ring(q: u16) -> usize {
    RING + RING_STRIDE * q as usize
}

/// Where buffer `i` of queue `q` starts.
pub const fn buffer(q: u16, i: u16) -> usize {
    let base = if q == 0 { RX_BUFFERS } else { TX_BUFFERS };
    base + BUFFER_SIZE * i as usize
}

/// Where region window `r` starts in virtio-net's VSpace.
pub const fn region_window(r: usize) -> u64 {
    REGIONS + (REGION_WINDOW * r) as u64
}

const _: () = {
    // The rings, each part aligned as virtio 1.x asks (16, 2 and 4) and
    // inside its page, with the 6 + 2 × 64 and 6 + 8 × 64 bytes that the
    // specification's table gives (the 2 of `used_event` and `avail_event`
    // included, though unused).
    assert!(DESC.is_multiple_of(16) && AVAIL.is_multiple_of(2) && USED.is_multiple_of(4));
    assert!(DESC + DESC_SIZE * QUEUE_SIZE as usize <= AVAIL);
    assert!(AVAIL + AVAIL_SIZE + 2 <= USED);
    assert!(USED + USED_SIZE + 2 <= RING_STRIDE);
    assert!(ring(QUEUES) <= RX_BUFFERS);
    assert!(buffer(0, QUEUE_SIZE) == TX_BUFFERS);
    assert!(buffer(1, QUEUE_SIZE) == END);
    assert!(END <= DMA_SIZE);
    assert!(BUFFER_SIZE >= crate::HEADER + libsys::frames::MAX_FRAME);
    // Below the frame queues' window, in the first GiB, apart.
    assert!(DMA + DMA_SIZE as u64 <= REGIONS);
    assert!(region_window(3) <= libsys::frames::WINDOW);
    assert!(DMA.is_multiple_of(DMA_SIZE as u64));
};
