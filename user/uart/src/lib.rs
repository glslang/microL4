//! `uart`: the COM1 driver (`docs/design.md`, "uart" under "User-level
//! drivers and console").
//!
//! uart drives the 16550 at `0x3F8` through an IOPort capability and the
//! IRQHandler of ISA IRQ 4, an edge-triggered pin, and serves one writer,
//! console, through endpoint U. Everything that decides is here, generic
//! over [`Port`] (the registers) and [`Irq`] (the handler's `Ack`), and
//! host-tested against a model of the 16550 and of an I/O APIC pin with
//! the kernel's Ack rule; [`run`], the server loop, exists only on the
//! user target, where the root task starts it in a VSpace and CSpace of
//! its own with the capabilities [`slot`] lists.
//!
//! - [`Uart::start`] programs the device ([`setup`]), then Acks and
//!   services once, since an interrupt between issue and binding signalled
//!   nothing.
//! - [`Uart::on_interrupt`] runs for every signal: `Ack`, then the service
//!   routine, which reads IIR until no cause is pending (ADR 0028: on an
//!   edge pin the Ack must open the pin before the driver's last look at
//!   the device).
//! - [`Uart::request`] runs one request: `Write`, `Read`, `Drain` or
//!   `Stats` ([`decode`] checks the label, badge and length first).
//!
//! The rules: a 2,048-byte transmit queue, written in bursts of 15 bytes
//! per THRE seen (1 without FIFOs; a THRE interrupt counts only if LSR
//! still says THRE), so even a debug kernel's byte cannot
//! overflow the 16-byte FIFO; a 256-byte receive ring, whose filling clears
//! IER's data bit until a `Read` makes room; IER.THRI exactly while the
//! queue holds bytes or a `Drain` is held; one held request at a time, in
//! slot 7, its refusal decided by `CNode_SaveCaller`; and a limit of 64
//! reads that move no byte per service routine.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod regs;
mod ring;
#[cfg(target_os = "none")]
mod run;
#[cfg(test)]
mod tests;

use libsys::proto::{self, MAX_BYTES, Refusal, UartStats, label};

pub use ring::Ring;
#[cfg(target_os = "none")]
pub use run::run;

use regs::*;

/// uart's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities").
pub mod slot {
    /// Slots in uart's CNode, and its radix and guard.
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard, for `CNode_SaveCaller`.
    pub const CNODE: u64 = 1;
    /// Endpoint U, uart's requests, with Read.
    pub const ENDPOINT: u64 = 2;
    /// IOPort `0x3F8`-`0x3FF`.
    pub const IOPORT: u64 = 3;
    /// The IRQHandler of ISA IRQ 4, bound to notification NU.
    pub const IRQ: u64 = 4;
    /// console's notification NC, with Write and badge `RX_READY`.
    pub const CONSOLE_NTFN: u64 = 5;
    /// Endpoint F, uart's fault endpoint.
    pub const FAULT: u64 = 6;
    /// A held request's reply capability.
    pub const HELD: u64 = 7;
}

/// The badge of console's capability to U: `Write`, `Read` and `Drain`
/// need it.
pub const CONSOLE_BADGE: u64 = 1;
/// The transmit queue, at least twice the largest Write.
pub const TX_QUEUE: usize = 2048;
/// The receive ring.
pub const RX_RING: usize = 256;
/// A burst into a working 16550's FIFO: 15 of its 16 places, leaving one
/// for a debug kernel's byte.
pub const FIFO_BURST: usize = 15;
/// Reads of IIR whose cause moves no byte before a service routine stops.
pub const IDLE_LIMIT: u32 = 64;
/// LSR polls for TEMT at setup.
pub const TEMT_POLLS: u32 = 10_000;

const _: () = assert!(TX_QUEUE >= 2 * MAX_BYTES);

/// The device's registers, by offset from `0x3F8`.
pub trait Port {
    fn read(&mut self, reg: u8) -> u8;
    fn write(&mut self, reg: u8, value: u8);
}

/// The interrupt's handler.
pub trait Irq {
    /// `IRQHandler_Ack`: the pin is open again.
    fn ack(&mut self);
}

/// Programs the 16550 (`docs/design.md`, uart's "Setup", steps 1 to 8):
/// 115,200 baud 8N1 after the bytes in flight have left, FIFOs on with an
/// 8-byte receive trigger if they work, DTR, RTS and OUT2, and IER =
/// received data and line status. Returns the transmit burst: 15 with
/// working FIFOs, else 1.
pub fn setup<P: Port>(port: &mut P) -> usize {
    // 1: DLAB clear, so offset 1 is IER; no interrupt during setup.
    port.write(LCR, LCR_8N1);
    port.write(IER, 0);
    // 2: let what others wrote leave before the FIFO reset.
    for _ in 0..TEMT_POLLS {
        if port.read(LSR) & LSR_TEMT != 0 {
            break;
        }
    }
    // 3: divisor 1.
    port.write(LCR, LCR_DLAB);
    port.write(DLL, 1);
    port.write(DLM, 0);
    port.write(LCR, LCR_8N1);
    // 4, 5: FIFOs on and cleared, then whether they work.
    port.write(FCR, FCR_SETUP);
    let burst = if port.read(IIR) & IIR_FIFOS == IIR_FIFOS {
        FIFO_BURST
    } else {
        port.write(FCR, 0);
        1
    };
    // 6: OUT2 gates the interrupt line on a PC.
    port.write(MCR, MCR_SETUP);
    // 7: clear latched errors and modem deltas.
    port.read(LSR);
    port.read(MSR);
    // 8: received data, with the timeout, and line status.
    port.write(IER, IER_SETUP);
    burst
}

/// A request, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Write(&'a [u8]),
    Read,
    Drain,
    Stats,
}

/// Decodes a request: its label, then its badge, then its length
/// (`docs/design.md`, "Protocols"), the byte string into `buf`. `word`
/// reads MR0 and up. Requests without words ignore any sent.
pub fn decode<'a>(
    label: u64,
    badge: u64,
    length: usize,
    word: impl FnMut(usize) -> u64,
    buf: &'a mut [u8; MAX_BYTES],
) -> Result<Request<'a>, Refusal> {
    let console_only = match label {
        label::UART_WRITE | label::UART_READ | label::UART_DRAIN => true,
        label::UART_STATS => false,
        _ => return Err(Refusal::BadLabel),
    };
    if console_only && badge != CONSOLE_BADGE {
        return Err(Refusal::BadBadge);
    }
    Ok(match label {
        label::UART_WRITE => {
            let n = proto::decode(length, word, MAX_BYTES, buf)?;
            Request::Write(&buf[..n])
        }
        label::UART_READ => Request::Read,
        label::UART_DRAIN => Request::Drain,
        _ => Request::Stats,
    })
}

/// A request held for a later reply through slot 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// A Write of this many bytes, waiting for room in the queue.
    Write(usize),
    /// A Drain, waiting for the queue and the FIFO to empty.
    Drain,
}

/// The reply a held request gets once it can be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// MR0 `n`: the held Write's bytes are queued.
    Written(usize),
    /// The held Drain: the queue and the FIFO are empty.
    Drained,
}

/// What uart does after an interrupt's service routine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Bytes reached the receive ring: signal console's NC.
    pub signal_console: bool,
    /// A held request to answer through slot 7.
    pub release: Option<Release>,
}

/// The answer to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Reply MR0 `n`.
    Written(usize),
    /// Reply with this many bytes from the caller's buffer.
    Read(usize),
    /// Reply with nothing.
    Drained,
    Stats(UartStats),
    /// The caller's reply capability is saved; it is answered later.
    Held,
    Refused(Refusal),
}

/// The driver's state.
#[derive(Clone, Debug)]
pub struct Uart {
    burst: usize,
    /// IER as last written.
    ier: u8,
    tx: Ring<TX_QUEUE>,
    rx: Ring<RX_RING>,
    held: Option<Held>,
    held_bytes: [u8; MAX_BYTES],
    stats: UartStats,
}

impl Uart {
    /// Programs the device, then Acks and services it once.
    pub fn start<D: Port + Irq>(dev: &mut D) -> (Uart, Outcome) {
        let burst = setup(dev);
        let mut uart = Uart {
            burst,
            ier: IER_SETUP,
            tx: Ring::new(),
            rx: Ring::new(),
            held: None,
            held_bytes: [0; MAX_BYTES],
            // Stats MR8 reports the burst setup chose.
            stats: UartStats {
                burst: burst as u64,
                ..UartStats::default()
            },
        };
        dev.ack();
        let out = uart.service(dev);
        (uart, out)
    }

    /// The transmit burst: 15, or 1 without working FIFOs.
    pub fn burst(&self) -> usize {
        self.burst
    }

    /// Bytes waiting in the transmit queue.
    pub fn queued(&self) -> usize {
        self.tx.len()
    }

    /// Bytes waiting in the receive ring.
    pub fn buffered(&self) -> usize {
        self.rx.len()
    }

    /// The held request, if any.
    pub fn held(&self) -> Option<Held> {
        self.held
    }

    pub fn stats(&self) -> UartStats {
        self.stats
    }

    /// IER as the rules want it now: line status always, received data
    /// unless the ring is full, THRE while the queue holds bytes or a
    /// Drain is held.
    pub fn wanted_ier(&self) -> u8 {
        let mut ier = IER_RLSI;
        if !self.rx.is_full() {
            ier |= IER_RDI;
        }
        if !self.tx.is_empty() || self.held == Some(Held::Drain) {
            ier |= IER_THRI;
        }
        ier
    }

    /// A signal from IRQ 4: `Ack`, then the service routine.
    pub fn on_interrupt<D: Port + Irq>(&mut self, dev: &mut D) -> Outcome {
        self.stats.signals += 1;
        dev.ack();
        self.service(dev)
    }

    /// The service routine: reads IIR until no cause is pending, handling
    /// each in the 16550's priority order, and stops early after
    /// [`IDLE_LIMIT`] reads whose cause moved no byte.
    pub fn service<P: Port>(&mut self, port: &mut P) -> Outcome {
        let mut out = Outcome::default();
        let mut idle = 0;
        loop {
            let iir = port.read(IIR);
            if iir & IIR_NO_INT != 0 {
                break;
            }
            let moved = match iir & IIR_ID {
                IIR_RLSI => {
                    self.lsr(port);
                    false
                }
                IIR_RDI | IIR_CTI => {
                    let n = self.receive(port);
                    out.signal_console |= n > 0;
                    n > 0
                }
                // A THRE interrupt is taken only if LSR still says THRE, as
                // Linux's 8250 driver does: a device that reports THRE while
                // the FIFO still holds bytes (Hyper-V's appears to, after a
                // THR write) would otherwise bring a burst onto it, or
                // release a Drain early. Stats MR9 counts them.
                IIR_THRI if self.lsr(port) & LSR_THRE == 0 => {
                    self.stats.stale_thre += 1;
                    false
                }
                IIR_THRI if self.tx.is_empty() => {
                    if self.held == Some(Held::Drain) {
                        self.held = None;
                        out.release = Some(Release::Drained);
                    }
                    false
                }
                IIR_THRI => {
                    self.write_burst(port);
                    self.stats.thre_bursts += 1;
                    if let Some(Held::Write(n)) = self.held
                        && self.tx.push_all(&self.held_bytes[..n])
                    {
                        self.held = None;
                        out.release = Some(Release::Written(n));
                    }
                    true
                }
                IIR_MSI => {
                    port.read(MSR);
                    false
                }
                // No 16550 cause: nothing to clear.
                _ => false,
            };
            self.update_ier(port);
            if !moved {
                idle += 1;
                if idle >= IDLE_LIMIT {
                    self.stats.cut_short += 1;
                    break;
                }
            }
        }
        self.update_ier(port);
        out
    }

    /// Runs one request. `save` moves the caller's reply capability into
    /// slot 7 (`CNode_SaveCaller`) and says whether it could: a request
    /// that must wait is held if it could, and refused `Busy` if not, since
    /// a request already holds the slot. A Read's bytes go to `out`.
    pub fn request<P: Port>(
        &mut self,
        port: &mut P,
        req: Request<'_>,
        out: &mut [u8],
        save: impl FnOnce() -> bool,
    ) -> Answer {
        let answer = match req {
            Request::Write(bytes) => {
                let thre = self.refill(port);
                if self.held.is_none() && self.tx.push_all(bytes) {
                    if thre {
                        self.write_burst(port);
                    }
                    Answer::Written(bytes.len())
                } else if save() {
                    self.held = Some(Held::Write(bytes.len()));
                    self.held_bytes[..bytes.len()].copy_from_slice(bytes);
                    self.stats.writes_held += 1;
                    Answer::Held
                } else {
                    Answer::Refused(Refusal::Busy)
                }
            }
            Request::Drain => {
                let thre = self.refill(port);
                if self.held.is_none() && self.tx.is_empty() && thre {
                    Answer::Drained
                } else if save() {
                    self.held = Some(Held::Drain);
                    Answer::Held
                } else {
                    Answer::Refused(Refusal::Busy)
                }
            }
            Request::Read => {
                self.receive(port);
                Answer::Read(self.rx.take_into(out))
            }
            Request::Stats => Answer::Stats(self.stats),
        };
        self.update_ier(port);
        answer
    }

    /// Insurance against a lost THRE interrupt, before a Write or Drain:
    /// reads LSR and, if THRE is set and bytes wait, writes a burst.
    /// Whether THRE is still unused: set, and no burst written.
    fn refill<P: Port>(&mut self, port: &mut P) -> bool {
        let thre = self.lsr(port) & LSR_THRE != 0;
        if thre && !self.tx.is_empty() {
            self.write_burst(port);
            return false;
        }
        thre
    }

    /// Reads LSR and counts the errors it reports; reading clears them.
    fn lsr<P: Port>(&mut self, port: &mut P) -> u8 {
        let lsr = port.read(LSR);
        if lsr & LSR_OE != 0 {
            self.stats.overruns += 1;
        }
        if lsr & (LSR_PE | LSR_FE | LSR_BI) != 0 {
            self.stats.line_errors += 1;
        }
        lsr
    }

    /// Moves bytes from RBR to the ring while LSR.DR is set and the ring
    /// has room; how many.
    fn receive<P: Port>(&mut self, port: &mut P) -> usize {
        let mut n = 0;
        while !self.rx.is_full() && self.lsr(port) & LSR_DR != 0 {
            self.rx.push(port.read(RBR));
            n += 1;
        }
        self.stats.received += n as u64;
        n
    }

    /// Writes one burst from the queue, after a THRE seen.
    fn write_burst<P: Port>(&mut self, port: &mut P) {
        for _ in 0..self.burst {
            let Some(b) = self.tx.pop() else { break };
            port.write(THR, b);
            self.stats.sent += 1;
        }
    }

    fn update_ier<P: Port>(&mut self, port: &mut P) {
        let want = self.wanted_ier();
        if want != self.ier {
            port.write(IER, want);
            self.ier = want;
        }
    }
}
