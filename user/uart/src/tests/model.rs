//! A 16550 and an I/O APIC pin, as uart's host tests need them
//! (`docs/design.md`, "Code and tests"): IIR priorities; THRE cleared by an
//! IIR read that reports it or a THR write (with `stale_thre`, only by the
//! IIR read, a device some 16550 emulations may be); 16-byte FIFOs, the receive
//! trigger and the character timeout; OE; OUT2 gating the line; a
//! transmitter that takes a byte time per byte or empties at once as
//! QEMU's does; a receiver that overruns as hardware does or, as QEMU's,
//! takes no byte it has no room for; and an edge-triggered pin with the
//! kernel's rule (`docs/design.md`, "IRQControl and IRQHandler"): an edge
//! on an open pin is delivered, setting `pending` and masking the pin if
//! `pending` was already set; Ack clears `pending` and opens the pin; an
//! edge on a masked pin is dropped.

use std::collections::VecDeque;
use std::vec::Vec;

use crate::regs::*;

/// Who wrote a byte that reached the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    Uart,
    Kernel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx {
    /// A byte time per byte: each tick moves one byte to the wire.
    Slow,
    /// QEMU: a THR write leaves at once (`serial_xmit`).
    Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx {
    /// A byte that finds the FIFO full is lost, and LSR.OE set.
    Overrun,
    /// QEMU: no byte is offered while the FIFO is full
    /// (`serial_can_receive`).
    Wait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edges {
    /// Only a rising line is an edge.
    Rising,
    /// QEMU: every update that leaves the line high raises it again
    /// (`ioapic_set_irq` for an edge pin).
    EveryRaise,
}

/// The 16550.
pub struct Dev {
    pub has_fifos: bool,
    fifo_on: bool,
    trigger: usize,
    lcr: u8,
    pub mcr: u8,
    pub ier: u8,
    pub dll: u8,
    pub dlm: u8,
    scr: u8,
    rx: VecDeque<u8>,
    tx: VecDeque<(Src, u8)>,
    tsr: Option<(Src, u8)>,
    errors: u8,
    thr_pending: bool,
    timeout_pending: bool,
    pub tx_mode: Tx,
    pub rx_mode: Rx,
    /// Bytes on the wire, by writer.
    pub wire: Vec<(Src, u8)>,
    /// A THR write found the FIFO full.
    pub overflowed: bool,
    /// A THR write leaves a pending THRE interrupt pending: only an IIR
    /// read that reports it clears it.
    pub stale_thre: bool,
    /// Bytes received while the FIFO was full.
    pub lost: usize,
}

impl Dev {
    pub fn new(tx_mode: Tx, rx_mode: Rx) -> Dev {
        Dev {
            has_fifos: true,
            fifo_on: false,
            trigger: 1,
            lcr: 0,
            mcr: 0,
            ier: 0,
            dll: 0,
            dlm: 0,
            scr: 0,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            tsr: None,
            errors: 0,
            thr_pending: false,
            timeout_pending: false,
            tx_mode,
            rx_mode,
            wire: Vec::new(),
            overflowed: false,
            stale_thre: false,
            lost: 0,
        }
    }

    fn cap(&self) -> usize {
        if self.fifo_on { 16 } else { 1 }
    }

    fn dlab(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    pub fn thre(&self) -> bool {
        self.tx.is_empty()
    }

    fn temt(&self) -> bool {
        self.tx.is_empty() && self.tsr.is_none()
    }

    /// The cause IIR reports, in the 16550's priority order.
    pub fn cause(&self) -> u8 {
        let data = if self.fifo_on {
            self.rx.len() >= self.trigger
        } else {
            !self.rx.is_empty()
        };
        if self.ier & IER_RLSI != 0 && self.errors != 0 {
            IIR_RLSI
        } else if self.ier & IER_RDI != 0 && self.timeout_pending {
            IIR_CTI
        } else if self.ier & IER_RDI != 0 && data {
            IIR_RDI
        } else if self.ier & IER_THRI != 0 && self.thr_pending {
            IIR_THRI
        } else {
            IIR_NO_INT
        }
    }

    /// The interrupt line: a cause, gated by OUT2.
    pub fn line(&self) -> bool {
        self.mcr & MCR_OUT2 != 0 && self.cause() != IIR_NO_INT
    }

    pub fn read(&mut self, reg: u8) -> u8 {
        match reg {
            RBR if !self.dlab() => {
                self.timeout_pending = false;
                self.rx.pop_front().unwrap_or(0)
            }
            DLL => self.dll,
            IER if !self.dlab() => self.ier,
            DLM => self.dlm,
            IIR => {
                let cause = self.cause();
                if cause == IIR_THRI {
                    self.thr_pending = false;
                }
                let fifos = if self.fifo_on && self.has_fifos {
                    IIR_FIFOS
                } else {
                    0
                };
                cause | fifos
            }
            LCR => self.lcr,
            MCR => self.mcr,
            LSR => {
                let mut v = self.errors;
                self.errors = 0;
                if !self.rx.is_empty() {
                    v |= LSR_DR;
                }
                if self.thre() {
                    v |= LSR_THRE;
                }
                if self.temt() {
                    v |= LSR_TEMT;
                }
                v
            }
            MSR => 0,
            _ => self.scr,
        }
    }

    pub fn write(&mut self, reg: u8, value: u8, src: Src) {
        match reg {
            THR if !self.dlab() => {
                if !self.stale_thre {
                    self.thr_pending = false;
                }
                if self.tx.len() >= self.cap() {
                    self.overflowed = true;
                } else {
                    self.tx.push_back((src, value));
                }
                if self.tx_mode == Tx::Instant {
                    while !self.tx.is_empty() {
                        self.tick();
                    }
                    self.tick();
                }
            }
            DLL => self.dll = value,
            IER if !self.dlab() => {
                let was = self.ier;
                self.ier = value & 0x0F;
                if self.ier & IER_THRI != 0 && was & IER_THRI == 0 && self.thre() {
                    self.thr_pending = true;
                }
            }
            DLM => self.dlm = value,
            FCR => {
                self.fifo_on = value & 1 != 0;
                if value & 2 != 0 {
                    self.rx.clear();
                    self.timeout_pending = false;
                }
                if value & 4 != 0 {
                    self.tx.clear();
                }
                self.trigger = if self.fifo_on {
                    [1, 4, 8, 14][usize::from(value >> 6)]
                } else {
                    1
                };
            }
            LCR => self.lcr = value,
            MCR => self.mcr = value,
            _ => self.scr = value,
        }
    }

    /// The transmitter: the shift register's byte reaches the wire, and
    /// the FIFO's next moves in; THRE when the FIFO empties.
    pub fn tick(&mut self) -> bool {
        let busy = self.tsr.is_some() || !self.tx.is_empty();
        if let Some(b) = self.tsr.take() {
            self.wire.push(b);
        }
        if let Some(b) = self.tx.pop_front() {
            self.tsr = Some(b);
            if self.tx.is_empty() {
                self.thr_pending = true;
            }
        }
        busy
    }

    /// Whether any of `src`'s bytes wait in the transmit FIFO; the shift
    /// register's byte is on its way out.
    pub fn fifo_holds(&self, src: Src) -> bool {
        self.tx.iter().any(|b| b.0 == src)
    }

    pub fn tx_busy(&self) -> bool {
        self.tsr.is_some() || !self.tx.is_empty()
    }

    /// Whether the receiver would take a byte now.
    pub fn can_receive(&self) -> bool {
        self.rx_mode == Rx::Overrun || self.rx.len() < self.cap()
    }

    /// A byte arrives from the host, with line-error bits `errors` (PE,
    /// FE or BI; the byte is still read as data).
    pub fn receive(&mut self, b: u8, errors: u8) {
        if self.rx.len() >= self.cap() {
            self.errors |= LSR_OE;
            self.lost += 1;
        } else {
            self.rx.push_back(b);
            self.errors |= errors;
        }
    }

    /// Four character times pass with no read.
    pub fn timeout(&mut self) -> bool {
        let fire = self.timeout_due();
        if fire {
            self.timeout_pending = true;
        }
        fire
    }

    /// Whether [`Dev::timeout`] would fire.
    pub fn timeout_due(&self) -> bool {
        self.fifo_on && !self.rx.is_empty() && !self.timeout_pending
    }

    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }
}

/// An I/O APIC pin with the kernel's rule for an edge pin, and the
/// notification NU it signals.
pub struct Pin {
    pub edges: Edges,
    line: bool,
    pub pending: bool,
    pub masked: bool,
    /// NU's word: a signal waits.
    pub signal: bool,
    pub delivered: u64,
    pub dropped: u64,
}

impl Pin {
    pub fn new(edges: Edges) -> Pin {
        Pin {
            edges,
            line: false,
            pending: false,
            masked: false,
            signal: false,
            delivered: 0,
            dropped: 0,
        }
    }

    /// The line as the device drives it now.
    pub fn update(&mut self, level: bool) {
        let edge = match self.edges {
            Edges::Rising => level && !self.line,
            Edges::EveryRaise => level,
        };
        self.line = level;
        if !edge {
            return;
        }
        if self.masked {
            self.dropped += 1;
            return;
        }
        if self.pending {
            self.masked = true;
        }
        self.pending = true;
        self.signal = true;
        self.delivered += 1;
    }

    /// `IRQHandler_Ack`. Opening the pin makes no edge.
    pub fn ack(&mut self) {
        self.pending = false;
        self.masked = false;
    }
}
