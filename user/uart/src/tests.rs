//! uart against the model of `model.rs`: setup's accesses, the request
//! rules, the receive ring, and random interleavings of host input,
//! transmit progress, a debug kernel's writer and uart's own steps
//! (`docs/design.md`, "Code and tests").

mod model;

use std::collections::VecDeque;
use std::format;
use std::vec::Vec;

use libsys::proto::{MAX_BYTES, Refusal, label};

use super::*;
use model::{Dev, Edges, Pin, Rx, Src, Tx};

/// xorshift64*: small, deterministic and fast under Miri.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < per_mille as usize
    }
}

/// A port that records every access and answers from a script of reads.
struct Script {
    log: Vec<(char, u8, u8)>,
    reads: VecDeque<u8>,
    acks: usize,
}

impl Port for Script {
    fn read(&mut self, reg: u8) -> u8 {
        let v = self.reads.pop_front().unwrap_or(0);
        self.log.push(('r', reg, v));
        v
    }

    fn write(&mut self, reg: u8, value: u8) {
        self.log.push(('w', reg, value));
    }
}

impl Irq for Script {
    fn ack(&mut self) {
        self.acks += 1;
        self.log.push(('a', 0, 0));
    }
}

#[test]
fn setup_programs_the_device_in_order() {
    // LSR busy twice, then TEMT; IIR with working FIFOs; LSR, MSR; then
    // the first service routine finds nothing.
    let reads = [0, 0, LSR_TEMT, 0xC1, 0x60, 0, IIR_NO_INT | IIR_FIFOS];
    let mut s = Script {
        log: Vec::new(),
        reads: reads.into_iter().collect(),
        acks: 0,
    };
    let (uart, out) = Uart::start(&mut s);
    assert_eq!(uart.burst(), FIFO_BURST);
    assert_eq!(out, Outcome::default());
    let w = |reg, v| ('w', reg, v);
    let r = |reg, v| ('r', reg, v);
    assert_eq!(
        s.log,
        [
            w(LCR, 0x03),
            w(IER, 0),
            r(LSR, 0),
            r(LSR, 0),
            r(LSR, LSR_TEMT),
            w(LCR, 0x80),
            w(DLL, 1),
            w(DLM, 0),
            w(LCR, 0x03),
            w(FCR, 0x87),
            r(IIR, 0xC1),
            w(MCR, 0x0B),
            r(LSR, 0x60),
            r(MSR, 0),
            w(IER, 0x05),
            // Step 9: Ack, then the service routine.
            ('a', 0, 0),
            r(IIR, 0xC1),
        ]
    );
    assert_eq!(s.acks, 1);
    // Setup's LSR reads count no errors; Stats MR8 is the burst.
    assert_eq!(
        uart.stats(),
        UartStats {
            burst: 15,
            ..UartStats::default()
        }
    );
    assert_eq!(uart.stats().to_words()[8], 15);
}

#[test]
fn without_working_fifos_the_burst_is_one() {
    for iir in [0x01, 0x41, 0x81] {
        let mut s = Script {
            log: Vec::new(),
            reads: [LSR_TEMT, iir].into_iter().collect(),
            acks: 0,
        };
        assert_eq!(setup(&mut s), 1);
        assert!(s.log.contains(&('w', FCR, 0)), "FIFOs off for IIR {iir:#x}");
    }
    // Stats MR8 says so.
    let mut s = Script {
        log: Vec::new(),
        reads: [LSR_TEMT, 0x01, 0x60, 0, IIR_NO_INT].into_iter().collect(),
        acks: 0,
    };
    let (uart, _) = Uart::start(&mut s);
    assert_eq!((uart.burst(), uart.stats().burst), (1, 1));
    // TEMT never comes: 10,000 polls, then on.
    let mut s = Script {
        log: Vec::new(),
        reads: VecDeque::new(),
        acks: 0,
    };
    setup(&mut s);
    let polls = s.log.iter().filter(|e| e.1 == LSR && e.0 == 'r').count();
    assert_eq!(polls, TEMT_POLLS as usize + 1, "and step 7's read");
}

#[test]
fn requests_check_label_then_badge_then_length() {
    let mut buf = [0; MAX_BYTES];
    let words = [3u64, u64::from_le_bytes(*b"abc\0\0\0\0\0")];
    let w = |i: usize| words[i];
    assert_eq!(decode(0x114, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    assert_eq!(decode(0x120, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    assert_eq!(decode(0, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    // A bad badge before a bad length.
    assert_eq!(
        decode(label::UART_WRITE, 2, 9, w, &mut buf),
        Err(Refusal::BadBadge)
    );
    assert_eq!(
        decode(label::UART_READ, 0, 0, w, &mut buf),
        Err(Refusal::BadBadge)
    );
    assert_eq!(
        decode(label::UART_DRAIN, 3, 0, w, &mut buf),
        Err(Refusal::BadBadge)
    );
    assert_eq!(
        decode(label::UART_WRITE, 1, 3, w, &mut buf),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        decode(label::UART_WRITE, 1, 0, w, &mut buf),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        decode(label::UART_WRITE, 1, 2, w, &mut buf),
        Ok(Request::Write(b"abc"))
    );
    // Stats takes any badge; requests without words ignore any sent.
    for badge in [0, 1, 2, u64::MAX] {
        assert_eq!(
            decode(label::UART_STATS, badge, 5, w, &mut buf),
            Ok(Request::Stats)
        );
    }
    assert_eq!(
        decode(label::UART_READ, 1, 2, w, &mut buf),
        Ok(Request::Read)
    );
    assert_eq!(
        decode(label::UART_DRAIN, 1, 0, w, &mut buf),
        Ok(Request::Drain)
    );
    let big = |i: usize| if i == 0 { 953 } else { 0 };
    assert_eq!(
        decode(label::UART_WRITE, 1, 120, big, &mut buf),
        Err(Refusal::BadLength)
    );
}

/// What the random runs vary.
#[derive(Clone, Copy, Debug)]
struct Config {
    tx: Tx,
    rx: Rx,
    edges: Edges,
    fifos: bool,
    host_bytes: usize,
    console_bytes: usize,
    kernel_bytes: usize,
    /// Chance, per mille, of a device event before each access.
    p_event: u32,
    /// Chance, per mille, that console acts when it could.
    p_console: u32,
    line_errors: bool,
    /// The old loop: service, then Ack.
    service_first: bool,
    /// A THR write leaves a pending THRE interrupt pending (`Dev`).
    stale_thre: bool,
}

/// The device, the pin and the outside world, as uart's [`Port`] and
/// [`Irq`]: before each access, and on each side of an Ack, random events
/// may happen.
struct Sim {
    dev: Dev,
    pin: Pin,
    rng: Rng,
    host: VecDeque<u8>,
    sent_by_host: Vec<u8>,
    kernel: VecDeque<u8>,
    printed_by_kernel: Vec<u8>,
    p_event: u32,
    line_errors: bool,
    /// uart's THR writes since it last saw THRE (LSR or IIR).
    since_thre: usize,
    most_per_thre: usize,
    /// Time: uart's accesses, and the events while it waits.
    clock: u64,
    /// When the next host byte may arrive: a receiver that overruns
    /// gets at most one byte per [`BYTE_TIME`], a rate uart keeps up
    /// with; QEMU's offers bytes as fast as its FIFO has room.
    next_host: u64,
    /// When the slow transmitter may next move a byte: one per
    /// [`BYTE_TIME`], the same line rate as the receiver's.
    next_tick: u64,
}

/// A byte time, in uart's register accesses: at 115,200 baud a byte takes
/// 87 µs, several IOPort invocations' worth.
const BYTE_TIME: u64 = 6;

impl Sim {
    fn new(cfg: &Config, rng: Rng) -> Sim {
        let mut dev = Dev::new(cfg.tx, cfg.rx);
        dev.has_fifos = cfg.fifos;
        dev.stale_thre = cfg.stale_thre;
        Sim {
            dev,
            pin: Pin::new(cfg.edges),
            rng,
            host: VecDeque::new(),
            sent_by_host: Vec::new(),
            kernel: VecDeque::new(),
            printed_by_kernel: Vec::new(),
            p_event: cfg.p_event,
            line_errors: cfg.line_errors,
            since_thre: 0,
            most_per_thre: 0,
            clock: 0,
            next_host: 0,
            next_tick: 0,
        }
    }

    fn sync(&mut self) {
        let level = self.dev.line();
        self.pin.update(level);
    }

    /// One random event among those possible; false if none is. With
    /// `idle`, uart waits, so time may pass until the next host byte.
    fn event(&mut self, idle: bool) -> bool {
        let arriving = !self.host.is_empty() && self.dev.can_receive();
        let host = arriving && self.clock >= self.next_host;
        let sending = self.dev.tx_mode == Tx::Slow && self.dev.tx_busy();
        let tick = sending && self.clock >= self.next_tick;
        let timeout = self.dev.timeout_due();
        let kernel = !self.kernel.is_empty();
        let choices = [(host, 4), (tick, 4), (timeout, 1), (kernel, 1)];
        let total: usize = choices.iter().filter(|c| c.0).map(|c| c.1).sum();
        if total == 0 {
            // Nothing but time until the next byte arrives or leaves.
            let next = [(arriving, self.next_host), (sending, self.next_tick)]
                .into_iter()
                .filter(|w| w.0)
                .map(|w| w.1)
                .min();
            return match next {
                Some(t) if idle => {
                    self.clock = t;
                    true
                }
                _ => false,
            };
        }
        let mut pick = self.rng.below(total);
        let mut which = 0;
        for (i, &(ok, w)) in choices.iter().enumerate() {
            if !ok {
                continue;
            }
            if pick < w {
                which = i;
                break;
            }
            pick -= w;
        }
        match which {
            0 => {
                let b = self.host.pop_front().unwrap();
                let errors = if self.line_errors && self.rng.chance(20) {
                    LSR_FE
                } else {
                    0
                };
                self.dev.receive(b, errors);
                self.sent_by_host.push(b);
                if self.dev.rx_mode == Rx::Overrun {
                    self.next_host = self.clock + BYTE_TIME;
                }
            }
            1 => {
                self.dev.tick();
                self.next_tick = self.clock + BYTE_TIME;
            }
            2 => {
                self.dev.timeout();
            }
            _ => {
                // The debug kernel's writer: LSR until THRE, then THR.
                if self.dev.read(LSR) & LSR_THRE != 0 {
                    let b = self.kernel.pop_front().unwrap();
                    self.dev.write(THR, b, Src::Kernel);
                    self.printed_by_kernel.push(b);
                }
            }
        }
        self.sync();
        true
    }

    /// The transmitter moves one byte; whether it was busy.
    fn tick(&mut self) -> bool {
        let busy = self.dev.tick();
        self.sync();
        busy
    }

    fn maybe_events(&mut self) {
        while self.rng.chance(self.p_event) {
            if !self.event(false) {
                break;
            }
        }
    }
}

impl Port for Sim {
    fn read(&mut self, reg: u8) -> u8 {
        self.clock += 1;
        self.maybe_events();
        let v = self.dev.read(reg);
        let thre = match reg {
            LSR => v & LSR_THRE != 0,
            IIR => v & (IIR_NO_INT | IIR_ID) == IIR_THRI,
            _ => false,
        };
        if thre {
            self.since_thre = 0;
        }
        self.sync();
        v
    }

    fn write(&mut self, reg: u8, value: u8) {
        self.clock += 1;
        self.maybe_events();
        if reg == THR && self.dev.read(LCR) & LCR_DLAB == 0 {
            self.since_thre += 1;
            self.most_per_thre = self.most_per_thre.max(self.since_thre);
        }
        self.dev.write(reg, value, Src::Uart);
        self.sync();
    }
}

impl Irq for Sim {
    fn ack(&mut self) {
        self.maybe_events();
        self.pin.ack();
        self.maybe_events();
    }
}

/// console, as uart sees it: one request at a time.
#[derive(Default)]
struct Console {
    to_write: VecDeque<u8>,
    written: Vec<u8>,
    received: Vec<u8>,
    /// Bytes of a Write uart holds, or `Some(empty)` for a held Drain.
    held: Option<Vec<u8>>,
    held_drain: bool,
    rx_ready: bool,
    drained: bool,
}

/// How a run went wrong.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// uart blocked in its receive with an interrupt cause pending and no
    /// signal: it waits for ever.
    Stuck {
        step: usize,
        cause: u8,
    },
    Broken(std::string::String),
}

/// Runs uart and console against the model until nothing more can
/// happen, checking the invariants each time uart blocks.
fn run(cfg: Config, seed: u64) -> Result<(Uart, Sim, Console), Failure> {
    let mut sim = Sim::new(&cfg, Rng::new(seed));
    let mut con = Console {
        to_write: (0..cfg.console_bytes)
            .map(|i| (i * 31 % 251) as u8)
            .collect(),
        ..Console::default()
    };
    let broken = |m: std::string::String| Err(Failure::Broken(m));
    let (mut uart, first) = Uart::start(&mut sim);
    // Input starts once uart runs, as the harness's `send:` waits for a
    // line uart printed: setup's FIFO reset drops what came before. So
    // does the kernel's output: step 2 lets the bytes written before it
    // leave, but one written between it and the reset is lost, so tests
    // print nothing while uart starts.
    sim.host = (0..cfg.host_bytes).map(|_| sim.rng.next() as u8).collect();
    sim.kernel = (0..cfg.kernel_bytes)
        .map(|i| b'A' + (i % 26) as u8)
        .collect();
    let mut outcome = Some(first);
    let mut out = [0u8; MAX_BYTES];
    for step in 0..5_000_000 {
        if let Some(o) = outcome.take() {
            if o.signal_console {
                con.rx_ready = true;
            }
            match o.release {
                Some(Release::Written(n)) => {
                    let bytes = con.held.take().filter(|_| !con.held_drain);
                    match bytes {
                        Some(b) if b.len() == n => con.written.extend(b),
                        other => return broken(format!("released Write({n}) for {other:?}")),
                    }
                }
                Some(Release::Drained) => {
                    if !con.held_drain {
                        return broken("released a Drain nobody sent".into());
                    }
                    // A debug kernel's byte may follow uart's last.
                    if uart.queued() != 0 || sim.dev.fifo_holds(Src::Uart) {
                        return broken("a Drain answered before the queue and FIFO emptied".into());
                    }
                    con.held = None;
                    con.held_drain = false;
                    con.drained = true;
                }
                None => {}
            }
        }
        // uart's receive takes a pending signal first.
        if sim.pin.signal {
            sim.pin.signal = false;
            outcome = Some(if cfg.service_first {
                uart.stats.signals += 1;
                let o = uart.service(&mut sim);
                sim.ack();
                o
            } else {
                uart.on_interrupt(&mut sim)
            });
            continue;
        }
        // uart blocks here.
        if sim.dev.line() {
            return Err(Failure::Stuck {
                step,
                cause: sim.dev.cause(),
            });
        }
        if sim.dev.ier != uart.wanted_ier() {
            return broken(format!(
                "IER {:#x} with {} queued, {} buffered, {:?} held",
                sim.dev.ier,
                uart.queued(),
                uart.buffered(),
                uart.held()
            ));
        }
        if sim.dev.overflowed {
            return broken("the transmit FIFO overflowed".into());
        }
        // console runs only while uart waits.
        let idle = con.held.is_none() && !con.rx_ready && con.to_write.is_empty() && con.drained;
        if con.held.is_none() && !idle && sim.rng.chance(cfg.p_console) {
            let mut saved = false;
            let bytes: Vec<u8>;
            let req = if con.rx_ready {
                con.rx_ready = false;
                Request::Read
            } else if !con.to_write.is_empty() {
                let n = (1 + sim.rng.below(MAX_BYTES)).min(con.to_write.len());
                bytes = con.to_write.drain(..n).collect();
                Request::Write(&bytes)
            } else {
                Request::Drain
            };
            let a = uart.request(&mut sim, req, &mut out, || {
                saved = true;
                true
            });
            match (req, a) {
                (Request::Write(b), Answer::Written(n)) if n == b.len() => {
                    con.written.extend_from_slice(b)
                }
                (Request::Write(b), Answer::Held) if saved => con.held = Some(b.to_vec()),
                (Request::Read, Answer::Read(n)) => con.received.extend_from_slice(&out[..n]),
                (Request::Drain, Answer::Drained) => {
                    if uart.queued() != 0 || sim.dev.fifo_holds(Src::Uart) {
                        return broken("a Drain answered at once with bytes waiting".into());
                    }
                    con.drained = true;
                }
                (Request::Drain, Answer::Held) if saved => {
                    con.held = Some(Vec::new());
                    con.held_drain = true;
                }
                (r, a) => return broken(format!("{r:?} answered {a:?}")),
            }
            continue;
        }
        sim.clock += 1;
        if !sim.event(true) {
            // Nothing more can happen.
            if !idle {
                if con.held.is_some() {
                    return broken(format!(
                        "console's request is held for ever: {:?}",
                        uart.held()
                    ));
                }
                // console has work but chose not to act; let it.
                continue;
            }
            return Ok((uart, sim, con));
        }
    }
    broken("no end in 5,000,000 steps".into())
}

/// The checks of a run that ended: every byte once and in order, and the
/// limits held.
fn check_end(cfg: &Config, uart: &Uart, sim: &Sim, con: &Console) {
    let from = |src| -> Vec<u8> {
        sim.dev
            .wire
            .iter()
            .filter(|w| w.0 == src)
            .map(|w| w.1)
            .collect()
    };
    let expect: Vec<u8> = (0..cfg.console_bytes)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    assert_eq!(con.written, expect, "console's bytes, accepted in order");
    assert_eq!(
        from(Src::Uart),
        expect,
        "console's bytes on the wire, once and in order"
    );
    assert_eq!(
        from(Src::Kernel),
        sim.printed_by_kernel,
        "the kernel's bytes"
    );
    assert!(sim.kernel.is_empty() && sim.host.is_empty());
    match cfg.rx {
        Rx::Wait => assert_eq!(con.received, sim.sent_by_host, "every byte received"),
        Rx::Overrun => {
            // The bytes not lost, in order.
            let mut it = sim.sent_by_host.iter();
            assert!(con.received.iter().all(|b| it.any(|x| x == b)));
            assert_eq!(con.received.len() + sim.dev.lost, sim.sent_by_host.len());
            if sim.dev.lost > 0 && cfg.kernel_bytes == 0 {
                assert!(uart.stats().overruns > 0, "an overrun was counted");
            }
        }
    }
    let s = uart.stats();
    assert_eq!(s.cut_short, 0, "a working device never reaches the limit");
    assert_eq!(s.received as usize, con.received.len());
    assert_eq!(s.sent as usize, expect.len());
    assert!(
        sim.most_per_thre <= uart.burst(),
        "{} bytes after one THRE",
        sim.most_per_thre
    );
    assert_eq!(uart.queued(), 0);
    assert_eq!(uart.held(), None);
}

fn config(rng: &mut Rng) -> Config {
    let pick = |rng: &mut Rng, n| rng.below(n);
    let miri = cfg!(miri);
    let tx = [Tx::Slow, Tx::Instant][pick(rng, 2)];
    let fifos = pick(rng, 8) != 0;
    Config {
        // QEMU's instant transmitter comes with its receiver, which never
        // overruns; a device that sent at once but received at the line
        // rate would be no device at all.
        tx,
        rx: if tx == Tx::Instant {
            Rx::Wait
        } else {
            [Rx::Wait, Rx::Overrun][pick(rng, 2)]
        },
        edges: [Edges::Rising, Edges::EveryRaise][pick(rng, 2)],
        fifos,
        host_bytes: if miri { 40 } else { pick(rng, 700) },
        console_bytes: if miri { 300 } else { pick(rng, 6000) },
        // Without FIFOs the holding register has no spare place: a debug
        // kernel's byte written between uart's look at THRE and its own
        // write replaces it. Only a 16550 with FIFOs shares safely.
        kernel_bytes: if !fifos || pick(rng, 2) == 0 {
            0
        } else {
            pick(rng, 60)
        },
        p_event: [50, 200, 500, 800][pick(rng, 4)],
        p_console: [100, 500, 1000][pick(rng, 3)],
        line_errors: pick(rng, 4) == 0,
        service_first: false,
        stale_thre: pick(rng, 4) == 0,
    }
}

#[test]
fn random_interleavings_lose_nothing_and_never_strand_uart() {
    let runs = if cfg!(miri) { 2 } else { 400 };
    for seed in 0..runs {
        let mut rng = Rng::new(1000 + seed);
        let cfg = config(&mut rng);
        match run(cfg, seed) {
            Ok((uart, sim, con)) => check_end(&cfg, &uart, &sim, &con),
            Err(f) => panic!("seed {seed}, {cfg:?}: {f:?}"),
        }
    }
}

/// A THRE interrupt left pending by a THR write (`Dev::stale_thre`; the M8
/// Hyper-V check first suspected Hyper-V's 16550 of it, but its re-run
/// counted none) must not bring a burst onto a FIFO that still holds
/// bytes: uart writes one only when LSR says THRE, and counts the others
/// (Stats MR9). The slow transmitter, since QEMU's instant one
/// empties the FIFO before any interrupt can go stale.
#[test]
fn a_stale_thre_interrupt_never_overflows_the_fifo() {
    let runs = if cfg!(miri) { 2 } else { 300 };
    let mut stale = 0;
    for seed in 0..runs {
        let mut rng = Rng::new(9000 + seed);
        let base = config(&mut rng);
        let cfg = Config {
            tx: Tx::Slow,
            fifos: true,
            stale_thre: true,
            ..base
        };
        match run(cfg, seed) {
            Ok((uart, sim, con)) => {
                check_end(&cfg, &uart, &sim, &con);
                stale += uart.stats().stale_thre;
            }
            Err(f) => panic!("seed {seed}, {cfg:?}: {f:?}"),
        }
    }
    if !cfg!(miri) {
        assert!(stale > 0, "no THRE interrupt went stale");
    }
}

#[test]
fn servicing_before_the_ack_strands_uart() {
    // The old loop, wait, service, Ack, on an edge pin that drops edges
    // while masked: the same model finds a run where uart waits for ever
    // with a cause pending (ADR 0028).
    let tries = if cfg!(miri) { 0 } else { 400 };
    let found = (0..tries).find_map(|seed| {
        let mut rng = Rng::new(7000 + seed);
        let cfg = Config {
            edges: Edges::Rising,
            service_first: true,
            ..config(&mut rng)
        };
        match run(cfg, seed) {
            Err(Failure::Stuck { step, cause }) => Some((seed, step, cause)),
            _ => None,
        }
    });
    if !cfg!(miri) {
        assert!(found.is_some(), "the old order never lost an interrupt");
    }
}

/// A device for the hand-written tests: a FIFO 16550 set up by uart,
/// QEMU's instant transmitter, and no random events.
fn quiet(tx: Tx) -> (Uart, Sim) {
    let cfg = Config {
        tx,
        rx: Rx::Wait,
        edges: Edges::Rising,
        fifos: true,
        host_bytes: 0,
        console_bytes: 0,
        kernel_bytes: 0,
        p_event: 0,
        p_console: 1000,
        line_errors: false,
        service_first: false,
        stale_thre: false,
    };
    let mut sim = Sim::new(&cfg, Rng::new(1));
    let (uart, _) = Uart::start(&mut sim);
    (uart, sim)
}

fn write(uart: &mut Uart, sim: &mut Sim, bytes: &[u8], save: bool) -> Answer {
    let mut out = [0; MAX_BYTES];
    uart.request(sim, Request::Write(bytes), &mut out, || save)
}

#[test]
fn a_write_that_does_not_fit_is_held_and_released_in_order() {
    let (mut uart, mut sim) = quiet(Tx::Slow);
    let a = [b'a'; MAX_BYTES];
    let b = [b'b'; MAX_BYTES];
    let c = [b'c'; 300];
    // 952 fit; the first burst goes at once, since THRE is set.
    assert_eq!(write(&mut uart, &mut sim, &a, true), Answer::Written(952));
    assert_eq!(uart.queued(), 952 - 15);
    assert_eq!(write(&mut uart, &mut sim, &b, true), Answer::Written(952));
    // 1,889 queued: 300 more do not fit; nothing could be saved: Busy,
    // and nothing changes.
    assert_eq!(
        write(&mut uart, &mut sim, &c, false),
        Answer::Refused(Refusal::Busy)
    );
    assert_eq!((uart.queued(), uart.held()), (1889, None));
    assert_eq!(write(&mut uart, &mut sim, &c[..160], true), Answer::Held);
    assert_eq!(uart.held(), Some(Held::Write(160)));
    assert_eq!(uart.stats().writes_held, 1);
    // A second Write or a Drain while one is held: the slot is full.
    assert_eq!(
        write(&mut uart, &mut sim, b"x", false),
        Answer::Refused(Refusal::Busy)
    );
    let mut out = [0; MAX_BYTES];
    assert_eq!(
        uart.request(&mut sim, Request::Drain, &mut out, || false),
        Answer::Refused(Refusal::Busy)
    );
    assert_ne!(sim.dev.ier & IER_THRI, 0);
    // Transmit; every THRE interrupt gets a burst, and the held Write is
    // released once there is room for all of it.
    let mut released = Vec::new();
    while uart.queued() > 0 || uart.held().is_some() {
        while sim.tick() && !sim.pin.signal {}
        if sim.pin.signal {
            sim.pin.signal = false;
            let o = uart.on_interrupt(&mut sim);
            released.extend(o.release);
            assert!(uart.queued() <= TX_QUEUE);
        }
    }
    assert_eq!(released, [Release::Written(160)]);
    while sim.tick() {}
    let wire: Vec<u8> = sim.dev.wire.iter().map(|w| w.1).collect();
    assert_eq!(wire, [&a[..], &b, &c[..160]].concat());
    // Idle: no THRE interrupts.
    if sim.pin.signal {
        sim.pin.signal = false;
        uart.on_interrupt(&mut sim);
    }
    assert_eq!(sim.dev.ier & IER_THRI, 0);
    assert!(uart.stats().thre_bursts > 0);
}

#[test]
fn a_drain_is_answered_only_when_the_queue_and_fifo_are_empty() {
    let (mut uart, mut sim) = quiet(Tx::Slow);
    let mut out = [0; MAX_BYTES];
    // Idle: at once.
    assert_eq!(
        uart.request(&mut sim, Request::Drain, &mut out, || panic!()),
        Answer::Drained
    );
    assert_eq!(
        write(&mut uart, &mut sim, &[7; 40], true),
        Answer::Written(40)
    );
    assert_eq!(
        uart.request(&mut sim, Request::Drain, &mut out, || true),
        Answer::Held
    );
    assert_eq!(uart.held(), Some(Held::Drain));
    let mut released = None;
    for _ in 0..1000 {
        if sim.pin.signal {
            sim.pin.signal = false;
            let o = uart.on_interrupt(&mut sim);
            if let Some(r) = o.release {
                assert!(uart.queued() == 0 && sim.dev.thre(), "released early");
                released = Some(r);
                break;
            }
        }
        sim.tick();
    }
    assert_eq!(released, Some(Release::Drained));
    assert_eq!(sim.dev.ier & IER_THRI, 0, "nothing queued, nothing held");
}

#[test]
fn a_full_ring_stops_and_resumes_reception() {
    let (mut uart, mut sim) = quiet(Tx::Instant);
    let input: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
    sim.host = input.iter().copied().collect();
    let mut signals_to_console = 0;
    // No Read: the ring fills, the data bit goes off, the FIFO fills and
    // the host waits (QEMU's receiver).
    while sim.event(true) {
        if sim.pin.signal {
            sim.pin.signal = false;
            if uart.on_interrupt(&mut sim).signal_console {
                signals_to_console += 1;
            }
        }
    }
    assert_eq!(uart.buffered(), RX_RING);
    assert_eq!(sim.dev.rx_len(), 16);
    assert_eq!(sim.host.len(), 400 - RX_RING - 16);
    assert_eq!(sim.dev.ier & IER_RDI, 0);
    assert!(signals_to_console > 0);
    // Reads make room; reception resumes and nothing is lost.
    let mut out = [0; MAX_BYTES];
    let mut got = Vec::new();
    loop {
        let Answer::Read(n) = uart.request(&mut sim, Request::Read, &mut out, || panic!()) else {
            panic!()
        };
        got.extend_from_slice(&out[..n]);
        assert_ne!(sim.dev.ier & IER_RDI, 0, "the data bit is back");
        while sim.event(true) {
            if sim.pin.signal {
                sim.pin.signal = false;
                uart.on_interrupt(&mut sim);
            }
        }
        if sim.pin.signal {
            sim.pin.signal = false;
            uart.on_interrupt(&mut sim);
        }
        if got.len() == input.len() {
            break;
        }
        assert!(n > 0 || uart.buffered() > 0, "stalled at {}", got.len());
    }
    assert_eq!(got, input);
    assert_eq!(uart.stats().overruns, 0);
}

#[test]
fn qemus_transmitter_empties_the_queue_in_one_routine() {
    let (mut uart, mut sim) = quiet(Tx::Instant);
    for _ in 0..2 {
        assert_eq!(
            write(&mut uart, &mut sim, &[b'q'; MAX_BYTES], true),
            Answer::Written(952)
        );
    }
    // Each THR write leaves at once and raises THRE again.
    assert!(sim.pin.signal);
    sim.pin.signal = false;
    uart.on_interrupt(&mut sim);
    assert_eq!(uart.queued(), 0);
    assert_eq!(sim.dev.wire.len(), 2 * MAX_BYTES);
    let s = uart.stats();
    assert_eq!(s.cut_short, 0);
    assert_eq!(s.thre_bursts as usize, (2 * MAX_BYTES - 30).div_ceil(15));
}

#[test]
fn line_errors_and_overruns_are_counted() {
    let (mut uart, mut sim) = quiet(Tx::Instant);
    sim.dev.rx_mode = Rx::Overrun;
    sim.dev.receive(b'x', LSR_FE);
    for b in 0..20 {
        sim.dev.receive(b, 0);
    }
    sim.sync();
    assert!(sim.pin.signal);
    sim.pin.signal = false;
    let o = uart.on_interrupt(&mut sim);
    assert!(o.signal_console);
    let s = uart.stats();
    assert_eq!((s.overruns, s.line_errors), (1, 1));
    // The byte with the framing error is still read as data.
    let mut out = [0; MAX_BYTES];
    let Answer::Read(n) = uart.request(&mut sim, Request::Read, &mut out, || panic!()) else {
        panic!()
    };
    assert_eq!(n, 16);
    assert_eq!(out[0], b'x');
}

#[test]
fn a_device_whose_iir_never_clears_is_left_after_64_reads() {
    struct Stuck;
    impl Port for Stuck {
        fn read(&mut self, reg: u8) -> u8 {
            match reg {
                IIR => IIR_RLSI,
                _ => 0,
            }
        }
        fn write(&mut self, _: u8, _: u8) {}
    }
    let (mut uart, _) = quiet(Tx::Instant);
    uart.service(&mut Stuck);
    assert_eq!(uart.stats().cut_short, 1);
}
