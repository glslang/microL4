//! `udp_echo:`'s exchange (`docs/design.md`, "The harness: `nic:` and
//! `udp_echo:`"): datagrams sent through QEMU's forwarded port to the
//! guest's echo service, each of which must come back once, unaltered.
//!
//! [`exchange`] sends from one loopback socket, at most [`WINDOW`]
//! datagrams unanswered at a time and the next as each echo arrives, with
//! no retransmission, and takes the echoes in any order. Each must come
//! from the forwarded port and equal an unanswered datagram's payload byte
//! for byte; an echo from another source, of nothing outstanding, altered
//! or answering a datagram twice is a problem the [`Report`] keeps, and
//! fails the scenario. It ends once every datagram is answered, after
//! [`Limits::idle`] with no echo, after [`Limits::total`] in all, or at
//! the scenario's deadline. `tools/hyperv/Send-L4Udp.ps1` sends the same
//! payloads the same way on Hyper-V.

use std::fmt::Write as _;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Datagram `k` is `LENGTHS[k % 13]` bytes long. 18 bytes make a 60-byte
/// Ethernet frame, the shortest without padding, and 17 and below shorter
/// ones; 1,472 is the most that fits a 1,500-byte IPv4 packet, so none is
/// fragmented; the odd lengths exercise a checksum's last byte.
pub const LENGTHS: [usize; 13] = [8, 9, 17, 18, 19, 64, 255, 256, 512, 952, 953, 1471, 1472];
/// Every payload's first four bytes.
pub const MAGIC: [u8; 4] = *b"uL4E";
/// The most datagrams unanswered at a time.
pub const WINDOW: u32 = 8;
/// The most datagrams one `udp_echo:` sends.
pub const MAX_COUNT: u32 = 1000;
/// The most problems a report lists one by one; it counts the rest.
const MAX_LISTED: usize = 8;

/// When an exchange gives up.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// It ends after this long with no echo, counted from its start or
    /// from the last datagram that came back.
    pub idle: Duration,
    /// It ends after this long in all.
    pub total: Duration,
    /// Once every datagram is answered, it listens this much longer, so a
    /// duplicate of the last echo still fails it.
    pub grace: Duration,
}

impl Limits {
    /// A scenario's: 5 s with no echo, 30 s in all, then 500 ms more.
    pub const SCENARIO: Limits = Limits {
        idle: Duration::from_secs(5),
        total: Duration::from_secs(30),
        grace: Duration::from_millis(500),
    };
}

/// Datagram `k`'s payload: [`LENGTHS`]`[k % 13]` bytes, of which bytes 0
/// to 3 are [`MAGIC`], 4 to 7 `k` as a little-endian `u32`, and byte `j`
/// from 8 on `(k + 3j) mod 256`.
pub fn payload(k: u32) -> Vec<u8> {
    let len = LENGTHS[k as usize % LENGTHS.len()];
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(&MAGIC);
    p.extend_from_slice(&k.to_le_bytes());
    p.extend((8..len).map(|j| (k as usize + 3 * j) as u8));
    p
}

/// Why an exchange ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// Every datagram came back.
    Answered,
    /// [`Limits::idle`] passed with no echo.
    Idle,
    /// [`Limits::total`] passed.
    Total,
    /// The scenario's deadline came first.
    Deadline,
}

/// What one exchange sent and got back.
#[derive(Debug)]
pub struct Report {
    /// The forwarded port the datagrams went to.
    pub to: SocketAddr,
    /// How many datagrams the step asked for.
    pub count: u32,
    /// How many were sent: those from 0 to `sent - 1`.
    pub sent: u32,
    /// The limits it ran under.
    limits: Limits,
    /// Whether each datagram has come back.
    answered: Vec<bool>,
    /// How many came back.
    pub echoed: u32,
    /// Why it ended.
    pub end: End,
    /// The first [`MAX_LISTED`] problems, in the order they came.
    problems: Vec<String>,
    /// How many problems there were in all.
    bad: usize,
}

impl Report {
    fn new(to: SocketAddr, count: u32, limits: Limits) -> Report {
        Report {
            to,
            count,
            sent: 0,
            limits,
            answered: vec![false; count as usize],
            echoed: 0,
            end: End::Answered,
            problems: Vec::new(),
            bad: 0,
        }
    }

    /// The datagrams that never came back, sent or not.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.count)
            .filter(|&k| !self.answered[k as usize])
            .collect()
    }

    /// Every echo that broke a rule, the first [`MAX_LISTED`] each in a
    /// line, then how many more there were.
    pub fn problems(&self) -> Vec<String> {
        let mut lines = self.problems.clone();
        if self.bad > self.problems.len() {
            lines.push(format!("and {} more", self.bad - self.problems.len()));
        }
        lines
    }

    /// The log's line: `udp_echo <count> to <to>: <k> echoed`, with the
    /// missing indices and why the exchange ended when `k` is short.
    pub fn line(&self) -> String {
        let mut line = format!(
            "udp_echo {} to {}: {} echoed",
            self.count, self.to, self.echoed
        );
        if self.echoed < self.count {
            let secs = |d: Duration| format!("{} s", d.as_secs_f64());
            let why = match self.end {
                End::Answered => String::new(),
                End::Idle => format!("after {} with no echo", secs(self.limits.idle)),
                End::Total => format!("after {} in all", secs(self.limits.total)),
                End::Deadline => "at the scenario's deadline".into(),
            };
            let _ = write!(
                line,
                "; missing {} ({} sent; ended {why})",
                ranges(&self.missing()),
                self.sent
            );
        }
        line
    }

    /// Why the scenario fails, if it does: a datagram missing, or any
    /// problem.
    pub fn failure(&self) -> Option<String> {
        let mut why = Vec::new();
        if self.echoed < self.count {
            why.push(format!(
                "{} of {} echoed, missing {}",
                self.echoed,
                self.count,
                ranges(&self.missing())
            ));
        }
        if let Some(first) = self.problems.first() {
            let more = match self.bad {
                1 => String::new(),
                n => format!(" ({n} problems in all)"),
            };
            why.push(format!("{first}{more}"));
        }
        (!why.is_empty()).then(|| format!("udp_echo {}: {}", self.count, why.join("; ")))
    }

    fn problem(&mut self, what: String) {
        self.bad += 1;
        if self.problems.len() < MAX_LISTED {
            self.problems.push(what);
        }
    }

    /// Checks one datagram that came back from `from`.
    fn take(&mut self, echo: &[u8], from: SocketAddr) {
        if from != self.to {
            return self.problem(format!(
                "an echo from {from}, not from the forwarded port {}",
                self.to
            ));
        }
        let k = match echo {
            [a, b, c, d, k @ ..] if [*a, *b, *c, *d] == MAGIC && k.len() >= 4 => {
                u32::from_le_bytes([k[0], k[1], k[2], k[3]])
            }
            _ => {
                return self.problem(format!(
                    "an echo of {} bytes that begins as no datagram does",
                    echo.len()
                ));
            }
        };
        if k >= self.sent {
            return self.problem(format!(
                "an echo of datagram {k}, of {}, which was never sent",
                self.count
            ));
        }
        let want = payload(k);
        if echo != want.as_slice() {
            let how = match want.iter().zip(echo).position(|(w, e)| w != e) {
                Some(j) => format!("byte {j} differs"),
                None => format!("{} bytes, not {}", echo.len(), want.len()),
            };
            return self.problem(format!("an altered echo of datagram {k}: {how}"));
        }
        let answered = &mut self.answered[k as usize];
        if *answered {
            return self.problem(format!("a second echo of datagram {k}"));
        }
        *answered = true;
        self.echoed += 1;
    }
}

/// Sends `count` datagrams to `to`, the forwarded port, and checks what
/// comes back, until every datagram is answered, `limits` end it, or
/// `deadline` comes. Fails only if the socket does.
pub fn exchange(
    to: SocketAddr,
    count: u32,
    limits: Limits,
    deadline: Instant,
) -> io::Result<Report> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let start = Instant::now();
    let total = start + limits.total;
    let mut report = Report::new(to, count, limits);
    // When the last datagram came back, or the start.
    let mut last = start;
    // Room for any datagram, so a long echo is not cut to look right.
    let mut buf = vec![0; 1 << 16];
    loop {
        while report.sent < count && report.sent - report.echoed < WINDOW {
            socket.send_to(&payload(report.sent), to)?;
            report.sent += 1;
        }
        if report.echoed == count {
            // Every datagram answered: listen `grace` longer, so an echo
            // that trails the last one (a duplicate) is still checked.
            let until = (Instant::now() + limits.grace).min(deadline);
            loop {
                let now = Instant::now();
                if now >= until {
                    break;
                }
                socket.set_read_timeout(Some(until - now))?;
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => report.take(&buf[..n], from),
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    Err(e) => return Err(e),
                }
            }
            report.end = End::Answered;
            return Ok(report);
        }
        let now = Instant::now();
        let idle = last + limits.idle;
        let (until, end) = [
            (idle, End::Idle),
            (total, End::Total),
            (deadline, End::Deadline),
        ]
        .into_iter()
        .min_by_key(|(t, _)| *t)
        .unwrap();
        if now >= until {
            report.end = end;
            return Ok(report);
        }
        socket.set_read_timeout(Some(until - now))?;
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                last = Instant::now();
                report.take(&buf[..n], from);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Indices as ranges: `3, 17-99`. Past 16 ranges it stops and says how
/// many indices there are in all.
pub fn ranges(indices: &[u32]) -> String {
    const MAX_RANGES: usize = 16;
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for &k in indices {
        match runs.last_mut() {
            Some((_, end)) if *end + 1 == k => *end = k,
            _ => runs.push((k, k)),
        }
    }
    let mut out: Vec<String> = runs
        .iter()
        .take(MAX_RANGES)
        .map(|&(a, b)| match a == b {
            true => a.to_string(),
            false => format!("{a}-{b}"),
        })
        .collect();
    if runs.len() > MAX_RANGES {
        out.push(format!("... ({} in all)", indices.len()));
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};

    /// What the fake echo server does with each datagram it receives.
    #[derive(Clone, Copy)]
    enum Peer {
        /// Echoes each at once.
        Echo,
        /// Holds each batch of up to [`WINDOW`] and echoes it backwards.
        Reverse,
        /// Echoes all but datagram `k`.
        Lose(u32),
        /// Echoes datagram `k` twice.
        Twice(u32),
        /// Echoes datagram `k` with byte 12 flipped.
        Alter(u32),
        /// Echoes datagram `k` cut to 10 bytes.
        Cut(u32),
        /// Echoes datagram `k` from another socket.
        OtherPort(u32),
        /// Echoes each, and before datagram `k`'s also sends datagram
        /// `count + 5`'s payload and 6 bytes of nothing.
        Strays(u32),
        /// Echoes each after `ms` milliseconds.
        Slow(u64),
        /// Echoes nothing.
        Mute,
    }

    /// A fake of QEMU's forwarded port and the guest's echo service, on
    /// loopback, serving on a thread of its own until [`Fake::received`].
    struct Fake {
        addr: SocketAddr,
        thread: JoinHandle<Vec<u32>>,
    }

    /// What ends a fake: a datagram no exchange sends.
    const STOP: &[u8] = b"stop";

    impl Fake {
        fn start(peer: Peer, count: u32) -> Fake {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = socket.local_addr().unwrap();
            // A test that never stops its fake still ends.
            socket
                .set_read_timeout(Some(Duration::from_secs(60)))
                .unwrap();
            let thread = thread::spawn(move || {
                let mut got = Vec::new();
                let mut held: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
                let mut buf = vec![0; 1 << 16];
                while let Ok((n, from)) = socket.recv_from(&mut buf) {
                    let d = buf[..n].to_vec();
                    if d == STOP {
                        break;
                    }
                    let k = u32::from_le_bytes(d[4..8].try_into().unwrap());
                    got.push(k);
                    let send = |bytes: &[u8]| {
                        socket.send_to(bytes, from).unwrap();
                    };
                    match peer {
                        Peer::Echo => send(&d),
                        Peer::Reverse => {
                            held.push((d, from));
                            let batch_start = (got.len() as u32 - 1) / WINDOW * WINDOW;
                            if held.len() as u32 == WINDOW.min(count - batch_start) {
                                for (d, from) in held.drain(..).rev() {
                                    socket.send_to(&d, from).unwrap();
                                }
                            }
                        }
                        Peer::Lose(x) if k == x => {}
                        Peer::Twice(x) if k == x => {
                            send(&d);
                            send(&d);
                        }
                        Peer::Alter(x) if k == x => {
                            let mut d = d;
                            d[12] ^= 1;
                            send(&d);
                        }
                        Peer::Cut(x) if k == x => send(&d[..10]),
                        Peer::OtherPort(x) if k == x => {
                            other.send_to(&d, from).unwrap();
                        }
                        Peer::Strays(x) if k == x => {
                            send(&payload(count + 5));
                            send(b"stray!");
                            send(&d);
                        }
                        Peer::Slow(ms) => {
                            thread::sleep(Duration::from_millis(ms));
                            send(&d);
                        }
                        Peer::Mute => {}
                        _ => send(&d),
                    }
                }
                got
            });
            Fake { addr, thread }
        }

        /// Stops the fake once it has served what came before, and returns
        /// the indices it received, in order.
        fn received(self) -> Vec<u32> {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket.send_to(STOP, self.addr).unwrap();
            self.thread.join().unwrap()
        }
    }

    /// Short limits, so a test that must wait for one is quick; long
    /// enough that a loaded machine still answers within them.
    const SHORT: Limits = Limits {
        idle: Duration::from_millis(800),
        total: Duration::from_secs(20),
        grace: Duration::from_millis(300),
    };

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn run(peer: Peer, count: u32, limits: Limits) -> (Report, Vec<u32>) {
        let fake = Fake::start(peer, count);
        let report = exchange(fake.addr, count, limits, far()).unwrap();
        (report, fake.received())
    }

    #[test]
    fn payloads_have_the_lengths_and_bytes() {
        let lengths: Vec<usize> = (0..26).map(|k| payload(k).len()).collect();
        assert_eq!(lengths[..13], LENGTHS);
        assert_eq!(lengths[13..], LENGTHS);
        assert_eq!(payload(0), b"uL4E\0\0\0\0");
        assert_eq!(payload(1), [b'u', b'L', b'4', b'E', 1, 0, 0, 0, 1 + 3 * 8]);
        // 300 = 23 * 13 + 1: 9 bytes, and k's low byte in the formula.
        let p = payload(300);
        assert_eq!(p.len(), 9);
        assert_eq!(p[4..8], 300u32.to_le_bytes());
        assert_eq!(p[8], ((300 + 24) % 256) as u8);
        let p = payload(12 + 13 * 100);
        assert_eq!(p.len(), 1472);
        assert_eq!(p[..8], [b'u', b'L', b'4', b'E', 0x20, 0x05, 0, 0]);
        for (j, &b) in p.iter().enumerate().skip(8) {
            assert_eq!(b, ((1312 + 3 * j) % 256) as u8, "byte {j}");
        }
        // Every payload differs from every other.
        let all: Vec<Vec<u8>> = (0..MAX_COUNT).map(payload).collect();
        for (i, a) in all.iter().enumerate() {
            assert!(all[..i].iter().all(|b| b != a), "{i}");
        }
    }

    #[test]
    fn every_datagram_answered() {
        let (r, got) = run(Peer::Echo, 100, Limits::SCENARIO);
        assert_eq!((r.echoed, r.sent, r.end), (100, 100, End::Answered));
        assert_eq!(r.missing(), []);
        assert_eq!(r.problems(), Vec::<String>::new());
        assert_eq!(r.failure(), None);
        assert_eq!(
            got,
            (0..100).collect::<Vec<_>>(),
            "each sent once, in order"
        );
        assert_eq!(r.line(), format!("udp_echo 100 to {}: 100 echoed", r.to));
    }

    #[test]
    fn echoes_in_any_order_pass() {
        for count in [8, 13, 100] {
            let (r, got) = run(Peer::Reverse, count, Limits::SCENARIO);
            assert_eq!((r.echoed, r.end), (count, End::Answered), "{count}");
            assert_eq!(r.failure(), None, "{count}");
            assert_eq!(got.len() as u32, count);
        }
    }

    #[test]
    fn at_most_eight_go_unanswered() {
        let (r, got) = run(Peer::Mute, 100, SHORT);
        assert_eq!(got, (0..8).collect::<Vec<_>>());
        assert_eq!((r.sent, r.echoed, r.end), (8, 0, End::Idle));
        assert_eq!(r.missing().len(), 100);
        assert_eq!(
            r.line(),
            format!(
                "udp_echo 100 to {}: 0 echoed; missing 0-99 (8 sent; ended after 0.8 s with no echo)",
                r.to
            )
        );
        assert_eq!(
            r.failure().unwrap(),
            "udp_echo 100: 0 of 100 echoed, missing 0-99"
        );
        let (r, got) = run(Peer::Mute, 5, SHORT);
        assert_eq!((got.len(), r.sent), (5, 5));
    }

    #[test]
    fn a_lost_datagram_is_missing() {
        let (r, got) = run(Peer::Lose(41), 100, SHORT);
        assert_eq!(got, (0..100).collect::<Vec<_>>(), "no retransmission");
        assert_eq!((r.echoed, r.end), (99, End::Idle));
        assert_eq!(r.missing(), [41]);
        assert!(
            r.line()
                .ends_with(": 99 echoed; missing 41 (100 sent; ended after 0.8 s with no echo)"),
            "{}",
            r.line()
        );
        assert_eq!(
            r.failure().unwrap(),
            "udp_echo 100: 99 of 100 echoed, missing 41"
        );
    }

    /// A duplicate of the last outstanding echo arrives after every
    /// datagram is answered; the grace period still sees it.
    #[test]
    fn a_duplicate_of_the_last_echo_fails() {
        for count in [1, 8, 20] {
            let (r, _) = run(Peer::Twice(count - 1), count, Limits::SCENARIO);
            assert_eq!((r.echoed, r.end), (count, End::Answered), "{count}");
            let want = format!("a second echo of datagram {}", count - 1);
            assert_eq!(r.problems(), [want.as_str()], "{count}");
            assert_eq!(
                r.failure().unwrap(),
                format!("udp_echo {count}: {want}"),
                "{count}"
            );
        }
    }

    #[test]
    fn a_duplicate_fails() {
        let (r, _) = run(Peer::Twice(7), 20, Limits::SCENARIO);
        assert_eq!(r.echoed, 20);
        assert_eq!(r.problems(), ["a second echo of datagram 7"]);
        assert_eq!(
            r.failure().unwrap(),
            "udp_echo 20: a second echo of datagram 7"
        );
    }

    #[test]
    fn an_altered_or_cut_echo_fails() {
        let (r, _) = run(Peer::Alter(5), 20, SHORT);
        assert_eq!((r.echoed, r.missing()), (19, vec![5]));
        assert_eq!(
            r.problems(),
            ["an altered echo of datagram 5: byte 12 differs"]
        );
        assert_eq!(
            r.failure().unwrap(),
            "udp_echo 20: 19 of 20 echoed, missing 5; an altered echo of datagram 5: byte 12 differs"
        );
        // Datagram 6 is 255 bytes.
        let (r, _) = run(Peer::Cut(6), 20, SHORT);
        assert_eq!(r.missing(), [6]);
        assert_eq!(
            r.problems(),
            ["an altered echo of datagram 6: 10 bytes, not 255"]
        );
    }

    /// Review (M9, reviewer S): an echo longer than its datagram, its
    /// datagram's bytes and then more, is altered too: the comparison is
    /// of the whole echo, not of a prefix.
    #[test]
    fn an_echo_longer_than_its_datagram_fails() {
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let mut r = Report::new(to, 3, Limits::SCENARIO);
        r.sent = 3;
        let mut long = payload(1);
        long.push(0);
        r.take(&long, to);
        assert_eq!(
            r.problems(),
            ["an altered echo of datagram 1: 10 bytes, not 9"]
        );
        assert_eq!((r.echoed, r.missing()), (0, vec![0, 1, 2]));
        assert!(r.failure().unwrap().contains("missing 0-2"));
        // The datagram itself still counts once it comes.
        r.take(&payload(1), to);
        assert_eq!((r.echoed, r.missing()), (1, vec![0, 2]));
    }

    #[test]
    fn an_echo_from_another_port_fails() {
        let (r, _) = run(Peer::OtherPort(3), 20, SHORT);
        assert_eq!(r.missing(), [3]);
        let p = r.problems();
        assert_eq!(p.len(), 1);
        assert!(
            p[0].starts_with("an echo from 127.0.0.1:")
                && p[0].ends_with(&format!(", not from the forwarded port {}", r.to)),
            "{p:?}"
        );
    }

    #[test]
    fn an_echo_of_nothing_outstanding_fails() {
        let (r, _) = run(Peer::Strays(10), 20, Limits::SCENARIO);
        assert_eq!((r.echoed, r.end), (20, End::Answered));
        assert_eq!(
            r.problems(),
            [
                "an echo of datagram 25, of 20, which was never sent",
                "an echo of 6 bytes that begins as no datagram does",
            ]
        );
        assert_eq!(
            r.failure().unwrap(),
            "udp_echo 20: an echo of datagram 25, of 20, which was never sent (2 problems in all)"
        );
    }

    #[test]
    fn a_server_slower_than_the_idle_limit_fails() {
        let limits = Limits {
            idle: Duration::from_millis(300),
            total: Duration::from_secs(20),
            grace: Duration::from_millis(300),
        };
        let start = Instant::now();
        let fake = Fake::start(Peer::Slow(1000), 2);
        let r = exchange(fake.addr, 2, limits, far()).unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(900),
            "{:?}",
            start.elapsed()
        );
        assert_eq!((r.echoed, r.sent, r.end), (0, 2, End::Idle));
        // Its late echoes reach a socket that has gone.
        assert_eq!(fake.received(), [0, 1]);
    }

    #[test]
    fn the_total_limit_and_the_deadline_end_it() {
        // An echo every 100 ms keeps the idle limit away; the total ends it.
        let limits = Limits {
            idle: Duration::from_secs(5),
            total: Duration::from_millis(700),
            grace: Duration::from_millis(300),
        };
        let fake = Fake::start(Peer::Slow(100), 1000);
        let r = exchange(fake.addr, 1000, limits, far()).unwrap();
        assert_eq!(r.end, End::Total);
        assert!(r.echoed > 0 && r.echoed < 1000, "{}", r.echoed);
        assert!(
            r.line().contains("ended after 0.7 s in all"),
            "{}",
            r.line()
        );
        fake.received();

        let fake = Fake::start(Peer::Slow(100), 1000);
        let deadline = Instant::now() + Duration::from_millis(700);
        let r = exchange(fake.addr, 1000, Limits::SCENARIO, deadline).unwrap();
        assert_eq!(r.end, End::Deadline);
        assert!(Instant::now() < deadline + Duration::from_millis(500));
        assert!(
            r.line().contains("ended at the scenario's deadline"),
            "{}",
            r.line()
        );
        fake.received();
    }

    #[test]
    fn many_problems_are_counted() {
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let mut r = Report::new(to, 3, Limits::SCENARIO);
        r.sent = 3;
        for _ in 0..11 {
            r.take(b"junk", to);
        }
        let p = r.problems();
        assert_eq!(p.len(), MAX_LISTED + 1);
        assert_eq!(p[MAX_LISTED], "and 3 more");
        assert!(r.failure().unwrap().ends_with("(11 problems in all)"));
        // A good echo after them still counts.
        r.take(&payload(1), to);
        assert_eq!((r.echoed, r.missing()), (1, vec![0, 2]));
    }

    #[test]
    fn ranges_are_compact() {
        assert_eq!(ranges(&[]), "");
        assert_eq!(ranges(&[3]), "3");
        assert_eq!(ranges(&[3, 17, 18, 19, 99]), "3, 17-19, 99");
        assert_eq!(ranges(&(0..100).collect::<Vec<_>>()), "0-99");
        let every_other: Vec<u32> = (0..100).step_by(2).collect();
        let s = ranges(&every_other);
        assert!(
            s.starts_with("0, 2, 4,") && s.ends_with(", 30, ... (50 in all)"),
            "{s}"
        );
    }

    /// Every datagram leaves from one loopback socket.
    #[test]
    fn one_socket_sends_every_datagram() {
        let (tx, rx) = mpsc::channel();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = server.local_addr().unwrap();
        let t = thread::spawn(move || {
            let mut buf = [0; 2048];
            let mut sources = Vec::new();
            for _ in 0..30 {
                let (n, from) = server.recv_from(&mut buf).unwrap();
                sources.push(from);
                server.send_to(&buf[..n], from).unwrap();
            }
            tx.send(sources).unwrap();
        });
        let r = exchange(addr, 30, Limits::SCENARIO, far()).unwrap();
        assert_eq!(r.failure(), None);
        let sources = rx.recv().unwrap();
        t.join().unwrap();
        assert!(sources.iter().all(|s| *s == sources[0]), "{sources:?}");
        assert_eq!(sources[0].ip(), Ipv4Addr::LOCALHOST);
    }
}
