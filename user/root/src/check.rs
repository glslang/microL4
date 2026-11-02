//! The verdicts of `test=threads` and `test=fault`, from what the threads
//! recorded and the messages they received.

use core::fmt;

use libsys::Received;
use libsys::fault_label::VM_FAULT;

/// The names of `test=threads`' threads, by index.
pub const NAMES: [char; 2] = ['A', 'B'];

/// What the two threads of `test=threads` recorded.
#[derive(Clone, Copy, Debug)]
pub struct ThreadsLog<'a> {
    /// Per thread, how many times it found in its busy phase, which makes
    /// no system call, that the other thread had run since it last looked:
    /// each is a preemption that let the other thread run in between.
    pub preempted: [u64; 2],
    /// The index of the thread that printed each line, in print order.
    pub lines: &'a [u8],
    /// Lines each thread prints.
    pub lines_each: usize,
}

/// Why `test=threads` fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadsFailure {
    /// Entry `at` of the line log names no thread.
    BadLine { at: usize, id: u8 },
    /// A thread printed `count` lines, not `want`.
    LineCount {
        thread: usize,
        count: usize,
        want: usize,
    },
    /// A thread saw the other run in between only `count` times.
    TooFewPreemptions { thread: usize, count: u64, min: u64 },
    /// The print order changed thread only `count` times.
    TooFewAlternations { count: usize, min: usize },
}

impl fmt::Display for ThreadsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ThreadsFailure::BadLine { at, id } => {
                write!(
                    f,
                    "line {at} of the log names thread {id}, which does not exist"
                )
            }
            ThreadsFailure::LineCount {
                thread,
                count,
                want,
            } => write!(
                f,
                "thread {} printed {count} lines, not {want}",
                NAMES[thread]
            ),
            ThreadsFailure::TooFewPreemptions { thread, count, min } => write!(
                f,
                "thread {} was preempted with the other thread running in between {count} times, fewer than {min}",
                NAMES[thread]
            ),
            ThreadsFailure::TooFewAlternations { count, min } => write!(
                f,
                "the lines changed thread {count} times in print order, fewer than {min}: the output did not interleave"
            ),
        }
    }
}

/// Checks `test=threads`' log: each thread printed its lines, each was
/// preempted with the other running in between at least
/// `min_preemptions` times, and the print order changed thread at least
/// `min_alternations` times. Returns how many times it did.
pub fn threads(
    log: &ThreadsLog<'_>,
    min_preemptions: u64,
    min_alternations: usize,
) -> Result<usize, ThreadsFailure> {
    let mut count = [0; 2];
    for (at, &id) in log.lines.iter().enumerate() {
        match count.get_mut(usize::from(id)) {
            Some(c) => *c += 1,
            None => return Err(ThreadsFailure::BadLine { at, id }),
        }
    }
    for (thread, &count) in count.iter().enumerate() {
        if count != log.lines_each {
            return Err(ThreadsFailure::LineCount {
                thread,
                count,
                want: log.lines_each,
            });
        }
    }
    for (thread, &count) in log.preempted.iter().enumerate() {
        if count < min_preemptions {
            return Err(ThreadsFailure::TooFewPreemptions {
                thread,
                count,
                min: min_preemptions,
            });
        }
    }
    let alternations = log.lines.windows(2).filter(|w| w[0] != w[1]).count();
    if alternations < min_alternations {
        return Err(ThreadsFailure::TooFewAlternations {
            count: alternations,
            min: min_alternations,
        });
    }
    Ok(alternations)
}

/// Thread indices as their names, `"ABBA"`, in `buf`; `?` for an index
/// that names no thread, and the indices past `buf.len()` left out.
pub fn names<'b>(ids: &[u8], buf: &'b mut [u8]) -> &'b str {
    let n = ids.len().min(buf.len());
    for (b, &id) in buf.iter_mut().zip(&ids[..n]) {
        *b = NAMES.get(usize::from(id)).map_or(b'?', |&c| c as u8);
    }
    // Every byte written is ASCII.
    core::str::from_utf8(&buf[..n]).unwrap_or("")
}

/// The words of a `VMFault` message (`docs/abi.md`, "VMFault (5)").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmFault {
    /// The faulting instruction.
    pub ip: u64,
    /// The faulting address, CR2.
    pub addr: u64,
    /// 1 for an instruction fetch.
    pub prefetch: u64,
    /// The page-fault error code.
    pub fsr: u64,
}

/// Page-fault error code bits: a protection violation (else a page not
/// present), a write, from ring 3, a reserved bit set, an instruction fetch.
pub const PF_PRESENT: u64 = 1 << 0;
pub const PF_WRITE: u64 = 1 << 1;
pub const PF_USER: u64 = 1 << 2;
pub const PF_RESERVED: u64 = 1 << 3;
pub const PF_FETCH: u64 = 1 << 4;

/// A word of a message that is not what it should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub what: &'static str,
    pub got: u64,
    pub want: u64,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is {:#x}, not {:#x}", self.what, self.got, self.want)
    }
}

/// Checks that `r` is the fault message a ring-3 read of the unmapped
/// `addr` by the instruction at `ip` sends through an unbadged fault
/// endpoint capability: label `VMFault`, four words, badge 0, that `ip`
/// and `addr`, no fetch, and an error code that says a user-mode read of a
/// page not present.
pub fn vm_fault(r: &Received, ip: u64, addr: u64) -> Result<VmFault, Mismatch> {
    let expect = |what, got, want| {
        if got == want {
            Ok(())
        } else {
            Err(Mismatch { what, got, want })
        }
    };
    let info = r.msg.info;
    expect("the label (the fault type)", info.label(), VM_FAULT)?;
    expect("the length", info.length(), 4)?;
    expect("the badge", r.badge, 0)?;
    let [ip_got, addr_got, prefetch, fsr] = r.msg.mr;
    expect("MR0, ip", ip_got, ip)?;
    expect("MR1, addr", addr_got, addr)?;
    expect("MR2, prefetch", prefetch, 0)?;
    let bits = PF_PRESENT | PF_WRITE | PF_USER | PF_RESERVED | PF_FETCH;
    expect("MR3, fsr's low five bits", fsr & bits, PF_USER)?;
    Ok(VmFault {
        ip: ip_got,
        addr: addr_got,
        prefetch,
        fsr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::{Message, MessageInfo};
    use std::string::ToString;

    fn log(preempted: [u64; 2], lines: &[u8]) -> ThreadsLog<'_> {
        ThreadsLog {
            preempted,
            lines,
            lines_each: 3,
        }
    }

    #[test]
    fn interleaved_preempted_threads_pass() {
        assert_eq!(threads(&log([5, 4], &[0, 1, 0, 1, 1, 0]), 3, 3), Ok(4));
        assert_eq!(threads(&log([3, 3], &[0, 1, 1, 0, 0, 1]), 3, 3), Ok(3));
    }

    #[test]
    fn too_few_preemptions_fail() {
        assert_eq!(
            threads(&log([5, 2], &[0, 1, 0, 1, 0, 1]), 3, 3),
            Err(ThreadsFailure::TooFewPreemptions {
                thread: 1,
                count: 2,
                min: 3
            })
        );
        assert_eq!(
            threads(&log([0, 9], &[0, 1, 0, 1, 0, 1]), 1, 3),
            Err(ThreadsFailure::TooFewPreemptions {
                thread: 0,
                count: 0,
                min: 1
            })
        );
    }

    #[test]
    fn output_that_does_not_interleave_fails() {
        // One thread's lines, then the other's: preempted, but the output
        // came in two blocks.
        assert_eq!(
            threads(&log([9, 9], &[0, 0, 0, 1, 1, 1]), 3, 3),
            Err(ThreadsFailure::TooFewAlternations { count: 1, min: 3 })
        );
    }

    #[test]
    fn a_wrong_line_log_fails() {
        assert_eq!(
            threads(&log([9, 9], &[0, 1, 0, 1, 0]), 3, 3),
            Err(ThreadsFailure::LineCount {
                thread: 1,
                count: 2,
                want: 3
            })
        );
        assert_eq!(
            threads(&log([9, 9], &[0, 1, 2, 1, 0, 1]), 3, 3),
            Err(ThreadsFailure::BadLine { at: 2, id: 2 })
        );
        assert_eq!(
            threads(&log([9, 9], &[]), 3, 3),
            Err(ThreadsFailure::LineCount {
                thread: 0,
                count: 0,
                want: 3
            })
        );
    }

    #[test]
    fn failures_read_well() {
        let e = ThreadsFailure::TooFewPreemptions {
            thread: 1,
            count: 2,
            min: 3,
        };
        assert_eq!(
            e.to_string(),
            "thread B was preempted with the other thread running in between 2 times, fewer than 3"
        );
    }

    #[test]
    fn names_of_a_log() {
        let mut buf = [0; 4];
        assert_eq!(names(&[0, 1, 1], &mut buf), "ABB");
        assert_eq!(names(&[1, 7, 0, 0, 1], &mut buf), "B?AA");
        assert_eq!(names(&[], &mut buf), "");
    }

    const IP: u64 = 0x40_1234;
    const ADDR: u64 = 0xDEAD_BEE8;

    fn fault(label: u64, length: u64, badge: u64, mr: [u64; 4]) -> Received {
        Received {
            badge,
            msg: Message::new(MessageInfo::new(label, 0, 0, length), mr),
        }
    }

    #[test]
    fn the_vm_fault_of_a_user_read_passes() {
        for fsr in [PF_USER, PF_USER | 0x8000_0000] {
            assert_eq!(
                vm_fault(&fault(5, 4, 0, [IP, ADDR, 0, fsr]), IP, ADDR),
                Ok(VmFault {
                    ip: IP,
                    addr: ADDR,
                    prefetch: 0,
                    fsr
                })
            );
        }
    }

    #[test]
    fn any_other_fault_message_fails() {
        let good = [IP, ADDR, 0, PF_USER];
        let cases = [
            (fault(3, 5, 0, good), "the label (the fault type)"),
            (fault(5, 3, 0, good), "the length"),
            (fault(5, 4, 7, good), "the badge"),
            (fault(5, 4, 0, [IP + 3, ADDR, 0, PF_USER]), "MR0, ip"),
            (fault(5, 4, 0, [IP, ADDR & !0xFFF, 0, PF_USER]), "MR1, addr"),
            (fault(5, 4, 0, [IP, ADDR, 1, PF_USER]), "MR2, prefetch"),
            (
                fault(5, 4, 0, [IP, ADDR, 0, PF_USER | PF_WRITE]),
                "MR3, fsr's low five bits",
            ),
            (
                fault(5, 4, 0, [IP, ADDR, 0, PF_USER | PF_PRESENT]),
                "MR3, fsr's low five bits",
            ),
            (fault(5, 4, 0, [IP, ADDR, 0, 0]), "MR3, fsr's low five bits"),
        ];
        for (r, what) in cases {
            assert_eq!(vm_fault(&r, IP, ADDR).map_err(|m| m.what), Err(what));
        }
        assert_eq!(
            vm_fault(&fault(5, 4, 0, [IP, 0x1000, 0, PF_USER]), IP, ADDR)
                .unwrap_err()
                .to_string(),
            "MR1, addr is 0x1000, not 0xdeadbee8"
        );
    }
}
