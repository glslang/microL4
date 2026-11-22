//! Retiring a badge: `cancel_badged_sends` (`docs/design.md`, "Deletion
//! and cancellation" and "Badges, revoke and `CNode_CancelBadgedSends`";
//! `docs/abi.md`, `CNode_CancelBadgedSends`).
//!
//! A server retiring badge `b` first revokes its badged original, so that
//! no capability with `b` is left to send with, then releases the senders
//! already queued with `b`. Only the endpoint's queue is touched, as in
//! seL4's `cancelBadgedSends`: a caller whose message was already received
//! is `BlockedOnReply`, keeps its reply capability and waits for the reply
//! as before; receivers are never queued with senders.

use crate::sched;
use crate::tcb::{EpRef, ThreadState};

use super::endpoint::{self as queue, EpState, IpcEnv};

/// `cancel_badged_sends(E, b)`: every thread `BlockedOnSend` on `ep` whose
/// recorded badge is `badge` leaves the queue, in queue order, with its
/// fault cleared, and becomes `Restart`, made runnable, so it re-executes
/// its system call (or, for a queued fault, its faulting instruction) and
/// resolves its `CPtr`s afresh. The other senders keep their order, and
/// `ep` becomes `Idle` if none is left. Nothing happens for badge 0 or an
/// endpoint not in state `Send`.
///
/// Not preemptible, as in seL4 and like [`super::cancel_all_ipc`]: one
/// O(1) step per queued thread, and the queue holds at most the TCBs that
/// exist.
pub fn cancel_badged_sends<E: IpcEnv + ?Sized>(e: &mut E, ep: EpRef, badge: u64) {
    if badge == 0 || e.endpoint(ep).state != EpState::Send {
        return;
    }
    let mut next = e.endpoint(ep).head;
    while let Some(t) = next {
        next = e.ep_links(t).1;
        let ThreadState::BlockedOnSend { badge: sent, .. } = e.state(t) else {
            panic!("a thread in a Send queue is not sending");
        };
        if sent == badge {
            queue::remove(e, ep, t);
            e.set_fault(t, None);
            sched::set_thread_state(e, t, ThreadState::Restart);
            sched::make_runnable(e, t);
        }
    }
}
