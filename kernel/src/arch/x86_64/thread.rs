//! The end of every kernel entry (`docs/design.md`, "Scheduling", "Exit",
//! "FS and GS base", "Switching (M5)"): the scheduler picks a thread, which
//! is activated and exits to user mode, or the kernel idles.
//!
//! Switching to a thread other than the last one to run saves that one's
//! FS and GS bases from their MSRs (a segment load in ring 3 can change
//! them) and loads the new one's; every exit loads the VSpace in the
//! thread's VSpace slot, since `TCB_Configure` or `TCB_SetSpace` on the
//! caller changes it without a reschedule, and makes the thread own the
//! FP registers. The idle thread runs on the kernel PML4 and owns nothing,
//! so A, idle, A switches no FP state and no bases.

use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};

use l4core::cap::{Cap, TCB_SLOT_VSPACE};
use l4core::regs::Regs;
use l4core::sched;
use l4core::slot::SlotMemory;
use l4core::tcb::{self, REGS_OFFSET, TcbRef, Tcbs};

use super::{Objects, entry, fpu, paging, trap};

/// The thread whose FS and GS bases are in `IA32_FS_BASE` and
/// `IA32_KERNEL_GS_BASE`, by physical address, or 0 for none: at boot, and
/// once that TCB is finalised, whose bases then need no saving.
static LOADED: AtomicU64 = AtomicU64::new(0);

/// A TCB's last capability is gone: its bases are not saved on the next
/// switch (`docs/design.md`, "FS and GS base": "skipping a TCB finalised in
/// this entry").
pub fn forget(t: TcbRef) {
    let _ = LOADED.compare_exchange(t.get(), 0, Ordering::Relaxed, Ordering::Relaxed);
}

/// Most TCBs the debug check of the queues walks before it calls a cycle.
const QUEUE_LIMIT: usize = 1 << 20;

/// Ends a kernel entry: [`sched::schedule`] picks the thread to run, which
/// is activated (a `Restart` thread goes back to its `fault_ip`) and
/// entered through [`entry::exit_to_user`]; with nothing runnable the
/// kernel idles. Nothing may be held on the kernel stack: it is abandoned.
pub fn exit_to_scheduled() -> ! {
    let next = {
        let mut k = Objects::begin();
        let next = sched::schedule(&mut k);
        debug_assert_eq!(sched::check_exit(&k, QUEUE_LIMIT).err(), None);
        next.map(|t| {
            tcb::activate(&mut k, t);
            switch_to(&mut k, t);
            k.regs(t)
        })
    };
    match next {
        Some(regs) => entry::exit_to_user(&regs),
        None => {
            paging::set_vm_root(Cap::NULL);
            trap::idle()
        }
    }
}

/// Makes `t`'s FS and GS bases, VSpace and FP state the live ones.
fn switch_to(k: &mut Objects, t: TcbRef) {
    let loaded = LOADED.load(Ordering::Relaxed);
    if loaded != t.get() {
        if let Some(prev) = TcbRef::new(loaded) {
            let mut bases = Regs::default();
            entry::save_user_bases(&mut bases);
            let at = |f: usize| REGS_OFFSET + f as u64;
            k.set_tcb_word(prev, at(offset_of!(Regs, fs_base)), bases.fs_base);
            k.set_tcb_word(prev, at(offset_of!(Regs, gs_base)), bases.gs_base);
        }
        entry::load_user_bases(&k.regs(t));
        LOADED.store(t.get(), Ordering::Relaxed);
    }
    paging::set_vm_root(k.load(t.slot(TCB_SLOT_VSPACE)).cap);
    fpu::switch_to(t);
}
