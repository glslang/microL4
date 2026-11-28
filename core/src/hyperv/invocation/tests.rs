//! Host tests of the Hypervisor capability (`docs/abi.md`, "Hypervisor"):
//! its fields, Mint's narrowing through `CNode_Mint`, and the four
//! invocations through system calls as threads make them
//! ([`crate::syscall::handle_syscall`]) in the world of `crate::ipc`'s
//! tests, with every error row in its order, no hypercall made by a call
//! that fails, and the hypercalls' exact input recorded by the test kernel
//! (`crate::testing::Hypercall`).

use std::vec::Vec;

use super::*;
use crate::cdt;
use crate::error::SyscallError;
use crate::hyperv::{
    BLOCK_WORDS, POST_MESSAGE_INPUT, SIGNAL_EVENT_INPUT, parse_post_message_block, status,
};
use crate::invoke::label as cnode_label;
use crate::ipc::tests::*;
use crate::ipc::{MessageInfo, word};
use crate::slot::SlotMemory;
use crate::testing::Hypercall;

/// Root slots: the unrestricted capability, a boot root, and free slots
/// for minted ones.
const S_HV: u64 = S_FREE;
const S_M1: u64 = S_FREE + 1;
const S_M2: u64 = S_FREE + 2;
const S_M3: u64 = S_FREE + 3;

const ILLEGAL: SyscallError = SyscallError::IllegalOperation;
const TRUNCATED: SyscallError = SyscallError::TruncatedMessage;

fn world() -> World {
    let mut w = World::new();
    cdt::insert_root(&mut w.k, rs(S_HV), hypervisor_cap());
    w.k.dev.vp_index = 7;
    w
}

fn restricted(connection: u32, post: bool, signal: bool) -> HypervisorCap {
    HypervisorCap::Restricted {
        connection,
        post,
        signal,
    }
}

/// What thread A got back: the label (0 for success) and the words.
fn reply(w: &World) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(A).rsi);
    (
        m.label(),
        (0..m.length() as usize).map(|i| w.mr(A, i)).collect(),
    )
}

fn error(e: SyscallError) -> (u64, Vec<u64>) {
    let (words, n) = e.detail();
    (e.code(), words[..n].to_vec())
}

fn ok(words: &[u64]) -> (u64, Vec<u64>) {
    (0, words.to_vec())
}

/// Thread A calls `label` on `cptr` with `mrs`, MR4 and up in its buffer.
fn call(w: &mut World, cptr: u64, label: u64, mrs: &[u64]) -> (u64, Vec<u64>) {
    let mut regs = [0; 4];
    for (i, &m) in mrs.iter().enumerate() {
        match regs.get_mut(i) {
            Some(r) => *r = m,
            None => w.set_buf(A, word::MSG + i, m),
        }
    }
    let rsi = MessageInfo::new(label, 0, 0, mrs.len() as u64).word();
    w.syscall(A, 1, cptr, rsi, Some(regs));
    if !cfg!(miri) {
        w.check();
    }
    reply(w)
}

/// `CNode_Mint` of root slot `src` into `dst` with `data`.
fn mint(w: &mut World, dst: u64, src: u64, data: u64) -> (u64, Vec<u64>) {
    let rsi = MessageInfo::new(cnode_label::CNODE_MINT, 0, 1, 6).word();
    w.set_buf(A, word::MSG + 4, 0xF);
    w.set_buf(A, word::MSG + 5, data);
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    w.syscall(A, 1, S_ROOT, rsi, Some([dst, 64, src, 64]));
    reply(w)
}

fn post(w: &mut World, cptr: u64, connection: u64, ty: u64, payload: &[u8]) -> (u64, Vec<u64>) {
    let mut mrs = std::vec![connection, ty, payload.len() as u64];
    mrs.extend(payload.chunks(8).map(|c| {
        let mut b = [0u8; 8];
        b[..c.len()].copy_from_slice(c);
        u64::from_le_bytes(b)
    }));
    call(w, cptr, label::POST_MESSAGE, &mrs)
}

fn hv(w: &World, slot: u64) -> Option<HypervisorCap> {
    HypervisorCap::from_cap(&w.cap(rs(slot)))
}

#[test]
fn the_fields_round_trip_and_restricted_is_never_the_boot_word() {
    let caps = [
        HypervisorCap::Unrestricted,
        restricted(0, false, false),
        restricted(1, true, false),
        restricted(0xFF_FFFF, false, true),
        restricted(0x12_3456, true, true),
    ];
    for c in caps {
        let cap = c.cap();
        assert_eq!(cap.cap_type(), crate::cap::CapType::Hypervisor);
        assert_eq!(
            (cap.object(), cap.size_bits(), cap.is_device()),
            (0, 0, false)
        );
        assert_eq!(HypervisorCap::from_cap(&cap), Some(c));
    }
    assert_eq!(hypervisor_cap().data, 0);
    assert_ne!(restricted(0, false, false).cap().data, 0);
    assert_eq!(HypervisorCap::from_cap(&ntfn_cap(0, RW, 0)), None);
    // Same-object never holds, as for every capability without an object.
    assert!(!hypervisor_cap().same_object(&hypervisor_cap()));
}

#[test]
fn mint_narrows_never_widens_and_makes_an_original() {
    let u = HypervisorCap::Unrestricted;
    assert_eq!(u.mint(0), Ok((u, false)));
    let r = restricted(0x12_3456, true, true);
    assert_eq!(u.mint(0x12_3456 | MINT_POST | MINT_SIGNAL), Ok((r, true)));
    assert_eq!(u.mint(5), Ok((restricted(5, false, false), true)));
    assert_eq!(r.mint(0), Ok((r, false)));
    assert_eq!(
        r.mint(0x12_3456 | MINT_SIGNAL),
        Ok((restricted(0x12_3456, false, true), true))
    );
    assert_eq!(
        r.mint(0x12_3456),
        Ok((restricted(0x12_3456, false, false), true))
    );
    let s = restricted(0x12_3456, false, true);
    for widen in [
        0x12_3457 | MINT_SIGNAL,
        0x12_3456 | MINT_POST,
        0x12_3456 | MINT_POST | MINT_SIGNAL,
    ] {
        assert_eq!(s.mint(widen), Err(ILLEGAL), "{widen:#x}");
    }
    for bad in [1 << 26, 1 << 63, u64::MAX, 0x12_3456 | 1 << 40] {
        assert_eq!(u.mint(bad), Err(ILLEGAL), "{bad:#x}");
        assert_eq!(r.mint(bad), Err(ILLEGAL), "{bad:#x}");
    }
}

#[test]
fn cnode_mint_narrows_and_its_original_revokes_every_copy() {
    let mut w = world();
    // Data 0: a Copy, a child that is not an original.
    assert_eq!(mint(&mut w, S_M1, S_HV, 0), ok(&[]));
    assert_eq!(hv(&w, S_M1), Some(HypervisorCap::Unrestricted));
    assert!(!w.k.load(rs(S_M1)).node.original());
    assert_eq!(cdt::parent(&w.k, rs(S_M1)), Some(rs(S_HV)));
    // A narrowing: an original, a child of the boot capability.
    let conn = 0x2_0011;
    assert_eq!(mint(&mut w, S_M2, S_HV, conn | MINT_SIGNAL), ok(&[]));
    assert_eq!(hv(&w, S_M2), Some(restricted(conn as u32, false, true)));
    assert!(w.k.load(rs(S_M2)).node.original());
    assert_eq!(cdt::parent(&w.k, rs(S_M2)), Some(rs(S_HV)));
    // Narrowing a narrowed one widens nothing.
    assert_eq!(mint(&mut w, S_M3, S_M2, conn | MINT_POST), error(ILLEGAL));
    assert_eq!(
        mint(&mut w, S_M3, S_M2, (conn + 1) | MINT_SIGNAL),
        error(ILLEGAL)
    );
    assert_eq!(mint(&mut w, S_M3, S_M2, 1 << 26), error(ILLEGAL));
    assert!(w.cap(rs(S_M3)).is_null());
    // A plain copy of the narrowed original keeps its fields.
    let rsi = MessageInfo::new(cnode_label::CNODE_COPY, 0, 1, 5).word();
    w.set_buf(A, word::MSG + 4, 0xF);
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    w.syscall(A, 1, S_ROOT, rsi, Some([S_M3, 64, S_M2, 64]));
    assert_eq!(reply(&w), ok(&[]));
    assert_eq!(hv(&w, S_M3), hv(&w, S_M2));
    assert_eq!(cdt::parent(&w.k, rs(S_M3)), Some(rs(S_M2)));
    // Revoking the narrowed original takes back its copy, not itself.
    let rsi = MessageInfo::new(cnode_label::CNODE_REVOKE, 0, 0, 2).word();
    w.syscall(A, 1, S_ROOT, rsi, Some([S_M2, 64, 0, 0]));
    assert_eq!(reply(&w), ok(&[]));
    assert!(w.cap(rs(S_M3)).is_null());
    assert!(hv(&w, S_M2).is_some());
    // Deleting every capability changes nothing anywhere: no hook runs a
    // hypercall or a SynIC write.
    assert!(w.k.dev.hypercalls.is_empty());
    w.check();
}

#[test]
fn post_message_builds_the_whole_block_and_returns_the_status() {
    let mut w = world();
    let payload: Vec<u8> = (1..=13).collect();
    assert_eq!(post(&mut w, S_HV, 1, 1, &payload), ok(&[0]));
    let [Hypercall::Post { input, block }] = &w.k.dev.hypercalls[..] else {
        panic!("{:?}", w.k.dev.hypercalls)
    };
    assert_eq!(*input, POST_MESSAGE_INPUT);
    let (connection, reserved, ty, size, bytes) = parse_post_message_block(block);
    assert_eq!((connection, reserved, ty, size), (1, 0, 1, 13));
    assert_eq!(&bytes[..13], &payload[..]);
    assert!(bytes[13..].iter().all(|&b| b == 0));
    // Bytes past the size are dropped, whatever the registers hold.
    w.k.dev.hypercalls.clear();
    let r = call(
        &mut w,
        S_HV,
        label::POST_MESSAGE,
        &[0xFF_FFFF, 0x7FFF_FFFF, 3, u64::MAX],
    );
    assert_eq!(r, ok(&[0]));
    let Hypercall::Post { block, .. } = &w.k.dev.hypercalls[0] else {
        panic!()
    };
    assert_eq!(block[0], 0xFF_FFFF);
    assert_eq!(block[1], 0x7FFF_FFFF | 3 << 32);
    assert_eq!(block[2], 0xFF_FFFF);
    assert!(block[3..].iter().all(|&w| w == 0));
    // A full 240-byte payload: MR3 to MR32, most in the IPC buffer.
    w.k.dev.hypercalls.clear();
    w.k.dev.hv_status = status::INSUFFICIENT_BUFFERS;
    let full: Vec<u8> = (0..240).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(
        post(&mut w, S_HV, 0x2_0000, 14, &full),
        ok(&[u64::from(status::INSUFFICIENT_BUFFERS)])
    );
    let Hypercall::Post { block, .. } = &w.k.dev.hypercalls[0] else {
        panic!()
    };
    assert_eq!(block.len(), BLOCK_WORDS);
    let (_, _, _, size, bytes) = parse_post_message_block(block);
    assert_eq!((size, &bytes[..]), (240, &full[..]));
    // No payload at all.
    w.k.dev.hypercalls.clear();
    assert_eq!(post(&mut w, S_HV, 3, 9, &[]).0, 0);
    let Hypercall::Post { block, .. } = &w.k.dev.hypercalls[0] else {
        panic!()
    };
    assert!(block[1] >> 32 == 0 && block[2..].iter().all(|&w| w == 0));
}

#[test]
fn signal_event_is_fast_with_connection_and_flag_in_rdx() {
    let mut w = world();
    w.k.dev.hv_status = status::INVALID_PARAMETER;
    let r = call(&mut w, S_HV, label::SIGNAL_EVENT, &[0x12_3456, 0xFFFF]);
    assert_eq!(r, ok(&[u64::from(status::INVALID_PARAMETER)]));
    assert_eq!(
        w.k.dev.hypercalls,
        [Hypercall::Signal {
            input: SIGNAL_EVENT_INPUT,
            rdx: 0xFFFF_0012_3456
        }]
    );
}

#[test]
fn eom_and_vp_index_need_the_unrestricted_capability() {
    let mut w = world();
    assert_eq!(call(&mut w, S_HV, label::EOM, &[]), ok(&[]));
    assert_eq!(call(&mut w, S_HV, label::VP_INDEX, &[1, 2, 3]), ok(&[7]));
    assert_eq!(w.k.dev.hypercalls, [Hypercall::Eom, Hypercall::VpIndex]);
    assert_eq!(
        mint(&mut w, S_M1, S_HV, 9 | MINT_POST | MINT_SIGNAL),
        ok(&[])
    );
    w.k.dev.hypercalls.clear();
    for l in [label::EOM, label::VP_INDEX] {
        assert_eq!(call(&mut w, S_M1, l, &[]), error(ILLEGAL));
    }
    assert!(w.k.dev.hypercalls.is_empty());
}

#[test]
fn a_restricted_capability_acts_only_on_its_connection_with_its_rights() {
    let mut w = world();
    let conn = 0x2_0011;
    assert_eq!(mint(&mut w, S_M1, S_HV, conn | MINT_SIGNAL), ok(&[]));
    assert_eq!(mint(&mut w, S_M2, S_HV, conn | MINT_POST), ok(&[]));
    assert_eq!(mint(&mut w, S_M3, S_HV, conn), ok(&[]));
    // Signal only.
    assert_eq!(
        call(&mut w, S_M1, label::SIGNAL_EVENT, &[conn, 3]),
        ok(&[0])
    );
    assert_eq!(
        call(&mut w, S_M1, label::SIGNAL_EVENT, &[conn + 1, 3]),
        error(ILLEGAL)
    );
    assert_eq!(
        call(&mut w, S_M1, label::SIGNAL_EVENT, &[1, 3]),
        error(ILLEGAL)
    );
    assert_eq!(post(&mut w, S_M1, conn, 1, b"x"), error(ILLEGAL));
    // Post only.
    assert_eq!(post(&mut w, S_M2, conn, 1, b"x"), ok(&[0]));
    assert_eq!(post(&mut w, S_M2, 1, 1, b"x"), error(ILLEGAL));
    assert_eq!(
        call(&mut w, S_M2, label::SIGNAL_EVENT, &[conn, 0]),
        error(ILLEGAL)
    );
    // Neither.
    assert_eq!(post(&mut w, S_M3, conn, 1, b"x"), error(ILLEGAL));
    assert_eq!(
        call(&mut w, S_M3, label::SIGNAL_EVENT, &[conn, 0]),
        error(ILLEGAL)
    );
    assert_eq!(w.k.dev.hypercalls.len(), 2, "{:?}", w.k.dev.hypercalls);
}

#[test]
fn errors_in_order_and_no_hypercall_from_a_failed_call() {
    let mut w = world();
    let conn = 5;
    assert_eq!(mint(&mut w, S_M1, S_HV, conn | MINT_SIGNAL), ok(&[]));
    let post_l = label::POST_MESSAGE;
    let sig = label::SIGNAL_EVENT;
    let arg = SyscallError::InvalidArgument;
    let cases: &[(&str, u64, u64, &[u64], SyscallError)] = &[
        // 1: the label.
        ("reserved 0x84", S_HV, 0x84, &[], ILLEGAL),
        ("reserved 0x8F", S_HV, 0x8F, &[1, 1, 0], ILLEGAL),
        ("label 0x90", S_HV, 0x90, &[], ILLEGAL),
        ("IOPort's In8", S_HV, 0x71, &[0x3F8], ILLEGAL),
        ("CNode_Copy", S_HV, 0x13, &[], ILLEGAL),
        // 2: the length.
        ("PostMessage, 2 registers", S_HV, post_l, &[1, 1], TRUNCATED),
        (
            "PostMessage, bad type but short",
            S_M1,
            post_l,
            &[1, 0],
            TRUNCATED,
        ),
        ("SignalEvent, 1 register", S_HV, sig, &[1], TRUNCATED),
        (
            "SignalEvent, restricted and short",
            S_M1,
            sig,
            &[],
            TRUNCATED,
        ),
        // 3: the arguments, in register order.
        ("connection 2^24", S_HV, post_l, &[1 << 24, 0, 241], arg(0)),
        ("type 0", S_HV, post_l, &[1, 0, 241], arg(1)),
        ("type 2^31", S_HV, post_l, &[1, 1 << 31, 0], arg(1)),
        ("size 241", S_HV, post_l, &[1, 1, 241], arg(2)),
        ("size 2^63", S_HV, post_l, &[1, 1, 1 << 63], arg(2)),
        ("restricted, type 0", S_M1, post_l, &[conn, 0, 0], arg(1)),
        (
            "signal, connection 2^24",
            S_HV,
            sig,
            &[1 << 24, 1 << 16],
            arg(0),
        ),
        ("signal, flag 2^16", S_HV, sig, &[1, 1 << 16], arg(1)),
        (
            "restricted, flag 2^16",
            S_M1,
            sig,
            &[conn + 1, 1 << 16],
            arg(1),
        ),
        // 2, after 3: the payload's registers.
        (
            "size 9, one payload word",
            S_HV,
            post_l,
            &[1, 1, 9, 0],
            TRUNCATED,
        ),
        ("size 1, no payload", S_HV, post_l, &[1, 1, 1], TRUNCATED),
        (
            "restricted, no payload",
            S_M1,
            post_l,
            &[conn, 1, 8],
            TRUNCATED,
        ),
        // 4: the capability's limits.
        ("no post right", S_M1, post_l, &[conn, 1, 0], ILLEGAL),
        ("another connection", S_M1, sig, &[conn + 1, 0], ILLEGAL),
        ("restricted Eom", S_M1, label::EOM, &[], ILLEGAL),
        ("restricted VpIndex", S_M1, label::VP_INDEX, &[], ILLEGAL),
    ];
    for &(what, cptr, l, mrs, e) in cases {
        let before: Vec<_> = (0..32).map(|i| w.k.load(rs(i))).collect();
        assert_eq!(call(&mut w, cptr, l, mrs), error(e), "{what}");
        assert!(w.k.dev.hypercalls.is_empty(), "{what} made a hypercall");
        let after: Vec<_> = (0..32).map(|i| w.k.load(rs(i))).collect();
        assert!(before == after, "{what} changed a slot");
    }
}

#[test]
fn send_performs_the_call_and_drops_the_reply() {
    let mut w = world();
    let rsi = MessageInfo::new(label::SIGNAL_EVENT, 0, 0, 2).word();
    w.syscall(A, 3, S_HV, rsi, Some([1, 2, 0, 0]));
    assert_eq!(
        w.k.dev.hypercalls,
        [Hypercall::Signal {
            input: SIGNAL_EVENT_INPUT,
            rdx: 2 << 32 | 1
        }]
    );
    // No reply: `rsi` still holds the message's own info, MR0 its own word.
    assert_eq!((w.regs(A).rsi, w.mr(A, 0)), (rsi, 1), "no reply");
}
