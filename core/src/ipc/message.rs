//! The layout of a message (`docs/abi.md`, "Messages", "Message registers"
//! and "MessageInfo semantics"): [`MessageInfo`], the IPC buffer
//! ([`IpcBuffer`] and its [`word`] indices) and where message register `i`
//! travels ([`mr_location`]). The kernel and `libsys` both use it, so the
//! two sides cannot disagree.
//!
//! MR0 to MR3 travel in `r10`, `r8`, `r9` and `r15`; MR4 to MR119 in IPC
//! buffer words 5 to 120 (`msg[4..120]`). Buffer words 1 to 4 (`msg[0..4]`)
//! are never read or written by the kernel; user stubs may spill MR0 to MR3
//! there.

use core::fmt;

use crate::regs::Regs;

/// Message registers in one message (`MSG_MAX_LENGTH`).
pub const MSG_MAX_LENGTH: usize = 120;
/// Message registers held in CPU registers (`MSG_REG_COUNT`): `r10`, `r8`,
/// `r9` and `r15`.
pub const MSG_REG_COUNT: usize = 4;
/// Capability pointers one message may name (`MSG_MAX_EXTRA_CAPS`).
pub const MSG_MAX_EXTRA_CAPS: usize = 3;
/// The IPC buffer is `2^10` bytes, aligned to its size.
pub const IPC_BUFFER_BITS: u32 = 10;
/// Bytes in the IPC buffer.
pub const IPC_BUFFER_SIZE: u64 = 1 << IPC_BUFFER_BITS;
/// Words in the IPC buffer.
pub const IPC_BUFFER_WORDS: usize = 128;

const LENGTH_BITS: u32 = 7;
const EXTRA_CAPS_SHIFT: u32 = 7;
const EXTRA_CAPS_BITS: u32 = 2;
const CAPS_UNWRAPPED_SHIFT: u32 = 9;
const CAPS_UNWRAPPED_BITS: u32 = 3;
const LABEL_SHIFT: u32 = 12;
/// Bits in [`MessageInfo::label`]: 52.
pub const LABEL_BITS: u32 = 64 - LABEL_SHIFT;

const fn mask(bits: u32) -> u64 {
    (1 << bits) - 1
}

/// seL4's 64-bit `MessageInfo`: `length` in bits 0 to 6, `extra_caps` in 7
/// and 8, `caps_unwrapped` in 9 to 11, `label` in 12 to 63. Every word is
/// a valid `MessageInfo`; what a field means depends on the direction
/// (`docs/abi.md`, "MessageInfo semantics").
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MessageInfo(u64);

impl MessageInfo {
    /// A `MessageInfo` from its fields, in seL4's argument order
    /// (`seL4_MessageInfo_new`). Panics if a field does not fit its bits:
    /// `label` 52, `caps_unwrapped` 3, `extra_caps` 2 and `length` 7.
    pub const fn new(label: u64, caps_unwrapped: u64, extra_caps: u64, length: u64) -> MessageInfo {
        assert!(label <= mask(LABEL_BITS), "label wider than 52 bits");
        assert!(
            caps_unwrapped <= mask(CAPS_UNWRAPPED_BITS),
            "caps_unwrapped wider than 3 bits"
        );
        assert!(extra_caps <= mask(EXTRA_CAPS_BITS), "extra_caps above 3");
        assert!(length <= mask(LENGTH_BITS), "length above 127");
        MessageInfo(
            label << LABEL_SHIFT
                | caps_unwrapped << CAPS_UNWRAPPED_SHIFT
                | extra_caps << EXTRA_CAPS_SHIFT
                | length,
        )
    }

    /// The `MessageInfo` in a register.
    pub const fn from_word(word: u64) -> MessageInfo {
        MessageInfo(word)
    }

    /// The word that goes in `rsi`.
    pub const fn word(self) -> u64 {
        self.0
    }

    /// User data, an invocation label, a fault type or an error code.
    pub const fn label(self) -> u64 {
        self.0 >> LABEL_SHIFT
    }

    /// Bit `i` set: extra capability `i` was unwrapped to its badge.
    pub const fn caps_unwrapped(self) -> u64 {
        (self.0 >> CAPS_UNWRAPPED_SHIFT) & mask(CAPS_UNWRAPPED_BITS)
    }

    /// Capability pointers named in `caps_or_badges`, 0 to 3.
    pub const fn extra_caps(self) -> u64 {
        (self.0 >> EXTRA_CAPS_SHIFT) & mask(EXTRA_CAPS_BITS)
    }

    /// The field as written, 0 to 127.
    pub const fn length(self) -> u64 {
        self.0 & mask(LENGTH_BITS)
    }

    /// The message registers a sender asks to send: [`MessageInfo::length`]
    /// with 121 to 127 counted as 120 (seL4's `messageInfoFromWord`).
    pub const fn sent_length(self) -> u64 {
        let length = self.length();
        if length > MSG_MAX_LENGTH as u64 {
            MSG_MAX_LENGTH as u64
        } else {
            length
        }
    }
}

impl fmt::Debug for MessageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageInfo")
            .field("label", &self.label())
            .field("caps_unwrapped", &self.caps_unwrapped())
            .field("extra_caps", &self.extra_caps())
            .field("length", &self.length())
            .finish()
    }
}

/// The IPC buffer, seL4's layout: 128 words, 1024 bytes, aligned to 1024.
/// `libsys` reads and writes its own buffer through this type; the kernel
/// never forms a reference to one and uses the [`word`] indices.
#[repr(C, align(1024))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcBuffer {
    /// A `MessageInfo` for user libraries; the kernel never uses it.
    pub tag: u64,
    /// `msg[i]` is message register `i` for `i >= 4`; `msg[0..4]` are
    /// never read or written by the kernel.
    pub msg: [u64; MSG_MAX_LENGTH],
    /// Never touched by the kernel.
    pub user_data: u64,
    /// Capability pointers on send, badges of unwrapped capabilities on
    /// receive.
    pub caps_or_badges: [u64; MSG_MAX_EXTRA_CAPS],
    /// Where a received capability goes: CNode, index and depth.
    pub receive_cnode: u64,
    pub receive_index: u64,
    pub receive_depth: u64,
}

impl IpcBuffer {
    /// The all-zero buffer.
    pub const ZERO: IpcBuffer = IpcBuffer {
        tag: 0,
        msg: [0; MSG_MAX_LENGTH],
        user_data: 0,
        caps_or_badges: [0; MSG_MAX_EXTRA_CAPS],
        receive_cnode: 0,
        receive_index: 0,
        receive_depth: 0,
    };
}

/// The IPC buffer's word indices (`docs/abi.md`, "IPC buffer"); the byte
/// offset is 8 times the index.
pub mod word {
    /// `tag`.
    pub const TAG: usize = 0;
    /// `msg[0]`; `msg[i]` is word `MSG + i`.
    pub const MSG: usize = 1;
    /// `user_data`.
    pub const USER_DATA: usize = 121;
    /// `caps_or_badges[0]`; entry `i` is word `CAPS_OR_BADGES + i`.
    pub const CAPS_OR_BADGES: usize = 122;
    /// `receive_cnode`.
    pub const RECEIVE_CNODE: usize = 125;
    /// `receive_index`.
    pub const RECEIVE_INDEX: usize = 126;
    /// `receive_depth`.
    pub const RECEIVE_DEPTH: usize = 127;
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<IpcBuffer>() == IPC_BUFFER_SIZE as usize);
    assert!(size_of::<IpcBuffer>() == IPC_BUFFER_WORDS * 8);
    assert!(align_of::<IpcBuffer>() == IPC_BUFFER_SIZE as usize);
    assert!(offset_of!(IpcBuffer, tag) == word::TAG * 8);
    assert!(offset_of!(IpcBuffer, msg) == word::MSG * 8);
    assert!(offset_of!(IpcBuffer, user_data) == word::USER_DATA * 8);
    assert!(offset_of!(IpcBuffer, user_data) == 968);
    assert!(offset_of!(IpcBuffer, caps_or_badges) == word::CAPS_OR_BADGES * 8);
    assert!(offset_of!(IpcBuffer, caps_or_badges) == 976);
    assert!(offset_of!(IpcBuffer, receive_cnode) == word::RECEIVE_CNODE * 8);
    assert!(offset_of!(IpcBuffer, receive_index) == word::RECEIVE_INDEX * 8);
    assert!(offset_of!(IpcBuffer, receive_depth) == word::RECEIVE_DEPTH * 8);
    assert!(offset_of!(IpcBuffer, receive_depth) == 1016);
    assert!(word::MSG + MSG_MAX_LENGTH == word::USER_DATA);
    assert!(word::CAPS_OR_BADGES + MSG_MAX_EXTRA_CAPS == word::RECEIVE_CNODE);
};

/// A CPU register that carries a message register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MsgReg {
    /// MR0.
    R10,
    /// MR1.
    R8,
    /// MR2.
    R9,
    /// MR3.
    R15,
}

impl MsgReg {
    /// The registers of MR0 to MR3, in order.
    pub const ALL: [MsgReg; MSG_REG_COUNT] = [MsgReg::R10, MsgReg::R8, MsgReg::R9, MsgReg::R15];

    /// Its value in a saved register frame.
    pub const fn get(self, regs: &Regs) -> u64 {
        match self {
            MsgReg::R10 => regs.r10,
            MsgReg::R8 => regs.r8,
            MsgReg::R9 => regs.r9,
            MsgReg::R15 => regs.r15,
        }
    }

    /// Sets it in a saved register frame, leaving every other register.
    pub fn set(self, regs: &mut Regs, value: u64) {
        match self {
            MsgReg::R10 => regs.r10 = value,
            MsgReg::R8 => regs.r8 = value,
            MsgReg::R9 => regs.r9 = value,
            MsgReg::R15 => regs.r15 = value,
        }
    }

    /// The register's name, for messages.
    pub const fn name(self) -> &'static str {
        match self {
            MsgReg::R10 => "r10",
            MsgReg::R8 => "r8",
            MsgReg::R9 => "r9",
            MsgReg::R15 => "r15",
        }
    }
}

/// Where a message register travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MrLocation {
    /// MR0 to MR3: a CPU register.
    Register(MsgReg),
    /// MR4 to MR119: this IPC buffer word, `msg[i]`.
    Buffer(usize),
}

/// Where message register `i` travels, or `None` from
/// [`MSG_MAX_LENGTH`] on.
pub const fn mr_location(i: usize) -> Option<MrLocation> {
    if i < MSG_REG_COUNT {
        Some(MrLocation::Register(MsgReg::ALL[i]))
    } else if i < MSG_MAX_LENGTH {
        Some(MrLocation::Buffer(word::MSG + i))
    } else {
        None
    }
}

/// The `length` a receiver gets for a message of `length` registers
/// (`docs/abi.md`, "Message registers"): at most 120, and at most 4 unless
/// the sending side has a readable IPC buffer and the receiving side a
/// writable one. The kernel, sending a fault message or a reply, always
/// counts as having one.
pub const fn delivered_length(length: u64, sender_buffer: bool, receiver_buffer: bool) -> u64 {
    let limit = if sender_buffer && receiver_buffer {
        MSG_MAX_LENGTH
    } else {
        MSG_REG_COUNT
    };
    if length > limit as u64 {
        limit as u64
    } else {
        length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn fields_sit_where_the_abi_puts_them() {
        assert_eq!(MessageInfo::new(0, 0, 0, 1).word(), 1);
        assert_eq!(MessageInfo::new(0, 0, 0, 127).word(), 0x7F);
        assert_eq!(MessageInfo::new(0, 0, 1, 0).word(), 1 << 7);
        assert_eq!(MessageInfo::new(0, 0, 3, 0).word(), 3 << 7);
        assert_eq!(MessageInfo::new(0, 1, 0, 0).word(), 1 << 9);
        assert_eq!(MessageInfo::new(0, 7, 0, 0).word(), 7 << 9);
        assert_eq!(MessageInfo::new(1, 0, 0, 0).word(), 1 << 12);
        let top = (1 << LABEL_BITS) - 1;
        assert_eq!(MessageInfo::new(top, 0, 0, 0).word(), !0xFFF);
        assert_eq!(MessageInfo::new(top, 7, 3, 127).word(), u64::MAX);
    }

    #[test]
    fn every_word_reads_back() {
        let m = MessageInfo::from_word(u64::MAX);
        assert_eq!(
            (m.label(), m.caps_unwrapped(), m.extra_caps(), m.length()),
            ((1 << 52) - 1, 7, 3, 127)
        );
        let m = MessageInfo::from_word(0x0000_0000_0001_2A85);
        assert_eq!(
            (m.label(), m.caps_unwrapped(), m.extra_caps(), m.length()),
            (0x12, 5, 1, 5)
        );
        assert_eq!(MessageInfo::default().word(), 0);
    }

    #[test]
    fn a_sent_length_above_120_counts_as_120() {
        for length in 0..=127 {
            let m = MessageInfo::new(9, 0, 0, length);
            assert_eq!(m.length(), length);
            assert_eq!(m.sent_length(), length.min(120));
        }
    }

    #[test]
    #[should_panic(expected = "length above 127")]
    fn new_refuses_a_length_wider_than_its_field() {
        let _ = MessageInfo::new(0, 0, 0, 128);
    }

    #[test]
    #[should_panic(expected = "extra_caps above 3")]
    fn new_refuses_four_extra_caps() {
        let _ = MessageInfo::new(0, 0, 4, 0);
    }

    #[test]
    #[should_panic(expected = "caps_unwrapped wider than 3 bits")]
    fn new_refuses_a_wide_unwrapped_mask() {
        let _ = MessageInfo::new(0, 8, 0, 0);
    }

    #[test]
    #[should_panic(expected = "label wider than 52 bits")]
    fn new_refuses_a_wide_label() {
        let _ = MessageInfo::new(1 << 52, 0, 0, 0);
    }

    #[test]
    fn debug_shows_the_fields() {
        let s = std::format!("{:?}", MessageInfo::new(0x21, 2, 1, 4));
        assert_eq!(
            s,
            "MessageInfo { label: 33, caps_unwrapped: 2, extra_caps: 1, length: 4 }"
        );
    }

    #[test]
    fn message_registers_travel_where_the_abi_says() {
        let regs: std::vec::Vec<_> = (0..4).map(mr_location).collect();
        assert_eq!(
            regs,
            [
                Some(MrLocation::Register(MsgReg::R10)),
                Some(MrLocation::Register(MsgReg::R8)),
                Some(MrLocation::Register(MsgReg::R9)),
                Some(MrLocation::Register(MsgReg::R15)),
            ]
        );
        // MR4 is msg[4], word 5 at byte 40; MR119 is word 120 at byte 960.
        assert_eq!(mr_location(4), Some(MrLocation::Buffer(5)));
        assert_eq!(mr_location(119), Some(MrLocation::Buffer(120)));
        assert_eq!(mr_location(120), None);
        assert_eq!(mr_location(usize::MAX), None);
        // No buffer word the kernel uses is msg[0..4], user_data or a word
        // past the message.
        for i in 4..MSG_MAX_LENGTH {
            let Some(MrLocation::Buffer(w)) = mr_location(i) else {
                panic!("MR{i} not in the buffer");
            };
            assert!((word::MSG + MSG_REG_COUNT..word::USER_DATA).contains(&w));
        }
    }

    #[test]
    fn a_message_register_is_its_own_field_of_regs() {
        for (i, r) in MsgReg::ALL.into_iter().enumerate() {
            let mut regs = Regs::default();
            r.set(&mut regs, 0x1000 + i as u64);
            assert_eq!(r.get(&regs), 0x1000 + i as u64);
            let mut expect = Regs::default();
            match i {
                0 => expect.r10 = 0x1000,
                1 => expect.r8 = 0x1001,
                2 => expect.r9 = 0x1002,
                _ => expect.r15 = 0x1003,
            }
            assert_eq!(regs, expect, "{}", r.name());
        }
    }

    #[test]
    fn the_buffer_fields_are_their_words() {
        let mut b = IpcBuffer::ZERO;
        b.tag = 1;
        b.msg[0] = 2;
        b.msg[119] = 3;
        b.user_data = 4;
        b.caps_or_badges = [5, 6, 7];
        b.receive_cnode = 8;
        b.receive_index = 9;
        b.receive_depth = 10;
        // The same buffer as words, read the way the kernel reads one.
        let words: std::vec::Vec<u64> = [b.tag]
            .into_iter()
            .chain(b.msg)
            .chain([b.user_data])
            .chain(b.caps_or_badges)
            .chain([b.receive_cnode, b.receive_index, b.receive_depth])
            .collect();
        assert_eq!(words.len(), IPC_BUFFER_WORDS);
        assert_eq!(words[word::TAG], 1);
        assert_eq!(words[word::MSG], 2);
        assert_eq!(words[word::MSG + 119], 3);
        assert_eq!(words[word::USER_DATA], 4);
        assert_eq!(words[word::CAPS_OR_BADGES..][..3], [5, 6, 7]);
        assert_eq!(words[word::RECEIVE_CNODE], 8);
        assert_eq!(words[word::RECEIVE_INDEX], 9);
        assert_eq!(words[word::RECEIVE_DEPTH], 10);
    }

    #[test]
    fn delivered_length_needs_both_buffers_past_four() {
        for length in [0, 1, 4, 5, 119, 120, 121, 127, 1000, u64::MAX] {
            let both = length.min(120);
            let regs_only = length.min(4);
            assert_eq!(delivered_length(length, true, true), both);
            assert_eq!(delivered_length(length, true, false), regs_only);
            assert_eq!(delivered_length(length, false, true), regs_only);
            assert_eq!(delivered_length(length, false, false), regs_only);
        }
    }

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: if cfg!(miri) { 16 } else { 1024 },
            // No files: Miri forbids them.
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn fields_round_trip(
            label in 0u64..1 << 52,
            unwrapped in 0u64..8,
            extra in 0u64..4,
            length in 0u64..128,
        ) {
            let m = MessageInfo::new(label, unwrapped, extra, length);
            prop_assert_eq!(
                (m.label(), m.caps_unwrapped(), m.extra_caps(), m.length()),
                (label, unwrapped, extra, length)
            );
            prop_assert_eq!(MessageInfo::from_word(m.word()), m);
        }

        #[test]
        fn words_round_trip(w in any::<u64>()) {
            let m = MessageInfo::from_word(w);
            let again = MessageInfo::new(m.label(), m.caps_unwrapped(), m.extra_caps(), m.length());
            prop_assert_eq!(again.word(), w);
        }
    }
}
