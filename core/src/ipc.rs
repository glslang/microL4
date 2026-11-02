//! IPC (`docs/design.md`, "IPC"; `docs/abi.md`, "Messages" and "IPC and
//! notifications").
//!
//! [`message`] is the layout every message follows, shared by the kernel and
//! `libsys`: [`MessageInfo`], the IPC buffer's words and where each message
//! register travels. The endpoint state machine comes next to it.

pub mod message;

pub use message::{
    IPC_BUFFER_BITS, IPC_BUFFER_SIZE, IPC_BUFFER_WORDS, IpcBuffer, LABEL_BITS, MSG_MAX_EXTRA_CAPS,
    MSG_MAX_LENGTH, MSG_REG_COUNT, MessageInfo, MrLocation, MsgReg, delivered_length, mr_location,
    word,
};
