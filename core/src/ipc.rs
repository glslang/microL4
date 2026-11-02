//! IPC (`docs/design.md`, "IPC"; `docs/abi.md`, "Messages" and "IPC and
//! notifications").
//!
//! [`message`] is the layout every message follows, shared by the kernel and
//! `libsys`: [`MessageInfo`], the IPC buffer's words and where each message
//! register travels. The endpoint objects and their queues, with
//! [`IpcEnv`], what IPC needs from the kernel, are in `endpoint`; the state
//! machine (send, receive and reply phases, message transfer, reply
//! capabilities, cancellation and fault delivery) in `machine`. M5 builds
//! endpoints without capability transfer (ADR 0023); M6 adds capability
//! transfer, notifications and `CNode_SaveCaller`.

mod endpoint;
mod machine;
pub mod message;

pub use endpoint::{Endpoint, EndpointCap, EpState, IpcEnv, ep_field};
pub use machine::{
    DoubleFault, cancel_all_ipc, cancel_ipc, check, deliver_fault, finalise, read_message, receive,
    reply, reply_error, reply_success, send, transfer,
};
pub use message::{
    IPC_BUFFER_BITS, IPC_BUFFER_SIZE, IPC_BUFFER_WORDS, IpcBuffer, LABEL_BITS, MSG_MAX_EXTRA_CAPS,
    MSG_MAX_LENGTH, MSG_REG_COUNT, MessageInfo, MrLocation, MsgReg, delivered_length, mr_location,
    word,
};

/// The state machine's tests, and the world `crate::syscall`'s tests share.
#[cfg(test)]
pub(crate) mod tests;
