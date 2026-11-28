//! The UDP echo service (RFC 862) on port 7: each datagram's payload,
//! unchanged, back to its source address and port.

use crate::udp::{Endpoint, Reply, Service};

/// The echo service's port.
pub const PORT: u16 = 7;
/// net's line once the stack is up.
pub const LISTENING: &str = "echo: listening on UDP port 7";

/// The echo service. It keeps no state: the stack counts what it
/// receives and echoes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Echo;

impl Service for Echo {
    const PORT: u16 = PORT;

    fn datagram<'p>(&mut self, _from: Endpoint, payload: &'p [u8], reply: &mut Reply<'p>) {
        reply.send(payload);
    }
}
