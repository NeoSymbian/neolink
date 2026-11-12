// SPDX-License-Identifier: Apache-2.0
//! The NeoNet IPC API (server NEONET.EXE, docs wifi.md W5): names, function numbers, errors and the status record,
//! shared by the server and [`crate::client`].
//!
//! | Function | Arguments | Completes with |
//! |---|---|---|
//! | `STATUS` | 0: out des (>= [`STATUS_SIZE`]) | 0, the [`Status`] written |
//! | `RESOLVE` | 0: the name (des8), 1: out des (4 bytes) | 0 and the IPv4 address, or an error (later) |
//! | `CONNECT` | 0: IPv4 address (big-endian u32), 1: port | the socket id once established, or an error (later) |
//! | `SEND` | 0: socket id, 1: data (des8, <= [`MAX_IO`]) | bytes taken (> 0), waiting while the send buffer is full |
//! | `RECV` | 0: socket id, 1: out des | bytes read (0 = the peer closed), waiting until data arrives |
//! | `CLOSE` | 0: socket id | 0 |
//!
//! A socket belongs to the session that opened it and closes with it.

/// The server's name.
pub const NAME: &str = "NeoNet";
/// The major version a client sends; the server refuses others.
pub const VERSION_MAJOR: u8 = 1;
/// Bytes one SEND or RECV moves at most.
pub const MAX_IO: usize = 8 * 1024;

pub mod op {
    pub const STATUS: i32 = 1;
    pub const RESOLVE: i32 = 2;
    pub const CONNECT: i32 = 3;
    pub const SEND: i32 = 4;
    pub const RECV: i32 = 5;
    pub const CLOSE: i32 = 6;
}

/// The Symbian error codes the API answers with (`e32err.h`).
pub mod err {
    pub const NOT_FOUND: i32 = -1;
    pub const GENERAL: i32 = -2;
    pub const CANCEL: i32 = -3;
    pub const NOT_SUPPORTED: i32 = -5;
    pub const ARGUMENT: i32 = -6;
    pub const OVERFLOW: i32 = -9;
    pub const NOT_READY: i32 = -18;
    pub const TIMED_OUT: i32 = -33;
    pub const COULD_NOT_CONNECT: i32 = -34;
    pub const DISCONNECTED: i32 = -36;
}

/// Where the network is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    /// No Wi-Fi link.
    #[default]
    Down = 0,
    /// Linked, asking DHCP for an address.
    Configuring = 1,
    /// An address is held.
    Up = 2,
}

/// The network's state and its DHCP lease. Addresses are IPv4 octets; `0.0.0.0` means none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gateway: [u8; 4],
    pub dns: [[u8; 4]; 2],
}

/// Bytes of an encoded [`Status`].
pub const STATUS_SIZE: usize = 20;

impl Status {
    /// `{version 1, state, prefix, 0, ip, gateway, dns 1, dns 2}`.
    pub fn encode(&self) -> [u8; STATUS_SIZE] {
        let mut b = [0u8; STATUS_SIZE];
        b[0] = 1;
        b[1] = self.state as u8;
        b[2] = self.prefix;
        b[4..8].copy_from_slice(&self.ip);
        b[8..12].copy_from_slice(&self.gateway);
        b[12..16].copy_from_slice(&self.dns[0]);
        b[16..20].copy_from_slice(&self.dns[1]);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < STATUS_SIZE || b[0] != 1 {
            return None;
        }
        let state = match b[1] {
            0 => State::Down,
            1 => State::Configuring,
            2 => State::Up,
            _ => return None,
        };
        let ip4 = |at: usize| -> [u8; 4] { b[at..at + 4].try_into().unwrap() };
        Some(Self {
            state,
            ip: ip4(4),
            prefix: b[2],
            gateway: ip4(8),
            dns: [ip4(12), ip4(16)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip() {
        let s = Status {
            state: State::Up,
            ip: [192, 168, 3, 57],
            prefix: 24,
            gateway: [192, 168, 3, 1],
            dns: [[192, 168, 3, 1], [8, 8, 8, 8]],
        };
        assert_eq!(Status::decode(&s.encode()), Some(s));
        assert_eq!(
            Status::decode(&Status::default().encode()),
            Some(Status::default())
        );
    }

    #[test]
    fn status_rejects_bad_records() {
        let mut b = Status::default().encode();
        assert_eq!(Status::decode(&b[..STATUS_SIZE - 1]), None);
        b[1] = 3;
        assert_eq!(Status::decode(&b), None);
        b[1] = 0;
        b[0] = 2;
        assert_eq!(Status::decode(&b), None);
    }
}
