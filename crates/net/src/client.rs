// SPDX-License-Identifier: Apache-2.0
//! The client side of the NeoNet API ([`crate::proto`]): a session with NEONET.EXE, name lookups and TCP streams.
//! Calls block the calling thread until the server answers (a RECV until data arrives), so a UI keeps them off its
//! own thread, except [`Net::status`], which never waits.
//!
//! ```ignore
//! let net = Net::connect()?;
//! let ip = net.resolve("connectivitycheck.gstatic.com")?;
//! let mut s = net.tcp_connect(ip, 80)?;
//! s.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n")?;
//! let n = s.read(&mut buf)?; // 0: the server closed
//! ```

use crate::proto::{MAX_IO, NAME, STATUS_SIZE, Status, VERSION_MAJOR, err, op};
use e32::ipc::{Session, TIpcArgs, TVersion};
use e32::sys::{TPtr8, TPtrC8};

/// A session with NeoNet. Bound to the thread that connected.
pub struct Net(Session);

impl Net {
    /// Connect to NEONET.EXE (`KErrNotFound` until it runs).
    pub fn connect() -> Result<Self, i32> {
        let v = TVersion {
            major: VERSION_MAJOR,
            minor: 0,
            build: 0,
        };
        Session::connect(NAME, v).map(Net)
    }

    /// The network's state and lease.
    pub fn status(&self) -> Result<Status, i32> {
        let mut b = [0u8; STATUS_SIZE];
        let mut d = TPtr8::new(&mut b);
        let mut a = TIpcArgs::new();
        a.des8(0, &mut d);
        self.0.send_receive(op::STATUS, &a)?;
        let n = d.len();
        Status::decode(&b[..n]).ok_or(err::GENERAL)
    }

    /// The IPv4 address of `name` (a host name or a dotted address), through DNS.
    pub fn resolve(&self, name: &str) -> Result<[u8; 4], i32> {
        let n = TPtrC8::new(name.as_bytes());
        let mut ip = [0u8; 4];
        let mut d = TPtr8::new(&mut ip);
        let mut a = TIpcArgs::new();
        a.desc8(0, &n).des8(1, &mut d);
        self.0.send_receive(op::RESOLVE, &a)?;
        if d.len() != 4 {
            return Err(err::GENERAL);
        }
        Ok(ip)
    }

    /// Open a TCP connection; returns once it is established (or failed: `KErrCouldNotConnect`, `KErrNotReady`
    /// without an address).
    pub fn tcp_connect(&self, ip: [u8; 4], port: u16) -> Result<TcpStream<'_>, i32> {
        let mut a = TIpcArgs::new();
        a.int(0, u32::from_be_bytes(ip) as i32).int(1, port as i32);
        let id = self.0.send_receive(op::CONNECT, &a)?;
        Ok(TcpStream { net: self, id })
    }
}

/// A TCP connection of a [`Net`] session; dropping it closes it.
pub struct TcpStream<'a> {
    net: &'a Net,
    id: i32,
}

impl TcpStream<'_> {
    /// Queue some of `data`: the bytes taken (waits while the send buffer is full).
    pub fn write(&mut self, data: &[u8]) -> Result<usize, i32> {
        let chunk = TPtrC8::new(&data[..data.len().min(MAX_IO)]);
        let mut a = TIpcArgs::new();
        a.int(0, self.id).desc8(1, &chunk);
        self.net.0.send_receive(op::SEND, &a).map(|n| n as usize)
    }

    pub fn write_all(&mut self, mut data: &[u8]) -> Result<(), i32> {
        while !data.is_empty() {
            let n = self.write(data)?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Read into `buf`, waiting until something arrives: the bytes read, 0 once the peer closed.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        let max = buf.len().min(MAX_IO);
        let mut d = TPtr8::new(&mut buf[..max]);
        let mut a = TIpcArgs::new();
        a.int(0, self.id).des8(1, &mut d);
        self.net.0.send_receive(op::RECV, &a).map(|n| n as usize)
    }
}

impl Drop for TcpStream<'_> {
    fn drop(&mut self) {
        let mut a = TIpcArgs::new();
        a.int(0, self.id);
        let _ = self.net.0.send_receive(op::CLOSE, &a);
    }
}
