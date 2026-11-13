// SPDX-License-Identifier: Apache-2.0
//! The client side of the NeoNet API ([`crate::proto`]): a session with NEONET.EXE, name lookups, TCP streams and
//! listeners, UDP sockets.
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

use crate::Endpoint;
use crate::proto::{
    ENDPOINT_SIZE, MAX_IO, NAME, STATUS_SIZE, Status, VERSION_MAJOR, decode_endpoint,
    encode_endpoint, err, op,
};
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

    /// Listen for TCP connections on `port`.
    pub fn tcp_listen(&self, port: u16) -> Result<TcpListener<'_>, i32> {
        let mut a = TIpcArgs::new();
        a.int(0, port as i32);
        let id = self.0.send_receive(op::LISTEN, &a)?;
        Ok(TcpListener { net: self, id })
    }

    /// A UDP socket on `port` (0: any free one).
    pub fn udp_open(&self, port: u16) -> Result<UdpSocket<'_>, i32> {
        let mut a = TIpcArgs::new();
        a.int(0, port as i32);
        let id = self.0.send_receive(op::UDP_OPEN, &a)?;
        Ok(UdpSocket { net: self, id })
    }

    fn close(&self, id: i32) {
        let mut a = TIpcArgs::new();
        a.int(0, id);
        let _ = self.0.send_receive(op::CLOSE, &a);
    }
}

/// A listening TCP socket of a [`Net`] session; dropping it closes it.
pub struct TcpListener<'a> {
    net: &'a Net,
    id: i32,
}

impl<'a> TcpListener<'a> {
    /// Wait for the next connection: it and the peer's address.
    pub fn accept(&self) -> Result<(TcpStream<'a>, Endpoint), i32> {
        let mut peer = [0u8; ENDPOINT_SIZE];
        let mut d = TPtr8::new(&mut peer);
        let mut a = TIpcArgs::new();
        a.int(0, self.id).des8(1, &mut d);
        let id = self.net.0.send_receive(op::ACCEPT, &a)?;
        let peer = decode_endpoint(&peer).ok_or(err::GENERAL)?;
        Ok((TcpStream { net: self.net, id }, peer))
    }
}

impl Drop for TcpListener<'_> {
    fn drop(&mut self) {
        self.net.close(self.id);
    }
}

/// A UDP socket of a [`Net`] session; dropping it closes it.
pub struct UdpSocket<'a> {
    net: &'a Net,
    id: i32,
}

impl UdpSocket<'_> {
    /// Send one datagram (<= [`MAX_IO`] bytes) to `to`, waiting while the send buffer is full.
    pub fn send_to(&self, data: &[u8], to: Endpoint) -> Result<usize, i32> {
        if data.len() > MAX_IO {
            return Err(err::OVERFLOW);
        }
        let addr = encode_endpoint(to.0, to.1);
        let (data, addr) = (TPtrC8::new(data), TPtrC8::new(&addr));
        let mut a = TIpcArgs::new();
        a.int(0, self.id).desc8(1, &data).desc8(2, &addr);
        self.net.0.send_receive(op::SEND_TO, &a).map(|n| n as usize)
    }

    /// Wait for the next datagram: its length and sender (`KErrOverflow` if `buf` was too small: it is gone).
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Endpoint), i32> {
        let max = buf.len().min(MAX_IO);
        let mut from = [0u8; ENDPOINT_SIZE];
        let mut d = TPtr8::new(&mut buf[..max]);
        let mut f = TPtr8::new(&mut from);
        let mut a = TIpcArgs::new();
        a.int(0, self.id).des8(1, &mut d).des8(2, &mut f);
        let n = self.net.0.send_receive(op::RECV_FROM, &a)?;
        Ok((n as usize, decode_endpoint(&from).ok_or(err::GENERAL)?))
    }
}

impl Drop for UdpSocket<'_> {
    fn drop(&mut self) {
        self.net.close(self.id);
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
        self.net.close(self.id);
    }
}
