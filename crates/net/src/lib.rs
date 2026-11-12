// SPDX-License-Identifier: Apache-2.0
//! NeoNet (docs wifi.md W5): the phone's IP stack over the Wi-Fi link, on smoltcp. [`Stack`] holds the Ethernet
//! interface, a DHCPv4 client, a DNS resolver and up to [`MAX_TCP`] TCP sockets; the caller (NEONET.EXE) moves the
//! frames in and out through a `smoltcp::phy::Device` and calls [`Stack::poll`]. Sans-I/O: the clock and the device
//! are parameters, so the host tests run it on smoltcp's loopback device.
#![no_std]

extern crate alloc;

#[cfg(feature = "client")]
pub mod client;
pub mod proto;

use alloc::vec;
use alloc::vec::Vec;
use proto::{State, Status, err};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::Device;
use smoltcp::socket::{dhcpv4, dns, tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{DnsQueryType, EthernetAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

pub use smoltcp::socket::dns::QueryHandle;

/// TCP sockets open at once, over all clients.
pub const MAX_TCP: usize = 16;
/// Each TCP socket's receive and send buffer. shortcut: one size for every socket, make it a CONNECT argument when a
/// bulk transfer needs more.
const TCP_BUF: usize = 8 * 1024;
/// A connect gives up after this, and so does an established socket whose data goes unacknowledged.
const TCP_TIMEOUT: Duration = Duration::from_secs(20);
/// A closing socket is aborted after this, if the peer never finishes the close.
const CLOSE_LINGER_MS: u64 = 30_000;
/// The longest [`Stack::poll`] asks the caller to wait.
const MAX_DELAY_MS: u64 = 1000;

struct Tcp {
    handle: SocketHandle,
    /// When the owner closed it (ms); the socket is freed once the close finishes.
    closed_at: Option<u64>,
}

/// The outcome of [`Stack::resolve`]: an address at once (the name was one), or a DNS query to poll.
#[derive(Clone, Copy)]
pub enum Lookup {
    Ip([u8; 4]),
    Query(QueryHandle),
}

pub struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    dns: SocketHandle,
    tcp: Vec<Option<Tcp>>,
    status: Status,
    next_port: u16,
}

impl Stack {
    /// A stack for the interface with MAC `mac`. `seed` should be random (TCP sequence numbers, DNS ids, ports).
    pub fn new<D: Device + ?Sized>(dev: &mut D, mac: [u8; 6], seed: u64, now_ms: u64) -> Self {
        let mut config = Config::new(EthernetAddress(mac).into());
        config.random_seed = seed;
        let iface = Interface::new(config, dev, Instant::from_millis(now_ms as i64));
        let mut sockets = SocketSet::new(vec![]);
        let dhcp = sockets.add(dhcpv4::Socket::new());
        let dns = sockets.add(dns::Socket::new(&[], vec![]));
        Self {
            iface,
            sockets,
            dhcp,
            dns,
            tcp: (0..MAX_TCP).map(|_| None).collect(),
            status: Status::default(),
            next_port: 49152 + (seed % 16384) as u16,
        }
    }

    /// The Wi-Fi link came up: DHCP starts at the next poll.
    pub fn link_up(&mut self) {
        if self.status.state == State::Down {
            self.status.state = State::Configuring;
        }
    }

    /// The link went away: the lease and every TCP connection with it.
    pub fn link_down(&mut self) {
        self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).reset();
        self.deconfigure();
        for t in self.tcp.iter().flatten() {
            self.sockets.get_mut::<tcp::Socket>(t.handle).abort();
        }
        self.status.state = State::Down;
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Move frames and timers: call it whenever frames may have arrived, and again within the returned ms.
    pub fn poll<D: Device + ?Sized>(&mut self, now_ms: u64, dev: &mut D) -> u64 {
        if self.status.state == State::Down {
            return MAX_DELAY_MS;
        }
        let now = Instant::from_millis(now_ms as i64);
        self.iface.poll(now, dev, &mut self.sockets);
        let lease = match self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).poll() {
            None => None,
            Some(dhcpv4::Event::Configured(c)) => {
                Some(Some((c.address, c.router, c.dns_servers.clone())))
            }
            Some(dhcpv4::Event::Deconfigured) => Some(None),
        };
        match lease {
            Some(Some((address, router, dns))) => self.configure(address, router, &dns),
            Some(None) => self.deconfigure(),
            None => {}
        }
        self.reap(now_ms);
        self.iface
            .poll_delay(now, &self.sockets)
            .map_or(MAX_DELAY_MS, |d| d.total_millis().min(MAX_DELAY_MS))
    }

    fn configure(&mut self, address: Ipv4Cidr, router: Option<Ipv4Address>, dns: &[Ipv4Address]) {
        self.iface.update_ip_addrs(|a| {
            a.clear();
            let _ = a.push(IpCidr::Ipv4(address));
        });
        let routes = self.iface.routes_mut();
        match router {
            Some(r) => drop(routes.add_default_ipv4_route(r)),
            None => drop(routes.remove_default_ipv4_route()),
        }
        let servers: Vec<IpAddress> = dns.iter().map(|&d| d.into()).collect();
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .update_servers(&servers);
        self.status = Status {
            state: State::Up,
            ip: address.address().octets(),
            prefix: address.prefix_len(),
            gateway: router.map_or([0; 4], |r| r.octets()),
            dns: [0, 1].map(|i| dns.get(i).map_or([0; 4], |d| d.octets())),
        };
    }

    fn deconfigure(&mut self) {
        self.iface.update_ip_addrs(|a| a.clear());
        self.iface.routes_mut().remove_default_ipv4_route();
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .update_servers(&[]);
        self.status = Status {
            state: if self.status.state == State::Down {
                State::Down
            } else {
                State::Configuring
            },
            ..Status::default()
        };
    }

    /// Free the sockets whose close finished (or lingered too long).
    fn reap(&mut self, now_ms: u64) {
        for slot in self.tcp.iter_mut() {
            let Some(t) = slot else { continue };
            let Some(at) = t.closed_at else { continue };
            let s = self.sockets.get_mut::<tcp::Socket>(t.handle);
            if now_ms.saturating_sub(at) > CLOSE_LINGER_MS {
                s.abort();
            }
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                self.sockets.remove(t.handle);
                *slot = None;
            }
        }
    }

    /// Start resolving `name` (a host name or a dotted IPv4 address).
    pub fn resolve(&mut self, name: &str) -> Result<Lookup, i32> {
        if let Ok(ip) = name.parse::<Ipv4Address>() {
            return Ok(Lookup::Ip(ip.octets()));
        }
        if self.status.state != State::Up || self.status.dns == [[0; 4]; 2] {
            return Err(err::NOT_READY);
        }
        let cx = self.iface.context();
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .start_query(cx, name, DnsQueryType::A)
            .map(Lookup::Query)
            .map_err(|_| err::ARGUMENT)
    }

    /// A query's result: `None` while it runs. Polling a finished query again panics (smoltcp frees its slot).
    pub fn resolve_result(&mut self, q: QueryHandle) -> Option<Result<[u8; 4], i32>> {
        match self
            .sockets
            .get_mut::<dns::Socket>(self.dns)
            .get_query_result(q)
        {
            Err(dns::GetQueryResultError::Pending) => None,
            Err(dns::GetQueryResultError::Failed) => Some(Err(err::NOT_FOUND)),
            Ok(addrs) => Some(
                addrs
                    .first()
                    .map(|IpAddress::Ipv4(v4)| v4.octets()) // IPv4 only: A records
                    .ok_or(err::NOT_FOUND),
            ),
        }
    }

    /// Give up on a query (its client went away).
    pub fn resolve_cancel(&mut self, q: QueryHandle) {
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .cancel_query(q);
    }

    /// Open a TCP connection to `ip:port`: its id at once; [`Stack::connected`] says when it is up.
    pub fn connect(&mut self, ip: [u8; 4], port: u16) -> Result<usize, i32> {
        if self.status.state != State::Up {
            return Err(err::NOT_READY);
        }
        let id = self
            .tcp
            .iter()
            .position(Option::is_none)
            .ok_or(err::OVERFLOW)?;
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0; TCP_BUF]),
        );
        s.set_timeout(Some(TCP_TIMEOUT));
        let local = self.next_port;
        self.next_port = if local == u16::MAX { 49152 } else { local + 1 };
        let remote = (IpAddress::Ipv4(Ipv4Address::from_octets(ip)), port);
        s.connect(self.iface.context(), remote, local)
            .map_err(|_| err::ARGUMENT)?;
        self.tcp[id] = Some(Tcp {
            handle: self.sockets.add(s),
            closed_at: None,
        });
        Ok(id)
    }

    fn socket(&mut self, id: usize) -> Result<&mut tcp::Socket<'static>, i32> {
        match self.tcp.get(id) {
            Some(Some(t)) if t.closed_at.is_none() => {
                Ok(self.sockets.get_mut::<tcp::Socket>(t.handle))
            }
            _ => Err(err::ARGUMENT),
        }
    }

    /// `None` while connecting; then `Ok` once established, or the error it failed with.
    pub fn connected(&mut self, id: usize) -> Option<Result<(), i32>> {
        let s = match self.socket(id) {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
        };
        match s.state() {
            tcp::State::SynSent | tcp::State::SynReceived => None,
            tcp::State::Closed => Some(Err(err::COULD_NOT_CONNECT)),
            _ => Some(Ok(())),
        }
    }

    /// Queue `data`: the bytes taken, 0 if the send buffer is full.
    pub fn send(&mut self, id: usize, data: &[u8]) -> Result<usize, i32> {
        let s = self.socket(id)?;
        if !s.may_send() {
            return Err(err::DISCONNECTED);
        }
        s.send_slice(data).map_err(|_| err::DISCONNECTED)
    }

    /// Read into `buf`: `None` while nothing has arrived; `Some(Ok(0))` once the peer closed and all is read.
    pub fn recv(&mut self, id: usize, buf: &mut [u8]) -> Option<Result<usize, i32>> {
        let s = match self.socket(id) {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
        };
        if s.can_recv() {
            return Some(s.recv_slice(buf).map_err(|_| err::DISCONNECTED));
        }
        match s.state() {
            tcp::State::SynSent | tcp::State::SynReceived => None,
            _ if !s.may_recv() => Some(Ok(0)),
            _ => None,
        }
    }

    /// Close the connection (FIN after the queued data); the id is no longer usable, the socket goes once it closed.
    pub fn close(&mut self, id: usize, now_ms: u64) {
        if let Some(Some(t)) = self.tcp.get_mut(id)
            && t.closed_at.is_none()
        {
            t.closed_at = Some(now_ms);
            self.sockets.get_mut::<tcp::Socket>(t.handle).close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{Loopback, Medium};

    const MAC: [u8; 6] = [0x02, 0x4e, 0, 0, 0, 1];

    /// A stack on the loopback device, holding 127.0.0.1/8 as if DHCP had given it.
    fn stack(dev: &mut Loopback) -> Stack {
        let mut s = Stack::new(dev, MAC, 7, 0);
        s.link_up();
        s.poll(0, dev); // the DHCP client's first event (Deconfigured) is out of the way
        s.configure(Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 8), None, &[]);
        s
    }

    #[test]
    fn tcp_round_trip_on_loopback() {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut s = stack(&mut dev);
        let mut server = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1024]),
            tcp::SocketBuffer::new(vec![0; 1024]),
        );
        server.listen(80).unwrap();
        let server = s.sockets.add(server);

        let id = s.connect([127, 0, 0, 1], 80).unwrap();
        assert_eq!(s.connected(id), None);
        let (mut now, mut sent, mut got, mut request) = (0u64, false, Vec::new(), Vec::new());
        let mut eof = false;
        while now < 5000 && !eof {
            s.poll(now, &mut dev);
            if s.connected(id) == Some(Ok(())) && !sent {
                assert_eq!(s.send(id, b"GET /").unwrap(), 5);
                sent = true;
            }
            let srv = s.sockets.get_mut::<tcp::Socket>(server);
            if srv.can_recv() {
                srv.recv(|b| {
                    request.extend_from_slice(b);
                    (b.len(), ())
                })
                .unwrap();
                srv.send_slice(b"HTTP/1.1 204").unwrap();
                srv.close();
            }
            let mut buf = [0u8; 64];
            match s.recv(id, &mut buf) {
                Some(Ok(0)) => eof = true,
                Some(Ok(n)) => got.extend_from_slice(&buf[..n]),
                Some(Err(e)) => panic!("recv {e}"),
                None => {}
            }
            now += 10;
        }
        assert_eq!(request, b"GET /");
        assert_eq!(got, b"HTTP/1.1 204");
        assert!(eof);

        s.close(id, now);
        assert_eq!(s.send(id, b"x"), Err(err::ARGUMENT)); // closed ids are gone at once
        for _ in 0..100 {
            s.poll(now, &mut dev);
            now += 100;
        }
        assert!(s.tcp[id].is_none(), "the closed socket is freed");
    }

    #[test]
    fn connect_needs_an_address() {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut s = Stack::new(&mut dev, MAC, 7, 0);
        assert_eq!(s.connect([10, 0, 0, 1], 80), Err(err::NOT_READY));
        s.link_up();
        assert_eq!(s.status().state, State::Configuring);
        assert_eq!(s.connect([10, 0, 0, 1], 80), Err(err::NOT_READY));
        assert_eq!(s.resolve("example.com").err(), Some(err::NOT_READY));
    }

    #[test]
    fn socket_limit_and_reuse() {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut s = stack(&mut dev);
        let ids: Vec<usize> = (0..MAX_TCP)
            .map(|_| s.connect([127, 0, 0, 1], 9).unwrap())
            .collect();
        assert_eq!(s.connect([127, 0, 0, 1], 9), Err(err::OVERFLOW));
        s.close(ids[3], 0);
        s.poll(0, &mut dev); // a socket closed before it connected is freed at once
        assert_eq!(s.connect([127, 0, 0, 1], 9), Ok(ids[3]));
    }

    #[test]
    fn link_down_drops_the_lease_and_connections() {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut s = stack(&mut dev);
        assert_eq!(s.status().ip, [127, 0, 0, 1]);
        assert_eq!(s.status().prefix, 8);
        let id = s.connect([127, 0, 0, 1], 9).unwrap();
        s.link_down();
        assert_eq!(s.status(), Status::default());
        assert_eq!(s.connected(id), Some(Err(err::COULD_NOT_CONNECT)));
        s.link_up();
        assert_eq!(s.status().state, State::Configuring);
    }

    #[test]
    fn resolve_takes_dotted_addresses() {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut s = Stack::new(&mut dev, MAC, 7, 0);
        assert!(matches!(
            s.resolve("192.168.3.20"),
            Ok(Lookup::Ip([192, 168, 3, 20]))
        ));
    }
}
