// SPDX-License-Identifier: Apache-2.0
//! NEONET.EXE (docs wifi.md W5): the phone's IP stack. It moves Ethernet frames between [`net::Stack`] and the Wi-Fi
//! driver (kernel HAL WlanLink 0x4e1f: op 3 the link, op 8 a received frame, op 9 a frame to send), gets an address
//! by DHCP once the link is connected, and serves the NeoNet API ([`net::proto`]) to SYSSTART and apps. SYSSTART
//! starts it at boot; a second copy finds the server name taken and exits.
#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::pin::pin;
use e32::rt::{self, Either};
use e32::server::{self, Message, Server, Service};
use e32::sys::TPtr8;
use e32::sys::ipc::TVersion;
use e32::sys::ui::hal_function;
use e32::{dprintln, time};
use net::proto::{MAX_IO, NAME, Status, VERSION_MAJOR, err, op};
use net::{Lookup, MAX_TCP, QueryHandle, Stack};
use smoltcp::phy::{self, DeviceCapabilities, Medium};

const GROUP_VARIANT: i32 = 1;
const WLAN_LINK: i32 = 0x4e1f;
const PRNG: i32 = 0x4e23;
/// WlanLink op 3's state byte for "connected" (kernel TLink ELinkConnected)
const LINK_CONNECTED: u8 = 3;
const ETH_MAX: usize = 1514;
/// How often the link state is read.
const LINK_POLL_MS: u64 = 200;
/// shortcut: the driver has no frame-arrival event yet, so frames are polled every 2 ms while the link is up; wait on
/// an event once the kernel driver takes interrupts.
const LINKED_POLL_MS: u64 = 2;
const IDLE_POLL_MS: u64 = 200;

/// One WlanLink op: a2 = a TDes8 the kernel reads (`input`) or fills.
fn link(op: usize, buf: &mut [u8], input: bool) -> Result<usize, i32> {
    let mut des = if input {
        TPtr8::new_full(buf)
    } else {
        TPtr8::new(buf)
    };
    let des_ptr: *mut u8 = (&mut des as *mut TPtr8).cast();
    // SAFETY: the kernel reads or writes the TDes8 within its length/max length; a1 is only a number.
    let r = unsafe { hal_function(GROUP_VARIANT, WLAN_LINK, op as *mut u8, des_ptr) };
    if r < 0 { Err(r) } else { Ok(des.len()) }
}

/// The link: `Some(our MAC)` while connected.
fn link_state() -> Option<[u8; 6]> {
    let mut b = [0u8; 29 + 64];
    let n = link(3, &mut b, false).ok()?;
    (n >= 20 && b[1] == LINK_CONNECTED).then(|| b[14..20].try_into().unwrap())
}

fn seed() -> u64 {
    let mut b = [0u8; 8];
    let mut des = TPtr8::new_full(&mut b);
    let des_ptr: *mut u8 = (&mut des as *mut TPtr8).cast();
    // SAFETY: the kernel fills the TDes8 to its current length.
    let r = unsafe { hal_function(GROUP_VARIANT, PRNG, des_ptr, core::ptr::null_mut()) };
    if r < 0 {
        return time::fast_counter() as u64 ^ time::millis() << 32; // no PRNG HAL (Syborg): good enough there
    }
    u64::from_le_bytes(b)
}

/// The Wi-Fi link as a smoltcp device: each receive pops one frame from the driver, each send queues one.
struct Wlan {
    rx: [u8; ETH_MAX],
    dropped: u32,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut u32);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        if link(9, &mut b, true).is_err() {
            *self.0 += 1; // the queue was full or the link went: TCP resends, DHCP/DNS retry
        }
        r
    }
}

impl phy::Device for Wlan {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let n = link(8, &mut self.rx, false).ok()?;
        Some((Rx(self.rx[..n].to_vec()), Tx(&mut self.dropped)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.dropped))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = ETH_MAX;
        c
    }
}

/// A request that waits for the network.
enum Wait {
    Resolve(QueryHandle),
    Connect(usize),
    Send(usize, Vec<u8>),
    Recv(usize),
}

struct Pending {
    session: u32,
    wait: Wait,
    msg: Message,
}

struct Daemon {
    dev: Wlan,
    /// Made when the link first comes up (its MAC is the station's).
    stack: Option<Stack>,
    linked: bool,
    next_link_ms: u64,
    shown: Status,
    pending: Vec<Pending>,
    /// The session that opened each TCP socket id (0 = free).
    owner: [u32; MAX_TCP],
    next_session: u32,
    scratch: Vec<u8>,
}

impl Daemon {
    /// Follow the link, move frames, answer what can be answered: the ms until the next pump.
    fn pump(&mut self, now: u64) -> u64 {
        if now >= self.next_link_ms {
            self.next_link_ms = now + LINK_POLL_MS;
            let mac = link_state();
            if mac.is_some() != self.linked {
                self.linked = mac.is_some();
                dprintln!("[neonet] link {}", if self.linked { "up" } else { "down" });
                match (mac, &mut self.stack) {
                    (Some(_), Some(s)) => s.link_up(),
                    (Some(mac), None) => {
                        let mut s = Stack::new(&mut self.dev, mac, seed(), now);
                        s.link_up();
                        self.stack = Some(s);
                    }
                    (None, Some(s)) => s.link_down(),
                    (None, None) => {}
                }
            }
        }
        let Some(stack) = &mut self.stack else {
            return IDLE_POLL_MS;
        };
        let delay = stack.poll(now, &mut self.dev);
        let status = stack.status();
        if status != self.shown {
            self.shown = status;
            let (ip, gw) = (status.ip, status.gateway);
            dprintln!(
                "[neonet] {:?}: {}.{}.{}.{}/{} gateway {}.{}.{}.{} ({} frames not sent)",
                status.state,
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                status.prefix,
                gw[0],
                gw[1],
                gw[2],
                gw[3],
                self.dev.dropped
            );
        }
        self.finish_ready(now);
        if self.linked {
            delay.min(LINKED_POLL_MS)
        } else {
            IDLE_POLL_MS
        }
    }

    /// Complete every waiting request the network can now answer.
    fn finish_ready(&mut self, now: u64) {
        for p in core::mem::take(&mut self.pending) {
            if let Some(p) = self.try_finish(p, now) {
                self.pending.push(p);
            }
        }
    }

    /// Answer `p` if it can be: `Some(p)` if it still waits (never drop it: a dropped Message completes with
    /// KErrGeneral).
    fn try_finish(&mut self, p: Pending, now: u64) -> Option<Pending> {
        let Some(stack) = &mut self.stack else {
            p.msg.complete(err::NOT_READY);
            return None;
        };
        match &p.wait {
            Wait::Resolve(q) => match stack.resolve_result(*q) {
                None => return Some(p), // still resolving
                Some(r) => match r {
                    Ok(ip) => reply_data(p.msg, &ip, 0),
                    Err(e) => p.msg.complete(e),
                },
            },
            &Wait::Connect(id) => match stack.connected(id) {
                None => return Some(p), // still connecting
                Some(r) => match r {
                    Ok(()) => p.msg.complete(id as i32),
                    Err(e) => {
                        stack.close(id, now);
                        self.owner[id] = 0;
                        p.msg.complete(e);
                    }
                },
            },
            Wait::Send(id, data) => match stack.send(*id, data) {
                Ok(0) => return Some(p),
                Ok(n) => p.msg.complete(n as i32),
                Err(e) => p.msg.complete(e),
            },
            &Wait::Recv(id) => {
                let max = p.msg.des_max_len(1).unwrap_or(0).min(MAX_IO);
                self.scratch.resize(max, 0);
                match stack.recv(id, &mut self.scratch) {
                    None => return Some(p), // nothing yet
                    Some(Ok(n)) => {
                        let data = &self.scratch[..n];
                        match p.msg.write8(1, data, 0) {
                            Ok(()) => p.msg.complete(n as i32),
                            Err(e) => p.msg.complete(e),
                        }
                    }
                    Some(Err(e)) => p.msg.complete(e),
                }
            }
        }
        None
    }

    /// A TCP socket id `msg` names, if `session` owns it.
    fn owned(&self, session: u32, msg: &Message) -> Option<usize> {
        let id = usize::try_from(msg.int(0)).ok()?;
        (id < MAX_TCP && self.owner[id] == session).then_some(id)
    }

    fn wait(&mut self, session: u32, wait: Wait, msg: Message) {
        self.pending.push(Pending { session, wait, msg });
        self.finish_ready(time::millis());
    }
}

fn reply_data(msg: Message, data: &[u8], r: i32) {
    match msg.write8(1, data, 0) {
        Ok(()) => msg.complete(r),
        Err(e) => msg.complete(e),
    }
}

impl Service for Daemon {
    type Session = u32;

    fn connect(&mut self, version: TVersion) -> Result<u32, i32> {
        if version.major != VERSION_MAJOR {
            return Err(err::NOT_SUPPORTED);
        }
        self.next_session = self.next_session.wrapping_add(1).max(1);
        Ok(self.next_session)
    }

    fn message(&mut self, session: &mut u32, msg: Message) {
        let session = *session;
        let f = msg.function();
        if f == op::STATUS {
            let s = self.stack.as_ref().map_or(Status::default(), Stack::status);
            match msg.write8(0, &s.encode(), 0) {
                Ok(()) => msg.complete(0),
                Err(e) => msg.complete(e),
            }
            return;
        }
        let Some(stack) = &mut self.stack else {
            msg.complete(err::NOT_READY);
            return;
        };
        match f {
            op::RESOLVE => {
                let name = match msg.read8_vec(0) {
                    Ok(n) if !n.is_empty() && n.len() <= 255 => n,
                    _ => return msg.complete(err::ARGUMENT),
                };
                let Ok(name) = core::str::from_utf8(&name) else {
                    return msg.complete(err::ARGUMENT);
                };
                match stack.resolve(name) {
                    Ok(Lookup::Ip(ip)) => reply_data(msg, &ip, 0),
                    Ok(Lookup::Query(q)) => self.wait(session, Wait::Resolve(q), msg),
                    Err(e) => msg.complete(e),
                }
            }
            op::CONNECT => {
                let ip = (msg.int(0) as u32).to_be_bytes();
                let Ok(port) = u16::try_from(msg.int(1)) else {
                    return msg.complete(err::ARGUMENT);
                };
                match stack.connect(ip, port) {
                    Ok(id) => {
                        self.owner[id] = session;
                        self.wait(session, Wait::Connect(id), msg);
                    }
                    Err(e) => msg.complete(e),
                }
            }
            op::SEND => {
                let Some(id) = self.owned(session, &msg) else {
                    return msg.complete(err::ARGUMENT);
                };
                match msg.des_len(1) {
                    Ok(n) if n <= MAX_IO => {}
                    _ => return msg.complete(err::ARGUMENT),
                }
                match msg.read8_vec(1) {
                    Ok(data) => self.wait(session, Wait::Send(id, data), msg),
                    Err(e) => msg.complete(e),
                }
            }
            op::RECV => match self.owned(session, &msg) {
                Some(id) => self.wait(session, Wait::Recv(id), msg),
                None => msg.complete(err::ARGUMENT),
            },
            op::CLOSE => {
                if let Some(id) = self.owned(session, &msg) {
                    self.close(id);
                }
                msg.complete(0);
            }
            _ => msg.complete(err::NOT_SUPPORTED),
        }
    }

    fn disconnect(&mut self, session: u32) -> ControlFlow<()> {
        for p in core::mem::take(&mut self.pending) {
            if p.session != session {
                self.pending.push(p);
                continue;
            }
            if let (Wait::Resolve(q), Some(s)) = (&p.wait, &mut self.stack) {
                s.resolve_cancel(*q);
            }
            p.msg.complete(err::CANCEL);
        }
        for id in 0..MAX_TCP {
            if self.owner[id] == session {
                self.close(id);
            }
        }
        ControlFlow::Continue(())
    }
}

impl Daemon {
    /// Close socket `id`: its waiting requests end with `KErrCancel`.
    fn close(&mut self, id: usize) {
        for p in core::mem::take(&mut self.pending) {
            match p.wait {
                Wait::Connect(i) | Wait::Send(i, _) | Wait::Recv(i) if i == id => {
                    p.msg.complete(err::CANCEL)
                }
                _ => self.pending.push(p),
            }
        }
        if let Some(s) = &mut self.stack {
            s.close(id, time::millis());
        }
        self.owner[id] = 0;
    }
}

fn main() -> i32 {
    let server = match Server::create(NAME) {
        Ok(s) => s,
        Err(e) => {
            dprintln!("[neonet] already running ({}): exiting", e);
            return 0;
        }
    };
    dprintln!("[neonet] start: serving {} (API {})", NAME, VERSION_MAJOR);
    let mut d = Daemon {
        dev: Wlan {
            rx: [0; ETH_MAX],
            dropped: 0,
        },
        stack: None,
        linked: false,
        next_link_ms: 0,
        shown: Status::default(),
        pending: Vec::new(),
        owner: [0; MAX_TCP],
        next_session: 0,
        scratch: Vec::new(),
    };
    rt::block_on(async {
        let mut receive = pin!(server.receive());
        loop {
            let wait_ms = d.pump(time::millis()).max(1);
            match rt::select(receive.as_mut(), time::delay((wait_ms * 1000) as i32)).await {
                Either::Left(Ok(msg)) => {
                    receive.set(server.receive());
                    let _ = server::dispatch(&mut d, msg);
                }
                Either::Left(Err(e)) => {
                    dprintln!("[neonet] receive failed ({}): exiting", e);
                    return e;
                }
                Either::Right(()) => {}
            }
        }
    })
}

e32::main!(main);
