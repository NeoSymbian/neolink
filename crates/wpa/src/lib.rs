// SPDX-License-Identifier: Apache-2.0
//! WPA2-PSK, the supplicant side (docs wifi.md W4): the passphrase hash, the pairwise key expansion, and the 4-way and
//! group key handshakes over EAPOL-Key frames, sans-I/O. [`Handshake`] turns each EAPOL frame from the AP into
//! [`Action`]s the caller carries out in order through the driver (send, install keys, open the port).
//!
//! Written from IEEE 802.11-2016 12.7 (key hierarchy, EAPOL-Key frames, 4-way and group key handshakes) for one
//! profile only: RSN, AKM PSK (00-0F-AC:2), pairwise and group cipher CCMP-128 (00-0F-AC:4), key descriptor
//! version 2 (HMAC-SHA1-128 MIC, AES key wrap), no management frame protection.
//! The crypto primitives are RustCrypto's (sha1, hmac, pbkdf2, aes-kw).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use aes_kw::{KeyInit, KwAes128};
use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// The PMK for a passphrase (8..63 printable characters) on an SSID: PBKDF2-HMAC-SHA1, 4096 rounds, 32 bytes
/// (802.11-2016 J.4.1).
pub fn psk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase, ssid, 4096, &mut pmk);
    pmk
}

/// PRF-n (802.11-2016 12.7.1.2): HMAC-SHA1(key, label || 0 || data || i) for i = 0, 1, ... until `out` is full.
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let mut m = HmacSha1::new_from_slice(key).expect("HMAC takes any key length");
        m.update(label);
        m.update(&[0]);
        m.update(data);
        m.update(&[i as u8]);
        let d = m.finalize().into_bytes();
        chunk.copy_from_slice(&d[..chunk.len()]);
    }
}

/// The pairwise transient key for CCMP: KCK (MIC key), KEK (key-data key), TK (the CCMP temporal key).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ptk {
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 16],
}

/// PRF-384(PMK, "Pairwise key expansion", min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
pub fn ptk(
    pmk: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> Ptk {
    let mut data = [0u8; 76];
    let (lo, hi) = if aa < spa { (aa, spa) } else { (spa, aa) };
    data[..6].copy_from_slice(lo);
    data[6..12].copy_from_slice(hi);
    let (lo, hi) = if anonce < snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    data[12..44].copy_from_slice(lo);
    data[44..].copy_from_slice(hi);
    let mut k = [0u8; 48];
    prf(pmk, b"Pairwise key expansion", &data, &mut k);
    let mut p = Ptk {
        kck: [0; 16],
        kek: [0; 16],
        tk: [0; 16],
    };
    p.kck.copy_from_slice(&k[..16]);
    p.kek.copy_from_slice(&k[16..32]);
    p.tk.copy_from_slice(&k[32..]);
    p
}

/// The EAPOL-Key MIC (descriptor version 2): HMAC-SHA1 over the whole EAPOL frame with the MIC field zeroed, first
/// 16 bytes.
pub fn mic(kck: &[u8; 16], frame: &[u8]) -> [u8; 16] {
    let mut m = HmacSha1::new_from_slice(kck).expect("HMAC takes any key length");
    m.update(&frame[..MIC]);
    m.update(&[0; 16]);
    m.update(&frame[MIC + 16..]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&m.finalize().into_bytes()[..16]);
    out
}

/// Our RSN element: version 1, group CCMP, one pairwise CCMP, one AKM PSK, capabilities 0 (no MFP). It goes in the
/// Association Request and, byte for byte, in message 2.
pub const RSN_IE: [u8; 22] = [
    0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0,
];

/// What an AP's RSN element (`ie` = id, length, body) offers, as far as this profile cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rsn {
    pub group_ccmp: bool,
    pub pairwise_ccmp: bool,
    pub akm_psk: bool,
    /// management frame protection required (capability bit 6): we can't join
    pub mfp_required: bool,
}

impl Rsn {
    pub fn parse(ie: &[u8]) -> Option<Rsn> {
        if ie.len() < 2 || ie[0] != 0x30 || ie.len() < 2 + ie[1] as usize {
            return None;
        }
        let b = &ie[2..2 + ie[1] as usize];
        let suite = |s: &[u8]| s[..3] == [0x00, 0x0f, 0xac];
        if b.len() < 8 || b[..2] != [1, 0] {
            return None;
        }
        let group_ccmp = suite(&b[2..]) && b[5] == 4;
        let mut at = 6;
        let mut list = |want: u8| -> Option<bool> {
            let n = u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize;
            let s = b.get(at + 2..at + 2 + 4 * n)?;
            at += 2 + 4 * n;
            Some(s.chunks(4).any(|c| suite(c) && c[3] == want))
        };
        let pairwise_ccmp = list(4)?;
        let akm_psk = list(2)?;
        let caps = b
            .get(at..at + 2)
            .map_or(0, |c| u16::from_le_bytes([c[0], c[1]]));
        Some(Rsn {
            group_ccmp,
            pairwise_ccmp,
            akm_psk,
            mfp_required: caps & 0x40 != 0,
        })
    }

    /// Everything this crate can join.
    pub fn supported(&self) -> bool {
        self.group_ccmp && self.pairwise_ccmp && self.akm_psk && !self.mfp_required
    }
}

// EAPOL-Key frame offsets, from the 802.1X header (802.11-2016 12.7.2)
const KEY_INFO: usize = 5;
const KEY_LEN: usize = 7;
const REPLAY: usize = 9;
const NONCE: usize = 17;
const MIC: usize = 81;
const DATA_LEN: usize = 97;
const DATA: usize = 99;

// key information bits
const VER2: u16 = 2;
const PAIRWISE: u16 = 1 << 3;
const INSTALL: u16 = 1 << 6;
const ACK: u16 = 1 << 7;
const HAS_MIC: u16 = 1 << 8;
const SECURE: u16 = 1 << 9;
const ERROR: u16 = 1 << 10;
const REQUEST: u16 = 1 << 11;
const ENCRYPTED: u16 = 1 << 12;

/// One thing for the driver to do, in the order given.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// send this EAPOL frame (802.1X header onward) to the AP; wait until it is sent before the next action
    Send(Vec<u8>),
    /// install the pairwise CCMP key
    InstallPtk([u8; 16]),
    /// install the group CCMP key with this key index
    InstallGtk(u8, [u8; 16]),
    /// the 4-way handshake is done: open the port for data
    Authorize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// not an EAPOL-Key frame of our profile, or truncated: ignore it
    Malformed,
    /// the replay counter did not increase: ignore it
    Replay,
    /// the MIC did not verify (a forged frame, or the AP derived another PTK): ignore it
    Mic,
    /// message 3 arrived before message 1, or its ANonce differs: ignore it
    Unexpected,
    /// message 3's RSN element differs from the beacon's (a downgrade): leave the network
    RsnMismatch,
    /// the key data does not carry a usable GTK: leave the network
    NoGtk,
}

/// The supplicant's handshake state for one association.
pub struct Handshake {
    pmk: [u8; 32],
    aa: [u8; 6],
    spa: [u8; 6],
    ap_rsn: Vec<u8>,
    snonce: [u8; 32],
    anonce: Option<[u8; 32]>,
    ptk: Option<Ptk>,
    replay: Option<[u8; 8]>,
    authorized: bool,
}

impl Handshake {
    /// `aa` = the AP's MAC (BSSID), `spa` = ours, `ap_rsn` = the RSN element from its beacon or probe response,
    /// `snonce` = 32 bytes from the hardware random source (never time-derived).
    pub fn new(pmk: [u8; 32], aa: [u8; 6], spa: [u8; 6], ap_rsn: &[u8], snonce: [u8; 32]) -> Self {
        Handshake {
            pmk,
            aa,
            spa,
            ap_rsn: ap_rsn.to_vec(),
            snonce,
            anonce: None,
            ptk: None,
            replay: None,
            authorized: false,
        }
    }

    /// True once the 4-way handshake completed.
    pub fn authorized(&self) -> bool {
        self.authorized
    }

    /// One EAPOL frame from the AP (802.1X header onward).
    pub fn on_eapol(&mut self, f: &[u8]) -> Result<Vec<Action>, Error> {
        if f.len() < DATA || f[1] != 3 || f[4] != 2 {
            return Err(Error::Malformed);
        }
        let body = u16::from_be_bytes([f[2], f[3]]) as usize;
        let dlen = u16::from_be_bytes([f[DATA_LEN], f[DATA_LEN + 1]]) as usize;
        if 4 + body > f.len() || DATA + dlen > 4 + body {
            return Err(Error::Malformed);
        }
        let f = &f[..4 + body];
        let info = u16::from_be_bytes([f[KEY_INFO], f[KEY_INFO + 1]]);
        if info & 7 != VER2 || info & ACK == 0 || info & (ERROR | REQUEST) != 0 {
            return Err(Error::Malformed);
        }
        let replay: [u8; 8] = f[REPLAY..NONCE].try_into().unwrap();
        // message 1 may be resent with the same counter; anything with a MIC must move the counter forward
        let fresh = self
            .replay
            .is_none_or(|r| replay > r || (info & HAS_MIC == 0 && replay == r));
        if !fresh {
            return Err(Error::Replay);
        }
        if info & PAIRWISE != 0 && info & HAS_MIC == 0 {
            return Ok(self.msg1(f, replay));
        }
        let ptk = self.ptk.clone().ok_or(Error::Unexpected)?;
        if info & HAS_MIC == 0 || mic(&ptk.kck, f) != f[MIC..MIC + 16] {
            return Err(Error::Mic);
        }
        if info & PAIRWISE != 0 {
            self.msg3(f, info, replay, &ptk)
        } else {
            self.group1(f, info, replay, &ptk)
        }
    }

    fn msg1(&mut self, f: &[u8], replay: [u8; 8]) -> Vec<Action> {
        let anonce: [u8; 32] = f[NONCE..NONCE + 32].try_into().unwrap();
        let ptk = ptk(&self.pmk, &self.aa, &self.spa, &anonce, &self.snonce);
        let reply = reply(
            f[0],
            &ptk.kck,
            VER2 | PAIRWISE | HAS_MIC,
            &replay,
            &self.snonce,
            &RSN_IE,
        );
        self.anonce = Some(anonce);
        self.ptk = Some(ptk);
        self.replay = Some(replay);
        vec![Action::Send(reply)]
    }

    fn msg3(
        &mut self,
        f: &[u8],
        info: u16,
        replay: [u8; 8],
        ptk: &Ptk,
    ) -> Result<Vec<Action>, Error> {
        if info & (INSTALL | SECURE | ENCRYPTED) != INSTALL | SECURE | ENCRYPTED
            || self.anonce.is_none_or(|a| a[..] != f[NONCE..NONCE + 32])
        {
            return Err(Error::Unexpected);
        }
        self.replay = Some(replay);
        let data = unwrap(&ptk.kek, key_data(f))?;
        let rsn = ies(&data)
            .find(|ie| ie[0] == 0x30)
            .ok_or(Error::RsnMismatch)?;
        if rsn != &self.ap_rsn[..] {
            return Err(Error::RsnMismatch);
        }
        let (idx, gtk) = gtk(&data)?;
        let msg4 = reply(
            f[0],
            &ptk.kck,
            VER2 | PAIRWISE | HAS_MIC | SECURE,
            &replay,
            &[0; 32],
            &[],
        );
        if self.authorized {
            // a resent msg3 (our msg4 was lost): answer it, but never install the keys again (a reinstalled PTK
            // restarts its packet numbers: the KRACK nonce reuse)
            return Ok(vec![Action::Send(msg4)]);
        }
        self.authorized = true;
        Ok(vec![
            Action::Send(msg4),
            Action::InstallPtk(ptk.tk),
            Action::InstallGtk(idx, gtk),
            Action::Authorize,
        ])
    }

    // the AP's group key handshake message 1 (a GTK rekey after the 4-way)
    fn group1(
        &mut self,
        f: &[u8],
        info: u16,
        replay: [u8; 8],
        ptk: &Ptk,
    ) -> Result<Vec<Action>, Error> {
        if !self.authorized || info & (SECURE | ENCRYPTED) != SECURE | ENCRYPTED {
            return Err(Error::Unexpected);
        }
        self.replay = Some(replay);
        let (idx, gtk) = gtk(&unwrap(&ptk.kek, key_data(f))?)?;
        let msg2 = reply(
            f[0],
            &ptk.kck,
            VER2 | HAS_MIC | SECURE,
            &replay,
            &[0; 32],
            &[],
        );
        Ok(vec![Action::Send(msg2), Action::InstallGtk(idx, gtk)])
    }
}

fn key_data(f: &[u8]) -> &[u8] {
    let n = u16::from_be_bytes([f[DATA_LEN], f[DATA_LEN + 1]]) as usize;
    &f[DATA..DATA + n]
}

fn unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return Err(Error::NoGtk);
    }
    let mut out = vec![0u8; wrapped.len()];
    let n = KwAes128::new(kek.into())
        .unwrap_key(wrapped, &mut out)
        .map_err(|_| Error::NoGtk)?
        .len();
    out.truncate(n);
    Ok(out)
}

// the elements of key data (id, length, body each); stops at padding (0xdd 0x00) or a truncated one
fn ies(d: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    core::iter::from_fn(move || {
        let n = *d.get(at + 1)? as usize;
        let ie = d.get(at..at + 2 + n)?;
        if ie[0] == 0xdd && n == 0 {
            return None;
        }
        at += 2 + n;
        Some(ie)
    })
}

// the GTK KDE: dd len 00-0F-AC 01, key id (bits 0-1), reserved, the 16-byte CCMP key
fn gtk(d: &[u8]) -> Result<(u8, [u8; 16]), Error> {
    let kde = ies(d)
        .find(|ie| ie[0] == 0xdd && ie.len() == 2 + 6 + 16 && ie[2..6] == [0x00, 0x0f, 0xac, 1]);
    let kde = kde.ok_or(Error::NoGtk)?;
    Ok((kde[6] & 3, kde[8..24].try_into().unwrap()))
}

// an EAPOL-Key frame from us: 802.1X version as the AP's, key length 0, the MIC filled in last
fn reply(
    version: u8,
    kck: &[u8; 16],
    info: u16,
    replay: &[u8; 8],
    nonce: &[u8; 32],
    data: &[u8],
) -> Vec<u8> {
    let mut f = vec![0u8; DATA + data.len()];
    f[0] = version;
    f[1] = 3;
    let body = (f.len() - 4) as u16;
    f[2..4].copy_from_slice(&body.to_be_bytes());
    f[4] = 2;
    f[KEY_INFO..KEY_LEN].copy_from_slice(&info.to_be_bytes());
    f[REPLAY..NONCE].copy_from_slice(replay);
    f[NONCE..NONCE + 32].copy_from_slice(nonce);
    f[DATA_LEN..DATA].copy_from_slice(&(data.len() as u16).to_be_bytes());
    f[DATA..].copy_from_slice(data);
    let m = mic(kck, &f);
    f[MIC..MIC + 16].copy_from_slice(&m);
    f
}

#[cfg(test)]
mod tests;
