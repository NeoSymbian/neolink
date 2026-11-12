// SPDX-License-Identifier: Apache-2.0
// PBKDF2 vectors: IEEE 802.11-2016 J.4.2; PRF and PTK vectors cross-checked with Python's hashlib/hmac.
// A small in-test authenticator (the AP side) runs whole handshakes against `Handshake`.

use super::*;
use std::vec::Vec;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn psk_vectors() {
    assert_eq!(
        psk(b"password", b"IEEE")[..],
        hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
    );
    assert_eq!(
        psk(b"ThisIsAPassword", b"ThisIsASSID")[..],
        hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
    );
}

#[test]
fn prf_vector() {
    let mut out = [0u8; 64];
    prf(&[0x0b; 20], b"prefix", b"Hi There", &mut out);
    assert_eq!(
        out[..],
        hex(
            "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee\
             75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
        )
    );
}

const AA: [u8; 6] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5];
const SPA: [u8; 6] = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];

fn nonces() -> ([u8; 32], [u8; 32]) {
    (
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|i| 32 + i as u8),
    )
}

#[test]
fn ptk_vector() {
    let (an, sn) = nonces();
    let pmk = psk(b"ThisIsAPassword", b"ThisIsASSID");
    let k = hex(
        "8d59336efcfe0d51e428d3073415cf3b41d606188a68cfa3513f038d5ff30eae6119fadb3a99d8659ec1949941b7197b",
    );
    // the argument order must not matter: min/max of the addresses and nonces
    for p in [
        ptk(&pmk, &AA, &SPA, &an, &sn),
        ptk(&pmk, &SPA, &AA, &sn, &an),
    ] {
        assert_eq!(
            (&p.kck[..], &p.kek[..], &p.tk[..]),
            (&k[..16], &k[16..32], &k[32..])
        );
    }
}

#[test]
fn rfc3394_unwrap() {
    let kek: [u8; 16] = core::array::from_fn(|i| i as u8);
    let out = unwrap(
        &kek,
        &hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
    )
    .unwrap();
    assert_eq!(out, hex("00112233445566778899aabbccddeeff"));
}

#[test]
fn rsn_parse() {
    let r = Rsn::parse(&RSN_IE).unwrap();
    assert!(r.supported());
    // WPA2/WPA3 transition: pairwise CCMP, AKM SAE (8) + PSK (2), MFP capable (0x80) but not required
    let mixed = hex("30180100000fac040100000fac040200000fac08000fac028000");
    assert!(Rsn::parse(&mixed).unwrap().supported());
    // WPA3 only: SAE, MFP required (0xc0)
    let sae = hex("30140100000fac040100000fac040100000fac08c000");
    let r = Rsn::parse(&sae).unwrap();
    assert!(!r.akm_psk && r.mfp_required && !r.supported());
    // TKIP group
    let tkip = hex("30140100000fac020100000fac040100000fac020000");
    assert!(!Rsn::parse(&tkip).unwrap().supported());
    assert_eq!(Rsn::parse(&hex("3002")), None);
    assert_eq!(Rsn::parse(&hex("301401")), None);
}

// ---- the AP side
struct Ap {
    pmk: [u8; 32],
    anonce: [u8; 32],
    replay: u64,
    gtk: [u8; 16],
    ptk: Option<Ptk>,
}

impl Ap {
    fn new(pass: &[u8]) -> Self {
        Ap {
            pmk: psk(pass, b"home"),
            anonce: nonces().0,
            replay: 1,
            gtk: [0x77; 16],
            ptk: None,
        }
    }

    fn frame(
        &mut self,
        info: u16,
        nonce: &[u8; 32],
        data: &[u8],
        kck: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut f = vec![0u8; DATA + data.len()];
        f[0] = 2;
        f[1] = 3;
        let body = (f.len() - 4) as u16;
        f[2..4].copy_from_slice(&body.to_be_bytes());
        f[4] = 2;
        f[KEY_INFO..KEY_LEN].copy_from_slice(&info.to_be_bytes());
        f[KEY_LEN..REPLAY].copy_from_slice(&16u16.to_be_bytes());
        f[REPLAY..NONCE].copy_from_slice(&self.replay.to_be_bytes());
        f[NONCE..NONCE + 32].copy_from_slice(nonce);
        f[DATA_LEN..DATA].copy_from_slice(&(data.len() as u16).to_be_bytes());
        f[DATA..].copy_from_slice(data);
        if let Some(k) = kck {
            let m = mic(k, &f);
            f[MIC..MIC + 16].copy_from_slice(&m);
        }
        self.replay += 1;
        f
    }

    fn msg1(&mut self) -> Vec<u8> {
        let a = self.anonce;
        self.frame(VER2 | PAIRWISE | ACK, &a, &[], None)
    }

    // checks message 2 as an AP would, and derives the PTK from its SNonce
    fn take_msg2(&mut self, f: &[u8]) -> bool {
        let snonce: [u8; 32] = f[NONCE..NONCE + 32].try_into().unwrap();
        let p = ptk(&self.pmk, &AA, &SPA, &self.anonce, &snonce);
        let ok = mic(&p.kck, f) == f[MIC..MIC + 16] && key_data(f) == RSN_IE;
        self.ptk = Some(p);
        ok
    }

    fn wrapped(&self, rsn: &[u8], key_id: u8) -> Vec<u8> {
        let mut d = rsn.to_vec();
        d.extend_from_slice(&[0xdd, 22, 0x00, 0x0f, 0xac, 1, key_id, 0]);
        d.extend_from_slice(&self.gtk);
        d.extend_from_slice(&[0xdd, 0]);
        d.resize(d.len().div_ceil(8) * 8, 0);
        let mut out = vec![0u8; d.len() + 8];
        KwAes128::new(&self.ptk.as_ref().unwrap().kek.into())
            .wrap_key(&d, &mut out)
            .unwrap();
        out
    }

    fn msg3(&mut self, rsn: &[u8]) -> Vec<u8> {
        let (data, a, kck) = (
            self.wrapped(rsn, 1),
            self.anonce,
            self.ptk.clone().unwrap().kck,
        );
        self.frame(
            VER2 | PAIRWISE | INSTALL | ACK | HAS_MIC | SECURE | ENCRYPTED,
            &a,
            &data,
            Some(&kck),
        )
    }
}

fn supplicant(pass: &[u8]) -> Handshake {
    Handshake::new(psk(pass, b"home"), AA, SPA, &RSN_IE, nonces().1)
}

fn sent(a: &Action) -> &[u8] {
    match a {
        Action::Send(f) => f,
        other => panic!("expected Send, got {other:?}"),
    }
}

#[test]
fn four_way_then_rekey() {
    let mut ap = Ap::new(b"correct horse");
    let mut s = supplicant(b"correct horse");
    let a = s.on_eapol(&ap.msg1()).unwrap();
    assert!(ap.take_msg2(sent(&a[0])));
    let tk = ap.ptk.clone().unwrap().tk;
    let a = s.on_eapol(&ap.msg3(&RSN_IE.clone())).unwrap();
    let msg4 = sent(&a[0]);
    assert_eq!(
        mic(&ap.ptk.as_ref().unwrap().kck, msg4),
        msg4[MIC..MIC + 16]
    );
    assert_eq!(
        u16::from_be_bytes([msg4[KEY_INFO], msg4[KEY_INFO + 1]]),
        VER2 | PAIRWISE | HAS_MIC | SECURE
    );
    assert_eq!(
        a[1..],
        [
            Action::InstallPtk(tk),
            Action::InstallGtk(1, [0x77; 16]),
            Action::Authorize
        ]
    );
    assert!(s.authorized());

    // group rekey: a new GTK with key id 2
    ap.gtk = [0x99; 16];
    let (data, kck) = (ap.wrapped(&[], 2), ap.ptk.clone().unwrap().kck);
    let g1 = ap.frame(
        VER2 | ACK | HAS_MIC | SECURE | ENCRYPTED,
        &[0; 32],
        &data,
        Some(&kck),
    );
    let a = s.on_eapol(&g1).unwrap();
    assert_eq!(mic(&kck, sent(&a[0])), sent(&a[0])[MIC..MIC + 16]);
    assert_eq!(a[1], Action::InstallGtk(2, [0x99; 16]));
    // the same frame again is a replay
    assert_eq!(s.on_eapol(&g1), Err(Error::Replay));
}

#[test]
fn wrong_password() {
    let mut ap = Ap::new(b"correct horse");
    let mut s = supplicant(b"wrong horse");
    let a = s.on_eapol(&ap.msg1()).unwrap();
    // the AP rejects message 2; even a message 3 it sent anyway fails our MIC check
    assert!(!ap.take_msg2(sent(&a[0])));
    assert_eq!(s.on_eapol(&ap.msg3(&RSN_IE.clone())), Err(Error::Mic));
    assert!(!s.authorized());
}

#[test]
fn msg1_resent_and_replays() {
    let mut ap = Ap::new(b"pw-pw-pw");
    let mut s = supplicant(b"pw-pw-pw");
    let m1 = ap.msg1();
    s.on_eapol(&m1).unwrap();
    // the AP resends message 1 unchanged (same counter): answered again
    assert!(s.on_eapol(&m1).is_ok());
    // a new message 1 with a new ANonce replaces the PTK
    ap.anonce = [5; 32];
    let a = s.on_eapol(&ap.msg1()).unwrap();
    assert!(ap.take_msg2(sent(&a[0])));
    // an old counter is refused
    assert_eq!(s.on_eapol(&m1), Err(Error::Replay));
    assert!(s.on_eapol(&ap.msg3(&RSN_IE.clone())).is_ok());
}

#[test]
fn downgrade_and_garbage() {
    let mut ap = Ap::new(b"pw-pw-pw");
    let mut s = supplicant(b"pw-pw-pw");
    let a = s.on_eapol(&ap.msg1()).unwrap();
    ap.take_msg2(sent(&a[0]));
    // message 3 carries an RSN element other than the beacon's
    let other = hex("30140100000fac040100000fac040100000fac020c00");
    assert_eq!(s.on_eapol(&ap.msg3(&other)), Err(Error::RsnMismatch));

    let mut s = supplicant(b"pw-pw-pw");
    assert_eq!(s.on_eapol(&[]), Err(Error::Malformed));
    assert_eq!(s.on_eapol(&[2, 3, 0, 95]), Err(Error::Malformed));
    let mut m1 = Ap::new(b"pw-pw-pw").msg1();
    m1[3] = 200; // body length past the end
    assert_eq!(s.on_eapol(&m1), Err(Error::Malformed));
    // message 3 before any message 1
    let mut ap = Ap::new(b"pw-pw-pw");
    ap.ptk = Some(ptk(&ap.pmk, &AA, &SPA, &ap.anonce, &nonces().1));
    assert_eq!(
        s.on_eapol(&ap.msg3(&RSN_IE.clone())),
        Err(Error::Unexpected)
    );
}

#[test]
fn resent_msg3_reinstalls_nothing() {
    // msg4 was lost, so the AP resends msg3 (a new replay counter): answer it, but install no key again (a reinstalled
    // PTK would reset its packet numbers: the KRACK nonce reuse)
    let mut ap = Ap::new(b"pw-pw-pw");
    let mut s = supplicant(b"pw-pw-pw");
    let a = s.on_eapol(&ap.msg1()).unwrap();
    ap.take_msg2(sent(&a[0]));
    assert_eq!(s.on_eapol(&ap.msg3(&RSN_IE.clone())).unwrap().len(), 4);
    let again = s.on_eapol(&ap.msg3(&RSN_IE.clone())).unwrap();
    assert_eq!(again.len(), 1);
    let msg4 = sent(&again[0]);
    assert_eq!(
        mic(&ap.ptk.as_ref().unwrap().kck, msg4),
        msg4[MIC..MIC + 16]
    );
}
