# NeoLink

NeoSymbian's wireless connectivity: user-side Rust for the Pixel 3a XL's Qualcomm WCN3990 (SDM670), Wi-Fi now and
Bluetooth later (the same combo chip), on the 2010 Symbian user side
(`armv5te-none-eabi`, `no_std` + `alloc`). The Wi-Fi plan, hardware facts and stages are in
[docs/wifi.md](https://github.com/NeoSymbian/docs/blob/main/wifi.md); Bluetooth is driver-support D6.

(Not the dropped USB-SSH tool of the same name from the debug-access work: nothing of it is here.)

| Crate | What |
|---|---|
| `wlfw` | The firmware's QMI control service (WLFW, QMI 69): start-up to firmware ready, WLAN cfg, mission mode. Driven by MODEMD (telephony), which owns the modem's QRTR link |
| `wpa` | WPA2-PSK, supplicant side: passphrase → PMK, PTK, the 4-way and group key handshakes over EAPOL-Key frames (sans-I/O; CCMP, PSK, no MFP). Driven by neoui's Wi-Fi join (docs wifi.md W4) |

The kernel side (copy engines, HTC, WMI; the WHA chip driver later) is C++ in
[kernel](https://github.com/NeoSymbian/kernel) `baseport/arm64/sdm670_assp/qcom_wcn3990.cpp`.

No Qualcomm firmware or board data is stored here: the phone's own vendor partition provides them at runtime.

## Licence

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0` in every file). Message ids and layouts are facts from Linux ath10k
(ISC, Copyright (c) 2018 The Linux Foundation), cited in the source.
`wpa` follows IEEE 802.11-2016 12.7 and uses RustCrypto's `sha1`, `hmac`, `pbkdf2` and `aes-kw` (MIT/Apache-2.0).
