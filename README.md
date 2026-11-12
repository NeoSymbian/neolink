# NeoSymbian Wi-Fi

User-side Rust for the Pixel 3a XL's Wi-Fi (Qualcomm WCN3990 on SDM670), on the 2010 Symbian user side
(`armv5te-none-eabi`, `no_std` + `alloc`). The plan, hardware facts and stages are in
[docs/wifi.md](https://github.com/NeoSymbian/docs/blob/main/wifi.md).

| Crate | What |
|---|---|
| `wlfw` | The firmware's QMI control service (WLFW, QMI 69): start-up to firmware ready, WLAN cfg, mission mode. Driven by MODEMD (telephony), which owns the modem's QRTR link |

The kernel side (copy engines, HTC, WMI; the WHA chip driver later) is C++ in
[kernel](https://github.com/NeoSymbian/kernel) `baseport/arm64/sdm670_assp/qcom_wcn3990.cpp`.

No Qualcomm firmware or board data is stored here: the phone's own vendor partition provides them at runtime.

## Licence

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0` in every file). Message ids and layouts are facts from Linux ath10k
(ISC, Copyright (c) 2018 The Linux Foundation), cited in the source.
