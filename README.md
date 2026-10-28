# Petrel

**Dual-band (2.4 + 5 GHz) Wi-Fi and BLE security-research toolkit for the Flipper Zero, built on the Realtek RTL8720DN (BW16).**

Petrel pairs an inexpensive BW16 companion board with a Flipper Zero (over UART) to scan, audit and
analyse Wi-Fi and BLE on **both the 2.4 GHz and 5 GHz bands**. The 5 GHz band is out of reach for the
2.4 GHz-only ESP32 radios that most Flipper Wi-Fi tools are built on, which is where the dual-band
BW16 earns its place. The firmware runs on the BW16; a native Flipper app drives it. It can also be
flashed onto an existing BW16 board (see **Flashing**).

---

## ⚠️ Disclaimer

Petrel is provided **for educational purposes and authorized security testing only**.

- Use it **only** on networks and devices you **own** or have **explicit written permission** to test.
- Transmitting deauthentication frames, operating rogue access points, or capturing credentials on
  networks you do not own may be **illegal** in your jurisdiction.
- **You are solely responsible** for complying with all applicable local, national and international laws.
- Provided **"AS IS", without warranty of any kind**. The authors and contributors accept **no liability**
  for any damage, data loss or legal consequence arising from use or misuse.

By using Petrel you confirm you are operating within a lawful, authorized scope.

---

## Features

- **Dual-band scan** — 2.4 **and 5 GHz** APs with signal, channel, encryption, **PMF / WPA3 detection**
  and RSSI sorting.
- **Channel map / analyzer** across both bands.
- **Handshake capture → PCAP** and **PMKID** (incl. clientless) with **exchange-aware capture validation**
  (matches BSSID / station / replay counter — not just message presence).
- **BLE reconnaissance** — scanner with vendor tagging (Apple / Find My / Microsoft), GATT service
  enumeration, iBeacon broadcast.
- **WIDS** — passive deauthentication / disassociation detection.
- Dual-use Wi-Fi primitives (deauth, beacon/probe tooling, captive-portal demo, KARMA, floods) — see the
  disclaimer; these transmit and must only be used on your own equipment in a shielded/authorized lab.
- Results and audit metadata logged to the Flipper SD card.

For an honest, per-feature status (HW-verified / implemented / experimental / unsupported, plus which
bands each path covers), see **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)**.

> **Note on captive portals:** the public tree ships only a **neutral** sign-in page plus a *load your own
> portal from SD* mechanism. Real-brand login clones are **not** included here (phishing / trademark /
> platform-policy reasons); they live in a separate private overlay and are the user's own responsibility.

---

## Hardware

A BW16 / RTL8720DN board wired to the Flipper Zero GPIO:

| BW16 | Flipper Zero |
|------|--------------|
| 5V   | (1) 5V       |
| GND  | (8) GND      |
| RX1  | (13) TX      |
| TX1  | (14) RX      |

Use the **TX1/RX1** port (not RX0/TX0). Do **not** power the BW16 from both USB and the Flipper 5V at once.

---

## Build

**Firmware** (Docker, x86_64 AmebaD toolchain):
```bash
bash firmware-build/build_petrel.sh "$PWD/RTL8720dn-firmware" "$PWD/firmware-build/out" ~/.cache/petrel-arduino15
```

**Flipper app** (ufbt):
```bash
cd flipper-app && ufbt            # builds dist/petrelrtl.fap
ufbt launch                       # install + launch on a connected Flipper
```

**Host tooling** (`tools/`) needs `pyserial` (`python3 -m venv .venv && .venv/bin/pip install pyserial`).
Screen capture without an RPC session — the FAP mirrors every frame to `/ext/petrel/shot.hex`, so the
20 KB an RPC session (`flipctl`/qFlipper) would take never goes missing:
```bash
python3 tools/flip_shot.py shot.png
```

---

## Flashing (incl. for 5Ghost / BW16 users)

The BW16 is the same board several closed firmwares ship on, so you can replace that firmware with
Petrel. After building, flash the generated `firmware-build/out/build/km0_km4_image2.bin`:

```bash
cp firmware-build/out/build/km0_km4_image2.bin flasher/petrel-km0_km4_image2.bin
cd flasher && python3 flash_petrel.py            # CH340 @ 115200, writes image2 @ 0x6000
```

The board drops into download mode automatically (CH340 DTR/RTS). If it does not, hold the BOOT/BURN
button while re-plugging. Boot + calibration are left untouched. See `flasher/README.md` for details.

---

## Standalone vs Flipper

The firmware runs on the BW16 itself; the Flipper app is the control UI over UART. The board can also be
driven by any host over the CH340 serial link (see `tools/`), so it is not strictly tied to the Flipper.

---

## Credits & License

Petrel is a fork of **gorebrau/delfyRTL** — https://github.com/gorebrau/delfyRTL

Licensed under the **MIT License** — see [LICENSE](LICENSE). The upstream copyright notice is retained as required.
