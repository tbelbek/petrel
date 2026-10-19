# Petrel capability ledger

An honest, per-feature status for Petrel. The point is transparency, not a feature race:
a capability is listed at the level actually demonstrated, not at the level the code *intends*.
Radio outcomes depend on the specific AP, client, channel and RF environment, so "works here"
is never a guarantee it works everywhere.

## Status legend

| Status | Meaning |
|--------|---------|
| **HW‑verified** | Exercised on real hardware with an observed, reproducible result (RF‑confirmed where relevant). |
| **Implemented** | Code path complete and build‑clean; routine on‑device confirmation expected but not independently logged here. |
| **Experimental** | Present but unproven / known to depend heavily on target or timing; treat results with suspicion. |
| **Unsupported** | Deliberately refused or out of scope. |

## Bands

| Band | Channels | TX | RX |
|------|----------|----|----|
| 2.4 GHz | 1–14 | yes | yes |
| 5 GHz UNII‑1 | 36–48 | **HW‑verified** (raw TX + SoftAP) | yes |
| 5 GHz UNII‑2 / DFS | 52–144 | **Unsupported** (radar bands — RX only) | yes |
| 5 GHz UNII‑3 | 149–165 | **HW‑verified** (raw TX) | yes |

5 GHz raw TX requires a channel set immediately before each frame (`wext_set_channel`); the board
has **one** radio, so an active SoftAP and a hopping/monitoring receiver are mutually exclusive.

## Reconnaissance (RX, no frames transmitted)

| Feature | Band(s) | Status | Notes |
|---------|---------|--------|-------|
| Dual‑band scan (SSID/BSSID/RSSI/ch/enc) | 2.4 + 5 | HW‑verified | Core scan path. |
| PMF / WPA3 detection (SAE, MFP cap/req) | 2.4 + 5 | Implemented | Classifies WPA2 / WPA2+PMFcap / WPA3(PMFcap) / WPA3‑only. |
| Station scan (STASCAN) | per‑channel | Implemented | |
| Probe / PNL sniff | per‑channel | Implemented | |
| Client tracker (first/last/count) | per‑channel | Implemented | |
| Deauth IDS (passive) | per‑channel | Implemented | Counts deauth frames; no TX. |
| Live frame sniffer stream (DP_FRAME) | per‑channel | Implemented | Bounded ring; sustained load drops frames (surfaced). |

## Capture & audit (RX capture; some paths TX to force a handshake)

| Feature | Band(s) | Status | Notes |
|---------|---------|--------|-------|
| Passive handshake capture (CAPTURE) | 2.4 + 5 | Implemented | Channel‑wide; no injection. |
| Handshake grab (HSGRAB, deauth‑assisted) | 2.4 + 5 | Implemented | TX deauth → operator‑validated (affects third parties). BSSID‑filtered. |
| PMKID passive | 2.4 + 5 | Implemented | Channel‑wide; extracts M1 PMKID. |
| PMKID grab (PKGRAB, deauth) | 2.4 + 5 | Implemented | TX deauth → operator‑validated. |
| PMKID clientless (raw assoc) | 2.4 + 5 | Experimental | Raw open‑auth + WPA2‑PSK assoc; success is AP‑dependent. |
| Guided audit (method select + evidence pack) | 2.4 + 5 | Implemented | Picks HS vs PMKID, binds to the selected BSSID, writes `audit.json` + `report.txt` with a confirmed‑`saved` flag. |
| Capture validation (EAPOL 4‑way, PMKID 22000) | n/a | HW‑verified (logic) | Pure‑C validator, host unit‑tested (`common/petrel_capture_quality_test.c`). Validates structure, not MIC authenticity. |

Completion is quality‑gated (an exchange‑consistent handshake pair, or a target‑bound PMKID) and
reported separately from whether the evidence file was confirmed written (`saved`). A capture is
never auto‑cracked on‑device: the artifacts are for offline hashcat/aircrack.

## Offensive (TX — operator‑validated only)

These transmit frames that affect third‑party networks/clients. They are implemented and build‑clean,
but their *effect* is only ever confirmed by the operator against networks they own/are authorised to
test — this project does not ship demonstrated‑impact claims for them.

| Feature | Band(s) | Status |
|---------|---------|--------|
| Deauth list (multi‑target) + RUN/STOP | 2.4 + 5 | Implemented |
| CSA (channel‑switch) attack | 2.4 + 5 | Implemented |
| BTM (BSS transition) attack | 2.4 + 5 | Implemented |
| Auth flood | 2.4 + 5 | Implemented |
| Assoc+sleep flood | 2.4 + 5 | Implemented |
| SAE / Dragonblood commit flood (WPA3) | 2.4 + 5 | Experimental |
| Eviltwin / captive portal (SoftAP) | 2.4 (HW‑verified) · 5 (SoftAP HW‑verified ch36/149) | Implemented |
| Raw beacon / probe flood | 2.4 + 5 | HW‑verified (TX path, ch36 + ch149) |

Real‑brand credential‑capture portals are **not** in this repository (neutral Default page only);
they live in a separate private overlay for GitHub‑ToS / trademark / phishing‑liability reasons.

## BLE

| Feature | Status | Notes |
|---------|--------|-------|
| BLE scan / advertise / HID | Implemented | AmebaD BLE stack. |
| BLE client (service/characteristic enumerate) | Implemented | Core patched to expose discovered UUIDs. |

## Known limits

- **One radio.** No simultaneous independent 2.4 + 5 GHz operation; SoftAP and monitor/hop cannot run at once.
- **DFS (52–144) is RX‑only** by design (radar bands).
- **Capture buffers are bounded** (firmware 8 frames × 256 B; FAP 16 records) — heavy channel load can drop frames; the validator's reject histogram surfaces why a capture is unusable.
- **Validation is structural**, not cryptographic: it proves a crackable *exchange shape*, not that the MIC authenticates or that the password will fall.
- `BBH` and similar exploratory commands remain explicitly unverified in firmware.
