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

### Captive‑portal behaviour

The portal is served by a raw‑lwIP listener on the SoftAP, not by the Arduino `WiFiServer`
(whose accept never fires on the AP). What the listener does, per request:

| Request | Un‑authorized client | Client that already submitted the form |
|---------|----------------------|----------------------------------------|
| OS probe (`generate_204`, `ncsi`, `hotspot`, …) | 302 to the portal root | **204 No Content**; Windows `ncsi`/`connecttest` get a 200 with the body they validate |
| `/cp.json` (RFC 8908) | `captive:true` | `captive:false` |
| anything else | the selected portal page | the selected portal page |

- **Authorization** is keyed on the client's IPv4 and lasts until the AP is torn down or the entry is
  evicted. The lease/authorization tables hold 8 clients: a ninth distinct client takes the oldest
  slot, so its address (and authorization) can be reused before the old lease expires.
- **Rotation** (`PORTALROT 1`) advances to the next page on every credential submit; `Custom`
  (the page loaded from SD) is never rotated away from.
- **URLs** (DHCP option 114, the 302 `Location`, the `cp.json` body) are all derived from the AP
  SSID by `build_portal_urls()`, so they always agree with each other and with the DNS hijack.
- The page is streamed with `TCP_WRITE_FLAG_COPY` for the mutable buffers (Default, Custom) and
  zero‑copy only for immutable flash gzip blobs.

Both entry points are live: **Create AP** (`APSTART`) and **Evil** (`EVIL <n>`, which also deauths
the real AP). Both run through the cooperative AP lifecycle, so `loop()` stays responsive and a
bare `STOP` tears the AP down from any state.

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
- **The FAP's heap budget is tight.** Its image is ~82 KB of the Flipper's 187 KB heap, so free
  heap is 28–34 KB at idle (23 KB with the CLI attached). Anything that takes a large extra block —
  most of all an RPC session (`flipctl`, qFlipper), measured at **~20 KB** — pushes it into
  `out of memory` and reboots the Flipper. Drive keys from the CLI (`input send <key>
  press|short|release`) and take screenshots with `tools/flip_shot.py` (reads the frame the app
  mirrors to `/ext/petrel/shot.hex`; no RPC).
- **Capability-gated menus disappear when IDENT fails.** If the board does not answer `HELLO`,
  `fw_caps` stays empty and Tools / Load Portal / KARMA rows are hidden. Reset the board **while the
  Flipper is up** (opening the CH340 does it) and re-enter the Wi-Fi hub to retry.
- `BBH` and similar exploratory commands remain explicitly unverified in firmware.

## Coverage & target-compatibility matrix

> **Anchor:** the 2026‑10‑19 PASS rows below were produced on the **v1.0.0** build. They are not
> re-established for the current development tree — a 2026‑10‑28 hardware run on it hit repeated
> `out of memory` crashes (see the memory limit in *Known limits*), so treat the endurance and
> traversal rows as "passed on v1.0.0", not "passes today".

Radio behaviour is environment- and target-specific, so this project does not publish blanket
"works everywhere" claims. The matrix below is the **reproducible coverage template**: fill the
result columns from your own runs on networks you own / are authorised to test. "Expected" is what
the design intends; "Observed" is for your logged result (date, firmware version, notes). Leave a
row blank until you have actually run it — an empty cell is honest; a guessed cell is not.

| Scenario | Band / channel | Expected | Observed (operator) |
|----------|----------------|----------|---------------------|
| Dual-band scan sees 5 GHz APs | 5 GHz 36–48 / 149–165 | APs listed with ch/enc/PMF | |
| Scan sees DFS APs (RX only) | 5 GHz 52–144 | APs listed, no TX | |
| Handshake capture (WPA2, client present) | 2.4 GHz | M1–M4 pair, `complete=true` | |
| Handshake capture (WPA2, 5 GHz AP) | 5 GHz 36/149 | M1–M4 pair, `complete=true` | |
| PMKID clientless (RSN AP, no client) | 2.4 / 5 GHz | PMKID line, target-bound | |
| Guided audit picks PMKID for PMF-required | any | method=pmkid, refusal if none | |
| Eviltwin / SoftAP joinable (DHCP+DNS+HTTP) | 2.4 GHz | client gets IP, portal loads | |
| Eviltwin / SoftAP joinable | 5 GHz 36 / 149 | client gets IP, portal loads | |
| Off-target handshake rejected | shared channel | other AP's pair NOT counted | |
| Mode-change / cancel (AP start→stop ×N + cancel) | n/a | no wedge, board stays responsive | **PASS 2026-10-19** — 10/10 AP cycles + cancellation clean (no stray READY, returns to idle), 0 faults/resets, max PING RTT 9 ms |
| Long run / SD-full behaviour | n/a | failed save surfaced, no false COMPLETE | **Endurance PASS 2026-10-19** — 60-lap FAP self-test soak: no crash/fault/OOM, no heap leak (boot_min flat 4624, largest-block stable); SD-full not yet tested |
| FAP scene traversal (nav crash/OOM) | n/a | clean 3-lap self-exit, no faults | **PASS 2026-10-19** — self-test 3-lap: kind7/8/9/10 complete, fault=0, clean exit to desktop |

### Reproducing results

1. Build + flash firmware (`firmware-build/build_petrel.sh`, then `flasher/`), install the FAP (`ufbt`).
2. Run the scenario against **your own** AP/client; for capture rows, pull the artifacts from
   `/ext/petrel/sessions/<id>/` (`audit.json`, `report.txt`, `hs.pcap` / `pmkid.22000`).
3. Record firmware version (`IDENT` / `PETREL_FW_VERSION`), FAP version, channel, target security, and
   the `complete` / `saved` / `counters` fields from `audit.json`.
4. For crack-through confirmation, run the `.pcap` / `.22000` through hashcat/aircrack **offline** — the
   device never cracks and never claims a password.

Rows that need third-party RF (joinable-AP end-to-end, long-run endurance, independent replication) are
**operator-validated by design**: they depend on live networks and hardware this repository cannot
exercise on its own.

### Verification log — v1.0.0 (2026-10-19)

What was actually verified for this release, and — just as importantly — what was **not**. Nothing
below is inferred: each "verified" line was run; each "not verified" line needs hardware/RF the repo
cannot exercise itself.

**Verified (host / build, reproducible without a board):**
- Capture validator unit tests: `common/petrel_capture_quality_test.c` — 18/18 pass under
  `cc -O2 -Wall -Wextra` (no warnings). Covers valid M1+M2 / M2+M3, replay & STA mismatch, duplicate,
  explicit off-target rejection, truncation, degenerate nonce/MIC, QoS-header offset, direction/`kdl`
  consistency, key-version pair mismatch, M2+M3 BSSID binding, histogram, capacity.
- Flipper app: `ufbt` build clean (Target 7, API 88.2); `.fap` produced and APPCHK-passed.
- Companion firmware: `firmware-build/build_petrel.sh` linux/amd64 Docker build clean;
  `km0_km4_image2.bin` produced (958 KB, 46% of program storage). BSSID-filter + QoS/HT offset compile.

**Verified on-device (BW16 + Flipper, 2026-10-19):**
- Firmware flashed to a physical BW16 (image2 verified ok) and the FAP launched on the Flipper.
- FAP scene-traversal self-test (3-lap): complete diagnostics, 0 faults, clean self-exit to desktop.
- Endurance soak (60-lap self-test, ~28 min / 600 scene transitions): no crash/fault/OOM and no heap
  leak (boot_min flat at 4624, largest free block stable at 12312; ~30 diag breadcrumbs dropped by the
  known recorder concurrency limitation — app behaviour was complete).
- AP mode-change / cancellation reliability: 10/10 AP start→ready→stop cycles plus a cancellation all
  clean (no stray READY, returns to idle), 0 faults/resets, board responsive throughout (max RTT 9 ms).

**NOT verified (requires real APs/clients or third parties — fill the matrix above):**
- Live capture outcomes against real APs/clients: 2.4/5 GHz handshake/PMKID, PMKID clientless,
  off-target rejection on a shared channel.
- Eviltwin/SoftAP joinability end-to-end (a real client joining + DHCP/DNS/HTTP), SD-full behaviour,
  and independent replication by a third party.

So "v1.0.0" means the code is build-clean and its host-testable logic is proven — not that its radio
behaviour has been independently RF-verified. Treat RF claims as expectations until the matrix is filled.

### Code-review hardening (2026-10-27)

A full review of the Wi-Fi card firmware found 23 defects. All are fixed; the same fixes are applied
to the sibling `petrel` tree, whose code was byte-identical. Build-verified only — the RF rows above
are still open.

**Dead code removed.** The legacy Arduino `WiFiServer` path (~120 lines) could never run: `atStart()`
always sets `webui_mode` or `web_portal_mode`, so its guard was permanently false. `handleRequest`,
`makeResponse`, `parseRequest`, `handle204/404`, `handleRedirect`, `ip_is_authed` and the per-loop
`server.available()` accept loop are gone; the raw-lwIP listener is the only HTTP server.

**Dead features made live.** `EVIL` and `createAP()` were stubs that only printed
`ERROR:Evil disabled`, so the app's main flow (scan → select → Evil) was inert. Both now start the
clone AP through the cooperative lifecycle and deauth the target. The portal behaviours that lived
only in the dead block were ported into `web_lwip.cpp`: per-client authorization with a 204 on OS
probes, `captive:false` on `/cp.json`, portal rotation, and SSID-derived URLs.

**Memory safety.** Out-of-bounds read of `deauth_wifis` after any list shrink (`current_num` was
reset only after the dereference); `strchr` on a non-NUL-terminated pbuf plus a missing
`len >= 12` guard in the DNS handler; use-after-free in `unbind_all_udp()`; leaked send cursor on
peer FIN; uninitialized `Content-Length`; `TX_RAW_MAX_PAYLOAD` (64) smaller than its own buffer
(128), which silently dropped the DS Parameter Set from beacons; `PORTAL <n>` without a range check.

**Logic.** `atFail(1)` retried forever and never reached `FAILED` (now capped at 3); `tx_raw_chan_ok`
accepted the non-channels 15–35; `EVILTWIN START … LIVE` accepted DFS and failed 4 s later; the
IBSS BSSID was read from the wrong address; `hsg_target_set` was never cleared, so a stale filter
leaked into later passive captures; `rec_note` recorded commands the gate had rejected; `STOP <n>`
was ignored while an AP was up; `DEAUTHCLEAR` did not clear the deauth list.

**Threading / performance.** DHCP and DNS logged with `printf` from the tcpip thread, blocking the
stack and racing `loop()` on the UART — both now go through a bounded deferred log drained by
`loop()`. The 800-byte WebUI buffer moved off the `loop()` stack, `scan_results` is capped at 255
(the `DP_SCAN_AP` index is a `u8`) and reserved, and `|` in an SSID is escaped in the ASCII list.

**Corrected finding.** The reported `tcp_listen()` double free is not real: lwIP 2.0.2 frees the pcb
only on success, so the `tcp_close()` on the failure path is correct (noted in the source).
