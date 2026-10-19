#!/usr/bin/env python3
"""Live bisect of the SDK raw-TX hang (see notes 2026-10-15).

Each frame goes out in its OWN serial session (opening the CH340 resets the BW16), so a hang
in one case does not poison the next. TXRAW <hex> pushes an arbitrary frame through
wifi_tx_raw_frame; a reply means the frame was accepted, silence means the board spun.

Frame layout under test (24-byte mgmt header + IEs):
  A  = probe request, addr3=broadcast, no beacon fixed fields      (known good: PROBEFLOOD)
  A2 = A but addr3 = source
  A3 = A but with the 12 beacon fixed bytes (timestamp/interval/cap) before the SSID IE
  B  = mine: addr3 = source AND the 12 fixed bytes                 (known bad: hangs)
"""
import time

import serial

PORT = "/dev/cu.usbserial-20220"

HDR_FF = "40000000" + "FFFFFFFFFFFF" + "00E04C010203"
HDR_SRC = HDR_FF + "00E04C010203"
HDR_FF3 = HDR_FF + "FFFFFFFFFFFF"
FIXED = "000000000000000064002100"          # 8B timestamp + 2B interval + 2B capability
SSID = "000141"                              # SSID IE: tag 0, len 1, 'A'
RATES = "010482848B96"                       # supported rates IE

FRAMES = [
    ("A  (probe, addr3=bcast, no fixed)", HDR_FF3 + "0000" + SSID + RATES),
    ("A2 (A + addr3=src)", HDR_SRC + "0000" + SSID + RATES),
    ("A3 (A + 12 fixed bytes)", HDR_FF3 + "0000" + FIXED + SSID + RATES),
    ("B  (addr3=src + 12 fixed = mine)", HDR_SRC + "0000" + FIXED + SSID + RATES),
]


def session(label, hexframe):
    s = serial.Serial(PORT, 115200, timeout=0.3)
    s.dtr = False
    s.rts = False
    time.sleep(0.7)
    s.reset_input_buffer()

    def cmd(c, wait):
        s.write((c + "\n").encode())
        time.sleep(wait)
        out = s.read(8000).decode("utf-8", "replace")
        return [l.strip() for l in out.splitlines() if l.strip() and "DEBUG" not in l]

    ping1 = cmd("PING", 2)
    tx = cmd("TXRAW " + hexframe, 3)
    ping2 = cmd("PING", 2)
    s.close()
    nbytes = len(hexframe) // 2
    ok = bool(tx)
    print(f"{label:38s} {nbytes:3d}B  TXRAW={'OK ' if ok else 'HANG'}  PING_after={'OK' if ping2 else 'HANG'}  {tx}")


if __name__ == "__main__":
    for label, frame in FRAMES:
        session(label, frame)
