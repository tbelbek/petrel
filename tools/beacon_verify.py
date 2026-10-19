#!/usr/bin/env python3
"""End-to-end check of the raw-TX fix + BEACONOFF, while holding the board port open.

Opening the CH340 resets the BW16, so everything has to happen inside ONE open:
  reset -> drive the FAP into a beacon mode -> watch the beacon log -> leave the screen
  -> confirm the log goes quiet (BEACONOFF).

Before the fix the first raw TX wedged the SDK: exactly one "START ..." line, then silence
forever (no replies, no reboot). After the fix the loop keeps beaconing, and BEACONOFF (sent
when the FAP leaves the beacon screen) stops it.
"""
import sys
import time

import serial

sys.path.insert(0, ".")
import flipctl as F  # noqa: E402

PORT = "/dev/cu.usbserial-20220"
SHOT_DIR = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/fix20"


def drive(cmds, tag=""):
    s = F.connect()
    F.send(s, b"\xA2\x01\x00")
    time.sleep(0.4)
    for key, wait in cmds:
        F.send_press(s, key)
        time.sleep(wait)
    time.sleep(1.5)
    d = F.grab(s, 3.0)
    if d:
        F.png(f"{SHOT_DIR}/{tag}.png", d)
    F.close_session(s)
    s.close()


def sample(secs):
    """Count how many beacon lines the board emits in `secs` seconds."""
    b.reset_input_buffer()
    time.sleep(secs)
    out = b.read(400000).decode("utf-8", "replace")
    return out.count("START"), len(out)


if __name__ == "__main__":
    b = serial.Serial(PORT, 115200, timeout=0.4)
    b.dtr = False
    b.rts = False
    time.sleep(7)          # let it boot after the open-triggered reset
    b.reset_input_buffer()
    b.write(b"PING\n")
    time.sleep(2)
    print("board PING ->", b.read(4000).decode("utf-8", "replace").strip()[:40] or "(sessiz)")

    # The app starts on its main menu with Wi-Fi selected; OK enters the Wi-Fi hub.
    drive([("OK", 1.5)], "A0-hub")
    print("-> Send Beacon / Custom (name input -> save -> prints 'START <ssid>' per beacon)")
    drive([("DOWN", 0.35)] * 4 + [("OK", 1.3), ("OK", 1.6), ("OK", 1.8)], "A1-beacon-screen")

    n1, l1 = sample(6)
    print(f"beacon acikken  : {n1} 'START' satiri / {l1} bayt  (~{n1/6:.0f}/sn)")

    print("-> BACK (ekrandan cik -> BEACONOFF)")
    drive([("BACK", 1.5)], "A2-after-back")

    n2, l2 = sample(6)
    print(f"BEACONOFF sonra : {n2} 'START' satiri / {l2} bayt")
    print("SONUC:", "FIX CALISIYOR (yayin basladi + durdu)" if n1 > 50 and n2 < 5 else "KONTROL ET")
    b.close()
